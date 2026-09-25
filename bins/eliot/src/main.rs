#![forbid(unsafe_code)]
// Machine-readable and human CLI output is the public contract of this binary.
#![allow(clippy::print_stdout)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use eliot_bootstrap::capture::{capture_snapshot, write_snapshot_artifact};
use eliot_cli::{
    CommandCatalogue, CommandPort, CommandPortError, CommandRequest, USER_AUTOMATION_ROUTE,
    user_automation_route_payload,
};
use eliot_doctor::integration;
use eliot_host::{NotifyFallbackSetupInputs, setup_notify_fallback_per_user};
use eliot_installation::{
    ActivationCommitFence, ApprovedGenerationRegistry, CandidateManifest,
    GenerationPackagePlanInput, GenerationPackagePlanner, InstallationEpoch, InstallationError,
    InstallationProfile, InstallationStage, InstallationStepOutcome, InstallationTransaction,
    InstallationTransactionStore, PlatformHandle, RedbInstallationRegistry,
    RedbInstallationTransactionStore, WindowsInstallationCoordinator,
    parse_installation_transaction_id, registry_projection_pending_ref,
    require_published_source_bundle_journal, validate_installation_transaction_json,
};
use eliot_kernel_core::KernelRuntimeHealthEvidence;
use eliot_live_canary::{
    CANARY_COMPLETION_SCHEMA, CanaryConfig, CanaryError, ProductionCanary,
    ProductionCanaryCompletionBinding, Pulse, publish_production_evidence,
};
use eliot_platform_windows::{
    FileIdentity, HostOwnerLease, InstallerRootError, InstallerRootObjectSnapshot,
    InstallerRootPrimitiveObservation, InstallerRootPrimitiveSpec, InstallerRootProfile,
    PackageStagingError, PackageStagingStage, ProtectedRootLease, ProtectedRuntimePathLease,
    TrustedSourceBundle, TrustedSourceFileLease, UserOwnedRootLease, WindowsInstallerRootPrimitive,
    is_eliot_governor_running, is_process_elevated, observe_current_user_config,
    windows_path_identity_digest,
};
use eliot_runtime_contracts::RuntimeLiveStoreIdentity;
use eliot_store_surreal::{StoreLaunchConfig, launch_config_digest};
mod backup_entry;
#[cfg(windows)]
mod legacy_governor_config;
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

mod bootstrap_draft;
mod controlboard_status;
mod first_run_flow;
mod plugin_preview;
mod scope_observe;
mod source_bundle_materializer;
mod update_installer;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const INVALID_REQUEST_EXIT: i32 = 2;
const FRONT_DOOR_CLOSED_EXIT: i32 = 69;
const UNKNOWN_OUTCOME_EXIT: i32 = 75;
/// The serving owner invalidated the generation/session-bound operator
/// handoff: the UI must restart through a fresh broker-issued binding.
const RESTART_REQUIRED_EXIT: i32 = 77;
/// A backup command reached its registered typed Kernel operation and the
/// Kernel answered honestly, but a named owner is not admitted yet.
///
/// This is deliberately neither a usage failure (the bounded typed
/// arguments were accepted) nor success (no capture, verification, or
/// rehearsal was proven): backup existence is not recovery proof, so a
/// process exit never stands in for it.
const BACKUP_OWNER_ADMISSION_REQUIRED_EXIT: i32 = 78;
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
    /// Compile a typed work-unit bootstrap brief and publish evidence only.
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommand,
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
    /// Governor-backed first-run setup: typed per-role routes, visible
    /// defaults, and Human-board recommendations. Replaces the retired
    /// legacy `governor.toml` path, which is never adopted as authority.
    Setup {
        #[command(subcommand)]
        command: SetupCommand,
    },
    /// Preview or install a plugin/bridge with rollback (I3.7).
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Verify plugin/bridge integration coverage for one profile (I3.7).
    Doctor {
        #[command(subcommand)]
        command: DoctorCommand,
    },
    /// Read the reconciled `ControlBoard` status projection (#1213).
    #[command(name = "controlboard")]
    ControlBoard {
        #[command(subcommand)]
        command: ControlBoardCommand,
    },
    /// Backup creation/restore previews, issuance, isolated restore runs, key coverage (#1873; previews never issue; restore runs never cut over), and the three advertised `create`/`verify`/`restore-test` catalogue commands routed through the authenticated Kernel front door (#963).
    Backup {
        #[command(subcommand)]
        command: backup_entry::BackupCommand,
    },
    /// Observe one explicit workspace root for `WorkScope` attach decisions.
    Scope {
        #[command(subcommand)]
        command: scope_observe::ScopeCommand,
    },
    Version,
    /// Start or reuse the authenticated User Broker and launch Operator.
    Ui,
}

#[derive(Debug, Subcommand)]
enum BootstrapCommand {
    /// Compile one brief from an existing `AgentWorkUnitBrief` seed.
    Brief {
        /// Absolute path to the typed `AgentWorkUnitBrief` JSON seed.
        #[arg(long)]
        work_unit: PathBuf,
        /// Absolute repository root; never inferred from the current directory.
        #[arg(long)]
        repo_root: PathBuf,
    },
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
    /// Materialize an exact thirteen-role Phase-A source bundle and feed it through
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
        eliot_doctor: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_testd: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_native_worker: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_wasm_host: PathBuf,
        /// Release per-user `eliot-notify.exe` adapter path (I1.3/I1.4).
        #[arg(long, value_parser = absolute_path)]
        eliot_notify: PathBuf,
        /// Optional explicit external agent-bridge executable source. Must be
        /// supplied together with `--agent-bridge-account`.
        #[arg(long, value_parser = absolute_path)]
        agent_bridge_exe: Option<PathBuf>,
        /// Optional account name whose canonical SID is resolved by Windows.
        /// Raw SID text is not accepted as an admission input.
        #[arg(long)]
        agent_bridge_account: Option<String>,
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
    /// Publish the per-user Notify fallback declaration and register the
    /// signed Task Scheduler fallback. Runs in the interactive session
    /// matching `--sid`/`--session-id`; normal launch stays User-Broker
    /// owned (I11.6). No process is spawned by this command.
    SetupNotifyFallback {
        /// Stable installation identity.
        #[arg(long)]
        installation: String,
        /// Declared fallback audience.
        #[arg(long)]
        audience: String,
        /// Non-zero authority epoch.
        #[arg(long)]
        authority_epoch: u64,
        /// Watchdog signing key identifier.
        #[arg(long)]
        key_id: String,
        /// Lowercase hex Watchdog verifying key (public half only).
        #[arg(long)]
        public_key: String,
        /// Absolute installed `eliot-notify.exe` path. The image digest is
        /// always hashed from these exact bytes at setup time; no
        /// caller-supplied digest is accepted.
        #[arg(long, value_parser = absolute_path)]
        notify_exe: PathBuf,
        /// Explicit installation profile (`system_service`, `user_mode`, or `portable_dev`).
        #[arg(long, value_parser = parse_installation_profile)]
        profile: InstallationProfile,
        /// Absolute OS-validated profile anchor root.
        #[arg(long, value_parser = absolute_path)]
        profile_anchor_root: PathBuf,
        /// Absolute create-new diagnostic JSON path.
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
    },
    /// Stage one update package into a new versioned directory without
    /// overwriting the running executable. `eliot-kernel` and `eliot-host`
    /// are release-level and require `--release-approved`; optional modules
    /// stage as generation updates with rollback metadata.
    StageUpdate {
        /// Absolute installation root; `<root>/<package>/<version>` is created new.
        #[arg(long, value_parser = absolute_path)]
        install_root: PathBuf,
        /// Package (binary) name.
        #[arg(long)]
        package: String,
        /// Version label; becomes the new versioned directory name.
        #[arg(long)]
        version: String,
        /// Declared update channel (`stable`, `preview`, or `local-dev`).
        #[arg(long, value_parser = parse_update_channel)]
        channel: update_installer::UpdateChannel,
        /// Lowercase hex SHA-256 of the payload file.
        #[arg(long)]
        artifact_sha256: String,
        /// Absolute payload executable file staged into the versioned directory.
        #[arg(long, value_parser = absolute_path)]
        payload: PathBuf,
        /// Optional running executable; staging fails closed on collision.
        #[arg(long, value_parser = absolute_path)]
        running_exe: Option<PathBuf>,
        /// Optional previous versioned directory recorded for module rollback.
        #[arg(long, value_parser = absolute_path)]
        previous_version_dir: Option<PathBuf>,
        /// Required for Kernel/Host release-level updates.
        #[arg(long)]
        release_approved: bool,
        /// Absolute create-new update record JSON path.
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
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
enum PluginCommand {
    /// Render the exact I3.7 preview fields without mutating anything.
    Preview {
        /// Absolute path to the plugin proposal manifest JSON.
        #[arg(long, value_parser = absolute_path)]
        manifest: PathBuf,
        /// Absolute rollback directory bound into the preview.
        #[arg(long, value_parser = absolute_path)]
        rollback_dir: PathBuf,
    },
    /// Preserve the rollback artifact before mutation, then record an
    /// install receipt scoped to the rollback directory. Never claims
    /// runtime liveness.
    Install {
        /// Absolute path to the plugin proposal manifest JSON.
        #[arg(long, value_parser = absolute_path)]
        manifest: PathBuf,
        /// Absolute rollback directory receiving the artifact and receipt.
        #[arg(long, value_parser = absolute_path)]
        rollback_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DoctorCommand {
    /// Inspect expected file hashes, active registrations, observed hook
    /// events, and the handshake result for one profile, reporting
    /// installation separately from runtime liveness. Read-only: executes
    /// no repair, mints no authority, mutates nothing.
    Integration {
        /// Integration profile name; must equal the expectation record profile.
        profile: String,
        /// Absolute path to the expected integration state JSON.
        #[arg(long, value_parser = absolute_path)]
        expectation: PathBuf,
        /// Absolute path to the observed integration state JSON.
        #[arg(long, value_parser = absolute_path)]
        observation: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ControlBoardCommand {
    /// Fetch one reconciled `ControlBoard` board over the authenticated
    /// `controlboard.status` transact path and project its typed rows.
    /// Read-only: owns no board handle, cache, or canonical state, and
    /// synthesizes no health from the dispositions.
    Status,
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
    /// Print the generated catalogue help text. Named `help-text` because clap
    /// reserves `help` on every command that has subcommands.
    #[command(name = "help-text")]
    Help,
    Schema,
    Validate,
}

/// Governor-backed first-run setup commands (issue #1962).
#[derive(Debug, Subcommand)]
enum SetupCommand {
    /// Decide typed per-role route state. Omitted roles stay `UNASSIGNED`;
    /// paid routes require explicit consent flags.
    Apply {
        /// Dreamer route kind: `unassigned`, `local`, `economy`, or `paid`.
        #[arg(long)]
        dreamer_route: Option<String>,
        /// Watchdog route kind: `unassigned`, `local`, `economy`, or `paid`.
        #[arg(long)]
        watchdog_route: Option<String>,
        /// The setup screen displayed the Dreamer local/economy default.
        #[arg(long, default_value = "false")]
        dreamer_displayed: bool,
        /// The setup screen displayed the Watchdog local/economy default.
        #[arg(long, default_value = "false")]
        watchdog_displayed: bool,
        /// Explicit paid-route consent for Dreamer.
        #[arg(long, default_value = "false")]
        dreamer_explicit: bool,
        /// Explicit paid-route consent for Watchdog.
        #[arg(long, default_value = "false")]
        watchdog_explicit: bool,
        /// Automation mode: `suggest_only`, `manual`, `idle_only`,
        /// `scheduled`, `continuous_bounded`, or `off`. Omitted keeps the
        /// visible `SUGGEST_ONLY` default.
        #[arg(long)]
        automation: Option<String>,
        /// Human owner ref recorded on every persisted setting. Required:
        /// no identity is invented by the CLI.
        #[arg(long)]
        owner_ref: String,
    },
    /// Inspect every default through the same typed path (reversible).
    Show,
    /// Update one role and/or the automation mode through the same typed
    /// path used by `apply`.
    Set {
        /// Role key: `main`, `worker`, `auditor`, `verifier`, `watchdog`,
        /// `dreamer`, or `research`. Required with `--route`.
        #[arg(long)]
        role: Option<String>,
        /// Route kind: `unassigned`, `local`, `economy`, or `paid`. Omitted
        /// clears the role back to `UNASSIGNED`.
        #[arg(long)]
        route: Option<String>,
        /// The setup screen displayed the local/economy default.
        #[arg(long, default_value = "false")]
        displayed: bool,
        /// Explicit paid-route consent.
        #[arg(long, default_value = "false")]
        explicit_consent: bool,
        /// Automation mode update: `suggest_only`, `manual`, `idle_only`,
        /// `scheduled`, `continuous_bounded`, or `off`. At least one of
        /// `--route` or `--automation` is required.
        #[arg(long)]
        automation: Option<String>,
        /// Human owner ref recorded on every persisted setting. Required:
        /// no identity is invented by the CLI.
        #[arg(long)]
        owner_ref: String,
    },
    /// With automation disabled, record one deduplicated Human-board
    /// recommendation for a needed action; no job starts.
    Recommend {
        /// Automation mode: `suggest_only`, `manual`, `idle_only`,
        /// `scheduled`, `continuous_bounded`, or `off`.
        #[arg(long)]
        automation: String,
        /// Maintenance family, e.g. `RESEARCH_EXCHANGE_CLEANUP`.
        #[arg(long)]
        family: String,
        /// Affected scope reference.
        #[arg(long)]
        scope: String,
    },
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
        Command::Bootstrap { command } => Ok(run_bootstrap(command)),
        Command::Installation { command } => run_installation(command),
        Command::Runtime { command } => run_runtime(command),
        Command::Setup { command } => run_setup(command),
        Command::Plugin { command } => run_plugin(command),
        Command::Doctor { command } => run_doctor(command),
        Command::ControlBoard { command } => run_controlboard(command),
        Command::Backup { command } => backup_entry::run_backup(command),
        Command::Scope { command } => Ok(run_scope(command)),
        Command::Dispatch => run_dispatch(),
        Command::Ui => run_ui(),
    }
}

#[cfg(windows)]
fn reject_present_legacy_governor_config() -> Result<()> {
    observe_legacy_governor_config()
}

#[cfg(not(windows))]
fn reject_present_legacy_governor_config() -> Result<()> {
    Ok(())
}

fn run_setup(command: SetupCommand) -> Result<i32> {
    // #1962: reject a present legacy Governor file before any setup
    // decision; absent proceeds with no legacy config adopted.
    reject_present_legacy_governor_config()?;
    match command {
        SetupCommand::Apply {
            dreamer_route,
            watchdog_route,
            dreamer_displayed,
            watchdog_displayed,
            dreamer_explicit,
            watchdog_explicit,
            automation,
            owner_ref,
        } => first_run_flow::run_setup_apply(&first_run_flow::SetupApplyArgs {
            dreamer_route,
            watchdog_route,
            dreamer_displayed,
            watchdog_displayed,
            dreamer_explicit,
            watchdog_explicit,
            automation,
            owner_ref,
        }),
        SetupCommand::Show => first_run_flow::run_setup_show(),
        SetupCommand::Set {
            role,
            route,
            displayed,
            explicit_consent,
            automation,
            owner_ref,
        } => first_run_flow::run_setup_set(&first_run_flow::SetupSetArgs {
            role,
            route,
            displayed,
            explicit_consent,
            automation,
            owner_ref,
        }),
        SetupCommand::Recommend {
            automation,
            family,
            scope,
        } => first_run_flow::run_setup_recommend(&first_run_flow::SetupRecommendArgs {
            automation,
            family,
            scope,
        }),
    }
}

fn run_plugin(command: PluginCommand) -> Result<i32> {
    match command {
        PluginCommand::Preview {
            manifest,
            rollback_dir,
        } => {
            let proposal = match plugin_preview::load_manifest(&manifest) {
                Ok(proposal) => proposal,
                Err(error) => {
                    write_installation_error("PLUGIN_PREVIEW_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let preview = plugin_preview::render_preview(&proposal, &rollback_dir);
            println!(
                "{}",
                serde_json::to_string_pretty(&plugin_preview::preview_json(&preview))?
            );
            Ok(0)
        }
        PluginCommand::Install {
            manifest,
            rollback_dir,
        } => {
            let proposal = match plugin_preview::load_manifest(&manifest) {
                Ok(proposal) => proposal,
                Err(error) => {
                    write_installation_error("PLUGIN_INSTALL_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            match plugin_preview::install_with_rollback(&proposal, &rollback_dir) {
                // No admitted mutation port exists, so success is unreachable:
                // a backup-only path cannot yield installed success. The
                // defensive arm stays fail-closed if that ever changes.
                Ok(_) => {
                    write_installation_error(
                        "PLUGIN_INSTALL_UNEXPECTED",
                        "install reported success without an admitted mutation port; no installed claim is emitted",
                    );
                    Ok(INVALID_REQUEST_EXIT)
                }
                Err(plugin_preview::PluginPreviewError::InstallNotAttempted {
                    detail,
                    rollback_artifact,
                    receipt_path,
                }) => {
                    write_installation_error(
                        "PLUGIN_INSTALL_NOT_ATTEMPTED",
                        &format!(
                            "{detail} rollback={} receipt={}",
                            rollback_artifact.display(),
                            receipt_path.display()
                        ),
                    );
                    Ok(INVALID_REQUEST_EXIT)
                }
                Err(error) => {
                    write_installation_error("PLUGIN_INSTALL_FAILED", &error.to_string());
                    Ok(INVALID_REQUEST_EXIT)
                }
            }
        }
    }
}

fn run_doctor(command: DoctorCommand) -> Result<i32> {
    match command {
        DoctorCommand::Integration {
            profile,
            expectation,
            observation,
        } => {
            // Same shared gate as `eliot-doctor integration`: the evaluator
            // and output contract live in `eliot_doctor::integration`; this
            // front door only decodes arguments and projects the result.
            // Verification mismatches are data inside the JSON report
            // (exit 0); only input errors exit nonzero.
            match integration::verify_profile(&profile, &expectation, &observation) {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    Ok(0)
                }
                Err(error) => {
                    write_installation_error("DOCTOR_INTEGRATION_INVALID", &error.to_string());
                    Ok(INVALID_REQUEST_EXIT)
                }
            }
        }
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "single-variant command dispatch keeps the by-value shape reserved for future variants"
)]
fn run_controlboard(command: ControlBoardCommand) -> Result<i32> {
    match command {
        // Actual consumer over the authenticated EBP transact path: the
        // serving runtime (Ramanujan/Kernel lane) reconciles the board and
        // answers `controlboard.status`; this front door only decodes the
        // served board with the owner's transport types and projects its
        // typed rows. No board handle, cache, or canonical state is owned
        // here, and no health is synthesized from the dispositions.
        ControlBoardCommand::Status => {
            #[cfg(windows)]
            {
                run_controlboard_status_windows()
            }
            #[cfg(not(windows))]
            {
                write_json_error(
                    "KERNEL_APPLICATION_PORT_CLOSED",
                    "Windows authenticated Kernel front door",
                );
                Ok(FRONT_DOOR_CLOSED_EXIT)
            }
        }
    }
}

#[cfg(windows)]
fn run_controlboard_status_windows() -> Result<i32> {
    use eliot_cli::kernel_client::KernelClientError;

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
    let served = match port.transact_controlboard_status() {
        Ok(served) => served,
        Err(KernelClientError::FrontDoorClosed(contract)) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            return Ok(FRONT_DOOR_CLOSED_EXIT);
        }
        Err(KernelClientError::UnknownOutcome(detail)) => {
            write_json_error("CONTROLBOARD_STATUS_UNKNOWN", &detail);
            return Ok(UNKNOWN_OUTCOME_EXIT);
        }
        Err(KernelClientError::MissingRequestIdentity) => {
            write_json_error(
                "CONTROLBOARD_STATUS_NOT_ADMITTED",
                "no admitted EBP request identity is bound for an operator-initiated controlboard read; the identity must arrive through the admitted host request path and Ramanujan must serve controlboard.status; tracker #1213",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_json_error("CONTROLBOARD_STATUS_REJECTED", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let board = match controlboard_status::decode_status_response(served) {
        Ok(board) => board,
        Err(error) => {
            write_json_error("CONTROLBOARD_STATUS_REFUSED", &error.to_string());
            return Ok(UNKNOWN_OUTCOME_EXIT);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&controlboard_status::render_status_json(&board)?)?
    );
    Ok(0)
}

fn run_scope(command: scope_observe::ScopeCommand) -> i32 {
    match command {
        scope_observe::ScopeCommand::Observe {
            repo_root,
            generation,
        } => match scope_observe::execute(&repo_root, generation) {
            Ok(value) => {
                println!("{value}");
                0
            }
            Err(error) => {
                println!("{}", error.envelope());
                error.exit_code()
            }
        },
    }
}

fn run_bootstrap(command: BootstrapCommand) -> i32 {
    match command {
        BootstrapCommand::Brief {
            work_unit,
            repo_root,
        } => match bootstrap_draft::execute(&work_unit, &repo_root) {
            Ok(success) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "response": success.response,
                        "draft_path": success.draft_path,
                        "draft_sha256": success.draft_sha256,
                    })
                );
                0
            }
            Err(error) => {
                println!("{}", error.envelope());
                error.exit_code()
            }
        },
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
fn observe_legacy_governor_config() -> Result<()> {
    // #1687: the legacy Governor file is never adopted as authority. A present
    // file fails closed with the Kernel-surface migration action; an absent
    // file is provisional and lets the canary/install path proceed.
    // #1858 (I19.5): each legacy-entrypoint refusal additionally emits a
    // stable machine-readable cutover code with a redirect receipt naming
    // the canonical Kernel-governed route. The report is observational only:
    // the returned Err still aborts the operation, so no legacy entrypoint
    // can initialize an independent Governor, direct store mutation route,
    // local control channel, or alternate launch journal.
    match observe_current_user_config(INSTALLATION_INPUT_LIMIT) {
        Ok(eliot_platform_windows::LocalAppDataConfigObservation::Absent { .. }) => {
            legacy_governor_config::gate_legacy_config_observation(None)
                .map_err(|error| anyhow::anyhow!(error))?;
        }
        Ok(eliot_platform_windows::LocalAppDataConfigObservation::Present(read)) => {
            if let Err(error) = legacy_governor_config::gate_legacy_config_observation(Some((
                read.path(),
                read.bytes(),
            ))) {
                write_legacy_governor_cutover_rejection(
                    legacy_governor_config::LEGACY_GOVERNOR_CONFIG_RETIRED,
                    &error,
                );
                return Err(anyhow::anyhow!(error));
            }
        }
        Err(error) => {
            let detail = format!("legacy Governor config observation is unknown: {error}");
            write_legacy_governor_cutover_rejection(
                legacy_governor_config::LEGACY_GOVERNOR_OBSERVATION_UNKNOWN,
                &detail,
            );
            return Err(anyhow::anyhow!(detail));
        }
    }
    let process_state = is_eliot_governor_running().map_err(|error| error.to_string());
    match &process_state {
        Ok(false) => {}
        Ok(true) => {
            let detail = "legacy eliot-governor.exe is running";
            write_legacy_governor_cutover_rejection(
                legacy_governor_config::LEGACY_GOVERNOR_PROCESS_RUNNING,
                detail,
            );
        }
        Err(error) => {
            let detail = format!("legacy Governor process state is unknown: {error}");
            write_legacy_governor_cutover_rejection(
                legacy_governor_config::LEGACY_GOVERNOR_OBSERVATION_UNKNOWN,
                &detail,
            );
        }
    }
    classify_legacy_governor_process_state(process_state).map_err(|error| anyhow::anyhow!(error))
}

#[cfg(windows)]
fn revalidate_legacy_governor_gate() -> Result<()> {
    // Re-observe the OS-known path after the guarded operation so a file that
    // appears mid-operation is rejected rather than silently adopted.
    observe_legacy_governor_config()
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
    // #1687: reject a present legacy Governor file before any canary effect;
    // absent proceeds with no legacy config adopted.
    observe_legacy_governor_config()?;
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
    revalidate_legacy_governor_gate()?;
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
            }
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
            eliot_doctor,
            eliot_testd,
            eliot_native_worker,
            eliot_wasm_host,
            eliot_notify,
            agent_bridge_exe,
            agent_bridge_account,
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
            eliot_doctor,
            eliot_testd,
            eliot_native_worker,
            eliot_wasm_host,
            eliot_notify,
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
            agent_bridge_exe,
            agent_bridge_account,
        ),
        InstallationCommand::SetupNotifyFallback {
            installation,
            audience,
            authority_epoch,
            key_id,
            public_key,
            notify_exe,
            profile,
            profile_anchor_root,
            output,
        } => run_installation_setup_notify_fallback(
            installation,
            audience,
            authority_epoch,
            key_id,
            public_key,
            notify_exe,
            profile,
            profile_anchor_root,
            output,
        ),
        InstallationCommand::StageUpdate {
            install_root,
            package,
            version,
            channel,
            artifact_sha256,
            payload,
            running_exe,
            previous_version_dir,
            release_approved,
            output,
        } => run_installation_stage_update(
            &install_root,
            package,
            version,
            channel,
            artifact_sha256,
            &payload,
            running_exe.as_deref(),
            previous_version_dir.as_deref(),
            release_approved,
            &output,
        ),
    }
}

fn parse_update_channel(
    value: &str,
) -> std::result::Result<update_installer::UpdateChannel, String> {
    value
        .parse::<update_installer::UpdateChannel>()
        .map_err(|error| error.to_string())
}

fn update_installer_error_code(error: &update_installer::UpdateInstallerError) -> &'static str {
    match error {
        update_installer::UpdateInstallerError::UnknownChannel { .. }
        | update_installer::UpdateInstallerError::InvalidPackage { .. } => {
            "INSTALLATION_UPDATE_REJECTED"
        }
        update_installer::UpdateInstallerError::RunningBinaryWouldBeOverwritten { .. } => {
            "INSTALLATION_UPDATE_RUNNING_GUARD"
        }
        update_installer::UpdateInstallerError::VersionedDirExists { .. } => {
            "INSTALLATION_UPDATE_VERSION_EXISTS"
        }
        update_installer::UpdateInstallerError::ReleaseApprovalRequired => {
            "INSTALLATION_UPDATE_RELEASE_APPROVAL_REQUIRED"
        }
        update_installer::UpdateInstallerError::StagingFailed { .. } => {
            "INSTALLATION_UPDATE_STAGING_FAILED"
        }
    }
}

fn write_update_record_artifact(
    path: &Path,
    record: &update_installer::UpdateRecord,
) -> Result<(), std::io::Error> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "update record output must be absolute",
        ));
    }
    let mut bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let readback = fs::read(path)?;
    if readback != bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "update record output readback differs from the exact written bytes",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_installation_stage_update(
    install_root: &Path,
    package: String,
    version: String,
    channel: update_installer::UpdateChannel,
    artifact_sha256: String,
    payload: &Path,
    running_exe: Option<&Path>,
    previous_version_dir: Option<&Path>,
    release_approved: bool,
    output: &Path,
) -> Result<i32> {
    let payload_bytes = match load_input(payload) {
        Ok(bytes) => bytes,
        Err(error) => {
            write_installation_error("INSTALLATION_UPDATE_PAYLOAD_REJECTED", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let metadata = update_installer::PackageMetadata {
        name: package,
        version,
        channel,
        artifact_sha256,
    };
    let payload_digest = format!("{:x}", Sha256::digest(&payload_bytes));
    if payload_digest != metadata.artifact_sha256 {
        write_installation_error(
            "INSTALLATION_UPDATE_DIGEST_MISMATCH",
            "payload SHA-256 differs from the declared update package metadata",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    let request = update_installer::InstallUpdateRequest {
        install_root,
        running_executable: running_exe,
        package: &metadata,
        payload: &payload_bytes,
        previous_version_dir,
        release_approved,
    };
    let record = match update_installer::install_update(&request) {
        Ok(record) => record,
        Err(error) => {
            write_installation_error(update_installer_error_code(&error), &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if let Err(error) = write_update_record_artifact(output, &record) {
        write_installation_error("INSTALLATION_UPDATE_OUTPUT_REJECTED", &error.to_string());
        return Ok(INVALID_REQUEST_EXIT);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": "STAGED",
            "package": record.package_name,
            "version": record.version,
            "channel": record.channel.as_str(),
            "kind": record.kind.as_str(),
            "release_approval_required": record.kind.requires_release_approval(),
            "installed_dir": record.installed_dir,
            "executable": record.executable_path,
            "generation": record.generation,
            "rollback_from": record.rollback_from,
            "scope": INSTALLATION_SCOPE,
        }))?
    );
    Ok(0)
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
    agent_bridge_source: Option<Box<eliot_installation::AgentBridgeSourceMaterializationPlan>>,
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
            agent_bridge_source,
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
    clippy::too_many_arguments,
    reason = "per-user setup carries the full explicit declaration field set"
)]
fn run_installation_setup_notify_fallback(
    installation: String,
    audience: String,
    authority_epoch: u64,
    key_id: String,
    public_key: String,
    notify_exe: PathBuf,
    profile: InstallationProfile,
    profile_anchor_root: PathBuf,
    output: PathBuf,
) -> Result<i32> {
    use eliot_host::HostError;
    let portable_root = match profile {
        InstallationProfile::PortableDev => Some(
            UserOwnedRootLease::open_existing(&profile_anchor_root).map_err(|error| {
                anyhow::anyhow!("portable setup root is not provisioned: {error}")
            })?,
        ),
        InstallationProfile::SystemService | InstallationProfile::UserMode => None,
    };
    let inputs = NotifyFallbackSetupInputs {
        installation_identity: cli_handle(installation.clone(), "installation")?,
        audience: cli_handle(audience.clone(), "audience")?,
        authority_epoch,
        key_id: cli_handle(key_id.clone(), "key_id")?,
        public_key,
        notify_executable: notify_exe,
        profile,
        portable_root,
    };
    let setup = match setup_notify_fallback_per_user(&inputs) {
        Ok(setup) => setup,
        Err(error) => {
            if let HostError::RecoveryRequired(_) = &error {
                write_installation_error(
                    "NOTIFY_FALLBACK_SETUP_RECOVERY_REQUIRED",
                    &error.to_string(),
                );
                return Ok(UNKNOWN_OUTCOME_EXIT);
            }
            write_installation_error("NOTIFY_FALLBACK_SETUP_REJECTED", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let receipt = serde_json::to_string_pretty(&json!({
        "contract": "eliot.kernel.installation",
        "contract_version": INSTALLATION_CONTRACT_VERSION,
        "status": "NOTIFY_FALLBACK_SETUP_PUBLISHED",
        "output_role": "DIAGNOSTIC_NON_IMPORTABLE",
        "declaration_path": setup.declaration.declaration_path.display().to_string(),
        "declaration_digest": setup.declaration.declaration_digest.as_str(),
        "task_name": setup.registration.task_name,
        "sid": setup.registration.sid,
        "session_id": setup.registration.session_id,
        "notify_artifact_sha256": setup.registration.notify_artifact_sha256,
        "verifier_sha256": setup.registration.verifier_sha256,
        "task_xml_sha256": setup.registration.task_xml_sha256,
    }))?;
    let mut output_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .map_err(|error| anyhow::anyhow!("open setup output: {error}"))?;
    output_file
        .write_all(receipt.as_bytes())
        .map_err(|error| anyhow::anyhow!("write setup output: {error}"))?;
    println!("{receipt}");
    Ok(0)
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
    eliot_doctor: PathBuf,
    eliot_testd: PathBuf,
    eliot_native_worker: PathBuf,
    eliot_wasm_host: PathBuf,
    eliot_notify: PathBuf,
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
    agent_bridge_exe: Option<PathBuf>,
    agent_bridge_account: Option<String>,
) -> Result<i32> {
    let materialize_input = source_bundle_materializer::CanarySourceBundleMaterializeInput {
        eliot_host_exe: eliot_host,
        eliot_watchdog_exe: eliot_watchdog,
        eliot_kernel_exe: eliot_kernel,
        eliot_store_surreal_exe: eliot_store_surreal,
        surreal_exe: surreal,
        eliotd_exe: eliotd,
        eliot_doctor_exe: eliot_doctor,
        eliot_testd_exe: eliot_testd,
        eliot_native_worker_exe: eliot_native_worker,
        eliot_wasm_host_exe: eliot_wasm_host,
        eliot_notify_exe: eliot_notify,
        agent_bridge_exe,
        agent_bridge_account,
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
                if let InstallationError::RecoveryRequired { .. } = &error {
                    write_installation_error(
                        "SOURCE_BUNDLE_MATERIALIZATION_RECOVERY_REQUIRED",
                        &error.to_string(),
                    );
                    return Ok(UNKNOWN_OUTCOME_EXIT);
                }
                write_installation_error(
                    "SOURCE_BUNDLE_MATERIALIZATION_REJECTED",
                    &error.to_string(),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        };
    let source_publication = receipt.planner_binding()?;
    let agent_bridge_source =
        source_bundle_materializer::bridge_source_plan_for_receipt(&materialize_input, &receipt)?;
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
        agent_bridge_source,
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
    let runtime_health = match load_authenticated_kernel_runtime_health() {
        Ok(runtime_health) => runtime_health,
        Err(error) => {
            let (code, detail) = match error {
                AuthenticatedRuntimeHealthError::Unavailable(detail) => {
                    ("KERNEL_RUNTIME_HEALTH_UNAVAILABLE", detail)
                }
                AuthenticatedRuntimeHealthError::Invalid(detail) => {
                    ("KERNEL_RUNTIME_HEALTH_INVALID", detail)
                }
            };
            write_runtime_status_error(code, &detail, false);
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    match eliot_runtime_status::collect_status_with_kernel_health(
        host_state_root,
        deadline,
        &runtime_health,
    ) {
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
                    "runtime_health": report.runtime_health,
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
        revalidate_legacy_governor_gate()
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
    // #1687: reject a present legacy Governor file before installation effects;
    // absent proceeds with no legacy config adopted.
    observe_legacy_governor_config()?;
    Ok(InstallationRuntimePreflightGuard {
        _source: source,
        generation: lease,
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
        if preflight_transaction.has_activation_projection_intent() {
            rollback_with_activation_owner(
                &mut coordinator,
                &preflight_transaction,
                &transaction_id,
            )
        } else {
            coordinator.rollback(&transaction_id)
        }
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
                        // E3: the retained Host root cannot be reopened after
                        // the bootstrap prefix applied. Persist the same
                        // durable typed rejection as E4/E5 so a later
                        // recover/rollback reaches RolledBack; an unconfirmed
                        // rejection stays INSTALLATION_APPLY_RECOVERY_REQUIRED.
                        return Ok(report_post_bootstrap_failure(
                            &mut coordinator,
                            &transaction_id,
                            &format!("retained Host root could not be reopened: {error}"),
                        ));
                    }
                };
                let registry = match RedbInstallationRegistry::open_at(host_root) {
                    Ok(registry) => registry,
                    Err(error) => {
                        // E4: persist a durable typed rejection so a later
                        // recover/rollback reaches RolledBack and removes exactly
                        // the CreatedByTransaction service registrations. The
                        // persist result is projected, never discarded: an
                        // unconfirmed rejection is
                        // INSTALLATION_APPLY_RECOVERY_REQUIRED (unknown).
                        return Ok(report_post_bootstrap_failure(
                            &mut coordinator,
                            &transaction_id,
                            &format!("pending registry could not be opened: {error}"),
                        ));
                    }
                };
                let expected_revision = match registry.load() {
                    Ok(registry) => registry.revision(),
                    Err(error) => {
                        // E5: same durable rejection as E4 (registry unreadable
                        // after open is UNKNOWN_OUTCOME/ROLLBACK_REQUIRED).
                        // The persist result is projected, never discarded.
                        return Ok(report_post_bootstrap_failure(
                            &mut coordinator,
                            &transaction_id,
                            &format!("pending registry preflight failed: {error}"),
                        ));
                    }
                };
                if let Err(error) = coordinator.stage_bootstrap_pending_activation(
                    &registry,
                    &transaction_id,
                    expected_revision,
                ) {
                    // E6: reload first. If an activation projection intent is now
                    // present (Activating) do NOT persist — mark_unknown is
                    // refused in Activating — and resume via the existing
                    // Activating reconcile / terminal query path. Only persist
                    // while still Registering (CAS never happened); the persist
                    // result is projected, never discarded.
                    let still_registering = match coordinator.store().load(&transaction_id) {
                        Ok(Some(current)) => {
                            current.stage() == InstallationStage::Registering
                                && !current.has_activation_projection_intent()
                        }
                        Ok(None) | Err(_) => false,
                    };
                    if still_registering {
                        return Ok(report_post_bootstrap_failure(
                            &mut coordinator,
                            &transaction_id,
                            &format!("pending registry projection failed: {error}"),
                        ));
                    }
                    write_installation_error(
                        "INSTALLATION_APPLY_ERROR",
                        &format!("pending registry projection failed: {error}"),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
                // INSTALL-WATCHDOG-APPROVAL: the staged `registry` is the sole
                // redb writer for the installation registry. Release it (with
                // its retained root/file leases) before the unbounded SCM
                // start + convergence wait so the Watchdog approval reader
                // (`inspect_existing_at`, a short-lived ReadOnlyDatabase) can
                // open the same file. Terminal reconcile re-opens short-lived
                // handles via `open_existing_at`.
                drop(registry);
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

/// The terminal-reconcile writer open below is short-lived and bounded: it
/// retries only redb exclusive-lock contention with backoff, then fails
/// typed with the preserved cause (A13.9:14 no exclusive owner across an
/// unbounded wait; `crates/kernel/eliot-installation/src/installation_registry.rs:8-13`
/// bounded-hold contract; prior `drop(registry)` fix at main.rs:2221-2228;
/// redb `Database::open` takes an exclusive file lock while the Watchdog
/// 250ms poll may hold the file).
fn is_redb_exclusive_lock_contention(error: &InstallationError) -> bool {
    match error {
        InstallationError::Platform(reason) => {
            let normalized = reason.to_lowercase();
            normalized.contains("already open") || normalized.contains("cannot acquire lock")
        }
        _ => false,
    }
}

/// Opens the existing registry for terminal reconcile with bounded
/// lock-contention retry. Absent stays `Ok(None)`; non-lock failures fail
/// fast with the preserved cause. Total sleep is bounded well below 5s so
/// this second-apply query-reconcile never becomes an unbounded wait.
fn open_existing_registry_for_terminal_reconcile(
    host_state_root: &Path,
) -> Result<Option<RedbInstallationRegistry>, InstallationError> {
    // NOTE: Writer-A may add a shared retry primitive in the registry crate;
    // writers run in parallel from the same base, so this file keeps a small
    // local loop. The integrator may dedupe to the shared helper on merge.
    const MAX_ATTEMPTS: usize = 6;
    // 100+200+400+800+1600 = 3100ms total sleep, strictly below the 5s bound.
    const BACKOFF_MS: [u64; 5] = [100, 200, 400, 800, 1600];
    let mut last_contention: Option<InstallationError> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let host_root = ProtectedRootLease::open_existing(host_state_root)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        match RedbInstallationRegistry::open_existing_at(host_root) {
            Ok(registry) => return Ok(registry),
            Err(error) if is_redb_exclusive_lock_contention(&error) => {
                last_contention = Some(error);
                if attempt + 1 < MAX_ATTEMPTS {
                    let Some(&backoff_ms) = BACKOFF_MS.get(attempt) else {
                        panic!("backoff schedule covers all retries");
                    };
                    std::thread::sleep(Duration::from_millis(backoff_ms));
                    continue;
                }
                break;
            }
            Err(error) => return Err(error),
        }
    }
    let Some(cause) = last_contention else {
        panic!("lock-contention loop must retain its cause");
    };
    Err(cause)
}

/// Re-enters the installation owner's pre-no-return rollback seam for a
/// durable activation intent.  The CLI only wires already-owned capabilities:
/// the protected Host root bounds the one short-lived redb writer, while the
/// installation-wide Host lease supplies the non-forgeable mutation proof.
/// No caller-supplied approval, registry revision, or root path is accepted.
fn rollback_with_activation_owner(
    coordinator: &mut WindowsInstallationCoordinator<RedbInstallationTransactionStore>,
    transaction: &InstallationTransaction,
    transaction_id: &PlatformHandle,
) -> Result<InstallationStepOutcome, InstallationError> {
    let host_state_root = Path::new(
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str(),
    );
    let registry =
        open_existing_registry_for_terminal_reconcile(host_state_root)?.ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "Host activation registry is absent for owner-aware rollback".to_owned(),
            )
        })?;
    let owner = HostOwnerLease::acquire(&transaction.installation_epoch.installation)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let host = owner.activation_capability();
    coordinator.rollback_with_activation_owner(&registry, &host, transaction_id)
}

/// Reconciles only an exact Host-committed registry terminal.  A missing
/// terminal is the expected fenced first-install state and remains pending;
/// this query never starts services, rewrites descriptors, or retries a
/// credential/SCM effect.
fn reconcile_host_activation_terminal(
    store_path: &Path,
    transaction: &InstallationTransaction,
) -> Result<Option<InstallationStepOutcome>, InstallationError> {
    let host_state_root = Path::new(
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str(),
    );
    let host_root = ProtectedRootLease::open_existing(host_state_root)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let Some(registry) = RedbInstallationRegistry::inspect_existing_at(host_root)? else {
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
        Err(eliot_cli::kernel_client::KernelClientError::RestartRequired(detail)) => {
            // Generation/session-bound handoff invalidated by the serving
            // owner: restart through a fresh broker-issued binding. The
            // consumed endpoint, PID, pipe name, and cached environment are
            // never continuity evidence.
            write_json_error("KERNEL_OPERATOR_RESTART_REQUIRED", &detail);
            Ok(RESTART_REQUIRED_EXIT)
        }
        Err(eliot_cli::kernel_client::KernelClientError::UnknownOutcome(detail)) => {
            // Possibly launched: reconcile the same launch operation by its
            // operation identity; never resubmit a second launch.
            write_json_error("KERNEL_OPERATOR_LAUNCH_UNKNOWN", &detail);
            Ok(UNKNOWN_OUTCOME_EXIT)
        }
        Err(eliot_cli::kernel_client::KernelClientError::MissingRequestIdentity) => {
            write_json_error(
                "KERNEL_OPERATOR_LAUNCH_NOT_ADMITTED",
                "no admitted EBP request identity is bound for a broker-admitted operator launch; the identity must arrive through the admitted host request path",
            );
            Ok(INVALID_REQUEST_EXIT)
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

/// Structured legacy-entrypoint cutover rejection (#1858, I19.5). Emits the
/// stable machine-readable cutover code with a redirect receipt naming the
/// canonical Kernel-governed route. Observational only: callers still return
/// Err, so the refusal stays fail-closed with no alternate writer.
#[cfg(windows)]
fn write_legacy_governor_cutover_rejection(code: &str, detail: &str) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "canonical_route": legacy_governor_config::LEGACY_GOVERNOR_CANONICAL_ROUTE,
            "completed": false,
        })
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

/// Projects a post-bootstrap non-effect failure observed after the Host
/// bootstrap prefix (Host-root reopen, registry open/load, registry
/// projection staging: `E3`/`E4`/`E5` and the still-`Registering` branch of
/// `E6`).
///
/// The coordinator-owned durable typed rejection is always attempted and its
/// result is never discarded: success keeps the existing
/// `INSTALLATION_APPLY_ERROR` with a recoverable-rollback note (the stored
/// `Registering → RollbackRequired` transition lets a later recover reach
/// `RolledBack` and remove exactly the `CreatedByTransaction` registrations);
/// when the rejection cannot be confirmed the outcome stays truthful
/// `INSTALLATION_APPLY_RECOVERY_REQUIRED` per `I3.15`
/// (`UNKNOWN_OUTCOME/ROLLBACK_REQUIRED` until read-back reconciliation), never
/// a plain apply error that would imply durable recovery. The
/// transaction/fence/owner gates are untouched: a refusal in `Activating` (or
/// a store CAS failure) surfaces here as unconfirmed, it is never overridden.
fn report_post_bootstrap_failure<S>(
    coordinator: &mut WindowsInstallationCoordinator<S>,
    transaction_id: &PlatformHandle,
    detail: &str,
) -> i32
where
    S: InstallationTransactionStore,
{
    let pending_ref = match registry_projection_pending_ref(transaction_id) {
        Ok(pending_ref) => pending_ref,
        Err(error) => {
            write_installation_error(
                "INSTALLATION_APPLY_RECOVERY_REQUIRED",
                &format!(
                    "{detail}; durable rejection reference could not be built ({error}): recovery is required and rollback readiness is unknown"
                ),
            );
            return INVALID_REQUEST_EXIT;
        }
    };
    match coordinator.persist_non_effect_rejection(transaction_id, pending_ref) {
        Ok(_) => {
            write_installation_error(
                "INSTALLATION_APPLY_ERROR",
                &format!(
                    "{detail}; durable typed rejection persisted: run installation recover with the exact --store and --transaction-id to roll back CreatedByTransaction registrations"
                ),
            );
            INVALID_REQUEST_EXIT
        }
        Err(error) => {
            write_installation_error(
                "INSTALLATION_APPLY_RECOVERY_REQUIRED",
                &format!(
                    "{detail}; durable rejection could not be confirmed ({error}): recovery is required and rollback readiness is unknown"
                ),
            );
            INVALID_REQUEST_EXIT
        }
    }
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
        PackageStagingStage::KnownFolderPath => "known-folder-path",
        PackageStagingStage::CanonicalizePath => "canonicalize-path",
        PackageStagingStage::SymlinkMetadata => "symlink-metadata",
        PackageStagingStage::SetSecurityInfo => "set-security-info",
        PackageStagingStage::GetSecurityInfo => "get-security-info",
        PackageStagingStage::CreateFileW => "create-file-w",
        PackageStagingStage::FileMetadata => "file-metadata",
        PackageStagingStage::FlushFileBuffers => "flush-file-buffers",
        PackageStagingStage::GetFileInformationByHandle => "get-file-information-by-handle",
        PackageStagingStage::GetFinalPathNameByHandleW => "get-final-path-name-by-handle-w",
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

#[derive(Debug)]
enum AuthenticatedRuntimeHealthError {
    Unavailable(String),
    Invalid(String),
}

/// Decodes the exact owner-produced health carrier returned by the
/// authenticated Kernel front door. Deserialization alone is insufficient:
/// the consumer boundary must rerun the Kernel carrier invariants before the
/// evidence reaches the operator projection.
fn decode_authenticated_kernel_runtime_health(
    payload: serde_json::Value,
) -> std::result::Result<KernelRuntimeHealthEvidence, AuthenticatedRuntimeHealthError> {
    let evidence: KernelRuntimeHealthEvidence = serde_json::from_value(payload).map_err(|error| {
        AuthenticatedRuntimeHealthError::Invalid(format!(
            "authenticated Kernel health payload is not the canonical runtime-health carrier: {error}"
        ))
    })?;
    evidence.validate().map_err(|error| {
        AuthenticatedRuntimeHealthError::Invalid(format!(
            "authenticated Kernel health carrier failed canonical validation: {error}"
        ))
    })?;
    Ok(evidence)
}

#[cfg(windows)]
fn load_authenticated_kernel_runtime_health()
-> std::result::Result<KernelRuntimeHealthEvidence, AuthenticatedRuntimeHealthError> {
    let mut port = AuthenticatedKernelPort::load().map_err(|error| {
        AuthenticatedRuntimeHealthError::Unavailable(format!(
            "load authenticated Kernel health caller: {error}"
        ))
    })?;
    let payload = port.probe_runtime_health().map_err(|error| {
        AuthenticatedRuntimeHealthError::Unavailable(format!(
            "authenticated Kernel health probe did not produce an owner response: {error}"
        ))
    })?;
    decode_authenticated_kernel_runtime_health(payload)
}

#[cfg(not(windows))]
fn load_authenticated_kernel_runtime_health()
-> std::result::Result<KernelRuntimeHealthEvidence, AuthenticatedRuntimeHealthError> {
    Err(AuthenticatedRuntimeHealthError::Unavailable(
        "the authenticated Kernel health front door is Windows-only".to_owned(),
    ))
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

    fn probe_runtime_health(
        &mut self,
    ) -> std::result::Result<serde_json::Value, eliot_cli::kernel_client::KernelClientError> {
        self.client.probe()
    }

    /// Sends the exact `controlboard.status` operation through the
    /// authenticated EBP Execute seam and returns the served result payload.
    ///
    /// The EBP request identity must already be bound on the client by an
    /// admitted flow; this front door never mints principal, session, fence,
    /// or idempotency identity. Without one the call fails closed with
    /// `MissingRequestIdentity` before any byte is sent.
    fn transact_controlboard_status(
        &mut self,
    ) -> std::result::Result<serde_json::Value, eliot_cli::kernel_client::KernelClientError> {
        self.client.transact_json(
            controlboard_status::STATUS_OPERATION,
            controlboard_status::status_request_payload(),
        )
    }
}

#[cfg(windows)]
impl CommandPort for AuthenticatedKernelPort {
    fn dispatch(
        &mut self,
        request: &CommandRequest,
    ) -> Result<eliot_cli::CommandResponse, CommandPortError> {
        self.client.set_request_identity(request.request.clone());
        if request.command == eliot_cli::CommandId::UserAutomation {
            let payload = user_automation_route_payload(request)
                .map_err(|error| CommandPortError::Rejected(error.to_string()))?;
            let routed = self
                .client
                .transact_json(USER_AUTOMATION_ROUTE, payload)
                .map_err(|error| match error {
                    eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract) => {
                        CommandPortError::FrontDoorClosed { contract }
                    }
                    other => CommandPortError::Rejected(other.to_string()),
                })?;
            let spec = CommandCatalogue::current()
                .commands()
                .iter()
                .find(|spec| spec.id == request.command)
                .ok_or_else(|| {
                    CommandPortError::Rejected(
                        "UserAutomation command is not catalogued".to_owned(),
                    )
                })?;
            return Ok(eliot_cli::CommandResponse {
                request: request.request.clone(),
                command: request.command,
                effect: spec.effect,
                proof_ceiling: spec.proof_ceiling,
                result: eliot_cli::CommandResult::Forwarded { payload: routed },
            });
        }
        // The three advertised backup command IDs map one-to-one onto the
        // three closed Kernel backup operations. They never travel as a
        // generic `eliot.cli.command`: a payload that selects another
        // method, another owner, or a defaulted scope or destination is
        // refused by the typed surface and by the Kernel route.
        if matches!(
            request.command,
            eliot_cli::CommandId::BackupCreate
                | eliot_cli::CommandId::BackupVerify
                | eliot_cli::CommandId::BackupRestoreTest
        ) {
            return match request.command {
                eliot_cli::CommandId::BackupCreate => {
                    eliot_cli::backup::backup_create(&mut self.client, request)
                }
                eliot_cli::CommandId::BackupVerify => {
                    eliot_cli::backup::backup_verify(&mut self.client, request)
                }
                eliot_cli::CommandId::BackupRestoreTest => {
                    eliot_cli::backup::backup_restore_test(&mut self.client, request)
                }
                _ => Err(eliot_cli::backup::BackupClientError::Client(
                    eliot_cli::CliError::ArgumentCommandMismatch,
                )),
            }
            .map_err(|error| match error {
                eliot_cli::backup::BackupClientError::Transport(transport) => match transport {
                    eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract) => {
                        CommandPortError::FrontDoorClosed { contract }
                    }
                    other => CommandPortError::Rejected(other.to_string()),
                },
                eliot_cli::backup::BackupClientError::Client(client) => {
                    CommandPortError::Rejected(client.to_string())
                }
            });
        }
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

/// Returns the closed Kernel operation selector a backup catalogue command
/// routes to, or `None` when the command is not a backup command.
///
/// The mapping is one-to-one and closed: the CLI never names an owner, a
/// method the catalogue does not advertise, or a destination.
#[cfg(windows)]
fn backup_operation(command: eliot_cli::CommandId) -> Option<&'static str> {
    match command {
        eliot_cli::CommandId::BackupCreate => Some(eliot_cli::backup::BACKUP_CREATE_OPERATION),
        eliot_cli::CommandId::BackupVerify => Some(eliot_cli::backup::BACKUP_VERIFY_OPERATION),
        eliot_cli::CommandId::BackupRestoreTest => {
            Some(eliot_cli::backup::BACKUP_RESTORE_TEST_OPERATION)
        }
        _ => None,
    }
}

/// Renders the bounded human and JSON projections of one routed backup
/// command and returns its typed exit status.
///
/// Both projections are rendered from the same
/// [`eliot_cli::backup::BackupOperationOutcome`], so the bounded human text
/// and the JSON document cannot disagree. A verified outcome exits zero; an
/// invalid one exits as a usage failure; a refused or blocked one exits as
/// owner-admission-required. No exit status is ever a capture, verification,
/// or restore proof.
#[cfg(windows)]
fn render_backup_outcome(response: &eliot_cli::CommandResponse) -> Result<i32> {
    let eliot_cli::CommandResult::Forwarded { payload } = &response.result else {
        write_json_error(
            "BACKUP_RESULT_NOT_TYPED",
            "the backup route returned no typed outcome projection",
        );
        return Ok(INVALID_REQUEST_EXIT);
    };
    let outcome: eliot_cli::backup::BackupOperationOutcome =
        match serde_json::from_value(payload.clone()) {
            Ok(outcome) => outcome,
            Err(error) => {
                write_json_error("BACKUP_RESULT_NOT_TYPED", &error.to_string());
                return Ok(INVALID_REQUEST_EXIT);
            }
        };
    print!(
        "{}",
        eliot_cli::backup::render_backup_outcome_human(&outcome)
    );
    println!("{}", serde_json::to_string(&outcome)?);
    Ok(match outcome.state.as_str() {
        eliot_cli::backup::BACKUP_STATE_VERIFIED => 0,
        eliot_cli::backup::BACKUP_STATE_INVALID => INVALID_REQUEST_EXIT,
        _ => BACKUP_OWNER_ADMISSION_REQUIRED_EXIT,
    })
}

/// Maps one typed backup delegation failure onto its own bounded status.
///
/// The typed failures stay distinct across the layer boundary: a closed
/// front door, an unadmitted request identity, an unproven outcome, and a
/// typed argument or result mismatch are four different reports. An unproven
/// outcome is reported with the same-operation reconciliation instruction
/// and never with a second capture or restore.
#[cfg(windows)]
fn report_backup_failure(
    operation: &str,
    request: &CommandRequest,
    error: eliot_cli::backup::BackupClientError,
) -> Result<i32> {
    use eliot_cli::backup::BackupClientError;
    use eliot_cli::kernel_client::KernelClientError;

    match error {
        BackupClientError::Transport(KernelClientError::FrontDoorClosed(contract)) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            Ok(FRONT_DOOR_CLOSED_EXIT)
        }
        BackupClientError::Transport(KernelClientError::UnknownOutcome(detail)) => {
            let unknown =
                eliot_cli::backup::backup_unknown_outcome(operation, &request.request, &detail);
            print!(
                "{}",
                eliot_cli::backup::render_backup_unknown_human(&unknown)
            );
            println!("{}", serde_json::to_string(&unknown)?);
            Ok(UNKNOWN_OUTCOME_EXIT)
        }
        BackupClientError::Transport(KernelClientError::MissingRequestIdentity) => {
            write_json_error(
                "BACKUP_REQUEST_IDENTITY_NOT_ADMITTED",
                "no admitted EBP request identity is bound for this backup operation; the identity must arrive through the admitted host request path, and the CLI never mints one",
            );
            Ok(INVALID_REQUEST_EXIT)
        }
        BackupClientError::Transport(KernelClientError::RestartRequired(detail)) => {
            write_json_error("KERNEL_OPERATOR_RESTART_REQUIRED", &detail);
            Ok(RESTART_REQUIRED_EXIT)
        }
        BackupClientError::Transport(
            KernelClientError::Rejected(detail) | KernelClientError::Configuration(detail),
        ) => {
            write_json_error("BACKUP_OPERATION_REJECTED", &detail);
            Ok(INVALID_REQUEST_EXIT)
        }
        BackupClientError::Client(error) => {
            let (code, detail): (&str, String) = match error {
                eliot_cli::CliError::InvalidArgument { field } => (
                    "BACKUP_ARGUMENT_INVALID",
                    format!("bounded typed field {field} is missing, blank, oversized, or outside the closed vocabulary"),
                ),
                eliot_cli::CliError::ArgumentCommandMismatch => (
                    "BACKUP_COMMAND_ARGUMENT_MISMATCH",
                    "the typed arguments do not match the advertised backup command".to_owned(),
                ),
                eliot_cli::CliError::CorrelationMismatch => (
                    "BACKUP_CORRELATION_MISMATCH",
                    "the Kernel reply is not bound to this request's operation identity".to_owned(),
                ),
                eliot_cli::CliError::ResultMismatch => (
                    "BACKUP_RESULT_NOT_TYPED",
                    "the Kernel reply does not carry the exact typed domain result for this operation"
                        .to_owned(),
                ),
                other => ("BACKUP_REQUEST_REJECTED", other.to_string()),
            };
            write_json_error(code, &detail);
            Ok(INVALID_REQUEST_EXIT)
        }
    }
}

/// Routes one backup catalogue command through the authenticated Kernel
/// front door and renders both projections of the same typed result.
///
/// The Kernel client is the one already used by every other authenticated
/// front door in this binary: this creates no second transport and no second
/// client. The bounded typed arguments were admitted locally by the closed
/// parsers, the correlated request identity came from the admitted host
/// request path, and the domain outcome comes back as a typed result or as a
/// distinct typed failure — never as a fabricated success.
#[cfg(windows)]
fn dispatch_backup_command(request: &CommandRequest) -> Result<i32> {
    use eliot_cli::CliError;
    use eliot_cli::backup::{BackupClientError, backup_create, backup_restore_test, backup_verify};

    let Some(operation) = backup_operation(request.command) else {
        write_json_error(
            "BACKUP_COMMAND_UNKNOWN",
            "the requested command is not one of the three advertised backup commands",
        );
        return Ok(INVALID_REQUEST_EXIT);
    };
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
    let routed = match request.command {
        eliot_cli::CommandId::BackupCreate => backup_create(&mut port.client, request),
        eliot_cli::CommandId::BackupVerify => backup_verify(&mut port.client, request),
        eliot_cli::CommandId::BackupRestoreTest => backup_restore_test(&mut port.client, request),
        _ => Err(BackupClientError::Client(CliError::ArgumentCommandMismatch)),
    };
    match routed {
        Ok(response) => render_backup_outcome(&response),
        Err(error) => report_backup_failure(operation, request, error),
    }
}

/// Non-Windows builds have no authenticated Windows Kernel front door, so
/// no backup operation is ever admitted there.
#[cfg(not(windows))]
fn dispatch_backup_command(_request: &CommandRequest) -> Result<i32> {
    write_json_error(
        "KERNEL_APPLICATION_PORT_CLOSED",
        "Windows authenticated Kernel front door",
    );
    Ok(FRONT_DOOR_CLOSED_EXIT)
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

    #[test]
    fn runtime_status_caller_rejects_untyped_kernel_health_payload() {
        let error = decode_authenticated_kernel_runtime_health(json!({ "status": "OPEN" }))
            .expect_err("an incomplete payload must not reach operator status");
        assert!(matches!(
            error,
            AuthenticatedRuntimeHealthError::Invalid(detail)
                if detail.contains("canonical runtime-health carrier")
        ));
    }

    #[test]
    fn command_tree_is_valid_and_catalogue_help_text_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let parsed = Cli::try_parse_from(["eliot", "catalogue", "help-text"])
            .expect("catalogue help-text parses");
        assert!(matches!(
            parsed.command,
            Command::Catalogue {
                command: CatalogueCommand::Help
            }
        ));
    }

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

    #[test]
    fn plugin_preview_and_install_parse() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let parsed = Cli::try_parse_from([
            "eliot",
            "plugin",
            "preview",
            "--manifest",
            "C:\\eliot\\manifest.json",
            "--rollback-dir",
            "C:\\eliot\\rollback",
        ])
        .expect("plugin preview parses");
        assert!(matches!(
            parsed.command,
            Command::Plugin {
                command: PluginCommand::Preview { .. }
            }
        ));
        let parsed = Cli::try_parse_from([
            "eliot",
            "plugin",
            "install",
            "--manifest",
            "C:\\eliot\\manifest.json",
            "--rollback-dir",
            "C:\\eliot\\rollback",
        ])
        .expect("plugin install parses");
        assert!(matches!(
            parsed.command,
            Command::Plugin {
                command: PluginCommand::Install { .. }
            }
        ));
    }

    #[test]
    fn doctor_integration_parses() {
        let parsed = Cli::try_parse_from([
            "eliot",
            "doctor",
            "integration",
            "demo",
            "--expectation",
            "C:\\eliot\\expectation.json",
            "--observation",
            "C:\\eliot\\observation.json",
        ])
        .expect("doctor integration parses");
        assert!(matches!(
            parsed.command,
            Command::Doctor {
                command: DoctorCommand::Integration { .. }
            }
        ));
    }

    #[test]
    fn plugin_install_without_admitted_port_exits_nonsuccess() {
        // End-to-end CLI honesty: a valid manifest still cannot produce an
        // installed-success result without an admitted mutation port.
        let root =
            std::env::temp_dir().join(format!("eliot-plugin-install-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let target = root.join("config.json");
        std::fs::write(&target, b"{\"bridge\":\"demo\"}").expect("write target");
        let manifest_path = root.join("manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "plugin_id": "demo-bridge",
                "profile": "demo",
                "files_to_modify": [target.display().to_string()],
                "config_block": "{\"bridge\":\"demo\"}",
                "hooks": ["on_task"],
                "mcp_server": "demo-mcp",
                "tool_count": 3,
                "skill_count": 2,
                "expected_coverage": {
                    "profile": "demo",
                    "expected_file_hashes": {},
                    "expected_registrations": ["demo-mcp"],
                    "expected_hook_events": ["on_task"],
                },
            }))
            .expect("serialize manifest"),
        )
        .expect("write manifest");
        let rollback_dir = root.join("rollback");
        let code = run_plugin(PluginCommand::Install {
            manifest: manifest_path.clone(),
            rollback_dir: rollback_dir.clone(),
        })
        .expect("install front door executes");
        assert_eq!(code, INVALID_REQUEST_EXIT);
        let receipt_path = rollback_dir.join("demo-bridge.installed.json");
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt_path).expect("read install receipt"))
                .expect("parse install receipt");
        assert_eq!(receipt["status"], "INSTALL_NOT_ATTEMPTED");
        assert_eq!(receipt["code"], "PLAN_GAP");
        assert_eq!(receipt["completed"], false);
        // The target itself is untouched: no mutation occurred.
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"{\"bridge\":\"demo\"}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn controlboard_status_parses() {
        let parsed = Cli::try_parse_from(["eliot", "controlboard", "status"])
            .expect("controlboard status parses");
        assert!(matches!(
            parsed.command,
            Command::ControlBoard {
                command: ControlBoardCommand::Status
            }
        ));
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
    fn package_staging_stage_names_are_canonical_and_exhaustive() {
        for (stage, expected) in [
            (PackageStagingStage::KnownFolderPath, "known-folder-path"),
            (PackageStagingStage::CanonicalizePath, "canonicalize-path"),
            (PackageStagingStage::SymlinkMetadata, "symlink-metadata"),
            (PackageStagingStage::SetSecurityInfo, "set-security-info"),
            (PackageStagingStage::GetSecurityInfo, "get-security-info"),
            (PackageStagingStage::CreateFileW, "create-file-w"),
            (PackageStagingStage::FileMetadata, "file-metadata"),
            (PackageStagingStage::FlushFileBuffers, "flush-file-buffers"),
            (
                PackageStagingStage::GetFileInformationByHandle,
                "get-file-information-by-handle",
            ),
            (
                PackageStagingStage::GetFinalPathNameByHandleW,
                "get-final-path-name-by-handle-w",
            ),
            (PackageStagingStage::DuplicateHandle, "duplicate-handle"),
            (PackageStagingStage::SetFilePointerEx, "set-file-pointer-ex"),
            (PackageStagingStage::ReadFile, "read-file"),
            (PackageStagingStage::WriteFile, "write-file"),
        ] {
            assert_eq!(package_staging_stage_name(stage), expected);
        }
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
