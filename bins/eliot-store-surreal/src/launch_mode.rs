#![forbid(unsafe_code)]

//! Launch mode cell for `eliot-store-surreal`.
//!
//! Architecture: `A12.3` (`docs/architecture/A12-03-one-governed-write-path.md`)
//! and `A13.2` (`docs/architecture/A13-02-kernel-and-failure-domains.md`), plus
//! Decision Anchors `docs/architecture/A16-01-decision-anchors.md`
//! `ARCH-AUTH-01`, `ARCH-SEC-02`, and `ARCH-RES-01`. Implementation: `I5`
//! (`docs/architecture/I05-storage-and-canonical-memory.md`), the Kernel-Store
//! storage boundary `I5.1` (`docs/architecture/I05-01-storage-boundary.md`), and
//! `I2.23`
//! (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`).
//! Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This cell owns closed launch-mode parsing, launch preparation routing,
//! portable-dev clock observation, and control-frame construction only. It
//! forbids dispatcher, provider, tests, and root main lifecycle.

use std::path::PathBuf;

#[cfg(windows)]
use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId};
#[cfg(windows)]
use eliot_platform::{ClockObservation, ClockPort, ClockRequest, PortOutcome};
#[cfg(windows)]
use eliot_platform_windows::WindowsPlatform;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
#[cfg(windows)]
use eliot_store_surreal::{
    SERVICE_NAME, StoreComposition, StoreLaunchConfig, load_config, load_portable_dev_config,
    load_user_mode_config,
};

#[derive(Debug, Eq, PartialEq)]
pub(super) enum LaunchMode {
    Protected {
        config_path: PathBuf,
    },
    UserMode {
        root: PathBuf,
        config_path: PathBuf,
    },
    PortableDev {
        root: PathBuf,
        config_path: PathBuf,
        initialize_schema_only: bool,
    },
    /// One-shot `ECXF/1` export for a single declared scope (issue #1871).
    ///
    /// It is a portable-dev launch, not a service launch, for the same reason
    /// `initialize_schema_only` is: the export reads the canonical source
    /// through the store owner this process composes itself, so it must not
    /// adopt or become the long-running writer, and it must not be reachable
    /// from the production service profile where it could contend with a live
    /// provider. The `--export-ecxf` form carries the operator's declared
    /// export id, declared scope, canonical request hash and absolute
    /// destination; the export fence itself is observed inside the store's
    /// single capture transaction, never taken from argv.
    ExportEcxf {
        root: PathBuf,
        config_path: PathBuf,
        export_id: String,
        scope_id: String,
        canonical_request_hash: String,
        out_dir: PathBuf,
    },
    EmitBootstrapDescriptor {
        config_path: PathBuf,
        output_path: PathBuf,
    },
}

pub(super) struct PreparedLaunch {
    pub config: StoreLaunchConfig,
    pub user_mode_root_lease: Option<eliot_platform_windows::UserOwnedRootLease>,
}

#[cfg(windows)]
#[allow(clippy::print_stdout)]
pub(super) async fn prepare_launch(mode: LaunchMode) -> Result<Option<PreparedLaunch>, String> {
    match mode {
        LaunchMode::EmitBootstrapDescriptor { .. } => {
            Err("descriptor emission must be handled before Store composition launch".to_owned())
        }
        LaunchMode::Protected { config_path } => {
            let config = load_config(Some(&config_path))?;
            if config.runtime_launch.profile
                != eliot_installation::InstallationProfile::SystemService
            {
                return Err("protected --config launch requires SystemService profile".to_owned());
            }
            Ok(Some(PreparedLaunch {
                config,
                user_mode_root_lease: None,
            }))
        }
        LaunchMode::UserMode { root, config_path } => {
            let (root_lease, config) = resolve_user_mode_config(&root, config_path)?;
            Ok(Some(PreparedLaunch {
                config,
                user_mode_root_lease: Some(root_lease),
            }))
        }
        LaunchMode::PortableDev {
            root,
            config_path,
            initialize_schema_only,
        } => {
            // The lease stays bound for the whole arm; dropping it at once would
            // release the root this launch resolved its config through.
            let (_root_lease, config) = resolve_portable_dev_config(&root, config_path)?;
            if initialize_schema_only {
                // Schema initialization is a provider write, so it must pass
                // the same installation-visible compatibility gate as the
                // long-running canonical writer before the provider starts. A
                // maintenance verdict refuses the mode with the exact report:
                // maintenance authority never migrates an unqualified
                // generation.
                let composition = StoreComposition::new(&config)?;
                let _root_use = composition
                    .retain_roots_for_use()
                    .map_err(|error| format!("revalidate Store roots: {error}"))?;
                super::require_writer_admission(&config)?;
                composition.connect().await?;
                // Bind the recorded decision to the connected provider's live
                // identity before allowing the migration to mutate its schema.
                super::require_writer_admission(&config)?;
                super::bind_observed_identity(&composition, &config)?;
                let clock = read_portable_dev_clock(&config)?;
                let receipt = composition
                    .apply_initial_schema_migration(&clock)
                    .await
                    .map_err(|error| error.to_string())?;
                let output = serde_json::json!({
                    "service": SERVICE_NAME,
                    "operation": "initialize_schema_only",
                    "migration_id": receipt.migration_id,
                    "checksum_sha256": receipt.checksum_sha256,
                    "generation_after": receipt.generation_after.as_str(),
                });
                println!(
                    "{}",
                    serde_json::to_string(&output)
                        .map_err(|error| format!("serialize migration receipt: {error}"))?
                );
                return Ok(None);
            }
            Ok(Some(PreparedLaunch {
                config,
                user_mode_root_lease: None,
            }))
        }
        LaunchMode::ExportEcxf {
            root,
            config_path,
            export_id,
            scope_id,
            canonical_request_hash,
            out_dir,
        } => {
            // The lease stays bound for the whole arm; `_` would drop it at
            // once and release the root this export is reading through.
            let (_root_lease, config) = resolve_portable_dev_config(&root, config_path)?;
            // The export reads the closed canonical source through this
            // process's own store owner, so it passes the same installation
            // gates the portable-dev one-shot does: the compatibility decision
            // before the provider starts, and the observed provider identity
            // after it connects. Without the identity binding the recorded
            // `source_adapter_version` of an archive would describe a binary
            // nobody verified.
            let composition = StoreComposition::new(&config)?;
            let _root_use = composition
                .retain_roots_for_use()
                .map_err(|error| format!("revalidate Store roots: {error}"))?;
            super::require_writer_admission(&config)?;
            composition.connect().await?;
            super::require_writer_admission(&config)?;
            super::bind_observed_identity(&composition, &config)?;
            let clock = read_portable_dev_clock(&config)?;
            eliot_store_surreal::export_ecxf_once(
                &composition,
                &config,
                &clock,
                &eliot_store_surreal::EcxfExportArgs {
                    export_id,
                    scope_id,
                    canonical_request_hash,
                    out_dir,
                },
            )
            .await?;
            Ok(None)
        }
    }
}

/// Resolves one portable-dev root lease and the launch config beside it.
///
/// The lease is returned with the config because it is the validated handle the
/// config was resolved through: dropping it before the provider work would
/// release the root this launch is bound to. A relative config path resolves
/// inside the leased root, never against the process current directory.
#[cfg(windows)]
fn resolve_portable_dev_config(
    root: &std::path::Path,
    config_path: PathBuf,
) -> Result<
    (
        eliot_platform_windows::UserOwnedRootLease,
        eliot_store_surreal::StoreLaunchConfig,
    ),
    String,
> {
    let root = eliot_platform_windows::UserOwnedRootLease::open_existing(root)
        .map_err(|error| format!("open portable-dev root: {error}"))?;
    let config_path = if config_path.is_absolute() {
        config_path
    } else {
        root.path().join(config_path)
    };
    let config = load_portable_dev_config(&root, &config_path)?;
    if config.runtime_launch.profile != eliot_installation::InstallationProfile::PortableDev {
        return Err("portable-dev launch config does not select PortableDev profile".to_owned());
    }
    Ok((root, config))
}

/// Resolves an explicit `UserMode` immutable-binaries root lease and loads its
/// materialized Store config through a no-follow file lease. The loaded
/// descriptor must bind the same root in its I3.1 profile selection.
#[cfg(windows)]
fn resolve_user_mode_config(
    root: &std::path::Path,
    config_path: PathBuf,
) -> Result<
    (
        eliot_platform_windows::UserOwnedRootLease,
        StoreLaunchConfig,
    ),
    String,
> {
    let root = eliot_platform_windows::UserOwnedRootLease::open_existing(root)
        .map_err(|error| format!("open UserMode immutable-binaries root: {error}"))?;
    let config_path = if config_path.is_absolute() {
        config_path
    } else {
        root.path().join(config_path)
    };
    let config = load_user_mode_config(&root, &config_path)?;
    Ok((root, config))
}

#[cfg(windows)]
fn read_portable_dev_clock(config: &StoreLaunchConfig) -> Result<ClockObservation, String> {
    let request = ClockRequest {
        context: RequestMetadata {
            request_id: RequestId::new(format!(
                "portable-dev-schema-init-{}-{}",
                config.instance_id, config.launch_nonce
            ))
            .map_err(|error| format!("invalid clock request id: {error}"))?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new(SERVICE_NAME)
                .map_err(|error| format!("invalid clock product id: {error}"))?,
            source_id: SourceId::new(config.instance_id.clone())
                .map_err(|error| format!("invalid clock source id: {error}"))?,
            state_fence: config.runtime_launch.authority_state_fence.clone(),
            clock: ClockReading::default(),
        },
    };
    let mut platform = WindowsPlatform::new(config.blob_root.clone())
        .map_err(|error| format!("initialize P-01 clock platform: {error}"))?;
    match platform.read(&request) {
        PortOutcome::Known(observation) => {
            observation
                .validate()
                .map_err(|error| format!("invalid P-01 clock observation: {error}"))?;
            Ok(observation)
        }
        PortOutcome::Partial { .. } => Err("P-01 clock observation was partial".to_owned()),
        PortOutcome::Unknown(reason) => Err(format!("P-01 clock observation unknown: {reason}")),
        PortOutcome::Error(error) => Err(format!("P-01 clock observation failed: {error}")),
    }
}

/// Supported launch forms are deliberately closed:
///
/// - `eliot-store-surreal --config <protected .json or .toml path>`
/// - `eliot-store-surreal --user-mode-root <absolute existing immutable-binaries root> --config <path>`
/// - `eliot-store-surreal --emit-bootstrap-descriptor <config path> <descriptor path>`
/// - `eliot-store-surreal --portable-dev-root <absolute existing root> --config <path>`
/// - `eliot-store-surreal --portable-dev-root <absolute existing root> --config <path> --initialize-schema-only`
/// - `eliot-store-surreal --portable-dev-root <absolute existing root> --config <path> --export-ecxf <export id> <scope id> <canonical request hash> <absolute destination>`
pub(super) fn parse_launch_mode<I>(args: I) -> Result<LaunchMode, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut args = args.into_iter();
    match args.next() {
        None => Err("--config is required; launch config must be explicit".to_owned()),
        Some(value) if value == "--emit-bootstrap-descriptor" => {
            let config_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--emit-bootstrap-descriptor requires a config path".to_owned())?;
            let output_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--emit-bootstrap-descriptor requires an output path".to_owned())?;
            if args.next().is_some() {
                return Err("--emit-bootstrap-descriptor requires exactly two paths".to_owned());
            }
            Ok(LaunchMode::EmitBootstrapDescriptor {
                config_path,
                output_path,
            })
        }
        Some(value) if value == "--config" => match args.next() {
            Some(path) if args.next().is_none() => Ok(LaunchMode::Protected {
                config_path: PathBuf::from(path),
            }),
            _ => Err("--config requires exactly one path".to_owned()),
        },
        Some(value) if value == "--user-mode-root" => {
            let root = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--user-mode-root requires one root path".to_owned())?;
            if !root.is_absolute() {
                return Err("--user-mode-root requires an absolute root path".to_owned());
            }
            if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
                return Err(
                    "UserMode launch requires --config immediately after the root".to_owned(),
                );
            }
            let config_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--config requires exactly one path".to_owned())?;
            if args.next().is_some() {
                return Err("UserMode launch accepts exactly one config path".to_owned());
            }
            Ok(LaunchMode::UserMode { root, config_path })
        }
        Some(value) if value == "--portable-dev-root" => {
            let root = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--portable-dev-root requires one root path".to_owned())?;
            if !root.is_absolute() {
                return Err("--portable-dev-root requires an absolute root path".to_owned());
            }
            if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
                return Err(
                    "portable-dev launch requires --config immediately after the root".to_owned(),
                );
            }
            let config_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--config requires exactly one path".to_owned())?;
            let initialize_schema_only = match args.next() {
                None => false,
                Some(flag) if flag == "--initialize-schema-only" && args.next().is_none() => true,
                Some(flag) if flag == "--export-ecxf" => {
                    let (export_id, scope_id, canonical_request_hash, out_dir) =
                        parse_export_ecxf(&mut args)?;
                    return Ok(LaunchMode::ExportEcxf {
                        root,
                        config_path,
                        export_id,
                        scope_id,
                        canonical_request_hash,
                        out_dir,
                    });
                }
                Some(_) => {
                    return Err(
                        "portable-dev launch accepts only --initialize-schema-only or --export-ecxf after --config"
                            .to_owned(),
                    );
                }
            };
            Ok(LaunchMode::PortableDev {
                root,
                config_path,
                initialize_schema_only,
            })
        }
        Some(value) => Err(format!("unknown argument: {}", value.to_string_lossy())),
    }
}

/// Decodes the exact `--export-ecxf <export id> <scope id> <canonical request
/// hash> <destination>` argument tail.
///
/// The form is positional and closed, exactly like
/// `--emit-bootstrap-descriptor <config path> <descriptor path>`: a missing,
/// extra, or non-absolute member refuses the launch instead of being defaulted.
/// The destination must be absolute here as well as inside the command, so a
/// launch never resolves a package destination against whatever current
/// directory the process happened to inherit.
fn parse_export_ecxf<I>(args: &mut I) -> Result<(String, String, String, PathBuf), String>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let export_id = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| "--export-ecxf requires an export id".to_owned())?;
    let scope_id = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| "--export-ecxf requires a declared scope id".to_owned())?;
    let canonical_request_hash = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| "--export-ecxf requires the canonical request hash".to_owned())?;
    let out_dir = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "--export-ecxf requires an absolute destination path".to_owned())?;
    if !out_dir.is_absolute() {
        return Err("--export-ecxf requires an absolute destination path".to_owned());
    }
    if args.next().is_some() {
        return Err("--export-ecxf requires exactly four arguments".to_owned());
    }
    Ok((export_id, scope_id, canonical_request_hash, out_dir))
}

pub(super) fn control_frame(
    connection_id: &str,
    protocol_version: ProtocolVersion,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Frame {
    Frame {
        protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.to_owned(),
        request_id: None,
        kind: FrameKind::Control,
        message_type,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    }
}
