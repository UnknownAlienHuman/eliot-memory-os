#![forbid(unsafe_code)]

//! Launch mode cell for `eliot-store-surreal`.
//!
//! Architecture (verified):
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A12.3`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A13.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-AUTH-01`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-SEC-02`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-RES-01`
//!
//! Implementation (verified):
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I5`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.B.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.23`
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
};

#[derive(Debug, Eq, PartialEq)]
pub(super) enum LaunchMode {
    Protected {
        config_path: PathBuf,
    },
    PortableDev {
        root: PathBuf,
        config_path: PathBuf,
        initialize_schema_only: bool,
    },
    EmitBootstrapDescriptor {
        config_path: PathBuf,
        output_path: PathBuf,
    },
}

#[cfg(windows)]
#[allow(clippy::print_stdout)]
pub(super) async fn prepare_launch(mode: LaunchMode) -> Result<Option<StoreLaunchConfig>, String> {
    match mode {
        LaunchMode::EmitBootstrapDescriptor { .. } => {
            Err("descriptor emission must be handled before Store composition launch".to_owned())
        }
        LaunchMode::Protected { config_path } => load_config(Some(&config_path)).map(Some),
        LaunchMode::PortableDev {
            root,
            config_path,
            initialize_schema_only,
        } => {
            let root = eliot_platform_windows::UserOwnedRootLease::open_existing(&root)
                .map_err(|error| format!("open portable-dev root: {error}"))?;
            let config_path = if config_path.is_absolute() {
                config_path
            } else {
                root.path().join(config_path)
            };
            let config = load_portable_dev_config(&root, &config_path)?;
            if initialize_schema_only {
                let composition = StoreComposition::new(&config)?;
                composition.connect().await?;
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
            Ok(Some(config))
        }
    }
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
/// - `eliot-store-surreal --emit-bootstrap-descriptor <config path> <descriptor path>`
/// - `eliot-store-surreal --portable-dev-root <absolute existing root> --config <path>`
/// - `eliot-store-surreal --portable-dev-root <absolute existing root> --config <path> --initialize-schema-only`
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
                Some(_) => {
                    return Err(
                        "portable-dev launch accepts only --initialize-schema-only after --config"
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
