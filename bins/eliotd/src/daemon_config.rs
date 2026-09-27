//! Protected daemon config boundary — bounded thin binary cell.
//! Architecture: A2.3 (Governor/N4 composition), A13.2 (Kernel/Governor authenticated IPC boundary).
//! Implementation: I1.11 (`FunctionalCapabilityCell`), I2.1 (bounded cell), boundary-owner validation, thin binary config.
//! Boundary owns protected config path/bytes, nonce, runtime identity and binding validation only; no Kernel, Store, SCM, lifecycle, effect, or canonical authority.
//! It also resolves the effective canonical configuration while loading the launch file and refuses a configuration that does not resolve; that resolution validates typed input and grants no authority of its own.

use std::path::{Path, PathBuf};

use eliot_contracts::{StateFence, sha256_hex};
use eliot_governor::GovernorLaunchConfig;
use eliot_platform_windows::{
    ProtectedRuntimePathLease, current_process_named_pipe_expectation, protected_program_data_path,
};

use super::canonical_config_precedence::{
    PolicyDocument, ResolvedChain, resolve_effective_configuration,
};
use super::{DaemonError, KERNEL_PIPE_NAME, KernelLaunchBinding, MAX_CONFIG_BYTES};

/// I3.9 installation config file, relative to the protected `ProgramData` root.
const INSTALLATION_CONFIG_RELATIVE: &str = r"Eliot\config\installation.toml";

/// I3.9 System Owner policy file, relative to the protected `ProgramData` root.
const SYSTEM_OWNER_POLICY_RELATIVE: &str = r"Eliot\config\policy.toml";

fn observed_runtime_identity() -> Result<(String, u32), DaemonError> {
    let expectation = current_process_named_pipe_expectation()
        .map_err(|error| DaemonError::Kernel(format!("observe LocalService identity: {error}")))?;
    Ok((
        expectation.expected_sid().to_owned(),
        expectation.expected_session_id(),
    ))
}

/// Resolves the effective canonical configuration from the I3.9 typed
/// configuration files under the protected `ProgramData` root.
///
/// Each file is read through a protected path lease, so the platform owner
/// refuses a reparse or out-of-root document before it is parsed. A file that
/// is not present means its layer abstains and the next broader value carries
/// forward; any other presence failure refuses the load, because an unreadable
/// policy file must never be read as an absent one. A script, an untyped file,
/// an unknown or duplicated layer, and a lower-layer expansion that no higher
/// layer delegated all fail this function.
fn resolve_effective_canonical_config() -> Result<ResolvedChain, DaemonError> {
    let mut retained: Vec<(&str, Vec<u8>)> = Vec::new();
    for relative in [INSTALLATION_CONFIG_RELATIVE, SYSTEM_OWNER_POLICY_RELATIVE] {
        let path = protected_program_data_path(relative)?;
        match path.try_exists() {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => {
                return Err(DaemonError::LaunchConfig(format!(
                    "canonical layer document presence is unreadable for {relative}: {error}"
                )));
            }
        }
        let lease = ProtectedRuntimePathLease::open_existing_absolute(&path)?;
        if lease.path() != path {
            return Err(DaemonError::LaunchConfig(
                "canonical layer document path is not the retained canonical runtime identity"
                    .to_owned(),
            ));
        }
        retained.push((relative, lease.read_bounded(MAX_CONFIG_BYTES)?));
    }
    let documents: Vec<PolicyDocument<'_>> = retained
        .iter()
        .map(|(file_name, bytes)| PolicyDocument {
            file_name,
            bytes: bytes.as_slice(),
        })
        .collect();
    resolve_effective_configuration(&documents)
        .map_err(|error| DaemonError::LaunchConfig(error.to_string()))
}

/// Typed protected launch inputs. Production values are read from the exact
/// Host-approved runtime path and retained by a protected lease; environment
/// variables, current directory and arbitrary caller paths are not authority
/// sources.
#[derive(Debug)]
pub struct DaemonConfig {
    pub(super) launch: GovernorLaunchConfig,
    pub(super) config_path: PathBuf,
    pub(super) state_root: PathBuf,
    pub(super) config_lease: Option<ProtectedRuntimePathLease>,
    pub(super) kernel_binding: KernelLaunchBinding,
    pub(super) canonical_chain: ResolvedChain,
}

impl DaemonConfig {
    /// Loads the Host-approved launch file through a bounded protected read.
    pub fn load_protected() -> Result<Self, DaemonError> {
        let config_path = protected_program_data_path(super::PROTECTED_CONFIG_RELATIVE)?;
        let config_lease = ProtectedRuntimePathLease::open_existing_absolute(&config_path)?;
        if config_lease.path() != config_path {
            return Err(DaemonError::LaunchConfig(
                "launch config path is not the retained canonical runtime identity".to_owned(),
            ));
        }
        let bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        let launch: GovernorLaunchConfig = serde_json::from_slice(&bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        let mut config = Self::from_launch(launch, config_path)?;
        config.config_lease = Some(config_lease);
        Ok(config)
    }

    /// Loads the exact Host-approved daemon descriptor binding. The path,
    /// bytes, public launch correlation, and module artifact are all checked
    /// before the config can become a Kernel client binding.
    pub fn load_protected_bound(
        config_path: impl AsRef<Path>,
        expected_config_sha256: &str,
        launch_nonce: &str,
        expected_artifact_sha256: &str,
    ) -> Result<Self, DaemonError> {
        // #740: config-boundary span. Records the outcome plus a bounded
        // reason only; digests, nonces and file bytes never enter the sink.
        let _span = tracing::info_span!("eliotd.config_load").entered();
        let outcome: Result<Self, DaemonError> = (|| {
            let config_path = config_path.as_ref().to_path_buf();
            if !config_path.is_absolute() {
                return Err(DaemonError::LaunchConfig(
                    "launch config path must be an absolute approved runtime identity".to_owned(),
                ));
            }
            validate_sha256(expected_config_sha256, "config descriptor digest")?;
            validate_sha256(expected_artifact_sha256, "executable digest")?;
            validate_launch_nonce(launch_nonce)?;
            let config_lease = ProtectedRuntimePathLease::open_existing_absolute(&config_path)?;
            if config_lease.path() != config_path {
                return Err(DaemonError::LaunchConfig(
                    "launch config path is not the retained canonical runtime identity".to_owned(),
                ));
            }
            let bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
            if sha256_hex(&bytes) != expected_config_sha256 {
                return Err(DaemonError::LaunchConfig(
                    "launch config digest does not match the retained bytes".to_owned(),
                ));
            }
            let launch: GovernorLaunchConfig = serde_json::from_slice(&bytes)
                .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
            let mut config = Self::from_launch_with_binding(
                launch,
                config_path,
                launch_nonce,
                expected_artifact_sha256,
            )?;
            config.config_lease = Some(config_lease);
            Ok(config)
        })();
        // #740: owning error record at the config boundary. Success needs no
        // record beyond the span: digests, nonces and bytes stay out.
        if let Err(error) = &outcome {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(error).emit();
        }
        outcome
    }

    /// Creates a config only for the exact protected path used by production.
    /// This constructor is also useful to tests that provide a protected
    /// fixture; it rejects arbitrary roots before composition.
    pub fn from_launch(
        launch: GovernorLaunchConfig,
        config_path: PathBuf,
    ) -> Result<Self, DaemonError> {
        launch.validate()?;
        if !config_path.is_absolute() {
            return Err(DaemonError::LaunchConfig(
                "launch config path must be an absolute approved runtime identity".to_owned(),
            ));
        }
        let state_root = config_path
            .parent()
            .ok_or_else(|| {
                DaemonError::LaunchConfig(
                    "launch config path has no approved runtime parent".to_owned(),
                )
            })?
            .join("state");
        let (expected_kernel_sid, expected_kernel_session_id) = observed_runtime_identity()?;
        let kernel_binding = KernelLaunchBinding {
            kernel_pipe_name: KERNEL_PIPE_NAME.to_owned(),
            expected_kernel_sid,
            expected_kernel_session_id,
            module_generation: launch.kernel.generation,
            authority_epoch: launch.kernel.authority_epoch.clone(),
            state_fence: StateFence::new(
                launch.kernel.authority_epoch.clone(),
                launch.kernel.generation,
            ),
            launch_nonce: format!("eliotd:{}", launch.instance_id),
            kernel_artifact_sha256: launch.kernel.artifact_digest.clone(),
            daemon_artifact_sha256: launch.kernel.artifact_digest.clone(),
        };
        Ok(Self {
            launch,
            config_path,
            state_root,
            config_lease: None,
            kernel_binding,
            canonical_chain: resolve_effective_canonical_config()?,
        })
    }

    pub(super) fn from_launch_with_binding(
        launch: GovernorLaunchConfig,
        config_path: PathBuf,
        launch_nonce: &str,
        expected_artifact_sha256: &str,
    ) -> Result<Self, DaemonError> {
        launch.validate()?;
        validate_launch_nonce(launch_nonce)?;
        validate_sha256(expected_artifact_sha256, "executable digest")?;
        let state_root = config_path
            .parent()
            .ok_or_else(|| {
                DaemonError::LaunchConfig(
                    "launch config path has no approved runtime parent".to_owned(),
                )
            })?
            .join("state");
        let (expected_kernel_sid, expected_kernel_session_id) = observed_runtime_identity()?;
        let kernel_binding = KernelLaunchBinding {
            kernel_pipe_name: KERNEL_PIPE_NAME.to_owned(),
            expected_kernel_sid,
            expected_kernel_session_id,
            module_generation: launch.kernel.generation,
            authority_epoch: launch.kernel.authority_epoch.clone(),
            state_fence: StateFence::new(
                launch.kernel.authority_epoch.clone(),
                launch.kernel.generation,
            ),
            launch_nonce: launch_nonce.to_owned(),
            // The daemon child artifact is a separate domain from the
            // KernelGenerationExpectation artifact. The former is supplied by
            // the exact launch descriptor; the latter remains the Kernel
            // peer/generation snapshot identity.
            kernel_artifact_sha256: launch.kernel.artifact_digest.clone(),
            daemon_artifact_sha256: expected_artifact_sha256.to_owned(),
        };
        Ok(Self {
            launch,
            config_path,
            state_root,
            config_lease: None,
            kernel_binding,
            canonical_chain: resolve_effective_canonical_config()?,
        })
    }

    /// Returns the immutable Host-approved launch config.
    #[must_use]
    pub const fn launch(&self) -> &GovernorLaunchConfig {
        &self.launch
    }

    /// Returns the effective canonical configuration: the winning value of the
    /// resolved setting chain and each contributing layer in canonical
    /// precedence order.
    #[must_use]
    pub const fn canonical_chain(&self) -> &ResolvedChain {
        &self.canonical_chain
    }

    /// Returns the retained protected config identity path.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the protected daemon state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
}

fn validate_sha256(value: &str, label: &str) -> Result<(), DaemonError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DaemonError::LaunchConfig(format!(
            "{label} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_launch_nonce(value: &str) -> Result<(), DaemonError> {
    let Some(suffix) = value.strip_prefix("eliotd:") else {
        return Err(DaemonError::LaunchConfig(
            "launch nonce must use the opaque eliotd correlation format".to_owned(),
        ));
    };
    if suffix.len() < 32
        || suffix.len() > 120
        || suffix
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':')))
    {
        return Err(DaemonError::LaunchConfig(
            "launch nonce must be bounded opaque text with at least 32 safe bytes".to_owned(),
        ));
    }
    Ok(())
}
