//! Production N4 Governor daemon composition root.
//!
//! `eliotd` owns application scheduling and the pure Governor projections. It
//! does not own a Kernel, a canonical store client, a store adapter, or a
//! physical process executor. Canonical transitions leave this process only
//! through the neutral authenticated [`KernelTransitionPort`].

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_governor::{
    CompositionError, CompositionReadiness, GovernorComposition, GovernorLaunchConfig,
    KernelGenerationPort, QueueLimits,
};
use eliot_platform_windows::{
    ProtectedPathError, ProtectedPathLease, prepare_protected_directory,
    protected_program_data_path,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable daemon identity.
pub const SERVICE_NAME: &str = "eliotd";
/// Stable daemon protocol revision.
pub const PROTOCOL_VERSION: &str = "eliot.daemon.v1";
/// Protected Host-approved launch configuration relative to `ProgramData`.
pub const PROTECTED_CONFIG_RELATIVE: &str = r"Eliot\governor\eliotd.json";
/// Protected daemon state directory relative to `ProgramData`.
pub const PROTECTED_STATE_RELATIVE: &str = r"Eliot\governor\state";
/// Maximum accepted launch-config bytes.
pub const MAX_CONFIG_BYTES: u64 = 128 * 1024;

/// Errors raised while loading or composing the daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Protected `ProgramData` path policy rejected the requested object.
    #[error("protected daemon path: {0}")]
    Protected(#[from] ProtectedPathError),
    /// The protected launch file was not a valid typed config.
    #[error("launch configuration: {0}")]
    LaunchConfig(String),
    /// Exact Kernel/provider or Governor recovery admission failed.
    #[error("Governor composition: {0}")]
    Composition(#[from] CompositionError),
    /// A second daemon owner cannot be admitted in this process.
    #[error("daemon lifecycle: {0}")]
    Lifecycle(String),
}

/// Typed protected launch inputs. The values are read from the fixed
/// `ProgramData` path; environment variables, current directory and arbitrary
/// caller paths are not authority sources.
#[derive(Debug)]
pub struct DaemonConfig {
    launch: GovernorLaunchConfig,
    config_path: PathBuf,
    state_root: PathBuf,
    config_lease: Option<ProtectedPathLease>,
}

impl DaemonConfig {
    /// Loads the Host-approved launch file through a bounded protected read.
    pub fn load_protected() -> Result<Self, DaemonError> {
        let config_path = protected_program_data_path(PROTECTED_CONFIG_RELATIVE)?;
        let config_lease = ProtectedPathLease::open_existing_absolute(&config_path)?;
        let bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        let launch: GovernorLaunchConfig = serde_json::from_slice(&bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        let mut config = Self::from_launch(launch, config_path)?;
        config.config_lease = Some(config_lease);
        Ok(config)
    }

    /// Creates a config only for the exact protected path used by production.
    /// This constructor is also useful to tests that provide a protected
    /// fixture; it rejects arbitrary roots before composition.
    pub fn from_launch(
        launch: GovernorLaunchConfig,
        config_path: PathBuf,
    ) -> Result<Self, DaemonError> {
        launch.validate()?;
        let expected_config = protected_program_data_path(PROTECTED_CONFIG_RELATIVE)?;
        if config_path != expected_config {
            return Err(DaemonError::LaunchConfig(
                "launch config path is not the fixed ProgramData identity".to_owned(),
            ));
        }
        let state_root = protected_program_data_path(PROTECTED_STATE_RELATIVE)?;
        Ok(Self {
            launch,
            config_path,
            state_root,
            config_lease: None,
        })
    }

    /// Returns the immutable Host-approved launch config.
    #[must_use]
    pub const fn launch(&self) -> &GovernorLaunchConfig {
        &self.launch
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

/// Readiness/status projection emitted by the daemon. It is derived only
/// after exact Kernel and recovery admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonStatus {
    /// Service identity.
    pub service: String,
    /// Daemon protocol revision.
    pub protocol: String,
    /// Active Kernel resource generation.
    pub generation: u64,
    /// Active authority epoch.
    pub authority_epoch: u64,
    /// Whether the owner set is admitted and accepting work.
    pub ready: bool,
}

/// The one production daemon composition. Application scheduling belongs here;
/// physical process execution and canonical persistence remain outside it.
pub struct DaemonComposition {
    governor: GovernorComposition<dyn KernelGenerationPort>,
    config_lease: ProtectedPathLease,
    state_lease: ProtectedPathLease,
    config_path: PathBuf,
    state_root: PathBuf,
    started: bool,
}

impl DaemonComposition {
    /// Composes the daemon only from a Host-approved authenticated Kernel port.
    ///
    /// The port is retained exactly once. Its snapshot and the recovered owner
    /// set are checked before this method returns a composition marked ready.
    pub fn start(
        mut config: DaemonConfig,
        kernel: Arc<dyn KernelGenerationPort>,
    ) -> Result<Self, DaemonError> {
        let config_lease = config.config_lease.take().ok_or_else(|| {
            DaemonError::Lifecycle(
                "production start requires the retained Host-approved config lease".to_owned(),
            )
        })?;
        config_lease.verify_stable_identity()?;
        let retained_bytes = config_lease.read_bounded(MAX_CONFIG_BYTES)?;
        let retained_launch: GovernorLaunchConfig = serde_json::from_slice(&retained_bytes)
            .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
        if retained_launch != config.launch {
            return Err(DaemonError::Lifecycle(
                "retained config bytes changed before composition".to_owned(),
            ));
        }
        prepare_protected_directory(config.state_root())?;
        let state_file = config.state_root().join("daemon.lifecycle");
        let state_lease = ProtectedPathLease::open_or_create(
            Path::new(PROTECTED_STATE_RELATIVE).join("daemon.lifecycle"),
        )?;
        if state_lease.path() != state_file {
            return Err(DaemonError::Lifecycle(
                "protected lifecycle identity changed during composition".to_owned(),
            ));
        }
        let governor =
            GovernorComposition::new(kernel, &config.launch().kernel, QueueLimits::default())?;
        Ok(Self {
            governor,
            config_lease,
            state_lease,
            config_path: config.config_path,
            state_root: config.state_root,
            started: true,
        })
    }

    /// Returns the admitted Kernel snapshot.
    #[must_use]
    pub fn kernel_snapshot(&self) -> &eliot_governor::KernelGenerationSnapshot {
        self.governor.kernel_snapshot()
    }

    /// Returns the retained protected config path, for diagnostics only.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the retained protected daemon state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Returns the exact readiness state.
    #[must_use]
    pub const fn readiness(&self) -> CompositionReadiness {
        self.governor.readiness()
    }

    /// Returns a bounded status projection.
    #[must_use]
    pub fn status(&self) -> DaemonStatus {
        let snapshot = self.kernel_snapshot();
        DaemonStatus {
            service: SERVICE_NAME.to_owned(),
            protocol: PROTOCOL_VERSION.to_owned(),
            generation: snapshot.generation.value(),
            authority_epoch: snapshot.authority_epoch.value(),
            ready: self.started && self.readiness() == CompositionReadiness::Ready,
        }
    }

    /// Stops the one daemon owner and releases protected handles together.
    pub fn shutdown(mut self) -> Result<(), DaemonError> {
        if !self.started {
            return Err(DaemonError::Lifecycle(
                "daemon shutdown was already completed".to_owned(),
            ));
        }
        self.governor.stop();
        self.started = false;
        let _ = (&self.config_lease, &self.state_lease);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_config_has_no_root_or_environment_override() {
        assert!(!PROTECTED_CONFIG_RELATIVE.contains("ProgramData"));
        assert!(!PROTECTED_CONFIG_RELATIVE.contains(".."));
        assert!(!PROTECTED_STATE_RELATIVE.contains(".."));
    }
}
