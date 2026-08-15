//! Production composition root for the ELIOT daemon.
//!
//! The daemon owns process lifetime and composes the kernel transport with the
//! Governor service supervisor.  Domain services remain owned by
//! `eliot-engine`; the daemon does not duplicate their state or provide a
//! second authority path.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eliot_engine::{LifecycleService, RuntimeLock, ServiceSupervisor, default_runtime_services};
use eliot_kernel::{KernelBuildError, KernelComposition, KernelConfig};
use eliot_types::{RuntimeMode, RuntimeStatusReport};
use thiserror::Error;

/// Stable daemon identity.
pub const SERVICE_NAME: &str = "eliotd";
/// Stable daemon protocol revision.
pub const PROTOCOL_VERSION: &str = "eliot.daemon.v1";
/// Maximum cooperative shutdown interval.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Explicit construction inputs for one daemon generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    /// Canonical operational data root containing the daemon lock and reports.
    pub data_root: PathBuf,
    /// Canonical project/work root bound to the kernel platform adapter.
    pub work_root: PathBuf,
    /// Local kernel transport name.
    pub pipe_name: String,
    /// Runtime instance identity used in service contexts.
    pub instance_id: String,
}

impl DaemonConfig {
    /// Creates the default user-local configuration.
    pub fn from_roots(data_root: impl Into<PathBuf>, work_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
            work_root: work_root.into(),
            pipe_name: eliot_kernel::DEFAULT_PIPE_NAME.to_owned(),
            instance_id: "default".to_owned(),
        }
    }

    fn validate(&self) -> Result<(), DaemonError> {
        if self.instance_id.trim().is_empty() {
            return Err(DaemonError::InvalidConfiguration(
                "instance_id must not be empty".to_owned(),
            ));
        }
        if self.pipe_name.trim().is_empty() {
            return Err(DaemonError::InvalidConfiguration(
                "pipe_name must not be empty".to_owned(),
            ));
        }
        if !self.data_root.is_absolute() || !self.work_root.is_absolute() {
            return Err(DaemonError::InvalidConfiguration(
                "data_root and work_root must be absolute paths".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Errors raised while composing or stopping the daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Configuration failed before any service was started.
    #[error("invalid daemon configuration: {0}")]
    InvalidConfiguration(String),
    /// The daemon's operational lock or directory could not be established.
    #[error("lifecycle: {0}")]
    Lifecycle(#[source] eliot_engine::EngineError),
    /// Kernel composition failed before readiness.
    #[error("kernel: {0}")]
    Kernel(#[source] KernelBuildError),
    /// A Governor service failed its ordered start.
    #[error("governor services: {0}")]
    Governor(#[source] eliot_engine::EngineError),
    /// One or more services failed during ordered shutdown.
    #[error("shutdown: {0}")]
    Shutdown(#[source] eliot_engine::EngineError),
}

/// Fully composed daemon state.  A value owns exactly one kernel and one
/// Governor supervisor, preventing competing lifecycle owners.
pub struct DaemonComposition {
    kernel: KernelComposition,
    governor: ServiceSupervisor,
    lifecycle: RuntimeLock,
    data_root: PathBuf,
    started: bool,
}

impl DaemonComposition {
    /// Builds and starts the production composition in contract order.
    pub async fn start(config: DaemonConfig) -> Result<Self, DaemonError> {
        config.validate()?;
        std::fs::create_dir_all(&config.data_root).map_err(|error| {
            DaemonError::InvalidConfiguration(format!(
                "create data root {}: {error}",
                config.data_root.display()
            ))
        })?;
        let lifecycle = LifecycleService::new(&config.data_root)
            .acquire_single_instance()
            .map_err(DaemonError::Lifecycle)?;
        let kernel_config = KernelConfig {
            work_root: config.work_root,
            pipe_name: config.pipe_name,
        };
        let kernel = match KernelComposition::new(kernel_config) {
            Ok(kernel) => kernel,
            Err(error) => return Err(DaemonError::Kernel(error)),
        };
        let mut governor = ServiceSupervisor::new(default_runtime_services());
        if let Err(error) = governor.start_all(&config.instance_id).await {
            return Err(DaemonError::Governor(error));
        }
        Ok(Self {
            kernel,
            governor,
            lifecycle,
            data_root: config.data_root,
            started: true,
        })
    }

    /// Returns the authenticated kernel transport selected for this generation.
    #[must_use]
    pub fn ipc_name(&self) -> &str {
        self.kernel.ipc()
    }

    /// Produces the canonical Governor runtime status projection.
    #[must_use]
    pub fn status(&self) -> RuntimeStatusReport {
        self.governor
            .status_report(RuntimeMode::Daemon, &self.data_root, self.started, true)
    }

    /// Performs ordered Governor shutdown followed by kernel shutdown.
    pub async fn shutdown(mut self) -> Result<(), DaemonError> {
        if self.started {
            self.governor
                .shutdown_all(Instant::now() + SHUTDOWN_GRACE)
                .await
                .map_err(DaemonError::Shutdown)?;
            self.started = false;
        }
        self.kernel.shutdown().await;
        self.lifecycle
            .mark_clean_shutdown()
            .map_err(DaemonError::Lifecycle)
    }
}

/// Canonicalises a configured root without silently substituting another root.
pub fn canonical_root(path: &Path) -> Result<PathBuf, DaemonError> {
    std::fs::canonicalize(path).map_err(|error| {
        DaemonError::InvalidConfiguration(format!("canonicalize {}: {error}", path.display()))
    })
}
