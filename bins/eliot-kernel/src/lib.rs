//! The Kernel composition root.
//!
//! Kernel owns process lifetime and selects one concrete transport boundary.
//! It does not duplicate protocol, platform, or task-runtime policy: those
//! contracts are supplied by the lower-layer packages and are assembled here
//! exactly once.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use eliot_ipc::TransportLimits;
use eliot_platform::PortError;
use eliot_platform_windows::WindowsPlatform;
use eliot_runtime::{Runtime, RuntimeConfig, ShutdownOutcome};

/// Stable Kernel process identity and wire revision.
pub const SERVICE_NAME: &str = "eliot-kernel";
pub const PROTOCOL_VERSION: &str = "eliot.kernel.v1";
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\eliot\kernel\frontdoor";

/// The only transport implementation admitted by the Windows-first Kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcImplementation {
    /// Local authenticated EBP/1 named pipe.
    WindowsNamedPipe { name: String },
}

impl IpcImplementation {
    fn new(name: impl Into<String>) -> Result<Self, KernelBuildError> {
        let name = name.into();
        eliot_ipc::validate_pipe_name(&name).map_err(KernelBuildError::Transport)?;
        Ok(Self::WindowsNamedPipe { name })
    }

    /// Returns the selected transport name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::WindowsNamedPipe { name } => name,
        }
    }

    /// Returns the transport limits selected by the Kernel composition.
    #[must_use]
    pub const fn limits(&self) -> TransportLimits {
        TransportLimits {
            max_frame_bytes: eliot_protocol::MAX_FRAME_BYTES,
            queue_capacity: 128,
            queue_bytes: 8 * 1024 * 1024,
            control_reserve: 4,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

/// Explicit construction input for the Kernel process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelConfig {
    /// Existing absolute WorkScope root bound to the platform adapter.
    pub work_root: PathBuf,
    /// Local pipe selected once by the composition root.
    pub pipe_name: String,
}

impl KernelConfig {
    /// Creates the production configuration using the canonical pipe.
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        Self {
            work_root: work_root.into(),
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
        }
    }
}

/// Errors raised before the Kernel is admitted to its service loop.
#[derive(Debug)]
pub enum KernelBuildError {
    /// The platform adapter rejected the WorkScope root.
    Platform(PortError),
    /// The selected transport is not valid.
    Transport(eliot_ipc::TransportError),
    /// The bounded runtime rejected its fixed production policy.
    Runtime(eliot_runtime::ConfigError),
}

impl fmt::Display for KernelBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform composition failed: {error}"),
            Self::Transport(error) => write!(f, "IPC composition failed: {error}"),
            Self::Runtime(error) => write!(f, "runtime composition failed: {error:?}"),
        }
    }
}

impl std::error::Error for KernelBuildError {}

/// The complete, production Kernel composition.
pub struct KernelComposition {
    runtime: Runtime,
    platform: WindowsPlatform,
    ipc: IpcImplementation,
}

impl KernelComposition {
    /// Builds all lower-layer surfaces once and binds them to one runtime.
    pub fn new(config: KernelConfig) -> Result<Self, KernelBuildError> {
        let platform = WindowsPlatform::new(config.work_root).map_err(KernelBuildError::Platform)?;
        let ipc = IpcImplementation::new(config.pipe_name)?;
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 128,
                control_reserve: 4,
                concurrency: 4,
                control_concurrency_reserve: 1,
                fairness_quantum: 8,
                restart_budget: 3,
                restart_window: Duration::from_secs(60),
                restart_backoff: Duration::from_millis(100),
                shutdown_grace: Duration::from_secs(5),
            },
            None,
        )
        .map_err(KernelBuildError::Runtime)?;
        Ok(Self {
            runtime,
            platform,
            ipc,
        })
    }

    /// Returns the selected local IPC implementation.
    #[must_use]
    pub const fn ipc(&self) -> &IpcImplementation {
        &self.ipc
    }

    /// Returns the platform surface owned by this composition.
    #[must_use]
    pub const fn platform(&self) -> &WindowsPlatform {
        &self.platform
    }

    /// Returns the runtime's protected-control capacity.
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        self.runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl)
    }

    /// Requests shutdown without starting a second lifecycle owner.
    #[must_use]
    pub fn request_shutdown(&self) -> bool {
        self.runtime.shutdown_handle().request()
    }

    /// Completes the bounded cooperative-then-forced shutdown sequence.
    pub async fn shutdown(&self) -> ShutdownOutcome {
        self.runtime.shutdown().await
    }
}

/// Resolves and validates the default WorkScope root for the binary entrypoint.
pub fn default_work_root() -> Result<PathBuf, std::io::Error> {
    let root = std::env::var_os("ELIOT_WORK_ROOT")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?);
    std::fs::canonicalize(Path::new(&root))
}
