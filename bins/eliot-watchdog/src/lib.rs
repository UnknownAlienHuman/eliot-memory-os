//! Composition root for the independent Runtime 0.17 watchdog.
//!
//! The watchdog owns timing and supervision admission only.  Kernel effects
//! remain behind [`KernelWatchdogPort`], which makes it impossible for this
//! binary to turn a stale observation into process authority by itself.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_runtime::{
    ChildClass, Runtime, RuntimeConfig, ShutdownOutcome, SupervisionStrategy, TaskFailure,
};
use eliot_runtime_contracts::{LeaseState, SupervisionLease};
use eliot_watchdog_core::{Epoch, Watchdog};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-watchdog";
pub const PROTOCOL_VERSION: &str = "eliot.watchdog.v1";
/// Errors from the independent protected watchdog spool.
#[derive(Debug, Error)]
pub enum SpoolError {
    #[error("watchdog spool I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("watchdog spool path must be absolute")]
    RelativePath,
    #[error("watchdog spool must be below the canonical ProgramData protected root")]
    InvalidProtectedRoot,
    #[error("watchdog spool serialization: {0}")]
    Serialization(String),
    #[error("watchdog lease is unavailable or invalid: {0}")]
    InvalidLease(String),
}

const SPOOL_LIMIT: u64 = 1024 * 1024;
const SPOOL_ROTATIONS: usize = 3;

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat<'a> {
    service: &'static str,
    lease: &'a str,
    scope: &'a str,
    kernel_epoch: u64,
    watchdog_epoch: u64,
}

/// Minimal independent sensor surface used by the SCM sibling process.
///
/// The spool is append-only and contains only bounded heartbeat observations;
/// Kernel remains the sole effect owner. The decision core is intentionally
/// composed here so a sensor tick can never bypass its generation fences.
pub struct IndependentKernelSensor {
    watchdog: Mutex<Watchdog>,
    spool: PathBuf,
}

impl IndependentKernelSensor {
    /// Opens a protected spool below the installation's durable data root.
    pub fn open(path: impl Into<PathBuf>, watchdog_epoch: u64) -> Result<Self, SpoolError> {
        let spool = path.into();
        if !spool.is_absolute() {
            return Err(SpoolError::RelativePath);
        }
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .ok_or(SpoolError::InvalidProtectedRoot)?;
        let root = fs::canonicalize(program_data)?;
        let parent = spool.parent().ok_or(SpoolError::InvalidProtectedRoot)?;
        ensure_contained_non_reparse(&root, parent)?;
        let parent = spool.parent().ok_or(SpoolError::InvalidProtectedRoot)?;
        fs::create_dir_all(parent)?;
        ensure_non_reparse(parent)?;
        OpenOptions::new().create(true).append(true).open(&spool)?;
        let watchdog = Watchdog::new(
            eliot_watchdog_core::WatchdogConfig::default(),
            Epoch(watchdog_epoch),
        )
        .map_err(|_| SpoolError::RelativePath)?;
        Ok(Self {
            watchdog: Mutex::new(watchdog),
            spool,
        })
    }

    /// Opens the canonical protected watchdog spool below ProgramData.  The
    /// root is canonicalized and every existing path component is rejected if
    /// it is a symlink/reparse point, preventing redirection outside the
    /// service data boundary.
    pub fn open_program_data(
        relative_path: impl Into<PathBuf>,
        watchdog_epoch: u64,
    ) -> Result<Self, SpoolError> {
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .ok_or(SpoolError::InvalidProtectedRoot)?;
        if !program_data.is_absolute() {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        let root = fs::canonicalize(&program_data)?;
        ensure_non_reparse(&root)?;
        let relative = relative_path.into();
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        let spool = root.join(relative);
        let parent = spool.parent().ok_or(SpoolError::InvalidProtectedRoot)?;
        fs::create_dir_all(parent)?;
        ensure_contained_non_reparse(&root, parent)?;
        Self::open(spool, watchdog_epoch)
    }

    fn record_heartbeat(&self, lease: &SupervisionLease) -> Result<(), KernelWatchdogError> {
        let watchdog = self
            .watchdog
            .lock()
            .map_err(|_| KernelWatchdogError::Failed)?;
        let epoch = watchdog.epoch();
        if epoch.0 == 0 || lease.watchdog_epoch.value() != epoch.0 {
            return Err(KernelWatchdogError::LeaseRejected);
        }
        lease
            .validate()
            .map_err(|_| KernelWatchdogError::LeaseRejected)?;
        let line = serde_json::to_vec(&Heartbeat {
            service: SERVICE_NAME,
            lease: &lease.lease_id,
            scope: &lease.scope_ref,
            kernel_epoch: lease.kernel_epoch.value(),
            watchdog_epoch: lease.watchdog_epoch.value(),
        })
        .map_err(|error| KernelWatchdogError::FailedWithDetail(error.to_string()))?;
        let mut line = line;
        line.push(b'\n');
        if let Some(parent) = self.spool.parent() {
            ensure_non_reparse(parent).map_err(|_| KernelWatchdogError::Failed)?;
        } else {
            return Err(KernelWatchdogError::Failed);
        }
        rotate_if_needed(&self.spool, line.len() as u64)
            .map_err(|_| KernelWatchdogError::Failed)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.spool)
            .map_err(|_| KernelWatchdogError::Failed)?;
        file.write_all(&line)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|_| KernelWatchdogError::Failed)
    }
}

impl KernelWatchdogPort for IndependentKernelSensor {
    fn supervise<'a>(
        &'a self,
        lease: &'a SupervisionLease,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
        Box::pin(async move { self.record_heartbeat(lease) })
    }
}

/// Tunables for the watchdog's bounded control loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogConfig {
    pub tick_interval: Duration,
    pub mailbox_capacity: usize,
    pub control_reserve: usize,
    pub restart_budget: usize,
    pub shutdown_grace: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(2),
            mailbox_capacity: 16,
            control_reserve: 2,
            restart_budget: 3,
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

impl WatchdogConfig {
    fn runtime(&self) -> Result<Runtime, CompositionError> {
        Runtime::new(
            RuntimeConfig {
                mailbox_capacity: self.mailbox_capacity,
                control_reserve: self.control_reserve,
                concurrency: 1,
                control_concurrency_reserve: 1,
                fairness_quantum: 4,
                restart_budget: self.restart_budget,
                restart_window: Duration::from_secs(60),
                restart_backoff: Duration::from_millis(250),
                shutdown_grace: self.shutdown_grace,
            },
            None,
        )
        .map_err(CompositionError::Runtime)
    }

    fn validate(&self) -> Result<(), CompositionError> {
        if self.tick_interval.is_zero() {
            return Err(CompositionError::InvalidConfiguration(
                "tick_interval must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Kernel-owned effect boundary used by the watchdog control loop.
pub trait KernelWatchdogPort: Send + Sync + 'static {
    fn supervise<'a>(
        &'a self,
        lease: &'a SupervisionLease,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>>;
}

/// Non-secret failure returned by the kernel supervision boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelWatchdogError {
    #[error("kernel supervision endpoint is unavailable")]
    Unavailable,
    #[error("kernel rejected supervision lease")]
    LeaseRejected,
    #[error("kernel supervision failed")]
    Failed,
    #[error("kernel supervision failed: {0}")]
    FailedWithDetail(String),
}

/// Errors raised while composing the watchdog process.
#[derive(Debug, Error)]
pub enum CompositionError {
    #[error("invalid watchdog configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid supervision lease: {0}")]
    InvalidLease(String),
    #[error("runtime configuration: {0:?}")]
    Runtime(eliot_runtime::ConfigError),
    #[error("watchdog admission was denied during shutdown")]
    AdmissionClosed,
}

/// Readiness data emitted by the process entrypoint.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WatchdogReadiness {
    pub service: &'static str,
    pub protocol: &'static str,
    pub kernel_epoch: u64,
    pub watchdog_epoch: u64,
    pub tick_interval_ms: u128,
}

/// Runtime-owned watchdog composition.
pub struct WatchdogComposition {
    runtime: Runtime,
    lease: Arc<SupervisionLease>,
    config: WatchdogConfig,
    task: eliot_runtime::SupervisedHandle,
    shutdown_requested: Arc<AtomicBool>,
}

impl WatchdogComposition {
    /// Builds and admits the watchdog loop against an injected kernel port.
    pub fn start(
        config: WatchdogConfig,
        lease: SupervisionLease,
        kernel: Arc<dyn KernelWatchdogPort>,
    ) -> Result<Self, CompositionError> {
        Self::start_with_shutdown(config, lease, kernel, Arc::new(AtomicBool::new(false)))
    }

    /// Starts the composition with a caller-owned stop flag.  SCM control
    /// handlers use this flag because they execute outside the Tokio runtime.
    pub fn start_with_shutdown(
        config: WatchdogConfig,
        lease: SupervisionLease,
        kernel: Arc<dyn KernelWatchdogPort>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        config.validate()?;
        lease
            .validate()
            .map_err(|error| CompositionError::InvalidLease(error.to_string()))?;
        if lease.state != LeaseState::Active {
            return Err(CompositionError::InvalidLease(
                "supervision lease is not active".to_owned(),
            ));
        }
        let runtime = config.runtime()?;
        let lease = Arc::new(lease);
        let task_lease = lease.clone();
        let interval = config.tick_interval;
        let task = match runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            SERVICE_NAME,
            ChildClass::Critical,
            move |token| {
                let kernel = kernel.clone();
                let lease = task_lease.clone();
                async move {
                    loop {
                        tokio::select! {
                            () = token.cancelled() => return Ok(()),
                            () = tokio::time::sleep(interval) => {}
                        }
                        kernel
                            .supervise(&lease)
                            .await
                            .map_err(|error| TaskFailure::Failed(error.to_string()))?;
                    }
                }
            },
        ) {
            eliot_runtime::SpawnDisposition::Admitted(task) => task,
            eliot_runtime::SpawnDisposition::DeniedShuttingDown => {
                return Err(CompositionError::AdmissionClosed);
            }
        };
        Ok(Self {
            runtime,
            lease,
            config,
            task,
            shutdown_requested,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> WatchdogReadiness {
        WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            kernel_epoch: self.lease.kernel_epoch.value(),
            watchdog_epoch: self.lease.watchdog_epoch.value(),
            tick_interval_ms: self.config.tick_interval.as_millis(),
        }
    }

    /// Waits for process termination and performs ordered runtime shutdown.
    pub async fn run_until_shutdown(self) -> Result<ShutdownOutcome, TaskFailure> {
        let WatchdogComposition {
            runtime,
            task,
            shutdown_requested,
            ..
        } = self;
        let mut task_result = Box::pin(task.join());
        tokio::select! {
            result = &mut task_result => {
                let shutdown = runtime.shutdown().await;
                result.map(|_| shutdown)
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    return Err(TaskFailure::Failed("failed to receive shutdown signal".to_owned()));
                }
                runtime.shutdown_handle().request();
                let result = task_result.await;
                let shutdown = runtime.shutdown().await;
                result.map(|_| shutdown)
            }
            result = wait_for_shutdown(shutdown_requested) => {
                if result {
                    runtime.shutdown_handle().request();
                    let result = task_result.await;
                    let shutdown = runtime.shutdown().await;
                    result.map(|_| shutdown)
                } else {
                    Err(TaskFailure::Failed("watchdog shutdown signal failed".to_owned()))
                }
            }
        }
    }

    /// Requests bounded shutdown from an SCM control path.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
    }
}

async fn wait_for_shutdown(shutdown_requested: Arc<AtomicBool>) -> bool {
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Loads and validates the current Host/Kernel-issued lease.  Missing,
/// malformed, stale or non-active bytes are a hard startup failure.
pub fn load_supervision_lease(
    path: impl AsRef<std::path::Path>,
) -> Result<SupervisionLease, SpoolError> {
    let path = path.as_ref();
    if !path.is_absolute() {
        return Err(SpoolError::InvalidProtectedRoot);
    }
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .ok_or(SpoolError::InvalidProtectedRoot)?;
    let root = fs::canonicalize(program_data)?;
    let parent = path.parent().ok_or(SpoolError::InvalidProtectedRoot)?;
    ensure_contained_non_reparse(&root, parent)?;
    let bytes = fs::read(path).map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let lease: SupervisionLease = serde_json::from_slice(&bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    lease
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if lease.state != LeaseState::Active
        || lease.kernel_epoch.value() == 0
        || lease.watchdog_epoch.value() == 0
    {
        return Err(SpoolError::InvalidLease(
            "lease is not active or carries a zero epoch".to_owned(),
        ));
    }
    Ok(lease)
}

fn rotate_if_needed(path: &std::path::Path, incoming: u64) -> io::Result<()> {
    if incoming > SPOOL_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "watchdog heartbeat exceeds spool frame limit",
        ));
    }
    let current = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if current.saturating_add(incoming) <= SPOOL_LIMIT {
        return Ok(());
    }
    for index in (1..=SPOOL_ROTATIONS).rev() {
        let source = if index == 1 {
            path.to_owned()
        } else {
            path.with_extension(format!(
                "jsonl.{index_minus_one}",
                index_minus_one = index - 1
            ))
        };
        let destination = path.with_extension(format!("jsonl.{index}"));
        if destination.exists() {
            fs::remove_file(&destination)?;
        }
        if source.exists() {
            fs::rename(source, destination)?;
        }
    }
    Ok(())
}

fn ensure_non_reparse(path: &std::path::Path) -> Result<(), SpoolError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(SpoolError::InvalidProtectedRoot);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(SpoolError::InvalidProtectedRoot);
        }
    }
    Ok(())
}

fn ensure_contained_non_reparse(
    root: &std::path::Path,
    path: &std::path::Path,
) -> Result<(), SpoolError> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(root) {
        return Err(SpoolError::InvalidProtectedRoot);
    }
    let mut cursor = root.to_owned();
    for component in canonical
        .strip_prefix(root)
        .unwrap_or(std::path::Path::new(""))
        .components()
    {
        cursor.push(component);
        ensure_non_reparse(&cursor)?;
    }
    Ok(())
}
