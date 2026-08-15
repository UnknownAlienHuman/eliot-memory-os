//! Composition root for the independent Runtime 0.17 watchdog.
//!
//! The watchdog owns timing and supervision admission only.  Kernel effects
//! remain behind [`KernelWatchdogPort`], which makes it impossible for this
//! binary to turn a stale observation into process authority by itself.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::AuthorityEpoch;
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
        if let Some(parent) = spool.parent() {
            fs::create_dir_all(parent)?;
        }
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

    fn record_heartbeat(&self, lease: &SupervisionLease) -> Result<(), KernelWatchdogError> {
        let watchdog = self
            .watchdog
            .lock()
            .map_err(|_| KernelWatchdogError::Failed)?;
        let _epoch = watchdog.epoch();
        let line = format!(
            "{{\"service\":\"{}\",\"lease\":\"{}\",\"scope\":\"{}\"}}\n",
            SERVICE_NAME, lease.lease_id, lease.scope_ref
        );
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.spool)
            .and_then(|mut file| file.write_all(line.as_bytes()))
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
}

impl WatchdogComposition {
    /// Builds and admits the watchdog loop against an injected kernel port.
    pub fn start(
        config: WatchdogConfig,
        lease: SupervisionLease,
        kernel: Arc<dyn KernelWatchdogPort>,
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
        let WatchdogComposition { runtime, task, .. } = self;
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
        }
    }
}

/// Constructs the canonical active lease for a process invocation.
pub fn active_lease(
    lease_id: impl Into<String>,
    scope_ref: impl Into<String>,
    kernel_epoch: AuthorityEpoch,
    watchdog_epoch: AuthorityEpoch,
) -> SupervisionLease {
    SupervisionLease {
        lease_id: lease_id.into(),
        scope_ref: scope_ref.into(),
        kernel_epoch,
        watchdog_epoch,
        state: LeaseState::Active,
    }
}
