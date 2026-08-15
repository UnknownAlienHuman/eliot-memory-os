//! Production Host composition root.
//!
//! Host is the outer Windows lifecycle owner. It opens the redb Host state
//! store under the installation's durable data root, keeps approved
//! generations separate from semantic state, and owns independent Job Object
//! branches for Kernel and the canonical store dependency.

#![forbid(unsafe_code)]

use std::io;
use std::path::Path;

use eliot_host_state::{EpochIdentity, EpochTransition, HostInstallationEpoch, RedbHostStateStore};
use eliot_installation::{
    ApprovedGenerationRegistry, CandidateManifest, InstallationError, RedbInstallationRegistry,
};
use eliot_platform::{HostInstallationState, HostStateStore, PlatformHandle};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-host";
pub const PROTOCOL_VERSION: &str = "eliot.host.v1";

#[derive(Debug, Error)]
pub enum HostError {
    #[error("host state store: {0}")]
    State(#[from] eliot_platform::HostStateError),
    #[error("installation registry: {0}")]
    Installation(#[from] InstallationError),
    #[error("host platform: {0}")]
    Platform(String),
    #[error("host is already stopped")]
    Stopped,
}

#[cfg(windows)]
use eliot_platform_windows::{JobObject, JobObjectIdentity, WindowsAdapterError};

/// The two physical process ownership branches controlled by Host.
#[cfg(windows)]
pub struct HostJobBranches {
    kernel: JobObject,
    store: JobObject,
}

#[cfg(windows)]
impl HostJobBranches {
    /// Creates fresh, owner-scoped kill-on-close branches.
    pub fn new() -> Result<Self, WindowsAdapterError> {
        let pid = std::process::id();
        let kernel = JobObject::new_named_kill_on_close(JobObjectIdentity::new(format!(
            "Local\\Eliot-Host-Kernel-{pid}"
        ))?)?;
        let store = JobObject::new_named_kill_on_close(JobObjectIdentity::new(format!(
            "Local\\Eliot-Host-Store-{pid}"
        ))?)?;
        Ok(Self { kernel, store })
    }

    /// Assigns the exact Kernel service process to Host's Kernel branch.
    pub fn assign_kernel(&self, process_id: u32) -> Result<(), WindowsAdapterError> {
        self.kernel.assign_process(process_id).map(|_| ())
    }

    /// Assigns the exact store dependency process to the independent store branch.
    pub fn assign_store(&self, process_id: u32) -> Result<(), WindowsAdapterError> {
        self.store.assign_process(process_id).map(|_| ())
    }

    /// Terminates the Kernel branch during bounded rollback or shutdown.
    pub fn terminate_kernel(&self) -> Result<(), WindowsAdapterError> {
        self.kernel.terminate(0xE017_0001)
    }

    /// Terminates the store branch during bounded rollback or shutdown.
    pub fn terminate_store(&self) -> Result<(), WindowsAdapterError> {
        self.store.terminate(0xE017_0002)
    }

    /// Returns the durable mechanics identity of the Kernel branch.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        self.kernel.identity().name()
    }

    /// Returns the durable mechanics identity of the store branch.
    #[must_use]
    pub fn store_name(&self) -> &str {
        self.store.identity().name()
    }
}

/// Host-owned lifecycle state and installation activation registry.
pub struct HostComposition {
    state_store: RedbHostStateStore,
    registry_store: RedbInstallationRegistry,
    registry: ApprovedGenerationRegistry,
    host: HostInstallationEpoch,
    running: bool,
    #[cfg(windows)]
    jobs: HostJobBranches,
}

impl HostComposition {
    /// Opens the durable Host contour for one installation epoch.
    pub fn open(path: impl AsRef<Path>, host: HostInstallationEpoch) -> Result<Self, HostError> {
        let path = path.as_ref();
        let initial = HostInstallationState {
            installation: host.installation.clone(),
            active_process: None,
            managed_dependencies: Vec::new(),
            last_clean_shutdown: None,
        };
        let state_store = RedbHostStateStore::open(path, initial)?;
        let registry_path = path.with_file_name("installation-registry.redb");
        let registry_store = RedbInstallationRegistry::open(registry_path)?;
        let registry = registry_store.load()?;
        #[cfg(windows)]
        let jobs =
            HostJobBranches::new().map_err(|error| HostError::Platform(error.to_string()))?;
        Ok(Self {
            state_store,
            registry_store,
            registry,
            host,
            running: true,
            #[cfg(windows)]
            jobs,
        })
    }

    /// Returns the Host epoch bound to this process.
    #[must_use]
    pub const fn host_epoch(&self) -> &HostInstallationEpoch {
        &self.host
    }

    /// Reads the Host-only operational state from redb.
    pub fn snapshot(&self) -> Result<HostInstallationState, HostError> {
        self.state_store
            .load_installation()
            .map_err(HostError::State)
    }

    /// Returns the installation-owned approved-generation registry.
    #[must_use]
    pub const fn registry(&self) -> &ApprovedGenerationRegistry {
        &self.registry
    }

    /// Approves an immutable generation for a later activation.
    pub fn approve_generation(
        &mut self,
        manifest: CandidateManifest,
        approval_ref: PlatformHandle,
    ) -> Result<(), HostError> {
        self.registry
            .approve(manifest, approval_ref)
            .map_err(HostError::Installation)?;
        self.registry_store
            .save(&self.registry)
            .map_err(HostError::Installation)
    }

    /// Activates an approved generation, preserving the previous one as LKG.
    pub fn activate_generation(&mut self, generation: &PlatformHandle) -> Result<(), HostError> {
        self.registry
            .activate(generation)
            .map_err(HostError::Installation)?;
        self.registry_store
            .save(&self.registry)
            .map_err(HostError::Installation)
    }

    /// Rolls back to the registry's last-known-good generation.
    pub fn rollback_generation(&mut self) -> Result<PlatformHandle, HostError> {
        let generation = self.registry.rollback().map_err(HostError::Installation)?;
        self.registry_store
            .save(&self.registry)
            .map_err(HostError::Installation)?;
        Ok(generation)
    }

    /// Requests a bounded Host stop. SCM owns the sibling Watchdog and is not
    /// represented by either Host Job Object branch.
    pub fn stop(&mut self) -> Result<(), HostError> {
        if !self.running {
            return Err(HostError::Stopped);
        }
        #[cfg(windows)]
        {
            self.jobs
                .terminate_kernel()
                .map_err(|error| HostError::Platform(error.to_string()))?;
            self.jobs
                .terminate_store()
                .map_err(|error| HostError::Platform(error.to_string()))?;
        }
        self.running = false;
        Ok(())
    }

    #[must_use]
    pub const fn running(&self) -> bool {
        self.running
    }

    #[cfg(windows)]
    /// Returns the physical Host job branches for service composition.
    #[must_use]
    pub const fn jobs(&self) -> &HostJobBranches {
        &self.jobs
    }
}

/// Builds the initial Host epoch from stable installation identity material.
pub fn initial_epoch(installation: PlatformHandle) -> HostInstallationEpoch {
    HostInstallationEpoch {
        installation,
        epoch: EpochTransition {
            current: EpochIdentity {
                lineage: handle("host-lineage"),
                sequence: 1,
            },
            parent: None,
        },
        nonce: handle("host-boot"),
        recovery: None,
    }
}

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

impl From<io::Error> for HostError {
    fn from(error: io::Error) -> Self {
        Self::Platform(error.to_string())
    }
}
