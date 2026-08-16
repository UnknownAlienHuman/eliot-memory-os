//! Production Host composition root.
//!
//! Host is the outer Windows lifecycle owner. It opens the redb Host state
//! store under the installation's durable data root, keeps approved
//! generations separate from semantic state, and owns independent Job Object
//! branches for Kernel and the canonical store dependency.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use eliot_contracts::{
    AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_host_state::{
    HostAdmissionState, HostInstallationEpoch, HostRecoverySnapshot, RedbHostReleaseToken,
    RedbHostStateStore,
};
use eliot_installation::{
    ApprovedGenerationRegistry, CandidateManifest, InstallationError, RedbInstallationRegistry,
    verify_approved_path, verify_file_digest_with_lease,
};
use eliot_platform::{
    HostBranchKind, HostBranchRecoveryFence, HostInstallationState, HostJobDisposition,
    HostProcessRecoveryBinding, HostRecoveryEvidence, HostStateStore, PlatformHandle,
};
use eliot_platform_windows::{
    HostOwnerLease, HostOwnerLeaseError, HostOwnerLeaseReleaseError, ProtectedPathLease,
};
use eliot_runtime_contracts::{HealthVector, ServiceProcessRecord, ServiceProcessState};
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
    #[error("host installation identity is required")]
    MissingInstallation,
    #[error("approved process contour is unavailable: {0}")]
    ProcessContour(String),
    #[error("another live Host owns this installation")]
    OwnerLeaseHeld,
    #[error("Host owner lease recovery is required: {0}")]
    OwnerLeaseRecovery(String),
}

#[cfg(windows)]
use eliot_platform_windows::{
    JobObjectIdentity, PinnedRuntimeFile, ProcessIdentity, RunningJobChild, SuspendedJobChild,
    SuspendedLaunchSpec, WindowsAdapterError,
};

/// The two physical process ownership branches controlled by Host.
#[cfg(windows)]
pub struct HostJobBranches {
    kernel: Option<RunningJobChild<PlatformHandle>>,
    store: Option<RunningJobChild<PlatformHandle>>,
    kernel_identity: JobObjectIdentity,
    store_identity: JobObjectIdentity,
    kernel_executable: Option<PathBuf>,
    store_executable: Option<PathBuf>,
    kernel_lease: Option<ProtectedPathLease>,
    store_lease: Option<ProtectedPathLease>,
    config_path: Option<PathBuf>,
    config_lease: Option<ProtectedPathLease>,
    config_pin: Option<PinnedRuntimeFile>,
    kernel_artifact_digest: Option<PlatformHandle>,
    store_artifact_digest: Option<PlatformHandle>,
    config_digest: Option<PlatformHandle>,
    kernel_restart_attempts: u8,
    store_restart_attempts: u8,
}

/// Independent branch disposition after one bounded reconciliation pass.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostBranchDisposition {
    /// Both Host-owned process branches are healthy.
    Healthy,
    /// Kernel authority is unavailable; the canonical store is not stopped.
    KernelDegraded,
    /// Canonical store is unavailable; Kernel is not stopped.
    StoreDegraded,
    /// Both process branches are unavailable after their independent bounds.
    BothDegraded,
}

#[cfg(windows)]
impl HostJobBranches {
    /// Creates two owner-scoped Job identities.  The actual Job handles are
    /// created only by the approved suspended launch below; there is no
    /// unbound PID assignment path.
    ///
    /// # Errors
    ///
    /// Returns an error if either owner-scoped Job identity is invalid.
    pub fn new(host: &HostInstallationEpoch) -> Result<Self, WindowsAdapterError> {
        let suffix = format!(
            "{}-{}",
            host.epoch.current.lineage.as_str(),
            host.epoch.current.sequence
        );
        let kernel_identity = JobObjectIdentity::new(format!("Local\\Eliot-Host-Kernel-{suffix}"))?;
        let store_identity = JobObjectIdentity::new(format!("Local\\Eliot-Host-Store-{suffix}"))?;
        Ok(Self {
            kernel: None,
            store: None,
            kernel_identity,
            store_identity,
            kernel_executable: None,
            store_executable: None,
            kernel_lease: None,
            store_lease: None,
            config_path: None,
            config_lease: None,
            config_pin: None,
            kernel_artifact_digest: None,
            store_artifact_digest: None,
            config_digest: None,
            kernel_restart_attempts: 0,
            store_restart_attempts: 0,
        })
    }

    fn environment(
        host: &HostInstallationEpoch,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        job_identity: &JobObjectIdentity,
    ) -> Vec<(OsString, OsString)> {
        let mut environment = std::env::vars_os()
            .filter(|(key, _)| {
                !matches!(
                    key.to_string_lossy().as_ref(),
                    "ELIOT_APPROVED_GENERATION"
                        | "ELIOT_GENERATION_CONFIG_DIGEST"
                        | "ELIOT_APPROVED_ARTIFACT"
                        | "ELIOT_GENERATION_CONFIG_PATH"
                        | "ELIOT_HOST_INSTALLATION"
                        | "ELIOT_HOST_EPOCH"
                        | "ELIOT_ACTIVATION_NONCE"
                        | "ELIOT_JOB_OBJECT_ID"
                )
            })
            .collect::<Vec<_>>();
        environment.extend([
            (
                OsString::from("ELIOT_APPROVED_GENERATION"),
                OsString::from(generation.as_str()),
            ),
            (
                OsString::from("ELIOT_GENERATION_CONFIG_DIGEST"),
                OsString::from(config_digest.as_str()),
            ),
            (
                OsString::from("ELIOT_APPROVED_ARTIFACT"),
                OsString::from(artifact.as_str()),
            ),
            (
                OsString::from("ELIOT_GENERATION_CONFIG_PATH"),
                config_path.as_os_str().to_owned(),
            ),
            (
                OsString::from("ELIOT_HOST_INSTALLATION"),
                OsString::from(host.installation.as_str()),
            ),
            (
                OsString::from("ELIOT_HOST_EPOCH"),
                OsString::from(host.epoch.current.sequence.to_string()),
            ),
            (
                OsString::from("ELIOT_ACTIVATION_NONCE"),
                OsString::from(host.nonce.as_str()),
            ),
            (
                OsString::from("ELIOT_JOB_OBJECT_ID"),
                OsString::from(job_identity.name()),
            ),
        ]);
        environment
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the ordered suspended-launch inputs are separate authority bindings and must remain explicit"
    )]
    fn launch(
        executable: &Path,
        executable_lease: &ProtectedPathLease,
        identity: &JobObjectIdentity,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        config_lease: &ProtectedPathLease,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        _config_pin: &PinnedRuntimeFile,
        host: &HostInstallationEpoch,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        if executable_lease.path() != executable || config_lease.path() != config_path {
            return Err(HostError::ProcessContour(
                "launch locator is not bound to its retained protected file".to_owned(),
            ));
        }
        let approved_executable = verify_approved_path(
            executable,
            approved_executable_path,
            "runtime.approved_executable_path",
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if approved_executable != executable {
            return Err(HostError::ProcessContour(
                "executable locator is not the approved path".to_owned(),
            ));
        }
        let approved_config = verify_approved_path(
            config_path,
            approved_config_path,
            "runtime.approved_config_path",
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if approved_config != config_path {
            return Err(HostError::ProcessContour(
                "config locator is not the approved path".to_owned(),
            ));
        }
        executable_lease
            .verify_stable_identity()
            .and_then(|()| executable_lease.verify_path_identity())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        config_lease
            .verify_stable_identity()
            .and_then(|()| config_lease.verify_path_identity())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        verify_file_digest_with_lease(executable_lease, artifact, "runtime.artifact")
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        verify_file_digest_with_lease(config_lease, config_digest, "runtime.config")
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let working_directory = executable
            .parent()
            .ok_or_else(|| HostError::ProcessContour("approved image has no parent".to_owned()))?;
        let spec = SuspendedLaunchSpec::new(
            executable.to_path_buf(),
            Vec::new(),
            working_directory,
            Self::environment(
                host,
                generation,
                config_digest,
                artifact,
                config_path,
                identity,
            ),
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let child = SuspendedJobChild::spawn_named(spec, identity.clone())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let expected = executable;
        let validated = child
            .validate(|evidence| {
                let observed = std::fs::canonicalize(&evidence.process().image_path)
                    .map_err(|error| error.to_string())?;
                if observed != expected {
                    return Err("approved image identity changed before resume".to_owned());
                }
                let observed_executable = verify_approved_path(
                    &observed,
                    approved_executable_path,
                    "runtime.approved_executable_path",
                )
                .map_err(|error| error.to_string())?;
                if observed_executable != expected {
                    return Err("approved image path changed before resume".to_owned());
                }
                executable_lease
                    .verify_stable_identity()
                    .and_then(|()| executable_lease.verify_path_identity())
                    .map_err(|error| error.to_string())?;
                verify_file_digest_with_lease(executable_lease, artifact, "runtime.artifact")
                    .map_err(|error| error.to_string())?;
                let observed_config = verify_approved_path(
                    config_path,
                    approved_config_path,
                    "runtime.approved_config_path",
                )
                .map_err(|error| error.to_string())?;
                if observed_config != config_path {
                    return Err("approved config path changed before resume".to_owned());
                }
                config_lease
                    .verify_stable_identity()
                    .and_then(|()| config_lease.verify_path_identity())
                    .map_err(|error| error.to_string())?;
                verify_file_digest_with_lease(config_lease, config_digest, "runtime.config")
                    .map_err(|error| error.to_string())?;
                Ok(generation.clone())
            })
            .map_err(|error| HostError::ProcessContour(format!("validation failed: {error:?}")))?;
        validated
            .resume()
            .map_err(|error| HostError::ProcessContour(error.to_string()))
    }

    /// Starts the approved Kernel and store images in separate Job Objects.
    /// Both images are pinned and validated while suspended, then resumed only
    /// after the generation identity has been accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if an approved path, retained file identity, digest,
    /// suspended launch, or rollback cleanup cannot be validated or completed.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is an independently validated process-contour authority binding"
    )]
    pub fn start_approved(
        &mut self,
        kernel_executable: &Path,
        store_executable: &Path,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        approved_kernel_path: &PlatformHandle,
        approved_store_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<(), HostError> {
        if self.kernel.is_some() || self.store.is_some() {
            return Err(HostError::ProcessContour(
                "approved contour is already running".to_owned(),
            ));
        }
        let kernel_executable = verify_approved_path(
            kernel_executable,
            approved_kernel_path,
            "runtime.approved_kernel_path",
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let kernel_lease = ProtectedPathLease::open_existing_absolute(&kernel_executable)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        verify_file_digest_with_lease(&kernel_lease, kernel_artifact, "runtime.kernel_artifact")
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let store_executable = verify_approved_path(
            store_executable,
            approved_store_path,
            "runtime.approved_store_path",
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let store_lease = ProtectedPathLease::open_existing_absolute(&store_executable)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        verify_file_digest_with_lease(&store_lease, store_artifact, "runtime.store_artifact")
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let config_path = verify_approved_path(
            config_path,
            approved_config_path,
            "runtime.approved_config_path",
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let config_pin = PinnedRuntimeFile::open(&config_path)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let config_lease = ProtectedPathLease::open_existing_absolute(&config_path)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        verify_file_digest_with_lease(&config_lease, config_digest, "runtime.config")
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let kernel = Self::launch(
            &kernel_executable,
            &kernel_lease,
            &self.kernel_identity,
            generation,
            config_digest,
            kernel_artifact,
            &config_path,
            &config_lease,
            approved_kernel_path,
            approved_config_path,
            &config_pin,
            host,
        )?;
        let store = match Self::launch(
            &store_executable,
            &store_lease,
            &self.store_identity,
            generation,
            config_digest,
            store_artifact,
            &config_path,
            &config_lease,
            approved_store_path,
            approved_config_path,
            &config_pin,
            host,
        ) {
            Ok(store) => store,
            Err(error) => {
                let _ = kernel.terminate(0xE017_0001);
                return Err(error);
            }
        };
        self.kernel_executable = Some(kernel_executable);
        self.store_executable = Some(store_executable);
        self.kernel_lease = Some(kernel_lease);
        self.store_lease = Some(store_lease);
        self.config_path = Some(config_path);
        self.config_lease = Some(config_lease);
        self.config_pin = Some(config_pin);
        self.kernel_artifact_digest = Some(kernel_artifact.clone());
        self.store_artifact_digest = Some(store_artifact.clone());
        self.config_digest = Some(config_digest.clone());
        self.kernel_restart_attempts = 0;
        self.store_restart_attempts = 0;
        self.kernel = Some(kernel);
        self.store = Some(store);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "relaunch keeps every approved authority binding explicit at the process boundary"
    )]
    fn relaunch_kernel(
        &mut self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        artifact: &PlatformHandle,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<(), HostError> {
        let executable = self
            .kernel_executable
            .clone()
            .ok_or_else(|| HostError::ProcessContour("Kernel image is not recorded".to_owned()))?;
        let executable_lease = self
            .kernel_lease
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("Kernel image lease is missing".to_owned()))?;
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        let config_pin = self.config_pin.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config pin is missing".to_owned())
        })?;
        let child = Self::launch(
            &executable,
            executable_lease,
            &self.kernel_identity,
            generation,
            config_digest,
            artifact,
            config_path,
            config_lease,
            approved_executable_path,
            approved_config_path,
            config_pin,
            host,
        )?;
        self.kernel = Some(child);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "relaunch keeps every approved authority binding explicit at the process boundary"
    )]
    fn relaunch_store(
        &mut self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        artifact: &PlatformHandle,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<(), HostError> {
        let executable = self
            .store_executable
            .clone()
            .ok_or_else(|| HostError::ProcessContour("store image is not recorded".to_owned()))?;
        let executable_lease = self
            .store_lease
            .as_ref()
            .ok_or_else(|| HostError::ProcessContour("store image lease is missing".to_owned()))?;
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        let config_pin = self.config_pin.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config pin is missing".to_owned())
        })?;
        let child = Self::launch(
            &executable,
            executable_lease,
            &self.store_identity,
            generation,
            config_digest,
            artifact,
            config_path,
            config_lease,
            approved_executable_path,
            approved_config_path,
            config_pin,
            host,
        )?;
        self.store = Some(child);
        Ok(())
    }

    fn branch_dead(
        child: Option<&RunningJobChild<PlatformHandle>>,
    ) -> Result<bool, WindowsAdapterError> {
        match child {
            Some(child) => Ok(!matches!(
                child.observe()?,
                eliot_platform_windows::RunningJobObservation::Running { .. }
            )),
            None => Ok(true),
        }
    }

    /// Reconciles Kernel and store branches independently with one bounded
    /// restart attempt per branch failure. A failed branch never terminates a
    /// healthy sibling or reuses an observed PID.
    ///
    /// # Errors
    ///
    /// Returns an error if retained process/configuration identity changes or
    /// a protected file, digest, or approved path cannot be revalidated.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "ordered branch reconciliation keeps all authority bindings visible and fail-closed"
    )]
    pub fn reconcile(
        &mut self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        approved_kernel_path: &PlatformHandle,
        approved_store_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<HostBranchDisposition, HostError> {
        if self
            .kernel_artifact_digest
            .as_ref()
            .is_some_and(|digest| digest != kernel_artifact)
            || self
                .store_artifact_digest
                .as_ref()
                .is_some_and(|digest| digest != store_artifact)
            || self
                .config_digest
                .as_ref()
                .is_some_and(|digest| digest != config_digest)
        {
            return Err(HostError::ProcessContour(
                "approved generation material changed; bounded cutover is required".to_owned(),
            ));
        }
        let canonical_config = verify_approved_path(
            config_path,
            approved_config_path,
            "runtime.approved_config_path",
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if self.config_path.as_ref() != Some(&canonical_config) {
            return Err(HostError::ProcessContour(
                "generation config path changed outside the approved contour".to_owned(),
            ));
        }
        let config_lease = self.config_lease.as_ref().ok_or_else(|| {
            HostError::ProcessContour("generation config lease is missing".to_owned())
        })?;
        if config_lease.path() != canonical_config {
            return Err(HostError::ProcessContour(
                "generation config lease is not the approved path".to_owned(),
            ));
        }
        config_lease
            .verify_stable_identity()
            .and_then(|()| config_lease.verify_path_identity())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        verify_file_digest_with_lease(config_lease, config_digest, "runtime.config")
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if let Some(kernel) = &self.kernel_executable {
            let approved =
                verify_approved_path(kernel, approved_kernel_path, "runtime.approved_kernel_path")
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let lease = self.kernel_lease.as_ref().ok_or_else(|| {
                HostError::ProcessContour("Kernel image lease is missing".to_owned())
            })?;
            if approved != *kernel || lease.path() != kernel {
                return Err(HostError::ProcessContour(
                    "Kernel image lease is not the approved path".to_owned(),
                ));
            }
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            verify_file_digest_with_lease(lease, kernel_artifact, "runtime.kernel_artifact")
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        }
        if let Some(store) = &self.store_executable {
            let approved =
                verify_approved_path(store, approved_store_path, "runtime.approved_store_path")
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            let lease = self.store_lease.as_ref().ok_or_else(|| {
                HostError::ProcessContour("store image lease is missing".to_owned())
            })?;
            if approved != *store || lease.path() != store {
                return Err(HostError::ProcessContour(
                    "store image lease is not the approved path".to_owned(),
                ));
            }
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            verify_file_digest_with_lease(lease, store_artifact, "runtime.store_artifact")
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        }
        let kernel_dead = Self::branch_dead(self.kernel.as_ref()).unwrap_or(true);
        let store_dead = Self::branch_dead(self.store.as_ref()).unwrap_or(true);
        let mut kernel_degraded = false;
        let mut store_degraded = false;

        if kernel_dead {
            if self.terminate_kernel().is_err() || self.kernel_restart_attempts >= 1 {
                kernel_degraded = true;
            } else {
                self.kernel_restart_attempts += 1;
                if self
                    .relaunch_kernel(
                        generation,
                        config_digest,
                        config_path,
                        kernel_artifact,
                        approved_kernel_path,
                        approved_config_path,
                        host,
                    )
                    .is_err()
                {
                    kernel_degraded = true;
                }
            }
        }

        if store_dead {
            if self.terminate_store().is_err() || self.store_restart_attempts >= 1 {
                store_degraded = true;
            } else {
                self.store_restart_attempts += 1;
                if self
                    .relaunch_store(
                        generation,
                        config_digest,
                        config_path,
                        store_artifact,
                        approved_store_path,
                        approved_config_path,
                        host,
                    )
                    .is_err()
                {
                    store_degraded = true;
                }
            }
        }

        if self.kernel.is_none() {
            kernel_degraded = true;
        }
        if self.store.is_none() {
            store_degraded = true;
        }
        Ok(match (kernel_degraded, store_degraded) {
            (false, false) => HostBranchDisposition::Healthy,
            (true, false) => HostBranchDisposition::KernelDegraded,
            (false, true) => HostBranchDisposition::StoreDegraded,
            (true, true) => HostBranchDisposition::BothDegraded,
        })
    }

    /// Performs a bounded side-by-side cutover with an explicit rollback
    /// image.  The old branches are drained before the candidate is admitted;
    /// if candidate startup or suspended validation fails, only the supplied
    /// prior approved images may be relaunched.
    ///
    /// # Errors
    ///
    /// Returns an error when shutdown, candidate admission, or restoration of
    /// the prior approved contour fails.
    #[allow(
        clippy::too_many_arguments,
        reason = "candidate and rollback authority sets stay explicit to prevent cross-generation substitution"
    )]
    pub fn cutover_with_rollback(
        &mut self,
        candidate_kernel: &Path,
        candidate_store: &Path,
        prior_kernel: &Path,
        prior_store: &Path,
        candidate_generation: &PlatformHandle,
        candidate_config_digest: &PlatformHandle,
        candidate_config_path: &Path,
        candidate_kernel_path: &PlatformHandle,
        candidate_store_path: &PlatformHandle,
        candidate_approved_config_path: &PlatformHandle,
        candidate_kernel_artifact: &PlatformHandle,
        candidate_store_artifact: &PlatformHandle,
        prior_generation: &PlatformHandle,
        prior_config_digest: &PlatformHandle,
        prior_config_path: &Path,
        prior_kernel_path: &PlatformHandle,
        prior_store_path: &PlatformHandle,
        prior_approved_config_path: &PlatformHandle,
        prior_kernel_artifact: &PlatformHandle,
        prior_store_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<(), HostError> {
        self.terminate_kernel()?;
        self.terminate_store()?;
        match self.start_approved(
            candidate_kernel,
            candidate_store,
            candidate_generation,
            candidate_config_digest,
            candidate_config_path,
            candidate_kernel_path,
            candidate_store_path,
            candidate_approved_config_path,
            candidate_kernel_artifact,
            candidate_store_artifact,
            host,
        ) {
            Ok(()) => Ok(()),
            Err(candidate_error) => {
                let rollback = self
                    .start_approved(
                        prior_kernel,
                        prior_store,
                        prior_generation,
                        prior_config_digest,
                        prior_config_path,
                        prior_kernel_path,
                        prior_store_path,
                        prior_approved_config_path,
                        prior_kernel_artifact,
                        prior_store_artifact,
                        host,
                    )
                    .map_err(|error| {
                        HostError::ProcessContour(format!(
                            "candidate failed ({candidate_error}); rollback failed ({error})"
                        ))
                    });
                match rollback {
                    Ok(()) => Err(HostError::ProcessContour(format!(
                        "candidate rejected; prior approved contour restored: {candidate_error}"
                    ))),
                    Err(error) => Err(error),
                }
            }
        }
    }

    /// Terminates the Kernel branch during bounded rollback or shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the owned Kernel Job branch cannot be terminated.
    pub fn terminate_kernel(&mut self) -> Result<(), HostError> {
        if let Some(kernel) = self.kernel.take() {
            kernel
                .terminate(0xE017_0001)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        }
        Ok(())
    }

    /// Terminates the store branch during bounded rollback or shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the owned store Job branch cannot be terminated.
    pub fn terminate_store(&mut self) -> Result<(), HostError> {
        if let Some(store) = self.store.take() {
            store
                .terminate(0xE017_0002)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        }
        Ok(())
    }

    fn clear_recorded_contour(&mut self) {
        self.kernel_executable = None;
        self.store_executable = None;
        self.kernel_lease = None;
        self.store_lease = None;
        self.config_path = None;
        self.config_lease = None;
        self.config_pin = None;
        self.kernel_artifact_digest = None;
        self.store_artifact_digest = None;
        self.config_digest = None;
        self.kernel_restart_attempts = 0;
        self.store_restart_attempts = 0;
    }

    /// Returns the durable mechanics identity of the Kernel branch.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        self.kernel_identity.name()
    }

    /// Returns the durable mechanics identity of the store branch.
    #[must_use]
    pub fn store_name(&self) -> &str {
        self.store_identity.name()
    }

    #[must_use]
    pub fn kernel_process(&self) -> Option<&ProcessIdentity> {
        self.kernel.as_ref().map(|child| child.evidence().process())
    }

    #[must_use]
    pub fn store_process(&self) -> Option<&ProcessIdentity> {
        self.store.as_ref().map(|child| child.evidence().process())
    }

    #[must_use]
    pub fn has_recorded_contour(&self) -> bool {
        self.kernel.is_some()
            || self.store.is_some()
            || self.kernel_executable.is_some()
            || self.store_executable.is_some()
    }

    fn kernel_recovery_binding(
        &self,
        generation: &PlatformHandle,
        observed_process: &ServiceProcessRecord,
        installation: &PlatformHandle,
    ) -> Result<HostProcessRecoveryBinding, HostError> {
        let process = self
            .kernel_process()
            .ok_or_else(|| HostError::ProcessContour("Kernel process is unavailable".to_owned()))?;
        process_recovery_binding(
            process,
            generation,
            &self.kernel_identity,
            installation,
            observed_process,
        )
    }
}

/// Host-owned lifecycle state and installation activation registry.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the lifecycle flags are independent durable shutdown and lease-release fences"
)]
pub struct HostComposition {
    state_store: RedbHostStateStore,
    registry_store: RedbInstallationRegistry,
    registry: ApprovedGenerationRegistry,
    host: HostInstallationEpoch,
    host_process: ServiceProcessRecord,
    running: bool,
    #[cfg(windows)]
    jobs: HostJobBranches,
    owner_lease: HostOwnerLease,
    pending_release: Option<RedbHostReleaseToken>,
    durable_finalized: bool,
    owner_released: bool,
    shutdown_failed: bool,
}

impl HostComposition {
    /// Opens the durable Host contour for one installation identity and
    /// advances its persisted epoch before any process admission.
    ///
    /// # Errors
    ///
    /// Returns an error if installation identity, owner-lease acquisition,
    /// durable admission, recovery state, or approved process startup fails.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the public constructor owns the installation identity while retaining its established API"
    )]
    pub fn open(path: impl AsRef<Path>, installation: PlatformHandle) -> Result<Self, HostError> {
        let path = path.as_ref();
        if installation.as_str().trim().is_empty() {
            return Err(HostError::MissingInstallation);
        }
        let owner_lease = HostOwnerLease::acquire(&installation).map_err(owner_lease_error)?;
        match RedbHostStateStore::inspect_admission(path, &installation).map_err(|error| {
            HostError::OwnerLeaseRecovery(format!(
                "durable Host admission inspection failed; recovery required: {error}"
            ))
        })? {
            HostAdmissionState::FirstInstall | HostAdmissionState::Clean => {}
            HostAdmissionState::RecoveryRequired => {
                return Err(HostError::OwnerLeaseRecovery(
                    "durable Host state is unclean or still running; explicit recovery evidence is required"
                        .to_owned(),
                ));
            }
        }
        let (state_store, host) = RedbHostStateStore::open_epoch(path, installation.clone())?;
        let registry_path = path.with_file_name("installation-registry.redb");
        let registry_store = RedbInstallationRegistry::open(registry_path)?;
        let registry = registry_store.load()?;
        let host_process = host_process_record(&host)?;
        let host_recovery = host_process_recovery_binding(&host, &host_process)?;
        // Every Host invocation records an activation boundary.  If a prior
        // projection had no clean marker, this deliberately remains an
        // unclean recovery until stop() writes the shutdown receipt.
        state_store
            .commit_activation(
                eliot_platform::HostActivationTransition {
                    context: lifecycle_context(&host, "host-open")?,
                    installation: host.installation.clone(),
                    process: host_process.clone(),
                },
                host_recovery,
            )
            .map_err(HostError::State)?;
        #[cfg(windows)]
        let jobs =
            HostJobBranches::new(&host).map_err(|error| HostError::Platform(error.to_string()))?;
        let mut composition = Self {
            state_store,
            registry_store,
            registry,
            host,
            host_process,
            running: true,
            #[cfg(windows)]
            jobs,
            owner_lease,
            pending_release: None,
            durable_finalized: false,
            owner_released: false,
            shutdown_failed: false,
        };
        #[cfg(windows)]
        if composition.registry.active().is_some() {
            let kernel = configured_image("ELIOT_KERNEL_BINARY")?;
            let store = configured_image("ELIOT_STORE_BINARY")?;
            composition.start_approved_contour(kernel, store)?;
        }
        Ok(composition)
    }

    /// Clears an unclean durable Host admission gate using typed evidence that
    /// exactly matches the inspected stale process, epoch and Job disposition.
    /// This path does not advance an epoch or fabricate process identity and
    /// is intended for bounded offline recovery only.
    ///
    /// # Errors
    ///
    /// Returns an error if the owner lease cannot be acquired, durable state
    /// cannot be inspected, evidence mismatches, or recovery cannot finalize.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the recovery API retains its established owned installation identity parameter"
    )]
    pub fn recover_unclean(
        path: impl AsRef<Path>,
        installation: PlatformHandle,
        evidence: HostRecoveryEvidence,
    ) -> Result<(), HostError> {
        if installation.as_str().trim().is_empty() {
            return Err(HostError::MissingInstallation);
        }
        let mut owner_lease = HostOwnerLease::acquire(&installation).map_err(owner_lease_error)?;
        let snapshot = RedbHostStateStore::inspect_recovery(path.as_ref(), &installation).map_err(
            |error| {
                HostError::OwnerLeaseRecovery(format!(
                    "durable Host admission inspection failed; recovery required: {error}"
                ))
            },
        )?;
        validate_recovery_evidence(&snapshot, &evidence)?;
        let state_store = RedbHostStateStore::open_existing(path, &installation)?;
        let token = state_store
            .prepare_recovery_pending(evidence)
            .map_err(HostError::State)?;
        // Compare-and-clear is durable while the owner mutex is still held.
        // The RecoveryFinalized disposition remains a gate until the owner
        // release is proven and the exact token is cleanly finalized.
        state_store
            .finalize_recovery_clear(&token)
            .map_err(HostError::State)?;
        // Keep the installation owner mutex through both durable recovery
        // mutations. Releasing first would allow a second Host to observe
        // the intermediate RecoveryFinalized projection and race the final
        // clean transition.
        state_store
            .finalize_clean_shutdown(token)
            .map_err(HostError::State)?;
        owner_lease.release().map_err(owner_lease_release_error)
    }

    /// Returns the Host epoch bound to this process.
    #[must_use]
    pub const fn host_epoch(&self) -> &HostInstallationEpoch {
        &self.host
    }

    /// Returns the canonical owner-object name held for this composition.
    ///
    /// The handle itself remains private and is released only after durable
    /// shutdown completion and `HostComposition` drop.
    #[must_use]
    pub fn owner_lease_name(&self) -> &str {
        self.owner_lease.name()
    }

    /// Reads the Host-only operational state from redb.
    ///
    /// # Errors
    ///
    /// Returns an error if the durable Host state cannot be loaded.
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
    ///
    /// # Errors
    ///
    /// Returns an error if approval validation or durable registry persistence fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, the generation is not
    /// approved, an active contour requires cutover, or persistence fails.
    pub fn activate_generation(&mut self, generation: &PlatformHandle) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        #[cfg(windows)]
        if self.has_process_contour() {
            return Err(HostError::ProcessContour(
                "active process contour requires cutover_generation".to_owned(),
            ));
        }
        self.registry
            .activate(generation)
            .map_err(HostError::Installation)?;
        self.registry_store
            .save(&self.registry)
            .map_err(HostError::Installation)
    }

    /// Rolls back to the registry's last-known-good generation.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, an active contour requires a
    /// bounded rollback, no last-known-good generation exists, or persistence fails.
    pub fn rollback_generation(&mut self) -> Result<PlatformHandle, HostError> {
        self.ensure_admission_open()?;
        #[cfg(windows)]
        if self.has_process_contour() {
            return Err(HostError::ProcessContour(
                "active process contour requires bounded cutover rollback".to_owned(),
            ));
        }
        let generation = self.registry.rollback().map_err(HostError::Installation)?;
        self.registry_store
            .save(&self.registry)
            .map_err(HostError::Installation)?;
        Ok(generation)
    }

    /// Starts the currently approved Kernel and store images in their
    /// independent Host-owned Job branches.  The registry is checked before
    /// any process is created, and the launch contour binds generation,
    /// configuration digest, installation and Host epoch into the child
    /// environment.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, no approved generation exists,
    /// or process identity, artifact, configuration, launch, or persistence fails.
    #[cfg(windows)]
    pub fn start_approved_contour(
        &mut self,
        kernel_executable: impl AsRef<Path>,
        store_executable: impl AsRef<Path>,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        let active = self
            .registry
            .active()
            .ok_or_else(|| HostError::ProcessContour("no approved active generation".to_owned()))?;
        let (kernel_artifact, store_artifact) = active
            .manifest
            .runtime_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (approved_kernel_path, approved_store_path, approved_config_path) =
            active.manifest.runtime_paths();
        let config_path = PathBuf::from(approved_config_path.as_str());
        self.jobs.start_approved(
            kernel_executable.as_ref(),
            store_executable.as_ref(),
            &active.manifest.generation,
            &active.manifest.config_digest,
            &config_path,
            approved_kernel_path,
            approved_store_path,
            approved_config_path,
            kernel_artifact,
            store_artifact,
            &self.host,
        )?;
        if let Err(error) = self.persist_process_observations(&active.manifest.generation) {
            self.cleanup_launched_contour(error)
        } else {
            Ok(())
        }
    }

    /// Activates one approved generation only after a bounded process cutover;
    /// a rejected candidate restores the registry's previous LKG projection.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, either generation is invalid,
    /// cutover or rollback fails, or the registry cannot be persisted.
    #[cfg(windows)]
    pub fn cutover_generation(
        &mut self,
        generation: &PlatformHandle,
        candidate_kernel: impl AsRef<Path>,
        candidate_store: impl AsRef<Path>,
        prior_kernel: impl AsRef<Path>,
        prior_store: impl AsRef<Path>,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        let prior = self.registry.active().cloned().ok_or_else(|| {
            HostError::ProcessContour("no active generation to cut over".to_owned())
        })?;
        let candidate = self
            .registry
            .generations
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour("candidate generation is not approved".to_owned())
            })?;
        let (candidate_kernel_artifact, candidate_store_artifact) = candidate
            .manifest
            .runtime_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (prior_kernel_artifact, prior_store_artifact) = prior
            .manifest
            .runtime_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (candidate_kernel_path, candidate_store_path, candidate_config_path) =
            candidate.manifest.runtime_paths();
        let (prior_kernel_path, prior_store_path, prior_config_path) =
            prior.manifest.runtime_paths();
        let candidate_config_locator = PathBuf::from(candidate_config_path.as_str());
        let prior_config_locator = PathBuf::from(prior_config_path.as_str());
        // Resolve every candidate and rollback locator before mutating the
        // in-memory active projection.  A malformed manifest must not leave
        // the registry pointed at a generation that never entered the
        // bounded cutover contour.
        self.registry
            .activate(generation)
            .map_err(HostError::Installation)?;
        let result = self.jobs.cutover_with_rollback(
            candidate_kernel.as_ref(),
            candidate_store.as_ref(),
            prior_kernel.as_ref(),
            prior_store.as_ref(),
            &candidate.manifest.generation,
            &candidate.manifest.config_digest,
            &candidate_config_locator,
            candidate_kernel_path,
            candidate_store_path,
            candidate_config_path,
            candidate_kernel_artifact,
            candidate_store_artifact,
            &prior.manifest.generation,
            &prior.manifest.config_digest,
            &prior_config_locator,
            prior_kernel_path,
            prior_store_path,
            prior_config_path,
            prior_kernel_artifact,
            prior_store_artifact,
            &self.host,
        );
        match result {
            Ok(()) => {
                if let Err(error) = self.registry_store.save(&self.registry) {
                    let cleanup_error =
                        self.cleanup_launched_contour(HostError::Installation(error));
                    let _ = self.registry.rollback();
                    let _ = self.registry_store.save(&self.registry);
                    return cleanup_error;
                }
                if let Err(error) =
                    self.persist_process_observations(&candidate.manifest.generation)
                {
                    let cleanup = self.cleanup_launched_contour(error);
                    // A post-launch observation failure must not leave the
                    // candidate as the in-memory or durable active
                    // generation.  The newly launched branches have already
                    // been consumed by cleanup; restore the prior LKG
                    // projection before returning the failure.
                    let _ = self.registry.rollback();
                    let _ = self.registry_store.save(&self.registry);
                    cleanup
                } else {
                    Ok(())
                }
            }
            Err(error) => {
                let _ = self.registry.rollback();
                let _ = self.registry_store.save(&self.registry);
                Err(error)
            }
        }
    }

    /// Reconciles the approved contour and records fresh process observations.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is fenced, approved material cannot be
    /// revalidated, branch reconciliation fails, or observations cannot persist.
    #[cfg(windows)]
    pub fn reconcile_approved_contour(&mut self) -> Result<HostBranchDisposition, HostError> {
        self.ensure_admission_open()?;
        let active = self
            .registry
            .active()
            .ok_or_else(|| HostError::ProcessContour("no approved active generation".to_owned()))?;
        let (kernel_artifact, store_artifact) = active
            .manifest
            .runtime_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (approved_kernel_path, approved_store_path, approved_config_path) =
            active.manifest.runtime_paths();
        let config_path = PathBuf::from(approved_config_path.as_str());
        let disposition = self.jobs.reconcile(
            &active.manifest.generation,
            &active.manifest.config_digest,
            &config_path,
            approved_kernel_path,
            approved_store_path,
            approved_config_path,
            kernel_artifact,
            store_artifact,
            &self.host,
        )?;
        if let Err(error) = self
            .persist_process_observations_with_disposition(&active.manifest.generation, disposition)
        {
            return self.cleanup_launched_contour(error).map(|()| disposition);
        }
        Ok(disposition)
    }

    /// Returns whether either approved process branch or its bounded recovery
    /// record remains present for reconciliation.
    #[cfg(windows)]
    #[must_use]
    pub fn has_process_contour(&self) -> bool {
        self.jobs.has_recorded_contour()
    }

    #[cfg(windows)]
    fn persist_process_observations(&self, generation: &PlatformHandle) -> Result<(), HostError> {
        self.persist_process_observations_with_disposition(
            generation,
            HostBranchDisposition::Healthy,
        )
    }

    #[cfg(windows)]
    fn persist_process_observations_with_disposition(
        &self,
        generation: &PlatformHandle,
        disposition: HostBranchDisposition,
    ) -> Result<(), HostError> {
        if let Some(kernel) = self.jobs.kernel_process() {
            let kernel_record = process_record(kernel, "Kernel", &self.host)?;
            let kernel_recovery = self.jobs.kernel_recovery_binding(
                generation,
                &kernel_record,
                &self.host.installation,
            )?;
            self.state_store
                .commit_activation(
                    eliot_platform::HostActivationTransition {
                        context: lifecycle_context(&self.host, "kernel-activation")?,
                        installation: self.host.installation.clone(),
                        process: kernel_record,
                    },
                    kernel_recovery,
                )
                .map_err(HostError::State)?;
        }
        if let Some(store) = self.jobs.store_process() {
            let store_record = process_record(store, "Store", &self.host)?;
            self.state_store
                .record_dependency(eliot_platform::ManagedDependencyTransition {
                    context: lifecycle_context(&self.host, "store-observation")?,
                    installation: self.host.installation.clone(),
                    dependency: store_record,
                })
                .map_err(HostError::State)?;
        }
        if !matches!(disposition, HostBranchDisposition::Healthy) {
            let state = self.snapshot()?;
            let store_process = state
                .managed_dependencies
                .iter()
                .find(|process| process.owner == "Store")
                .cloned();
            let mut fences = Vec::new();
            if matches!(
                disposition,
                HostBranchDisposition::KernelDegraded | HostBranchDisposition::BothDegraded
            ) {
                fences.push((HostBranchKind::Kernel, state.active_process.clone()));
            }
            if matches!(
                disposition,
                HostBranchDisposition::StoreDegraded | HostBranchDisposition::BothDegraded
            ) {
                fences.push((HostBranchKind::Store, store_process));
            }
            for (branch, observed_process) in fences {
                self.state_store
                    .record_branch_recovery(HostBranchRecoveryFence {
                        installation: self.host.installation.clone(),
                        generation: generation.clone(),
                        branch,
                        observed_process,
                        reason: PlatformHandle::new(format!(
                            "host-branch-degraded:{disposition:?}"
                        ))
                        .map_err(|error| HostError::Platform(error.to_string()))?,
                    })
                    .map_err(HostError::State)?;
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    /// Returns whether a durable degraded-branch recovery fence is active.
    ///
    /// # Errors
    ///
    /// Returns an error if the durable Host state cannot be loaded.
    pub fn has_durable_branch_fence(&self) -> Result<bool, HostError> {
        Ok(self.snapshot()?.recovery_fence.is_some())
    }

    #[cfg(windows)]
    fn cleanup_launched_contour(&mut self, error: HostError) -> Result<(), HostError> {
        let kernel = self.jobs.terminate_kernel();
        let store = self.jobs.terminate_store();
        self.jobs.clear_recorded_contour();
        match (kernel, store) {
            (Ok(()), Ok(())) => Err(error),
            (kernel, store) => Err(HostError::ProcessContour(format!(
                "persistence failed ({error}); launched contour cleanup failed: kernel={kernel:?}, store={store:?}"
            ))),
        }
    }

    fn ensure_admission_open(&self) -> Result<(), HostError> {
        if !self.running {
            return Err(HostError::Stopped);
        }
        if self.pending_release.is_some() || self.shutdown_failed {
            return Err(HostError::OwnerLeaseRecovery(
                "durable Host release/recovery is still pending".to_owned(),
            ));
        }
        let state = self.snapshot()?;
        if state.disposition.is_release_pending() || state.recovery_fence.is_some() {
            return Err(HostError::OwnerLeaseRecovery(
                "durable Host release/recovery fence is still active".to_owned(),
            ));
        }
        Ok(())
    }

    /// Requests a bounded Host stop. SCM owns the sibling Watchdog and is not
    /// represented by either Host Job Object branch.
    ///
    /// # Errors
    ///
    /// Returns an error if the Host is already stopped or if process
    /// termination, durable shutdown finalization, or owner-lease release fails.
    pub fn stop(&mut self) -> Result<(), HostError> {
        if !self.running {
            return Err(HostError::Stopped);
        }
        if self.pending_release.is_none() {
            let state = self.snapshot()?;
            let process = state
                .active_process
                .unwrap_or_else(|| self.host_process.clone());
            #[cfg(windows)]
            {
                self.jobs.terminate_kernel()?;
                self.jobs.terminate_store()?;
            }
            let marker = eliot_platform::HostShutdownMarker {
                context: lifecycle_context(&self.host, "host-stop")?,
                installation: self.host.installation.clone(),
                process,
            };
            let token = self
                .state_store
                .prepare_release_pending(marker)
                .map_err(HostError::State)?;
            self.pending_release = Some(token);
            self.durable_finalized = false;
        }
        let token = self.pending_release.take().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("release token is unavailable".to_owned())
        })?;
        if !self.durable_finalized {
            if let Err(error) = self
                .state_store
                .finalize_clean_shutdown(token.clone())
                .map_err(HostError::State)
            {
                // ReleasePending remains durable and ownership is retained;
                // a retry must complete this mutation before release.
                self.pending_release = Some(token);
                self.shutdown_failed = true;
                return Err(error);
            }
            self.durable_finalized = true;
        }
        if !self.owner_released {
            if let Err(error) = self
                .owner_lease
                .release()
                .map_err(owner_lease_release_error)
            {
                self.pending_release = Some(token);
                self.shutdown_failed = true;
                return Err(error);
            }
            self.owner_released = true;
        }
        self.running = false;
        self.shutdown_failed = false;
        Ok(())
    }

    #[must_use]
    pub const fn running(&self) -> bool {
        self.running
    }

    /// Returns whether a prior shutdown attempt recorded a release/recovery
    /// failure. A stopped composition with this flag is not a clean success.
    #[must_use]
    pub const fn shutdown_failed(&self) -> bool {
        self.shutdown_failed
    }

    #[cfg(windows)]
    /// Returns the physical Host job branches for service composition.
    #[must_use]
    pub const fn jobs(&self) -> &HostJobBranches {
        &self.jobs
    }
}

fn host_process_record(host: &HostInstallationEpoch) -> Result<ServiceProcessRecord, HostError> {
    let authority_epoch = AuthorityEpoch::new(host.epoch.current.sequence)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(ServiceProcessRecord {
        process_id: format!(
            "host:{}:{}:{}",
            host.epoch.current.lineage, host.epoch.current.sequence, host.nonce
        ),
        owner: SERVICE_NAME.to_owned(),
        state: ServiceProcessState::Ready,
        health: HealthVector::healthy(),
        authority_epoch,
    })
}

fn host_process_recovery_binding(
    host: &HostInstallationEpoch,
    observed_process: &ServiceProcessRecord,
) -> Result<HostProcessRecoveryBinding, HostError> {
    let image_path = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| {
            HostError::Platform(format!("Host image identity unavailable: {error}"))
        })?;
    Ok(HostProcessRecoveryBinding {
        installation: host.installation.clone(),
        observed_process: observed_process.clone(),
        process_generation: host.nonce.clone(),
        process_id: std::process::id(),
        image_path: PlatformHandle::new(image_path.to_string_lossy().into_owned()).map_err(
            |error| HostError::Platform(format!("invalid Host image identity: {error}")),
        )?,
        job: HostJobDisposition::NotAssigned,
    })
}

#[cfg(windows)]
fn process_recovery_binding(
    process: &ProcessIdentity,
    generation: &PlatformHandle,
    job: &JobObjectIdentity,
    installation: &PlatformHandle,
    observed_process: &ServiceProcessRecord,
) -> Result<HostProcessRecoveryBinding, HostError> {
    Ok(HostProcessRecoveryBinding {
        installation: installation.clone(),
        observed_process: observed_process.clone(),
        process_generation: generation.clone(),
        process_id: process.process_id,
        image_path: PlatformHandle::new(process.image_path.clone()).map_err(|error| {
            HostError::ProcessContour(format!("invalid observed image identity: {error}"))
        })?,
        job: HostJobDisposition::Assigned {
            job: PlatformHandle::new(job.name()).map_err(|error| {
                HostError::ProcessContour(format!("invalid Job identity: {error}"))
            })?,
        },
    })
}

fn validate_recovery_evidence(
    snapshot: &HostRecoverySnapshot,
    evidence: &HostRecoveryEvidence,
) -> Result<(), HostError> {
    evidence.validate().map_err(HostError::State)?;
    let disposition_matches = snapshot.disposition == evidence.observed_disposition
        || snapshot.recovery_evidence.as_ref() == Some(evidence);
    if snapshot.installation != evidence.installation
        || snapshot.host_epoch != evidence.host_epoch
        || snapshot.active_process != evidence.stale_active_process
        || snapshot.process != evidence.process
        || !disposition_matches
    {
        return Err(HostError::OwnerLeaseRecovery(
            "recovery evidence does not exactly match the inspected stale Host projection"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn process_record(
    process: &ProcessIdentity,
    owner: &str,
    host: &HostInstallationEpoch,
) -> Result<ServiceProcessRecord, HostError> {
    let authority_epoch = AuthorityEpoch::new(host.epoch.current.sequence)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(ServiceProcessRecord {
        process_id: format!("{}:{}", process.process_id, process.start_time_100ns),
        owner: owner.to_owned(),
        state: ServiceProcessState::Ready,
        health: HealthVector::healthy(),
        authority_epoch,
    })
}

fn lifecycle_context(
    host: &HostInstallationEpoch,
    operation: &str,
) -> Result<RequestMetadata, HostError> {
    let request_id = RequestId::new(format!(
        "host:{}:{}:{}:{}",
        host.epoch.current.lineage,
        host.epoch.current.sequence,
        operation,
        std::process::id()
    ))
    .map_err(|error| HostError::Platform(error.to_string()))?;
    let authority_epoch = AuthorityEpoch::new(host.epoch.current.sequence)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(RequestMetadata {
        request_id,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("eliot-host")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        source_id: SourceId::new("eliot-host-service")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        state_fence: StateFence::new(authority_epoch, ResourceGeneration::genesis()),
        clock: ClockReading::default(),
    })
}

fn owner_lease_error(error: HostOwnerLeaseError) -> HostError {
    match error {
        HostOwnerLeaseError::LiveOwner => HostError::OwnerLeaseHeld,
        HostOwnerLeaseError::ExistingObject => HostError::OwnerLeaseRecovery(
            "a pre-existing Host owner object is untrusted; explicit recovery is required"
                .to_owned(),
        ),
        HostOwnerLeaseError::AbandonedOwner => HostError::OwnerLeaseRecovery(
            "the previous Host owner abandoned its mutex; inspect durable shutdown state before retrying"
                .to_owned(),
        ),
        HostOwnerLeaseError::OwnershipUncertain { win32_error } => HostError::OwnerLeaseRecovery(
            format!("Windows could not classify the owner mutex (Win32 error {win32_error})"),
        ),
        HostOwnerLeaseError::CreationFailed { win32_error } => HostError::Platform(format!(
            "Host owner mutex could not be created or opened (Win32 error {win32_error})"
        )),
        HostOwnerLeaseError::UnsupportedPlatform => HostError::Platform(
            "Host owner lease is unavailable on this platform; refusing Host admission".to_owned(),
        ),
    }
}

fn owner_lease_release_error(error: HostOwnerLeaseReleaseError) -> HostError {
    HostError::OwnerLeaseRecovery(format!(
        "owner release failed; durable recovery remains required: {error}"
    ))
}

#[cfg(windows)]
fn configured_image(name: &str) -> Result<PathBuf, HostError> {
    let value = std::env::var_os(name)
        .ok_or_else(|| HostError::ProcessContour(format!("{name} is not configured")))?;
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        return Err(HostError::ProcessContour(format!(
            "{name} must name an absolute executable file"
        )));
    }
    Ok(path)
}

impl From<io::Error> for HostError {
    fn from(error: io::Error) -> Self {
        Self::Platform(error.to_string())
    }
}
