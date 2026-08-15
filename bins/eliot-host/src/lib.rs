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
};
use eliot_platform::{
    HostInstallationState, HostJobDisposition, HostProcessRecoveryBinding, HostRecoveryEvidence,
    HostStateStore, PlatformHandle,
};
use eliot_platform_windows::{HostOwnerLease, HostOwnerLeaseError, HostOwnerLeaseReleaseError};
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
    JobObjectIdentity, ProcessIdentity, RunningJobChild, SuspendedJobChild, SuspendedLaunchSpec,
    WindowsAdapterError,
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
}

#[cfg(windows)]
impl HostJobBranches {
    /// Creates two owner-scoped Job identities.  The actual Job handles are
    /// created only by the approved suspended launch below; there is no
    /// unbound PID assignment path.
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
        })
    }

    fn environment(
        host: &HostInstallationEpoch,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        job_identity: &JobObjectIdentity,
    ) -> Vec<(OsString, OsString)> {
        let mut environment = std::env::vars_os()
            .filter(|(key, _)| {
                !matches!(
                    key.to_string_lossy().as_ref(),
                    "ELIOT_APPROVED_GENERATION"
                        | "ELIOT_GENERATION_CONFIG_DIGEST"
                        | "ELIOT_APPROVED_ARTIFACT"
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

    fn launch(
        executable: &Path,
        identity: &JobObjectIdentity,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        let executable = std::fs::canonicalize(executable)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let working_directory = executable
            .parent()
            .ok_or_else(|| HostError::ProcessContour("approved image has no parent".to_owned()))?;
        let spec = SuspendedLaunchSpec::new(
            executable.clone(),
            Vec::new(),
            working_directory,
            Self::environment(host, generation, config_digest, artifact, identity),
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
    pub fn start_approved(
        &mut self,
        kernel_executable: &Path,
        store_executable: &Path,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<(), HostError> {
        if self.kernel.is_some() || self.store.is_some() {
            return Err(HostError::ProcessContour(
                "approved contour is already running".to_owned(),
            ));
        }
        let kernel = Self::launch(
            kernel_executable,
            &self.kernel_identity,
            generation,
            config_digest,
            artifact,
            host,
        )?;
        let store = match Self::launch(
            store_executable,
            &self.store_identity,
            generation,
            config_digest,
            artifact,
            host,
        ) {
            Ok(store) => store,
            Err(error) => {
                let _ = kernel.terminate(0xE017_0001);
                return Err(error);
            }
        };
        self.kernel_executable = Some(kernel_executable.to_owned());
        self.store_executable = Some(store_executable.to_owned());
        self.kernel = Some(kernel);
        self.store = Some(store);
        Ok(())
    }

    /// Reconciles both branches with a bounded restart budget.  If a
    /// candidate branch exits, the old branch is terminated and relaunched
    /// only from the stored approved image, never from an observed PID.
    pub fn reconcile(
        &mut self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<(), HostError> {
        for attempt in 0..2 {
            let kernel_dead = self
                .kernel
                .as_ref()
                .map(|child| child.observe())
                .transpose()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
                .is_some_and(|observation| {
                    !matches!(
                        observation,
                        eliot_platform_windows::RunningJobObservation::Running { .. }
                    )
                });
            let store_dead = self
                .store
                .as_ref()
                .map(|child| child.observe())
                .transpose()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?
                .is_some_and(|observation| {
                    !matches!(
                        observation,
                        eliot_platform_windows::RunningJobObservation::Running { .. }
                    )
                });
            if !kernel_dead && !store_dead {
                return Ok(());
            }
            self.terminate_kernel()?;
            self.terminate_store()?;
            if attempt == 1 {
                return Err(HostError::ProcessContour(
                    "approved contour exceeded bounded restart budget".to_owned(),
                ));
            }
            let kernel = self.kernel_executable.clone().ok_or_else(|| {
                HostError::ProcessContour("Kernel image is not recorded".to_owned())
            })?;
            let store = self.store_executable.clone().ok_or_else(|| {
                HostError::ProcessContour("store image is not recorded".to_owned())
            })?;
            self.start_approved(&kernel, &store, generation, config_digest, artifact, host)?;
        }
        Ok(())
    }

    /// Performs a bounded side-by-side cutover with an explicit rollback
    /// image.  The old branches are drained before the candidate is admitted;
    /// if candidate startup or suspended validation fails, only the supplied
    /// prior approved images may be relaunched.
    pub fn cutover_with_rollback(
        &mut self,
        candidate_kernel: &Path,
        candidate_store: &Path,
        prior_kernel: &Path,
        prior_store: &Path,
        candidate_generation: &PlatformHandle,
        candidate_config_digest: &PlatformHandle,
        candidate_artifact: &PlatformHandle,
        prior_generation: &PlatformHandle,
        prior_config_digest: &PlatformHandle,
        prior_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
    ) -> Result<(), HostError> {
        self.terminate_kernel()?;
        self.terminate_store()?;
        match self.start_approved(
            candidate_kernel,
            candidate_store,
            candidate_generation,
            candidate_config_digest,
            candidate_artifact,
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
                        prior_artifact,
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
    pub fn terminate_kernel(&mut self) -> Result<(), HostError> {
        if let Some(kernel) = self.kernel.take() {
            kernel
                .terminate(0xE017_0001)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        }
        Ok(())
    }

    /// Terminates the store branch during bounded rollback or shutdown.
    pub fn terminate_store(&mut self) -> Result<(), HostError> {
        if let Some(store) = self.store.take() {
            store
                .terminate(0xE017_0002)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        }
        Ok(())
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

    fn kernel_recovery_binding(
        &self,
        generation: &PlatformHandle,
    ) -> Result<HostProcessRecoveryBinding, HostError> {
        let process = self
            .kernel_process()
            .ok_or_else(|| HostError::ProcessContour("Kernel process is unavailable".to_owned()))?;
        process_recovery_binding(process, generation, &self.kernel_identity)
    }
}

/// Host-owned lifecycle state and installation activation registry.
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
    shutdown_failed: bool,
}

impl HostComposition {
    /// Opens the durable Host contour for one installation identity and
    /// advances its persisted epoch before any process admission.
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
        let host_recovery = host_process_recovery_binding(&host)?;
        // Every Host invocation records an activation boundary.  If a prior
        // projection had no clean marker, this deliberately remains an
        // unclean recovery until stop() writes the shutdown receipt.
        state_store
            .commit_activation_with_recovery(
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
        owner_lease.release().map_err(owner_lease_release_error)?;
        state_store
            .finalize_clean_shutdown(token)
            .map_err(HostError::State)
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
    pub fn rollback_generation(&mut self) -> Result<PlatformHandle, HostError> {
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
    #[cfg(windows)]
    pub fn start_approved_contour(
        &mut self,
        kernel_executable: impl AsRef<Path>,
        store_executable: impl AsRef<Path>,
    ) -> Result<(), HostError> {
        let active = self
            .registry
            .active()
            .ok_or_else(|| HostError::ProcessContour("no approved active generation".to_owned()))?;
        let artifact = active.manifest.artifact_digests.first().ok_or_else(|| {
            HostError::ProcessContour("active generation has no artifact".to_owned())
        })?;
        self.jobs.start_approved(
            kernel_executable.as_ref(),
            store_executable.as_ref(),
            &active.manifest.generation,
            &active.manifest.config_digest,
            artifact,
            &self.host,
        )?;
        self.persist_process_observations(active.manifest.generation.clone())
    }

    /// Activates one approved generation only after a bounded process cutover;
    /// a rejected candidate restores the registry's previous LKG projection.
    #[cfg(windows)]
    pub fn cutover_generation(
        &mut self,
        generation: &PlatformHandle,
        candidate_kernel: impl AsRef<Path>,
        candidate_store: impl AsRef<Path>,
        prior_kernel: impl AsRef<Path>,
        prior_store: impl AsRef<Path>,
    ) -> Result<(), HostError> {
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
        self.registry
            .activate(generation)
            .map_err(HostError::Installation)?;
        let result =
            self.jobs.cutover_with_rollback(
                candidate_kernel.as_ref(),
                candidate_store.as_ref(),
                prior_kernel.as_ref(),
                prior_store.as_ref(),
                &candidate.manifest.generation,
                &candidate.manifest.config_digest,
                candidate.manifest.artifact_digests.first().ok_or_else(|| {
                    HostError::ProcessContour("candidate has no artifact".to_owned())
                })?,
                &prior.manifest.generation,
                &prior.manifest.config_digest,
                prior.manifest.artifact_digests.first().ok_or_else(|| {
                    HostError::ProcessContour("prior generation has no artifact".to_owned())
                })?,
                &self.host,
            );
        match result {
            Ok(()) => {
                self.registry_store
                    .save(&self.registry)
                    .map_err(HostError::Installation)?;
                self.persist_process_observations(candidate.manifest.generation)
            }
            Err(error) => {
                let _ = self.registry.rollback();
                let _ = self.registry_store.save(&self.registry);
                Err(error)
            }
        }
    }

    /// Reconciles the approved contour and records fresh process observations.
    #[cfg(windows)]
    pub fn reconcile_approved_contour(&mut self) -> Result<(), HostError> {
        let active = self
            .registry
            .active()
            .ok_or_else(|| HostError::ProcessContour("no approved active generation".to_owned()))?;
        let artifact = active.manifest.artifact_digests.first().ok_or_else(|| {
            HostError::ProcessContour("active generation has no artifact".to_owned())
        })?;
        self.jobs.reconcile(
            &active.manifest.generation,
            &active.manifest.config_digest,
            artifact,
            &self.host,
        )?;
        self.persist_process_observations(active.manifest.generation.clone())
    }

    /// Returns whether both approved process branches have been admitted.
    #[cfg(windows)]
    #[must_use]
    pub fn has_process_contour(&self) -> bool {
        self.jobs.kernel_process().is_some() && self.jobs.store_process().is_some()
    }

    #[cfg(windows)]
    fn persist_process_observations(&self, generation: PlatformHandle) -> Result<(), HostError> {
        let kernel = self.jobs.kernel_process().ok_or_else(|| {
            HostError::ProcessContour("Kernel process observation is unavailable".to_owned())
        })?;
        let store = self.jobs.store_process().ok_or_else(|| {
            HostError::ProcessContour("store process observation is unavailable".to_owned())
        })?;
        let kernel_record = process_record(kernel, "Kernel", &self.host)?;
        let store_record = process_record(store, "Store", &self.host)?;
        let kernel_recovery = self.jobs.kernel_recovery_binding(&generation)?;
        self.state_store
            .commit_activation_with_recovery(
                eliot_platform::HostActivationTransition {
                    context: lifecycle_context(&self.host, "kernel-activation")?,
                    installation: self.host.installation.clone(),
                    process: kernel_record,
                },
                kernel_recovery,
            )
            .map_err(HostError::State)?;
        self.state_store
            .record_dependency(eliot_platform::ManagedDependencyTransition {
                context: lifecycle_context(&self.host, "store-observation")?,
                installation: self.host.installation.clone(),
                dependency: store_record,
            })
            .map_err(HostError::State)?;
        let _ = generation;
        Ok(())
    }

    /// Requests a bounded Host stop. SCM owns the sibling Watchdog and is not
    /// represented by either Host Job Object branch.
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
        }
        let token = self.pending_release.take().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("release token is unavailable".to_owned())
        })?;
        if let Err(error) = self
            .owner_lease
            .release()
            .map_err(owner_lease_release_error)
        {
            // The durable ReleasePending disposition remains in place and
            // the owner handle/ownership is retained by the platform adapter
            // for a bounded retry. Drop must not turn this into Clean.
            self.pending_release = Some(token);
            self.shutdown_failed = true;
            return Err(error);
        }
        if let Err(error) = self
            .state_store
            .finalize_clean_shutdown(token)
            .map_err(HostError::State)
        {
            // The mutex is already released, so no further process admission
            // is possible until this pending/recovery projection is cleared.
            self.shutdown_failed = true;
            self.running = false;
            return Err(error);
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
) -> Result<HostProcessRecoveryBinding, HostError> {
    let image_path = std::env::current_exe()
        .and_then(|path| std::fs::canonicalize(path))
        .map_err(|error| {
            HostError::Platform(format!("Host image identity unavailable: {error}"))
        })?;
    Ok(HostProcessRecoveryBinding {
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
) -> Result<HostProcessRecoveryBinding, HostError> {
    Ok(HostProcessRecoveryBinding {
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
