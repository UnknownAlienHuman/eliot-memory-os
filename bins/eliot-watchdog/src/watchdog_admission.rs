//! Read-only installation-backed Watchdog admission and runtime binding.
//!
//! Architecture anchors: `A8.1` (Watchdog purpose), `ARCH-WDG-01` (independent supervision).
//! Implementation anchors: `I8.1` (process and authority), `I8.2` (independent observation routes).
//!
//! This module owns only the installer-bound admission read, validation, and retained no-follow
//! runtime binding. It performs no SCM mutation, lifecycle decision, canonical/ORS/Host-journal
//! write, authority minting, or policy operation.
//!
//! It owns two admissions. `FileWatchdogAdmission` admits the installation THIS
//! PROCESS runs under, and additionally requires that the running image and the
//! durable Phase-B supervision authority belong to it.
//! [`admit_isolated_destination`] admits a DIFFERENT, isolated, new installation
//! as a recovery-import destination, and requires neither — a destination is by
//! definition not the running process and has no authority to reuse. Both go
//! through the same registry inspection, manifest selection, service-approval,
//! artifact-digest, and retained-root-lease owners; only those two
//! process-coupled checks differ.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_installation::{
    ApprovedGenerationRegistry, CandidateManifest, InstallationError, InstallationProfile,
    PendingActivationState, RedbInstallationRegistry, RuntimeStateRoots,
    ValidatedRuntimeRootLeases, WindowsRuntimeRootLease, WindowsRuntimeRootLeaseProvider,
    verify_file_digest, verify_file_digest_with_lease,
};
use eliot_platform_windows::{
    ProtectedPathLease, ProtectedRootLease, ServiceBootstrapArguments, ServiceRegistrationRequest,
    windows_paths_equal,
};
use eliot_runtime_contracts::ProvisionedSupervisionAuthority;

use super::runtime_manifest_selection::{approved_host_artifact_path, select_runtime_manifest};
use super::service_registration_projection::load_approved_service_registrations;
use super::{
    ApprovedHostRegistration, INSTALLATION_REGISTRY_FILE_NAME, PROTOCOL_VERSION, SERVICE_NAME,
    SpoolError, VerifiedWatchdogAdmission, WatchdogAdmissionSource, WatchdogAuthorityState,
    WatchdogConfig, WatchdogReadiness, supervision_lease_load,
};

/// Registry- and ORS-backed admission source for the immutable Host
/// publication selected by the current authoritative ORS receipt.
pub struct FileWatchdogAdmission {
    pub(super) registry_path: PathBuf,
    pub(super) installation_id: String,
    pub(super) roots_digest: String,
    pub(super) bootstrap: ServiceBootstrapArguments,
    pub(super) binding: WatchdogRuntimeBinding,
}

/// Approved runtime roots plus the retained no-follow leases that prove them.
#[derive(Clone)]
pub struct WatchdogRuntimeBinding {
    /// Canonical installer-approved Host root selected by SCM and the
    /// registry manifest.
    pub(super) host_state_root: PathBuf,
    pub(super) roots: RuntimeStateRoots,
    pub(super) selected_manifest: Arc<CandidateManifest>,
    pub(super) approved_host_image: PathBuf,
    pub(super) approved_host_registration: ApprovedHostRegistration,
    pub(super) approved_watchdog_registration: ServiceRegistrationRequest,
    pub(super) provisioned_supervision_authority: ProvisionedSupervisionAuthority,
    /// Retained for the complete lifetime of the admission and sensor. This
    /// is the no-follow proof that the Host-state contour cannot be replaced
    /// underneath path-based redb/file consumers.
    pub(super) host_state_root_lease: Arc<ProtectedRootLease>,
    pub(super) _approved_host_image_lease: Arc<ProtectedPathLease>,
    pub(super) _root_leases: Arc<ValidatedRuntimeRootLeases<WindowsRuntimeRootLease>>,
}

impl WatchdogRuntimeBinding {
    /// Returns the canonical installer-approved Host state root.
    #[must_use]
    pub fn host_state_root(&self) -> &Path {
        &self.host_state_root
    }

    #[must_use]
    pub fn watchdog_state_root(&self) -> &Path {
        Path::new(self.roots.watchdog_state_root.as_str())
    }

    /// Returns the immutable `eliot-host.exe` sibling derived from the active
    /// generation's approved Watchdog image path.
    #[must_use]
    pub fn approved_host_image(&self) -> &Path {
        &self.approved_host_image
    }

    /// Returns the immutable `eliot-kernel.exe` image of this approved
    /// generation, read out of the retained manifest.
    ///
    /// This is the ONLY accepted client image for the canonical Watchdog signals
    /// pipe. It is the same installer-approved generation whose registry, service
    /// approvals, and artifact digests admitted this process, so the pipe's
    /// authenticated peer is compared against one installation's own approved
    /// lineage rather than against a path a caller presented.
    #[must_use]
    pub fn approved_kernel_image(&self) -> &Path {
        Path::new(self.selected_manifest.kernel_executable_path.as_str())
    }
}

impl FileWatchdogAdmission {
    /// Transient redb lock-contention probe for registry reads (s37, #1339).
    ///
    /// Returns true when `message` carries the redb file-lock contention
    /// signal (`DatabaseAlreadyOpen`, rendered as
    /// `Database already open. Cannot acquire lock.`), including through the
    /// `InstallationError::Platform` and `SpoolError::InvalidLease` wrappers
    /// the Watchdog read path adds. Matching is case-insensitive and requires
    /// the lock marker so a same-process `Table ... already opened` defect
    /// stays fail-closed instead of retrying as transient contention.
    ///
    /// A transient lock is never a verdict on registry bytes: callers retry
    /// with bounded backoff inside their readiness window (A0.3 defaults to
    /// retry with new evidence outside Hard Boundaries) and keep every fence
    /// and approval check intact.
    #[must_use]
    pub fn is_transient_registry_lock(message: &str) -> bool {
        let folded = message.to_ascii_lowercase();
        if folded.contains("cannot acquire lock") {
            return true;
        }
        (folded.contains("already open") || folded.contains("alreadyopen"))
            && folded.contains("lock")
    }

    /// # Errors
    ///
    /// Returns an error when the registry is missing, invalid, has no exact
    /// bootstrap-selected active/pending contour, or its runtime roots cannot
    /// be retained and validated.
    pub fn from_registry(
        registry_path: impl Into<PathBuf>,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, SpoolError> {
        let _span = tracing::debug_span!("watchdog.admission_from_registry").entered();
        tracing::debug!(
            event = "watchdog.admission_attempted",
            observation = "attempted",
            "attempting watchdog admission from registry"
        );
        let registry_path = registry_path.into();
        let (installation_id, binding) = load_runtime_binding(&registry_path, &bootstrap)?;
        Ok(Self {
            registry_path,
            installation_id,
            roots_digest: binding.roots.roots_digest.as_str().to_owned(),
            bootstrap,
            binding,
        })
    }

    /// # Errors
    ///
    /// Returns an error when the registry is missing, invalid, has no exact
    /// bootstrap-selected active/pending contour, or its runtime roots cannot
    /// be retained and validated.
    pub fn new(
        registry_path: impl Into<PathBuf>,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, SpoolError> {
        Self::from_registry(registry_path, bootstrap)
    }

    /// Proves a pre-Phase-B pending fence without requiring durable authority.
    ///
    /// s33.2: the first-install dependency contour starts Watchdog before Host,
    /// credential provisioning, and Phase-B materialization by design
    /// (`package_planner.rs:1555-1557`; enforced through activation by
    /// `transaction.rs:795-805,870-882`), so the selected pending generation
    /// has no intent+prepared+receipt triple yet and
    /// `provisioned_supervision_authority_for_generation` returns `None`
    /// (`approved_generation_registry.rs:2798-2804`). Authority absence there
    /// is not corruption: I8.1 keeps the minimal sensor alive on demand with
    /// no coverage claimed, and I1.11 step 11 admits Watchdog coverage only
    /// after the supervision evidence exists.
    ///
    /// Returns the observable fenced readiness (`RunningNoAuthority`, no
    /// coverage claimed) if and only if every bootstrap-selected contour check
    /// that `from_registry` performs passes except the durable-authority gate:
    /// exact retained Host root, exact registry child, manifest selection,
    /// installer SCM registration approvals, and the `SystemService` profile.
    /// Retained image digests, root leases, and the authority template stay
    /// enforced by `from_registry` before any composition starts; they are
    /// never dropped, only deferred until the Phase-B receipt exists.
    ///
    /// Every other registry state (substituted contour, recovery-required
    /// pending, active generation without a committed fence, or an already
    /// provisioned authority) returns an error so the caller keeps failing
    /// closed instead of fencing.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is missing, invalid, has no exact
    /// bootstrap-selected contour, or is not a pre-Phase-B pending activation
    /// without durable supervision authority.
    pub fn pending_phase_b_fence_readiness(
        registry_path: impl Into<PathBuf>,
        bootstrap: &ServiceBootstrapArguments,
    ) -> Result<WatchdogReadiness, SpoolError> {
        let _span = tracing::debug_span!("watchdog.fence_readiness_probe").entered();
        tracing::debug!(
            event = "watchdog.fence_probe_attempted",
            observation = "attempted",
            "probing pre-Phase-B fence readiness"
        );
        let registry_path = registry_path.into();
        let declared_host_root = bootstrap.host_state_root().ok_or_else(|| {
            SpoolError::InvalidLease(
                "Watchdog SCM bootstrap omitted the installer-approved Host state root".to_owned(),
            )
        })?;
        let host_state_root_lease =
            ProtectedRootLease::open_existing(declared_host_root).map_err(|error| {
                SpoolError::InvalidLease(format!("Host state root open failed: {error}"))
            })?;
        let canonical_host_root = host_state_root_lease.canonical_path().map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root resolve failed: {error}"))
        })?;
        if !windows_paths_equal(&canonical_host_root, declared_host_root) {
            return Err(SpoolError::InvalidLease(
                "SCM Host state root is not the exact retained installation root".to_owned(),
            ));
        }
        let expected_registry_path = canonical_host_root.join(INSTALLATION_REGISTRY_FILE_NAME);
        if !windows_paths_equal(&registry_path, &expected_registry_path) {
            return Err(SpoolError::InvalidLease(
                "Watchdog registry path is not the exact approved Host child".to_owned(),
            ));
        }
        let registry = inspect_registry_at(
            ProtectedRootLease::open_existing(&canonical_host_root).map_err(|error| {
                SpoolError::InvalidLease(format!("Host state root reopen failed: {error}"))
            })?,
        )
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
        let selected_manifest = select_runtime_manifest(&registry, bootstrap)?;
        let authority = registry
            .provisioned_supervision_authority_for_generation(&selected_manifest.generation)
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
        if authority.is_some() {
            return Err(SpoolError::InvalidLease(
                "durable provisioned supervision authority already exists; pre-Phase-B fence is not applicable"
                    .to_owned(),
            ));
        }
        let pending = registry.pending_activation().ok_or_else(|| {
            SpoolError::InvalidLease(
                "selected generation without durable authority is not a pending pre-Phase-B activation"
                    .to_owned(),
            )
        })?;
        if !matches!(pending.state, PendingActivationState::Pending)
            || pending.manifest.generation != selected_manifest.generation
        {
            return Err(SpoolError::InvalidLease(
                "selected generation without durable authority is not a pending pre-Phase-B activation"
                    .to_owned(),
            ));
        }
        let _ = load_approved_service_registrations(&registry, &selected_manifest, bootstrap)?;
        if selected_manifest.runtime_launch.runtime_state_roots.profile
            != InstallationProfile::SystemService
        {
            return Err(SpoolError::InvalidLease(
                "watchdog has no retained file adapter for this installation profile".to_owned(),
            ));
        }
        Ok(WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state: WatchdogAuthorityState::RunningNoAuthority,
            coverage_claimed: false,
            kernel_epoch: 0,
            watchdog_epoch: 0,
            tick_interval_ms: WatchdogConfig::default().tick_interval.as_millis(),
            service_instance_guid: String::new(),
            host_challenge_nonce: String::new(),
            watchdog_readiness_sequence: 0,
        })
    }

    #[must_use]
    pub fn runtime_binding(&self) -> WatchdogRuntimeBinding {
        self.binding.clone()
    }
}

impl WatchdogAdmissionSource for FileWatchdogAdmission {
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError> {
        let template = self
            .binding
            .provisioned_supervision_authority
            .watchdog_admission_template()
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
        supervision_lease_load::load_content_addressed_supervision_lease_bound(
            self,
            &template,
            &self
                .binding
                .provisioned_supervision_authority
                .watchdog_admission_template_digest,
        )
    }

    fn approved_host_image(&self) -> Option<PathBuf> {
        Some(self.binding.approved_host_image().to_owned())
    }

    fn approved_host_registration(&self) -> Option<ApprovedHostRegistration> {
        Some(self.binding.approved_host_registration.clone())
    }
}

/// Single read-only registry inspection for the Watchdog contour.
///
/// Every Watchdog registry read flows through this choke point so lock, lease,
/// and validation handling has one future fix site. The handle is a
/// short-lived read-only inspection that is dropped before return: it never
/// creates a file, database, table, or ACL and never retains a writer across
/// a wait. Callers keep their exact `SpoolError` mapping so capsule detail
/// and failure taxonomy are unchanged.
pub(crate) fn inspect_registry_at(
    host_root: ProtectedRootLease,
) -> Result<Option<ApprovedGenerationRegistry>, InstallationError> {
    RedbInstallationRegistry::inspect_existing_at(host_root)
}

/// One externally admitted isolated destination installation.
///
/// Built only by [`admit_isolated_destination`], which reads the DESTINATION
/// installation's own installer-owned registry at the path that installation's
/// own SCM bootstrap declares, selects the single approved generation that
/// bootstrap names, verifies both of that generation's approved images against
/// their approved digests, and retains no-follow leases for that generation's
/// runtime roots. The installation identity and the Watchdog state root are
/// therefore both read out of the destination's own approved manifest: no
/// presented string and no presented path chooses either one.
///
/// This is deliberately not a [`WatchdogRuntimeBinding`] and carries none of
/// that type's authority material. It holds no provisioned supervision
/// authority, no supervision lease, no heartbeat readiness, no Kernel or
/// Watchdog epoch, and makes no running-image assertion. An isolated restore
/// destination is a NEW installation that is not the running process, so
/// requiring this process to be its approved image — or requiring it to hold
/// durable Phase-B supervision authority — would refuse exactly the
/// destination an isolated restore exists to produce. Nothing here can be read
/// as, converted into, or used to satisfy any authority check; the only thing
/// it authorizes is "this root is an installer-approved installation, and it is
/// not the source or the active one".
///
/// Isolation is not asserted here. It is proved at the point of import, by
/// [`validate_isolated_destination`](crate::validate_isolated_destination)
/// comparing this destination's owner-issued identity against the presented
/// source identity and the OWNER-HELD active identity.
pub struct AdmittedIsolatedDestination {
    /// Installation identity the destination's own approved manifest declares.
    destination_installation: String,
    /// Destination's own installer-approved Watchdog state root.
    destination_state_root: PathBuf,
    /// Retained no-follow proof that the destination's Host-state contour
    /// cannot be replaced underneath the registry this binding was read from.
    _host_state_root_lease: Arc<ProtectedRootLease>,
    /// Retained no-follow lease for the destination's approved Host image, held
    /// for this binding's whole lifetime so the image whose digest was proved
    /// at admission is the one still present at import.
    _approved_host_image_lease: Arc<ProtectedPathLease>,
    /// Retained validated no-follow leases for every destination runtime root,
    /// including the Watchdog state root, so that root cannot be swapped between
    /// admission and the import's own read.
    _root_leases: Arc<ValidatedRuntimeRootLeases<WindowsRuntimeRootLease>>,
}

impl AdmittedIsolatedDestination {
    /// Returns the destination installation identity the destination's own
    /// approved manifest declares.
    ///
    /// Owner-issued: it is read out of the destination's own registry-selected
    /// approved generation, so it is never a value a caller chose.
    #[must_use]
    pub fn installation(&self) -> &str {
        &self.destination_installation
    }

    /// Returns the destination installation's own installer-approved Watchdog
    /// state root.
    #[must_use]
    pub fn watchdog_state_root(&self) -> &Path {
        &self.destination_state_root
    }
}

/// Admits one isolated destination installation for recovery import.
///
/// This is the SAME owner, registry, and validator chain the live installation
/// is admitted through — [`inspect_registry_at`],
/// [`select_runtime_manifest`], [`load_approved_service_registations`], the
/// approved-artifact digest checks, and
/// [`WindowsRuntimeRootLeaseProvider`] root retention — applied to the
/// DESTINATION's own registry and the destination's own SCM bootstrap rather
/// than to this process's. The presented `registry_path` and `bootstrap` are
/// claims, never identities: the bootstrap's installation identity, generation,
/// Host state root, and configuration descriptor must all equal the approved
/// manifest that the destination's own registry holds, or this refuses.
///
/// It differs from the live-installation admission in exactly two checks, both
/// of which would refuse a real destination:
///
/// - it does not require durable provisioned supervision authority, because a
///   new isolated installation has none yet and requiring one would demand the
///   destination already hold the authority an isolated restore exists not to
///   reuse; and
/// - it does not compare the running image to the destination's approved
///   Watchdog image, because the destination is by definition not the running
///   process.
///
/// It therefore proves a destination is an installer-approved installation with
/// retained, no-follow, digest-checked roots — and nothing about authority,
/// liveness, or the running process.
///
/// # Errors
///
/// Returns [`SpoolError`] when the destination's declared Host state root
/// cannot be retained or does not canonicalize to itself, the registry is not
/// that root's exact approved child or is absent, no single approved
/// generation matches the destination bootstrap, the installer SCM approvals or
/// the `SystemService` profile do not hold, either approved image is absent or
/// digest-mismatched, or the destination runtime roots cannot be retained and
/// validated.
pub fn admit_isolated_destination(
    registry_path: impl Into<PathBuf>,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<AdmittedIsolatedDestination, SpoolError> {
    let _span = tracing::debug_span!("watchdog.admit_isolated_destination").entered();
    tracing::debug!(
        event = "watchdog.isolated_destination_admission_attempted",
        observation = "attempted",
        "attempting admission of an isolated restore destination installation"
    );
    let registry_path = registry_path.into();
    let declared_host_root = bootstrap.host_state_root().ok_or_else(|| {
        SpoolError::InvalidLease(
            "isolated restore destination admission omitted the installer-approved Host state root"
                .to_owned(),
        )
    })?;
    let host_state_root_lease =
        ProtectedRootLease::open_existing(declared_host_root).map_err(|error| {
            SpoolError::InvalidLease(format!(
                "isolated restore destination Host state root open failed: {error}"
            ))
        })?;
    let canonical_host_root = host_state_root_lease.canonical_path().map_err(|error| {
        SpoolError::InvalidLease(format!(
            "isolated restore destination Host state root resolve failed: {error}"
        ))
    })?;
    if !windows_paths_equal(&canonical_host_root, declared_host_root) {
        return Err(SpoolError::InvalidLease(
            "isolated restore destination Host state root is not the exact retained installation root"
                .to_owned(),
        ));
    }
    let expected_registry_path = canonical_host_root.join(INSTALLATION_REGISTRY_FILE_NAME);
    if !windows_paths_equal(&registry_path, &expected_registry_path) {
        return Err(SpoolError::InvalidLease(
            "isolated restore destination registry path is not the exact approved Host child"
                .to_owned(),
        ));
    }
    let registry = inspect_registry_at(
        ProtectedRootLease::open_existing(&canonical_host_root).map_err(|error| {
            SpoolError::InvalidLease(format!(
                "isolated restore destination Host state root reopen failed: {error}"
            ))
        })?,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
    .ok_or_else(|| {
        SpoolError::InvalidLease(
            "isolated restore destination installation registry is missing".to_owned(),
        )
    })?;
    let selected_manifest = select_runtime_manifest(&registry, bootstrap)?;
    let _ = load_approved_service_registrations(&registry, &selected_manifest, bootstrap)?;
    let roots = selected_manifest.runtime_launch.runtime_state_roots.clone();
    if roots.profile != InstallationProfile::SystemService {
        return Err(SpoolError::InvalidLease(
            "isolated restore destination has no retained file adapter for this installation profile"
                .to_owned(),
        ));
    }
    let approved_host_image_lease = verify_destination_approved_artifacts(&selected_manifest)?;
    let mut provider = WindowsRuntimeRootLeaseProvider::for_roots(&roots)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let root_leases = roots
        .retain_and_validate(&mut provider)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    Ok(AdmittedIsolatedDestination {
        destination_installation: selected_manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str()
            .to_owned(),
        destination_state_root: PathBuf::from(roots.watchdog_state_root.as_str()),
        _host_state_root_lease: Arc::new(host_state_root_lease),
        _approved_host_image_lease: Arc::new(approved_host_image_lease),
        _root_leases: Arc::new(root_leases),
    })
}

/// Proves both approved images an isolated destination's approved generation
/// declares, and returns the retained no-follow Host-image lease.
///
/// Both digests come from the destination's OWN registry-selected approved
/// manifest, and both are read through the same `verify_file_digest*` owners the
/// live-installation admission uses, so an absent, substituted, or
/// digest-mismatched destination image is refused here rather than discovered
/// later. The Watchdog image is verified against its approved digest only —
/// deliberately NOT against this process's running image, because the
/// destination is not the running process.
///
/// # Errors
///
/// Returns [`SpoolError::InvalidLease`] when the approved Host artifact binding
/// cannot be resolved, either approved image cannot be opened under the
/// protected no-follow lease, or either approved digest does not match the
/// bytes at that image.
fn verify_destination_approved_artifacts(
    selected_manifest: &CandidateManifest,
) -> Result<ProtectedPathLease, SpoolError> {
    let approved_host_image = approved_host_artifact_path(selected_manifest)?;
    let approved_host_image_lease =
        ProtectedPathLease::open_existing_absolute(&approved_host_image).map_err(|error| {
            SpoolError::InvalidLease(format!(
                "isolated restore destination approved Host image open failed: {error}"
            ))
        })?;
    verify_file_digest_with_lease(
        &approved_host_image_lease,
        &selected_manifest.runtime_launch.host_artifact_digest,
        "runtime_launch.host_artifact_digest",
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    verify_file_digest(
        Path::new(
            selected_manifest
                .runtime_launch
                .watchdog_executable_path
                .as_str(),
        ),
        &selected_manifest.runtime_launch.watchdog_artifact_digest,
        "runtime_launch.watchdog_artifact_digest",
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    Ok(approved_host_image_lease)
}

#[allow(
    clippy::too_many_lines,
    reason = "runtime binding selection keeps protected registry, manifest, bootstrap, and retained-root checks in one fail-closed read transaction"
)]
fn load_runtime_binding(
    registry_path: &Path,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(String, WatchdogRuntimeBinding), SpoolError> {
    let declared_host_root = bootstrap.host_state_root().ok_or_else(|| {
        SpoolError::InvalidLease(
            "Watchdog SCM bootstrap omitted the installer-approved Host state root".to_owned(),
        )
    })?;
    let host_state_root_lease =
        ProtectedRootLease::open_existing(declared_host_root).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root open failed: {error}"))
        })?;
    let canonical_host_root = host_state_root_lease.canonical_path().map_err(|error| {
        SpoolError::InvalidLease(format!("Host state root resolve failed: {error}"))
    })?;
    if !windows_paths_equal(&canonical_host_root, declared_host_root) {
        return Err(SpoolError::InvalidLease(
            "SCM Host state root is not the exact retained installation root".to_owned(),
        ));
    }
    let expected_registry_path = canonical_host_root.join(INSTALLATION_REGISTRY_FILE_NAME);
    if !windows_paths_equal(registry_path, &expected_registry_path) {
        return Err(SpoolError::InvalidLease(
            "Watchdog registry path is not the exact approved Host child".to_owned(),
        ));
    }
    let registry = inspect_registry_at(
        ProtectedRootLease::open_existing(&canonical_host_root).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root reopen failed: {error}"))
        })?,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
    .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let selected_manifest = select_runtime_manifest(&registry, bootstrap)?;
    let provisioned_supervision_authority = registry
        .provisioned_supervision_authority_for_generation(&selected_manifest.generation)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .cloned()
        .ok_or_else(|| {
            SpoolError::InvalidLease(
                "selected generation has no durable provisioned supervision authority".to_owned(),
            )
        })?;
    provisioned_supervision_authority
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if provisioned_supervision_authority.candidate_generation
        != selected_manifest.generation.as_str()
    {
        return Err(SpoolError::InvalidLease(
            "provisioned supervision authority is foreign to the selected generation".to_owned(),
        ));
    }
    let (approved_host_registration, watchdog_request) =
        load_approved_service_registrations(&registry, &selected_manifest, bootstrap)?;
    let roots = selected_manifest.runtime_launch.runtime_state_roots.clone();
    let watchdog_image = PathBuf::from(
        selected_manifest
            .runtime_launch
            .watchdog_executable_path
            .as_str(),
    );
    let approved_host_image = approved_host_artifact_path(&selected_manifest)?;
    let approved_host_image_lease =
        ProtectedPathLease::open_existing_absolute(&approved_host_image).map_err(|error| {
            SpoolError::InvalidLease(format!("approved Host image open failed: {error}"))
        })?;
    verify_file_digest_with_lease(
        &approved_host_image_lease,
        &selected_manifest.runtime_launch.host_artifact_digest,
        "runtime_launch.host_artifact_digest",
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let current_image =
        std::env::current_exe().map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if !windows_paths_equal(&current_image, &watchdog_image) {
        return Err(SpoolError::InvalidLease(
            "running Watchdog image is not the active approved generation image".to_owned(),
        ));
    }
    verify_file_digest(
        &watchdog_image,
        &selected_manifest.runtime_launch.watchdog_artifact_digest,
        "runtime_launch.watchdog_artifact_digest",
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if roots.profile != InstallationProfile::SystemService {
        return Err(SpoolError::InvalidLease(
            "watchdog has no retained file adapter for this installation profile".to_owned(),
        ));
    }
    let mut provider = WindowsRuntimeRootLeaseProvider::for_roots(&roots)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let leases = roots
        .retain_and_validate(&mut provider)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    Ok((
        selected_manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str()
            .to_owned(),
        WatchdogRuntimeBinding {
            host_state_root: canonical_host_root,
            roots,
            selected_manifest: Arc::new(selected_manifest),
            approved_host_image,
            approved_host_registration,
            approved_watchdog_registration: watchdog_request,
            provisioned_supervision_authority,
            host_state_root_lease: Arc::new(host_state_root_lease),
            _approved_host_image_lease: Arc::new(approved_host_image_lease),
            _root_leases: Arc::new(leases),
        },
    ))
}

pub(super) fn validate_runtime_binding(
    active_installation_id: &str,
    active_roots_digest: &str,
    expected_installation_id: &str,
    expected_roots_digest: &str,
) -> Result<(), SpoolError> {
    if active_installation_id != expected_installation_id {
        return Err(SpoolError::InvalidLease(
            "active generation installation identity changed after binding".to_owned(),
        ));
    }
    if active_roots_digest != expected_roots_digest {
        return Err(SpoolError::InvalidLease(
            "active generation runtime roots changed after binding".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_fixture::RegistryFixture;

    #[test]
    fn pre_phase_b_pending_registry_yields_fenced_readiness_not_admission() {
        let fixture = RegistryFixture::new();
        fixture.write_registry(&fixture.pending_only());
        let bootstrap = fixture.base_bootstrap();
        let registry_path = fixture.host_root().join(INSTALLATION_REGISTRY_FILE_NAME);
        // s33.2 reader lead: the crash cause is exactly the missing durable
        // authority for a pending generation without the Phase-B triple.
        let error =
            match FileWatchdogAdmission::from_registry(registry_path.clone(), bootstrap.clone()) {
                Ok(_) => panic!(
                    "pending-only first install unexpectedly admitted without Phase-B authority"
                ),
                Err(error) => error,
            };
        assert!(
            error
                .to_string()
                .contains("no durable provisioned supervision authority"),
            "unexpected admission error: {error}"
        );
        let fence = FileWatchdogAdmission::pending_phase_b_fence_readiness(
            registry_path.clone(),
            &bootstrap,
        )
        .unwrap_or_else(|error| panic!("pre-Phase-B fence was rejected: {error}"));
        assert_eq!(
            fence.authority_state,
            WatchdogAuthorityState::RunningNoAuthority
        );
        assert!(!fence.coverage_claimed);
        assert_eq!(fence.kernel_epoch, 0);
        assert_eq!(fence.watchdog_epoch, 0);
        // Recovery-required pending must stay fail-closed, never fenced.
        fixture.write_registry(&fixture.recovery_required());
        assert!(
            FileWatchdogAdmission::pending_phase_b_fence_readiness(
                registry_path.clone(),
                &bootstrap
            )
            .is_err()
        );
        // An active generation without a committed Phase-B fence is corruption,
        // not an awaitable bootstrap state, so it must also stay fail-closed.
        fixture.write_registry(&fixture.active_only());
        assert!(
            FileWatchdogAdmission::pending_phase_b_fence_readiness(registry_path, &bootstrap)
                .is_err()
        );
    }
}
