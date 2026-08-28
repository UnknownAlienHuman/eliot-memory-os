//! Read-only installation-backed Watchdog admission and runtime binding.
//!
//! Architecture anchors: `A8.1` (Watchdog purpose), `ARCH-WDG-01` (independent supervision).
//! Implementation anchors: `I8.1` (process and authority), `I8.2` (independent observation routes).
//!
//! This module owns only the installer-bound admission read, validation, and retained no-follow
//! runtime binding. It performs no SCM mutation, lifecycle decision, canonical/ORS/Host-journal
//! write, authority minting, or policy operation.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_installation::{
    CandidateManifest, InstallationProfile, RedbInstallationRegistry, RuntimeStateRoots,
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
    ApprovedHostRegistration, INSTALLATION_REGISTRY_FILE_NAME, SpoolError,
    VerifiedWatchdogAdmission, WatchdogAdmissionSource, supervision_lease_load,
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
}

impl FileWatchdogAdmission {
    /// # Errors
    ///
    /// Returns an error when the registry is missing, invalid, has no exact
    /// bootstrap-selected active/pending contour, or its runtime roots cannot
    /// be retained and validated.
    pub fn from_registry(
        registry_path: impl Into<PathBuf>,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, SpoolError> {
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
    let registry = RedbInstallationRegistry::inspect_existing_at(
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
