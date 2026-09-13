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
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<WatchdogReadiness, SpoolError> {
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
        let selected_manifest = select_runtime_manifest(&registry, &bootstrap)?;
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
        let _ = load_approved_service_registrations(&registry, &selected_manifest, &bootstrap)?;
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
            bootstrap.clone(),
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
                bootstrap.clone()
            )
            .is_err()
        );
        // An active generation without a committed Phase-B fence is corruption,
        // not an awaitable bootstrap state, so it must also stay fail-closed.
        fixture.write_registry(&fixture.active_only());
        assert!(
            FileWatchdogAdmission::pending_phase_b_fence_readiness(registry_path, bootstrap)
                .is_err()
        );
    }
}
