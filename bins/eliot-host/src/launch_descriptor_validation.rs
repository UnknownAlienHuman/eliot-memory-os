//! Host launch-descriptor validation cell.
//!
//! Architecture anchors:
//! `ELIOT_ARCHITECTURE.md` §A5.5 (scoped verifier contract) and §A13.2
//! (Host boundary and failure domains). Implementation anchors:
//! `ELIOT_IMPLEMENTATION.md` §I1.2
//! (Host ownership), §I1.8 (exact ownership and call paths), §I1.11
//! (startup validation), and §P.2 (Host state boundary).
//!
//! This cell performs only mechanical approved-artifact, descriptor-byte, and
//! retained process-identity validation. It does not own Host start, stop,
//! restart, or kill; lifecycle, reconciliation, composition, or SCM; or
//! canonical semantic authority.

#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use eliot_installation::{CandidateManifest, InstallationProfile, RuntimeLaunchDescriptor};
#[cfg(windows)]
use eliot_kernel_service::{
    EliotdLaunchDescriptor, HostProcessBinding, HostStoreBootstrapRequirement, KERNEL_CONTROL_PIPE,
};
#[cfg(windows)]
use eliot_platform::PlatformHandle;
#[cfg(windows)]
use eliot_platform_windows::{
    UserOwnedRootLease, WindowsAdapterError, observe_named_pipe_peer_process,
};
#[cfg(windows)]
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use super::HostError;
#[cfg(windows)]
use super::launch_artifact::{
    LaunchLease, approved_locator, open_launch_lease, verify_launch_digest,
};

// F-LOG-HOST-3 (#978) launch-descriptor observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never digests,
// paths, nonces, descriptor bytes, or arbitrary error text — so bounding
// limits size, not sensitivity (I15.4). Sink outcome never alters
// result/order/count/handle/cleanup/timeout. There is no mutable global dedup
// cache and no terminal emission here: one terminal per failed operation is
// owned by the single outermost contour (`HostJobBranches::start_approved`
// guard owns `host-launch-failed`), while these descriptor phases correlate
// by stage order only. Retained identity on substitution failure is preserved
// (case 978/3); descriptor rejections stay typed (case 978/2).
#[cfg(windows)]
fn launch_descriptor_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn launch_descriptor_observe(detail: &str) {
    launch_descriptor_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::LaunchConfig,
        detail,
    );
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct KernelLaunchBinding {
    pub(super) pipe_identity: PlatformHandle,
    pub(super) host_process: HostProcessBinding,
}

#[cfg(windows)]
impl KernelLaunchBinding {
    pub(super) fn observe_current() -> Result<Self, WindowsAdapterError> {
        let observed = observe_named_pipe_peer_process(std::process::id())?;
        let host_process = HostProcessBinding {
            process_id: observed.process_id(),
            start_time_100ns: observed.start_time_100ns(),
            image_path: observed.image_path().to_owned(),
        };
        host_process
            .validate()
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        let pipe_identity = PlatformHandle::new(KERNEL_CONTROL_PIPE)
            .map_err(|_| WindowsAdapterError::InvalidInput)?;
        Ok(Self {
            pipe_identity,
            host_process,
        })
    }

    pub(super) fn validate_current(&self) -> Result<(), HostError> {
        let observed = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if !self.matches_observed(
            observed.process_id(),
            observed.start_time_100ns(),
            observed.image_path(),
        ) {
            return Err(HostError::ProcessContour(
                "retained Host process identity changed before Kernel control".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn matches_observed(
        &self,
        process_id: u32,
        start_time_100ns: u64,
        image_path: &str,
    ) -> bool {
        self.host_process.process_id == process_id
            && self.host_process.start_time_100ns == start_time_100ns
            && self.host_process.image_path == image_path
    }
}

#[cfg(windows)]
pub(super) fn verify_host_artifact_at(
    manifest: &CandidateManifest,
    current_executable: &Path,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — host artifact requested.
    launch_descriptor_observe("host.launch-descriptor host artifact requested");
    let (approved_path, approved_digest) = manifest.host_artifact_binding().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor host artifact typed rejection");
        HostError::ProcessContour(error.to_string())
    })?;
    let launch = &manifest.runtime_launch;
    let portable_root = if launch.profile == InstallationProfile::PortableDev {
        Some(
            UserOwnedRootLease::open_existing(Path::new(
                launch
                    .portable_root
                    .as_ref()
                    .ok_or_else(|| {
                        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                        launch_descriptor_observe(
                            "host.launch-descriptor host artifact typed rejection",
                        );
                        HostError::ProcessContour("portable root is missing".to_owned())
                    })?
                    .as_str(),
            ))
            .map_err(|error| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                launch_descriptor_observe("host.launch-descriptor host artifact typed rejection");
                HostError::ProcessContour(error.to_string())
            })?,
        )
    } else {
        None
    };
    let current_executable = approved_locator(current_executable, approved_path, launch.profile)
        .inspect_err(|_| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            launch_descriptor_observe("host.launch-descriptor substitution preserved");
        })?;
    let lease = open_launch_lease(launch.profile, portable_root.as_ref(), &current_executable)
        .inspect_err(|_| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_descriptor_observe("host.launch-descriptor host artifact typed rejection");
        })?;
    let result = verify_launch_digest(&lease, approved_digest, "runtime.host_artifact");
    match &result {
        Ok(()) => {
            // WORK_UNIT_CASE: 978/1 — host artifact admitted.
            launch_descriptor_observe("host.launch-descriptor host artifact admitted");
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_descriptor_observe("host.launch-descriptor host artifact typed rejection");
        }
    }
    result
}

#[cfg(windows)]
pub(super) fn verify_current_host_artifact(manifest: &CandidateManifest) -> Result<(), HostError> {
    // The OS-reported current image is process identity evidence, never a
    // fallback for the approved launch descriptor.
    // WORK_UNIT_CASE: 978/1 — current host requested.
    // WORK_UNIT_CASE: 978/4 — process identity distinct from launch request; admitted is never readiness.
    launch_descriptor_observe("host.launch-descriptor current host requested");
    let current_executable = std::env::current_exe().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor current host typed rejection");
        HostError::ProcessContour(error.to_string())
    })?;
    let result = verify_host_artifact_at(manifest, &current_executable);
    if result.is_ok() {
        // WORK_UNIT_CASE: 978/1 — current host admitted.
        launch_descriptor_observe("host.launch-descriptor current host admitted");
    }
    result
}

#[cfg(windows)]
pub(super) fn validate_store_bootstrap_descriptor(
    lease: &LaunchLease,
    approved_digest: &PlatformHandle,
    expected_artifact: &PlatformHandle,
    expected_config: &PlatformHandle,
    expected_nonce: &PlatformHandle,
) -> Result<HostStoreBootstrapRequirement, HostError> {
    // WORK_UNIT_CASE: 978/1 — store bootstrap requested.
    launch_descriptor_observe("host.launch-descriptor store bootstrap requested");
    lease.verify().map_err(|error| {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_descriptor_observe("host.launch-descriptor substitution preserved");
        HostError::ProcessContour(error)
    })?;
    let bytes = match lease {
        LaunchLease::Protected(lease) => lease.read_bounded(1024 * 1024),
        LaunchLease::Portable(lease) => lease.read_bounded(1024 * 1024),
    }
    .map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor store bootstrap typed rejection");
        HostError::ProcessContour(format!("read Store bootstrap descriptor: {error}"))
    })?;
    let actual = Sha256::digest(&bytes);
    if format!("{actual:x}") != approved_digest.as_str() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor store bootstrap typed rejection");
        return Err(HostError::ProcessContour(
            "Store bootstrap descriptor digest changed before launch".to_owned(),
        ));
    }
    let requirement: HostStoreBootstrapRequirement =
        serde_json::from_slice(&bytes).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_descriptor_observe("host.launch-descriptor store bootstrap typed rejection");
            HostError::ProcessContour(format!("parse Store bootstrap descriptor: {error}"))
        })?;
    requirement.validate().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor store bootstrap typed rejection");
        HostError::ProcessContour(format!("validate Store bootstrap descriptor: {error}"))
    })?;
    if requirement.approved_artifact_hash != *expected_artifact
        || requirement.approved_config_hash != *expected_config
        || requirement.launch_nonce != *expected_nonce
    {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_descriptor_observe("host.launch-descriptor substitution preserved");
        return Err(HostError::ProcessContour(
            "Store bootstrap descriptor is not bound to the approved generation".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 978/1 — store bootstrap admitted.
    launch_descriptor_observe("host.launch-descriptor store bootstrap admitted");
    Ok(requirement)
}

#[cfg(windows)]
pub(super) fn validate_eliotd_launch_descriptor(
    lease: &LaunchLease,
    approved_digest: &PlatformHandle,
    launch: &RuntimeLaunchDescriptor,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — eliotd requested.
    launch_descriptor_observe("host.launch-descriptor eliotd requested");
    lease.verify().map_err(|error| {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_descriptor_observe("host.launch-descriptor substitution preserved");
        HostError::ProcessContour(error)
    })?;
    let bytes = lease.read_bounded(1024 * 1024).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor eliotd typed rejection");
        HostError::ProcessContour(format!("read eliotd launch descriptor: {error}"))
    })?;
    let result = validate_eliotd_launch_descriptor_bytes(&bytes, approved_digest, launch);
    if result.is_ok() {
        // WORK_UNIT_CASE: 978/1 — eliotd admitted.
        launch_descriptor_observe("host.launch-descriptor eliotd admitted");
    }
    result
}

#[cfg(windows)]
pub(super) fn validate_eliotd_launch_descriptor_bytes(
    bytes: &[u8],
    approved_digest: &PlatformHandle,
    launch: &RuntimeLaunchDescriptor,
) -> Result<(), HostError> {
    let actual = Sha256::digest(bytes);
    if format!("{actual:x}") != approved_digest.as_str() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor eliotd typed rejection");
        return Err(HostError::ProcessContour(
            "eliotd launch descriptor digest changed before launch".to_owned(),
        ));
    }
    let descriptor: EliotdLaunchDescriptor = serde_json::from_slice(bytes).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor eliotd typed rejection");
        HostError::ProcessContour(format!("parse eliotd launch descriptor: {error}"))
    })?;
    descriptor.validate().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe("host.launch-descriptor eliotd typed rejection");
        HostError::ProcessContour(format!("validate eliotd launch descriptor: {error}"))
    })?;
    if descriptor.executable != launch.eliotd_executable_path
        || descriptor.executable_sha256 != launch.eliotd_artifact_digest.as_str()
        || descriptor.working_directory != launch.kernel_work_root
        || descriptor.config_descriptor != launch.eliotd_config_path
        || descriptor.config_descriptor_sha256 != launch.eliotd_config_digest.as_str()
        || descriptor.protected_snapshot_digest != launch.protected_snapshot_digest.as_str()
        || descriptor.launch_nonce != launch.eliotd_launch_nonce
        || descriptor.authority_epoch != launch.authority_state_fence.authority_epoch
        || descriptor.generation != launch.authority_generation
        || descriptor.generation != launch.authority_state_fence.resource_generation
    {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_descriptor_observe("host.launch-descriptor substitution preserved");
        return Err(HostError::ProcessContour(
            "eliotd launch descriptor is not bound to the approved generation".to_owned(),
        ));
    }
    Ok(())
}
