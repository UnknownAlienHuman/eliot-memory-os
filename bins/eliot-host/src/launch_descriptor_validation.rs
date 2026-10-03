//! Host launch-descriptor validation cell.
//!
//! Architecture anchors:
//! `A5.5` (`docs/architecture/A05-05-verifier-and-evaluation-contract.md`,
//! scoped verifier contract) and `A13.2`
//! (`docs/architecture/A13-02-kernel-and-failure-domains.md`,
//! Host boundary and failure domains). Implementation anchors:
//! `I1.2` (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`,
//! Host ownership), `I1.8` (`docs/architecture/I01-08-exact-ownership-and-call-paths.md`,
//! exact ownership and call paths), `I1.11`
//! (`docs/architecture/I01-11-startup-algorithm.md`, startup validation), and the
//! R0 Platform layer (`docs/architecture/I-PREFACE-04-runtime-layer-model.md`,
//! Host state boundary).
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
#[cfg(windows)]
use crate::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) launch-descriptor observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Structured correlation (audit 5910159678, defects 3 and 5): every
// observation carries a phase token plus the bounded identities its call site
// already holds, rendered by `crate::host_job_launch::LaunchPhaseCorrelation`
// through `host_diagnostics::bound_field`. A static label can classify a
// phase; only a bound approved artifact/source digest handle, installation
// identity, and generation say which approved descriptor was validated. Each
// slot is an already-held non-secret handle or counter: the approved image
// path, descriptor paths, argv, environment values, credentials, nonces,
// descriptor bytes, and arbitrary `Debug`/`Display` text never enter a slot,
// and no probe, lease open, byte read, re-validation, or duplicate evaluation
// of an expression runs to obtain one. A call site holding none of them binds
// `LaunchPhaseCorrelation::NONE`, so a missing identity stays explicitly
// missing instead of being invented. Bounding limits size, not sensitivity
// (I15.4).
//
// Substitution and refusal paths record the retained approved identity that is
// already in hand, never the rejected or substituted path text (case 978/3);
// descriptor rejections stay typed and never become admissions (case 978/2).
//
// Slots this cell has no evidence for stay explicitly absent (rendered by the
// shared correlation as `missing`) on purpose. The approved `StateFence` is a
// numeric epoch/generation pair with no owner-produced string handle, so `fence`
// is never composed here. The retained
// Host process identity lives in `KernelLaunchBinding`, which emits no phase
// record of its own, so `process_start` is absent from every record in this file
// and a bare PID is never promoted into one (case 978/5). No typed cause enum
// exists in this cell, so `reason` stays missing and the typed `HostError`
// refusal text is never bound (case 978/12). `verify_user_broker_artifact`
// emits no phase record of its own, so no correlation is built there either.
//
// Readiness rule: an admitted descriptor is a launch/admission observation,
// never readiness — process identity is distinct from the launch request and
// admitted is never ready (case 978/4).
//
// Sink outcome never alters result/order/count/handle/cleanup/timeout. There
// is no mutable global dedup cache and no terminal emission here: one terminal
// per failed operation is owned by the single outermost launch contour
// (`HostJobBranches::start_approved` in `host_job_launch.rs`, whose outer Host
// start terminal `lib.rs` already owns), while these descriptor phases
// correlate by order plus the bound identities.
#[cfg(windows)]
fn launch_descriptor_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn launch_descriptor_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    launch_descriptor_note_event_log_unavailable();
    let detail = correlation.render(phase);
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::LaunchConfig,
        &detail,
    );
}

/// Bounded correlation of the approved identities an admitted
/// [`CandidateManifest`] already holds: the approved Host artifact digest, the
/// installation identity of its launch lineage, and the authority generation.
///
/// Plain field reads: no probe, lease open, descriptor byte read, or
/// re-validation runs for a log field, and the approved image path, descriptor
/// paths, argv, nonces, and descriptor bytes are never bound.
#[cfg(windows)]
fn launch_descriptor_manifest_correlation(
    manifest: &CandidateManifest,
) -> LaunchPhaseCorrelation<'_> {
    LaunchPhaseCorrelation::NONE
        .with_artifact(manifest.host_artifact_digest.as_str())
        .with_installation(
            manifest
                .runtime_launch
                .installation_epoch
                .installation
                .as_str(),
        )
        .with_generation(manifest.runtime_launch.authority_generation.value())
}

/// Bounded correlation of the approved identities one
/// [`RuntimeLaunchDescriptor`] and the approved descriptor digest handle
/// already hold: the descriptor digest under validation, the installation
/// identity, and the authority generation.
///
/// Never the descriptor path, the descriptor bytes, a launch nonce, or any
/// rejected value the comparison is about to fail on.
#[cfg(windows)]
fn launch_descriptor_install_correlation<'a>(
    launch: &'a RuntimeLaunchDescriptor,
    approved_digest: &'a PlatformHandle,
) -> LaunchPhaseCorrelation<'a> {
    LaunchPhaseCorrelation::NONE
        .with_artifact(approved_digest.as_str())
        .with_installation(launch.installation_epoch.installation.as_str())
        .with_generation(launch.authority_generation.value())
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
    launch_descriptor_observe(
        "host.launch-descriptor host artifact requested",
        &launch_descriptor_manifest_correlation(manifest),
    );
    let (approved_path, approved_digest) = manifest.host_artifact_binding().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted. The
        // approved identity still in hand is recorded; the rejected descriptor
        // text is not.
        launch_descriptor_observe(
            "host.launch-descriptor host artifact typed rejection",
            &launch_descriptor_manifest_correlation(manifest),
        );
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
                            &launch_descriptor_install_correlation(launch, approved_digest),
                        );
                        HostError::ProcessContour("portable root is missing".to_owned())
                    })?
                    .as_str(),
            ))
            .map_err(|error| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                launch_descriptor_observe(
                    "host.launch-descriptor host artifact typed rejection",
                    &launch_descriptor_install_correlation(launch, approved_digest),
                );
                HostError::ProcessContour(error.to_string())
            })?,
        )
    } else {
        None
    };
    let current_executable = approved_locator(current_executable, approved_path, launch.profile)
        .inspect_err(|_| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            launch_descriptor_observe(
                "host.launch-descriptor substitution preserved",
                &launch_descriptor_install_correlation(launch, approved_digest),
            );
        })?;
    let lease = open_launch_lease(launch.profile, portable_root.as_ref(), &current_executable)
        .inspect_err(|_| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_descriptor_observe(
                "host.launch-descriptor host artifact typed rejection",
                &launch_descriptor_install_correlation(launch, approved_digest),
            );
        })?;
    let result = verify_launch_digest(&lease, approved_digest, "runtime.host_artifact");
    match &result {
        Ok(()) => {
            // WORK_UNIT_CASE: 978/1 — host artifact admitted. Admission is a
            // launch observation, never readiness.
            launch_descriptor_observe(
                "host.launch-descriptor host artifact admitted",
                &launch_descriptor_install_correlation(launch, approved_digest),
            );
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_descriptor_observe(
                "host.launch-descriptor host artifact typed rejection",
                &launch_descriptor_install_correlation(launch, approved_digest),
            );
        }
    }
    result
}

#[cfg(windows)]
pub(super) fn verify_user_broker_artifact(
    manifest: &CandidateManifest,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<(), HostError> {
    let launch = &manifest.runtime_launch;
    let approved_path = approved_locator(
        Path::new(launch.user_broker_executable_path.as_str()),
        &launch.user_broker_executable_path,
        launch.profile,
    )?;
    let lease = open_launch_lease(launch.profile, portable_root, &approved_path)?;
    lease.verify().map_err(|error| {
        HostError::RecoveryRequired(format!("User Broker artifact identity changed: {error}"))
    })?;
    verify_launch_digest(
        &lease,
        &launch.user_broker_artifact_digest,
        "runtime.user_broker_artifact",
    )
    .map_err(|error| {
        HostError::RecoveryRequired(format!("User Broker artifact digest is not exact: {error}"))
    })
}

#[cfg(windows)]
pub(super) fn verify_current_host_artifact(manifest: &CandidateManifest) -> Result<(), HostError> {
    // The OS-reported current image is process identity evidence, never a
    // fallback for the approved launch descriptor.
    // WORK_UNIT_CASE: 978/1 — current host requested.
    // WORK_UNIT_CASE: 978/4 — process identity distinct from launch request; admitted is never readiness.
    launch_descriptor_observe(
        "host.launch-descriptor current host requested",
        &launch_descriptor_manifest_correlation(manifest),
    );
    let current_executable = std::env::current_exe().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor current host typed rejection",
            &launch_descriptor_manifest_correlation(manifest),
        );
        HostError::ProcessContour(error.to_string())
    })?;
    let result = verify_host_artifact_at(manifest, &current_executable);
    if result.is_ok() {
        // WORK_UNIT_CASE: 978/1 — current host admitted.
        launch_descriptor_observe(
            "host.launch-descriptor current host admitted",
            &launch_descriptor_manifest_correlation(manifest),
        );
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
    // The approved Store bootstrap descriptor digest handle is already in hand
    // and is the only identity this operation validates; the approved artifact
    // and config hashes it must bind and the launch nonce are never bound.
    let descriptor_correlation =
        LaunchPhaseCorrelation::NONE.with_artifact(approved_digest.as_str());
    // WORK_UNIT_CASE: 978/1 — store bootstrap requested.
    launch_descriptor_observe(
        "host.launch-descriptor store bootstrap requested",
        &descriptor_correlation,
    );
    lease.verify().map_err(|error| {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_descriptor_observe(
            "host.launch-descriptor substitution preserved",
            &descriptor_correlation,
        );
        HostError::ProcessContour(error)
    })?;
    let bytes = match lease {
        LaunchLease::Protected(lease) => lease.read_bounded(1024 * 1024),
        LaunchLease::Portable(lease) => lease.read_bounded(1024 * 1024),
    }
    .map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor store bootstrap typed rejection",
            &descriptor_correlation,
        );
        HostError::ProcessContour(format!("read Store bootstrap descriptor: {error}"))
    })?;
    let actual = Sha256::digest(&bytes);
    if format!("{actual:x}") != approved_digest.as_str() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor store bootstrap typed rejection",
            &descriptor_correlation,
        );
        return Err(HostError::ProcessContour(
            "Store bootstrap descriptor digest changed before launch".to_owned(),
        ));
    }
    let requirement: HostStoreBootstrapRequirement =
        serde_json::from_slice(&bytes).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_descriptor_observe(
                "host.launch-descriptor store bootstrap typed rejection",
                &descriptor_correlation,
            );
            HostError::ProcessContour(format!("parse Store bootstrap descriptor: {error}"))
        })?;
    requirement.validate().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor store bootstrap typed rejection",
            &descriptor_correlation,
        );
        HostError::ProcessContour(format!("validate Store bootstrap descriptor: {error}"))
    })?;
    if requirement.approved_artifact_hash != *expected_artifact
        || requirement.approved_config_hash != *expected_config
        || requirement.launch_nonce != *expected_nonce
    {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_descriptor_observe(
            "host.launch-descriptor substitution preserved",
            &descriptor_correlation,
        );
        return Err(HostError::ProcessContour(
            "Store bootstrap descriptor is not bound to the approved generation".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 978/1 — store bootstrap admitted.
    launch_descriptor_observe(
        "host.launch-descriptor store bootstrap admitted",
        &descriptor_correlation,
    );
    Ok(requirement)
}

#[cfg(windows)]
pub(super) fn validate_eliotd_launch_descriptor(
    lease: &LaunchLease,
    approved_digest: &PlatformHandle,
    launch: &RuntimeLaunchDescriptor,
) -> Result<(), HostError> {
    let descriptor_correlation = launch_descriptor_install_correlation(launch, approved_digest);
    // WORK_UNIT_CASE: 978/1 — eliotd requested.
    launch_descriptor_observe(
        "host.launch-descriptor eliotd requested",
        &descriptor_correlation,
    );
    lease.verify().map_err(|error| {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_descriptor_observe(
            "host.launch-descriptor substitution preserved",
            &descriptor_correlation,
        );
        HostError::ProcessContour(error)
    })?;
    let bytes = lease.read_bounded(1024 * 1024).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor eliotd typed rejection",
            &descriptor_correlation,
        );
        HostError::ProcessContour(format!("read eliotd launch descriptor: {error}"))
    })?;
    let result = validate_eliotd_launch_descriptor_bytes(&bytes, approved_digest, launch);
    if result.is_ok() {
        // WORK_UNIT_CASE: 978/1 — eliotd admitted. Admission is a launch
        // observation, never readiness.
        launch_descriptor_observe(
            "host.launch-descriptor eliotd admitted",
            &descriptor_correlation,
        );
    }
    result
}

#[cfg(windows)]
pub(super) fn validate_eliotd_launch_descriptor_bytes(
    bytes: &[u8],
    approved_digest: &PlatformHandle,
    launch: &RuntimeLaunchDescriptor,
) -> Result<(), HostError> {
    let descriptor_correlation = launch_descriptor_install_correlation(launch, approved_digest);
    let actual = Sha256::digest(bytes);
    if format!("{actual:x}") != approved_digest.as_str() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor eliotd typed rejection",
            &descriptor_correlation,
        );
        return Err(HostError::ProcessContour(
            "eliotd launch descriptor digest changed before launch".to_owned(),
        ));
    }
    let descriptor: EliotdLaunchDescriptor = serde_json::from_slice(bytes).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor eliotd typed rejection",
            &descriptor_correlation,
        );
        HostError::ProcessContour(format!("parse eliotd launch descriptor: {error}"))
    })?;
    descriptor.validate().map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_descriptor_observe(
            "host.launch-descriptor eliotd typed rejection",
            &descriptor_correlation,
        );
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
        launch_descriptor_observe(
            "host.launch-descriptor substitution preserved",
            &descriptor_correlation,
        );
        return Err(HostError::ProcessContour(
            "eliotd launch descriptor is not bound to the approved generation".to_owned(),
        ));
    }
    Ok(())
}

// F-LOG-HOST-3 (#978) inline proof for this cell's private observation
// contract. Every case drives a real instrumented call site of this cell
// through its existing seam — the descriptor-bytes seam
// (`validate_eliotd_launch_descriptor_bytes`) and the retained-lease Store
// bootstrap seam (`validate_store_bootstrap_descriptor`, reached through the
// real `open_launch_lease` and a real `UserOwnedRootLease` over a temporary
// descriptor) — and widens no visibility. No case here calls
// `launch_descriptor_observe` and none renders a detail of its own, so no case
// can pass on a record it fabricated. Outcomes that need a fully validated
// approved `CandidateManifest` stay with the integration fixture owner; what is
// proven here is the correlation these seams build from identities their callers
// already hold: the retained approved identity on an admission, a substitution
// or a refusal, no readiness and no process-start claim, no
// argv/nonce/path/pipe canary, and determinism and separation per held
// identity.
//
// Every record a case reads is read back out of a scoped `tracing` subscriber
// over the real emission, using the same in-memory sink harness as this issue's
// other inline harnesses (`host_job_launch::phase_correlation_tests`). There is
// still exactly one logging facade: these cases observe the records the
// production call sites emit. No case here renders a record or a detail of its
// own; what the assertions do pin is the shared correlation's own frozen
// `<slot>=missing` spelling for the slots a call site has no evidence for.
#[cfg(all(test, windows))]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::super::launch_artifact::{LaunchLease, open_launch_lease};
    use super::{
        HostError, validate_eliotd_launch_descriptor, validate_eliotd_launch_descriptor_bytes,
        validate_store_bootstrap_descriptor,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_installation::{
        INSTALLATION_ROOT_BINDING_VERSION, InstallationEpoch, InstallationProfile,
        InstallationRoots, RuntimeLaunchDescriptor, RuntimeStateRoots, SupervisionAuthorityBinding,
    };
    use eliot_kernel_service::{EliotdLaunchDescriptor, HostStoreBootstrapRequirement};
    use eliot_platform::PlatformHandle;
    use eliot_platform_windows::UserOwnedRootLease;
    use sha2::{Digest as _, Sha256};

    const APPROVED_DIGEST: &str =
        "9780000000000000000000000000000000000000000000000000000000000001";
    const OTHER_APPROVED_DIGEST: &str =
        "9780000000000000000000000000000000000000000000000000000000000002";
    const REJECTED_PATH_CANARY: &str = r"C:\978-canary\store-bootstrap-descriptor.json";
    const NONCE_CANARY: &str = "978-canary-launch-nonce";
    const SUBSTITUTION_PHASE: &str = "host.launch-descriptor substitution preserved";
    const ADMITTED_PHASE: &str = "host.launch-descriptor store bootstrap admitted";

    // The eliotd descriptor-bytes seam, executed below. Every value here is a
    // synthetic fixture identity: an approved contour, the substituted image it
    // must refuse, and the exact retained rejection text of the real call sites.
    const ELIOTD_TYPED_REJECTION_PHASE: &str = "host.launch-descriptor eliotd typed rejection";
    const APPROVED_ELIOTD_WIRE_ID: &str = "eliot.kernel.eliotd-launch";
    const REJECTED_ELIOTD_WIRE_ID: &str = "978-canary-unsupported-wire";
    const APPROVED_ROOT: &str = r"C:\Eliot\approved";
    const APPROVED_ELIOTD_EXECUTABLE: &str = r"C:\Eliot\approved\eliotd.exe";
    const SUBSTITUTED_ELIOTD_EXECUTABLE: &str = r"C:\978-canary-substituted\eliotd.exe";
    const APPROVED_ELIOTD_CONFIG: &str = r"C:\Eliot\approved\eliotd-governor.json";
    const APPROVED_WORK_ROOT: &str = r"C:\Eliot\approved\kernel\work";
    const INSTALLATION_IDENTITY: &str = "978-launch-installation";
    const APPROVED_LAUNCH_NONCE: &str = "eliotd:978c0123456789abcdef0123456789ab";
    const DIGEST_CHANGE_REJECTION: &str = "eliotd launch descriptor digest changed before launch";
    const SUBSTITUTION_REJECTION: &str =
        "eliotd launch descriptor is not bound to the approved generation";
    const PARSE_REJECTION_PREFIX: &str = "parse eliotd launch descriptor: ";
    const VALIDATE_REJECTION_PREFIX: &str = "validate eliotd launch descriptor: ";
    const REJECTED_BYTES_CANARY: &str = "978-canary-bytes-that-are-not-json";

    // The Store bootstrap seam, executed below over a real retained lease. Every
    // value is the approved identity the caller already holds when the seam
    // runs: the pipe, the nonce and the connection are descriptor-adjacent
    // handles that must never reach a record.
    const BOOTSTRAP_PIPE: &str = r"\\.\pipe\eliot\store-bootstrap-978";
    const BOOTSTRAP_NONCE: &str = "978-store-bootstrap-nonce";
    const BOOTSTRAP_CONNECTION: &str = "978-store-bootstrap-connection";

    // The Store bootstrap seam's own refusal vocabulary, executed below over the
    // same real retained lease: the phase the call site emits when it refuses
    // and the exact retained rejection text it builds.
    const BOOTSTRAP_TYPED_REJECTION_PHASE: &str =
        "host.launch-descriptor store bootstrap typed rejection";
    const BOOTSTRAP_DIGEST_CHANGE_REJECTION: &str =
        "Store bootstrap descriptor digest changed before launch";
    const BOOTSTRAP_BINDING_REJECTION: &str =
        "Store bootstrap descriptor is not bound to the approved generation";
    const BOOTSTRAP_PARSE_REJECTION_PREFIX: &str = "parse Store bootstrap descriptor: ";
    const BOOTSTRAP_VALIDATE_REJECTION_PREFIX: &str = "validate Store bootstrap descriptor: ";
    const BOOTSTRAP_READ_REJECTION_PREFIX: &str = "read Store bootstrap descriptor: ";
    const ELIOTD_READ_REJECTION_PREFIX: &str = "read eliotd launch descriptor: ";
    const REJECTED_BOOTSTRAP_BYTES_CANARY: &str = "978-canary-store-bootstrap-bytes";

    /// The exact bound both retained-lease call sites pass to `read_bounded`, so
    /// the over-limit fixture below is one byte past the limit the seam itself
    /// enforces and the lease refuses the read rather than any later comparison.
    const BOOTSTRAP_BOUNDED_READ_LIMIT: usize = 1024 * 1024;

    fn approved_digest_handle(digest: &str) -> PlatformHandle {
        PlatformHandle::new(digest)
            .unwrap_or_else(|_| panic!("approved descriptor digest handle must build"))
    }

    /// One fixture handle. A malformed fixture fails loudly here instead of
    /// producing a silently different contour.
    fn fixture_handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value)
            .unwrap_or_else(|_| panic!("fixture handle must be a valid platform handle: {value}"))
    }

    /// One lowercase SHA-256 spelling this fixture binds as an approved digest.
    fn fixture_digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    /// The approved descriptor digest handle over exact bytes, which is what
    /// the real call sites already hold before the comparison runs.
    fn digest_handle_of(bytes: &[u8]) -> PlatformHandle {
        fixture_handle(&format!("{:x}", Sha256::digest(bytes)))
    }

    /// One canonical lineage-aware authority epoch, which is what the fence
    /// constructor needs. No epoch or generation is invented by logging: the
    /// fixture only supplies the identity the descriptor binds.
    fn fixture_epoch() -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .unwrap_or_else(|_| panic!("fixture epoch lineage must be canonical"));
        let sequence = std::num::NonZeroU64::new(1)
            .unwrap_or_else(|| panic!("fixture epoch sequence must be non-zero"));
        EpochId::new(lineage, sequence).unwrap_or_else(|_| panic!("fixture epoch must build"))
    }

    /// The mutable runtime root topology of this fixture. Plain field values:
    /// the seam under test reads only `kernel_work_root` and never validates
    /// the topology, so no real root directory is opened or leased here.
    fn fixture_runtime_roots() -> RuntimeStateRoots {
        RuntimeStateRoots {
            profile: InstallationProfile::PortableDev,
            profile_anchor_root: fixture_handle(APPROVED_ROOT),
            installation_root: fixture_handle(APPROVED_ROOT),
            host_state_root: fixture_handle(r"C:\Eliot\approved\host"),
            kernel_ors_root: fixture_handle(r"C:\Eliot\approved\kernel\state"),
            kernel_work_root: fixture_handle(APPROVED_WORK_ROOT),
            store_data_root: fixture_handle(r"C:\Eliot\approved\store\data"),
            store_work_root: fixture_handle(r"C:\Eliot\approved\store\work"),
            store_temp_root: fixture_handle(r"C:\Eliot\approved\store\tmp"),
            watchdog_state_root: fixture_handle(r"C:\Eliot\approved\watchdog"),
            roots_digest: fixture_handle(&fixture_digest('d')),
        }
    }

    fn fixture_profile_roots(roots: &RuntimeStateRoots) -> InstallationRoots {
        InstallationRoots {
            binding_version: INSTALLATION_ROOT_BINDING_VERSION,
            immutable_binaries: r"C:\Eliot\approved\target".to_owned(),
            durable_data: r"C:\Eliot\approved\.eliot-dev\state".to_owned(),
            user_config: r"C:\Eliot\approved\.eliot-dev\config".to_owned(),
            user_cache: r"C:\Eliot\approved\.eliot-dev\cache".to_owned(),
            runtime_state_roots: roots.clone(),
        }
    }

    /// The approved launch contour the descriptor must stay bound to. This is a
    /// launch descriptor, not a `CandidateManifest`: no approved candidate is
    /// fabricated here, and the only identities the seam binds from it are the
    /// ones it reads itself - the installation lineage and the generation.
    fn fixture_launch(eliotd_executable: &str) -> RuntimeLaunchDescriptor {
        let roots = fixture_runtime_roots();
        RuntimeLaunchDescriptor {
            profile: InstallationProfile::PortableDev,
            profile_component: fixture_handle("eliot"),
            profile_version: fixture_handle("978-fixture-version"),
            profile_installation_key: None,
            profile_governed_roots: fixture_profile_roots(&roots),
            portable_root: Some(fixture_handle(APPROVED_ROOT)),
            installation_epoch: InstallationEpoch {
                installation: fixture_handle(INSTALLATION_IDENTITY),
                lineage_id: fixture_handle("978-fixture-lineage"),
                sequence: 1,
            },
            generation: fixture_handle("978-fixture-generation"),
            authority_generation: ResourceGeneration::genesis(),
            authority_state_fence: StateFence::new(fixture_epoch(), ResourceGeneration::genesis()),
            authority_descriptor_path: fixture_handle(r"C:\Eliot\approved\authority.json"),
            authority_descriptor_digest: fixture_handle(&fixture_digest('9')),
            supervision_authority: SupervisionAuthorityBinding::Pending {
                supervision_lease_scope_id: fixture_handle("978-fixture-supervision-scope"),
            },
            runtime_state_roots: roots.clone(),
            kernel_work_root: fixture_handle(APPROVED_WORK_ROOT),
            kernel_artifact_digest: fixture_handle(&fixture_digest('5')),
            eliotd_executable_path: fixture_handle(eliotd_executable),
            eliotd_artifact_digest: fixture_handle(&fixture_digest('a')),
            eliotd_config_path: fixture_handle(APPROVED_ELIOTD_CONFIG),
            eliotd_config_digest: fixture_handle(&fixture_digest('b')),
            protected_snapshot_digest: fixture_handle(&fixture_digest('c')),
            eliotd_descriptor_path: fixture_handle(r"C:\Eliot\approved\eliotd.json"),
            eliotd_descriptor_digest: fixture_handle(&fixture_digest('f')),
            eliotd_launch_nonce: fixture_handle(APPROVED_LAUNCH_NONCE),
            store_config_path: fixture_handle(r"C:\Eliot\approved\generation.json"),
            store_credential_target: fixture_handle("eliot/store/v1/978fixture"),
            store_bridge_executable_path: fixture_handle(r"C:\Eliot\approved\store-bridge.exe"),
            store_bridge_artifact_digest: fixture_handle(&fixture_digest('6')),
            store_bootstrap_descriptor_path: fixture_handle(r"C:\Eliot\approved\bootstrap.json"),
            store_bootstrap_descriptor_digest: fixture_handle(&fixture_digest('7')),
            canonical_store_executable_path: fixture_handle(r"C:\Eliot\approved\surreal.exe"),
            canonical_store_artifact_digest: fixture_handle(&fixture_digest('8')),
            kernel_arguments: Vec::new(),
            store_bridge_arguments: Vec::new(),
            canonical_store_arguments: Vec::new(),
            host_executable_path: fixture_handle(r"C:\Eliot\approved\eliot-host.exe"),
            host_artifact_digest: fixture_handle(&fixture_digest('4')),
            watchdog_executable_path: fixture_handle(r"C:\Eliot\approved\eliot-watchdog.exe"),
            watchdog_artifact_digest: fixture_handle(&fixture_digest('3')),
            doctor_artifact_digest: fixture_handle(&fixture_digest('2')),
            testd_artifact_digest: fixture_handle(&fixture_digest('1')),
            native_worker_artifact_digest: fixture_handle(&fixture_digest('e')),
            user_broker_artifact_digest: fixture_handle(&fixture_digest('d')),
            wasm_host_artifact_digest: fixture_handle(&fixture_digest('c')),
            doctor_executable_path: fixture_handle(r"C:\Eliot\approved\eliot-doctor.exe"),
            testd_executable_path: fixture_handle(r"C:\Eliot\approved\eliot-testd.exe"),
            native_worker_executable_path: fixture_handle(r"C:\Eliot\approved\eliot-native.exe"),
            user_broker_executable_path: fixture_handle(r"C:\Eliot\approved\eliot-broker.exe"),
            wasm_host_executable_path: fixture_handle(r"C:\Eliot\approved\eliot-wasm-host.exe"),
            descriptor_digest: fixture_handle(&fixture_digest('0')),
        }
    }

    /// Serialized descriptor bytes over one wire id and one declared image.
    ///
    /// Every other field is the approved contour's own value, and
    /// `with_computed_digest` seals the exact bytes, so the digest a case
    /// derives from them is the approved descriptor digest for precisely this
    /// content - nothing is fabricated to force an admission.
    fn fixture_descriptor_bytes(wire_id: &str, eliotd_executable: &str) -> Vec<u8> {
        let executable_digest = fixture_digest('a');
        let config_digest = fixture_digest('b');
        let descriptor = EliotdLaunchDescriptor {
            wire_id: wire_id.to_owned(),
            wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
            executable: fixture_handle(eliotd_executable),
            executable_sha256: executable_digest.clone(),
            arguments: vec![
                fixture_handle("--config-descriptor"),
                fixture_handle(APPROVED_ELIOTD_CONFIG),
                fixture_handle("--config-descriptor-sha256"),
                fixture_handle(&config_digest),
                fixture_handle("--launch-nonce"),
                fixture_handle(APPROVED_LAUNCH_NONCE),
                fixture_handle("--executable-sha256"),
                fixture_handle(&executable_digest),
            ],
            working_directory: fixture_handle(APPROVED_WORK_ROOT),
            config_descriptor: fixture_handle(APPROVED_ELIOTD_CONFIG),
            config_descriptor_sha256: config_digest,
            protected_snapshot_digest: fixture_digest('c'),
            launch_nonce: fixture_handle(APPROVED_LAUNCH_NONCE),
            authority_epoch: fixture_epoch(),
            generation: ResourceGeneration::genesis(),
            restart_policy: None,
            job_object_limits: None,
            health_readiness_contract_ref: None,
            descriptor_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap_or_else(|_| panic!("the fixture descriptor must seal"));
        serde_json::to_vec(&descriptor)
            .unwrap_or_else(|_| panic!("the fixture descriptor must serialize"))
    }

    /// The approved Store bootstrap requirement the caller already holds when
    /// this seam runs: the real Kernel route identity, a canonical pipe, the
    /// genesis store generation inside a real `StateFence`, and the approved
    /// artifact, config and nonce handles the requirement must bind.
    fn approved_store_bootstrap_requirement() -> HostStoreBootstrapRequirement {
        HostStoreBootstrapRequirement {
            route_identity: fixture_handle(eliot_kernel_service::STORE_ROUTE_IDENTITY),
            canonical_pipe_identity: fixture_handle(BOOTSTRAP_PIPE),
            store_generation: ResourceGeneration::genesis(),
            state_fence: StateFence::new(fixture_epoch(), ResourceGeneration::genesis()),
            launch_nonce: fixture_handle(BOOTSTRAP_NONCE),
            connection_id: fixture_handle(BOOTSTRAP_CONNECTION),
            expected_peer_sid: fixture_handle("S-1-5-18"),
            expected_peer_session_id: 0,
            approved_artifact_hash: fixture_handle(&fixture_digest('6')),
            approved_config_hash: fixture_handle(&fixture_digest('7')),
            timeout_ms: 5_000,
        }
    }

    /// One temporary Store bootstrap descriptor, its approved digest handle and
    /// the approved requirement it encodes.
    ///
    /// The approved digest is the handle a caller already holds for exactly the
    /// bytes on disk, and the requirement's artifact, config and nonce handles
    /// are the ones the caller already holds when the seam compares them, so
    /// nothing here is fabricated to force an admission.
    struct BootstrapDescriptor {
        root: std::path::PathBuf,
        descriptor: std::path::PathBuf,
        approved_digest: PlatformHandle,
        requirement: HostStoreBootstrapRequirement,
    }

    impl BootstrapDescriptor {
        /// Writes one approved requirement to a temporary descriptor and
        /// returns it beside the digest handle that hashes those exact bytes.
        /// An unwritable fixture panics: a skipped case is not proof.
        fn create(requirement: HostStoreBootstrapRequirement) -> Self {
            let name = format!("eliot-978-bootstrap-{}", std::process::id());
            let root = std::env::temp_dir().join(name);
            let Ok(()) = std::fs::create_dir_all(&root) else {
                panic!("the Store bootstrap fixture root must be creatable");
            };
            let descriptor = root.join("978-store-bootstrap-descriptor.json");
            let Ok(bytes) = serde_json::to_vec(&requirement) else {
                panic!("the approved Store bootstrap requirement must serialize");
            };
            let Ok(()) = std::fs::write(&descriptor, &bytes) else {
                panic!("the Store bootstrap descriptor fixture must be writable");
            };
            Self {
                approved_digest: digest_handle_of(&bytes),
                root,
                descriptor,
                requirement,
            }
        }

        /// Replaces the descriptor bytes on disk. That path is the only input
        /// the retained lease reads, so this is how a case presents the seam
        /// with bytes the caller's approved digest handle does not cover, with
        /// no second fixture and no new seam. An unwritable fixture panics.
        fn write_bytes(&self, bytes: &[u8]) {
            let Ok(()) = std::fs::write(&self.descriptor, bytes) else {
                panic!("the Store bootstrap descriptor fixture must be rewritable");
            };
        }

        /// The retained lease over that descriptor, opened through the same
        /// portable root seam the launch contour retains, so the Store
        /// bootstrap validation runs its real lease verify, bounded read,
        /// digest comparison and requirement validation.
        fn lease(&self) -> LaunchLease {
            let Ok(root) = UserOwnedRootLease::open_existing(&self.root) else {
                panic!("the Store bootstrap fixture root must open as a root lease");
            };
            let profile = InstallationProfile::PortableDev;
            let Ok(lease) = open_launch_lease(profile, Some(&root), &self.descriptor) else {
                panic!("the Store bootstrap descriptor must retain a launch lease");
            };
            lease
        }
    }

    impl Drop for BootstrapDescriptor {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.descriptor);
            let _ = std::fs::remove_dir(&self.root);
        }
    }

    /// In-memory sink that captures facade output without contending for the
    /// process-global subscriber.
    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs the real instrumented call under a scoped subscriber and returns
    /// the captured record text together with the exact value the call
    /// returned, so a case asserts the real outcome and the real emitted
    /// record instead of a detail it rendered itself. Generic over the returned
    /// value, so an admitted decision and a multi-decision window are captured
    /// by the same harness the refusals use.
    fn capture_rejection<T>(drive: impl FnOnce() -> T) -> (String, T) {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        let mut outcome = None;
        tracing::subscriber::with_default(subscriber, || {
            outcome = Some(drive());
        });
        let bytes = sink
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let outcome =
            outcome.unwrap_or_else(|| panic!("the instrumented call must return one outcome"));
        (text, outcome)
    }

    fn count(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    /// The captured subordinate records of one window, one per emitted line, so
    /// a case reads a property off a real record instead of off the formatted
    /// window as a whole.
    fn captured_records(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| line.contains("host.entrypoint_stage"))
            .collect()
    }

    /// The captured records whose own emission carries one marker, so a case
    /// separates real emissions by the phase or by the bound identity the call
    /// site wrote rather than by capture position.
    fn records_carrying<'a>(records: &[&'a str], marker: &str) -> Vec<&'a str> {
        records
            .iter()
            .copied()
            .filter(|record| record.contains(marker))
            .collect()
    }

    /// The captured records whose own emission names one phase, so a case
    /// selects a record by the phase the production call site emitted.
    fn records_naming_phase<'a>(records: &[&'a str], phase: &str) -> Vec<&'a str> {
        let needle = format!("phase={phase}");
        records_carrying(records, needle.as_str())
    }

    /// The typed rejection reason of the one `HostError` variant this seam
    /// produces, so a case asserts the exact variant and never a debug shape.
    fn process_contour_reason(error: HostError) -> String {
        let HostError::ProcessContour(reason) = error else {
            panic!("a descriptor refusal must stay the typed ProcessContour variant");
        };
        reason
    }

    /// The invariants every record this cell emits on a refusal shares:
    /// the retained approved descriptor digest the call site already held, the
    /// slots it has no evidence for explicitly absent, and no admission and no
    /// terminal. `window` is the captured text of the whole refused operation
    /// and `refusal` is the one record out of it the production call site
    /// emitted for the refusal, so a seam that also records its own request is
    /// asserted on the record that actually refused.
    fn assert_refusal_record(window: &str, refusal: &str, approved: &PlatformHandle) {
        assert_eq!(
            count(window, "host.terminal_error"),
            0,
            "this cell is phase-only; the outer launch contour owns the one terminal: {window}"
        );
        assert!(
            refusal.contains(&format!("artifact={}", approved.as_str())),
            "the retained approved descriptor digest must survive verbatim: {refusal}"
        );
        for absent in ["operation", "process_start", "fence", "reason"] {
            assert!(
                refusal.contains(&format!("{absent}=missing")),
                "this cell proves no {absent} and it must stay explicitly absent: {refusal}"
            );
        }
        assert!(
            !window.contains("admitted"),
            "a refused descriptor never emits an admission: {window}"
        );
    }

    /// `assert_refusal_record` plus the two extra identities the descriptor-bytes
    /// seam already holds beside the approved descriptor digest, on the only
    /// subordinate record its refused window contains. It takes one captured
    /// subordinate record, which is either the only record of a refused window
    /// or one record selected out of a multi-decision window.
    fn assert_retained_rejection_record(
        text: &str,
        phase: &str,
        approved: &PlatformHandle,
        launch: &RuntimeLaunchDescriptor,
    ) {
        assert_eq!(
            count(text, "host.entrypoint_stage"),
            1,
            "one refused descriptor emits exactly one subordinate record: {text}"
        );
        let refusals = records_naming_phase(&captured_records(text), phase);
        assert_eq!(
            refusals.len(),
            1,
            "the refusal record must name its own phase exactly once: {text}"
        );
        let refusal = refusals[0];
        assert_refusal_record(text, refusal, approved);
        assert!(
            refusal.contains(&format!(
                "installation={}",
                launch.installation_epoch.installation.as_str()
            )),
            "the retained installation identity must survive verbatim: {refusal}"
        );
        let generation = launch.authority_generation.value();
        assert!(
            refusal.contains(&format!("generation={generation}")),
            "the retained authority generation must survive verbatim: {refusal}"
        );
    }

    /// The same refusal invariants on the retained-lease Store bootstrap seam,
    /// whose refused window also holds the request record that seam emits before
    /// it refuses, plus the two identity slots this seam can never hold:
    /// `validate_store_bootstrap_descriptor` takes no launch descriptor and
    /// binds only the approved descriptor digest handle, so `installation` and
    /// `generation` are explicitly missing here instead of invented.
    fn assert_retained_store_bootstrap_record(text: &str, phase: &str, approved: &PlatformHandle) {
        let records = captured_records(text);
        assert_eq!(
            records.len(),
            2,
            "this seam records its request, then exactly one refusal: {text}"
        );
        let refusals = records_naming_phase(&records, phase);
        assert_eq!(
            refusals.len(),
            1,
            "the refusal record must name its own phase exactly once: {text}"
        );
        let refusal = refusals[0];
        assert_refusal_record(text, refusal, approved);
        for absent in ["installation", "generation"] {
            assert!(
                refusal.contains(&format!("{absent}=missing")),
                "this seam holds no {absent} and it stays explicitly absent: {refusal}"
            );
        }
    }

    /// `WORK_UNIT_CASE`: 978/3 — a substitution or refusal record keeps the exact
    /// retained approved identity and never the rejected value; `WORK_UNIT_CASE`:
    /// 978/12 — no path, argv, or nonce value reaches a slot.
    ///
    /// Executed over the descriptor-bytes seam, which is reachable in-crate
    /// because it takes bytes rather than a filesystem lease: a self-consistent
    /// descriptor whose image is substituted for the approved one reaches the
    /// real substitution branch, and the record read back out of the scoped
    /// subscriber carries the approved identities only. Every assertion below
    /// reads that captured record; this case renders nothing itself.
    #[test]
    fn substitution_record_keeps_the_retained_approved_digest_and_drops_the_rejected_value() {
        let launch = fixture_launch(APPROVED_ELIOTD_EXECUTABLE);
        let substituted_bytes =
            fixture_descriptor_bytes(APPROVED_ELIOTD_WIRE_ID, SUBSTITUTED_ELIOTD_EXECUTABLE);
        // The descriptor digest handle the call site holds for exactly these
        // bytes: the approved identity of the descriptor under validation.
        let descriptor_digest = digest_handle_of(&substituted_bytes);
        let (text, outcome) = capture_rejection(|| {
            validate_eliotd_launch_descriptor_bytes(&substituted_bytes, &descriptor_digest, &launch)
        });
        let Err(error) = outcome else {
            panic!("a descriptor bound to a substituted image must stay rejected");
        };
        assert_eq!(
            process_contour_reason(error),
            SUBSTITUTION_REJECTION,
            "the substitution keeps the exact retained typed rejection"
        );
        assert_retained_rejection_record(&text, SUBSTITUTION_PHASE, &descriptor_digest, &launch);
        // The rejected image, the launch nonce and the refusal prose itself stay
        // out of the record. The canary marker matches however the subscriber
        // renders a field value, and no path separator may reach any slot, so
        // neither the substituted nor the approved locator can leak.
        assert!(
            !text.contains("978-canary"),
            "no rejected image or canary value may be bound: {text}"
        );
        for canary in [
            SUBSTITUTION_REJECTION,
            APPROVED_LAUNCH_NONCE,
            REJECTED_PATH_CANARY,
            NONCE_CANARY,
        ] {
            assert!(
                !text.contains(canary),
                "a rejected value must never be bound: {text}"
            );
        }
        assert!(
            !text.contains('\\'),
            "no slot may carry a path separator, so no locator can leak: {text}"
        );
    }

    /// One refusal of the descriptor-bytes seam: descriptor bytes that are not
    /// the approved bytes at all, refused by the digest comparison.
    ///
    /// The approved digest handle is already in hand when the comparison runs,
    /// so the record must bind that approved identity and never the digest of
    /// the bytes that actually arrived.
    fn refuses_descriptor_bytes_whose_digest_is_not_approved(launch: &RuntimeLaunchDescriptor) {
        let approved_bytes =
            fixture_descriptor_bytes(APPROVED_ELIOTD_WIRE_ID, APPROVED_ELIOTD_EXECUTABLE);
        let approved = digest_handle_of(&approved_bytes);
        let foreign =
            fixture_descriptor_bytes(APPROVED_ELIOTD_WIRE_ID, SUBSTITUTED_ELIOTD_EXECUTABLE);
        let (text, outcome) = capture_rejection(|| {
            validate_eliotd_launch_descriptor_bytes(&foreign, &approved, launch)
        });
        let Err(error) = outcome else {
            panic!("descriptor bytes that are not the approved bytes must stay rejected");
        };
        assert_eq!(
            process_contour_reason(error),
            DIGEST_CHANGE_REJECTION,
            "the digest refusal keeps the exact retained typed rejection"
        );
        assert_retained_rejection_record(&text, ELIOTD_TYPED_REJECTION_PHASE, &approved, launch);
        assert!(
            !text.contains(digest_handle_of(&foreign).as_str()),
            "the refused bytes' own digest must never become the bound identity: {text}"
        );
    }

    /// One refusal of the descriptor-bytes seam: approved bytes that are not a
    /// descriptor, refused by the JSON decode.
    fn refuses_descriptor_bytes_that_are_not_json(launch: &RuntimeLaunchDescriptor) {
        let rejected = REJECTED_BYTES_CANARY.as_bytes();
        let approved = digest_handle_of(rejected);
        let (text, outcome) = capture_rejection(|| {
            validate_eliotd_launch_descriptor_bytes(rejected, &approved, launch)
        });
        let Err(error) = outcome else {
            panic!("descriptor bytes that are not JSON must stay rejected");
        };
        let reason = process_contour_reason(error);
        assert!(
            reason.starts_with(PARSE_REJECTION_PREFIX),
            "the parse refusal keeps its own exact typed prefix: {reason}"
        );
        assert_retained_rejection_record(&text, ELIOTD_TYPED_REJECTION_PHASE, &approved, launch);
        assert!(
            !text.contains(REJECTED_BYTES_CANARY),
            "rejected descriptor text must never reach a record: {text}"
        );
    }

    /// One refusal of the descriptor-bytes seam: a decodable descriptor whose
    /// own contract validation refuses it, refused with the validation text.
    fn refuses_a_descriptor_the_contract_does_not_admit(launch: &RuntimeLaunchDescriptor) {
        let rejected =
            fixture_descriptor_bytes(REJECTED_ELIOTD_WIRE_ID, APPROVED_ELIOTD_EXECUTABLE);
        let approved = digest_handle_of(&rejected);
        let (text, outcome) = capture_rejection(|| {
            validate_eliotd_launch_descriptor_bytes(&rejected, &approved, launch)
        });
        let Err(error) = outcome else {
            panic!("a descriptor the contract refuses must stay rejected");
        };
        let reason = process_contour_reason(error);
        assert!(
            reason.starts_with(VALIDATE_REJECTION_PREFIX),
            "the validation refusal keeps its own exact typed prefix: {reason}"
        );
        assert_retained_rejection_record(&text, ELIOTD_TYPED_REJECTION_PHASE, &approved, launch);
        assert!(
            !text.contains(REJECTED_ELIOTD_WIRE_ID),
            "the refused wire identity must never reach a record: {text}"
        );
    }

    /// One refusal of the retained-lease Store bootstrap seam: the bytes the
    /// retained lease reads are not the bytes the caller's approved descriptor
    /// digest handle covers.
    ///
    /// Only the descriptor bytes change. The approved digest handle is the one
    /// the caller already held before the comparison ran, so the record must
    /// bind that approved identity and never the digest of the bytes that
    /// actually arrived.
    fn store_bootstrap_refuses_bytes_whose_digest_is_not_approved() {
        let fixture = BootstrapDescriptor::create(approved_store_bootstrap_requirement());
        let approved = fixture.approved_digest.clone();
        let arrived = REJECTED_BOOTSTRAP_BYTES_CANARY.as_bytes();
        fixture.write_bytes(arrived);
        let lease = fixture.lease();
        let (text, outcome) = capture_rejection(|| {
            validate_store_bootstrap_descriptor(
                &lease,
                &approved,
                &fixture.requirement.approved_artifact_hash,
                &fixture.requirement.approved_config_hash,
                &fixture.requirement.launch_nonce,
            )
        });
        let Err(error) = outcome else {
            panic!("descriptor bytes that are not the approved bytes must stay rejected");
        };
        assert_eq!(
            process_contour_reason(error),
            BOOTSTRAP_DIGEST_CHANGE_REJECTION,
            "the digest refusal keeps the exact retained typed rejection"
        );
        assert_retained_store_bootstrap_record(&text, BOOTSTRAP_TYPED_REJECTION_PHASE, &approved);
        assert!(
            !text.contains(digest_handle_of(arrived).as_str()),
            "the refused bytes' own digest must never become the bound identity: {text}"
        );
        assert!(
            !text.contains(REJECTED_BOOTSTRAP_BYTES_CANARY),
            "rejected descriptor text must never reach a record: {text}"
        );
    }

    /// One refusal of the retained-lease Store bootstrap seam: descriptor bytes
    /// that are not a descriptor at all, refused by the JSON decode.
    ///
    /// The approved digest handle covers exactly the bytes that arrived, so the
    /// digest comparison passes and the decode is the refusing step.
    fn store_bootstrap_refuses_bytes_that_are_not_json() {
        let fixture = BootstrapDescriptor::create(approved_store_bootstrap_requirement());
        let arrived = REJECTED_BOOTSTRAP_BYTES_CANARY.as_bytes();
        fixture.write_bytes(arrived);
        let approved = digest_handle_of(arrived);
        let lease = fixture.lease();
        let (text, outcome) = capture_rejection(|| {
            validate_store_bootstrap_descriptor(
                &lease,
                &approved,
                &fixture.requirement.approved_artifact_hash,
                &fixture.requirement.approved_config_hash,
                &fixture.requirement.launch_nonce,
            )
        });
        let Err(error) = outcome else {
            panic!("descriptor bytes that are not JSON must stay rejected");
        };
        let reason = process_contour_reason(error);
        assert!(
            reason.starts_with(BOOTSTRAP_PARSE_REJECTION_PREFIX),
            "the parse refusal keeps its own exact typed prefix: {reason}"
        );
        assert_retained_store_bootstrap_record(&text, BOOTSTRAP_TYPED_REJECTION_PHASE, &approved);
        assert!(
            !text.contains(REJECTED_BOOTSTRAP_BYTES_CANARY),
            "rejected descriptor text must never reach a record: {text}"
        );
    }

    /// One refusal of the retained-lease Store bootstrap seam: a decodable
    /// requirement whose own contract validation refuses it, because its
    /// connection timeout is zero and the accepted range starts at one
    /// millisecond.
    ///
    /// Every bound identity the seam compares afterwards is the approved one, so
    /// `requirement.validate()` is the refusing step and nothing else.
    fn store_bootstrap_refuses_a_requirement_the_contract_does_not_admit() {
        let fixture = BootstrapDescriptor::create(HostStoreBootstrapRequirement {
            timeout_ms: 0,
            ..approved_store_bootstrap_requirement()
        });
        let approved = fixture.approved_digest.clone();
        let lease = fixture.lease();
        let (text, outcome) = capture_rejection(|| {
            validate_store_bootstrap_descriptor(
                &lease,
                &approved,
                &fixture.requirement.approved_artifact_hash,
                &fixture.requirement.approved_config_hash,
                &fixture.requirement.launch_nonce,
            )
        });
        let Err(error) = outcome else {
            panic!("a requirement the contract refuses must stay rejected");
        };
        let reason = process_contour_reason(error);
        assert!(
            reason.starts_with(BOOTSTRAP_VALIDATE_REJECTION_PREFIX),
            "the validation refusal keeps its own exact typed prefix: {reason}"
        );
        assert_retained_store_bootstrap_record(&text, BOOTSTRAP_TYPED_REJECTION_PHASE, &approved);
    }

    /// One refusal of the retained-lease Store bootstrap seam: a requirement the
    /// contract admits, refused because the artifact handle the caller passed is
    /// not the one the descriptor binds.
    ///
    /// The substituted handle is the caller's own held identity at that
    /// comparison, so the record must carry the approved descriptor digest and
    /// never the handle the comparison refused.
    fn store_bootstrap_refuses_a_descriptor_not_bound_to_the_approved_generation() {
        let fixture = BootstrapDescriptor::create(approved_store_bootstrap_requirement());
        let approved = fixture.approved_digest.clone();
        let other_artifact = fixture_handle(&fixture_digest('5'));
        let lease = fixture.lease();
        let (text, outcome) = capture_rejection(|| {
            validate_store_bootstrap_descriptor(
                &lease,
                &approved,
                &other_artifact,
                &fixture.requirement.approved_config_hash,
                &fixture.requirement.launch_nonce,
            )
        });
        let Err(error) = outcome else {
            panic!("a descriptor not bound to the approved generation must stay rejected");
        };
        assert_eq!(
            process_contour_reason(error),
            BOOTSTRAP_BINDING_REJECTION,
            "the binding refusal keeps the exact retained typed rejection"
        );
        assert_retained_store_bootstrap_record(&text, SUBSTITUTION_PHASE, &approved);
        assert!(
            !text.contains(other_artifact.as_str()),
            "the refused artifact identity must never become the bound identity: {text}"
        );
    }

    /// One refusal of the retained-lease Store bootstrap seam: the descriptor is
    /// one byte larger than the bound this call site passes to `read_bounded`,
    /// so the lease refuses the read itself and the seam never reaches its own
    /// digest comparison.
    ///
    /// Only the descriptor bytes change. They are written through the same path
    /// the retained lease reads and the lease is opened afterwards, so
    /// `lease.verify()` still proves the identity the lease was opened for and
    /// the refusing step is exactly the real bounded read this call site
    /// performs. The lease opens before the capture scope, so the captured
    /// window holds only the records this descriptor seam emits.
    fn store_bootstrap_refuses_a_descriptor_over_the_bounded_read() {
        let fixture = BootstrapDescriptor::create(approved_store_bootstrap_requirement());
        let over_limit = vec![b'x'; BOOTSTRAP_BOUNDED_READ_LIMIT + 1];
        fixture.write_bytes(&over_limit);
        let approved = fixture.approved_digest.clone();
        let lease = fixture.lease();
        let (text, outcome) = capture_rejection(|| {
            validate_store_bootstrap_descriptor(
                &lease,
                &approved,
                &fixture.requirement.approved_artifact_hash,
                &fixture.requirement.approved_config_hash,
                &fixture.requirement.launch_nonce,
            )
        });
        let Err(error) = outcome else {
            panic!("a descriptor over the bounded read limit must stay rejected");
        };
        let reason = process_contour_reason(error);
        assert!(
            reason.starts_with(BOOTSTRAP_READ_REJECTION_PREFIX),
            "the bounded read refusal keeps its own exact typed prefix: {reason}"
        );
        assert_retained_store_bootstrap_record(&text, BOOTSTRAP_TYPED_REJECTION_PHASE, &approved);
    }

    /// One refusal of the retained-lease eliotd seam: the descriptor is one byte
    /// larger than the bound that call site passes to `read_bounded`, so the
    /// lease refuses the read before the seam's own byte validation ever runs.
    ///
    /// The same fixture and the same over-limit bytes reach this site's own
    /// bounded read, one step after its `eliotd requested` record, because both
    /// seams take the same retained lease and hold the same approved descriptor
    /// digest handle. This seam binds the installation identity and the
    /// generation beside it, so its refused window holds two records and neither
    /// of those two slots is missing here; it therefore selects its own refusal
    /// record out of that window with the shared refusal invariants rather than
    /// with the Store bootstrap pair helper.
    fn eliotd_refuses_a_descriptor_over_the_bounded_read(launch: &RuntimeLaunchDescriptor) {
        let fixture = BootstrapDescriptor::create(approved_store_bootstrap_requirement());
        let over_limit = vec![b'x'; BOOTSTRAP_BOUNDED_READ_LIMIT + 1];
        fixture.write_bytes(&over_limit);
        let approved = approved_digest_handle(APPROVED_DIGEST);
        let lease = fixture.lease();
        let (text, outcome) =
            capture_rejection(|| validate_eliotd_launch_descriptor(&lease, &approved, launch));
        let Err(error) = outcome else {
            panic!("an eliotd descriptor over the bounded read limit must stay rejected");
        };
        let reason = process_contour_reason(error);
        assert!(
            reason.starts_with(ELIOTD_READ_REJECTION_PREFIX),
            "the bounded read refusal keeps its own exact typed prefix: {reason}"
        );
        let records = captured_records(&text);
        assert_eq!(
            records.len(),
            2,
            "this seam records its request, then exactly one refusal: {text}"
        );
        let refusals = records_naming_phase(&records, ELIOTD_TYPED_REJECTION_PHASE);
        assert_eq!(
            refusals.len(),
            1,
            "the refusal record must name its own phase exactly once: {text}"
        );
        let refusal = refusals[0];
        assert_refusal_record(&text, refusal, &approved);
        assert!(
            refusal.contains(&format!(
                "installation={}",
                launch.installation_epoch.installation.as_str()
            )),
            "the retained installation identity must survive verbatim: {refusal}"
        );
        let generation = launch.authority_generation.value();
        assert!(
            refusal.contains(&format!("generation={generation}")),
            "the retained authority generation must survive verbatim: {refusal}"
        );
    }

    /// `WORK_UNIT_CASE`: 978/2 — every descriptor refusal that is reachable
    /// in-crate keeps its exact typed variant and reason, emits the subordinate
    /// phase records that bind the retained approved identity rather than the
    /// rejected input, and never becomes an admission or a terminal.
    ///
    /// All three seams this case executes are reachable in-crate, so every
    /// refusal below is really executed. The descriptor-bytes seam takes bytes
    /// rather than a filesystem lease and refuses three ways: the digest
    /// comparison, the JSON decode, and the descriptor's own contract
    /// validation. The retained-lease Store bootstrap seam reads its descriptor
    /// bytes through a real `UserOwnedRootLease` and the real `open_launch_lease`
    /// and refuses four more ways from the descriptor path that fixture already
    /// owns, with no new machinery: that same digest comparison, that same JSON
    /// decode, `requirement.validate()`, and the binding comparison under a
    /// different `expected_artifact`. A descriptor one byte past the bound both
    /// retained-lease call sites pass to `read_bounded` refuses the bounded read
    /// itself, on the Store bootstrap seam and on the eliotd seam, so neither of
    /// those two refusal sites stays unexecuted. Each arm runs the real function
    /// once inside its own capture scope and asserts only what that execution
    /// emitted.
    ///
    /// The lease `verify` refusal of `validate_store_bootstrap_descriptor` and
    /// of `validate_eliotd_launch_descriptor` stay unexecuted here, for one
    /// concrete reason on each lease kind. `verify` is a retained-handle
    /// identity proof: it re-inspects the open handle and reopens the path by
    /// name, so it can only fail where the path names a different object than
    /// the retained handle does. A portable lease cannot make it fail, because
    /// its file lease is opened without `FILE_SHARE_DELETE`
    /// (`user_owned_leases.rs::open_user_owned_file`), which is what makes
    /// substitution impossible while the lease is live: content can still be
    /// rewritten under a retained lease, as the digest arms above prove, but the
    /// descriptor itself cannot be replaced or renamed. And
    /// `UserOwnedRootLease` is no way around that by being some other root type:
    /// it is the user-owned `portable_dev` root lease for an explicit already-
    /// existing directory owned by the current process identity rather than the
    /// installation-wide `ProgramData` policy, and the portable branch of this
    /// very file already opens one. The protected lease is the other route, and
    /// it needs the installation-wide `ProgramData` protected contour
    /// `ProtectedPathLease::open_existing_absolute` requires - the OS-resolved
    /// root, containment inside it, and the DACL only the installer provisions -
    /// which no development or test environment publishes. Both `verify`
    /// refusals therefore stay with the integration fixture owner that runs the
    /// real installed contour.
    ///
    /// `verify_host_artifact_at` and `verify_current_host_artifact` are left out
    /// by the writer's own scope choice, not by any constructibility limit:
    /// every `CandidateManifest` field is public, so a field-by-field literal
    /// is buildable in-crate exactly as the launch descriptor above is. What
    /// this case declines to do is assert which manifest is approved - image
    /// names, locators and nine role digests it invents itself - purely to make
    /// a refusal fire, because such a literal is a fabricated approved identity
    /// rather than the approved manifest a real installation publishes. Those
    /// refusals stay with the integration fixture owner.
    #[test]
    fn descriptor_refusals_keep_their_typed_rejection_and_the_retained_identity() {
        let launch = fixture_launch(APPROVED_ELIOTD_EXECUTABLE);
        refuses_descriptor_bytes_whose_digest_is_not_approved(&launch);
        refuses_descriptor_bytes_that_are_not_json(&launch);
        refuses_a_descriptor_the_contract_does_not_admit(&launch);
        store_bootstrap_refuses_bytes_whose_digest_is_not_approved();
        store_bootstrap_refuses_bytes_that_are_not_json();
        store_bootstrap_refuses_a_requirement_the_contract_does_not_admit();
        store_bootstrap_refuses_a_descriptor_not_bound_to_the_approved_generation();
        store_bootstrap_refuses_a_descriptor_over_the_bounded_read();
        eliotd_refuses_a_descriptor_over_the_bounded_read(&launch);
    }

    /// `WORK_UNIT_CASE`: 978/4 — an admitted descriptor is an admission, never
    /// readiness; `WORK_UNIT_CASE`: 978/5 - this cell holds no process-start
    /// identity, so the slot stays missing instead of carrying a bare PID.
    ///
    /// Executed over the real `validate_store_bootstrap_descriptor` seam, which
    /// is constructible in-crate after all: a retained `LaunchLease` over a
    /// temporary bootstrap descriptor, the approved descriptor digest handle the
    /// caller already holds for exactly those bytes, and the approved artifact,
    /// config and nonce handles the requirement must bind. Every assertion below
    /// reads the record that execution really emitted inside a scoped
    /// subscriber; this case emits nothing itself.
    #[test]
    fn admitted_descriptor_record_is_an_admission_and_holds_no_process_start() {
        let fixture = BootstrapDescriptor::create(approved_store_bootstrap_requirement());
        let lease = fixture.lease();
        // The lease is opened outside the capture scope, so the captured window
        // holds exactly the records this descriptor seam emits.
        let (text, outcome) = capture_rejection(|| {
            validate_store_bootstrap_descriptor(
                &lease,
                &fixture.approved_digest,
                &fixture.requirement.approved_artifact_hash,
                &fixture.requirement.approved_config_hash,
                &fixture.requirement.launch_nonce,
            )
        });
        let requirement = outcome.unwrap_or_else(|error| {
            panic!("the approved Store bootstrap descriptor must be admitted: {error}")
        });
        assert_eq!(requirement, fixture.requirement, "the admitted requirement");
        let terminals = count(&text, "host.terminal_error");
        assert_eq!(
            terminals, 0,
            "this cell is phase-only, never a terminal: {text}"
        );
        let records = captured_records(&text);
        assert_eq!(
            records.len(),
            2,
            "an admitted descriptor emits two records: {text}"
        );
        let admitted = records_naming_phase(&records, ADMITTED_PHASE);
        assert_eq!(
            admitted.len(),
            1,
            "the call site emits the admission: {text}"
        );
        let admitted = admitted[0];
        assert!(
            admitted.contains(&format!("artifact={}", fixture.approved_digest.as_str())),
            "the retained approved descriptor identity survives verbatim: {admitted}"
        );
        for absent in ["operation", "process_start", "fence", "reason"] {
            assert!(
                admitted.contains(&format!("{absent}=missing")),
                "{absent} has no evidence here and stays explicitly absent: {admitted}"
            );
        }
        assert!(
            !admitted.contains("pid"),
            "an admission record names no process identity at all, not even a pid: {admitted}"
        );
        assert!(
            !admitted.contains("ready"),
            "an admission is never readiness: {admitted}"
        );
        // The descriptor's pipe, nonce and connection identities are held by the
        // caller but are not bounded identities of this cell, so no record may
        // carry them and no record may carry a path separator.
        for excluded in [BOOTSTRAP_PIPE, BOOTSTRAP_NONCE, BOOTSTRAP_CONNECTION] {
            assert!(
                !text.contains(excluded),
                "an excluded descriptor identity must never be bound: {text}"
            );
        }
        assert!(
            !text.contains('\\'),
            "no slot may carry a path separator, so no locator can leak: {text}"
        );
    }

    /// `WORK_UNIT_CASE`: 978/13 — the emitted fields are deterministic per held
    /// identity and separate two approved descriptor contours, so they are not
    /// one vacuous field set.
    ///
    /// Proven over captured production emissions, not over strings this case
    /// rendered: three real executions of the descriptor-bytes seam run inside
    /// one scoped subscriber, each holding an approved descriptor digest
    /// handle the caller already had when the comparison ran. The same held
    /// identity decided twice must emit two identical records, a second held
    /// identity must emit a third, different record, and the digest of the
    /// bytes that actually arrived must never be bound.
    #[test]
    fn descriptor_records_are_deterministic_per_identity_and_separate_contours() {
        let launch = fixture_launch(APPROVED_ELIOTD_EXECUTABLE);
        // The two approved descriptor identities the caller holds, neither of
        // which is the digest of the bytes that actually arrive.
        let approved = approved_digest_handle(APPROVED_DIGEST);
        let other_approved = approved_digest_handle(OTHER_APPROVED_DIGEST);
        let arrived =
            fixture_descriptor_bytes(APPROVED_ELIOTD_WIRE_ID, SUBSTITUTED_ELIOTD_EXECUTABLE);
        let arrived_digest = digest_handle_of(&arrived);
        let (text, (first, repeated, other)) = capture_rejection(|| {
            (
                validate_eliotd_launch_descriptor_bytes(&arrived, &approved, &launch),
                validate_eliotd_launch_descriptor_bytes(&arrived, &approved, &launch),
                validate_eliotd_launch_descriptor_bytes(&arrived, &other_approved, &launch),
            )
        });
        for outcome in [first, repeated, other] {
            let Err(error) = outcome else {
                panic!("descriptor bytes that are not the approved bytes stay rejected");
            };
            let reason = process_contour_reason(error);
            assert_eq!(
                reason, DIGEST_CHANGE_REJECTION,
                "one exact retained refusal"
            );
        }
        let terminals = count(&text, "host.terminal_error");
        assert_eq!(
            terminals, 0,
            "this cell is phase-only, never a terminal: {text}"
        );
        let records = captured_records(&text);
        assert_eq!(
            records.len(),
            3,
            "each executed decision emits one record: {text}"
        );
        let approved_marker = format!("artifact={APPROVED_DIGEST}");
        let other_marker = format!("artifact={OTHER_APPROVED_DIGEST}");
        let same_identity = records_carrying(&records, approved_marker.as_str());
        let other_contour = records_carrying(&records, other_marker.as_str());
        assert_eq!(
            same_identity.len(),
            2,
            "one held identity decided twice: {text}"
        );
        assert_eq!(
            other_contour.len(),
            1,
            "a second held identity emits its own: {text}"
        );
        assert_eq!(
            same_identity[0], same_identity[1],
            "one identity emits one record"
        );
        assert_ne!(
            same_identity[0], other_contour[0],
            "two identities emit two records"
        );
        for record in same_identity.iter().copied() {
            assert_retained_rejection_record(
                record,
                ELIOTD_TYPED_REJECTION_PHASE,
                &approved,
                &launch,
            );
        }
        assert_retained_rejection_record(
            other_contour[0],
            ELIOTD_TYPED_REJECTION_PHASE,
            &other_approved,
            &launch,
        );
        assert!(
            !text.contains(arrived_digest.as_str()),
            "the arrived bytes' own digest is never the bound identity: {text}"
        );
    }
}
