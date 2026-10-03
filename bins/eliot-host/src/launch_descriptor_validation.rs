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
// contract. The cases drive the real `launch_descriptor_observe` helper with the
// exact correlation this file's call sites build, so they exercise the actual
// instrumented path through its existing seam, widen no visibility, and never
// hand-assemble an expected log record. Outcomes that need a real approved
// candidate manifest or a real Windows artifact lease stay with the integration
// fixture owner; what is proven here is the correlation this cell can construct
// privately: the retained approved identity on a substitution or refusal, no
// readiness and no process-start claim, no argv/nonce/path canary, and
// determinism per held identity.
#[cfg(all(test, windows))]
mod tests {
    use super::{LaunchPhaseCorrelation, launch_descriptor_observe};
    use eliot_platform::PlatformHandle;

    const APPROVED_DIGEST: &str =
        "9780000000000000000000000000000000000000000000000000000000000001";
    const OTHER_APPROVED_DIGEST: &str =
        "9780000000000000000000000000000000000000000000000000000000000002";
    const REJECTED_PATH_CANARY: &str = r"C:\978-canary\store-bootstrap-descriptor.json";
    const NONCE_CANARY: &str = "978-canary-launch-nonce";
    const SUBSTITUTION_PHASE: &str = "host.launch-descriptor substitution preserved";
    const ADMITTED_PHASE: &str = "host.launch-descriptor store bootstrap admitted";

    fn approved_digest_handle(digest: &str) -> PlatformHandle {
        PlatformHandle::new(digest)
            .unwrap_or_else(|_| panic!("approved descriptor digest handle must build"))
    }

    /// The exact correlation `validate_store_bootstrap_descriptor` builds from
    /// the approved descriptor digest handle it already holds, so a case never
    /// restates what that call site binds.
    fn approved_descriptor_correlation(
        approved_digest: &PlatformHandle,
    ) -> LaunchPhaseCorrelation<'_> {
        LaunchPhaseCorrelation::NONE.with_artifact(approved_digest.as_str())
    }

    /// `WORK_UNIT_CASE`: 978/3 — a substitution or refusal record keeps the exact
    /// retained approved identity and never the rejected value; `WORK_UNIT_CASE`:
    /// 978/12 — no path, argv, or nonce value reaches a slot.
    #[test]
    fn substitution_record_keeps_the_retained_approved_digest_and_drops_the_rejected_value() {
        let approved = approved_digest_handle(APPROVED_DIGEST);
        let correlation = approved_descriptor_correlation(&approved);
        let detail = correlation.render(SUBSTITUTION_PHASE);
        assert!(
            detail.contains(&format!("phase={SUBSTITUTION_PHASE}")),
            "the retained approved record must name its phase: {detail}"
        );
        assert!(
            detail.contains(&format!("artifact={APPROVED_DIGEST}")),
            "the retained approved identity must survive verbatim: {detail}"
        );
        for canary in [REJECTED_PATH_CANARY, NONCE_CANARY] {
            assert!(
                !detail.contains(canary),
                "a rejected path or nonce value must never be bound: {detail}"
            );
        }
        assert!(
            !detail.contains('\\'),
            "no slot may carry a path separator: {detail}"
        );
        // The production helper runs this exact record through the facade, so
        // the seam itself is exercised rather than assumed.
        launch_descriptor_observe(SUBSTITUTION_PHASE, &correlation);
    }

    /// `WORK_UNIT_CASE`: 978/4 — an admitted descriptor is an admission, never
    /// readiness; `WORK_UNIT_CASE`: 978/5 - this cell holds no process-start
    /// identity, so the slot stays missing instead of carrying a bare PID.
    #[test]
    fn admitted_descriptor_record_is_an_admission_and_holds_no_process_start() {
        let approved = approved_digest_handle(APPROVED_DIGEST);
        let correlation = approved_descriptor_correlation(&approved);
        let admitted = correlation.render(ADMITTED_PHASE);
        let substitution = correlation.render(SUBSTITUTION_PHASE);
        assert_ne!(
            admitted, substitution,
            "an admission and a substitution must stay distinguishable records"
        );
        assert!(
            admitted.contains(&format!("phase={ADMITTED_PHASE}")),
            "the admission record must name its phase: {admitted}"
        );
        assert!(
            !admitted.contains("ready"),
            "admission is never readiness: {admitted}"
        );
        for absent in ["process_start", "fence", "reason"] {
            assert!(
                admitted.contains(&format!("{absent}=missing")),
                "{absent} has no evidence in this cell and must stay explicitly absent: {admitted}"
            );
        }
        launch_descriptor_observe(ADMITTED_PHASE, &correlation);
    }

    /// `WORK_UNIT_CASE`: 978/13 — the emitted fields are deterministic per held
    /// identity and separate two approved descriptor contours, so they are not
    /// one vacuous field set.
    #[test]
    fn descriptor_records_are_deterministic_per_identity_and_separate_contours() {
        let approved = approved_digest_handle(APPROVED_DIGEST);
        let other = approved_digest_handle(OTHER_APPROVED_DIGEST);
        let first = approved_descriptor_correlation(&approved).render(SUBSTITUTION_PHASE);
        let repeated = approved_descriptor_correlation(&approved).render(SUBSTITUTION_PHASE);
        assert_eq!(
            first, repeated,
            "one held identity must render one deterministic record"
        );
        let other_contour = approved_descriptor_correlation(&other).render(SUBSTITUTION_PHASE);
        assert_ne!(
            first, other_contour,
            "two approved descriptor identities must not render one record"
        );
        assert!(
            other_contour.contains(&format!("artifact={}", other.as_str())),
            "each record must carry its own approved digest: {other_contour}"
        );
    }
}
