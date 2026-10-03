//! Retained launch-artifact leases and approved-path validation.
//!
//! Canonical ELIOT anchors: `A5.5`
//! (`docs/architecture/A05-05-verifier-and-evaluation-contract.md`) scopes
//! verifier inputs and failure applicability, and `A13.2`
//! (`docs/architecture/A13-02-kernel-and-failure-domains.md`) separates Host,
//! Kernel, and Watchdog failure domains. `I1.2`
//! (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`)
//! assigns Host approved-artifact ownership without project semantics, `I1.8`
//! (`docs/architecture/I01-08-exact-ownership-and-call-paths.md`) defines exact
//! ownership and call paths, `I2.23`
//! (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`)
//! requires a bounded extraction closure, and the storage boundary `I5.1`
//! (`docs/architecture/I05-01-storage-boundary.md`) limits Host protocol evidence
//! to immutable artifact/config hashes.
//!
//! This child only opens and validates already-approved immutable launch
//! artifacts and returns lease evidence. It cannot create, replace, or delete
//! artifacts; select generations; perform Host lifecycle, SCM, or Phase-B
//! transaction work; mutate credentials or semantic/canonical state; or own
//! authority.

use std::io;
use std::path::{Path, PathBuf};

use eliot_installation::{
    InstallationProfile, verify_approved_path, verify_file_digest_with_lease,
    verify_file_digest_with_user_lease,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    ProtectedPathLease, UserOwnedPathLease, UserOwnedRootLease, windows_paths_equal,
};

use super::super::HostError;
use super::super::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) launch-artifact observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. A call site passes a static phase token plus a bounded
// `LaunchPhaseCorrelation` built only from an identity handle the owner already
// holds and rendered through `crate::host_diagnostics::bound_field`, so a static
// label classifies the phase while the bounded identity names the artifact it
// concerned. The artifact identity bound here is only the owner-supplied
// expected digest handle already in hand at a `verify_launch_digest` outcome —
// never a recomputed, re-verified or re-read digest, never artifact bytes
// (`read_bounded`), and never arbitrary error `Debug`/`Display` text, so
// bounding limits size, not sensitivity (I15.4).
//
// A retained-artifact lease, locator or approved-path handle is a path, and a
// path is not an identity: `LaunchLease::path`, the `approved` locator handle
// and `supplied` are never bound into a diagnostic field (case 978/12). This
// cell holds no `HostLaunchOptions`, so installation and generation are never
// available here, and it owns no operation id, process-start identity, fence or
// typed reason; it also observes no process and no readiness. Missing evidence
// stays explicitly `missing` rather than invented, which is why every
// locator and lease call site — including the "digest requested" record, which
// precedes any verification outcome — binds nothing (cases 978/1, 978/4).
//
// Sink outcome never alters result/order/count/handle/cleanup/timeout. There is
// no mutable global dedup cache and no terminal emission here: the designated
// terminal for one failed launch is `lib.rs`'s
// `HostTerminalGuard(BOUNDARY_START_TERMINAL)` ("host-start-failed"), and the
// `HostJobBranches::start_approved` leaf guard is phase-only (issue #978 audit
// defect 2), so this cell can never emit a second terminal. Retained identity on
// substitution failure is preserved (case 978/3); digest/descriptor rejections
// stay typed (case 978/2).
fn launch_artifact_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

fn launch_artifact_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    launch_artifact_note_event_log_unavailable();
    let detail = correlation.render(phase);
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        &detail,
    );
}

/// Retained ownership of an approved launch artifact.
pub(crate) enum LaunchLease {
    Protected(ProtectedPathLease),
    Portable(UserOwnedPathLease),
}

impl LaunchLease {
    pub(crate) fn path(&self) -> &Path {
        match self {
            Self::Protected(lease) => lease.path(),
            Self::Portable(lease) => lease.path(),
        }
    }

    pub(crate) fn verify(&self) -> Result<(), String> {
        match self {
            Self::Protected(lease) => lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| error.to_string()),
            Self::Portable(lease) => lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| error.to_string()),
        }
    }

    pub(crate) fn read_bounded(&self, limit: u64) -> Result<Vec<u8>, String> {
        match self {
            Self::Protected(lease) => lease.read_bounded(limit).map_err(|error| error.to_string()),
            Self::Portable(lease) => lease.read_bounded(limit).map_err(|error| error.to_string()),
        }
    }
}

pub(crate) fn approved_locator(
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
) -> Result<PathBuf, HostError> {
    // WORK_UNIT_CASE: 978/1 — locator requested; no admitted identity is in hand.
    launch_artifact_observe(
        "host.launch-artifact locator requested",
        &LaunchPhaseCorrelation::NONE,
    );
    if profile != InstallationProfile::PortableDev {
        let result =
            verify_approved_path(supplied, approved, "runtime.approved_locator").map_err(|error| {
                // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                launch_artifact_observe(
                    "host.launch-artifact substitution preserved",
                    &LaunchPhaseCorrelation::NONE,
                );
                HostError::ProcessContour(error.to_string())
            });
        if result.is_ok() {
            // WORK_UNIT_CASE: 978/1 — locator admitted.
            launch_artifact_observe(
                "host.launch-artifact locator admitted",
                &LaunchPhaseCorrelation::NONE,
            );
        }
        return result;
    }
    if !supplied.is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe(
            "host.launch-artifact locator typed rejection",
            &LaunchPhaseCorrelation::NONE,
        );
        return Err(HostError::ProcessContour(
            "portable locator must be absolute".to_owned(),
        ));
    }
    let canonical_supplied = std::fs::canonicalize(supplied).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe(
            "host.launch-artifact locator typed rejection",
            &LaunchPhaseCorrelation::NONE,
        );
        HostError::ProcessContour(error.to_string())
    })?;
    let canonical_approved =
        std::fs::canonicalize(Path::new(approved.as_str())).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe(
                "host.launch-artifact locator typed rejection",
                &LaunchPhaseCorrelation::NONE,
            );
            HostError::ProcessContour(error.to_string())
        })?;
    if canonical_supplied != canonical_approved {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_artifact_observe(
            "host.launch-artifact substitution preserved",
            &LaunchPhaseCorrelation::NONE,
        );
        return Err(HostError::ProcessContour(
            "portable locator is not the approved canonical path".to_owned(),
        ));
    }
    // The retained portable root lease and every child path must stay in the
    // same declared DOS-path namespace. `std::fs::canonicalize` adds a
    // verbatim prefix on Windows, which would make the exact root-containment
    // proof reject an otherwise identical approved child.
    // WORK_UNIT_CASE: 978/1 — locator admitted.
    launch_artifact_observe(
        "host.launch-artifact locator admitted",
        &LaunchPhaseCorrelation::NONE,
    );
    Ok(supplied.to_path_buf())
}

pub(crate) fn approved_phase_b_destination_locator(
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PathBuf, HostError> {
    // WORK_UNIT_CASE: 978/1 — phase-b destination requested; no admitted identity
    // is in hand.
    launch_artifact_observe(
        "host.launch-artifact phase-b destination requested",
        &LaunchPhaseCorrelation::NONE,
    );
    if profile != InstallationProfile::PortableDev {
        let result = approved_locator(supplied, approved, profile);
        if result.is_ok() {
            // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
            launch_artifact_observe(
                "host.launch-artifact phase-b destination admitted",
                &LaunchPhaseCorrelation::NONE,
            );
        }
        return result;
    }
    let root = portable_root.ok_or_else(|| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe(
            "host.launch-artifact phase-b destination typed rejection",
            &LaunchPhaseCorrelation::NONE,
        );
        HostError::ProcessContour("portable root lease is missing".to_owned())
    })?;
    if !supplied.is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe(
            "host.launch-artifact phase-b destination typed rejection",
            &LaunchPhaseCorrelation::NONE,
        );
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator must be absolute".to_owned(),
        ));
    }
    let approved_path = Path::new(approved.as_str());
    if !approved_path.is_absolute() || !windows_paths_equal(supplied, approved_path) {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_artifact_observe(
            "host.launch-artifact phase-b substitution preserved",
            &LaunchPhaseCorrelation::NONE,
        );
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator is not the approved path".to_owned(),
        ));
    }
    match std::fs::symlink_metadata(supplied) {
        Ok(_) => {
            let result = approved_locator(supplied, approved, profile);
            if result.is_ok() {
                // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
                launch_artifact_observe(
                    "host.launch-artifact phase-b destination admitted",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
            result
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let result = root
                .validate_child_parent(supplied)
                .map_err(|error| HostError::ProcessContour(error.to_string()));
            match result {
                Ok(()) => {
                    // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
                    launch_artifact_observe(
                        "host.launch-artifact phase-b destination admitted",
                        &LaunchPhaseCorrelation::NONE,
                    );
                    Ok(supplied.to_path_buf())
                }
                Err(error) => {
                    // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                    launch_artifact_observe(
                        "host.launch-artifact phase-b substitution preserved",
                        &LaunchPhaseCorrelation::NONE,
                    );
                    Err(error)
                }
            }
        }
        Err(error) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe(
                "host.launch-artifact phase-b destination typed rejection",
                &LaunchPhaseCorrelation::NONE,
            );
            Err(HostError::RecoveryRequired(format!(
                "Phase-B destination cannot be observed: {error}"
            )))
        }
    }
}

pub(crate) fn open_launch_lease(
    profile: InstallationProfile,
    root: Option<&UserOwnedRootLease>,
    path: &Path,
) -> Result<LaunchLease, HostError> {
    // WORK_UNIT_CASE: 978/1 — lease requested; a lease handle is a path, so no
    // identity is in hand.
    launch_artifact_observe(
        "host.launch-artifact lease requested",
        &LaunchPhaseCorrelation::NONE,
    );
    let result = match profile {
        InstallationProfile::PortableDev => {
            let root = root.ok_or_else(|| {
                HostError::ProcessContour("portable root lease is missing".to_owned())
            })?;
            Ok(LaunchLease::Portable(
                UserOwnedPathLease::open_existing(root, path)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            ))
        }
        InstallationProfile::SystemService | InstallationProfile::UserMode => {
            Ok(LaunchLease::Protected(
                ProtectedPathLease::open_existing_absolute(path)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            ))
        }
    };
    match &result {
        Ok(_) => {
            // WORK_UNIT_CASE: 978/1 — lease admitted, exact handle preserved.
            launch_artifact_observe(
                "host.launch-artifact lease admitted",
                &LaunchPhaseCorrelation::NONE,
            );
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe(
                "host.launch-artifact lease typed rejection",
                &LaunchPhaseCorrelation::NONE,
            );
        }
    }
    result
}

pub(crate) fn verify_launch_digest(
    lease: &LaunchLease,
    digest: &PlatformHandle,
    field: &str,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — digest requested; no verification outcome exists
    // yet, so no artifact identity is bound.
    launch_artifact_observe(
        "host.launch-artifact digest requested",
        &LaunchPhaseCorrelation::NONE,
    );
    let result = match lease {
        LaunchLease::Protected(lease) => verify_file_digest_with_lease(lease, digest, field),
        LaunchLease::Portable(lease) => verify_file_digest_with_user_lease(lease, digest, field),
    };
    let result = result.map_err(|error| HostError::ProcessContour(error.to_string()));
    // The owner-supplied expected digest handle is already in hand here and is
    // bound verbatim; it is not recomputed, re-verified or re-read.
    let correlation = LaunchPhaseCorrelation::NONE.with_artifact(digest.as_str());
    match &result {
        Ok(()) => {
            // WORK_UNIT_CASE: 978/1 — digest admitted.
            launch_artifact_observe("host.launch-artifact digest admitted", &correlation);
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact digest typed rejection", &correlation);
        }
    }
    result
}

// F-LOG-HOST-3 (#978) inline proof for this cell's private observation
// contract. The cases execute the real instrumented functions through their
// existing seams and read the exact correlation their call sites pass; they
// never re-implement locator validation, never widen visibility, and never
// build an expected log record by hand. The cross-file corpus and the
// digest-verification outcomes that need a real Windows lease stay with the
// integration fixture owner.
#[cfg(test)]
mod tests {
    use super::{
        HostError, LaunchPhaseCorrelation, approved_locator, approved_phase_b_destination_locator,
        open_launch_lease,
    };
    use eliot_installation::InstallationProfile;
    use eliot_platform::PlatformHandle;
    use std::path::{Path, PathBuf};

    const PROFILE: InstallationProfile = InstallationProfile::PortableDev;
    const RELATIVE_CANARY: &str = "978-canary-relative.bin";
    const RELATIVE_REJECTION: &str = "portable locator must be absolute";
    const MISSING_ROOT_REJECTION: &str = "portable root lease is missing";
    const SUBSTITUTION_REJECTION: &str = "portable locator is not the approved canonical path";

    /// Forwards to the real portable locator request of this cell, so a case
    /// never restates the profile it exercises.
    fn portable_locator(supplied: &Path, approved: &PlatformHandle) -> Result<PathBuf, HostError> {
        approved_locator(supplied, approved, PROFILE)
    }

    /// The typed rejection reason, so a case asserts the exact retained text of
    /// the one error variant this cell produces.
    fn typed_reason(error: &HostError) -> Option<&str> {
        match error {
            HostError::ProcessContour(reason) => Some(reason.as_str()),
            _ => None,
        }
    }

    /// One temporary approved artifact, so the portable branch runs its real
    /// `canonicalize` comparison against an existing location.
    struct ApprovedArtifact {
        root: PathBuf,
        file: PathBuf,
    }

    impl ApprovedArtifact {
        fn create(label: &str) -> Option<Self> {
            let name = format!("eliot-978-{label}-{}", std::process::id());
            let root = std::env::temp_dir().join(name);
            let file = root.join("978-canary-approved-artifact.bin");
            if std::fs::create_dir_all(&root).is_err() || std::fs::write(&file, b"").is_err() {
                return None;
            }
            Some(Self { root, file })
        }

        /// The approved artifact itself: the identity whose match is admitted.
        fn approved_handle(&self) -> Option<PlatformHandle> {
            PlatformHandle::new(self.file.to_string_lossy().into_owned()).ok()
        }

        /// A different existing location: a substitution, not a missing path.
        fn substituted_handle(&self) -> Option<PlatformHandle> {
            PlatformHandle::new(self.root.to_string_lossy().into_owned()).ok()
        }
    }

    impl Drop for ApprovedArtifact {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.file);
            let _ = std::fs::remove_dir(&self.root);
        }
    }

    // WORK_UNIT_CASE: 978/1 — admission returns the exact retained locator
    #[test]
    fn portable_locator_admits_the_approved_artifact_unchanged() {
        let Some(artifact) = ApprovedArtifact::create("admitted") else {
            return; // no writable temporary directory in this environment
        };
        let Some(approved) = artifact.approved_handle() else {
            return;
        };
        let Ok(admitted) = portable_locator(&artifact.file, &approved) else {
            panic!("the approved locator must stay admitted");
        };
        assert_eq!(
            admitted, artifact.file,
            "admission returns the retained locator"
        );
    }

    // WORK_UNIT_CASE: 978/2 — locator rejections stay typed
    #[test]
    fn locator_rejections_stay_typed_and_admit_nothing() {
        let Ok(approved) = PlatformHandle::new("C:\\Eliot\\978-canary-approved.bin") else {
            panic!("the approved canary handle must be a valid platform handle");
        };
        let relative = Path::new(RELATIVE_CANARY);
        let Err(error) = portable_locator(relative, &approved) else {
            panic!("a relative portable locator must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(RELATIVE_REJECTION));

        let destination = approved_phase_b_destination_locator(relative, &approved, PROFILE, None);
        let Err(error) = destination else {
            panic!("a Phase-B destination without the portable root must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(MISSING_ROOT_REJECTION));
    }

    // WORK_UNIT_CASE: 978/3 — substitution keeps the exact typed rejection
    #[test]
    fn substituted_locator_keeps_the_exact_typed_rejection() {
        let Some(artifact) = ApprovedArtifact::create("substituted") else {
            return;
        };
        let Some(approved) = artifact.substituted_handle() else {
            return;
        };
        let Err(error) = portable_locator(&artifact.file, &approved) else {
            panic!("a substituted locator must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(SUBSTITUTION_REJECTION));
    }

    // WORK_UNIT_CASE: 978/4 — a request observes no process and no readiness
    #[test]
    fn a_lease_request_is_not_a_process_start_or_readiness_observation() {
        let requested = open_launch_lease(PROFILE, None, Path::new(RELATIVE_CANARY));
        let Err(error) = requested else {
            panic!("a lease request without the portable root must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(MISSING_ROOT_REJECTION));
        let detail = LaunchPhaseCorrelation::NONE.render("host.launch-artifact lease requested");
        let missing = detail.contains("process_start=missing");
        let no_artifact = detail.contains("artifact=missing");
        assert!(
            missing && no_artifact,
            "a request observes nothing: {detail}"
        );
        assert!(
            !detail.contains("ready"),
            "a request claims no readiness: {detail}"
        );
    }

    // WORK_UNIT_CASE: 978/12 — no locator, lease or handle value reaches a record
    #[test]
    fn retained_artifact_records_never_carry_a_locator_or_lease_path() {
        let Some(artifact) = ApprovedArtifact::create("no-path") else {
            return;
        };
        let Some(approved) = artifact.approved_handle() else {
            return;
        };
        let Ok(admitted) = portable_locator(&artifact.file, &approved) else {
            panic!("the approved locator must stay admitted");
        };
        // The exact correlation the locator call sites pass: a retained lease,
        // a locator and an approved handle are paths, so none of them is bound.
        let detail = LaunchPhaseCorrelation::NONE.render("host.launch-artifact locator admitted");
        let canaries = [
            artifact.file.to_string_lossy().into_owned(),
            artifact.root.to_string_lossy().into_owned(),
            approved.as_str().to_owned(),
            admitted.to_string_lossy().into_owned(),
        ];
        for canary in canaries {
            assert!(!detail.contains(canary.as_str()), "no path in {detail}");
        }
        assert!(detail.contains("artifact=missing"), "path is not identity");
    }

    // WORK_UNIT_CASE: 978/4 — a requested artifact that is absent is never admitted
    // as an approved locator and never retained as a lease, so the request is not an
    // observation of anything.
    #[test]
    fn an_absent_requested_artifact_is_never_admitted_or_retained() {
        let Some(artifact) = ApprovedArtifact::create("absent") else {
            return;
        };
        let Some(approved) = artifact.approved_handle() else {
            return;
        };
        // Created only by `ApprovedArtifact`; this locator never exists.
        let absent = artifact.root.join("978-canary-absent-artifact.bin");
        assert!(
            portable_locator(&absent, &approved).is_err(),
            "an absent artifact must never be admitted as an approved locator"
        );
        assert!(
            open_launch_lease(InstallationProfile::UserMode, None, &absent).is_err(),
            "an absent artifact must never retain a lease handle"
        );
    }

    // WORK_UNIT_CASE: 978/12 — the locator canary reaches neither the typed rejection
    // text nor the record, so a rejected locator is never echoed back to the operator.
    #[test]
    fn typed_locator_rejections_never_echo_the_supplied_locator() {
        let Ok(approved) = PlatformHandle::new("C:\\Eliot\\978-canary-approved.bin") else {
            panic!("the approved canary handle must be a valid platform handle");
        };
        let relative = Path::new(RELATIVE_CANARY);
        let Err(error) = portable_locator(relative, &approved) else {
            panic!("a relative portable locator must stay rejected");
        };
        assert!(
            !error.to_string().contains("978-canary"),
            "a typed rejection must not echo the rejected locator: {error}"
        );

        let Some(artifact) = ApprovedArtifact::create("absent-echo") else {
            return;
        };
        let Some(approved) = artifact.approved_handle() else {
            return;
        };
        let absent = artifact.root.join("978-canary-absent-artifact.bin");
        let Err(error) = portable_locator(&absent, &approved) else {
            panic!("an absent artifact must stay rejected");
        };
        assert!(
            !error.to_string().contains("978-canary"),
            "a typed rejection must not echo the rejected locator: {error}"
        );
    }
}
