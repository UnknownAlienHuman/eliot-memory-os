//! Retained launch-artifact leases and approved-path validation.
//!
//! Canonical ELIOT anchors: `ELIOT_ARCHITECTURE.md` `A5.5` scopes verifier
//! inputs and failure applicability, and `A13.2` separates Host, Kernel, and
//! Watchdog failure domains. `ELIOT_IMPLEMENTATION.md` `I1.2` assigns Host
//! approved-artifact ownership without project semantics, `I1.8` defines exact
//! ownership and call paths, `I2.23` requires a bounded extraction closure, and
//! `B.0` limits Host protocol evidence to immutable artifact/config hashes.
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

// F-LOG-HOST-3 (#978) launch-artifact observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never paths,
// digests, fields carrying identity, or arbitrary error text — so bounding
// limits size, not sensitivity (I15.4). Sink outcome never alters
// result/order/count/handle/cleanup/timeout. There is no mutable global dedup
// cache and no terminal emission here: one terminal per failed operation is
// owned by the single outermost contour (`HostJobBranches::start_approved`
// guard owns `host-launch-failed`), while these lease phases correlate by
// stage order only. Retained identity on substitution failure is preserved
// (case 978/3); digest/descriptor rejections stay typed (case 978/2).
fn launch_artifact_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

fn launch_artifact_observe(detail: &str) {
    launch_artifact_note_event_log_unavailable();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
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
    // WORK_UNIT_CASE: 978/1 — locator requested.
    launch_artifact_observe("host.launch-artifact locator requested");
    if profile != InstallationProfile::PortableDev {
        let result =
            verify_approved_path(supplied, approved, "runtime.approved_locator").map_err(|error| {
                // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                launch_artifact_observe("host.launch-artifact substitution preserved");
                HostError::ProcessContour(error.to_string())
            });
        if result.is_ok() {
            // WORK_UNIT_CASE: 978/1 — locator admitted.
            launch_artifact_observe("host.launch-artifact locator admitted");
        }
        return result;
    }
    if !supplied.is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe("host.launch-artifact locator typed rejection");
        return Err(HostError::ProcessContour(
            "portable locator must be absolute".to_owned(),
        ));
    }
    let canonical_supplied = std::fs::canonicalize(supplied).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe("host.launch-artifact locator typed rejection");
        HostError::ProcessContour(error.to_string())
    })?;
    let canonical_approved =
        std::fs::canonicalize(Path::new(approved.as_str())).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact locator typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
    if canonical_supplied != canonical_approved {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_artifact_observe("host.launch-artifact substitution preserved");
        return Err(HostError::ProcessContour(
            "portable locator is not the approved canonical path".to_owned(),
        ));
    }
    // The retained portable root lease and every child path must stay in the
    // same declared DOS-path namespace. `std::fs::canonicalize` adds a
    // verbatim prefix on Windows, which would make the exact root-containment
    // proof reject an otherwise identical approved child.
    // WORK_UNIT_CASE: 978/1 — locator admitted.
    launch_artifact_observe("host.launch-artifact locator admitted");
    Ok(supplied.to_path_buf())
}

pub(crate) fn approved_phase_b_destination_locator(
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PathBuf, HostError> {
    // WORK_UNIT_CASE: 978/1 — phase-b destination requested.
    launch_artifact_observe("host.launch-artifact phase-b destination requested");
    if profile != InstallationProfile::PortableDev {
        let result = approved_locator(supplied, approved, profile);
        if result.is_ok() {
            // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
            launch_artifact_observe("host.launch-artifact phase-b destination admitted");
        }
        return result;
    }
    let root = portable_root.ok_or_else(|| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe("host.launch-artifact phase-b destination typed rejection");
        HostError::ProcessContour("portable root lease is missing".to_owned())
    })?;
    if !supplied.is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe("host.launch-artifact phase-b destination typed rejection");
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator must be absolute".to_owned(),
        ));
    }
    let approved_path = Path::new(approved.as_str());
    if !approved_path.is_absolute() || !windows_paths_equal(supplied, approved_path) {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_artifact_observe("host.launch-artifact phase-b substitution preserved");
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator is not the approved path".to_owned(),
        ));
    }
    match std::fs::symlink_metadata(supplied) {
        Ok(_) => {
            let result = approved_locator(supplied, approved, profile);
            if result.is_ok() {
                // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
                launch_artifact_observe("host.launch-artifact phase-b destination admitted");
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
                    launch_artifact_observe("host.launch-artifact phase-b destination admitted");
                    Ok(supplied.to_path_buf())
                }
                Err(error) => {
                    // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                    launch_artifact_observe("host.launch-artifact phase-b substitution preserved");
                    Err(error)
                }
            }
        }
        Err(error) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact phase-b destination typed rejection");
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
    // WORK_UNIT_CASE: 978/1 — lease requested.
    launch_artifact_observe("host.launch-artifact lease requested");
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
            launch_artifact_observe("host.launch-artifact lease admitted");
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact lease typed rejection");
        }
    }
    result
}

pub(crate) fn verify_launch_digest(
    lease: &LaunchLease,
    digest: &PlatformHandle,
    field: &str,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — digest requested.
    launch_artifact_observe("host.launch-artifact digest requested");
    let result = match lease {
        LaunchLease::Protected(lease) => verify_file_digest_with_lease(lease, digest, field),
        LaunchLease::Portable(lease) => verify_file_digest_with_user_lease(lease, digest, field),
    };
    let result = result.map_err(|error| HostError::ProcessContour(error.to_string()));
    match &result {
        Ok(()) => {
            // WORK_UNIT_CASE: 978/1 — digest admitted.
            launch_artifact_observe("host.launch-artifact digest admitted");
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact digest typed rejection");
        }
    }
    result
}
