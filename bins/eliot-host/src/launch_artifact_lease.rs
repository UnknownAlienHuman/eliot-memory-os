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
    if profile != InstallationProfile::PortableDev {
        return verify_approved_path(supplied, approved, "runtime.approved_locator")
            .map_err(|error| HostError::ProcessContour(error.to_string()));
    }
    if !supplied.is_absolute() {
        return Err(HostError::ProcessContour(
            "portable locator must be absolute".to_owned(),
        ));
    }
    let canonical_supplied = std::fs::canonicalize(supplied)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let canonical_approved = std::fs::canonicalize(Path::new(approved.as_str()))
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if canonical_supplied != canonical_approved {
        return Err(HostError::ProcessContour(
            "portable locator is not the approved canonical path".to_owned(),
        ));
    }
    // The retained portable root lease and every child path must stay in the
    // same declared DOS-path namespace. `std::fs::canonicalize` adds a
    // verbatim prefix on Windows, which would make the exact root-containment
    // proof reject an otherwise identical approved child.
    Ok(supplied.to_path_buf())
}

pub(crate) fn approved_phase_b_destination_locator(
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PathBuf, HostError> {
    if profile != InstallationProfile::PortableDev {
        return approved_locator(supplied, approved, profile);
    }
    let root = portable_root
        .ok_or_else(|| HostError::ProcessContour("portable root lease is missing".to_owned()))?;
    if !supplied.is_absolute() {
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator must be absolute".to_owned(),
        ));
    }
    let approved_path = Path::new(approved.as_str());
    if !approved_path.is_absolute() || !windows_paths_equal(supplied, approved_path) {
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator is not the approved path".to_owned(),
        ));
    }
    match std::fs::symlink_metadata(supplied) {
        Ok(_) => approved_locator(supplied, approved, profile),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            root.validate_child_parent(supplied)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            Ok(supplied.to_path_buf())
        }
        Err(error) => Err(HostError::RecoveryRequired(format!(
            "Phase-B destination cannot be observed: {error}"
        ))),
    }
}

pub(crate) fn open_launch_lease(
    profile: InstallationProfile,
    root: Option<&UserOwnedRootLease>,
    path: &Path,
) -> Result<LaunchLease, HostError> {
    match profile {
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
    }
}

pub(crate) fn verify_launch_digest(
    lease: &LaunchLease,
    digest: &PlatformHandle,
    field: &str,
) -> Result<(), HostError> {
    let result = match lease {
        LaunchLease::Protected(lease) => verify_file_digest_with_lease(lease, digest, field),
        LaunchLease::Portable(lease) => verify_file_digest_with_user_lease(lease, digest, field),
    };
    result.map_err(|error| HostError::ProcessContour(error.to_string()))
}
