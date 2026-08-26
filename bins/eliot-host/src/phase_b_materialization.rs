use std::{
    io,
    path::{Path, PathBuf},
};

use eliot_installation::InstallationProfile;
use eliot_platform::{PlatformHandle, WorkScopePath};
use eliot_platform_windows::{
    FileIdentity, PublicationOutcome, UserOwnedRootLease, WindowsPlatform,
};
use sha2::{Digest as _, Sha256};

use super::{HostError, LaunchLease, open_launch_lease, phase_b_open_existing};

#[cfg(windows)]
pub(super) fn phase_b_lease_identity(lease: &LaunchLease) -> FileIdentity {
    match lease {
        LaunchLease::Protected(lease) => lease.identity(),
        LaunchLease::Portable(lease) => lease.identity(),
    }
}

#[cfg(windows)]
pub(super) fn phase_b_lease_bytes(lease: &LaunchLease) -> Result<Vec<u8>, HostError> {
    lease
        .read_bounded(1024 * 1024)
        .map_err(|error| HostError::RecoveryRequired(format!("read Phase-B file: {error}")))
}

#[cfg(windows)]
pub(super) fn phase_b_bytes_digest(bytes: &[u8]) -> Result<PlatformHandle, HostError> {
    PlatformHandle::new(format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(windows)]
pub(super) fn phase_b_materialize_file(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    allowed_existing_digests: &[&PlatformHandle],
    label: &str,
) -> Result<(PlatformHandle, FileIdentity), HostError> {
    phase_b_materialize_file_inner(
        profile,
        portable_root,
        path,
        desired,
        allowed_existing_digests,
        label,
        false,
    )
}

#[cfg(windows)]
pub(super) fn phase_b_materialize_file_with_rollback(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    allowed_existing_digests: &[&PlatformHandle],
    label: &str,
) -> Result<(PlatformHandle, FileIdentity), HostError> {
    phase_b_materialize_file_inner(
        profile,
        portable_root,
        path,
        desired,
        allowed_existing_digests,
        label,
        true,
    )
}

#[cfg(windows)]
fn phase_b_materialize_file_inner(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    allowed_existing_digests: &[&PlatformHandle],
    label: &str,
    retain_previous: bool,
) -> Result<(PlatformHandle, FileIdentity), HostError> {
    let desired_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(desired)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let mut previous_bytes = None;
    if let Ok(lease) = open_launch_lease(profile, portable_root, path) {
        lease.verify().map_err(HostError::RecoveryRequired)?;
        let current = phase_b_lease_bytes(&lease)?;
        let current_digest = format!("{:x}", Sha256::digest(&current));
        if current == desired {
            return Ok((desired_digest, phase_b_lease_identity(&lease)));
        }
        if !allowed_existing_digests
            .iter()
            .any(|digest| digest.as_str() == current_digest)
        {
            return Err(HostError::RecoveryRequired(format!(
                "Phase-B {label} destination is neither the immutable template nor the exact live bytes"
            )));
        }
        if retain_previous {
            previous_bytes = Some(current);
        }
    } else if std::fs::symlink_metadata(path).is_ok() {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} destination exists but cannot be retained"
        )));
    }

    let parent = path.parent().ok_or_else(|| {
        HostError::RecoveryRequired(format!("Phase-B {label} destination has no parent"))
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!("Phase-B {label} destination name is invalid"))
        })?;
    let adapter = WindowsPlatform::new(parent).map_err(|error| {
        HostError::RecoveryRequired(format!("prepare Phase-B {label}: {error}"))
    })?;
    let relative = WorkScopePath::new(file_name)
        .map_err(|error| HostError::RecoveryRequired(format!("Phase-B {label} path: {error}")))?;
    if let Some(previous) = previous_bytes.as_deref() {
        phase_b_write_rollback_backup(profile, portable_root, path, previous, label)?;
    }
    match adapter
        .publish_atomic(&relative, desired)
        .map_err(|error| HostError::RecoveryRequired(format!("publish Phase-B {label}: {error}")))?
    {
        PublicationOutcome::Published(receipt) => {
            if receipt.identity.file_index == 0 || receipt.identity.volume_serial_number == 0 {
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} publication receipt has no retained OS identity"
                )));
            }
        }
        PublicationOutcome::Unknown(_) => {
            // The replacement may already have committed. Reconcile the exact
            // destination once; never resend bytes after an unknown outcome.
            let lease = phase_b_open_existing(profile, portable_root, path)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            if phase_b_lease_bytes(&lease)? != desired {
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} publication outcome is unknown and readback is not exact"
                )));
            }
        }
    }
    let lease = phase_b_open_existing(profile, portable_root, path)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    if phase_b_lease_bytes(&lease)? != desired {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} publication readback is not exact"
        )));
    }
    Ok((desired_digest, phase_b_lease_identity(&lease)))
}

#[cfg(windows)]
fn phase_b_rollback_path(destination: &Path, label: &str) -> Result<PathBuf, HostError> {
    let parent = destination.parent().ok_or_else(|| {
        HostError::RecoveryRequired(format!(
            "Phase-B {label} rollback destination has no parent"
        ))
    })?;
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!(
                "Phase-B {label} rollback destination name is invalid"
            ))
        })?;
    let retained_name = format!("{file_name}.phase-b-rollback");
    WorkScopePath::new(&retained_name).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "Phase-B {label} rollback path is not within the protected scope: {error}"
        ))
    })?;
    Ok(parent.join(retained_name))
}

#[cfg(windows)]
fn phase_b_write_rollback_backup(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    previous: &[u8],
    label: &str,
) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label)?;
    let parent = backup.parent().ok_or_else(|| {
        HostError::RecoveryRequired(format!("Phase-B {label} rollback path has no parent"))
    })?;
    let file_name = backup
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!("Phase-B {label} rollback path name is invalid"))
        })?;
    let adapter = WindowsPlatform::new(parent).map_err(|error| {
        HostError::RecoveryRequired(format!("prepare Phase-B {label} rollback backup: {error}"))
    })?;
    let relative = WorkScopePath::new(file_name).map_err(|error| {
        HostError::RecoveryRequired(format!("Phase-B {label} rollback backup path: {error}"))
    })?;
    match adapter
        .publish_atomic(&relative, previous)
        .map_err(|error| {
            HostError::RecoveryRequired(format!("publish Phase-B {label} rollback backup: {error}"))
        })? {
        PublicationOutcome::Published(_) => {}
        PublicationOutcome::Unknown(_) => {
            let lease = phase_b_open_existing(profile, portable_root, &backup)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            if phase_b_lease_bytes(&lease)? != previous {
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} rollback backup outcome is unknown"
                )));
            }
        }
    }
    let lease = phase_b_open_existing(profile, portable_root, &backup)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    if phase_b_lease_bytes(&lease)? != previous {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} rollback backup readback is not exact"
        )));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_restore_or_remove(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    label: &str,
    preserve_template_digest: Option<&PlatformHandle>,
) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label)?;
    if std::fs::symlink_metadata(&backup).is_ok() {
        let backup_lease = phase_b_open_existing(profile, portable_root, &backup)?;
        backup_lease.verify().map_err(HostError::RecoveryRequired)?;
        let bytes = phase_b_lease_bytes(&backup_lease)?;
        let backup_digest = phase_b_bytes_digest(&bytes)?;
        let current_digest = match phase_b_open_existing(profile, portable_root, destination) {
            Ok(lease) => {
                lease.verify().map_err(HostError::RecoveryRequired)?;
                Some(phase_b_bytes_digest(&phase_b_lease_bytes(&lease)?)?)
            }
            Err(HostError::RecoveryRequired(reason)) if reason.contains("missing") => None,
            Err(error) => return Err(error),
        };
        if current_digest.as_ref() != Some(&backup_digest) {
            let allowed = current_digest.as_ref().map_or_else(
                || vec![&backup_digest],
                |current| vec![&backup_digest, current],
            );
            phase_b_materialize_file(
                profile,
                portable_root,
                destination,
                &bytes,
                &allowed,
                &format!("{label} rollback restore"),
            )?;
        }
    } else if std::fs::symlink_metadata(destination).is_ok() {
        let lease = phase_b_open_existing(profile, portable_root, destination)?;
        lease.verify().map_err(HostError::RecoveryRequired)?;
        let current = phase_b_lease_bytes(&lease)?;
        let current_digest = phase_b_bytes_digest(&current)?;
        if preserve_template_digest.is_none_or(|expected| expected != &current_digest) {
            std::fs::remove_file(destination).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "remove uncommitted Phase-B {label} destination: {error}"
                ))
            })?;
            if std::fs::symlink_metadata(destination).is_ok() {
                return Err(HostError::RecoveryRequired(format!(
                    "uncommitted Phase-B {label} destination remains after rollback"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_remove_rollback_backup(
    destination: &Path,
    label: &str,
) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label)?;
    if std::fs::symlink_metadata(&backup).is_ok() {
        std::fs::remove_file(&backup).map_err(|error| {
            HostError::RecoveryRequired(format!("remove Phase-B {label} rollback backup: {error}"))
        })?;
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_template_path(destination: &Path, label: &str) -> Result<PathBuf, HostError> {
    let parent = destination.parent().ok_or_else(|| {
        HostError::RecoveryRequired(format!(
            "Phase-B {label} template destination has no parent"
        ))
    })?;
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!(
                "Phase-B {label} template destination name is invalid"
            ))
        })?;
    let retained_name = format!("{file_name}.phase-a-template");
    WorkScopePath::new(&retained_name).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "Phase-B {label} template path is not within the protected scope: {error}"
        ))
    })?;
    Ok(parent.join(retained_name))
}

#[cfg(windows)]
pub(super) fn phase_b_template_bytes(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    expected_digest: &PlatformHandle,
    label: &str,
) -> Result<Vec<u8>, HostError> {
    // Phase A's destination is an immutable approved template until Host
    // first publishes the live overlay. Retain the exact bytes in a Host
    // scoped sidecar before that replacement so a fresh Host epoch can
    // validate a later replay without reconstructing authority from JSON.
    let retained_path = phase_b_template_path(destination, label)?;
    let (source_bytes, retained_exists) = match std::fs::symlink_metadata(&retained_path) {
        Ok(_) => {
            let lease = phase_b_open_existing(profile, portable_root, &retained_path)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            (phase_b_lease_bytes(&lease)?, true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let lease = phase_b_open_existing(profile, portable_root, destination)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            (phase_b_lease_bytes(&lease)?, false)
        }
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Phase-B {label} template cannot be observed: {error}"
            )));
        }
    };
    let source_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&source_bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if source_digest != *expected_digest {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} template digest is not the immutable Phase-A digest"
        )));
    }
    if !retained_exists {
        let retained_label = format!("{label} immutable template");
        phase_b_materialize_file(
            profile,
            portable_root,
            &retained_path,
            &source_bytes,
            &[expected_digest],
            &retained_label,
        )?;
    }
    let lease = phase_b_open_existing(profile, portable_root, &retained_path)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    let retained_bytes = phase_b_lease_bytes(&lease)?;
    if retained_bytes != source_bytes {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} retained template readback is not exact"
        )));
    }
    Ok(retained_bytes)
}
