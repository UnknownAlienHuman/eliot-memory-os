//! Phase-B rollback backup lifecycle.
//!
//! Architecture anchors: `A13.7` (Backups, restore and migration) requires
//! isolated recovery with integrity checks and an explicit rollback plan;
//! `A2.2` (Host Supervisor) keeps approved rollback outside semantic ownership.
//! Implementation anchors: `I1.2` (`eliot-host.exe`) assigns Host the
//! installation root and recovery/rollback channel; `I1.12` requires rollback
//! compatibility with durable formats; `I14.14` requires exact cutover
//! disposition and retention of rollback artifacts.
//!
//! This child owns only Phase-B rollback sidecar filesystem effects. It does
//! not create, widen, or grant canonical or semantic authority.

use std::path::{Path, PathBuf};

use eliot_installation::InstallationProfile;
use eliot_platform::{PlatformHandle, WorkScopePath};
use eliot_platform_windows::{PublicationOutcome, UserOwnedRootLease, WindowsPlatform};

use super::{
    HostError, phase_b_bytes_digest, phase_b_lease_bytes, phase_b_materialize_file,
    phase_b_open_existing,
};

pub(super) fn phase_b_rollback_path(destination: &Path, label: &str) -> Result<PathBuf, HostError> {
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

pub(super) fn phase_b_write_rollback_backup(
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

pub fn phase_b_restore_or_remove(
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

pub fn phase_b_remove_rollback_backup(destination: &Path, label: &str) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label)?;
    if std::fs::symlink_metadata(&backup).is_ok() {
        std::fs::remove_file(&backup).map_err(|error| {
            HostError::RecoveryRequired(format!("remove Phase-B {label} rollback backup: {error}"))
        })?;
    }
    Ok(())
}
