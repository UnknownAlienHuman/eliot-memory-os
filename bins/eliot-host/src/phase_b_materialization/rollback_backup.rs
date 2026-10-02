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

// F-LOG-HOST-5 (#980) inner-phase observations for rollback backups.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract (mirrors `host_composition_phase_b.rs:30-41`):
// every call projects a boundary already decided by the semantic owner.
// Labels are frozen literals behind the closed `RollbackContour` vocabulary —
// no digests, bytes, paths, caller labels, or error text are formatted, so
// no secret material can cross (I15.4) and no extra evaluation runs on the
// semantic path. The only rendered value is the installation profile the
// owner already holds, as a 1:1 typed label; a contour that holds none
// renders the explicit `unavailable` missing-evidence disposition rather than
// a placeholder. Length stays inside the facade's detail bound. Sink outcome
// never alters result, order, or cleanup. No terminal emission here: one
// terminal per failed operation stays with the outermost contour, while these
// inner phases are typed so they correlate by operation identity, not by
// stage order. A positive claim (`restored verified`, `removal verified`,
// `cleanup completed`) is emitted only after the existing exact readback or
// post-delete absence proof succeeds, so an unknown or failed outcome is never
// logged as restored.
//
// F-LOG-HOST-5 (#980, audit comment 5909832545 blocking defect 4): the
// contour vocabulary covers the complete rollback state map — backup prepared,
// restore requested, restore verified, uncommitted destination removal
// requested, removal verified, sidecar cleanup requested/completed, and an
// explicit failure/unknown disposition per failure branch. Both
// rollback-by-restoration and rollback-by-removal of an uncommitted
// destination are covered, and `phase_b_remove_rollback_backup` is no longer
// silent.
fn rollback_backup_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

/// Closed rollback state/failure vocabulary of this leaf (F-LOG-HOST-5 #980).
///
/// One variant per rollback boundary the semantic owner has already decided.
/// `label` is a 1:1 frozen-literal map: diagnostics project owner vocabulary
/// without formatting internals, never `Debug` and never owner error text, so
/// a label cannot drift from the decision it names.
#[derive(Clone, Copy)]
enum RollbackContour {
    // Rollback sidecar preparation (`phase_b_write_rollback_backup`).
    BackupRequested,
    BackupPathFailed,
    BackupPrepareFailed,
    BackupPublishFailed,
    BackupOpenFailed,
    BackupVerifyFailed,
    BackupReadFailed,
    BackupUnknownRetained,
    BackupPrepared,
    // Rollback by restoration of the retained sidecar bytes.
    RestoreRequested,
    RestoreBackupOpenFailed,
    RestoreBackupVerifyFailed,
    RestoreBackupReadFailed,
    RestoreDestinationOpenFailed,
    RestoreDestinationVerifyFailed,
    RestoreDestinationReadFailed,
    RestoreMaterializeFailed,
    RestoredVerified,
    // Rollback by removal of an uncommitted destination (no sidecar).
    RemovalDestinationOpenFailed,
    RemovalDestinationVerifyFailed,
    RemovalDestinationReadFailed,
    UncommittedRemovalNotRequired,
    UncommittedRemovalRequested,
    UncommittedRemovalDeleteFailed,
    UncommittedRemovalAbsenceUnproven,
    UncommittedRemovalVerified,
    // Rollback sidecar cleanup (`phase_b_remove_rollback_backup`).
    CleanupPathFailed,
    CleanupRequested,
    CleanupDeleteFailed,
    CleanupCompleted,
}

impl RollbackContour {
    /// The one frozen label of this contour. Never formats a value.
    const fn label(self) -> &'static str {
        match self {
            Self::BackupRequested => "host.phase-b rollback backup requested",
            Self::BackupPathFailed => "host.phase-b rollback backup path failed",
            Self::BackupPrepareFailed => "host.phase-b rollback backup prepare failed",
            Self::BackupPublishFailed => "host.phase-b rollback backup publish failed",
            Self::BackupOpenFailed => "host.phase-b rollback backup open failed",
            Self::BackupVerifyFailed => "host.phase-b rollback backup verify failed",
            Self::BackupReadFailed => "host.phase-b rollback backup read failed",
            Self::BackupUnknownRetained => "host.phase-b rollback backup unknown retained",
            Self::BackupPrepared => "host.phase-b rollback backup prepared",
            Self::RestoreRequested => "host.phase-b rollback restore requested",
            Self::RestoreBackupOpenFailed => "host.phase-b rollback restore backup open failed",
            Self::RestoreBackupVerifyFailed => "host.phase-b rollback restore backup verify failed",
            Self::RestoreBackupReadFailed => "host.phase-b rollback restore backup read failed",
            Self::RestoreDestinationOpenFailed => {
                "host.phase-b rollback restore destination open failed"
            }
            Self::RestoreDestinationVerifyFailed => {
                "host.phase-b rollback restore destination verify failed"
            }
            Self::RestoreDestinationReadFailed => {
                "host.phase-b rollback restore destination read failed"
            }
            Self::RestoreMaterializeFailed => "host.phase-b rollback restore materialize failed",
            Self::RestoredVerified => "host.phase-b rollback restored verified",
            Self::RemovalDestinationOpenFailed => {
                "host.phase-b rollback removal destination open failed"
            }
            Self::RemovalDestinationVerifyFailed => {
                "host.phase-b rollback removal destination verify failed"
            }
            Self::RemovalDestinationReadFailed => {
                "host.phase-b rollback removal destination read failed"
            }
            Self::UncommittedRemovalNotRequired => {
                "host.phase-b rollback uncommitted removal not required"
            }
            Self::UncommittedRemovalRequested => {
                "host.phase-b rollback uncommitted removal requested"
            }
            Self::UncommittedRemovalDeleteFailed => {
                "host.phase-b rollback uncommitted removal delete failed"
            }
            Self::UncommittedRemovalAbsenceUnproven => {
                "host.phase-b rollback uncommitted removal absence unproven"
            }
            Self::UncommittedRemovalVerified => {
                "host.phase-b rollback uncommitted removal verified"
            }
            Self::CleanupPathFailed => "host.phase-b rollback backup cleanup path failed",
            Self::CleanupRequested => "host.phase-b rollback backup cleanup requested",
            Self::CleanupDeleteFailed => "host.phase-b rollback backup cleanup delete failed",
            Self::CleanupCompleted => "host.phase-b rollback backup cleanup completed",
        }
    }
}

/// Frozen missing-evidence disposition for an identity slot this leaf's owner
/// does not hold (F-LOG-HOST-5 #980). Never a fabricated identity.
const ROLLBACK_IDENTITY_UNAVAILABLE: &str = "unavailable";

/// 1:1 projection of the installation profile the caller already selected.
/// `None` renders the explicit `unavailable` disposition, as for the sidecar
/// cleanup contour, which owns no profile.
const fn rollback_profile_label(profile: Option<&InstallationProfile>) -> &'static str {
    match profile {
        Some(InstallationProfile::SystemService) => "system_service",
        Some(InstallationProfile::UserMode) => "user_mode",
        Some(InstallationProfile::PortableDev) => "portable_dev",
        None => ROLLBACK_IDENTITY_UNAVAILABLE,
    }
}

/// Emits one typed rollback contour through the existing #889 facade.
///
/// The frozen label stays first so label-prefix consumers keep matching; the
/// owner-held installation profile follows as one bounded `k=v` pair.
fn rollback_backup_observe(contour: RollbackContour, profile: Option<&InstallationProfile>) {
    rollback_backup_note_event_log_unavailable();
    let mut detail = String::from(contour.label());
    detail.push_str(" profile=");
    detail.push_str(rollback_profile_label(profile));
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        &detail,
    );
}

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
    rollback_backup_observe(RollbackContour::BackupRequested, Some(&profile));
    let backup = phase_b_rollback_path(destination, label).inspect_err(|_| {
        rollback_backup_observe(RollbackContour::BackupPathFailed, Some(&profile));
    })?;
    let parent = backup.parent().ok_or_else(|| {
        rollback_backup_observe(RollbackContour::BackupPathFailed, Some(&profile));
        HostError::RecoveryRequired(format!("Phase-B {label} rollback path has no parent"))
    })?;
    let file_name = backup
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            rollback_backup_observe(RollbackContour::BackupPathFailed, Some(&profile));
            HostError::RecoveryRequired(format!("Phase-B {label} rollback path name is invalid"))
        })?;
    let adapter = WindowsPlatform::new(parent).map_err(|error| {
        rollback_backup_observe(RollbackContour::BackupPrepareFailed, Some(&profile));
        HostError::RecoveryRequired(format!("prepare Phase-B {label} rollback backup: {error}"))
    })?;
    let relative = WorkScopePath::new(file_name).map_err(|error| {
        rollback_backup_observe(RollbackContour::BackupPathFailed, Some(&profile));
        HostError::RecoveryRequired(format!("Phase-B {label} rollback backup path: {error}"))
    })?;
    match adapter
        .publish_atomic(&relative, previous)
        .map_err(|error| {
            rollback_backup_observe(RollbackContour::BackupPublishFailed, Some(&profile));
            HostError::RecoveryRequired(format!("publish Phase-B {label} rollback backup: {error}"))
        })? {
        PublicationOutcome::Published(_) => {}
        PublicationOutcome::Unknown(_) => {
            let lease = phase_b_open_existing(profile, portable_root, &backup).inspect_err(|_| {
                rollback_backup_observe(RollbackContour::BackupOpenFailed, Some(&profile));
            })?;
            lease.verify().map_err(|error| {
                rollback_backup_observe(RollbackContour::BackupVerifyFailed, Some(&profile));
                HostError::RecoveryRequired(error)
            })?;
            let bytes = phase_b_lease_bytes(&lease).inspect_err(|_| {
                rollback_backup_observe(RollbackContour::BackupReadFailed, Some(&profile));
            })?;
            if bytes != previous {
                rollback_backup_observe(RollbackContour::BackupUnknownRetained, Some(&profile));
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} rollback backup outcome is unknown"
                )));
            }
        }
    }
    let lease = phase_b_open_existing(profile, portable_root, &backup).inspect_err(|_| {
        rollback_backup_observe(RollbackContour::BackupOpenFailed, Some(&profile));
    })?;
    lease.verify().map_err(|error| {
        rollback_backup_observe(RollbackContour::BackupVerifyFailed, Some(&profile));
        HostError::RecoveryRequired(error)
    })?;
    let bytes = phase_b_lease_bytes(&lease).inspect_err(|_| {
        rollback_backup_observe(RollbackContour::BackupReadFailed, Some(&profile));
    })?;
    if bytes != previous {
        rollback_backup_observe(RollbackContour::BackupUnknownRetained, Some(&profile));
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} rollback backup readback is not exact"
        )));
    }
    rollback_backup_observe(RollbackContour::BackupPrepared, Some(&profile));
    Ok(())
}

pub fn phase_b_restore_or_remove(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    label: &str,
    preserve_template_digest: Option<&PlatformHandle>,
) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label).inspect_err(|_| {
        rollback_backup_observe(RollbackContour::BackupPathFailed, Some(&profile));
    })?;
    if std::fs::symlink_metadata(&backup).is_ok() {
        rollback_backup_observe(RollbackContour::RestoreRequested, Some(&profile));
        let backup_lease = phase_b_open_existing(profile, portable_root, &backup).inspect_err(|_| {
            rollback_backup_observe(RollbackContour::RestoreBackupOpenFailed, Some(&profile));
        })?;
        backup_lease.verify().map_err(|error| {
            rollback_backup_observe(RollbackContour::RestoreBackupVerifyFailed, Some(&profile));
            HostError::RecoveryRequired(error)
        })?;
        let bytes = phase_b_lease_bytes(&backup_lease).inspect_err(|_| {
            rollback_backup_observe(RollbackContour::RestoreBackupReadFailed, Some(&profile));
        })?;
        let backup_digest = phase_b_bytes_digest(&bytes).inspect_err(|_| {
            rollback_backup_observe(RollbackContour::RestoreBackupReadFailed, Some(&profile));
        })?;
        let current_digest = match phase_b_open_existing(profile, portable_root, destination) {
            Ok(lease) => {
                lease.verify().map_err(|error| {
                    rollback_backup_observe(
                        RollbackContour::RestoreDestinationVerifyFailed,
                        Some(&profile),
                    );
                    HostError::RecoveryRequired(error)
                })?;
                let current = phase_b_lease_bytes(&lease).inspect_err(|_| {
                    rollback_backup_observe(
                        RollbackContour::RestoreDestinationReadFailed,
                        Some(&profile),
                    );
                })?;
                Some(phase_b_bytes_digest(&current).inspect_err(|_| {
                    rollback_backup_observe(
                        RollbackContour::RestoreDestinationReadFailed,
                        Some(&profile),
                    );
                })?)
            }
            Err(HostError::RecoveryRequired(reason)) if reason.contains("missing") => None,
            Err(error) => {
                rollback_backup_observe(
                    RollbackContour::RestoreDestinationOpenFailed,
                    Some(&profile),
                );
                return Err(error);
            }
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
            )
            .inspect_err(|_| {
                rollback_backup_observe(RollbackContour::RestoreMaterializeFailed, Some(&profile));
            })?;
        }
        // Only reached after the retained bytes were proven or restored; an
        // unknown or failed outcome returned above and is never labelled here.
        rollback_backup_observe(RollbackContour::RestoredVerified, Some(&profile));
    } else if std::fs::symlink_metadata(destination).is_ok() {
        // No rollback sidecar exists: the uncommitted destination itself is
        // the rollback effect, so this contour observes the removal request,
        // the post-delete absence proof, and every failure disposition.
        remove_uncommitted_destination(
            profile,
            portable_root,
            destination,
            label,
            preserve_template_digest,
        )?;
    }
    Ok(())
}

/// Rollback by removal of an uncommitted destination that has no sidecar.
///
/// Pure extraction of the removal contour of `phase_b_restore_or_remove`: the
/// same open, verify, read, compare, delete, and absence-proof steps run in the
/// same order, with the same contours emitted on the same branches and the same
/// `Result` returned.
fn remove_uncommitted_destination(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    label: &str,
    preserve_template_digest: Option<&PlatformHandle>,
) -> Result<(), HostError> {
    let lease = phase_b_open_existing(profile, portable_root, destination).inspect_err(|_| {
        rollback_backup_observe(
            RollbackContour::RemovalDestinationOpenFailed,
            Some(&profile),
        );
    })?;
    lease.verify().map_err(|error| {
        rollback_backup_observe(
            RollbackContour::RemovalDestinationVerifyFailed,
            Some(&profile),
        );
        HostError::RecoveryRequired(error)
    })?;
    let current = phase_b_lease_bytes(&lease).inspect_err(|_| {
        rollback_backup_observe(
            RollbackContour::RemovalDestinationReadFailed,
            Some(&profile),
        );
    })?;
    let current_digest = phase_b_bytes_digest(&current).inspect_err(|_| {
        rollback_backup_observe(
            RollbackContour::RemovalDestinationReadFailed,
            Some(&profile),
        );
    })?;
    if preserve_template_digest.is_none_or(|expected| expected != &current_digest) {
        rollback_backup_observe(RollbackContour::UncommittedRemovalRequested, Some(&profile));
        std::fs::remove_file(destination).map_err(|error| {
            rollback_backup_observe(
                RollbackContour::UncommittedRemovalDeleteFailed,
                Some(&profile),
            );
            HostError::RecoveryRequired(format!(
                "remove uncommitted Phase-B {label} destination: {error}"
            ))
        })?;
        if std::fs::symlink_metadata(destination).is_ok() {
            rollback_backup_observe(
                RollbackContour::UncommittedRemovalAbsenceUnproven,
                Some(&profile),
            );
            return Err(HostError::RecoveryRequired(format!(
                "uncommitted Phase-B {label} destination remains after rollback"
            )));
        }
        rollback_backup_observe(RollbackContour::UncommittedRemovalVerified, Some(&profile));
    } else {
        // The destination is exactly the immutable template, so there is
        // no uncommitted material to remove. Recorded explicitly so the
        // silent no-op is distinguishable from an unproven removal.
        rollback_backup_observe(
            RollbackContour::UncommittedRemovalNotRequired,
            Some(&profile),
        );
    }
    Ok(())
}

pub fn phase_b_remove_rollback_backup(destination: &Path, label: &str) -> Result<(), HostError> {
    // This cleanup contour owns no installation profile, so its records render
    // the explicit `unavailable` missing-evidence disposition rather than a
    // fabricated identity.
    let backup = phase_b_rollback_path(destination, label).inspect_err(|_| {
        rollback_backup_observe(RollbackContour::CleanupPathFailed, None);
    })?;
    if std::fs::symlink_metadata(&backup).is_ok() {
        rollback_backup_observe(RollbackContour::CleanupRequested, None);
        std::fs::remove_file(&backup).map_err(|error| {
            rollback_backup_observe(RollbackContour::CleanupDeleteFailed, None);
            HostError::RecoveryRequired(format!("remove Phase-B {label} rollback backup: {error}"))
        })?;
        rollback_backup_observe(RollbackContour::CleanupCompleted, None);
    }
    Ok(())
}
