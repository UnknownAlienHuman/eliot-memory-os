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
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); Event Log
// sink disposition through the canonical
// (`crate::host_diagnostics::note_event_log_sink_status`) over the landed
// `windows_event_log` port, never probed here.
//
// Observation-only contract (mirrors `host_composition_phase_b.rs:30-41`):
// every call projects a boundary already decided by the semantic owner.
// Arguments are static literals only — no digests, bytes, paths, or error
// text are formatted, so no secret material can cross (I15.4) and no extra
// evaluation runs on the semantic path. Sink outcome never alters result,
// order, or cleanup. No terminal emission here: one terminal per failed
// operation stays with the outermost contour, while these inner phases
// correlate by stage order only. An unknown outcome is never logged as
// restored.
fn rollback_backup_observe(detail: &str) {
    crate::host_diagnostics::note_event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        detail,
    );
}

/// Closed observation vocabulary for the removal and cleanup contours.
///
/// Audit 5909832545 defect 4: rollback-by-removal ran with no request,
/// verified, or failure record, and sidecar cleanup observed nothing at
/// all. Every label below is a static literal: no digests, bytes, paths, or
/// error text are formatted. Unknown or failed outcomes are never logged as
/// restored or verified, and a successful removal is never silent.
const ROLLBACK_RESTORE_FAILED: &str = "host.phase-b rollback restore failed retained";
const ROLLBACK_REMOVAL_REQUESTED: &str = "host.phase-b rollback removal requested";
const ROLLBACK_REMOVAL_VERIFIED: &str = "host.phase-b rollback removal verified";
const ROLLBACK_REMOVAL_FAILED: &str = "host.phase-b rollback removal failed retained";
const ROLLBACK_CLEANUP_REQUESTED: &str = "host.phase-b rollback cleanup requested";
const ROLLBACK_CLEANUP_COMPLETED: &str = "host.phase-b rollback cleanup completed";
const ROLLBACK_CLEANUP_FAILED: &str = "host.phase-b rollback cleanup failed retained";

/// Observes one rollback-contour failure and returns the original error
/// unchanged: diagnostics-only, never alters result, order, or cleanup.
fn rollback_observe_failed(detail: &'static str, error: HostError) -> HostError {
    rollback_backup_observe(detail);
    error
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
    rollback_backup_observe("host.phase-b rollback backup requested");
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
                rollback_backup_observe("host.phase-b rollback backup unknown retained");
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} rollback backup outcome is unknown"
                )));
            }
        }
    }
    let lease = phase_b_open_existing(profile, portable_root, &backup)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    if phase_b_lease_bytes(&lease)? != previous {
        rollback_backup_observe("host.phase-b rollback backup unknown retained");
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} rollback backup readback is not exact"
        )));
    }
    rollback_backup_observe("host.phase-b rollback backup prepared");
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
        rollback_backup_observe("host.phase-b rollback restore requested");
        // Audit 5909832545 defect 4: every failure below previously left
        // only the generic outer terminal. The closure keeps the original
        // error value, order, and cleanup; the single failure record stays
        // distinct from any restored claim.
        let outcome = (|| -> Result<(), HostError> {
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
            Ok(())
        })();
        if let Err(error) = outcome {
            rollback_backup_observe(ROLLBACK_RESTORE_FAILED);
            return Err(error);
        }
        rollback_backup_observe("host.phase-b rollback restored verified");
    } else if std::fs::symlink_metadata(destination).is_ok() {
        // Audit 5909832545 defect 4: rollback-by-removal previously ran
        // silent. Read failures are observed as removal failures before any
        // verified claim; the request record fires only once removal of the
        // uncommitted destination is decided, and the verified record only
        // after absence is proven.
        let lease = phase_b_open_existing(profile, portable_root, destination)
            .map_err(|error| rollback_observe_failed(ROLLBACK_REMOVAL_FAILED, error))?;
        lease
            .verify()
            .map_err(|error| {
                rollback_observe_failed(
                    ROLLBACK_REMOVAL_FAILED,
                    HostError::RecoveryRequired(error),
                )
            })?;
        let current = phase_b_lease_bytes(&lease)
            .map_err(|error| rollback_observe_failed(ROLLBACK_REMOVAL_FAILED, error))?;
        let current_digest = phase_b_bytes_digest(&current)
            .map_err(|error| rollback_observe_failed(ROLLBACK_REMOVAL_FAILED, error))?;
        if preserve_template_digest.is_none_or(|expected| expected != &current_digest) {
            rollback_backup_observe(ROLLBACK_REMOVAL_REQUESTED);
            std::fs::remove_file(destination).map_err(|error| {
                rollback_observe_failed(
                    ROLLBACK_REMOVAL_FAILED,
                    HostError::RecoveryRequired(format!(
                        "remove uncommitted Phase-B {label} destination: {error}"
                    )),
                )
            })?;
            if std::fs::symlink_metadata(destination).is_ok() {
                return Err(rollback_observe_failed(
                    ROLLBACK_REMOVAL_FAILED,
                    HostError::RecoveryRequired(format!(
                        "uncommitted Phase-B {label} destination remains after rollback"
                    )),
                ));
            }
            rollback_backup_observe(ROLLBACK_REMOVAL_VERIFIED);
        }
    }
    Ok(())
}

pub fn phase_b_remove_rollback_backup(destination: &Path, label: &str) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label)?;
    // Audit 5909832545 defect 4: cleanup previously observed nothing. The
    // request record fires only when a sidecar exists to remove; completion
    // follows the successful delete, never before.
    if std::fs::symlink_metadata(&backup).is_ok() {
        rollback_backup_observe(ROLLBACK_CLEANUP_REQUESTED);
        std::fs::remove_file(&backup).map_err(|error| {
            rollback_observe_failed(
                ROLLBACK_CLEANUP_FAILED,
                HostError::RecoveryRequired(format!(
                    "remove Phase-B {label} rollback backup: {error}"
                )),
            )
        })?;
        rollback_backup_observe(ROLLBACK_CLEANUP_COMPLETED);
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod rollback_removal_cleanup_tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Fresh portable root leased exactly like the journal fixtures: a real
    /// temp directory opened through `UserOwnedRootLease`.
    fn leased_portable_root() -> (PathBuf, PathBuf, UserOwnedRootLease) {
        let root = std::env::temp_dir().join(format!(
            "eliot-980-rollback-{}-{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let portable = root.join("portable");
        std::fs::create_dir_all(&portable).unwrap_or_else(|_| unreachable!());
        let lease =
            UserOwnedRootLease::open_existing(&portable).unwrap_or_else(|_| unreachable!());
        (root, portable, lease)
    }

    /// Audit 5909832545 defect 4, positive: the removal and cleanup contours
    /// own request/verified/completion records distinct from the restore
    /// contour.
    #[test]
    fn removal_and_cleanup_vocabulary_names_each_contour() {
        for label in [ROLLBACK_REMOVAL_REQUESTED, ROLLBACK_REMOVAL_VERIFIED] {
            assert!(label.contains("removal"), "removal contour must name removal");
        }
        for label in [ROLLBACK_CLEANUP_REQUESTED, ROLLBACK_CLEANUP_COMPLETED] {
            assert!(label.contains("cleanup"), "cleanup contour must name cleanup");
        }
        let records = [
            "host.phase-b rollback restore requested",
            "host.phase-b rollback restored verified",
            ROLLBACK_RESTORE_FAILED,
            ROLLBACK_REMOVAL_REQUESTED,
            ROLLBACK_REMOVAL_VERIFIED,
            ROLLBACK_REMOVAL_FAILED,
            ROLLBACK_CLEANUP_REQUESTED,
            ROLLBACK_CLEANUP_COMPLETED,
            ROLLBACK_CLEANUP_FAILED,
        ];
        for (index, record) in records.iter().enumerate() {
            for other in records.iter().skip(index + 1) {
                assert_ne!(record, other, "rollback records must stay distinct");
            }
        }
    }

    /// Audit 5909832545 defect 4, refusal: unknown or failed outcomes never
    /// read as restored or verified, and a successful removal is never
    /// silent.
    #[test]
    fn failure_vocabulary_never_reads_as_restored_or_verified() {
        for label in [
            ROLLBACK_RESTORE_FAILED,
            ROLLBACK_REMOVAL_FAILED,
            ROLLBACK_CLEANUP_FAILED,
        ] {
            assert!(
                !label.contains("verified"),
                "failure records must never claim verification"
            );
            assert!(
                !label.contains("restored"),
                "failure records must never claim restoration"
            );
        }
        assert_ne!(ROLLBACK_REMOVAL_VERIFIED, ROLLBACK_REMOVAL_FAILED);
        assert_ne!(ROLLBACK_CLEANUP_COMPLETED, ROLLBACK_CLEANUP_FAILED);
        assert_ne!(
            ROLLBACK_REMOVAL_REQUESTED,
            "host.phase-b rollback restore requested"
        );
    }

    /// Audit 5909832545 defect 4, positive: rollback-by-removal deletes an
    /// uncommitted destination left with no sidecar.
    #[test]
    fn rollback_by_removal_deletes_uncommitted_destination() {
        let (root, portable, lease) = leased_portable_root();
        let destination = portable.join("generation.json");
        phase_b_materialize_file(
            InstallationProfile::PortableDev,
            Some(&lease),
            &destination,
            b"uncommitted",
            &[],
            "Store config",
        )
        .unwrap_or_else(|_| unreachable!());
        phase_b_restore_or_remove(
            InstallationProfile::PortableDev,
            Some(&lease),
            &destination,
            "Store config",
            None,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(std::fs::symlink_metadata(&destination).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Audit 5909832545 defect 4, refusal: a destination matching the
    /// retained template is kept, never removed.
    #[test]
    fn rollback_by_removal_keeps_committed_template() {
        let (root, portable, lease) = leased_portable_root();
        let destination = portable.join("generation.json");
        phase_b_materialize_file(
            InstallationProfile::PortableDev,
            Some(&lease),
            &destination,
            b"template",
            &[],
            "Store config",
        )
        .unwrap_or_else(|_| unreachable!());
        let template = phase_b_bytes_digest(b"template").unwrap_or_else(|_| unreachable!());
        phase_b_restore_or_remove(
            InstallationProfile::PortableDev,
            Some(&lease),
            &destination,
            "Store config",
            Some(&template),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            std::fs::read(&destination).unwrap_or_else(|_| unreachable!()),
            b"template"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Audit 5909832545 defect 4, positive: sidecar cleanup removes an
    /// existing rollback backup and leaves the destination alone.
    #[test]
    fn remove_rollback_backup_cleans_existing_sidecar() {
        let (root, portable, _) = leased_portable_root();
        let destination = portable.join("generation.json");
        let backup =
            phase_b_rollback_path(&destination, "Store config").unwrap_or_else(|_| unreachable!());
        std::fs::write(&backup, b"stale-backup").unwrap_or_else(|_| unreachable!());
        phase_b_remove_rollback_backup(&destination, "Store config")
            .unwrap_or_else(|_| unreachable!());
        assert!(std::fs::symlink_metadata(&backup).is_err());
        assert!(std::fs::symlink_metadata(&destination).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Audit 5909832545 defect 4, refusal: an unremovable sidecar fails
    /// cleanup instead of reporting completion.
    #[test]
    fn remove_rollback_backup_reports_unremovable_sidecar() {
        let (root, portable, _) = leased_portable_root();
        let destination = portable.join("generation.json");
        let backup =
            phase_b_rollback_path(&destination, "Store config").unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&backup).unwrap_or_else(|_| unreachable!());
        assert!(phase_b_remove_rollback_backup(&destination, "Store config").is_err());
        assert!(std::fs::symlink_metadata(&backup).is_ok());
        std::fs::remove_dir(&backup).unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_dir_all(&root);
    }
}
