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

use std::io::ErrorKind;
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
// no bytes, paths, caller labels, or error text are formatted, so no secret
// material can cross (I15.4) and no extra evaluation runs on the semantic
// path. The rendered values are the installation profile the owner already
// holds, as a 1:1 typed label, and the nonsecret `PlatformHandle` digests the
// owner already holds for this exact operation — the retained sidecar digest
// and the live destination digest — carried through the same
// `Bound`/`Unavailable` slot scheme and `bound_field` bounding used by
// `PhaseBAuthorityIdentity` in `host_composition_phase_b.rs`. A slot whose
// value the owner does not hold at that site renders the explicit
// `unavailable` missing-evidence disposition rather than a placeholder, a
// fabricated literal, or a recomputed digest, so two rollbacks of the same
// profile over different material are never byte-identical records. Length
// stays inside the facade's detail bound. Sink outcome never alters result,
// order, or cleanup. No terminal emission here: one terminal per failed
// operation stays with the outermost contour, while these
// inner phases are typed so they correlate by operation identity, not by
// stage order. A positive claim (`restored verified`, `removal verified`,
// `cleanup completed`) is emitted only after the existing exact readback or
// post-delete absence proof succeeds — and an absence proof must be the
// specific `ErrorKind::NotFound` outcome, never an unrelated `io::Error` — so
// an unknown or failed outcome is never logged as restored or removed.
//
// F-LOG-HOST-5 (#980, audit comment 5909832545 blocking defect 4): the
// contour vocabulary covers the complete rollback state map — backup prepared,
// restore requested, restore verified, uncommitted destination removal
// requested, removal verified, sidecar cleanup requested/completed, and an
// explicit failure/unknown disposition per failure branch. Both
// rollback-by-restoration and rollback-by-removal of an uncommitted
// destination are covered, and `phase_b_remove_rollback_backup` is no longer
// silent. The state map also names the two absence dispositions a delete needs
// beyond its own success: `absence unproven` (the entry is still there) and
// `absence unknown` (the re-probe failed for a reason other than
// `ErrorKind::NotFound`), each with its own frozen label so a completed
// removal is never claimed on an unproven or undetermined probe. The
// "nothing to roll back" case — no sidecar and no destination — is stated
// with the same `not required` disposition as the preserved-template no-op.
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
    UncommittedRemovalAbsenceUnknown,
    UncommittedRemovalVerified,
    // Rollback sidecar cleanup (`phase_b_remove_rollback_backup`).
    CleanupPathFailed,
    CleanupRequested,
    CleanupDeleteFailed,
    CleanupAbsenceUnproven,
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
            // The delete succeeded but the destination could not be re-probed
            // for absence by a non-`NotFound` outcome, so presence is
            // undetermined rather than disproved.
            Self::UncommittedRemovalAbsenceUnknown => {
                "host.phase-b rollback uncommitted removal absence unknown"
            }
            Self::UncommittedRemovalVerified => {
                "host.phase-b rollback uncommitted removal verified"
            }
            Self::CleanupPathFailed => "host.phase-b rollback backup cleanup path failed",
            Self::CleanupRequested => "host.phase-b rollback backup cleanup requested",
            Self::CleanupDeleteFailed => "host.phase-b rollback backup cleanup delete failed",
            // The delete succeeded but the sidecar could not be re-probed for
            // absence, or is still present; `cleanup completed` is withheld.
            Self::CleanupAbsenceUnproven => "host.phase-b rollback backup cleanup absence unproven",
            Self::CleanupCompleted => "host.phase-b rollback backup cleanup completed",
        }
    }
}

/// Frozen missing-evidence disposition for an identity slot this leaf's owner
/// does not hold (F-LOG-HOST-5 #980). Never a fabricated identity.
const ROLLBACK_IDENTITY_UNAVAILABLE: &str = "unavailable";

/// One nonsecret identity slot of a rollback record (F-LOG-HOST-5 #980).
///
/// Mirrors `PhaseBIdentity` in `host_composition_phase_b.rs`: `Bound` carries
/// an exact value the semantic owner already produced at this call site,
/// `Unavailable` records the explicit missing-evidence disposition so a record
/// never implies an operation binding that was not proven. Never a payload, a
/// raw path, a credential value, or arbitrary error text.
#[derive(Clone, Copy)]
enum RollbackIdentity<'a> {
    Bound(&'a str),
    Unavailable,
}

/// F-LOG-HOST-5 (#980): the rollback operation identity bound to one record.
///
/// Same projection the materialization contours use, extended with the two
/// nonsecret `PlatformHandle` digests the rollback owner already holds for
/// this exact operation. Every slot holds a value that owner already produced
/// at this call site, or `RollbackIdentity::Unavailable` while it holds none:
/// no digest is recomputed, re-derived, or fabricated here, and no slot makes
/// this a second authority owner — it decides nothing and runs no probe.
struct RollbackOperationIdentity<'a> {
    /// Digest of the retained rollback sidecar bytes read for this operation.
    backup: Option<&'a str>,
    /// Digest of the live destination content observed for this operation.
    current: Option<&'a str>,
}

impl<'a> RollbackOperationIdentity<'a> {
    /// The identity group of a contour that runs before its owner computed any
    /// digest. Both slots then render the explicit missing-evidence
    /// disposition.
    const fn empty() -> Self {
        Self { backup: None, current: None }
    }

    /// Binds the exact `PlatformHandle` digest of the sidecar bytes the owner
    /// already read and recorded, so two rollbacks of the same profile over
    /// different material produce different records.
    fn bind_backup_digest(&mut self, digest: &'a PlatformHandle) {
        self.backup = Some(digest.as_str());
    }

    /// Binds the exact `PlatformHandle` digest of the destination content the
    /// owner already read and recorded.
    fn bind_current_digest(&mut self, digest: &'a PlatformHandle) {
        self.current = Some(digest.as_str());
    }

    /// The frozen rollback key set, projected 1:1.
    fn slots(&self) -> [(&'static str, RollbackIdentity<'a>); 2] {
        [("backup", Self::slot(self.backup)), ("current", Self::slot(self.current))]
    }

    /// Projects one slot as the exact bound value or the explicit
    /// missing-evidence disposition; never a fabricated literal.
    fn slot(value: Option<&'a str>) -> RollbackIdentity<'a> {
        if let Some(text) = value {
            RollbackIdentity::Bound(text)
        } else {
            RollbackIdentity::Unavailable
        }
    }
}

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
/// owner-held installation profile and the frozen rollback identity slots
/// follow as bounded `k=v` pairs. Contours that run before their owner holds
/// any digest use [`rollback_backup_observe`], which states both absences
/// explicitly rather than omitting them.
fn rollback_backup_observe_bound(
    contour: RollbackContour,
    profile: Option<&InstallationProfile>,
    identity: &RollbackOperationIdentity<'_>,
) {
    rollback_backup_note_event_log_unavailable();
    let mut detail = String::from(contour.label());
    detail.push_str(" profile=");
    detail.push_str(rollback_profile_label(profile));
    for (key, value) in identity.slots() {
        push_rollback_identity(&mut detail, key, value);
    }
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        &detail,
    );
}

/// Appends one projected identity slot as `key=value`, or `key=unavailable`
/// for the explicit missing-evidence disposition (F-LOG-HOST-5 #980). The bound
/// value passes the same `bound_field` bounding the rest of the Host
/// projections use, so no slot can exceed the facade's field bound.
fn push_rollback_identity(detail: &mut String, key: &str, value: RollbackIdentity<'_>) {
    detail.push(' ');
    detail.push_str(key);
    detail.push('=');
    if let RollbackIdentity::Bound(text) = value {
        detail.push_str(crate::host_diagnostics::bound_field(text).text());
    } else {
        detail.push_str(ROLLBACK_IDENTITY_UNAVAILABLE);
    }
}

/// Emits one typed rollback contour for a boundary whose owner holds no digest
/// yet. The identity slots render the explicit `unavailable` disposition.
fn rollback_backup_observe(contour: RollbackContour, profile: Option<&InstallationProfile>) {
    rollback_backup_observe_bound(contour, profile, &RollbackOperationIdentity::empty());
}

/// F-LOG-HOST-5 (#980): one metadata probe outcome for a rollback path.
///
/// Split out of its call sites so a presence check that gates CONTROL FLOW and
/// a presence proof that gates a POSITIVE claim can share one specific
/// classification without the tightening of the proof ever moving a branch:
/// `Absent` requires [`ErrorKind::NotFound`] specifically, while any other
/// `io::Error` is `Unknown` rather than silently read as absence.
#[derive(Clone, Copy, Eq, PartialEq)]
enum RollbackPathPresence {
    /// The entry exists.
    Present,
    /// The entry is proven gone: the probe failed with `NotFound`.
    Absent,
    /// The probe failed for another reason, so presence is undetermined.
    Unknown,
}

/// Classifies one rollback path by a single `symlink_metadata` probe.
fn rollback_path_presence(path: &Path) -> RollbackPathPresence {
    match std::fs::symlink_metadata(path) {
        Ok(_) => RollbackPathPresence::Present,
        Err(error) => {
            let proven_absent = error.kind() == ErrorKind::NotFound;
            if proven_absent {
                RollbackPathPresence::Absent
            } else {
                RollbackPathPresence::Unknown
            }
        }
    }
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
            let lease =
                phase_b_open_existing(profile, portable_root, &backup).inspect_err(|_| {
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
    if rollback_path_presence(&backup) == RollbackPathPresence::Present {
        rollback_backup_observe(RollbackContour::RestoreRequested, Some(&profile));
        let mut identity = RollbackOperationIdentity::empty();
        let backup_lease =
            phase_b_open_existing(profile, portable_root, &backup).inspect_err(|_| {
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
        // From here on the owner's own recorded sidecar digest is part of every
        // record, so two restores of the same profile cannot be conflated.
        identity.bind_backup_digest(&backup_digest);
        let current_digest = match phase_b_open_existing(profile, portable_root, destination) {
            Ok(lease) => {
                lease.verify().map_err(|error| {
                    rollback_backup_observe_bound(
                        RollbackContour::RestoreDestinationVerifyFailed,
                        Some(&profile),
                        &identity,
                    );
                    HostError::RecoveryRequired(error)
                })?;
                let current = phase_b_lease_bytes(&lease).inspect_err(|_| {
                    rollback_backup_observe_bound(
                        RollbackContour::RestoreDestinationReadFailed,
                        Some(&profile),
                        &identity,
                    );
                })?;
                let current_digest = phase_b_bytes_digest(&current).inspect_err(|_| {
                    rollback_backup_observe_bound(
                        RollbackContour::RestoreDestinationReadFailed,
                        Some(&profile),
                        &identity,
                    );
                })?;
                identity.bind_current_digest(&current_digest);
                Some(current_digest)
            }
            Err(HostError::RecoveryRequired(reason)) if reason.contains("missing") => None,
            Err(error) => {
                rollback_backup_observe_bound(
                    RollbackContour::RestoreDestinationOpenFailed,
                    Some(&profile),
                    &identity,
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
                rollback_backup_observe_bound(
                    RollbackContour::RestoreMaterializeFailed,
                    Some(&profile),
                    &identity,
                );
            })?;
        }
        // Only reached after the retained bytes were proven or restored; an
        // unknown or failed outcome returned above and is never labelled here.
        rollback_backup_observe_bound(RollbackContour::RestoredVerified, Some(&profile), &identity);
    } else if rollback_path_presence(destination) == RollbackPathPresence::Present {
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
    } else {
        // No sidecar and no destination: there is nothing to restore and
        // nothing uncommitted to remove. Recorded with the same explicit
        // not-required disposition as the template-preserved no-op below, so a
        // silent no-op can never be confused with an unproven removal.
        rollback_backup_observe(RollbackContour::UncommittedRemovalNotRequired, Some(&profile));
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
    let mut identity = RollbackOperationIdentity::empty();
    identity.bind_current_digest(&current_digest);
    if preserve_template_digest.is_none_or(|expected| expected != &current_digest) {
        rollback_backup_observe_bound(
            RollbackContour::UncommittedRemovalRequested,
            Some(&profile),
            &identity,
        );
        std::fs::remove_file(destination).map_err(|error| {
            rollback_backup_observe_bound(
                RollbackContour::UncommittedRemovalDeleteFailed,
                Some(&profile),
                &identity,
            );
            HostError::RecoveryRequired(format!(
                "remove uncommitted Phase-B {label} destination: {error}"
            ))
        })?;
        // The positive claim needs absence PROVEN, not merely any probe
        // failure: a `NotFound` outcome alone discharges it. An entry still
        // present is the existing unproven disposition and keeps the existing
        // error; an undeterminable probe is recorded as the sibling unknown
        // and never as `uncommitted removal verified`. Neither changes which
        // inputs are accepted or the returned `Result`.
        match rollback_path_presence(destination) {
            RollbackPathPresence::Present => {
                rollback_backup_observe_bound(
                    RollbackContour::UncommittedRemovalAbsenceUnproven,
                    Some(&profile),
                    &identity,
                );
                return Err(HostError::RecoveryRequired(format!(
                    "uncommitted Phase-B {label} destination remains after rollback"
                )));
            }
            RollbackPathPresence::Absent => {
                rollback_backup_observe_bound(
                    RollbackContour::UncommittedRemovalVerified,
                    Some(&profile),
                    &identity,
                );
            }
            RollbackPathPresence::Unknown => {
                rollback_backup_observe_bound(
                    RollbackContour::UncommittedRemovalAbsenceUnknown,
                    Some(&profile),
                    &identity,
                );
            }
        }
    } else {
        // The destination is exactly the immutable template, so there is
        // no uncommitted material to remove. Recorded explicitly so the
        // silent no-op is distinguishable from an unproven removal.
        rollback_backup_observe_bound(
            RollbackContour::UncommittedRemovalNotRequired,
            Some(&profile),
            &identity,
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
    if rollback_path_presence(&backup) == RollbackPathPresence::Present {
        rollback_backup_observe(RollbackContour::CleanupRequested, None);
        std::fs::remove_file(&backup).map_err(|error| {
            rollback_backup_observe(RollbackContour::CleanupDeleteFailed, None);
            HostError::RecoveryRequired(format!("remove Phase-B {label} rollback backup: {error}"))
        })?;
        // F-LOG-HOST-5 (#980): `cleanup completed` is a positive removal
        // claim, so it is gated on the same post-delete absence proof the
        // destination contour uses: a delete that reports success while the
        // sidecar is still enumerated (or held open with delete sharing) is
        // never logged as completed. A probe that does not prove absence
        // records the explicit `absence unproven` disposition instead; the
        // returned `Result`, the accepted set, and the delete call itself are
        // unchanged.
        if rollback_path_presence(&backup) == RollbackPathPresence::Absent {
            rollback_backup_observe(RollbackContour::CleanupCompleted, None);
        } else {
            rollback_backup_observe(RollbackContour::CleanupAbsenceUnproven, None);
        }
    }
    Ok(())
}
