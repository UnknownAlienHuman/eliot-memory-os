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
// sink disposition is observed only through the canonical bounded observer
// `crate::host_diagnostics::note_event_log_sink_status`, which consumes the
// live `crate::windows_event_log::event_log_sink_status` answer. #984's safe
// port is landed, so that answer is `Ok` on Windows (nothing to note) and the
// typed `EventLogUnavailable` elsewhere, where the canonical observer records
// the standing seam state on the shared `tracing` sink. No sink state is read
// or interpreted here.
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
///
/// Each slot owns the digest TEXT the owner already computed once at this call
/// site, exactly as `PhaseBAuthorityIdentity` does, so the record outlives the
/// owner local it was bound from and no borrow keeps a handle in place.
struct RollbackOperationIdentity {
    /// Digest of the retained rollback sidecar bytes read for this operation.
    backup: Option<String>,
    /// Digest of the live destination content observed for this operation.
    current: Option<String>,
}

impl RollbackOperationIdentity {
    /// The identity group of a contour that runs before its owner computed any
    /// digest. Both slots then render the explicit missing-evidence
    /// disposition.
    const fn empty() -> Self {
        Self {
            backup: None,
            current: None,
        }
    }

    /// Binds the exact `PlatformHandle` digest of the sidecar bytes the owner
    /// already read and recorded, so two rollbacks of the same profile over
    /// different material produce different records.
    fn bind_backup_digest(&mut self, digest: &PlatformHandle) {
        self.backup = Some(digest.as_str().to_owned());
    }

    /// Binds the exact `PlatformHandle` digest of the destination content the
    /// owner already read and recorded.
    fn bind_current_digest(&mut self, digest: &PlatformHandle) {
        self.current = Some(digest.as_str().to_owned());
    }

    /// The frozen rollback key set, projected 1:1.
    fn slots(&self) -> [(&'static str, RollbackIdentity<'_>); 2] {
        [
            ("backup", Self::slot(self.backup.as_deref())),
            ("current", Self::slot(self.current.as_deref())),
        ]
    }

    /// Projects one slot as the exact bound value or the explicit
    /// missing-evidence disposition; never a fabricated literal.
    fn slot(value: Option<&str>) -> RollbackIdentity<'_> {
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
    identity: &RollbackOperationIdentity,
) {
    // Sink disposition is load-bearing for this record: the canonical bounded
    // observer states where a rollback contour stayed, in the same place in
    // the sequence the discarded status read used to occupy.
    crate::host_diagnostics::note_event_log_sink_status();
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
        rollback_backup_observe(
            RollbackContour::UncommittedRemovalNotRequired,
            Some(&profile),
        );
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
        // destination contour uses: it is emitted only when the probe failed
        // with `NotFound`, which is the classification that means the
        // directory entry is gone. Any other outcome — an entry still
        // enumerated, or a probe that could not determine presence — records
        // the explicit `absence unproven` disposition instead. The returned
        // `Result`, the accepted set, and the delete call itself are
        // unchanged.
        if rollback_path_presence(&backup) == RollbackPathPresence::Absent {
            rollback_backup_observe(RollbackContour::CleanupCompleted, None);
        } else {
            rollback_backup_observe(RollbackContour::CleanupAbsenceUnproven, None);
        }
    }
    Ok(())
}

// F-LOG-HOST-5 (#980) executed contours of the closed rollback state map.
//
// Placed at the owner because `phase_b_write_rollback_backup`,
// `phase_b_restore_or_remove`, `remove_uncommitted_destination`, and
// `phase_b_remove_rollback_backup` are `pub(super)`/`pub` inside this private
// leaf: an integration test under `tests/` cannot name them. Each case drives
// the REAL state map against an isolated temp directory the test creates and
// owns, and asserts the record production emitted for exactly that state.
//
// The capture reads the record back out of a real `tracing` subscriber, the
// same seam the crate's other diagnostics tests use; the record under test is
// never manufactured by calling the diagnostic facade directly.
#[cfg(test)]
mod rollback_contour_tests {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use uuid::Uuid;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture poisoned"))?
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `body` under a real `tracing` subscriber and returns exactly the
    /// text production emitted while it ran.
    fn capture(body: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer = sink.clone();
        let bytes = {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, body);
            sink.bytes
                .lock()
                .expect("capture is poisoned only by a panicking writer")
                .clone()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn emitted(record: &str, contour: RollbackContour) -> bool {
        record.contains(contour.label())
    }

    /// An isolated temp root the test owns, plus the portable lease every
    /// Phase-B file effect below is admitted through. The lease is released
    /// before the root is removed so the cleanup is itself deterministic.
    struct Fixture {
        root: PathBuf,
        portable: PathBuf,
        lease: Option<UserOwnedRootLease>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("eliot-host-rollback-contour-{}", Uuid::new_v4()));
            let portable = root.join("portable");
            std::fs::create_dir_all(&portable)
                .unwrap_or_else(|error| panic!("create fixture root: {error}"));
            let lease = UserOwnedRootLease::open_existing(&portable)
                .unwrap_or_else(|error| panic!("open portable lease: {error}"));
            Self {
                root,
                portable,
                lease: Some(lease),
            }
        }

        fn lease(&self) -> &UserOwnedRootLease {
            self.lease
                .as_ref()
                .unwrap_or_else(|| unreachable!("the fixture lease is live for the whole test"))
        }

        fn destination(&self, name: &str) -> PathBuf {
            self.portable.join(name)
        }

        /// Retains a handle that does NOT share delete, so a real
        /// `remove_file` against it fails with a sharing violation.
        ///
        /// Takes no `self`: the retained handle depends only on the exact path
        /// it opens and the share mode below, never on fixture state, so a
        /// receiver here would assert a binding the helper does not have.
        fn hold_without_delete_sharing(path: &Path) -> std::fs::File {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(path)
                .unwrap_or_else(|error| panic!("hold {}: {error}", path.display()))
        }

        /// Retains a handle that DOES share delete, so the real delete succeeds
        /// while this handle is still live. Note what Windows then does: the
        /// directory entry leaves the namespace at delete time, not at
        /// last-handle-close, so the name is free and the post-delete probe
        /// genuinely proves absence. This helper exists to pin that platform
        /// fact, not to manufacture an unproven absence — a live handle alone
        /// can never make the sidecar still enumerated.
        ///
        /// Takes no `self`, for the same reason as
        /// `Fixture::hold_without_delete_sharing`: the handle depends only on
        /// the exact path and the share mode below.
        fn hold_with_delete_sharing(path: &Path) -> std::fs::File {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(path)
                .unwrap_or_else(|error| panic!("hold {}: {error}", path.display()))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.lease.take());
            let _removed = std::fs::remove_dir_all(&self.root);
        }
    }

    /// `WORK_UNIT_CASE: 980/14` — a prepared sidecar is stated as prepared, with
    /// the owner-held profile projected as a 1:1 typed label.
    #[test]
    fn backup_preparation_is_observed_as_prepared_only_after_the_exact_readback() {
        let fixture = Fixture::new();
        let destination = fixture.destination("store-config.json");
        let previous = b"{\"phase\":\"previous\"}";
        std::fs::write(&destination, previous)
            .unwrap_or_else(|error| panic!("seed destination: {error}"));

        let record = capture(|| {
            let outcome = phase_b_write_rollback_backup(
                InstallationProfile::PortableDev,
                Some(fixture.lease()),
                &destination,
                previous,
                "Store config",
            );
            assert!(outcome.is_ok(), "backup preparation must succeed");
        });
        assert!(
            emitted(&record, RollbackContour::BackupRequested),
            "preparation must be requested: {record}"
        );
        assert!(
            emitted(&record, RollbackContour::BackupPrepared),
            "an exact readback must be observed as prepared: {record}"
        );
        assert!(
            record.contains("profile=portable_dev"),
            "the owner-held profile must be projected: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::BackupUnknownRetained),
            "an exact readback is not an unknown outcome: {record}"
        );
        let sidecar = phase_b_rollback_path(&destination, "Store config")
            .unwrap_or_else(|error| panic!("sidecar path: {error}"));
        assert!(sidecar.is_file(), "the retained sidecar must exist");
    }

    /// `WORK_UNIT_CASE: 980/15` — restoration is stated as requested and then as
    /// verified, carrying the owner's own sidecar digest so two rollbacks of the
    /// same profile over different material are never byte-identical records.
    #[test]
    fn restoration_is_requested_then_verified_with_the_owner_sidecar_digest() {
        let fixture = Fixture::new();
        let destination = fixture.destination("store-config.json");
        let previous = b"{\"phase\":\"previous\"}";
        std::fs::write(&destination, previous)
            .unwrap_or_else(|error| panic!("seed destination: {error}"));
        phase_b_write_rollback_backup(
            InstallationProfile::PortableDev,
            Some(fixture.lease()),
            &destination,
            previous,
            "Store config",
        )
        .unwrap_or_else(|error| panic!("prepare sidecar: {error}"));
        let sidecar_bytes = std::fs::read(
            phase_b_rollback_path(&destination, "Store config")
                .unwrap_or_else(|error| panic!("sidecar path: {error}")),
        )
        .unwrap_or_else(|error| panic!("read sidecar: {error}"));
        std::fs::write(&destination, b"{\"phase\":\"live\"}")
            .unwrap_or_else(|error| panic!("replace destination: {error}"));

        let record = capture(|| {
            let outcome = phase_b_restore_or_remove(
                InstallationProfile::PortableDev,
                Some(fixture.lease()),
                &destination,
                "Store config",
                None,
            );
            assert!(outcome.is_ok(), "restoration must succeed");
        });
        assert!(
            emitted(&record, RollbackContour::RestoreRequested),
            "restoration must be requested: {record}"
        );
        assert!(
            emitted(&record, RollbackContour::RestoredVerified),
            "a completed restoration must be observed as verified: {record}"
        );
        assert_eq!(
            std::fs::read(&destination).unwrap_or_else(|error| panic!("read back: {error}")),
            previous,
            "the retained bytes must be restored"
        );
        let digest = phase_b_bytes_digest(&sidecar_bytes)
            .unwrap_or_else(|error| panic!("sidecar digest: {error}"));
        assert!(
            record.contains(&format!("backup={}", digest.as_str())),
            "the verified record must carry the owner-held sidecar digest: {record}"
        );
    }

    /// `WORK_UNIT_CASE: 980/16` — with neither a sidecar nor a destination there
    /// is nothing to restore and nothing uncommitted to remove. The state map
    /// states it with the explicit not-required disposition, so a silent no-op
    /// can never be confused with an unproven removal.
    #[test]
    fn absent_sidecar_and_absent_destination_is_an_explicit_not_required_disposition() {
        let fixture = Fixture::new();
        let destination = fixture.destination("store-bootstrap.json");

        let record = capture(|| {
            let outcome = phase_b_restore_or_remove(
                InstallationProfile::PortableDev,
                Some(fixture.lease()),
                &destination,
                "Store bootstrap",
                None,
            );
            assert!(outcome.is_ok(), "nothing to roll back must succeed");
        });
        assert!(
            emitted(&record, RollbackContour::UncommittedRemovalNotRequired),
            "the nothing-to-do state must be stated explicitly: {record}"
        );
        for contour in [
            RollbackContour::RestoredVerified,
            RollbackContour::UncommittedRemovalRequested,
            RollbackContour::UncommittedRemovalVerified,
        ] {
            assert!(
                !emitted(&record, contour),
                "the nothing-to-do state claimed {:?}: {record}",
                contour.label()
            );
        }
    }

    /// `WORK_UNIT_CASE: 980/17` — CRITICAL: `uncommitted removal verified` is
    /// UNREACHABLE when the delete does not succeed. A destination whose bytes
    /// are not the immutable template is genuinely removal-requested, the real
    /// delete then fails against a retained no-delete-sharing handle, and the
    /// positive claim must be withheld in favour of the explicit failed
    /// disposition.
    #[test]
    fn uncommitted_removal_never_claims_verified_when_the_delete_fails() {
        let fixture = Fixture::new();
        let destination = fixture.destination("agent-bridge-profile.json");
        let template = b"{\"phase\":\"template\"}";
        let uncommitted = b"{\"phase\":\"uncommitted\"}";
        std::fs::write(&destination, uncommitted)
            .unwrap_or_else(|error| panic!("seed destination: {error}"));
        let template_digest = phase_b_bytes_digest(template)
            .unwrap_or_else(|error| panic!("template digest: {error}"));
        let _blocking = Fixture::hold_without_delete_sharing(&destination);

        let record = capture(|| {
            let outcome = phase_b_restore_or_remove(
                InstallationProfile::PortableDev,
                Some(fixture.lease()),
                &destination,
                "Agent Bridge profile",
                Some(&template_digest),
            );
            assert!(outcome.is_err(), "a failed delete must return Err");
        });
        assert!(
            emitted(&record, RollbackContour::UncommittedRemovalRequested),
            "an uncommitted destination must be removal-requested: {record}"
        );
        assert!(
            emitted(&record, RollbackContour::UncommittedRemovalDeleteFailed),
            "a failed delete must be observed as failed: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::UncommittedRemovalVerified),
            "a failed delete must never be claimed as removal verified: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::UncommittedRemovalAbsenceUnproven),
            "a delete that failed was never absence-proven: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::UncommittedRemovalAbsenceUnknown),
            "a failed delete has no undetermined absence probe to report: {record}"
        );
        assert!(
            destination.is_file(),
            "a failed delete must leave the destination in place"
        );
    }

    /// `WORK_UNIT_CASE: 980/18` — a destination that still holds exactly the
    /// immutable template has no uncommitted material, so no removal is
    /// requested and the state is stated as not required. The template is
    /// retained on disk.
    #[test]
    fn template_exact_destination_is_retained_as_an_explicit_not_required_disposition() {
        let fixture = Fixture::new();
        let destination = fixture.destination("store-config.json");
        let template = b"{\"phase\":\"template\"}";
        std::fs::write(&destination, template)
            .unwrap_or_else(|error| panic!("seed destination: {error}"));
        let template_digest = phase_b_bytes_digest(template)
            .unwrap_or_else(|error| panic!("template digest: {error}"));

        let record = capture(|| {
            let outcome = phase_b_restore_or_remove(
                InstallationProfile::PortableDev,
                Some(fixture.lease()),
                &destination,
                "Store config",
                Some(&template_digest),
            );
            assert!(
                outcome.is_ok(),
                "a template-preserved rollback must succeed"
            );
        });
        assert!(
            emitted(&record, RollbackContour::UncommittedRemovalNotRequired),
            "a template-preserved rollback must state not required: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::UncommittedRemovalRequested),
            "a template-preserved rollback must not request removal: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::UncommittedRemovalVerified),
            "a template-preserved rollback claims no removal: {record}"
        );
        assert_eq!(
            std::fs::read(&destination).unwrap_or_else(|error| panic!("read back: {error}")),
            template,
            "the immutable template must be retained"
        );
    }

    /// `WORK_UNIT_CASE: 980/19` — sidecar cleanup is stated as requested and then
    /// completed, and the cleanup contour owns no profile so it renders the
    /// explicit missing-evidence disposition instead of a fabricated identity.
    #[test]
    fn sidecar_cleanup_is_requested_then_completed_with_no_fabricated_profile() {
        let fixture = Fixture::new();
        let destination = fixture.destination("store-config.json");
        let previous = b"{\"phase\":\"previous\"}";
        std::fs::write(&destination, previous)
            .unwrap_or_else(|error| panic!("seed destination: {error}"));
        phase_b_write_rollback_backup(
            InstallationProfile::PortableDev,
            Some(fixture.lease()),
            &destination,
            previous,
            "Store config",
        )
        .unwrap_or_else(|error| panic!("prepare sidecar: {error}"));
        let sidecar = phase_b_rollback_path(&destination, "Store config")
            .unwrap_or_else(|error| panic!("sidecar path: {error}"));

        let record = capture(|| {
            let outcome = phase_b_remove_rollback_backup(&destination, "Store config");
            assert!(outcome.is_ok(), "sidecar cleanup must succeed");
        });
        assert!(
            emitted(&record, RollbackContour::CleanupRequested),
            "cleanup must be requested: {record}"
        );
        assert!(
            emitted(&record, RollbackContour::CleanupCompleted),
            "a proven-absent sidecar must be observed as cleanup completed: {record}"
        );
        assert!(
            record.contains(&format!("profile={ROLLBACK_IDENTITY_UNAVAILABLE}")),
            "the cleanup contour owns no profile and must say so: {record}"
        );
        assert!(!sidecar.exists(), "the retained sidecar must be gone");
    }

    /// `WORK_UNIT_CASE: 980/20` — CRITICAL: `backup cleanup completed` is gated on
    /// a `NotFound` classification and on nothing else, and on Windows that gate
    /// is exact even while a delete-sharing handle is still live.
    ///
    /// The earlier revision of this case asserted that a successful
    /// `remove_file` could leave the sidecar still enumerated. That premise is
    /// false on this platform: `std::fs::remove_file` is `DeleteFileW`, and
    /// Windows removes the directory entry from the namespace at delete time,
    /// not at last-handle-close time. Measured on this NTFS volume, the
    /// directory listing drops to zero entries and the same name is immediately
    /// re-creatable while the delete-sharing handle is still open, and the
    /// follow-up `symlink_metadata` (what `rollback_path_presence` calls) then
    /// fails with `ERROR_FILE_NOT_FOUND`, so the completion claim here IS
    /// absence-proven and is correctly emitted.
    ///
    /// So the property this case actually protects is the gate itself, proven
    /// where it is deterministically observable: absence is read ONLY from a
    /// `NotFound` probe, an undeterminable probe is `Unknown` (the arm the
    /// contour states as `absence unproven` / `absence unknown`), and an entry
    /// that is still there is `Present` (also `absence unproven`) — never
    /// `Absent`.
    #[test]
    fn cleanup_completion_is_gated_on_a_not_found_absence_not_on_the_delete_returning_ok() {
        let fixture = Fixture::new();
        let destination = fixture.destination("store-config.json");
        let previous = b"{\"phase\":\"previous\"}";
        std::fs::write(&destination, previous)
            .unwrap_or_else(|error| panic!("seed destination: {error}"));
        phase_b_write_rollback_backup(
            InstallationProfile::PortableDev,
            Some(fixture.lease()),
            &destination,
            previous,
            "Store config",
        )
        .unwrap_or_else(|error| panic!("prepare sidecar: {error}"));
        let sidecar = phase_b_rollback_path(&destination, "Store config")
            .unwrap_or_else(|error| panic!("sidecar path: {error}"));
        let _pending = Fixture::hold_with_delete_sharing(&sidecar);
        assert!(
            matches!(
                rollback_path_presence(&sidecar),
                RollbackPathPresence::Present
            ),
            "a sidecar that is still enumerated is Present, never Absent"
        );

        let record = capture(|| {
            let outcome = phase_b_remove_rollback_backup(&destination, "Store config");
            assert!(
                outcome.is_ok(),
                "a delete that succeeds must not change the returned Result"
            );
        });
        assert!(
            emitted(&record, RollbackContour::CleanupRequested),
            "cleanup must be requested: {record}"
        );
        assert!(
            emitted(&record, RollbackContour::CleanupCompleted),
            "a sidecar whose entry the delete removed is absence-proven: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::CleanupAbsenceUnproven),
            "a proven absence is never the unproven disposition: {record}"
        );
        assert!(
            !sidecar.exists(),
            "the delete must free the sidecar name even while a delete-sharing handle is live"
        );
        assert!(
            matches!(
                rollback_path_presence(&sidecar),
                RollbackPathPresence::Absent
            ),
            "only a NotFound probe is read as absence"
        );
        // The other side of the gate: a probe that fails for ANY reason other
        // than `NotFound` is undetermined. This is the exact classification the
        // cleanup contour states as `absence unproven` and the destination
        // contour as `absence unknown`, so a failing probe can never be read as
        // a removal proof.
        let undeterminable = fixture.portable.join("side\0car");
        assert!(
            matches!(
                rollback_path_presence(&undeterminable),
                RollbackPathPresence::Unknown
            ),
            "a probe that is not NotFound must never be classified as absence"
        );
    }

    /// `WORK_UNIT_CASE: 980/21` — a cleanup delete that cannot succeed is stated
    /// as failed, and the positive completion claim stays unreachable.
    #[test]
    fn cleanup_never_claims_completed_when_the_delete_fails() {
        let fixture = Fixture::new();
        let destination = fixture.destination("store-config.json");
        let previous = b"{\"phase\":\"previous\"}";
        std::fs::write(&destination, previous)
            .unwrap_or_else(|error| panic!("seed destination: {error}"));
        phase_b_write_rollback_backup(
            InstallationProfile::PortableDev,
            Some(fixture.lease()),
            &destination,
            previous,
            "Store config",
        )
        .unwrap_or_else(|error| panic!("prepare sidecar: {error}"));
        let sidecar = phase_b_rollback_path(&destination, "Store config")
            .unwrap_or_else(|error| panic!("sidecar path: {error}"));
        let _blocking = Fixture::hold_without_delete_sharing(&sidecar);

        let record = capture(|| {
            let outcome = phase_b_remove_rollback_backup(&destination, "Store config");
            assert!(outcome.is_err(), "a failed delete must return Err");
        });
        assert!(
            emitted(&record, RollbackContour::CleanupDeleteFailed),
            "a failed cleanup delete must be observed as failed: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::CleanupCompleted),
            "a failed delete must never be claimed as cleanup completed: {record}"
        );
        assert!(
            !emitted(&record, RollbackContour::CleanupAbsenceUnproven),
            "a delete that failed was never absence-proven: {record}"
        );
    }

    /// `WORK_UNIT_CASE: 980/22` — a destination with no derivable rollback path is
    /// rejected before any file effect, and the rejection is stated as a path
    /// failure rather than as a completion.
    #[test]
    fn unresolvable_rollback_path_is_rejected_before_any_file_effect() {
        let fixture = Fixture::new();
        let root_only = Path::new(r"C:\");
        assert!(
            root_only.parent().is_none(),
            "the fixture path must have no parent so the rollback path cannot be derived"
        );

        let cleanup = capture(|| {
            let outcome = phase_b_remove_rollback_backup(root_only, "Store config");
            assert!(outcome.is_err(), "an underivable path must return Err");
        });
        assert!(
            emitted(&cleanup, RollbackContour::CleanupPathFailed),
            "an underivable cleanup path must be observed as a path failure: {cleanup}"
        );
        assert!(
            !emitted(&cleanup, RollbackContour::CleanupCompleted),
            "a rejected cleanup path claims no completion: {cleanup}"
        );

        let backup = capture(|| {
            let outcome = phase_b_write_rollback_backup(
                InstallationProfile::PortableDev,
                Some(fixture.lease()),
                root_only,
                b"previous",
                "Store config",
            );
            assert!(outcome.is_err(), "an underivable path must return Err");
        });
        assert!(
            emitted(&backup, RollbackContour::BackupPathFailed),
            "an underivable backup path must be observed as a path failure: {backup}"
        );
        assert!(
            !emitted(&backup, RollbackContour::BackupPrepared),
            "a rejected backup path claims no preparation: {backup}"
        );
    }
}
