//! Read-only watchdog publication observation and exact bundle decoding.
//!
//! Architecture anchors: `A8` (Watchdog) and `ARCH-WDG-01` (independent
//! supervision). Implementation anchors: `I8.2` (independent observation
//! routes), `I8.3` (deterministic supervision loop), and `I8.14` (observables).
//!
//! This child owns only decoding, exact single-publication observation, and
//! ordered scanning. Publication, ORS reads, identity construction, and
//! retention remain with the parent Host facade.

use super::super::{
    HostError, OwnedDirectoryRetirementPrecondition, Path, PathBuf, SUPERVISION_LEASE_FILE_NAME,
    SignedSupervisionLease, WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_DIRECTORY_PREFIX,
    WATCHDOG_PUBLICATION_FILE_NAME, WatchdogAdmissionTemplate, WatchdogPublicationBundle,
};

// F-LOG-HOST-4 (#979) publication observation helpers.
//
// Through the #889 facade only
// (`super::super::host_diagnostics::observe_entrypoint_with_detail`); the
// Event Log seam stays typed-Unavailable
// (`super::super::windows_event_log::event_log_sink_status`), never
// implemented here (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never digests,
// paths, lease/nonce material, or arbitrary error text — so bounding limits
// size, not sensitivity (I15.4). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache and no
// terminal guard here: the single designated terminal per failed operation
// stays with the outer #891/#893 operation that owns the failure decision;
// these phase observations correlate by stage order only and never emit a
// terminal.
#[cfg(windows)]
fn watchdog_observation_note_event_log_unavailable() {
    let _ = super::super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn watchdog_observation_observe(detail: &str) {
    watchdog_observation_note_event_log_unavailable();
    super::super::host_diagnostics::observe_entrypoint_with_detail(
        super::super::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[cfg(windows)]
pub struct HostWatchdogPublicationObservation {
    pub(super) path: PathBuf,
    pub(super) marker: WatchdogPublicationBundle,
    pub(super) admission: WatchdogAdmissionTemplate,
    pub(super) lease: SignedSupervisionLease,
    pub(super) retirement: OwnedDirectoryRetirementPrecondition,
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "exact single-publication decoding keeps child extraction, validation, canonical comparison, signature, binding, and content-address checks ordered"
)]
pub(super) fn decode_watchdog_publication_observation(
    path: &Path,
    observation: &eliot_platform_windows::OwnedDirectoryObservation,
    require_final_name: bool,
) -> Result<HostWatchdogPublicationObservation, HostError> {
    let admission_bytes = observation
        .bytes(WATCHDOG_ADMISSION_FILE_NAME)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent publication child, never ready/current.
            watchdog_observation_observe("watchdog.publication child absent");
            HostError::RecoveryRequired("Watchdog admission child is absent".to_owned())
        })?;
    let lease_bytes = observation
        .bytes(SUPERVISION_LEASE_FILE_NAME)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent publication child, never ready/current.
            watchdog_observation_observe("watchdog.publication child absent");
            HostError::RecoveryRequired("Watchdog lease child is absent".to_owned())
        })?;
    let marker_bytes = observation
        .bytes(WATCHDOG_PUBLICATION_FILE_NAME)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent publication child, never ready/current.
            watchdog_observation_observe("watchdog.publication child absent");
            HostError::RecoveryRequired("Watchdog publication marker is absent".to_owned())
        })?;
    let admission: WatchdogAdmissionTemplate =
        serde_json::from_slice(admission_bytes).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — undecodable child, never ready/current.
            watchdog_observation_observe("watchdog.publication child decode rejected");
            HostError::RecoveryRequired(format!("Watchdog admission decode failed: {error}"))
        })?;
    let marker: WatchdogPublicationBundle =
        serde_json::from_slice(marker_bytes).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — undecodable child, never ready/current.
            watchdog_observation_observe("watchdog.publication child decode rejected");
            HostError::RecoveryRequired(format!("Watchdog marker decode failed: {error}"))
        })?;
    let lease: SignedSupervisionLease = serde_json::from_slice(lease_bytes).map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — undecodable child, never ready/current.
        watchdog_observation_observe("watchdog.publication child decode rejected");
        HostError::RecoveryRequired(format!("Watchdog lease decode failed: {error}"))
    })?;
    admission.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid child, never ready/current.
        watchdog_observation_observe("watchdog.publication child validation rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    marker.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid child, never ready/current.
        watchdog_observation_observe("watchdog.publication child validation rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    lease.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid child, never ready/current.
        watchdog_observation_observe("watchdog.publication child validation rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    if admission.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — uncanonicalizable child, never ready/current.
        watchdog_observation_observe("watchdog.publication child canonical rejected");
        HostError::RecoveryRequired(error.to_string())
    })? != admission_bytes
        || marker.canonical_bytes().map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — uncanonicalizable child, never ready/current.
            watchdog_observation_observe("watchdog.publication child canonical rejected");
            HostError::RecoveryRequired(error.to_string())
        })? != marker_bytes
        || serde_json::to_vec(&lease).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — uncanonicalizable child, never ready/current.
            watchdog_observation_observe("watchdog.publication child canonical rejected");
            HostError::RecoveryRequired(error.to_string())
        })? != lease_bytes
    {
        // WORK_UNIT_CASE: 979/3 — non-canonical children, never ready/current.
        watchdog_observation_observe("watchdog.publication children not canonical");
        return Err(HostError::RecoveryRequired(
            "Watchdog publication children are not canonical".to_owned(),
        ));
    }
    marker
        .verify_bytes(admission_bytes, lease_bytes)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverified marker, never ready/current.
            watchdog_observation_observe("watchdog.publication marker signature rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
    if marker.installation_id != admission.installation_id
        || marker.approved_generation != admission.approved_generation
        || marker.supervision_lease_scope_id != admission.supervision_lease_scope_id
        || marker.supervision_lease_id != lease.payload.lease_id
    {
        // WORK_UNIT_CASE: 979/3 — conflicting marker/admission binding, never current.
        watchdog_observation_observe("watchdog.publication marker binding conflicting");
        return Err(HostError::RecoveryRequired(
            "Watchdog marker is not bound to its admission template".to_owned(),
        ));
    }
    if require_final_name {
        let expected_name = marker.directory_name().map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — directory name not derivable, identity unproven.
            watchdog_observation_observe("watchdog.publication directory name rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
        let actual_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 979/4 — path name unusable, identity unproven.
                watchdog_observation_observe("watchdog.publication directory name rejected");
                HostError::RecoveryRequired("Watchdog publication path is not canonical".to_owned())
            })?;
        if !actual_name.eq_ignore_ascii_case(&expected_name) {
            // WORK_UNIT_CASE: 979/3 — conflicting directory name, never current.
            watchdog_observation_observe("watchdog.publication directory name conflicting");
            return Err(HostError::RecoveryRequired(
                "Watchdog publication directory is not content-addressed by its ORS receipt"
                    .to_owned(),
            ));
        }
    }
    // WORK_UNIT_CASE: 979/2 — decoded owner-observed publication with exact identity.
    // WORK_UNIT_CASE: 979/4 — service/process-start/generation identity preserved.
    watchdog_observation_observe("watchdog.publication decoded");
    Ok(HostWatchdogPublicationObservation {
        path: path.to_path_buf(),
        marker,
        admission,
        lease,
        retirement: observation.retirement_precondition(),
    })
}

#[cfg(windows)]
pub fn observe_host_watchdog_publication(
    path: &Path,
) -> Result<HostWatchdogPublicationObservation, HostError> {
    let observation = eliot_platform_windows::observe_owned_directory_exact(
        path,
        &[
            WATCHDOG_ADMISSION_FILE_NAME,
            SUPERVISION_LEASE_FILE_NAME,
            WATCHDOG_PUBLICATION_FILE_NAME,
        ],
        super::WATCHDOG_PUBLICATION_CHILD_LIMIT,
    )
    .map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — unreadable publication directory, never ready/current.
        watchdog_observation_observe("watchdog.publication directory unreadable");
        HostError::RecoveryRequired(error.to_string())
    })?;
    // WORK_UNIT_CASE: 979/2 — owner-observed publication directory, distinct from verified current.
    watchdog_observation_observe("watchdog.publication directory observed");
    decode_watchdog_publication_observation(path, &observation, true)
}

#[cfg(windows)]
pub fn verify_exact_current_watchdog_publication(
    observed: &HostWatchdogPublicationObservation,
    template: &WatchdogAdmissionTemplate,
    current: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<(), HostError> {
    if observed.admission != *template
        || observed.lease != current.record.artifact
        || observed.marker.lease_revision != current.record.revision
        || observed.marker.ors_record_id != current.record.record_id.as_str()
        || observed.marker.ors_receipt_sha256 != current.receipt.receipt_sha256
    {
        // WORK_UNIT_CASE: 979/2 — observed publication is not the exact current head.
        // WORK_UNIT_CASE: 979/3 — stale/conflicting publication, never ready/current.
        watchdog_observation_observe("watchdog.publication not exact current");
        return Err(HostError::RecoveryRequired(
            "Watchdog publication is not the exact authoritative ORS head".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 979/2 — publication verified as the exact authoritative ORS head.
    watchdog_observation_observe("watchdog.publication exact current verified");
    Ok(())
}

#[cfg(windows)]
pub(super) fn scan_host_watchdog_publications(
    host_state_root: &Path,
) -> Result<Vec<HostWatchdogPublicationObservation>, HostError> {
    let mut observed = Vec::new();
    for entry in std::fs::read_dir(host_state_root).map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — unreadable spool root, never ready/current.
        watchdog_observation_observe("watchdog.publication spool unreadable");
        HostError::RecoveryRequired(error.to_string())
    })? {
        let entry = entry.map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unreadable spool entry, never ready/current.
            watchdog_observation_observe("watchdog.publication spool unreadable");
            HostError::RecoveryRequired(error.to_string())
        })?;
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 979/4 — non-Unicode spool name, identity unproven.
                watchdog_observation_observe("watchdog.publication spool name rejected");
                HostError::RecoveryRequired("Host state child name is not Unicode".to_owned())
            })?;
        if !name
            .to_ascii_lowercase()
            .starts_with(WATCHDOG_PUBLICATION_DIRECTORY_PREFIX)
        {
            continue;
        }
        // `?` propagates the already-observed inner decode boundary; no second record.
        observed.push(observe_host_watchdog_publication(&entry.path())?);
    }
    observed.sort_by(|left, right| left.path.cmp(&right.path));
    // WORK_UNIT_CASE: 979/2 — ordered spool scan of owner-observed publications.
    watchdog_observation_observe("watchdog.publication spool scanned");
    Ok(observed)
}
