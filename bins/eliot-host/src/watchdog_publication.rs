use super::{
    CandidateManifest, DirectoryPublicationError, DirectoryPublicationOutcome, HostError,
    OperationIdentity, OwnedDirectoryPublication, OwnedDirectoryRetirementOutcome, Path, PathBuf,
    PlatformHandle, ProtectedRuntimePathLease, PublishedSupervisionIdentity, Read,
    SUPERVISION_LEASE_FILE_NAME, Seek, SupervisionLeaseVerifier, SystemTime, UNIX_EPOCH,
    WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_FILE_NAME,
    WATCHDOG_PUBLICATION_RETAINED_LIMIT, WatchdogAdmissionTemplate, WatchdogPublicationBundle,
    WatchdogPublicationRetentionPlan, Write, retire_owned_directory_exact, sha256_json,
    windows_paths_equal,
};

#[cfg(windows)]
mod observation;
#[cfg(windows)]
#[allow(unused_imports)]
pub(super) use observation::{
    HostWatchdogPublicationObservation, observe_host_watchdog_publication,
    verify_exact_current_watchdog_publication,
};
#[cfg(windows)]
use observation::{decode_watchdog_publication_observation, scan_host_watchdog_publications};

// F-LOG-HOST-4 (#979) publication helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never digests,
// paths, lease/nonce material, or arbitrary error text — so bounding limits
// size, not sensitivity (I15.4). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache and no
// terminal guard here: the single designated terminal per failed operation
// stays with the outer #891/#893 operation that owns the failure decision;
// these phase observations correlate by stage order only and never emit a
// terminal. A bare `?` on an already-observed inner boundary propagates
// without a second record.
#[cfg(windows)]
fn watchdog_publication_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn watchdog_publication_observe(detail: &str) {
    watchdog_publication_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[cfg(windows)]
const WATCHDOG_PUBLICATION_CHILD_LIMIT: u64 = 1024 * 1024;
#[cfg(windows)]
const KERNEL_ORS_FILE_NAME: &str = "kernel-ors.redb";
#[cfg(windows)]
pub(super) fn write_watchdog_publication_child(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_SHARE_READ,
    };

    if bytes.len() as u64 > WATCHDOG_PUBLICATION_CHILD_LIMIT {
        // WORK_UNIT_CASE: 979/4 — oversize child, bounded identity preserved.
        watchdog_publication_observe("watchdog.publication child oversize rejected");
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child exceeds the bounded size".to_owned(),
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
        .open(path)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — child create/open boundary.
            watchdog_publication_observe("watchdog.publication child write failed");
            HostError::RecoveryRequired(error.to_string())
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — child write/sync boundary.
            watchdog_publication_observe("watchdog.publication child write failed");
            HostError::RecoveryRequired(error.to_string())
        })?;
    let metadata = file.metadata().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child metadata boundary.
        watchdog_publication_observe("watchdog.publication child write failed");
        HostError::RecoveryRequired(error.to_string())
    })?;
    if !metadata.is_file()
        || metadata.len() != bytes.len() as u64
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        // WORK_UNIT_CASE: 979/4 — invalid child identity, never committed.
        watchdog_publication_observe("watchdog.publication child identity rejected");
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child identity is invalid".to_owned(),
        ));
    }
    file.seek(std::io::SeekFrom::Start(0)).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child readback seek boundary.
        watchdog_publication_observe("watchdog.publication child write failed");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let mut readback = Vec::with_capacity(bytes.len());
    file.read_to_end(&mut readback).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child readback read boundary.
        watchdog_publication_observe("watchdog.publication child write failed");
        HostError::RecoveryRequired(error.to_string())
    })?;
    if readback != bytes {
        // WORK_UNIT_CASE: 979/4 — readback changed, exact identity preserved by rejection.
        watchdog_publication_observe("watchdog.publication child readback changed");
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child readback changed".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 979/2 — child written with exact readback identity.
    watchdog_publication_observe("watchdog.publication child committed");
    Ok(())
}

#[cfg(windows)]
pub(super) fn read_manifest_current_supervision_lease(
    manifest: &CandidateManifest,
    lease_id: &str,
) -> Result<eliot_ors::SupervisionLeaseSnapshot, HostError> {
    let lease_id = OperationIdentity::new(lease_id.to_owned()).map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unusable lease identity, never read.
        watchdog_publication_observe("watchdog.publication lease identity rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let ors_path = PathBuf::from(
        manifest
            .runtime_launch
            .runtime_state_roots
            .kernel_ors_root
            .as_str(),
    )
    .join(KERNEL_ORS_FILE_NAME);
    let retained =
        ProtectedRuntimePathLease::open_existing_absolute(&ors_path).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unopenable ORS, no head observed.
            watchdog_publication_observe("watchdog.publication ORS open failed");
            HostError::RecoveryRequired(format!("Kernel ORS open failed: {error}"))
        })?;
    if !windows_paths_equal(retained.path(), &ors_path) {
        // WORK_UNIT_CASE: 979/3 — conflicting ORS selection, never read.
        watchdog_publication_observe("watchdog.publication ORS selection conflicting");
        return Err(HostError::RecoveryRequired(
            "Kernel ORS path is not the manifest-selected child".to_owned(),
        ));
    }
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — ORS identity changed before the read.
            watchdog_publication_observe("watchdog.publication ORS identity changed");
            HostError::RecoveryRequired(format!("Kernel ORS changed: {error}"))
        })?;
    let current = eliot_ors::read_current_supervision_lease_read_only(retained.path(), &lease_id)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unreadable ORS, no head observed.
            watchdog_publication_observe("watchdog.publication ORS read failed");
            HostError::RecoveryRequired(format!("Kernel ORS read failed: {error}"))
        })?
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent ORS head, never ready/current.
            watchdog_publication_observe("watchdog.publication ORS head absent");
            HostError::RecoveryRequired("Kernel ORS has no current supervision lease".to_owned())
        })?;
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — ORS identity changed across the read.
            watchdog_publication_observe("watchdog.publication ORS identity changed");
            HostError::RecoveryRequired(format!("Kernel ORS changed: {error}"))
        })?;
    current.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid ORS snapshot, never ready/current.
        watchdog_publication_observe("watchdog.publication ORS snapshot validation rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    // WORK_UNIT_CASE: 979/2 — owner-observed exact current ORS supervision head.
    watchdog_publication_observe("watchdog.publication ORS head read");
    Ok(current)
}

/// Returns the exact Kernel-signed supervision lease that still owes coverage
/// for `activation_id`, or `None` when no published lease is live for it.
///
/// I1.5 idle-drain gate: "Idle drain starts only when no `RuntimeLease` remains
/// and no valid `SupervisionLease` requires live sensing/containment". This is
/// the read-only half of the same publisher/decoder pair that commits the
/// publication, so the census never introduces a second reader of a
/// Watchdog-owned file, a second signature policy, or a second copy of the
/// publication schema. Coverage ends honestly at `expires_at_ms`: a lease that
/// cannot prove renewal stops blocking drain instead of blocking it forever,
/// while a terminal (`EXPIRED`/`REVOKED`/`CLOSED`) lease never blocked at all.
#[cfg(windows)]
pub(super) fn live_supervision_obligation(
    host_state_root: &Path,
    installation: &PlatformHandle,
    activation_id: &PlatformHandle,
    now_ms: u64,
) -> Result<Option<PlatformHandle>, HostError> {
    // `?` propagates the already-observed inner scan boundary; no second record.
    for observation in scan_host_watchdog_publications(host_state_root)? {
        let payload = &observation.lease.payload;
        if payload.installation_id != installation.as_str()
            || payload.scope_ref != observation.admission.supervision_lease_scope_id
            || observation.admission.installation_id != payload.installation_id
            || payload.activation_id != activation_id.as_str()
        {
            // A publication bound to a different installation, scope or
            // activation generation is a stale spool entry, never a live
            // obligation for this generation.
            continue;
        }
        if payload.state != eliot_runtime_contracts::LeaseState::Active
            || now_ms >= payload.expires_at_ms
        {
            continue;
        }
        return PlatformHandle::new(payload.lease_id.clone())
            .inspect(|_lease| {
                // WORK_UNIT_CASE: 979/2 — live supervision obligation observed.
                watchdog_publication_observe("watchdog.publication live obligation observed");
            })
            .map(Some)
            .map_err(|error| {
                // WORK_UNIT_CASE: 979/4 — unusable live lease identity, never reported.
                watchdog_publication_observe("watchdog.publication lease identity rejected");
                HostError::RecoveryRequired(error.to_string())
            });
    }
    // WORK_UNIT_CASE: 979/2 — no live supervision obligation; stale spool is not coverage.
    watchdog_publication_observe("watchdog.publication no live obligation");
    Ok(None)
}

#[cfg(windows)]
pub(super) fn supervision_publication_identity(
    template: &WatchdogAdmissionTemplate,
    current: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<PublishedSupervisionIdentity, HostError> {
    let lease_bytes = serde_json::to_vec(&current.record.artifact).map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unserializable lease, identity unprojected.
        watchdog_publication_observe("watchdog.publication identity serialization rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let marker = WatchdogPublicationBundle::new(
        template,
        current.record.revision,
        current.record.record_id.as_str(),
        current.receipt.receipt_sha256.clone(),
        &lease_bytes,
    )
    .map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unbindable marker, identity unprojected.
        watchdog_publication_observe("watchdog.publication identity binding rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let identity = PublishedSupervisionIdentity {
        lease_id: PlatformHandle::new(current.record.lease_id.as_str()).map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
            watchdog_publication_observe("watchdog.publication identity handle rejected");
            HostError::Platform(error.to_string())
        })?,
        ors_receipt_digest: PlatformHandle::new(current.receipt.receipt_sha256.clone()).map_err(
            |error| {
                // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
                watchdog_publication_observe("watchdog.publication identity handle rejected");
                HostError::Platform(error.to_string())
            },
        )?,
        publication_digest: PlatformHandle::new(sha256_json(&marker)?).map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
            watchdog_publication_observe("watchdog.publication identity handle rejected");
            HostError::Platform(error.to_string())
        })?,
    };
    // WORK_UNIT_CASE: 979/4 — publication identity projected with exact digests.
    watchdog_publication_observe("watchdog.publication identity projected");
    Ok(identity)
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "immutable Watchdog publication keeps ORS verification, marker-last creation, atomic commit, readback, and bounded retirement ordered"
)]
pub(super) fn publish_current_watchdog_supervision_bundle(
    host_state_root: &Path,
    manifest: &CandidateManifest,
    template: &WatchdogAdmissionTemplate,
    expected_template_digest: &str,
    kernel_snapshot: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<PublishedSupervisionIdentity, HostError> {
    // WORK_UNIT_CASE: 979/2 — publication requested, distinct from owner-observed.
    watchdog_publication_observe("watchdog.publication requested");
    template.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid template, never published.
        watchdog_publication_observe("watchdog.publication template validation rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    if template.digest().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — template digest boundary.
        watchdog_publication_observe("watchdog.publication template validation rejected");
        HostError::RecoveryRequired(error.to_string())
    })? != expected_template_digest
    {
        // WORK_UNIT_CASE: 979/3 — conflicting provisioned template, never published.
        watchdog_publication_observe("watchdog.publication template digest conflicting");
        return Err(HostError::RecoveryRequired(
            "Watchdog admission template does not match the provisioned Phase-B digest".to_owned(),
        ));
    }
    // `?` propagates the already-observed inner ORS-head boundary; no second record.
    let current = read_manifest_current_supervision_lease(
        manifest,
        kernel_snapshot.record.lease_id.as_str(),
    )?;
    if current != *kernel_snapshot {
        // WORK_UNIT_CASE: 979/3 — stale ProbeReady snapshot, never published.
        watchdog_publication_observe("watchdog.publication snapshot stale");
        return Err(HostError::RecoveryRequired(
            "Kernel ProbeReady supervision snapshot is not the current ORS head".to_owned(),
        ));
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — verification clock boundary.
            watchdog_publication_observe("watchdog.publication clock unavailable");
            HostError::RecoveryRequired(error.to_string())
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            // WORK_UNIT_CASE: 979/1 — verification clock boundary.
            watchdog_publication_observe("watchdog.publication clock unavailable");
            HostError::RecoveryRequired("system time exceeds u64".to_owned())
        })?;
    let verification_context = current
        .active_verification_context(template.trust_anchor.public_key_fingerprint(), now_ms)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverifiable snapshot, never published.
            watchdog_publication_observe("watchdog.publication verification context rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
    template
        .trust_anchor
        .verify(&current.record.artifact, &verification_context)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverified lease, never published.
            watchdog_publication_observe("watchdog.publication lease verification rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
    let admission_bytes = template.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        watchdog_publication_observe("watchdog.publication bundle serialization rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let lease_bytes = serde_json::to_vec(&current.record.artifact).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        watchdog_publication_observe("watchdog.publication bundle serialization rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let marker = WatchdogPublicationBundle::new(
        template,
        current.record.revision,
        current.record.record_id.as_str(),
        current.receipt.receipt_sha256.clone(),
        &lease_bytes,
    )
    .map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle binding boundary.
        watchdog_publication_observe("watchdog.publication bundle binding rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let marker_bytes = marker.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        watchdog_publication_observe("watchdog.publication bundle serialization rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let destination = host_state_root.join(marker.directory_name().map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — directory name not derivable, identity unproven.
        watchdog_publication_observe("watchdog.publication directory name rejected");
        HostError::RecoveryRequired(error.to_string())
    })?);

    match OwnedDirectoryPublication::create(&destination) {
        Ok(publication) => {
            let temporary = publication.temporary_path().to_path_buf();
            write_watchdog_publication_child(
                &temporary.join(WATCHDOG_ADMISSION_FILE_NAME),
                &admission_bytes,
            )?;
            write_watchdog_publication_child(
                &temporary.join(SUPERVISION_LEASE_FILE_NAME),
                &lease_bytes,
            )?;
            // Marker is created last inside the still-unpublished directory.
            write_watchdog_publication_child(
                &temporary.join(WATCHDOG_PUBLICATION_FILE_NAME),
                &marker_bytes,
            )?;
            let precommit = eliot_platform_windows::observe_owned_directory_exact(
                &temporary,
                &[
                    WATCHDOG_ADMISSION_FILE_NAME,
                    SUPERVISION_LEASE_FILE_NAME,
                    WATCHDOG_PUBLICATION_FILE_NAME,
                ],
                WATCHDOG_PUBLICATION_CHILD_LIMIT,
            )
            .map_err(|error| {
                // WORK_UNIT_CASE: 979/3 — unreadable precommit directory, never committed.
                watchdog_publication_observe("watchdog.publication precommit unreadable");
                HostError::RecoveryRequired(error.to_string())
            })?;
            // `?` propagates the already-observed inner decode/verify boundaries.
            let decoded = decode_watchdog_publication_observation(&temporary, &precommit, false)?;
            verify_exact_current_watchdog_publication(&decoded, template, &current)?;
            if precommit.directory_identity != publication.temporary_identity() {
                // WORK_UNIT_CASE: 979/3 — changed temporary identity, never committed.
                watchdog_publication_observe("watchdog.publication temporary identity changed");
                return Err(HostError::RecoveryRequired(
                    "Watchdog publication temporary directory identity changed".to_owned(),
                ));
            }
            // A concurrent exact replay may win the create-new name, and a
            // committed-unknown move may already own it. Neither outcome is
            // authority until the exact retained readback below succeeds.
            match publication.publish(precommit.directory_identity) {
                Ok(DirectoryPublicationOutcome::Published(_)) => {
                    // WORK_UNIT_CASE: 979/2 — directory committed, pending retained readback.
                    watchdog_publication_observe("watchdog.publication committed");
                }
                Ok(DirectoryPublicationOutcome::CommittedUnknown(_)) => {
                    // WORK_UNIT_CASE: 979/7 — commit outcome unknown; readback below decides.
                    watchdog_publication_observe("watchdog.publication commit unknown");
                }
                Err(DirectoryPublicationError::AlreadyExists) => {
                    // WORK_UNIT_CASE: 979/8 — concurrent exact replay retained, no new publication.
                    watchdog_publication_observe("watchdog.publication replay retained");
                }
                Err(error) => {
                    // WORK_UNIT_CASE: 979/1 — directory commit boundary.
                    watchdog_publication_observe("watchdog.publication commit rejected");
                    return Err(HostError::RecoveryRequired(format!(
                        "Watchdog directory publication failed before commit: {error}"
                    )));
                }
            }
        }
        Err(DirectoryPublicationError::AlreadyExists) => {
            // WORK_UNIT_CASE: 979/8 — concurrent exact replay retained, no new publication.
            watchdog_publication_observe("watchdog.publication replay retained");
        }
        Err(error) => {
            // WORK_UNIT_CASE: 979/1 — directory preparation boundary.
            watchdog_publication_observe("watchdog.publication preparation failed");
            return Err(HostError::RecoveryRequired(format!(
                "Watchdog directory preparation failed: {error}"
            )));
        }
    }

    // `?` propagates the already-observed inner readback/verify/reread boundaries.
    let published = observe_host_watchdog_publication(&destination)?;
    verify_exact_current_watchdog_publication(&published, template, &current)?;
    if read_manifest_current_supervision_lease(manifest, kernel_snapshot.record.lease_id.as_str())?
        != current
    {
        // WORK_UNIT_CASE: 979/3 — ORS head changed across publication, never current.
        watchdog_publication_observe("watchdog.publication ORS head changed");
        return Err(HostError::RecoveryRequired(
            "Kernel ORS head changed during Watchdog publication".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 979/2 — retained publication read back as the exact current head.
    watchdog_publication_observe("watchdog.publication observed");

    // Retirement begins only after the new exact current bundle is durable.
    let observed = scan_host_watchdog_publications(host_state_root)?;
    let markers = observed
        .iter()
        .map(|bundle| bundle.marker.clone())
        .collect::<Vec<_>>();
    let plan =
        WatchdogPublicationRetentionPlan::for_current(&marker, &markers).map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — retention plan boundary.
            watchdog_publication_observe("watchdog.publication retention plan rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
    for digest in plan.retired_receipt_digests() {
        if digest == &current.receipt.receipt_sha256 {
            // WORK_UNIT_CASE: 979/4 — current bundle protected from retirement.
            watchdog_publication_observe("watchdog.publication retention current protected");
            return Err(HostError::RecoveryRequired(
                "Watchdog retention attempted to retire the current ORS bundle".to_owned(),
            ));
        }
        let candidate = observed
            .iter()
            .find(|bundle| bundle.marker.ors_receipt_sha256 == *digest)
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 979/3 — absent retirement candidate, never retired.
                watchdog_publication_observe("watchdog.publication retirement candidate absent");
                HostError::RecoveryRequired(
                    "Watchdog retirement candidate disappeared before exact retirement".to_owned(),
                )
            })?;
        match retire_owned_directory_exact(&candidate.path, &candidate.retirement).map_err(
            |error| {
                // WORK_UNIT_CASE: 979/1 — exact retirement boundary.
                watchdog_publication_observe("watchdog.publication retirement failed");
                HostError::RecoveryRequired(error.to_string())
            },
        )? {
            OwnedDirectoryRetirementOutcome::Retired => {
                // WORK_UNIT_CASE: 979/2 — stale bundle retired; replay identity retained.
                watchdog_publication_observe("watchdog.publication stale retired");
            }
            OwnedDirectoryRetirementOutcome::CommittedUnknown(_) => {
                // WORK_UNIT_CASE: 979/7 — retirement committed unknown; absence unproven.
                watchdog_publication_observe("watchdog.publication retirement unknown");
                return Err(HostError::RecoveryRequired(
                    "Watchdog spool cleanup committed with unknown final absence".to_owned(),
                ));
            }
        }
    }
    // `?` propagates the already-observed inner scan boundary; no second record.
    let after = scan_host_watchdog_publications(host_state_root)?;
    if after.len() > WATCHDOG_PUBLICATION_RETAINED_LIMIT {
        // WORK_UNIT_CASE: 979/3 — spool above its fixed bound, never accepted.
        watchdog_publication_observe("watchdog.publication spool above bound");
        return Err(HostError::RecoveryRequired(
            "Watchdog protected spool remains above its fixed retention bound".to_owned(),
        ));
    }
    let current_after = after
        .iter()
        .find(|bundle| bundle.marker.ors_receipt_sha256 == current.receipt.receipt_sha256)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — current bundle absent after retention, never accepted.
            watchdog_publication_observe("watchdog.publication current absent");
            HostError::RecoveryRequired(
                "Watchdog current bundle disappeared during retention".to_owned(),
            )
        })?;
    // `?` propagates the already-observed inner verify/identity boundaries.
    verify_exact_current_watchdog_publication(current_after, template, &current)?;
    supervision_publication_identity(template, &current)
}
