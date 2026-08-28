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

#[cfg(windows)]
const WATCHDOG_PUBLICATION_CHILD_LIMIT: u64 = 1024 * 1024;
#[cfg(windows)]
const KERNEL_ORS_FILE_NAME: &str = "kernel-ors.redb";
#[cfg(windows)]
fn write_watchdog_publication_child(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_SHARE_READ,
    };

    if bytes.len() as u64 > WATCHDOG_PUBLICATION_CHILD_LIMIT {
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
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    if !metadata.is_file()
        || metadata.len() != bytes.len() as u64
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child identity is invalid".to_owned(),
        ));
    }
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let mut readback = Vec::with_capacity(bytes.len());
    file.read_to_end(&mut readback)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    if readback != bytes {
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child readback changed".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn read_manifest_current_supervision_lease(
    manifest: &CandidateManifest,
    lease_id: &str,
) -> Result<eliot_ors::SupervisionLeaseSnapshot, HostError> {
    let lease_id = OperationIdentity::new(lease_id.to_owned())
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let ors_path = PathBuf::from(
        manifest
            .runtime_launch
            .runtime_state_roots
            .kernel_ors_root
            .as_str(),
    )
    .join(KERNEL_ORS_FILE_NAME);
    let retained = ProtectedRuntimePathLease::open_existing_absolute(&ors_path)
        .map_err(|error| HostError::RecoveryRequired(format!("Kernel ORS open failed: {error}")))?;
    if !windows_paths_equal(retained.path(), &ors_path) {
        return Err(HostError::RecoveryRequired(
            "Kernel ORS path is not the manifest-selected child".to_owned(),
        ));
    }
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| HostError::RecoveryRequired(format!("Kernel ORS changed: {error}")))?;
    let current = eliot_ors::read_current_supervision_lease_read_only(retained.path(), &lease_id)
        .map_err(|error| HostError::RecoveryRequired(format!("Kernel ORS read failed: {error}")))?
        .ok_or_else(|| {
            HostError::RecoveryRequired("Kernel ORS has no current supervision lease".to_owned())
        })?;
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| HostError::RecoveryRequired(format!("Kernel ORS changed: {error}")))?;
    current
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    Ok(current)
}

#[cfg(windows)]
pub(super) fn supervision_publication_identity(
    template: &WatchdogAdmissionTemplate,
    current: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<PublishedSupervisionIdentity, HostError> {
    let lease_bytes = serde_json::to_vec(&current.record.artifact)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let marker = WatchdogPublicationBundle::new(
        template,
        current.record.revision,
        current.record.record_id.as_str(),
        current.receipt.receipt_sha256.clone(),
        &lease_bytes,
    )
    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    Ok(PublishedSupervisionIdentity {
        lease_id: PlatformHandle::new(current.record.lease_id.as_str())
            .map_err(|error| HostError::Platform(error.to_string()))?,
        ors_receipt_digest: PlatformHandle::new(current.receipt.receipt_sha256.clone())
            .map_err(|error| HostError::Platform(error.to_string()))?,
        publication_digest: PlatformHandle::new(sha256_json(&marker)?)
            .map_err(|error| HostError::Platform(error.to_string()))?,
    })
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
    template
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    if template
        .digest()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
        != expected_template_digest
    {
        return Err(HostError::RecoveryRequired(
            "Watchdog admission template does not match the provisioned Phase-B digest".to_owned(),
        ));
    }
    let current = read_manifest_current_supervision_lease(
        manifest,
        kernel_snapshot.record.lease_id.as_str(),
    )?;
    if current != *kernel_snapshot {
        return Err(HostError::RecoveryRequired(
            "Kernel ProbeReady supervision snapshot is not the current ORS head".to_owned(),
        ));
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| HostError::RecoveryRequired("system time exceeds u64".to_owned()))?;
    let verification_context = current
        .active_verification_context(template.trust_anchor.public_key_fingerprint(), now_ms)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    template
        .trust_anchor
        .verify(&current.record.artifact, &verification_context)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let admission_bytes = template
        .canonical_bytes()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let lease_bytes = serde_json::to_vec(&current.record.artifact)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let marker = WatchdogPublicationBundle::new(
        template,
        current.record.revision,
        current.record.record_id.as_str(),
        current.receipt.receipt_sha256.clone(),
        &lease_bytes,
    )
    .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let marker_bytes = marker
        .canonical_bytes()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let destination = host_state_root.join(
        marker
            .directory_name()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?,
    );

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
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let decoded = decode_watchdog_publication_observation(&temporary, &precommit, false)?;
            verify_exact_current_watchdog_publication(&decoded, template, &current)?;
            if precommit.directory_identity != publication.temporary_identity() {
                return Err(HostError::RecoveryRequired(
                    "Watchdog publication temporary directory identity changed".to_owned(),
                ));
            }
            // A concurrent exact replay may win the create-new name, and a
            // committed-unknown move may already own it. Neither outcome is
            // authority until the exact retained readback below succeeds.
            match publication.publish(precommit.directory_identity) {
                Ok(
                    DirectoryPublicationOutcome::Published(_)
                    | DirectoryPublicationOutcome::CommittedUnknown(_),
                )
                | Err(DirectoryPublicationError::AlreadyExists) => {}
                Err(error) => {
                    return Err(HostError::RecoveryRequired(format!(
                        "Watchdog directory publication failed before commit: {error}"
                    )));
                }
            }
        }
        Err(DirectoryPublicationError::AlreadyExists) => {}
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Watchdog directory preparation failed: {error}"
            )));
        }
    }

    let published = observe_host_watchdog_publication(&destination)?;
    verify_exact_current_watchdog_publication(&published, template, &current)?;
    if read_manifest_current_supervision_lease(manifest, kernel_snapshot.record.lease_id.as_str())?
        != current
    {
        return Err(HostError::RecoveryRequired(
            "Kernel ORS head changed during Watchdog publication".to_owned(),
        ));
    }

    // Retirement begins only after the new exact current bundle is durable.
    let observed = scan_host_watchdog_publications(host_state_root)?;
    let markers = observed
        .iter()
        .map(|bundle| bundle.marker.clone())
        .collect::<Vec<_>>();
    let plan = WatchdogPublicationRetentionPlan::for_current(&marker, &markers)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    for digest in plan.retired_receipt_digests() {
        if digest == &current.receipt.receipt_sha256 {
            return Err(HostError::RecoveryRequired(
                "Watchdog retention attempted to retire the current ORS bundle".to_owned(),
            ));
        }
        let candidate = observed
            .iter()
            .find(|bundle| bundle.marker.ors_receipt_sha256 == *digest)
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Watchdog retirement candidate disappeared before exact retirement".to_owned(),
                )
            })?;
        match retire_owned_directory_exact(&candidate.path, &candidate.retirement)
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
        {
            OwnedDirectoryRetirementOutcome::Retired => {}
            OwnedDirectoryRetirementOutcome::CommittedUnknown(_) => {
                return Err(HostError::RecoveryRequired(
                    "Watchdog spool cleanup committed with unknown final absence".to_owned(),
                ));
            }
        }
    }
    let after = scan_host_watchdog_publications(host_state_root)?;
    if after.len() > WATCHDOG_PUBLICATION_RETAINED_LIMIT {
        return Err(HostError::RecoveryRequired(
            "Watchdog protected spool remains above its fixed retention bound".to_owned(),
        ));
    }
    let current_after = after
        .iter()
        .find(|bundle| bundle.marker.ors_receipt_sha256 == current.receipt.receipt_sha256)
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "Watchdog current bundle disappeared during retention".to_owned(),
            )
        })?;
    verify_exact_current_watchdog_publication(current_after, template, &current)?;
    supervision_publication_identity(template, &current)
}
