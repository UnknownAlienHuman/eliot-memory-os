use std::{
    io,
    num::NonZeroU64,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::Digest;

use super::{
    CandidateManifest, EpochIdentity, EpochLineageId, EpochTransition, HostError,
    HostInstallationEpoch, InstallationProfile, LaunchLease, PhaseBLiveBinding, PlatformHandle,
    ProcessAuthorityHandoffDescriptor, ResourceGeneration, Sha256, UserOwnedRootLease,
    open_launch_lease, phase_b_authority_marker, phase_b_bytes_digest, phase_b_lease_bytes,
    phase_b_manifest_digest,
};

#[cfg(windows)]
// F-LOG-HOST-5 (#980) inner-phase observations for previous authority.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); Event Log
// sink disposition through the canonical
// (`crate::host_diagnostics::note_event_log_sink_status`) over the landed
// `windows_event_log` port, never probed here.
//
// Observation-only contract (mirrors `host_composition_phase_b.rs:30-41`):
// every call projects a boundary already decided by the semantic owner.
// Arguments are static literals only — no digests, paths, bytes, or error
// text are formatted, so no secret material can cross (I15.4) and no extra
// evaluation runs on the semantic path. Sink outcome never alters result,
// order, or cleanup. No terminal emission here: one terminal per failed
// operation stays with the outermost contour (`lib.rs` `HostTerminalGuard` /
// `host-phase-b-unknown`), while these inner phases correlate by stage order
// only. A prior receipt is historical evidence only, never a live
// authorization. Live admission of the current incoming
// `input.authority_descriptor_bytes` (`phase_b_validate_authority`) observes
// under the separate current-authority vocabulary below, never
// previous-binding labels.
#[cfg(windows)]
fn phase_b_previous_authority_observe(detail: &str) {
    crate::host_diagnostics::note_event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        detail,
    );
}

/// Closed observation vocabulary for live admission of the current incoming
/// authority descriptor (`phase_b_validate_authority`).
///
/// Audit 5909832545 defect 2: the current descriptor is validated for a new
/// materialization, so its request/refusal records name the live admission
/// binding, never a previous binding. The historical
/// `host.phase-b previous authority ...` labels stay with
/// `phase_b_observe_previous_binding` and
/// `phase_b_validate_durable_previous_binding` only.
#[cfg(windows)]
const PHASE_B_CURRENT_AUTHORITY_REQUESTED: &str =
    "host.phase-b current authority admission requested";
#[cfg(windows)]
const PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED: &str =
    "host.phase-b current authority admission refused: no exact live binding";

#[cfg(windows)]
fn phase_b_current_authority_observe(detail: &str) {
    crate::host_diagnostics::note_event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        detail,
    );
}

#[cfg(windows)]
#[derive(Clone, Debug)]
pub(super) struct PhaseBPreviousBinding {
    pub(super) host: HostInstallationEpoch,
    pub(super) authority: ProcessAuthorityHandoffDescriptor,
    pub(super) authority_digest: PlatformHandle,
}

#[cfg(windows)]
fn phase_b_parse_authority_marker(
    reference: &PlatformHandle,
    manifest_digest: &PlatformHandle,
    installation: &PlatformHandle,
    generation: ResourceGeneration,
) -> Option<(EpochIdentity, PlatformHandle, EpochIdentity)> {
    let payload = reference.as_str().strip_prefix("phase-b-host-v1:")?;
    let fields = serde_json::from_str::<Vec<String>>(payload).ok()?;
    if fields.len() != 8
        || fields[0] != installation.as_str()
        || fields[4] != manifest_digest.as_str()
        || fields[7].parse::<u64>().ok()? != generation.value()
    {
        return None;
    }
    let host_sequence = fields[2].parse::<u64>().ok().and_then(NonZeroU64::new)?;
    let activation_sequence = fields[6].parse::<u64>().ok().and_then(NonZeroU64::new)?;
    // Strict canonical lineage spelling: a marker carrying a non-UUID
    // lineage yields no binding (hence explicit recovery), never an
    // implicit current-lineage fallback.
    Some((
        EpochIdentity::new(EpochLineageId::new(fields[1].clone()).ok()?, host_sequence).ok()?,
        PlatformHandle::new(fields[3].clone()).ok()?,
        EpochIdentity::new(
            EpochLineageId::new(fields[5].clone()).ok()?,
            activation_sequence,
        )
        .ok()?,
    ))
}

#[cfg(windows)]
pub(super) fn phase_b_observe_previous_binding(
    manifest: &CandidateManifest,
    host: &HostInstallationEpoch,
    activation_generation: &EpochIdentity,
    portable_root: Option<&UserOwnedRootLease>,
    authority_path: &Path,
) -> Result<Option<PhaseBPreviousBinding>, HostError> {
    phase_b_previous_authority_observe("host.phase-b previous authority requested");
    let lease = match std::fs::symlink_metadata(authority_path) {
        Ok(_) => phase_b_open_existing(
            manifest.runtime_launch.profile,
            portable_root,
            authority_path,
        )?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            phase_b_previous_authority_observe(
                "host.phase-b previous authority no exact binding retained",
            );
            return Err(HostError::RecoveryRequired(format!(
                "Phase-B previous authority cannot be observed: {error}"
            )));
        }
    };
    lease.verify().map_err(|error| {
        phase_b_previous_authority_observe(
            "host.phase-b previous authority no exact binding retained",
        );
        HostError::RecoveryRequired(error)
    })?;
    let bytes = phase_b_lease_bytes(&lease)?;
    let authority: ProcessAuthorityHandoffDescriptor =
        serde_json::from_slice(&bytes).map_err(|error| {
            phase_b_previous_authority_observe(
                "host.phase-b previous authority no exact binding retained",
            );
            HostError::RecoveryRequired(format!(
                "Phase-B previous authority descriptor is not parseable: {error}"
            ))
        })?;
    authority.validate_structure().map_err(|error| {
        phase_b_previous_authority_observe(
            "host.phase-b previous authority no exact binding retained",
        );
        HostError::RecoveryRequired(format!(
            "Phase-B previous authority descriptor failed exact ORS validation: {error}"
        ))
    })?;
    let manifest_digest = phase_b_manifest_digest(manifest)?;
    if authority.state_fence.resource_generation != authority.generation {
        phase_b_previous_authority_observe(
            "host.phase-b previous authority no exact binding retained",
        );
        return Err(HostError::RecoveryRequired(
            "Phase-B previous authority has an inconsistent live resource generation".to_owned(),
        ));
    }
    let marker = authority.contour_refs.iter().find_map(|reference| {
        phase_b_parse_authority_marker(
            reference,
            &manifest_digest,
            &host.installation,
            authority.generation,
        )
    });
    let Some((previous_host_epoch, previous_nonce, previous_activation_generation)) = marker else {
        phase_b_previous_authority_observe(
            "host.phase-b previous authority no exact binding retained",
        );
        return Err(HostError::RecoveryRequired(
            "Phase-B previous authority has no exact prior Host binding".to_owned(),
        ));
    };
    if previous_host_epoch == host.epoch.current
        && previous_activation_generation == *activation_generation
        && previous_nonce == host.nonce
    {
        return Ok(None);
    }
    let authority_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    phase_b_previous_authority_observe(
        "host.phase-b previous authority historical evidence observed",
    );
    Ok(Some(PhaseBPreviousBinding {
        host: HostInstallationEpoch {
            installation: host.installation.clone(),
            epoch: EpochTransition {
                current: previous_host_epoch,
                parent: None,
            },
            nonce: previous_nonce,
            recovery: None,
        },
        authority,
        authority_digest,
    }))
}

#[cfg(windows)]
pub(super) fn phase_b_validate_durable_previous_binding(
    observed: &PhaseBPreviousBinding,
    durable: &PhaseBLiveBinding,
) -> Result<(), HostError> {
    phase_b_previous_authority_observe("host.phase-b previous authority requested");
    let observed_nonce_digest = phase_b_bytes_digest(observed.host.nonce.as_str().as_bytes())?;
    if observed.authority_digest != durable.authority_descriptor_digest
        || observed.host.epoch.current.lineage_id.as_str() != durable.host_epoch_lineage.as_str()
        || observed.host.epoch.current.sequence.get() != durable.host_epoch_sequence
        || observed_nonce_digest != durable.host_process_nonce_digest
    {
        phase_b_previous_authority_observe(
            "host.phase-b previous authority no exact binding retained",
        );
        return Err(HostError::RecoveryRequired(
            "Phase-B destination marker does not match the durable committed Phase-B binding"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_validate_authority(
    manifest: &CandidateManifest,
    host: &HostInstallationEpoch,
    activation_generation: &EpochIdentity,
    bytes: &[u8],
    allow_expired_exact_replay: bool,
) -> Result<
    (
        ProcessAuthorityHandoffDescriptor,
        PlatformHandle,
        PlatformHandle,
    ),
    HostError,
> {
    phase_b_current_authority_observe(PHASE_B_CURRENT_AUTHORITY_REQUESTED);
    let descriptor: ProcessAuthorityHandoffDescriptor =
        serde_json::from_slice(bytes).map_err(|error| {
            phase_b_current_authority_observe(PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED);
            HostError::RecoveryRequired(format!(
                "Phase-B authority descriptor is not parseable: {error}"
            ))
        })?;
    descriptor.validate_structure().map_err(|error| {
        phase_b_current_authority_observe(PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED);
        HostError::RecoveryRequired(format!(
            "Phase-B authority descriptor failed exact ORS validation: {error}"
        ))
    })?;
    if !allow_expired_exact_replay {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "Phase-B authority freshness clock is before UNIX epoch: {error}"
                ))
            })?
            .as_millis()
            .try_into()
            .map_err(|_| {
                HostError::RecoveryRequired(
                    "Phase-B authority freshness clock is outside the supported range".to_owned(),
                )
            })?;
        descriptor.validate(now_ms).map_err(|error| {
            phase_b_current_authority_observe(PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED);
            HostError::RecoveryRequired(format!(
                "Phase-B authority descriptor is not fresh for admission: {error}"
            ))
        })?;
    }
    if !descriptor
        .state_fence
        .authority_epoch
        .is_same_authority(&host.epoch.current)
        || descriptor.state_fence.resource_generation != descriptor.generation
    {
        phase_b_current_authority_observe(PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED);
        return Err(HostError::RecoveryRequired(
            "Phase-B authority descriptor is not bound to a consistent live generation and Host epoch"
                .to_owned(),
        ));
    }
    let manifest_digest = phase_b_manifest_digest(manifest)?;
    let marker =
        phase_b_authority_marker(&manifest_digest, host, activation_generation, &descriptor)?;
    if !descriptor
        .contour_refs
        .iter()
        .any(|reference| reference == &marker)
    {
        phase_b_current_authority_observe(PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED);
        return Err(HostError::RecoveryRequired(
            "Phase-B authority descriptor is missing the exact Host/activation binding".to_owned(),
        ));
    }
    let descriptor_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok((descriptor, manifest_digest, descriptor_digest))
}

#[cfg(windows)]
pub(super) fn phase_b_open_existing(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
) -> Result<LaunchLease, HostError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => open_launch_lease(profile, portable_root, path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(HostError::RecoveryRequired(
            format!("Phase-B required file is missing: {}", path.display()),
        )),
        Err(error) => Err(HostError::RecoveryRequired(format!(
            "Phase-B required file cannot be observed: {error}"
        ))),
    }
}

#[cfg(windows)]
pub(super) fn phase_b_authority_is_observable(
    manifest: &CandidateManifest,
) -> Result<bool, HostError> {
    let path = Path::new(manifest.runtime_launch.authority_descriptor_path.as_str());
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(HostError::RecoveryRequired(format!(
            "Phase-B authority destination cannot be observed: {error}"
        ))),
    }
}

#[cfg(all(test, windows))]
mod phase_b_current_authority_vocabulary_tests {
    use super::{PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED, PHASE_B_CURRENT_AUTHORITY_REQUESTED};

    /// Audit 5909832545 defect 2, positive: live admission of the current
    /// incoming descriptor owns a dedicated vocabulary naming the live
    /// admission binding.
    #[test]
    fn current_authority_admission_vocabulary_names_live_binding() {
        for label in [
            PHASE_B_CURRENT_AUTHORITY_REQUESTED,
            PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED,
        ] {
            assert!(
                label.contains("host.phase-b current authority"),
                "live admission label must name the current authority: {label:?}"
            );
            assert!(
                label.contains("admission"),
                "live admission label must name admission, not readback: {label:?}"
            );
        }
        assert_ne!(
            PHASE_B_CURRENT_AUTHORITY_REQUESTED,
            PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED
        );
    }

    /// Audit 5909832545 defect 2, refusal: the current-authority vocabulary
    /// never reads as a previous binding, and the historical vocabulary is
    /// untouched.
    #[test]
    fn current_authority_vocabulary_never_reads_as_previous_binding() {
        for label in [
            PHASE_B_CURRENT_AUTHORITY_REQUESTED,
            PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED,
        ] {
            assert!(
                !label.contains("previous"),
                "current admission must never emit previous-binding labels: {label:?}"
            );
        }
        for historical in [
            "host.phase-b previous authority requested",
            "host.phase-b previous authority no exact binding retained",
            "host.phase-b previous authority historical evidence observed",
        ] {
            assert!(historical.contains("previous"));
            assert_ne!(historical, PHASE_B_CURRENT_AUTHORITY_REQUESTED);
            assert_ne!(historical, PHASE_B_CURRENT_AUTHORITY_NOT_ADMITTED);
        }
    }
}
