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
    host_composition_phase_b::{PhaseBAuthorityIdentity, phase_b_observe_authority},
    open_launch_lease, phase_b_authority_marker, phase_b_bytes_digest, phase_b_lease_bytes,
    phase_b_manifest_digest,
};

#[cfg(windows)]
// F-LOG-HOST-5 (#980) inner-phase observations for the Phase-B authority
// contour, in TWO closed vocabularies.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`, reached through
// `super::host_composition_phase_b::phase_b_observe_authority`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract (mirrors `host_composition_phase_b.rs:30-41`):
// every call projects a boundary already decided by the semantic owner and
// reuses that module's identity projection, so no second observation scheme
// exists. Two distinct owner contours keep two distinct closed vocabularies:
//
//   * HISTORICAL — `phase_b_observe_previous_binding` and
//     `phase_b_validate_durable_previous_binding` read back the RETAINED
//     previous/destination authority. Their labels keep the historical
//     "previous authority" vocabulary. A prior receipt here is historical
//     evidence only, never a live authorization.
//   * CURRENT/LIVE — `phase_b_validate_authority` admits the INCOMING
//     `input.authority_descriptor_bytes` for this materialization. Its labels
//     are current-authority only and never name a previous binding, so a live
//     admission failure can no longer be reported as a failure to recover a
//     previous binding.
//
// Every record also carries the operation identity its owner already holds
// (installation, live Host epoch, current activation generation, the record's
// own Host epoch, State Fence, verified declared descriptor digest, physical
// descriptor digest, committed durable descriptor digest) or an explicit
// `unavailable` missing-evidence disposition. Arguments are identity values
// and frozen literals only — no bytes, payload, raw path, credential value, or
// error text are formatted, so no secret material can cross (I15.4). Sink
// outcome never alters result, order, or cleanup. No terminal emission here:
// one terminal per failed operation stays with the outermost contour
// (`lib.rs` `HostTerminalGuard` / `host-phase-b-unknown`); these inner records
// correlate to it by the bound operation identity, never by stage order
// alone.
#[cfg(windows)]
fn phase_b_previous_authority_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn phase_b_previous_authority_observe_bound(
    label: &'static str,
    manifest: &CandidateManifest,
    manifest_digest: Option<&str>,
    identity: &PhaseBAuthorityIdentity,
) {
    phase_b_previous_authority_note_event_log_unavailable();
    phase_b_observe_authority(label, manifest, manifest_digest, identity);
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
#[allow(
    clippy::too_many_lines,
    reason = "the previous-binding readback keeps its ordered lease/parse/structure/marker contour auditable next to each observation"
)]
pub(super) fn phase_b_observe_previous_binding(
    manifest: &CandidateManifest,
    host: &HostInstallationEpoch,
    activation_generation: &EpochIdentity,
    portable_root: Option<&UserOwnedRootLease>,
    authority_path: &Path,
    identity: &mut PhaseBAuthorityIdentity,
) -> Result<Option<PhaseBPreviousBinding>, HostError> {
    phase_b_previous_authority_observe_bound(
        "host.phase-b previous authority requested",
        manifest,
        None,
        identity,
    );
    let lease = match std::fs::symlink_metadata(authority_path) {
        Ok(_) => phase_b_open_existing(
            manifest.runtime_launch.profile,
            portable_root,
            authority_path,
        )?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            phase_b_previous_authority_observe_bound(
                "host.phase-b previous authority no exact binding retained",
                manifest,
                None,
                identity,
            );
            return Err(HostError::RecoveryRequired(format!(
                "Phase-B previous authority cannot be observed: {error}"
            )));
        }
    };
    lease.verify().map_err(|error| {
        phase_b_previous_authority_observe_bound(
            "host.phase-b previous authority no exact binding retained",
            manifest,
            None,
            identity,
        );
        HostError::RecoveryRequired(error)
    })?;
    let bytes = phase_b_lease_bytes(&lease)?;
    let authority: ProcessAuthorityHandoffDescriptor =
        serde_json::from_slice(&bytes).map_err(|error| {
            phase_b_previous_authority_observe_bound(
                "host.phase-b previous authority no exact binding retained",
                manifest,
                None,
                identity,
            );
            HostError::RecoveryRequired(format!(
                "Phase-B previous authority descriptor is not parseable: {error}"
            ))
        })?;
    // Exact structure validation is the owner that proves the declared digest,
    // so the descriptor identity is projected only from here on.
    authority.validate_structure().map_err(|error| {
        phase_b_previous_authority_observe_bound(
            "host.phase-b previous authority no exact binding retained",
            manifest,
            None,
            identity,
        );
        HostError::RecoveryRequired(format!(
            "Phase-B previous authority descriptor failed exact ORS validation: {error}"
        ))
    })?;
    identity.bind_state_fence(&authority.state_fence);
    identity.bind_declared_descriptor(&authority);
    let manifest_digest = phase_b_manifest_digest(manifest)?;
    if authority.state_fence.resource_generation != authority.generation {
        phase_b_previous_authority_observe_bound(
            "host.phase-b previous authority no exact binding retained",
            manifest,
            Some(manifest_digest.as_str()),
            identity,
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
        phase_b_previous_authority_observe_bound(
            "host.phase-b previous authority no exact binding retained",
            manifest,
            Some(manifest_digest.as_str()),
            identity,
        );
        return Err(HostError::RecoveryRequired(
            "Phase-B previous authority has no exact prior Host binding".to_owned(),
        ));
    };
    // The marker parse above is the owner that proved this prior Host epoch
    // against this exact installation, manifest digest, and generation, so the
    // bind happens only after that verification, from the parsed marker.
    identity.bind_host_epoch(&previous_host_epoch);
    if previous_host_epoch == host.epoch.current
        && previous_activation_generation == *activation_generation
        && previous_nonce == host.nonce
    {
        return Ok(None);
    }
    let authority_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    identity.bind_authority_descriptor(&authority_digest);
    phase_b_previous_authority_observe_bound(
        "host.phase-b previous authority historical evidence observed",
        manifest,
        Some(manifest_digest.as_str()),
        identity,
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
    manifest: &CandidateManifest,
    manifest_digest: &str,
    identity: &mut PhaseBAuthorityIdentity,
) -> Result<(), HostError> {
    // Both sides of this exact comparison are already produced: the observed
    // historical descriptor digest and the committed durable expectation. The
    // bound epoch is the one the caller's marker parse already proved against
    // this exact installation, manifest digest, and generation — a proven
    // value of the retained record, never an unverified claim.
    identity.bind_host_epoch(&observed.host.epoch.current);
    identity.bind_authority_descriptor(&observed.authority_digest);
    identity.bind_durable_authority_descriptor(&durable.authority_descriptor_digest);
    phase_b_previous_authority_observe_bound(
        "host.phase-b previous authority requested",
        manifest,
        Some(manifest_digest),
        identity,
    );
    let observed_nonce_digest = phase_b_bytes_digest(observed.host.nonce.as_str().as_bytes())?;
    if observed.authority_digest != durable.authority_descriptor_digest
        || observed.host.epoch.current.lineage_id.as_str() != durable.host_epoch_lineage.as_str()
        || observed.host.epoch.current.sequence.get() != durable.host_epoch_sequence
        || observed_nonce_digest != durable.host_process_nonce_digest
    {
        phase_b_previous_authority_observe_bound(
            "host.phase-b previous authority no exact binding retained",
            manifest,
            Some(manifest_digest),
            identity,
        );
        return Err(HostError::RecoveryRequired(
            "Phase-B destination marker does not match the durable committed Phase-B binding"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
// F-LOG-HOST-5 (#980) CURRENT/live authority admission.
//
// This validates the INCOMING `input.authority_descriptor_bytes` of the new
// materialization against the live Host epoch, the current activation
// generation, and the exact manifest. It is not a previous-binding readback,
// so every label below is current-authority vocabulary and none of them names
// a previous binding.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "current authority admission keeps its ordered parse/structure/freshness/fence/marker contour auditable next to each observation"
)]
pub(super) fn phase_b_validate_authority(
    manifest: &CandidateManifest,
    host: &HostInstallationEpoch,
    activation_generation: &EpochIdentity,
    bytes: &[u8],
    allow_expired_exact_replay: bool,
    identity: &mut PhaseBAuthorityIdentity,
) -> Result<
    (
        ProcessAuthorityHandoffDescriptor,
        PlatformHandle,
        PlatformHandle,
    ),
    HostError,
> {
    phase_b_previous_authority_observe_bound(
        "host.phase-b current authority descriptor requested",
        manifest,
        None,
        identity,
    );
    let descriptor: ProcessAuthorityHandoffDescriptor =
        serde_json::from_slice(bytes).map_err(|error| {
            phase_b_previous_authority_observe_bound(
                "host.phase-b current authority descriptor not parseable",
                manifest,
                None,
                identity,
            );
            HostError::RecoveryRequired(format!(
                "Phase-B authority descriptor is not parseable: {error}"
            ))
        })?;
    // Exact structure validation is the owner that proves the declared digest,
    // so the descriptor identity is projected only from here on.
    descriptor.validate_structure().map_err(|error| {
        phase_b_previous_authority_observe_bound(
            "host.phase-b current authority descriptor structure rejected",
            manifest,
            None,
            identity,
        );
        HostError::RecoveryRequired(format!(
            "Phase-B authority descriptor failed exact ORS validation: {error}"
        ))
    })?;
    identity.bind_state_fence(&descriptor.state_fence);
    identity.bind_declared_descriptor(&descriptor);
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
        phase_b_previous_authority_observe_bound(
            "host.phase-b current authority descriptor fence generation inconsistent",
            manifest,
            None,
            identity,
        );
        return Err(HostError::RecoveryRequired(
            "Phase-B authority descriptor is not bound to a consistent live generation and Host epoch"
                .to_owned(),
        ));
    }
    // The record's own Host epoch is the LIVE epoch, and it is bound here and
    // only here: the exact `is_same_authority` match above is what proves the
    // descriptor's claimed authority epoch and the live Host epoch are the same
    // authority. Binding the claim itself before that proof would put an
    // owner-unproven Host epoch into a slot that documents the record's PROVEN
    // one (and would only restate `fence`), so a rejected descriptor now leaves
    // this slot at its explicit missing-evidence disposition instead.
    identity.bind_host_epoch(&host.epoch.current);
    let manifest_digest = phase_b_manifest_digest(manifest)?;
    let marker =
        phase_b_authority_marker(&manifest_digest, host, activation_generation, &descriptor)?;
    if !descriptor
        .contour_refs
        .iter()
        .any(|reference| reference == &marker)
    {
        phase_b_previous_authority_observe_bound(
            "host.phase-b current authority descriptor missing exact host activation binding",
            manifest,
            Some(manifest_digest.as_str()),
            identity,
        );
        return Err(HostError::RecoveryRequired(
            "Phase-B authority descriptor is missing the exact Host/activation binding".to_owned(),
        ));
    }
    let descriptor_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    identity.bind_authority_descriptor(&descriptor_digest);
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
