use std::path::Path;

use sha2::Digest;

use super::{
    EliotdLaunchDescriptor, HostError, HostInstallationEpoch, HostPhaseBMaterialization,
    HostPhaseBPreparedMaterialization, HostStoreBootstrapRequirement, InstallationEpoch,
    InstallationProfile, PhaseBLiveBinding, PhaseBPreviousBinding, PlatformHandle,
    ProcessAuthorityHandoffDescriptor, ProvisionedSupervisionAuthority, RuntimeLaunchDescriptor,
    STORE_SEMANTIC_CONFIG_HASH_PENDING, Sha256, UserOwnedRootLease, phase_b_bytes_digest,
    phase_b_lease_bytes, phase_b_open_existing, semantic_store_config_hash_from_json, sha256_json,
};

#[cfg(windows)]
// F-LOG-HOST-5 (#980) inner-phase observations for previous projection.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract (mirrors `host_composition_phase_b.rs:30-41`):
// every call projects a boundary already decided by the semantic owner.
// Arguments are static literals only — no digests, bytes, paths, or error
// text are formatted, so no secret material can cross (I15.4) and no extra
// evaluation runs on the semantic path. Sink outcome never alters result,
// order, or cleanup. No terminal emission here: one terminal per failed
// operation stays with the outermost contour (`lib.rs` `HostTerminalGuard` /
// `host-phase-b-unknown`), while these inner phases correlate by stage order
// only. A mismatch retains its typed `RecoveryRequired` cause.
#[cfg(windows)]
fn phase_b_previous_projection_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn phase_b_previous_projection_observe(detail: &str) {
    phase_b_previous_projection_note_event_log_unavailable();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        detail,
    );
}

#[cfg(windows)]
pub(super) fn phase_b_live_installation_epoch(host: &HostInstallationEpoch) -> InstallationEpoch {
    InstallationEpoch {
        installation: host.installation.clone(),
        lineage_id: PlatformHandle::new(host.epoch.current.lineage_id.as_str())
            .unwrap_or_else(|_| unreachable!()),
        sequence: host.epoch.current.sequence.get(),
    }
}

#[cfg(windows)]
pub(super) fn phase_b_json_string(
    value: &serde_json::Value,
    field: &str,
) -> Result<String, HostError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!("Store config field {field} is missing"))
        })
}

#[cfg(windows)]
pub(super) fn phase_b_json_u64(value: &serde_json::Value, field: &str) -> Result<u64, HostError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!("Store config field {field} is missing"))
        })
}

#[cfg(windows)]
pub(super) fn phase_b_previous_live_launch(
    template: &RuntimeLaunchDescriptor,
    previous: &PhaseBPreviousBinding,
    previous_eliotd_digest: Option<&PlatformHandle>,
    provisioned_supervision_authority: &ProvisionedSupervisionAuthority,
) -> Result<RuntimeLaunchDescriptor, HostError> {
    phase_b_live_launch(
        template,
        &previous.host,
        &previous.authority,
        &previous.authority_digest,
        previous_eliotd_digest.unwrap_or(&template.eliotd_descriptor_digest),
        provisioned_supervision_authority,
    )
}

#[cfg(windows)]
pub(super) fn phase_b_previous_config_value(
    template_bytes: &[u8],
    template: &RuntimeLaunchDescriptor,
    previous: &PhaseBPreviousBinding,
    previous_store_bootstrap: &PhaseBPreviousStoreBootstrap,
    previous_eliotd_digest: Option<&PlatformHandle>,
    provisioned_supervision_authority: &ProvisionedSupervisionAuthority,
) -> Result<serde_json::Value, HostError> {
    let mut config =
        serde_json::from_slice::<serde_json::Value>(template_bytes).map_err(|error| {
            HostError::RecoveryRequired(format!("read prior Store config template: {error}"))
        })?;
    let launch = phase_b_previous_live_launch(
        template,
        previous,
        previous_eliotd_digest,
        provisioned_supervision_authority,
    )?;
    {
        let object = config.as_object_mut().ok_or_else(|| {
            HostError::RecoveryRequired(
                "prior Store config template root is not an object".to_owned(),
            )
        })?;
        object.insert(
            "expected_client_sid".to_owned(),
            serde_json::Value::String(
                previous_store_bootstrap
                    .expected_peer_sid
                    .as_str()
                    .to_owned(),
            ),
        );
        object.insert(
            "expected_client_session_id".to_owned(),
            serde_json::Value::from(previous_store_bootstrap.expected_peer_session_id),
        );
        object.insert(
            "launch_nonce".to_owned(),
            serde_json::Value::String(previous.host.nonce.as_str().to_owned()),
        );
        object.insert(
            "runtime_launch".to_owned(),
            serde_json::to_value(&launch)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        );
        object.insert(
            "approved_config_hash".to_owned(),
            serde_json::Value::String(STORE_SEMANTIC_CONFIG_HASH_PENDING.to_owned()),
        );
    }
    let without_hash = serde_json::to_vec(&config)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let semantic = semantic_store_config_hash_from_json(&without_hash)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    config
        .as_object_mut()
        .ok_or_else(|| {
            HostError::RecoveryRequired("prior Store config root is not an object".to_owned())
        })?
        .insert(
            "approved_config_hash".to_owned(),
            serde_json::Value::String(semantic.as_str().to_owned()),
        );
    let config_bytes = serde_json::to_vec(&config)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if phase_b_bytes_digest(&config_bytes)? != previous_store_bootstrap.config_file_digest
        || semantic != previous_store_bootstrap.semantic_config_hash
    {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(
            "prior Store config projection differs from its original physical Phase-B digest"
                .to_owned(),
        ));
    }
    Ok(config)
}

#[cfg(windows)]
#[allow(
    clippy::too_many_arguments,
    reason = "the exact prior-config readback binds each physical path, template, live epoch, and prior Host contour"
)]
pub(super) fn phase_b_previous_config_digest(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    template_digest: &PlatformHandle,
    template_bytes: &[u8],
    template: &RuntimeLaunchDescriptor,
    previous: Option<&PhaseBPreviousBinding>,
    previous_store_bootstrap: Option<&PhaseBPreviousStoreBootstrap>,
    previous_eliotd_digest: Option<&PlatformHandle>,
    provisioned_supervision_authority: &ProvisionedSupervisionAuthority,
) -> Result<Option<PlatformHandle>, HostError> {
    phase_b_previous_projection_observe("host.phase-b prior-projection requested");
    let lease = phase_b_open_existing(profile, portable_root, path)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    let current = phase_b_lease_bytes(&lease)?;
    if current == desired {
        return Ok(None);
    }
    let digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&current)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if &digest == template_digest {
        return Ok(None);
    }
    let previous = previous.ok_or_else(|| {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        HostError::RecoveryRequired(
            "Store config is neither the immutable Phase-A template nor an exact prior Phase-B contour"
                .to_owned(),
        )
    })?;
    let current_value = serde_json::from_slice::<serde_json::Value>(&current).map_err(|error| {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        HostError::RecoveryRequired(format!("prior Store config is not valid JSON: {error}"))
    })?;
    let previous_store_bootstrap = previous_store_bootstrap.ok_or_else(|| {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        HostError::RecoveryRequired(
            "prior Store config has no digest-bound Store bootstrap identity".to_owned(),
        )
    })?;
    if current_value
        != phase_b_previous_config_value(
            template_bytes,
            template,
            previous,
            previous_store_bootstrap,
            previous_eliotd_digest,
            provisioned_supervision_authority,
        )?
    {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(
            "prior Store config is not the exact previous Host materialization".to_owned(),
        ));
    }
    Ok(Some(digest))
}

#[cfg(windows)]
pub(super) fn phase_b_previous_eliotd_digest(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    template_digest: &PlatformHandle,
    template_bytes: &[u8],
    previous: Option<&PhaseBPreviousBinding>,
) -> Result<Option<PlatformHandle>, HostError> {
    phase_b_previous_projection_observe("host.phase-b prior-projection requested");
    let lease = phase_b_open_existing(profile, portable_root, path)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    let current = phase_b_lease_bytes(&lease)?;
    if current == desired {
        return Ok(None);
    }
    let digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&current)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if &digest == template_digest {
        return Ok(None);
    }
    let previous = previous.ok_or_else(|| {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        HostError::RecoveryRequired(
            "eliotd descriptor is neither the immutable Phase-A template nor an exact prior Phase-B contour"
                .to_owned(),
        )
    })?;
    let mut expected: EliotdLaunchDescriptor =
        serde_json::from_slice(template_bytes).map_err(|error| {
            phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
            HostError::RecoveryRequired(format!(
                "prior eliotd descriptor is not parseable: {error}"
            ))
        })?;
    expected.authority_epoch = previous.authority.state_fence.authority_epoch.clone();
    expected.generation = previous.authority.generation;
    let expected = expected
        .with_computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let current_descriptor: EliotdLaunchDescriptor =
        serde_json::from_slice(&current).map_err(|error| {
            phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
            HostError::RecoveryRequired(format!(
                "prior eliotd descriptor is not parseable: {error}"
            ))
        })?;
    if current_descriptor != expected {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(
            "prior eliotd descriptor is not the exact previous Host materialization".to_owned(),
        ));
    }
    Ok(Some(digest))
}

#[cfg(windows)]
pub(super) struct PhaseBPreviousStoreBootstrap {
    pub(super) digest: Option<PlatformHandle>,
    pub(super) requirement: Option<HostStoreBootstrapRequirement>,
    pub(super) expected_peer_sid: PlatformHandle,
    pub(super) expected_peer_session_id: u32,
    pub(super) config_file_digest: PlatformHandle,
    pub(super) semantic_config_hash: PlatformHandle,
}

#[cfg(windows)]
struct PhaseBPreviousProjectionFileInput<'a> {
    profile: InstallationProfile,
    portable_root: Option<&'a UserOwnedRootLease>,
    path: &'a Path,
    desired: &'a [u8],
    template_digest: &'a PlatformHandle,
    durable_digest: Option<&'a PlatformHandle>,
    prepared_digest: Option<&'a PlatformHandle>,
    allow_missing: bool,
    label: &'static str,
}

#[cfg(windows)]
struct PhaseBPreviousProjectionFile {
    bytes: Vec<u8>,
    digest: PlatformHandle,
    is_current: bool,
}

#[cfg(windows)]
impl PhaseBPreviousProjectionFile {
    fn is_template(&self, template_digest: &PlatformHandle) -> bool {
        &self.digest == template_digest
    }
}

#[cfg(windows)]
struct PhaseBPreviousProjectionDigestBinding {
    config_file_digest: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    semantic_config_hash: PlatformHandle,
}

#[cfg(windows)]
pub(super) struct PhaseBPreviousStoreBootstrapInput<'a> {
    pub(super) profile: InstallationProfile,
    pub(super) portable_root: Option<&'a UserOwnedRootLease>,
    pub(super) config_path: &'a Path,
    pub(super) config_desired: &'a [u8],
    pub(super) config_template_digest: &'a PlatformHandle,
    pub(super) bootstrap_path: &'a Path,
    pub(super) bootstrap_desired: &'a [u8],
    pub(super) bootstrap_template_digest: &'a PlatformHandle,
    pub(super) previous: Option<&'a PhaseBPreviousBinding>,
    pub(super) durable: Option<&'a PhaseBLiveBinding>,
    pub(super) prepared: Option<&'a HostPhaseBPreparedMaterialization>,
}

#[cfg(windows)]
fn phase_b_previous_projection_file(
    input: &PhaseBPreviousProjectionFileInput<'_>,
) -> Result<Option<PhaseBPreviousProjectionFile>, HostError> {
    if let Err(error) = std::fs::symlink_metadata(input.path) {
        if error.kind() == std::io::ErrorKind::NotFound
            && input.allow_missing
            && input.durable_digest.is_none()
        {
            return Ok(None);
        }
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(format!(
            "prior Store {} cannot be observed: {error}",
            input.label
        )));
    }
    let lease = phase_b_open_existing(input.profile, input.portable_root, input.path)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    let bytes = phase_b_lease_bytes(&lease)?;
    let digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let observation = PhaseBPreviousProjectionFile {
        is_current: bytes == input.desired,
        bytes,
        digest,
    };
    if !observation.is_current
        && !observation.is_template(input.template_digest)
        && !input
            .durable_digest
            .is_some_and(|expected| observation.digest == *expected)
        && !input
            .prepared_digest
            .is_some_and(|expected| observation.digest == *expected)
    {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(format!(
            "prior Store {} is neither current/template bytes nor bound by an original Phase-B digest",
            input.label
        )));
    }
    Ok(Some(observation))
}

#[cfg(windows)]
fn phase_b_previous_projection_digest_binding(
    config: &PhaseBPreviousProjectionFile,
    bootstrap: &PhaseBPreviousProjectionFile,
    durable: Option<&PhaseBLiveBinding>,
    prepared: Option<&HostPhaseBPreparedMaterialization>,
) -> Option<PhaseBPreviousProjectionDigestBinding> {
    if let Some(durable) = durable
        && (config.digest == durable.config_file_digest
            || bootstrap.digest == durable.store_bootstrap_descriptor_digest)
    {
        return Some(PhaseBPreviousProjectionDigestBinding {
            config_file_digest: durable.config_file_digest.clone(),
            store_bootstrap_descriptor_digest: durable.store_bootstrap_descriptor_digest.clone(),
            semantic_config_hash: durable.semantic_config_hash.clone(),
        });
    }
    if let Some(prepared) = prepared
        && (config.digest == prepared.config_file_digest
            || bootstrap.digest == prepared.store_bootstrap_descriptor_digest)
    {
        return Some(PhaseBPreviousProjectionDigestBinding {
            config_file_digest: prepared.config_file_digest.clone(),
            store_bootstrap_descriptor_digest: prepared.store_bootstrap_descriptor_digest.clone(),
            semantic_config_hash: prepared.semantic_config_hash.clone(),
        });
    }
    None
}

#[cfg(windows)]
fn phase_b_previous_store_bootstrap_requirement(
    file: &PhaseBPreviousProjectionFile,
    binding: &PhaseBPreviousProjectionDigestBinding,
    previous: &PhaseBPreviousBinding,
) -> Result<Option<HostStoreBootstrapRequirement>, HostError> {
    if file.digest != binding.store_bootstrap_descriptor_digest {
        return Ok(None);
    }
    let requirement: HostStoreBootstrapRequirement =
        serde_json::from_slice(&file.bytes).map_err(|error| {
            phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
            HostError::RecoveryRequired(format!("prior Store bootstrap is not parseable: {error}"))
        })?;
    requirement
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if requirement.launch_nonce != previous.host.nonce
        || requirement.state_fence != previous.authority.state_fence
        || requirement.store_generation != previous.authority.generation
        || requirement.approved_config_hash != binding.semantic_config_hash
    {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(
            "prior Store bootstrap is not bound to the exact previous Host contour".to_owned(),
        ));
    }
    Ok(Some(requirement))
}

#[cfg(windows)]
fn phase_b_previous_peer_identity(
    config: &PhaseBPreviousProjectionFile,
    binding: &PhaseBPreviousProjectionDigestBinding,
    requirement: Option<&HostStoreBootstrapRequirement>,
) -> Result<(PlatformHandle, u32), HostError> {
    if let Some(requirement) = requirement {
        return Ok((
            requirement.expected_peer_sid.clone(),
            requirement.expected_peer_session_id,
        ));
    }
    if config.digest != binding.config_file_digest {
        return Err(HostError::RecoveryRequired(
            "prior Store peer identity has no exact physical config digest".to_owned(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&config.bytes).map_err(|error| {
        HostError::RecoveryRequired(format!("prior Store config is not parseable: {error}"))
    })?;
    let sid = phase_b_json_string(&value, "expected_client_sid")?;
    let session_id = value
        .get("expected_client_session_id")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "prior Store config expected_client_session_id is missing or out of range"
                    .to_owned(),
            )
        })?;
    Ok((
        PlatformHandle::new(sid).map_err(|error| HostError::ProcessContour(error.to_string()))?,
        session_id,
    ))
}

#[cfg(windows)]
pub(super) fn phase_b_previous_store_bootstrap(
    input: &PhaseBPreviousStoreBootstrapInput<'_>,
) -> Result<Option<PhaseBPreviousStoreBootstrap>, HostError> {
    phase_b_previous_projection_observe("host.phase-b prior-projection requested");
    let config = phase_b_previous_store_config_file(input)?;
    let Some(bootstrap) = phase_b_previous_store_bootstrap_file(input)? else {
        return phase_b_previous_store_bootstrap_without_file(input, &config);
    };
    phase_b_previous_store_bootstrap_from_files(input, &config, &bootstrap)
}

#[cfg(windows)]
fn phase_b_previous_store_config_file(
    input: &PhaseBPreviousStoreBootstrapInput<'_>,
) -> Result<PhaseBPreviousProjectionFile, HostError> {
    let durable_config = input.durable.map(|binding| &binding.config_file_digest);
    let prepared_config = input.prepared.map(|binding| &binding.config_file_digest);
    phase_b_previous_projection_file(&PhaseBPreviousProjectionFileInput {
        profile: input.profile,
        portable_root: input.portable_root,
        path: input.config_path,
        desired: input.config_desired,
        template_digest: input.config_template_digest,
        durable_digest: durable_config,
        prepared_digest: prepared_config,
        allow_missing: false,
        label: "config",
    })?
    .ok_or_else(|| HostError::RecoveryRequired("prior Store config is missing".to_owned()))
}

#[cfg(windows)]
fn phase_b_previous_store_bootstrap_file(
    input: &PhaseBPreviousStoreBootstrapInput<'_>,
) -> Result<Option<PhaseBPreviousProjectionFile>, HostError> {
    let durable_bootstrap = input
        .durable
        .map(|binding| &binding.store_bootstrap_descriptor_digest);
    let prepared_bootstrap = input
        .prepared
        .map(|binding| &binding.store_bootstrap_descriptor_digest);
    phase_b_previous_projection_file(&PhaseBPreviousProjectionFileInput {
        profile: input.profile,
        portable_root: input.portable_root,
        path: input.bootstrap_path,
        desired: input.bootstrap_desired,
        template_digest: input.bootstrap_template_digest,
        durable_digest: durable_bootstrap,
        prepared_digest: prepared_bootstrap,
        allow_missing: true,
        label: "bootstrap",
    })
}

#[cfg(windows)]
fn phase_b_previous_store_bootstrap_without_file(
    input: &PhaseBPreviousStoreBootstrapInput<'_>,
    config: &PhaseBPreviousProjectionFile,
) -> Result<Option<PhaseBPreviousStoreBootstrap>, HostError> {
    let Some(prepared) = input.prepared.filter(|prepared| {
        !config.is_current
            && !config.is_template(input.config_template_digest)
            && config.digest == prepared.config_file_digest
    }) else {
        return Ok(None);
    };
    if input.previous.is_none() {
        return Err(HostError::RecoveryRequired(
            "prepared prior Store config has no exact previous Host binding".to_owned(),
        ));
    }
    let binding = PhaseBPreviousProjectionDigestBinding {
        config_file_digest: prepared.config_file_digest.clone(),
        store_bootstrap_descriptor_digest: prepared.store_bootstrap_descriptor_digest.clone(),
        semantic_config_hash: prepared.semantic_config_hash.clone(),
    };
    let (expected_peer_sid, expected_peer_session_id) =
        phase_b_previous_peer_identity(config, &binding, None)?;
    Ok(Some(PhaseBPreviousStoreBootstrap {
        digest: None,
        requirement: None,
        expected_peer_sid,
        expected_peer_session_id,
        config_file_digest: binding.config_file_digest,
        semantic_config_hash: binding.semantic_config_hash,
    }))
}

#[cfg(windows)]
fn phase_b_previous_store_bootstrap_from_files(
    input: &PhaseBPreviousStoreBootstrapInput<'_>,
    config: &PhaseBPreviousProjectionFile,
    bootstrap: &PhaseBPreviousProjectionFile,
) -> Result<Option<PhaseBPreviousStoreBootstrap>, HostError> {
    if config.is_current && bootstrap.is_current {
        return Ok(None);
    }
    let Some(binding) = phase_b_previous_projection_digest_binding(
        &config,
        &bootstrap,
        input.durable,
        input.prepared,
    ) else {
        return Ok(None);
    };
    if !config.is_current
        && !config.is_template(input.config_template_digest)
        && config.digest != binding.config_file_digest
        || !bootstrap.is_current
            && !bootstrap.is_template(input.bootstrap_template_digest)
            && bootstrap.digest != binding.store_bootstrap_descriptor_digest
    {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(
            "prior Store config/bootstrap digests belong to different Phase-B contours".to_owned(),
        ));
    }
    let previous = input.previous.ok_or_else(|| {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        HostError::RecoveryRequired(
            "prior Store projection has no exact previous Host binding".to_owned(),
        )
    })?;
    let requirement = phase_b_previous_store_bootstrap_requirement(&bootstrap, &binding, previous)?;
    let (expected_peer_sid, expected_peer_session_id) =
        phase_b_previous_peer_identity(&config, &binding, requirement.as_ref())?;
    Ok(Some(PhaseBPreviousStoreBootstrap {
        digest: (bootstrap.digest == binding.store_bootstrap_descriptor_digest)
            .then_some(bootstrap.digest),
        requirement,
        expected_peer_sid,
        expected_peer_session_id,
        config_file_digest: binding.config_file_digest,
        semantic_config_hash: binding.semantic_config_hash,
    }))
}

#[cfg(windows)]
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the exact prior-bootstrap readback keeps every physical path, config projection, launch, nonce, and prior Host contour explicit"
)]
pub(super) fn phase_b_previous_bootstrap_digest(
    previous_store_bootstrap: Option<&PhaseBPreviousStoreBootstrap>,
    config: &serde_json::Value,
    launch: &RuntimeLaunchDescriptor,
    launch_nonce: &PlatformHandle,
    previous: Option<&PhaseBPreviousBinding>,
) -> Result<Option<PlatformHandle>, HostError> {
    phase_b_previous_projection_observe("host.phase-b prior-projection requested");
    let Some(previous_store_bootstrap) = previous_store_bootstrap else {
        return Ok(None);
    };
    let Some(requirement) = previous_store_bootstrap.requirement.as_ref() else {
        return Ok(None);
    };
    let previous = previous.ok_or_else(|| {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        HostError::RecoveryRequired(
            "prior Store bootstrap has no exact previous Host binding".to_owned(),
        )
    })?;
    let store_pipe = phase_b_json_string(config, "store_pipe")?;
    let expected_peer_sid = phase_b_json_string(config, "expected_client_sid")?;
    let instance_id = phase_b_json_string(config, "instance_id")?;
    let connect_timeout_ms = phase_b_json_u64(config, "connect_timeout_ms")?;
    let expected_client_session_id = config
        .get("expected_client_session_id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "prior Store config field expected_client_session_id is missing".to_owned(),
            )
        })?;
    let expected_client_session_id = u32::try_from(expected_client_session_id).map_err(|_| {
        HostError::RecoveryRequired(
            "prior Store config expected_client_session_id is out of range".to_owned(),
        )
    })?;
    let semantic_config_hash = semantic_store_config_hash_from_json(
        &serde_json::to_vec(config)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?,
    )
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let expected = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)
            .map_err(|error| HostError::Platform(error.to_string()))?,
        canonical_pipe_identity: PlatformHandle::new(store_pipe)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        store_generation: launch.authority_generation,
        state_fence: launch.authority_state_fence.clone(),
        launch_nonce: launch_nonce.clone(),
        connection_id: PlatformHandle::new(format!(
            "kernel-store:{}:{}",
            instance_id,
            launch_nonce.as_str()
        ))
        .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        expected_peer_sid: PlatformHandle::new(expected_peer_sid)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        expected_peer_session_id: expected_client_session_id,
        approved_artifact_hash: launch.store_bridge_artifact_digest.clone(),
        approved_config_hash: semantic_config_hash,
        timeout_ms: connect_timeout_ms,
    };
    expected
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if requirement != &expected
        || expected.launch_nonce != previous.host.nonce
        || expected.state_fence != previous.authority.state_fence
        || expected.store_generation != previous.authority.generation
    {
        phase_b_previous_projection_observe("host.phase-b prior-projection mismatch retained");
        return Err(HostError::RecoveryRequired(
            "prior Store bootstrap is not the exact previous Host materialization".to_owned(),
        ));
    }
    Ok(previous_store_bootstrap.digest.clone())
}

#[cfg(windows)]
pub(super) fn phase_b_live_launch(
    template: &RuntimeLaunchDescriptor,
    host: &HostInstallationEpoch,
    descriptor: &ProcessAuthorityHandoffDescriptor,
    authority_descriptor_digest: &PlatformHandle,
    eliotd_descriptor_digest: &PlatformHandle,
    provisioned_supervision_authority: &ProvisionedSupervisionAuthority,
) -> Result<RuntimeLaunchDescriptor, HostError> {
    let live = template
        .with_phase_b_pending_bootstrap_overlay(
            descriptor.generation,
            descriptor.state_fence.clone(),
            authority_descriptor_digest.clone(),
            eliotd_descriptor_digest.clone(),
            provisioned_supervision_authority.clone(),
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let mut live = live;
    live.installation_epoch = phase_b_live_installation_epoch(host);
    live.with_computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn phase_b_activation_binding(
    receipt: &HostPhaseBMaterialization,
) -> Result<PlatformHandle, HostError> {
    let digest = phase_b_receipt_digest(receipt)?;
    PlatformHandle::new(format!("phase-b-materialized:{digest}"))
        .map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(windows)]
pub(super) fn phase_b_receipt_digest(
    receipt: &HostPhaseBMaterialization,
) -> Result<PlatformHandle, HostError> {
    let digest = sha256_json(&(
        &receipt.manifest_digest,
        &receipt.host_epoch,
        &receipt.host_process_nonce,
        &receipt.activation_generation,
        &receipt.authority_descriptor_digest,
        &receipt.store_bootstrap_descriptor_digest,
        &receipt.config_file_digest,
        &receipt.semantic_config_hash,
        &receipt.eliotd_descriptor_digest,
        &receipt.request_digest,
        &receipt.file_identities,
    ))?;
    PlatformHandle::new(digest).map_err(|error| HostError::Platform(error.to_string()))
}
