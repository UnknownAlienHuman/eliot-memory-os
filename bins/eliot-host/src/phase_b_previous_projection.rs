use std::path::Path;

use sha2::Digest;

use super::{
    EliotdLaunchDescriptor, HostError, HostInstallationEpoch, HostPhaseBMaterialization,
    HostStoreBootstrapRequirement, InstallationEpoch, InstallationProfile, PhaseBPreviousBinding,
    PlatformHandle, ProcessAuthorityHandoffDescriptor, ProvisionedSupervisionAuthority,
    RuntimeLaunchDescriptor, STORE_SEMANTIC_CONFIG_HASH_PENDING, Sha256, UserOwnedRootLease,
    phase_b_lease_bytes, phase_b_open_existing, semantic_store_config_hash_from_json, sha256_json,
};

#[cfg(windows)]
pub(super) fn phase_b_live_installation_epoch(host: &HostInstallationEpoch) -> InstallationEpoch {
    InstallationEpoch {
        installation: host.installation.clone(),
        lineage_id: host.epoch.current.lineage.clone(),
        sequence: host.epoch.current.sequence,
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
    previous_eliotd_digest: Option<&PlatformHandle>,
    provisioned_supervision_authority: &ProvisionedSupervisionAuthority,
) -> Result<Option<PlatformHandle>, HostError> {
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
        HostError::RecoveryRequired(
            "Store config is neither the immutable Phase-A template nor an exact prior Phase-B contour"
                .to_owned(),
        )
    })?;
    let current_value = serde_json::from_slice::<serde_json::Value>(&current).map_err(|error| {
        HostError::RecoveryRequired(format!("prior Store config is not valid JSON: {error}"))
    })?;
    if current_value
        != phase_b_previous_config_value(
            template_bytes,
            template,
            previous,
            previous_eliotd_digest,
            provisioned_supervision_authority,
        )?
    {
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
        HostError::RecoveryRequired(
            "eliotd descriptor is neither the immutable Phase-A template nor an exact prior Phase-B contour"
                .to_owned(),
        )
    })?;
    let mut expected: EliotdLaunchDescriptor =
        serde_json::from_slice(template_bytes).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "prior eliotd descriptor is not parseable: {error}"
            ))
        })?;
    expected.authority_epoch = previous.authority.state_fence.authority_epoch;
    expected.generation = previous.authority.generation;
    let expected = expected
        .with_computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let current_descriptor: EliotdLaunchDescriptor =
        serde_json::from_slice(&current).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "prior eliotd descriptor is not parseable: {error}"
            ))
        })?;
    if current_descriptor != expected {
        return Err(HostError::RecoveryRequired(
            "prior eliotd descriptor is not the exact previous Host materialization".to_owned(),
        ));
    }
    Ok(Some(digest))
}

#[cfg(windows)]
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the exact prior-bootstrap readback keeps every physical path, config projection, launch, nonce, and prior Host contour explicit"
)]
pub(super) fn phase_b_previous_bootstrap_digest(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    config: &serde_json::Value,
    launch: &RuntimeLaunchDescriptor,
    launch_nonce: &PlatformHandle,
    previous: Option<&PhaseBPreviousBinding>,
) -> Result<Option<PlatformHandle>, HostError> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    let lease = match phase_b_open_existing(profile, portable_root, path) {
        Ok(lease) => lease,
        Err(HostError::RecoveryRequired(reason)) if reason.contains("missing") => return Ok(None),
        Err(error) => return Err(error),
    };
    lease.verify().map_err(HostError::RecoveryRequired)?;
    let current = phase_b_lease_bytes(&lease)?;
    if current == desired {
        return Ok(None);
    }
    let digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&current)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
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
    let current_requirement: HostStoreBootstrapRequirement = serde_json::from_slice(&current)
        .map_err(|error| {
            HostError::RecoveryRequired(format!("prior Store bootstrap is not parseable: {error}"))
        })?;
    if current_requirement != expected
        || expected.launch_nonce != previous.host.nonce
        || expected.state_fence != previous.authority.state_fence
        || expected.store_generation != previous.authority.generation
    {
        return Err(HostError::RecoveryRequired(
            "prior Store bootstrap is not the exact previous Host materialization".to_owned(),
        ));
    }
    Ok(Some(digest))
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
