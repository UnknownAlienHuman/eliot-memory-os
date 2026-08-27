use std::{
    io::{self, Read},
    path::{Path, PathBuf},
};

use eliot_contracts::{ResourceGeneration, canonical_json_bytes};
use eliot_installation::{
    AGENT_BRIDGE_MODULE_ID, AgentBridgeInstallationProfile, AgentBridgePhaseBBinding,
    AgentBridgePreparedBinding, AgentBridgeSourceMaterializationPlan, AgentBridgeStagePrepared,
    HostPhaseBMaterializationIntent, InstallationProfile,
};
use eliot_kernel_service::{
    AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_ID, AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_VERSION,
    AgentBridgeAdmissionDescriptor, AgentBridgeCallerSessionPolicy as KernelCallerSessionPolicy,
    AgentBridgeProcessPolicy as KernelProcessPolicy, HostFileIdentity,
};
use eliot_platform::{PlatformHandle, WorkScopePath};
use eliot_platform_windows::{
    AGENT_BRIDGE_STAGE_WIRE, AGENT_BRIDGE_STAGE_WIRE_VERSION,
    AgentBridgeStagePrepared as PlatformAgentBridgeStagePrepared, AgentBridgeStagingReceipt,
    AgentBridgeStagingRequest, FileIdentity, ProtectedRootLease, PublicationOutcome,
    UserOwnedRootLease, WindowsPlatform, delete_owned_file_handle, open_no_follow_file_for_delete,
    prepare_agent_bridge_stage, reconcile_agent_bridge_stage, windows_paths_equal,
};
use sha2::{Digest as _, Sha256};

use super::{HostError, LaunchLease, open_launch_lease, phase_b_open_existing};

#[cfg(windows)]
pub(super) struct AgentBridgePreparedMaterialization {
    pub platform_prepared: PlatformAgentBridgeStagePrepared,
    pub installation_prepared: AgentBridgeStagePrepared,
    pub receipt: AgentBridgeStagingReceipt,
    pub binding: AgentBridgePreparedBinding,
    pub profile_bytes: Vec<u8>,
    pub declaration_bytes: Vec<u8>,
}

#[cfg(windows)]
fn agent_bridge_destination_path(
    installation_root: &PlatformHandle,
    generation: &PlatformHandle,
) -> Result<PathBuf, HostError> {
    let path = Path::new(installation_root.as_str())
        .join("external-modules")
        .join(AGENT_BRIDGE_MODULE_ID)
        .join(generation.as_str())
        .join("eliot-agent-bridge.exe");
    if !path.starts_with(Path::new(installation_root.as_str())) {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge destination escaped the installation root".to_owned(),
        ));
    }
    Ok(path)
}

#[cfg(windows)]
fn agent_bridge_request(
    source: &AgentBridgeSourceMaterializationPlan,
    destination_path: PathBuf,
) -> AgentBridgeStagingRequest {
    AgentBridgeStagingRequest {
        source_path: PathBuf::from(source.source_executable_path.as_str()),
        source_identity: source.source_executable_identity,
        source_sha256: source.source_executable_sha256.as_str().to_owned(),
        source_size: source.source_executable_size,
        destination_path,
    }
}

#[cfg(windows)]
pub(super) fn agent_bridge_stage_from_durable(
    stage: &AgentBridgeStagePrepared,
) -> Result<PlatformAgentBridgeStagePrepared, HostError> {
    let parent_path = Path::new(stage.destination_path.as_str())
        .parent()
        .ok_or_else(|| {
            HostError::RecoveryRequired("Agent Bridge destination has no parent".to_owned())
        })?
        .to_path_buf();
    Ok(PlatformAgentBridgeStagePrepared {
        wire: AGENT_BRIDGE_STAGE_WIRE.to_owned(),
        wire_version: AGENT_BRIDGE_STAGE_WIRE_VERSION,
        transaction_id: stage.transaction_id.as_str().to_owned(),
        effect_id: stage.effect_id.as_str().to_owned(),
        request_digest: stage.request_digest.as_str().to_owned(),
        source_path: PathBuf::from(stage.source_path.as_str()),
        source_identity: stage.source_identity,
        source_sha256: stage.source_sha256.as_str().to_owned(),
        source_size: stage.source_size,
        parent_path,
        parent_identity: stage.destination_parent_identity,
        temporary_path: PathBuf::from(stage.temporary_path.as_str()),
        temporary_identity: stage.temporary_identity,
        destination_path: PathBuf::from(stage.destination_path.as_str()),
        destination_identity: stage.temporary_identity,
    })
}

#[cfg(windows)]
pub(super) fn prepare_agent_bridge_materialization(
    launch: &eliot_installation::RuntimeLaunchDescriptor,
    intent: &HostPhaseBMaterializationIntent,
    source: &AgentBridgeSourceMaterializationPlan,
    manifest_digest: &PlatformHandle,
    existing_stage: Option<&AgentBridgeStagePrepared>,
) -> Result<
    (
        ProtectedRootLease,
        PlatformAgentBridgeStagePrepared,
        AgentBridgeStagePrepared,
    ),
    HostError,
> {
    let installation_root = launch.runtime_state_roots.installation_root.clone();
    let root = ProtectedRootLease::open_existing(Path::new(installation_root.as_str())).map_err(
        |error| {
            HostError::RecoveryRequired(format!("open Agent Bridge installation root: {error}"))
        },
    )?;
    let destination = agent_bridge_destination_path(&installation_root, &launch.generation)?;
    let platform = if let Some(stage) = existing_stage {
        if !windows_paths_equal(Path::new(stage.destination_path.as_str()), &destination) {
            return Err(HostError::RecoveryRequired(
                "durable Agent Bridge destination is not the deterministic launch path".to_owned(),
            ));
        }
        agent_bridge_stage_from_durable(stage)?
    } else {
        let request = agent_bridge_request(source, destination);
        prepare_agent_bridge_stage(
            &root,
            &request,
            intent.transaction_id.as_str(),
            intent.effect_id.as_str(),
            intent.request_digest.as_str(),
        )
        .map_err(|error| {
            HostError::RecoveryRequired(format!("prepare Agent Bridge stage: {error}"))
        })?
    };
    let installation = AgentBridgeStagePrepared::from_platform(
        &platform,
        launch.installation_epoch.installation.clone(),
        intent.installation_plan_digest.clone(),
        intent.host_state_root_digest.clone(),
        manifest_digest.clone(),
        launch.descriptor_digest.clone(),
        launch.generation.clone(),
    )
    .map_err(HostError::Installation)?;
    Ok((root, platform, installation))
}

#[cfg(windows)]
pub(super) fn retain_agent_bridge_profile(
    launch: &eliot_installation::RuntimeLaunchDescriptor,
    intent: &HostPhaseBMaterializationIntent,
    source: &AgentBridgeSourceMaterializationPlan,
    manifest_digest: &PlatformHandle,
    platform_prepared: &PlatformAgentBridgeStagePrepared,
    installation_prepared: AgentBridgeStagePrepared,
    receipt: AgentBridgeStagingReceipt,
) -> Result<AgentBridgePreparedMaterialization, HostError> {
    let installation_root = launch.runtime_state_roots.installation_root.clone();
    let generation = launch.generation.as_str().parse::<u64>().map_err(|error| {
        HostError::RecoveryRequired(format!("invalid Agent Bridge generation: {error}"))
    })?;
    let generation = ResourceGeneration::new(generation)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let retained =
        eliot_installation::RetainedAgentBridgeArtifact::open(&installation_root, generation)
            .map_err(HostError::Installation)?;
    let profile = AgentBridgeInstallationProfile::from_retained_artifact(
        launch.installation_epoch.installation.clone(),
        installation_root.clone(),
        launch.runtime_state_roots.host_state_root.clone(),
        &retained,
        source.approved_user_sid.clone(),
        source.allowed_effects.clone(),
        source.client_declaration.clone(),
    )
    .map_err(HostError::Installation)?;
    profile.validate().map_err(HostError::Installation)?;
    let profile_bytes = canonical_json_bytes(&profile)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let declaration_bytes = canonical_json_bytes(&profile.client_declaration)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let profile_digest = phase_b_bytes_digest(&profile_bytes)?;
    let declaration_digest = phase_b_bytes_digest(&declaration_bytes)?;
    let profile_path = profile.protected_paths.admission_profile_path.clone();
    let declaration_path = profile.protected_paths.client_declaration_path.clone();
    let binding = AgentBridgePreparedBinding::from_platform(
        platform_prepared,
        &receipt,
        launch.installation_epoch.installation.clone(),
        intent.installation_plan_digest.clone(),
        intent.host_state_root_digest.clone(),
        manifest_digest.clone(),
        launch.descriptor_digest.clone(),
        launch.generation.clone(),
        profile_path,
        profile_digest,
        declaration_path,
        declaration_digest,
    )
    .map_err(HostError::Installation)?;
    Ok(AgentBridgePreparedMaterialization {
        platform_prepared: platform_prepared.clone(),
        installation_prepared,
        receipt,
        binding,
        profile_bytes,
        declaration_bytes,
    })
}

#[cfg(windows)]
pub(super) fn publish_agent_bridge_pair(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    materialization: &AgentBridgePreparedMaterialization,
    allowed_profile_digests: &[&PlatformHandle],
    allowed_declaration_digests: &[&PlatformHandle],
) -> Result<(), HostError> {
    let binding = &materialization.binding;
    let profile_path = Path::new(binding.profile_path.as_str());
    let declaration_path = Path::new(binding.declaration_path.as_str());
    let bridge_directory = profile_path.parent().ok_or_else(|| {
        HostError::RecoveryRequired("Agent Bridge profile has no parent directory".to_owned())
    })?;
    let host_state_root = bridge_directory.parent().ok_or_else(|| {
        HostError::RecoveryRequired("Agent Bridge directory has no Host root".to_owned())
    })?;
    eliot_platform_windows::ensure_agent_bridge_directory(host_state_root).map_err(|error| {
        HostError::RecoveryRequired(format!("create Agent Bridge directory: {error}"))
    })?;
    phase_b_materialize_file(
        profile,
        portable_root,
        profile_path,
        &materialization.profile_bytes,
        allowed_profile_digests,
        "Agent Bridge admission profile",
    )?;
    phase_b_materialize_file(
        profile,
        portable_root,
        declaration_path,
        &materialization.declaration_bytes,
        allowed_declaration_digests,
        "Agent Bridge client declaration",
    )?;
    verify_agent_bridge_pair_readback(profile, portable_root, &materialization.binding)
}

#[cfg(windows)]
pub(super) fn verify_agent_bridge_pair_readback(
    _profile: InstallationProfile,
    _portable_root: Option<&UserOwnedRootLease>,
    binding: &AgentBridgePreparedBinding,
) -> Result<(), HostError> {
    for (path, expected, label) in [
        (
            binding.profile_path.as_str(),
            &binding.profile_digest,
            "profile",
        ),
        (
            binding.declaration_path.as_str(),
            &binding.declaration_digest,
            "declaration",
        ),
    ] {
        let (_, bytes) = read_agent_bridge_leaf(Path::new(path))?;
        if phase_b_bytes_digest(&bytes)? != *expected {
            return Err(HostError::RecoveryRequired(format!(
                "Agent Bridge {label} readback digest differs from durable binding"
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn read_agent_bridge_leaf(path: &Path) -> Result<(FileIdentity, Vec<u8>), HostError> {
    let (identity, mut file) = eliot_platform_windows::open_no_follow_file(path)
        .map_err(|error| HostError::RecoveryRequired(format!("open Agent Bridge leaf: {error}")))?;
    let length = file
        .metadata()
        .map_err(|error| HostError::RecoveryRequired(format!("stat Agent Bridge leaf: {error}")))?
        .len();
    if length == 0 || length > 16 * 1024 * 1024 {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge leaf has an invalid bounded size".to_owned(),
        ));
    }
    let capacity = usize::try_from(length).map_err(|_| {
        HostError::RecoveryRequired("Agent Bridge leaf size exceeds addressable memory".to_owned())
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| HostError::RecoveryRequired(format!("read Agent Bridge leaf: {error}")))?;
    if bytes.len() as u64 != length {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge leaf changed while being read".to_owned(),
        ));
    }
    Ok((identity, bytes))
}

#[cfg(windows)]
pub(super) fn open_agent_bridge_final_lease(
    binding: &AgentBridgePhaseBBinding,
    approved_user_sid: &str,
) -> Result<eliot_platform_windows::AgentBridgeFinalReadLease, HostError> {
    let bridge_directory = Path::new(binding.profile_path.as_str())
        .parent()
        .ok_or_else(|| {
            HostError::RecoveryRequired("Agent Bridge profile has no parent directory".to_owned())
        })?;
    let host_state_root = bridge_directory.parent().ok_or_else(|| {
        HostError::RecoveryRequired("Agent Bridge directory has no Host root".to_owned())
    })?;
    let lease = eliot_platform_windows::open_agent_bridge_final_read_lease(
        host_state_root,
        approved_user_sid,
        Path::new(binding.profile_path.as_str()),
        Path::new(binding.declaration_path.as_str()),
    )
    .map_err(|error| {
        HostError::RecoveryRequired(format!("verify Agent Bridge final ACL: {error}"))
    })?;
    let receipt = lease.receipt();
    let contour = &binding.security_contour;
    if binding.profile_identity != receipt.profile_identity
        || binding.declaration_identity != receipt.declaration_identity
        || binding.profile_security_descriptor_digest.as_str() != receipt.profile_descriptor_sha256
        || binding.declaration_security_descriptor_digest.as_str()
            != receipt.declaration_descriptor_sha256
        || contour.host_state_root_identity != receipt.host_state_root_identity
        || contour.bridge_directory_identity != receipt.bridge_directory_identity
        || contour.host_state_root_security_descriptor_digest.as_str()
            != receipt.host_state_root_descriptor_sha256
        || contour.bridge_directory_security_descriptor_digest.as_str()
            != receipt.bridge_directory_descriptor_sha256
    {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge final ACL readback differs from durable binding".to_owned(),
        ));
    }
    Ok(lease)
}

#[cfg(windows)]
pub(super) fn rehydrate_agent_bridge_binding(
    launch: &eliot_installation::RuntimeLaunchDescriptor,
    binding: &AgentBridgePhaseBBinding,
) -> Result<AgentBridgePhaseBBinding, HostError> {
    binding.validate().map_err(HostError::Installation)?;
    let expected_paths = eliot_installation::derive_agent_bridge_protected_paths(
        &launch.runtime_state_roots.host_state_root,
    )
    .map_err(HostError::Installation)?;
    if binding.profile_path != expected_paths.admission_profile_path
        || binding.declaration_path != expected_paths.client_declaration_path
    {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge pair paths are outside the deterministic Host state root".to_owned(),
        ));
    }
    let root_path = Path::new(launch.runtime_state_roots.installation_root.as_str());
    let root = ProtectedRootLease::open_existing(root_path).map_err(|error| {
        HostError::RecoveryRequired(format!("open Agent Bridge installation root: {error}"))
    })?;
    let platform_prepared = agent_bridge_stage_from_durable(&binding.stage_prepared)?;
    let receipt = reconcile_agent_bridge_stage(&root, &platform_prepared).map_err(|error| {
        HostError::RecoveryRequired(format!("reconcile Agent Bridge prepared stage: {error}"))
    })?;
    let receipt_digest = PlatformHandle::new(receipt.digest())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if receipt_digest != binding.staging_receipt_digest
        || receipt.destination_identity != binding.staged_destination_identity
        || receipt.sha256 != binding.staged_sha256.as_str()
        || receipt.size != binding.staged_size
    {
        return Err(HostError::RecoveryRequired(
            "rehydrated Agent Bridge receipt differs from the durable binding".to_owned(),
        ));
    }
    let generation = launch.generation.as_str().parse::<u64>().map_err(|error| {
        HostError::RecoveryRequired(format!("invalid Agent Bridge generation: {error}"))
    })?;
    let _retained = eliot_installation::RetainedAgentBridgeArtifact::open(
        &launch.runtime_state_roots.installation_root,
        ResourceGeneration::new(generation)
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?,
    )
    .map_err(HostError::Installation)?;
    let approved_sid = &binding.approved_user_sid;
    let mut lease = open_agent_bridge_final_lease(binding, approved_sid.as_str())?;
    let profile_bytes = lease.read_profile_bytes().map_err(|error| {
        HostError::RecoveryRequired(format!("read Agent Bridge profile lease: {error}"))
    })?;
    let profile_value: AgentBridgeInstallationProfile = serde_json::from_slice(&profile_bytes)
        .map_err(|error| {
            HostError::RecoveryRequired(format!("decode Agent Bridge profile: {error}"))
        })?;
    profile_value.validate().map_err(HostError::Installation)?;
    if profile_value.approved_user_sid.as_str() != approved_sid.as_str() {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge profile SID differs from the durable final binding".to_owned(),
        ));
    }
    if profile_value.executable_path != binding.staged_destination_path
        || profile_value.executable_identity != binding.staged_destination_identity
        || profile_value.executable_sha256 != binding.staged_sha256
    {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge profile executable proof differs from staged binding".to_owned(),
        ));
    }
    let declaration_bytes = lease.read_declaration_bytes().map_err(|error| {
        HostError::RecoveryRequired(format!("read Agent Bridge declaration lease: {error}"))
    })?;
    let declaration_value: serde_json::Value =
        serde_json::from_slice(&declaration_bytes).map_err(|error| {
            HostError::RecoveryRequired(format!("decode Agent Bridge declaration: {error}"))
        })?;
    let expected_declaration_value = serde_json::to_value(&profile_value.client_declaration)
        .map_err(|error| {
            HostError::RecoveryRequired(format!("encode Agent Bridge declaration: {error}"))
        })?;
    if declaration_value != expected_declaration_value {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge declaration differs from the retained profile".to_owned(),
        ));
    }
    Ok(binding.clone())
}

/// Reopens the exact protected profile/declaration pair and retained staged
/// executable, then projects the complete static profile into the Kernel
/// candidate wire.  No field is synthesized from the manifest or stage
/// digest: every artifact/profile/declaration fact is read back and checked
/// against the durable Phase-B binding first.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the projection keeps executable, profile, and declaration readback in one fail-closed boundary"
)]
pub(super) fn agent_bridge_admission_descriptor(
    profile_kind: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    binding: &AgentBridgePhaseBBinding,
) -> Result<AgentBridgeAdmissionDescriptor, HostError> {
    let approved_sid = &binding.approved_user_sid;
    let mut lease = open_agent_bridge_final_lease(binding, approved_sid.as_str())?;
    let profile_bytes = lease.read_profile_bytes().map_err(|error| {
        HostError::RecoveryRequired(format!("read Agent Bridge profile lease: {error}"))
    })?;
    if phase_b_bytes_digest(&profile_bytes)? != binding.profile_digest {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge profile readback digest differs from durable binding".to_owned(),
        ));
    }
    let profile: AgentBridgeInstallationProfile =
        serde_json::from_slice(&profile_bytes).map_err(|error| {
            HostError::RecoveryRequired(format!("decode Agent Bridge profile: {error}"))
        })?;
    profile.validate().map_err(HostError::Installation)?;
    if profile.approved_user_sid.as_str() != approved_sid.as_str() {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge profile SID differs from the durable final binding".to_owned(),
        ));
    }
    if profile.profile_sha256 != binding.profile_digest
        || profile.protected_paths.admission_profile_path != binding.profile_path
        || profile.protected_paths.client_declaration_path != binding.declaration_path
        || profile.executable_path != binding.staged_destination_path
        || profile.executable_identity != binding.staged_destination_identity
        || profile.executable_sha256 != binding.staged_sha256
    {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge profile is not bound to the exact staged Phase-B evidence".to_owned(),
        ));
    }

    let declaration_bytes = lease.read_declaration_bytes().map_err(|error| {
        HostError::RecoveryRequired(format!("read Agent Bridge declaration lease: {error}"))
    })?;
    if phase_b_bytes_digest(&declaration_bytes)? != binding.declaration_digest {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge declaration readback digest differs from durable binding".to_owned(),
        ));
    }
    let declaration: eliot_protocol::AgentBridgeClientDeclaration =
        serde_json::from_slice(&declaration_bytes).map_err(|error| {
            HostError::RecoveryRequired(format!("decode Agent Bridge declaration: {error}"))
        })?;
    declaration.validate().map_err(|error| {
        HostError::RecoveryRequired(format!("validate Agent Bridge declaration: {error}"))
    })?;
    if declaration != profile.client_declaration
        || declaration
            .compute_digest()
            .map_err(|error| {
                HostError::RecoveryRequired(format!("digest Agent Bridge declaration: {error}"))
            })?
            .as_str()
            != binding.declaration_digest.as_str()
    {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge declaration is not bound to the retained profile".to_owned(),
        ));
    }

    let executable_lease = phase_b_open_existing(
        profile_kind,
        portable_root,
        Path::new(profile.executable_path.as_str()),
    )?;
    executable_lease
        .verify()
        .map_err(HostError::RecoveryRequired)?;
    if phase_b_lease_identity(&executable_lease) != profile.executable_identity
        || phase_b_bytes_digest(&phase_b_lease_bytes(&executable_lease)?)?
            != profile.executable_sha256
    {
        return Err(HostError::RecoveryRequired(
            "retained Agent Bridge executable evidence differs from the profile".to_owned(),
        ));
    }

    AgentBridgeAdmissionDescriptor {
        wire_id: AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_ID.to_owned(),
        wire_version: AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_VERSION,
        module_id: profile.module_id,
        profile_id: profile.profile_id,
        profile_sha256: profile.profile_sha256.to_string(),
        executable: profile.executable_path,
        executable_sha256: profile.executable_sha256.to_string(),
        executable_identity: HostFileIdentity {
            volume_serial_number: profile.executable_identity.volume_serial_number,
            file_index: profile.executable_identity.file_index,
        },
        generation: profile.module_generation.generation,
        authority_epoch: profile.module_generation.state_fence.authority_epoch,
        state_fence: profile.module_generation.state_fence,
        approved_user_sid: profile.approved_user_sid,
        caller_session_policy: match profile.caller_session_policy {
            eliot_installation::AgentBridgeCallerSessionPolicy::AnyInteractiveSessionForApprovedSid =>
                KernelCallerSessionPolicy::AnyInteractiveSessionForApprovedSid,
        },
        process_policy: match profile.process_policy {
            eliot_installation::AgentBridgeProcessPolicy::ExactProcessPerConnection => {
                KernelProcessPolicy::ExactProcessPerConnection
            }
        },
        allowed_capabilities: profile.allowed_capabilities,
        allowed_privacy_classes: profile.allowed_privacy_classes,
        allowed_effects: profile.allowed_effects,
        max_frame: profile.max_frame,
        expected_kernel_principal_binding: declaration.expected_kernel_principal_binding,
        expected_kernel_config_snapshot_sha256: declaration
            .expected_kernel_config_snapshot_sha256,
        client_declaration_path: profile.protected_paths.client_declaration_path,
        client_declaration_sha256: declaration.declaration_sha256,
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
pub(super) fn rehydrate_agent_bridge_binding_from_pending(
    launch: &eliot_installation::RuntimeLaunchDescriptor,
    intent: &HostPhaseBMaterializationIntent,
    source: &AgentBridgeSourceMaterializationPlan,
    manifest_digest: &PlatformHandle,
    binding: &AgentBridgePreparedBinding,
    prior_binding: Option<&AgentBridgePhaseBBinding>,
) -> Result<AgentBridgePhaseBBinding, HostError> {
    binding.validate().map_err(HostError::Installation)?;
    let (installation_root, platform_prepared, installation_prepared) =
        prepare_agent_bridge_materialization(
            launch,
            intent,
            source,
            manifest_digest,
            Some(&binding.stage_prepared),
        )?;
    if installation_prepared != binding.stage_prepared {
        return Err(HostError::RecoveryRequired(
            "rehydrated Agent Bridge stage differs from the durable prepared binding".to_owned(),
        ));
    }
    let staging_receipt = reconcile_agent_bridge_stage(&installation_root, &platform_prepared)
        .map_err(|error| {
            HostError::RecoveryRequired(format!(
                "reconcile Agent Bridge stage during pair rehydrate: {error}"
            ))
        })?;
    let materialization = retain_agent_bridge_profile(
        launch,
        intent,
        source,
        manifest_digest,
        &platform_prepared,
        installation_prepared,
        staging_receipt,
    )?;
    if materialization.binding != *binding {
        return Err(HostError::RecoveryRequired(
            "rehydrated Agent Bridge profile/declaration proof differs from durable binding"
                .to_owned(),
        ));
    }
    let profile = launch.profile;
    let portable_root = if profile == InstallationProfile::PortableDev {
        Some(
            UserOwnedRootLease::open_existing(Path::new(
                launch
                    .portable_root
                    .as_ref()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "Agent Bridge pair rehydrate portable root is missing".to_owned(),
                        )
                    })?
                    .as_str(),
            ))
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?,
        )
    } else {
        None
    };
    let mut allowed_profile_digests = vec![&binding.profile_digest];
    let mut allowed_declaration_digests = vec![&binding.declaration_digest];
    if let Some(prior) = prior_binding {
        prior.validate().map_err(HostError::Installation)?;
        if prior.profile_path != binding.profile_path
            || prior.declaration_path != binding.declaration_path
        {
            return Err(HostError::RecoveryRequired(
                "prior committed Agent Bridge pair paths differ from the prepared pair".to_owned(),
            ));
        }
        allowed_profile_digests.push(&prior.profile_digest);
        allowed_declaration_digests.push(&prior.declaration_digest);
    }
    publish_agent_bridge_pair(
        profile,
        portable_root.as_ref(),
        &materialization,
        &allowed_profile_digests,
        &allowed_declaration_digests,
    )?;
    let bridge_directory = Path::new(binding.profile_path.as_str())
        .parent()
        .ok_or_else(|| {
            HostError::RecoveryRequired("Agent Bridge profile has no parent directory".to_owned())
        })?;
    let host_state_root = bridge_directory.parent().ok_or_else(|| {
        HostError::RecoveryRequired("Agent Bridge directory has no Host root".to_owned())
    })?;
    let acl = eliot_platform_windows::verify_agent_bridge_security(
        host_state_root,
        source.approved_user_sid.as_str(),
        Path::new(binding.profile_path.as_str()),
        Path::new(binding.declaration_path.as_str()),
    )
    .map_err(|error| {
        HostError::RecoveryRequired(format!("verify Agent Bridge final ACL: {error}"))
    })?;
    AgentBridgePhaseBBinding::from_prepared_security(
        binding.clone(),
        source.approved_user_sid.as_str(),
        PlatformHandle::new(host_state_root.to_string_lossy())
            .map_err(|error| HostError::Platform(error.to_string()))?,
        PlatformHandle::new(bridge_directory.to_string_lossy())
            .map_err(|error| HostError::Platform(error.to_string()))?,
        &acl,
    )
    .map_err(HostError::Installation)
}

#[cfg(windows)]
pub(super) fn delete_owned_agent_bridge_file(
    path: &Path,
    expected: FileIdentity,
    label: &str,
) -> Result<(), HostError> {
    if let Err(error) = std::fs::symlink_metadata(path) {
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(HostError::RecoveryRequired(format!(
            "observe Agent Bridge {label} for rollback: {error}"
        )));
    }
    let (actual, file) = open_no_follow_file_for_delete(path).map_err(|error| {
        HostError::RecoveryRequired(format!("open Agent Bridge {label} for rollback: {error}"))
    })?;
    if actual != expected {
        return Err(HostError::RecoveryRequired(format!(
            "Agent Bridge {label} identity is foreign during rollback"
        )));
    }
    delete_owned_file_handle(file, expected).map_err(|error| {
        HostError::RecoveryRequired(format!("delete owned Agent Bridge {label}: {error}"))
    })
}

#[cfg(windows)]
fn delete_agent_bridge_file_if_digest(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    expected_digest: &PlatformHandle,
    label: &str,
) -> Result<(), HostError> {
    let lease = match phase_b_open_existing(profile, portable_root, path) {
        Ok(lease) => lease,
        Err(HostError::RecoveryRequired(reason)) if reason.contains("missing") => return Ok(()),
        Err(error) => return Err(error),
    };
    lease.verify().map_err(HostError::RecoveryRequired)?;
    let bytes = phase_b_lease_bytes(&lease)?;
    if phase_b_bytes_digest(&bytes)? != *expected_digest {
        return Err(HostError::RecoveryRequired(format!(
            "Agent Bridge {label} rollback encountered foreign bytes"
        )));
    }
    let (identity, file) = open_no_follow_file_for_delete(path).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "open Agent Bridge {label} for retained-handle rollback: {error}"
        ))
    })?;
    delete_owned_file_handle(file, identity).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "delete owned Agent Bridge {label} during rollback: {error}"
        ))
    })
}

#[cfg(windows)]
pub(super) fn rollback_agent_bridge_pair(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    binding: &AgentBridgePreparedBinding,
) -> Result<(), HostError> {
    for (path, expected, label) in [
        (
            Path::new(binding.profile_path.as_str()),
            &binding.profile_digest,
            "admission profile",
        ),
        (
            Path::new(binding.declaration_path.as_str()),
            &binding.declaration_digest,
            "client declaration",
        ),
    ] {
        let backup = phase_b_rollback_path(path, label)?;
        if std::fs::symlink_metadata(&backup).is_ok() {
            let backup_lease = phase_b_open_existing(profile, portable_root, &backup)?;
            backup_lease.verify().map_err(HostError::RecoveryRequired)?;
            let prior_bytes = phase_b_lease_bytes(&backup_lease)?;
            let prior_digest = phase_b_bytes_digest(&prior_bytes)?;
            let current = match phase_b_open_existing(profile, portable_root, path) {
                Ok(lease) => {
                    lease.verify().map_err(HostError::RecoveryRequired)?;
                    let bytes = phase_b_lease_bytes(&lease)?;
                    Some((phase_b_bytes_digest(&bytes)?, bytes))
                }
                Err(HostError::RecoveryRequired(reason)) if reason.contains("missing") => None,
                Err(error) => return Err(error),
            };
            if let Some((current_digest, _)) = current.as_ref()
                && current_digest != expected
                && current_digest != &prior_digest
            {
                return Err(HostError::RecoveryRequired(format!(
                    "Agent Bridge {label} rollback encountered foreign bytes"
                )));
            }
            if current
                .as_ref()
                .is_none_or(|(digest, _)| digest != &prior_digest)
            {
                phase_b_materialize_file(
                    profile,
                    portable_root,
                    path,
                    &prior_bytes,
                    &[expected, &prior_digest],
                    &format!("{label} rollback restore"),
                )?;
            }
        } else {
            delete_agent_bridge_file_if_digest(profile, portable_root, path, expected, label)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn rollback_agent_bridge_stage(
    stage: &AgentBridgeStagePrepared,
) -> Result<(), HostError> {
    stage.validate().map_err(HostError::Installation)?;
    let temporary_path = PathBuf::from(stage.temporary_path.as_str());
    let destination_path = PathBuf::from(stage.destination_path.as_str());
    if temporary_path == destination_path {
        return Err(HostError::RecoveryRequired(
            "Agent Bridge temporary and destination paths unexpectedly match".to_owned(),
        ));
    }
    delete_owned_agent_bridge_file(&temporary_path, stage.temporary_identity, "temporary stage")?;
    delete_owned_agent_bridge_file(
        &destination_path,
        stage.temporary_identity,
        "published stage",
    )
}

#[cfg(windows)]
pub(super) fn phase_b_lease_identity(lease: &LaunchLease) -> FileIdentity {
    match lease {
        LaunchLease::Protected(lease) => lease.identity(),
        LaunchLease::Portable(lease) => lease.identity(),
    }
}

#[cfg(windows)]
pub(super) fn phase_b_lease_bytes(lease: &LaunchLease) -> Result<Vec<u8>, HostError> {
    lease
        .read_bounded(1024 * 1024)
        .map_err(|error| HostError::RecoveryRequired(format!("read Phase-B file: {error}")))
}

#[cfg(windows)]
pub(super) fn phase_b_bytes_digest(bytes: &[u8]) -> Result<PlatformHandle, HostError> {
    PlatformHandle::new(format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(windows)]
pub(super) fn phase_b_materialize_file(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    allowed_existing_digests: &[&PlatformHandle],
    label: &str,
) -> Result<(PlatformHandle, FileIdentity), HostError> {
    phase_b_materialize_file_inner(
        profile,
        portable_root,
        path,
        desired,
        allowed_existing_digests,
        label,
        false,
    )
}

#[cfg(windows)]
pub(super) fn phase_b_materialize_file_with_rollback(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    allowed_existing_digests: &[&PlatformHandle],
    label: &str,
) -> Result<(PlatformHandle, FileIdentity), HostError> {
    phase_b_materialize_file_inner(
        profile,
        portable_root,
        path,
        desired,
        allowed_existing_digests,
        label,
        true,
    )
}

#[cfg(windows)]
fn phase_b_materialize_file_inner(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    path: &Path,
    desired: &[u8],
    allowed_existing_digests: &[&PlatformHandle],
    label: &str,
    retain_previous: bool,
) -> Result<(PlatformHandle, FileIdentity), HostError> {
    let desired_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(desired)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let mut previous_bytes = None;
    if let Ok(lease) = open_launch_lease(profile, portable_root, path) {
        lease.verify().map_err(HostError::RecoveryRequired)?;
        let current = phase_b_lease_bytes(&lease)?;
        let current_digest = format!("{:x}", Sha256::digest(&current));
        if current == desired {
            return Ok((desired_digest, phase_b_lease_identity(&lease)));
        }
        if !allowed_existing_digests
            .iter()
            .any(|digest| digest.as_str() == current_digest)
        {
            return Err(HostError::RecoveryRequired(format!(
                "Phase-B {label} destination is neither the immutable template nor the exact live bytes"
            )));
        }
        if retain_previous {
            previous_bytes = Some(current);
        }
    } else if std::fs::symlink_metadata(path).is_ok() {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} destination exists but cannot be retained"
        )));
    }

    let parent = path.parent().ok_or_else(|| {
        HostError::RecoveryRequired(format!("Phase-B {label} destination has no parent"))
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!("Phase-B {label} destination name is invalid"))
        })?;
    let adapter = WindowsPlatform::new(parent).map_err(|error| {
        HostError::RecoveryRequired(format!("prepare Phase-B {label}: {error}"))
    })?;
    let relative = WorkScopePath::new(file_name)
        .map_err(|error| HostError::RecoveryRequired(format!("Phase-B {label} path: {error}")))?;
    if let Some(previous) = previous_bytes.as_deref() {
        phase_b_write_rollback_backup(profile, portable_root, path, previous, label)?;
    }
    match adapter
        .publish_atomic(&relative, desired)
        .map_err(|error| HostError::RecoveryRequired(format!("publish Phase-B {label}: {error}")))?
    {
        PublicationOutcome::Published(receipt) => {
            if receipt.identity.file_index == 0 || receipt.identity.volume_serial_number == 0 {
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} publication receipt has no retained OS identity"
                )));
            }
        }
        PublicationOutcome::Unknown(_) => {
            // The replacement may already have committed. Reconcile the exact
            // destination once; never resend bytes after an unknown outcome.
            let lease = phase_b_open_existing(profile, portable_root, path)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            if phase_b_lease_bytes(&lease)? != desired {
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} publication outcome is unknown and readback is not exact"
                )));
            }
        }
    }
    let lease = phase_b_open_existing(profile, portable_root, path)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    if phase_b_lease_bytes(&lease)? != desired {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} publication readback is not exact"
        )));
    }
    Ok((desired_digest, phase_b_lease_identity(&lease)))
}

#[cfg(windows)]
fn phase_b_rollback_path(destination: &Path, label: &str) -> Result<PathBuf, HostError> {
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

#[cfg(windows)]
fn phase_b_write_rollback_backup(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    previous: &[u8],
    label: &str,
) -> Result<(), HostError> {
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
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B {label} rollback backup outcome is unknown"
                )));
            }
        }
    }
    let lease = phase_b_open_existing(profile, portable_root, &backup)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    if phase_b_lease_bytes(&lease)? != previous {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} rollback backup readback is not exact"
        )));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_restore_or_remove(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    label: &str,
    preserve_template_digest: Option<&PlatformHandle>,
) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label)?;
    if std::fs::symlink_metadata(&backup).is_ok() {
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
    } else if std::fs::symlink_metadata(destination).is_ok() {
        let lease = phase_b_open_existing(profile, portable_root, destination)?;
        lease.verify().map_err(HostError::RecoveryRequired)?;
        let current = phase_b_lease_bytes(&lease)?;
        let current_digest = phase_b_bytes_digest(&current)?;
        if preserve_template_digest.is_none_or(|expected| expected != &current_digest) {
            std::fs::remove_file(destination).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "remove uncommitted Phase-B {label} destination: {error}"
                ))
            })?;
            if std::fs::symlink_metadata(destination).is_ok() {
                return Err(HostError::RecoveryRequired(format!(
                    "uncommitted Phase-B {label} destination remains after rollback"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_remove_rollback_backup(
    destination: &Path,
    label: &str,
) -> Result<(), HostError> {
    let backup = phase_b_rollback_path(destination, label)?;
    if std::fs::symlink_metadata(&backup).is_ok() {
        std::fs::remove_file(&backup).map_err(|error| {
            HostError::RecoveryRequired(format!("remove Phase-B {label} rollback backup: {error}"))
        })?;
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_template_path(destination: &Path, label: &str) -> Result<PathBuf, HostError> {
    let parent = destination.parent().ok_or_else(|| {
        HostError::RecoveryRequired(format!(
            "Phase-B {label} template destination has no parent"
        ))
    })?;
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            HostError::RecoveryRequired(format!(
                "Phase-B {label} template destination name is invalid"
            ))
        })?;
    let retained_name = format!("{file_name}.phase-a-template");
    WorkScopePath::new(&retained_name).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "Phase-B {label} template path is not within the protected scope: {error}"
        ))
    })?;
    Ok(parent.join(retained_name))
}

#[cfg(windows)]
pub(super) fn phase_b_template_bytes(
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
    destination: &Path,
    expected_digest: &PlatformHandle,
    label: &str,
) -> Result<Vec<u8>, HostError> {
    // Phase A's destination is an immutable approved template until Host
    // first publishes the live overlay. Retain the exact bytes in a Host
    // scoped sidecar before that replacement so a fresh Host epoch can
    // validate a later replay without reconstructing authority from JSON.
    let retained_path = phase_b_template_path(destination, label)?;
    let (source_bytes, retained_exists) = match std::fs::symlink_metadata(&retained_path) {
        Ok(_) => {
            let lease = phase_b_open_existing(profile, portable_root, &retained_path)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            (phase_b_lease_bytes(&lease)?, true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let lease = phase_b_open_existing(profile, portable_root, destination)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            (phase_b_lease_bytes(&lease)?, false)
        }
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Phase-B {label} template cannot be observed: {error}"
            )));
        }
    };
    let source_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&source_bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if source_digest != *expected_digest {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} template digest is not the immutable Phase-A digest"
        )));
    }
    if !retained_exists {
        let retained_label = format!("{label} immutable template");
        phase_b_materialize_file(
            profile,
            portable_root,
            &retained_path,
            &source_bytes,
            &[expected_digest],
            &retained_label,
        )?;
    }
    let lease = phase_b_open_existing(profile, portable_root, &retained_path)?;
    lease.verify().map_err(HostError::RecoveryRequired)?;
    let retained_bytes = phase_b_lease_bytes(&lease)?;
    if retained_bytes != source_bytes {
        return Err(HostError::RecoveryRequired(format!(
            "Phase-B {label} retained template readback is not exact"
        )));
    }
    Ok(retained_bytes)
}
