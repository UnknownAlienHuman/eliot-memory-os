use serde::Deserialize;

use super::{
    ActivationCommitFence, ActivePhaseBRebind, ActivePhaseBRebindIntent, ActivePhaseBRebindReceipt,
    ActivePhaseBRebindRecovery, ApprovedGeneration, ApprovedGenerationRegistry, CandidateManifest,
    ContractVersion, HostPhaseBMaterializationIntent, HostPhaseBMaterializationReceipt,
    HostPhaseBPreparedMaterialization, INSTALLATION_REGISTRY_WIRE_VERSION,
    InstallationActivationApproval, InstallationEpoch, InstallationError, InstallationProfile,
    InstallerServiceRegistrationApproval, PendingActivation, PendingActivationState,
    PendingActivationTerminal, PendingActivationTerminalDisposition, PlatformHandle,
    ResourceGeneration, RuntimeStateRoots, StateFence,
};

/// Private deserialization mirror for an authority-issued approval.  The
/// public approval type intentionally has no `Deserialize` implementation;
/// only this registry boundary may reconstruct a previously sealed value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationActivationApprovalWire {
    approval_ref: PlatformHandle,
    transaction_id: PlatformHandle,
    installer_plan_digest: PlatformHandle,
    generation: PlatformHandle,
    candidate_manifest_digest: PlatformHandle,
    runtime_descriptor_digest: PlatformHandle,
    required_owner: PlatformHandle,
    signature_ref: PlatformHandle,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
}

impl InstallationActivationApprovalWire {
    fn into_approval(self) -> InstallationActivationApproval {
        InstallationActivationApproval {
            approval_ref: self.approval_ref,
            transaction_id: self.transaction_id,
            installer_plan_digest: self.installer_plan_digest,
            generation: self.generation,
            candidate_manifest_digest: self.candidate_manifest_digest,
            runtime_descriptor_digest: self.runtime_descriptor_digest,
            required_owner: self.required_owner,
            signature_ref: self.signature_ref,
            authority_descriptor_path: self.authority_descriptor_path,
            authority_descriptor_digest: self.authority_descriptor_digest,
            authority_generation: self.authority_generation,
            authority_state_fence: self.authority_state_fence,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedGenerationWire {
    manifest: CandidateManifest,
    approval: InstallationActivationApprovalWire,
    active: bool,
    last_known_good: bool,
}

impl ApprovedGenerationWire {
    fn into_generation(self) -> ApprovedGeneration {
        ApprovedGeneration {
            manifest: self.manifest,
            approval: self.approval.into_approval(),
            active: self.active,
            last_known_good: self.last_known_good,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationWire {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    manifest: CandidateManifest,
    config_digest: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    host_executable_path: PlatformHandle,
    host_artifact_digest: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    manifest_digest: PlatformHandle,
    prior_active_generation: Option<PlatformHandle>,
    approval: InstallationActivationApprovalWire,
    phase_b_intent: RequiredOption<HostPhaseBMaterializationIntent>,
    phase_b_prepared: RequiredOption<HostPhaseBPreparedMaterialization>,
    phase_b_receipt: RequiredOption<HostPhaseBMaterializationReceipt>,
    state: PendingActivationState,
}

impl PendingActivationWire {
    fn into_pending(self) -> PendingActivation {
        PendingActivation {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            manifest: self.manifest,
            config_digest: self.config_digest,
            kernel_artifact_digest: self.kernel_artifact_digest,
            store_bridge_artifact_digest: self.store_bridge_artifact_digest,
            canonical_store_artifact_digest: self.canonical_store_artifact_digest,
            host_executable_path: self.host_executable_path,
            host_artifact_digest: self.host_artifact_digest,
            runtime_state_roots_digest: self.runtime_state_roots_digest,
            manifest_digest: self.manifest_digest,
            prior_active_generation: self.prior_active_generation,
            approval: self.approval.into_approval(),
            phase_b_intent: self.phase_b_intent.0,
            phase_b_prepared: self.phase_b_prepared.0,
            phase_b_receipt: self.phase_b_receipt.0,
            state: self.state,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationTerminalWire {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    generation: PlatformHandle,
    disposition: PendingActivationTerminalDisposition,
    /// The member is mandatory on the current wire, while explicit `null`
    /// remains the only valid value for an aborted terminal.
    commit_fence: RequiredOption<ActivationCommitFence>,
}

impl PendingActivationTerminalWire {
    fn into_terminal(self) -> PendingActivationTerminal {
        PendingActivationTerminal {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            generation: self.generation,
            disposition: self.disposition,
            commit_fence: self.commit_fence.0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivePhaseBRebindWireV11 {
    intent: ActivePhaseBRebindIntent,
    prepared: RequiredOption<HostPhaseBPreparedMaterialization>,
    receipt: RequiredOption<ActivePhaseBRebindReceipt>,
    recovery_history: Vec<ActivePhaseBRebindRecovery>,
}

impl ActivePhaseBRebindWireV11 {
    fn into_rebind(self) -> ActivePhaseBRebind {
        ActivePhaseBRebind {
            intent: self.intent,
            prepared: self.prepared.0,
            receipt: self.receipt.0,
            recovery_history: self.recovery_history,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryWireV11 {
    registry_wire_version: ContractVersion,
    revision: u64,
    generations: Vec<ApprovedGenerationWire>,
    service_registration_approvals: Vec<InstallerServiceRegistrationApproval>,
    active_generation: RequiredOption<PlatformHandle>,
    last_known_good_generation: RequiredOption<PlatformHandle>,
    pending_activation: RequiredOption<PendingActivationWire>,
    last_terminal_activation: RequiredOption<PendingActivationTerminalWire>,
    active_phase_b_rebind: RequiredOption<ActivePhaseBRebindWireV11>,
}

/// An optional wire member whose presence is mandatory.  Explicit `null` is
/// the only valid empty value; an omitted member is a schema migration rather
/// than an implicit serde default.
struct RequiredOption<T>(Option<T>);

impl<'de, T> Deserialize<'de> for RequiredOption<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

impl RegistryWireV11 {
    fn into_registry(self) -> ApprovedGenerationRegistry {
        ApprovedGenerationRegistry {
            registry_wire_version: self.registry_wire_version,
            revision: self.revision,
            generations: self
                .generations
                .into_iter()
                .map(ApprovedGenerationWire::into_generation)
                .collect(),
            service_registration_approvals: self.service_registration_approvals,
            active_generation: self.active_generation.0,
            last_known_good_generation: self.last_known_good_generation.0,
            pending_activation: self
                .pending_activation
                .0
                .map(PendingActivationWire::into_pending),
            last_terminal_activation: self
                .last_terminal_activation
                .0
                .map(PendingActivationTerminalWire::into_terminal),
            active_phase_b_rebind: self
                .active_phase_b_rebind
                .0
                .map(ActivePhaseBRebindWireV11::into_rebind),
        }
    }
}

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRegistryWire {
    generations: Vec<LegacyApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
}

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyApprovedGenerationWire {
    manifest: LegacyCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_launch: LegacyRuntimeLaunchDescriptor,
}

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeLaunchDescriptor {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitRegistryWire {
    generations: Vec<PreSplitApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitApprovedGenerationWire {
    manifest: PreSplitCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    runtime_launch: PreSplitRuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitRuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    runtime_state_roots: RuntimeStateRoots,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1RegistryWire {
    generations: Vec<V1ApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1ApprovedGenerationWire {
    manifest: V1CandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1CandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_launch: V1RuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1RuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingRegistryWire {
    generations: Vec<PreHostArtifactBindingApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
    pending_activation: Option<serde_json::Value>,
    last_terminal_activation: Option<serde_json::Value>,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingApprovedGenerationWire {
    manifest: PreHostArtifactBindingCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    store_credential_target: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    runtime_launch: PreHostArtifactBindingRuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingRuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    runtime_state_roots: RuntimeStateRoots,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    eliotd_executable_path: PlatformHandle,
    eliotd_artifact_digest: PlatformHandle,
    eliotd_config_path: PlatformHandle,
    eliotd_config_digest: PlatformHandle,
    eliotd_descriptor_path: PlatformHandle,
    eliotd_descriptor_digest: PlatformHandle,
    eliotd_launch_nonce: PlatformHandle,
    store_config_path: PlatformHandle,
    store_credential_target: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    store_bridge_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingRegistryWire {
    generations: Vec<PreCredentialBindingApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
    pending_activation: Option<serde_json::Value>,
    last_terminal_activation: Option<serde_json::Value>,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingApprovedGenerationWire {
    manifest: PreCredentialBindingCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    runtime_launch: PreCredentialBindingRuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingRuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    runtime_state_roots: RuntimeStateRoots,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    store_bridge_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreServiceRegistrationApprovalRegistryWire {
    generations: Vec<serde_json::Value>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
    pending_activation: Option<serde_json::Value>,
    last_terminal_activation: Option<serde_json::Value>,
}

fn registry_has_prior_shape(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    [
        "generations",
        "active_generation",
        "last_known_good_generation",
    ]
    .iter()
    .all(|field| object.contains_key(*field))
}

fn registry_runtime_objects(
    value: &serde_json::Value,
) -> impl Iterator<Item = &serde_json::Map<String, serde_json::Value>> {
    value
        .get("generations")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flat_map(|generations| generations.iter())
        .filter_map(serde_json::Value::as_object)
        .filter_map(|generation| generation.get("manifest"))
        .filter_map(serde_json::Value::as_object)
        .filter_map(|manifest| manifest.get("runtime_launch"))
        .filter_map(serde_json::Value::as_object)
}

fn is_pre_eliotd_config_registry(value: &serde_json::Value) -> bool {
    let mut seen = false;
    for runtime in registry_runtime_objects(value) {
        seen = true;
        if runtime.contains_key("eliotd_config_path")
            || runtime.contains_key("eliotd_config_digest")
        {
            return false;
        }
    }
    seen
}

fn current_registry_wire_missing_field(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return true;
    };
    let top_level_missing = [
        "registry_wire_version",
        "revision",
        "generations",
        "service_registration_approvals",
        "active_generation",
        "last_known_good_generation",
        "pending_activation",
        "last_terminal_activation",
        "active_phase_b_rebind",
    ]
    .iter()
    .any(|field| !object.contains_key(*field));
    let approval_binding_missing = object
        .get("service_registration_approvals")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|approvals| {
            approvals.iter().any(|approval| {
                approval
                    .as_object()
                    .is_none_or(|approval| !approval.contains_key("service_control_grant"))
            })
        });
    top_level_missing || approval_binding_missing
}

#[allow(
    clippy::too_many_lines,
    reason = "registry decoding keeps strict current-wire and migration classification together"
)]
pub(super) fn decode_registry_bytes(
    bytes: &[u8],
) -> Result<ApprovedGenerationRegistry, InstallationError> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|error| {
        InstallationError::CorruptRegistry {
            reason: format!("registry bytes are not valid JSON: {error}"),
        }
    })?;

    let declared_major = value
        .get("registry_wire_version")
        .and_then(|version| version.get("major"))
        .and_then(serde_json::Value::as_u64);
    if declared_major == Some(10) {
        return Err(InstallationError::MigrationRequired {
            reason: "approved-generation registry wire v10 contains the legacy Host owner-epoch/Phase-B rebind digest domain and requires explicit re-stage as v14; nested authority is never synthesized or adopted"
                .to_owned(),
        });
    }
    if declared_major == Some(u64::from(INSTALLATION_REGISTRY_WIRE_VERSION.major))
        && current_registry_wire_missing_field(&value)
    {
        return Err(InstallationError::CorruptRegistry {
            reason: "registry wire v14 is missing mandatory fields or contains an invalid field"
                .to_owned(),
        });
    }

    if let Ok(wire) = serde_json::from_value::<RegistryWireV11>(value.clone()) {
        if wire.registry_wire_version != INSTALLATION_REGISTRY_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "approved-generation registry wire {} requires explicit re-stage as {}",
                    wire.registry_wire_version, INSTALLATION_REGISTRY_WIRE_VERSION
                ),
            });
        }
        if wire.revision == 0 {
            return Err(InstallationError::CorruptRegistry {
                reason: "current registry revision must be non-zero".to_owned(),
            });
        }
        let registry = wire.into_registry();
        registry
            .validate()
            .map_err(|_| InstallationError::CorruptRegistry {
                reason: "current registry projection failed validation".to_owned(),
            })?;
        return Ok(registry);
    }

    if let Some(version) = declared_major {
        if version < u64::from(INSTALLATION_REGISTRY_WIRE_VERSION.major) {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "approved-generation registry wire v{version} requires explicit re-stage as v{}",
                    INSTALLATION_REGISTRY_WIRE_VERSION.major
                ),
            });
        }
        return Err(InstallationError::CorruptRegistry {
            reason: "registry wire v14 is missing mandatory fields or contains an invalid field"
                .to_owned(),
        });
    }

    if registry_has_prior_shape(&value) {
        if value.as_object().is_some_and(|object| {
            object.keys().any(|field| {
                !matches!(
                    field.as_str(),
                    "generations"
                        | "active_generation"
                        | "last_known_good_generation"
                        | "service_registration_approvals"
                        | "pending_activation"
                        | "last_terminal_activation"
                        | "active_phase_b_rebind"
                        | "registry_wire_version"
                        | "revision"
                )
            })
        }) {
            return Err(InstallationError::CorruptRegistry {
                reason: "prior registry schema contains unknown fields".to_owned(),
            });
        }
        let runtimes = registry_runtime_objects(&value).collect::<Vec<_>>();
        let manifests_missing_store_credential_target = value
            .get("generations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|generations| {
                generations.iter().any(|generation| {
                    generation
                        .get("manifest")
                        .and_then(serde_json::Value::as_object)
                        .is_some_and(|manifest| !manifest.contains_key("store_credential_target"))
                })
            });
        let has_pending = value.get("pending_activation").is_some();
        if manifests_missing_store_credential_target
            || runtimes
                .iter()
                .any(|runtime| !runtime.contains_key("store_credential_target"))
        {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates the descriptor-bound Store credential target and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if runtimes.iter().any(|runtime| {
            !runtime.contains_key("host_executable_path")
                || !runtime.contains_key("host_artifact_digest")
        }) {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates the approved Host executable artifact binding and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if runtimes
            .iter()
            .any(|runtime| !runtime.contains_key("store_bridge_arguments"))
        {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates split Store bridge/provider argv and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if is_pre_eliotd_config_registry(&value) {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates the separate eliotd Governor config binding and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if value.get("service_registration_approvals").is_none() {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates installer-owned SCM registration approvals and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if !has_pending {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates durable pending activation and requires explicit re-stage"
                    .to_owned(),
            });
        }
        return Err(InstallationError::MigrationRequired {
            reason: "approved-generation registry v2/pre-CAS requires explicit re-stage with a mandatory wire revision"
                .to_owned(),
        });
    }

    Err(InstallationError::CorruptRegistry {
        reason: "registry bytes are neither current nor structurally valid prior schema".to_owned(),
    })
}
