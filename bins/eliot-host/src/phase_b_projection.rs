use std::time::{SystemTime, UNIX_EPOCH};

use sha2::Digest;

use super::{
    ActivePhaseBRebindIntent, AuthorityEpoch, AuthoritySnapshotBindingWire, CandidateManifest,
    CredentialAccessReceipt, DispatchAuthorityId, EpochIdentity, EpochLineage, HostError,
    HostInstallationEpoch, HostPhaseBMaterialization, HostPhaseBMaterializationIntent,
    HostPhaseBMaterializationReceipt, LOCAL_SERVICE_SID, OpaqueLabel, OperationIdentity,
    OrsEpochIdentity, PhaseBLiveBinding, PlatformHandle, ProcessAuthorityHandoffDescriptor,
    ProvisionedSupervisionAuthority, SecretReference, Sha256, StateFence, StateFenceSnapshot,
    StoreCredentialProvider, StoreCredentialScope, host_owner_epoch_digest,
    installation_phase_b_credential_receipt_digest, installation_phase_b_host_state_root_digest,
    installation_phase_b_watchdog_selector_digest, observe_named_pipe_peer_process,
};

#[cfg(windows)]
pub(super) fn phase_b_manifest_digest(
    manifest: &CandidateManifest,
) -> Result<PlatformHandle, HostError> {
    manifest
        .compute_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn host_process_identity_digest() -> Result<PlatformHandle, HostError> {
    let observed = observe_named_pipe_peer_process(std::process::id())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    PlatformHandle::new(format!(
        "{:x}",
        Sha256::digest(observed.identity().stable_key().as_bytes())
    ))
    .map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(windows)]
pub(super) fn host_process_identity_digest_for_host(
    host: &HostInstallationEpoch,
) -> Result<PlatformHandle, HostError> {
    #[cfg(test)]
    {
        // The physical test-support graph intentionally has no live Kernel
        // peer. Keep the production identity domain explicit while deriving
        // a deterministic process binding from the exact Host epoch, so a
        // direct-child reopen receives a fresh identity and same-owner retries
        // remain idempotent.
        let image = std::env::current_exe()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "eliot.host.test-support-process.v1\0{}\0{}\0{}",
                    image.to_string_lossy(),
                    host.epoch.current.lineage,
                    host.epoch.current.sequence,
                )
                .as_bytes(),
            )
        ))
        .map_err(|error| HostError::Platform(error.to_string()))
    }
    #[cfg(not(test))]
    {
        let _ = host;
        host_process_identity_digest()
    }
}

#[cfg(windows)]
pub(super) fn phase_b_credential_receipt_digest(
    receipt: &CredentialAccessReceipt,
) -> Result<PlatformHandle, HostError> {
    installation_phase_b_credential_receipt_digest(receipt).map_err(HostError::Installation)
}

#[cfg(windows)]
pub(super) fn validate_phase_b_credential_receipt(
    receipt: &CredentialAccessReceipt,
    manifest: &CandidateManifest,
    intent: &HostPhaseBMaterializationIntent,
) -> Result<(), HostError> {
    receipt
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    if receipt.transaction_id != intent.transaction_id
        || receipt.effect_id != intent.credential_effect_id
        || receipt.generation != manifest.runtime_launch.authority_generation
        || receipt.config_digest != manifest.config_digest
        || receipt.target != manifest.runtime_launch.store_credential_target
        || receipt.provider != StoreCredentialProvider::WindowsCredentialManager
        || receipt.scope != StoreCredentialScope::LocalService
        || receipt.principal_sid.as_str() != LOCAL_SERVICE_SID
    {
        return Err(HostError::RecoveryRequired(
            "Phase-B credential receipt is not the exact LocalService receipt for the candidate"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn phase_b_root_binding_digest(
    manifest: &CandidateManifest,
) -> Result<PlatformHandle, HostError> {
    installation_phase_b_host_state_root_digest(manifest).map_err(HostError::Installation)
}

#[cfg(windows)]
pub(super) fn phase_b_watchdog_selector_digest(
    manifest: &CandidateManifest,
) -> Result<PlatformHandle, HostError> {
    installation_phase_b_watchdog_selector_digest(manifest).map_err(HostError::Installation)
}

#[cfg(windows)]
pub(super) fn phase_b_public_receipt(
    intent: &HostPhaseBMaterializationIntent,
    materialization: &HostPhaseBMaterialization,
    host: &HostInstallationEpoch,
) -> Result<HostPhaseBMaterializationReceipt, HostError> {
    if materialization.request_digest.as_ref() != Some(&intent.request_digest) {
        return Err(HostError::RecoveryRequired(
            "Host Phase-B receipt is not bound to the requested transaction effect".to_owned(),
        ));
    }
    let host_owner_epoch = materialization
        .host_owner_epoch
        .clone()
        .unwrap_or(host_owner_epoch_digest(host)?);
    let host_process_identity = materialization
        .host_process_identity
        .clone()
        .unwrap_or(host_process_identity_digest()?);
    let mut receipt = HostPhaseBMaterializationReceipt {
        transaction_id: intent.transaction_id.clone(),
        effect_id: intent.effect_id.clone(),
        candidate_manifest_digest: materialization.manifest_digest.clone(),
        request_digest: intent.request_digest.clone(),
        host_owner_epoch,
        host_process_identity,
        authority_descriptor_digest: materialization.authority_descriptor_digest.clone(),
        config_file_digest: materialization.config_file_digest.clone(),
        store_bootstrap_descriptor_digest: materialization
            .store_bootstrap_descriptor_digest
            .clone(),
        eliotd_descriptor_digest: materialization.eliotd_descriptor_digest.clone(),
        provisioned_supervision_authority: intent.provisioned_supervision_authority.clone(),
        receipt_digest: PlatformHandle::new("pending")
            .map_err(|error| HostError::Platform(error.to_string()))?,
    };
    receipt.receipt_digest = receipt
        .computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    receipt
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    Ok(receipt)
}

#[cfg(windows)]
pub(super) fn phase_b_public_receipt_from_binding(
    intent: &HostPhaseBMaterializationIntent,
    binding: &PhaseBLiveBinding,
    credential_receipt: &CredentialAccessReceipt,
) -> Result<HostPhaseBMaterializationReceipt, HostError> {
    credential_receipt
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    if binding.manifest_digest != intent.candidate_manifest_digest
        || binding.effect_id != intent.effect_id
        || binding.credential_receipt_digest != intent.credential_receipt_digest
        || binding.request_digest != intent.request_digest
        || binding.host_owner_epoch != credential_receipt.host_owner_epoch
        || binding.host_process_identity != credential_receipt.host_process_identity
        || binding.provisioned_supervision_authority != intent.provisioned_supervision_authority
        || phase_b_credential_receipt_digest(credential_receipt)?
            != binding.credential_receipt_digest
    {
        return Err(HostError::RecoveryRequired(
            "persisted Phase-B receipt is bound to a different request".to_owned(),
        ));
    }
    let receipt = HostPhaseBMaterializationReceipt {
        transaction_id: intent.transaction_id.clone(),
        effect_id: binding.effect_id.clone(),
        candidate_manifest_digest: binding.manifest_digest.clone(),
        request_digest: binding.request_digest.clone(),
        host_owner_epoch: binding.host_owner_epoch.clone(),
        host_process_identity: binding.host_process_identity.clone(),
        authority_descriptor_digest: binding.authority_descriptor_digest.clone(),
        config_file_digest: binding.config_file_digest.clone(),
        store_bootstrap_descriptor_digest: binding.store_bootstrap_descriptor_digest.clone(),
        eliotd_descriptor_digest: binding.eliotd_descriptor_digest.clone(),
        provisioned_supervision_authority: binding.provisioned_supervision_authority.clone(),
        receipt_digest: binding.public_receipt_digest.clone(),
    };
    receipt
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    Ok(receipt)
}

#[cfg(windows)]
pub(super) fn phase_b_build_authority_descriptor(
    manifest: &CandidateManifest,
    host: &HostInstallationEpoch,
    activation_generation: &EpochIdentity,
    intent: &HostPhaseBMaterializationIntent,
) -> Result<Vec<u8>, HostError> {
    let runtime = &manifest.runtime_launch;
    let authority_id = DispatchAuthorityId::new(intent.static_template.authority_id.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let record_id = OperationIdentity::new(intent.static_template.record_id.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let lineage_id = OpaqueLabel::new(host.epoch.current.lineage.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let authority_epoch = EpochLineage {
        current: OrsEpochIdentity {
            lineage_id,
            epoch: host.epoch.current.sequence,
        },
        predecessor: None,
    };
    let authority = AuthorityEpoch::new(host.epoch.current.sequence)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let state_fence = StateFence::new(authority, runtime.authority_generation);
    let snapshot_fence = StateFenceSnapshot::capture(&state_fence, host.epoch.current.sequence)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| HostError::ProcessContour("Phase-B clock overflow".to_owned()))?;
    let dispatch_target = eliot_installation::dispatch_credential_target_for_store_target(
        &runtime.store_credential_target,
    )
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let dispatch_key = SecretReference::new("windows-credential-manager", dispatch_target.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let mut descriptor = ProcessAuthorityHandoffDescriptor {
        contract_version: ProcessAuthorityHandoffDescriptor::CONTRACT_VERSION,
        handoff_id: PlatformHandle::new(format!(
            "phase-b:{}:{}",
            intent.transaction_id, host.epoch.current.sequence
        ))
        .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        handoff_nonce: host.nonce.clone(),
        authority_id: authority_id.clone(),
        snapshot_binding: AuthoritySnapshotBindingWire {
            authority_id,
            record_id,
            authority_epoch,
            state_fence: snapshot_fence,
            created_at_ms: now_ms,
            cleanup_after_ms: Some(now_ms.saturating_add(86_400_000)),
        },
        state_fence: state_fence.clone(),
        generation: runtime.authority_generation,
        revision_policy_binding: intent.static_template.revision_policy_binding.clone(),
        dispatch_key,
        supervision_authority: intent.provisioned_supervision_authority.clone(),
        descriptor_sha256: String::new(),
        issued_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(86_400_000),
        contour_refs: intent.static_template.contour_refs.clone(),
    };
    let marker = phase_b_authority_marker(
        &phase_b_manifest_digest(manifest)?,
        host,
        activation_generation,
        &descriptor,
    )?;
    descriptor.contour_refs.push(marker);
    descriptor = descriptor
        .with_computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    descriptor
        .validate_structure()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    serde_json::to_vec(&descriptor).map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn phase_b_build_authority_descriptor_for_rebind(
    manifest: &CandidateManifest,
    host: &HostInstallationEpoch,
    activation_generation: &EpochIdentity,
    intent: &ActivePhaseBRebindIntent,
    provisioned_supervision_authority: &ProvisionedSupervisionAuthority,
) -> Result<Vec<u8>, HostError> {
    let runtime = &manifest.runtime_launch;
    let authority_id = DispatchAuthorityId::new(intent.static_template.authority_id.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let record_id = OperationIdentity::new(intent.static_template.record_id.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let lineage_id = OpaqueLabel::new(host.epoch.current.lineage.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let authority_epoch = EpochLineage {
        current: OrsEpochIdentity {
            lineage_id,
            epoch: host.epoch.current.sequence,
        },
        predecessor: None,
    };
    let authority = AuthorityEpoch::new(host.epoch.current.sequence)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let state_fence = StateFence::new(authority, runtime.authority_generation);
    let snapshot_fence = StateFenceSnapshot::capture(&state_fence, host.epoch.current.sequence)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| HostError::ProcessContour("Phase-B clock overflow".to_owned()))?;
    let dispatch_target = eliot_installation::dispatch_credential_target_for_store_target(
        &runtime.store_credential_target,
    )
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let dispatch_key = SecretReference::new("windows-credential-manager", dispatch_target.as_str())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let mut descriptor = ProcessAuthorityHandoffDescriptor {
        contract_version: ProcessAuthorityHandoffDescriptor::CONTRACT_VERSION,
        handoff_id: PlatformHandle::new(format!(
            "phase-b-active-rebind:{}:{}",
            intent.effect_id, host.epoch.current.sequence
        ))
        .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        handoff_nonce: host.nonce.clone(),
        authority_id: authority_id.clone(),
        snapshot_binding: AuthoritySnapshotBindingWire {
            authority_id,
            record_id,
            authority_epoch,
            state_fence: snapshot_fence,
            created_at_ms: now_ms,
            cleanup_after_ms: Some(now_ms.saturating_add(86_400_000)),
        },
        state_fence: state_fence.clone(),
        generation: runtime.authority_generation,
        revision_policy_binding: intent.static_template.revision_policy_binding.clone(),
        dispatch_key,
        supervision_authority: provisioned_supervision_authority.clone(),
        descriptor_sha256: String::new(),
        issued_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(86_400_000),
        contour_refs: intent.static_template.contour_refs.clone(),
    };
    let marker = phase_b_authority_marker(
        &intent.manifest_digest,
        host,
        activation_generation,
        &descriptor,
    )?;
    descriptor.contour_refs.push(marker);
    descriptor = descriptor
        .with_computed_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    descriptor
        .validate_structure()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    serde_json::to_vec(&descriptor).map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn phase_b_authority_marker(
    manifest_digest: &PlatformHandle,
    host: &HostInstallationEpoch,
    activation_generation: &EpochIdentity,
    descriptor: &ProcessAuthorityHandoffDescriptor,
) -> Result<PlatformHandle, HostError> {
    let fields = [
        host.installation.as_str().to_owned(),
        host.epoch.current.lineage.as_str().to_owned(),
        host.epoch.current.sequence.to_string(),
        host.nonce.as_str().to_owned(),
        manifest_digest.as_str().to_owned(),
        activation_generation.lineage.as_str().to_owned(),
        activation_generation.sequence.to_string(),
        descriptor.generation.value().to_string(),
    ];
    let payload = serde_json::to_string(&fields)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    PlatformHandle::new(format!("phase-b-host-v1:{payload}"))
        .map_err(|error| HostError::Platform(error.to_string()))
}
