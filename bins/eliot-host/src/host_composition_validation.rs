use std::path::PathBuf;

use super::{
    ApprovedGenerationRegistry, CandidateManifest, HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR,
    HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR, HostComposition, HostError, HostLaunchOptions,
    phase_b_scm_selector,
};
#[cfg(windows)]
use super::{
    InstallationProfile, InstallerServiceRole, PhaseBLiveBinding, PlatformHandle,
    approved_service_registration_request,
};

impl HostComposition {
    #[cfg(windows)]
    pub(super) fn active_phase_b_rebind_binding(
        rebind: &eliot_installation::ActivePhaseBRebind,
    ) -> Result<PhaseBLiveBinding, HostError> {
        rebind.validate().map_err(HostError::Installation)?;
        let prepared = rebind.prepared.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "completed Active Phase-B rebind has no durable preparation".to_owned(),
            )
        })?;
        let receipt = rebind.receipt.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "completed Active Phase-B rebind has no durable receipt".to_owned(),
            )
        })?;
        receipt
            .validate_against(&rebind.intent, prepared)
            .map_err(HostError::Installation)?;
        Ok(PhaseBLiveBinding {
            manifest_digest: receipt.manifest_digest.clone(),
            authority_descriptor_digest: receipt.authority_descriptor_digest.clone(),
            store_bootstrap_descriptor_digest: receipt.store_bootstrap_descriptor_digest.clone(),
            config_file_digest: receipt.config_file_digest.clone(),
            eliotd_descriptor_digest: receipt.eliotd_descriptor_digest.clone(),
            semantic_config_hash: prepared.semantic_config_hash.clone(),
            host_epoch_lineage: receipt.host_epoch_lineage.clone(),
            host_epoch_sequence: receipt.host_epoch_sequence,
            host_process_nonce_digest: receipt.host_process_nonce_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            effect_id: receipt.effect_id.clone(),
            credential_receipt_digest: prepared.credential_receipt_digest.clone(),
            request_digest: receipt.request_digest.clone(),
            host_owner_epoch: receipt.host_owner_epoch.clone(),
            host_process_identity: receipt.host_process_identity.clone(),
            public_receipt_digest: receipt.receipt_digest.clone(),
            provisioned_supervision_authority: prepared
                .launch
                .provisioned_supervision_authority()
                .map_err(HostError::Installation)?
                .clone(),
        })
    }

    /// Returns the discriminator bound to the production Host composition.
    #[must_use]
    pub const fn production_store_rebind_discriminator() -> &'static str {
        HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    }

    #[must_use]
    pub const fn production_runtime_control_discriminator() -> &'static str {
        HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR
    }
    pub(super) fn validate_launch_options_for_manifest(
        options: &HostLaunchOptions,
        manifest: &CandidateManifest,
    ) -> Result<(), HostError> {
        let launch = &manifest.runtime_launch;
        // The optional registration nonce belongs to the installer effect
        // receipt. It has no approved-generation field to bind here, so it is
        // deliberately excluded; none of the five Host authority fields may
        // be substituted by it.
        let manifest_descriptor_path = PathBuf::from(launch.authority_descriptor_path.as_str());
        let manifest_host_root = PathBuf::from(launch.runtime_state_roots.host_state_root.as_str());
        let expected_descriptor_digest = phase_b_scm_selector(&launch.authority_descriptor_digest)
            .map_err(HostError::Installation)?;
        if manifest_descriptor_path != options.config_descriptor_path
            || expected_descriptor_digest.as_str() != options.config_descriptor_digest().as_str()
            || launch.installation_epoch.installation != *options.installation()
            || launch.authority_generation.value() != options.transaction_plan_generation()
            || manifest_host_root != options.host_state_root
        {
            return Err(HostError::ProcessContour(
                "SCM launch authority does not match the approved generation".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_launch_options_for_registry(
        options: &HostLaunchOptions,
        registry: &ApprovedGenerationRegistry,
        pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        if let Some(pending) = pending {
            Self::validate_launch_options_for_manifest(options, &pending.manifest)?;
            return Self::validate_host_registration_approval(options, registry, &pending.manifest);
        }
        if let Some(active) = registry.active() {
            Self::validate_launch_options_for_manifest(options, &active.manifest)?;
            return Self::validate_host_registration_approval(options, registry, &active.manifest);
        }
        Err(HostError::ProcessContour(
            "SCM launch authority has no approved generation".to_owned(),
        ))
    }

    #[cfg(windows)]
    fn validate_host_registration_approval(
        options: &HostLaunchOptions,
        registry: &ApprovedGenerationRegistry,
        manifest: &CandidateManifest,
    ) -> Result<(), HostError> {
        if manifest.runtime_launch.profile != InstallationProfile::SystemService {
            return Ok(());
        }
        let approval = registry
            .service_registration_approval(
                &manifest.runtime_launch.generation,
                InstallerServiceRole::Host,
            )
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "approved generation is missing the installer-owned Host SCM approval"
                        .to_owned(),
                )
            })?;
        let request = approved_service_registration_request(
            &manifest.runtime_launch,
            approval,
            InstallerServiceRole::Host,
            &manifest.runtime_launch.host_executable_path,
        )?;
        let approved_nonce = request
            .bootstrap()
            .and_then(|bootstrap| bootstrap.registration_nonce())
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "Host SCM approval is missing the installer-approved registration nonce"
                        .to_owned(),
                )
            })?;
        if Some(approved_nonce) != options.registration_nonce().map(PlatformHandle::as_str) {
            return Err(HostError::ProcessContour(
                "Host SCM launch nonce does not match installer approval".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn validate_host_registration_approval(
        _options: &HostLaunchOptions,
        _registry: &ApprovedGenerationRegistry,
        _manifest: &CandidateManifest,
    ) -> Result<(), HostError> {
        Ok(())
    }
}
