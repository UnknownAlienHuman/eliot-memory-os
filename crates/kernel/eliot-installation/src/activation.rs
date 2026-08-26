//! Activation approval, durable binding and projection-intent contracts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationEffectProgressState, InstallationError, InstallationStage, InstallationTransaction,
    InstallerEffectPlan, InstallerServiceRegistrationApproval, InstallerServiceRole,
    PlatformHandle, ResourceGeneration, StateFence, candidate_manifest_digest, handle,
    phase_b_digest_state, sha256_handle,
};

/// The typed approval binding for one installer-produced activation candidate.
///
/// This is an evidence reference plus the complete identity contour which Host
/// must consume.  It is deliberately not represented by a bare approval string:
/// changing any one of the transaction, manifest, request-owner, runtime
/// descriptor or authority-fence inputs invalidates the approval.
///
/// ```compile_fail
/// use eliot_installation::{InstallationActivationApproval, PlatformHandle};
/// fn forge(approval: &mut InstallationActivationApproval) {
///     approval.approval_ref = PlatformHandle::new("forged").unwrap();
/// }
/// ```
///
/// The approval is also intentionally not deserializable by callers. Only the
/// private registry wire decoder may reconstruct a durable approval record;
/// external JSON must first pass through the signed-authority verification
/// lane.
///
/// ```compile_fail
/// use eliot_installation::InstallationActivationApproval;
///
/// fn forge_from_json(bytes: &str) {
///     let _: InstallationActivationApproval = serde_json::from_str(bytes).unwrap();
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationActivationApproval {
    /// Non-secret approval evidence reference.  The fields are intentionally
    /// private: installation accepts this value only from an independently
    /// issuing authority that also supplies static-verification proof.
    pub(super) approval_ref: PlatformHandle,
    /// Sole installation transaction identity.
    pub(super) transaction_id: PlatformHandle,
    /// Digest of the immutable installer effect plan.
    pub(super) installer_plan_digest: PlatformHandle,
    /// Candidate generation identity.
    pub(super) generation: PlatformHandle,
    /// Digest of the exact candidate manifest bytes.
    pub(super) candidate_manifest_digest: PlatformHandle,
    /// Self-digest of the exact runtime launch descriptor.
    pub(super) runtime_descriptor_digest: PlatformHandle,
    /// Request owner required for admission.
    pub(super) required_owner: PlatformHandle,
    /// Candidate signature/approval evidence reference.
    pub(super) signature_ref: PlatformHandle,
    /// Exact authority handoff descriptor path.
    pub(super) authority_descriptor_path: PlatformHandle,
    /// SHA-256 digest of the authority descriptor bytes.
    pub(super) authority_descriptor_digest: PlatformHandle,
    /// Authority resource generation.
    pub(super) authority_generation: ResourceGeneration,
    /// Exact authority state fence.
    pub(super) authority_state_fence: StateFence,
}

impl InstallationActivationApproval {
    /// Returns the sole installation transaction identity bound by this approval.
    #[must_use]
    pub const fn transaction_id(&self) -> &PlatformHandle {
        &self.transaction_id
    }

    /// Returns the immutable installer-plan digest bound by this approval.
    #[must_use]
    pub const fn installer_plan_digest(&self) -> &PlatformHandle {
        &self.installer_plan_digest
    }

    /// Constructs the private registry approval after an independent signed
    /// authority verifier has authenticated every field.  The constructor is
    /// crate-visible so the signed-activation bridge remains the sole
    /// production path; external callers cannot manufacture this value.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_parts(
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
    ) -> Self {
        Self {
            approval_ref,
            transaction_id,
            installer_plan_digest,
            generation,
            candidate_manifest_digest,
            runtime_descriptor_digest,
            required_owner,
            signature_ref,
            authority_descriptor_path,
            authority_descriptor_digest,
            authority_generation,
            authority_state_fence,
        }
    }

    /// Validates the approval's self-contained typed binding.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.approval_ref, "activation_approval.approval_ref")?;
        handle(&self.transaction_id, "activation_approval.transaction_id")?;
        sha256_handle(
            &self.installer_plan_digest,
            "activation_approval.installer_plan_digest",
        )?;
        handle(&self.generation, "activation_approval.generation")?;
        sha256_handle(
            &self.candidate_manifest_digest,
            "activation_approval.candidate_manifest_digest",
        )?;
        sha256_handle(
            &self.runtime_descriptor_digest,
            "activation_approval.runtime_descriptor_digest",
        )?;
        handle(&self.required_owner, "activation_approval.required_owner")?;
        handle(&self.signature_ref, "activation_approval.signature_ref")?;
        handle(
            &self.authority_descriptor_path,
            "activation_approval.authority_descriptor_path",
        )?;
        phase_b_digest_state(
            &self.authority_descriptor_digest,
            "activation_approval.authority_descriptor_digest",
        )?;
        if self.authority_generation.value() == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_approval.authority_generation".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.authority_state_fence
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "activation_approval.authority_state_fence".to_owned(),
                reason: error.to_string(),
            })?;
        if self.authority_state_fence.resource_generation != self.authority_generation {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Validates every approval binding against the exact transaction.
    ///
    /// The activation-boundary gate runs first, so a partially applied or
    /// unknown installer transaction can never produce a valid activation
    /// approval.  A `SystemService` approval is intentionally issued while
    /// both ordered `StartService` effects are still pending; the coordinator
    /// owns their execution after this boundary.
    pub fn validate_against(
        &self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        let has_bootstrap_host_start = transaction.installer_effects.iter().any(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        }) && !transaction.installer_effects.iter().any(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        });
        if has_bootstrap_host_start && transaction.stage() == InstallationStage::Registering {
            transaction.require_bootstrap_effects_ready()?;
        } else if matches!(
            transaction.stage(),
            InstallationStage::Registering | InstallationStage::Activating
        ) && transaction
            .installer_effects
            .iter()
            .any(|effect| matches!(effect, InstallerEffectPlan::StartService { .. }))
            && transaction
                .installer_effects
                .iter()
                .zip(transaction.effect_progress())
                .any(|(effect, progress)| {
                    matches!(effect, InstallerEffectPlan::StartService { .. })
                        && matches!(progress.state, InstallationEffectProgressState::Pending)
                })
        {
            if transaction.stage() == InstallationStage::Registering {
                transaction.require_pre_activation_effects_ready()?;
            } else {
                transaction.require_signed_pending_activation_effects()?;
            }
        } else {
            transaction.require_all_effects_applied()?;
        }
        self.validate()?;
        let manifest = &transaction.candidate_manifest;
        let runtime = &manifest.runtime_launch;
        let expected_manifest_digest = candidate_manifest_digest(manifest)?;
        let matches = [
            self.transaction_id == transaction.transaction_id,
            self.installer_plan_digest == transaction.installer_plan_digest,
            self.generation == manifest.generation,
            self.candidate_manifest_digest == expected_manifest_digest,
            self.runtime_descriptor_digest == runtime.descriptor_digest,
            self.required_owner == transaction.request.required_owner,
            self.signature_ref == manifest.signature_ref,
            self.authority_descriptor_path == runtime.authority_descriptor_path,
            self.authority_descriptor_digest == runtime.authority_descriptor_digest,
            self.authority_generation == runtime.authority_generation,
            self.authority_state_fence == runtime.authority_state_fence,
        ];
        if matches.iter().any(|matches| !matches) {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Deserializable, non-secret projection of one verified activation approval.
///
/// [`InstallationActivationApproval`] intentionally remains private and
/// non-deserializable.  This mirror is the exact binding retained in the
/// transaction so a retry can prove that it is re-entering the same verified
/// approval rather than manufacturing a new one from durable JSON.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationActivationApprovalBinding {
    /// Detached signed-envelope evidence reference.
    pub approval_ref: PlatformHandle,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Immutable installer plan digest.
    pub installer_plan_digest: PlatformHandle,
    /// Candidate generation identity.
    pub generation: PlatformHandle,
    /// Candidate manifest digest.
    pub candidate_manifest_digest: PlatformHandle,
    /// Runtime launch descriptor digest.
    pub runtime_descriptor_digest: PlatformHandle,
    /// Required owner identity.
    pub required_owner: PlatformHandle,
    /// Candidate signature evidence reference.
    pub signature_ref: PlatformHandle,
    /// Authority descriptor path.
    pub authority_descriptor_path: PlatformHandle,
    /// Authority descriptor digest.
    pub authority_descriptor_digest: PlatformHandle,
    /// Authority resource generation.
    pub authority_generation: ResourceGeneration,
    /// Authority state fence.
    pub authority_state_fence: StateFence,
}

impl InstallationActivationApprovalBinding {
    pub(super) fn from_approval(approval: &InstallationActivationApproval) -> Self {
        Self {
            approval_ref: approval.approval_ref.clone(),
            transaction_id: approval.transaction_id.clone(),
            installer_plan_digest: approval.installer_plan_digest.clone(),
            generation: approval.generation.clone(),
            candidate_manifest_digest: approval.candidate_manifest_digest.clone(),
            runtime_descriptor_digest: approval.runtime_descriptor_digest.clone(),
            required_owner: approval.required_owner.clone(),
            signature_ref: approval.signature_ref.clone(),
            authority_descriptor_path: approval.authority_descriptor_path.clone(),
            authority_descriptor_digest: approval.authority_descriptor_digest.clone(),
            authority_generation: approval.authority_generation,
            authority_state_fence: approval.authority_state_fence.clone(),
        }
    }

    pub(super) fn matches_approval(&self, approval: &InstallationActivationApproval) -> bool {
        self == &Self::from_approval(approval)
    }

    fn validate(&self) -> Result<(), InstallationError> {
        let approval = InstallationActivationApproval {
            approval_ref: self.approval_ref.clone(),
            transaction_id: self.transaction_id.clone(),
            installer_plan_digest: self.installer_plan_digest.clone(),
            generation: self.generation.clone(),
            candidate_manifest_digest: self.candidate_manifest_digest.clone(),
            runtime_descriptor_digest: self.runtime_descriptor_digest.clone(),
            required_owner: self.required_owner.clone(),
            signature_ref: self.signature_ref.clone(),
            authority_descriptor_path: self.authority_descriptor_path.clone(),
            authority_descriptor_digest: self.authority_descriptor_digest.clone(),
            authority_generation: self.authority_generation,
            authority_state_fence: self.authority_state_fence.clone(),
        };
        approval.validate()
    }
}

/// Policy bound to the registry snapshot used by a signed activation
/// projection.  A retry may accept an exact pending projection at a later
/// registry revision, but a missing projection may only be created against the
/// exact observed snapshot.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationActivationRegistryRevisionPolicy {
    /// Require the expected snapshot for a new projection, or recognize an
    /// already committed exact pending projection regardless of its revision.
    ExactSnapshotOrMatchingPending,
}

/// Durable binding for the registry projection authorized by one signed
/// activation.  It is written in the same transaction CAS as
/// `Registering -> Activating`; no private key or detached signature bytes are
/// retained.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationActivationProjectionIntent {
    /// Digest of the complete detached signed envelope.
    pub envelope_digest: PlatformHandle,
    /// Digest of the canonical signed payload.
    pub payload_digest: PlatformHandle,
    /// Transaction revision authenticated by the signed envelope before the
    /// activation-boundary CAS.
    pub original_transaction_revision: u64,
    /// Sole transaction identity.
    pub transaction_id: PlatformHandle,
    /// Immutable installer plan digest.
    pub installer_plan_digest: PlatformHandle,
    /// Candidate manifest digest.
    pub candidate_manifest_digest: PlatformHandle,
    /// Candidate generation identity.
    pub generation: PlatformHandle,
    /// Digest of the one static package-verification receipt.
    pub static_verification_receipt_digest: PlatformHandle,
    /// Exact installer SCM readbacks authenticated by the signed payload.
    pub scm_readbacks: Vec<InstallerServiceRegistrationApproval>,
    /// Complete non-secret verified-approval binding.
    pub verified_approval: InstallationActivationApprovalBinding,
    /// Registry revision observed by the installer before the projection CAS.
    pub expected_registry_revision: u64,
    /// Digest of the complete registry snapshot observed at that revision.
    pub expected_registry_identity: PlatformHandle,
    /// Explicit retry/reconciliation policy for the registry projection.
    pub registry_revision_policy: InstallationActivationRegistryRevisionPolicy,
}

impl InstallationActivationProjectionIntent {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        transaction: &InstallationTransaction,
        approval: &InstallationActivationApproval,
        envelope_digest: PlatformHandle,
        payload_digest: PlatformHandle,
        expected_registry_revision: u64,
        expected_registry_identity: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        let static_receipts = transaction
            .effect_progress()
            .iter()
            .filter_map(|progress| progress.staging_receipt.as_ref())
            .collect::<Vec<_>>();
        if static_receipts.len() != 1 {
            return Err(InstallationError::IncompleteObservation(
                "activation projection requires exactly one static verification receipt".to_owned(),
            ));
        }
        let static_verification_receipt_digest = PlatformHandle::new(static_receipts[0].digest())
            .map_err(|error| {
            InstallationError::InvalidField {
                field: "activation_projection.static_verification_receipt_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
        let scm_readbacks = transaction.service_registration_approvals()?;
        let intent = Self {
            envelope_digest,
            payload_digest,
            original_transaction_revision: transaction.revision(),
            transaction_id: transaction.transaction_id.clone(),
            installer_plan_digest: transaction.installer_plan_digest.clone(),
            candidate_manifest_digest: candidate_manifest_digest(&transaction.candidate_manifest)?,
            generation: transaction.candidate_manifest.generation.clone(),
            static_verification_receipt_digest,
            scm_readbacks,
            verified_approval: InstallationActivationApprovalBinding::from_approval(approval),
            expected_registry_revision,
            expected_registry_identity,
            registry_revision_policy:
                InstallationActivationRegistryRevisionPolicy::ExactSnapshotOrMatchingPending,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<(), InstallationError> {
        sha256_handle(
            &self.envelope_digest,
            "activation_projection.envelope_digest",
        )?;
        sha256_handle(&self.payload_digest, "activation_projection.payload_digest")?;
        if self.original_transaction_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_projection.original_transaction_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        handle(&self.transaction_id, "activation_projection.transaction_id")?;
        sha256_handle(
            &self.installer_plan_digest,
            "activation_projection.installer_plan_digest",
        )?;
        handle(
            &self.candidate_manifest_digest,
            "activation_projection.candidate_manifest_digest",
        )?;
        handle(&self.generation, "activation_projection.generation")?;
        sha256_handle(
            &self.static_verification_receipt_digest,
            "activation_projection.static_verification_receipt_digest",
        )?;
        if self.scm_readbacks.len() != 2 {
            return Err(InstallationError::IncompleteObservation(
                "activation projection requires Host and Watchdog SCM readbacks".to_owned(),
            ));
        }
        for readback in &self.scm_readbacks {
            readback.validate()?;
        }
        self.verified_approval.validate()?;
        if self.expected_registry_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_projection.expected_registry_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        sha256_handle(
            &self.expected_registry_identity,
            "activation_projection.expected_registry_identity",
        )?;
        Ok(())
    }

    pub(crate) fn validate_against_transaction(
        &self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        if self.transaction_id != transaction.transaction_id
            || self.installer_plan_digest != transaction.installer_plan_digest
            || self.generation != transaction.candidate_manifest.generation
            || self.candidate_manifest_digest
                != candidate_manifest_digest(&transaction.candidate_manifest)?
            || self.original_transaction_revision >= transaction.revision()
        {
            return Err(InstallationError::IdentityConflict);
        }
        let static_receipts = transaction
            .effect_progress()
            .iter()
            .filter_map(|progress| progress.staging_receipt.as_ref())
            .collect::<Vec<_>>();
        if static_receipts.len() != 1
            || self.static_verification_receipt_digest.as_str() != static_receipts[0].digest()
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.scm_readbacks != transaction.service_registration_approvals_unchecked()? {
            return Err(InstallationError::IdentityConflict);
        }
        let expected_approval = InstallationActivationApproval::from_verified_parts(
            self.verified_approval.approval_ref.clone(),
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest.generation.clone(),
            self.candidate_manifest_digest.clone(),
            transaction
                .candidate_manifest
                .runtime_launch
                .descriptor_digest
                .clone(),
            transaction.request.required_owner.clone(),
            transaction.candidate_manifest.signature_ref.clone(),
            transaction
                .candidate_manifest
                .runtime_launch
                .authority_descriptor_path
                .clone(),
            transaction
                .candidate_manifest
                .runtime_launch
                .authority_descriptor_digest
                .clone(),
            transaction
                .candidate_manifest
                .runtime_launch
                .authority_generation,
            transaction
                .candidate_manifest
                .runtime_launch
                .authority_state_fence
                .clone(),
        );
        if !self.verified_approval.matches_approval(&expected_approval) {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    pub(crate) fn matches_verified(
        &self,
        transaction: &InstallationTransaction,
        approval: &InstallationActivationApproval,
        envelope_digest: &PlatformHandle,
        payload_digest: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        self.validate_against_transaction(transaction)?;
        if self.envelope_digest != *envelope_digest
            || self.payload_digest != *payload_digest
            || !self.verified_approval.matches_approval(approval)
        {
            return Err(InstallationError::IdentityConflict);
        }
        approval.validate_against(transaction)
    }
}
