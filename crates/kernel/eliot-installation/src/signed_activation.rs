#![allow(clippy::too_many_arguments, clippy::too_many_lines)]
//! Production signed-activation admission.
//!
//! This module is intentionally a narrow boundary.  It consumes an explicit
//! detached approval envelope and an opaque signer loaded by the protected
//! Windows installer-authority key contour, then derives the private
//! [`InstallationActivationApproval`] only inside the registry CAS.  The
//! public CLI does not call this surface because it has no trusted key,
//! elevation, SCM, or transaction-owner context.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use eliot_platform_windows::{
    InstallationAuthorityKeyError, InstallationAuthorityKeySigner,
    ServiceRegistrationRuntimeInspection, WindowsPlatform,
};
use eliot_runtime_contracts::{
    InstallationActivationError, InstallationActivationVerificationContext,
    InstallationDigestBinding, InstallationScmRole, SignedInstallationActivationApproval,
};

use super::transaction_store_private::{Sealed, TransactionVersion};
use super::{
    CandidateManifest, HostOwnerEpochCapability, InstallationActivationApproval, InstallationError,
    InstallationProfile, InstallationTransaction, InstallationTransactionStore,
    InstallerServiceRole, PlatformHandle, RedbInstallationRegistry,
    RedbInstallationTransactionStore, candidate_manifest_digest, registry_projection_identity,
    sha256_hex,
};

const ARTIFACT_KERNEL: &str = "kernel";
const ARTIFACT_STORE_BRIDGE: &str = "store_bridge";
const ARTIFACT_CANONICAL_STORE: &str = "canonical_store";
const ARTIFACT_HOST: &str = "host";
const ARTIFACT_ELIOTD: &str = "eliotd";
const ARTIFACT_WATCHDOG: &str = "watchdog";

const CONFIG_STORE: &str = "store_config";
const CONFIG_ELIOTD: &str = "eliotd_config";
const CONFIG_ELIOTD_DESCRIPTOR: &str = "eliotd_descriptor";
const CONFIG_STORE_BOOTSTRAP: &str = "store_bootstrap_descriptor";

const AUTHORITY_DESCRIPTOR: &str = "authority_descriptor";
const AUTHORITY_RUNTIME_ROOTS: &str = "runtime_state_roots";

fn activation_error(error: &InstallationActivationError) -> InstallationError {
    InstallationError::InvalidField {
        field: "signed_envelope".to_owned(),
        reason: error.to_string(),
    }
}

fn authority_key_error(error: InstallationAuthorityKeyError) -> InstallationError {
    InstallationError::Platform(format!("protected installer authority key: {error}"))
}

fn binding_mismatch(reason: impl Into<String>) -> InstallationError {
    InstallationError::InvalidField {
        field: "signed_envelope.binding".to_owned(),
        reason: reason.into(),
    }
}

fn expected_elevation_evidence_digest(
    precondition_evidence: &[PlatformHandle],
) -> Result<String, InstallationError> {
    // The transaction's precondition evidence is produced by the elevated
    // effect coordinator and persisted before any effect intent is executed.
    // Bind the complete ordered vector, rather than accepting one caller
    // supplied evidence reference or a digest that merely has SHA-256 shape.
    let bytes = serde_json::to_vec(precondition_evidence).map_err(|error| {
        InstallationError::CorruptRegistry {
            reason: format!("elevation evidence could not be canonicalized: {error}"),
        }
    })?;
    Ok(sha256_hex(&bytes))
}

fn require_exact_digest_set(
    field: &str,
    observed: &[InstallationDigestBinding],
    expected: &BTreeMap<&'static str, &str>,
) -> Result<(), InstallationError> {
    if observed.len() != expected.len() {
        return Err(binding_mismatch(format!(
            "{field} must contain exactly {} named bindings",
            expected.len()
        )));
    }
    let mut names = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for binding in observed {
        if !names.insert(binding.name.as_str()) {
            return Err(binding_mismatch(format!(
                "{field} contains a duplicate name"
            )));
        }
        let Some(expected_digest) = expected.get(binding.name.as_str()) else {
            return Err(binding_mismatch(format!(
                "{field} contains an unknown binding name"
            )));
        };
        if *expected_digest != binding.digest.as_str() {
            return Err(binding_mismatch(format!(
                "{field} digest does not match its exact named object"
            )));
        }
        if !digests.insert(binding.digest.as_str()) {
            return Err(binding_mismatch(format!(
                "{field} aliases one digest across multiple named objects"
            )));
        }
    }
    let expected_names = expected.keys().copied().collect::<BTreeSet<_>>();
    if names != expected_names {
        return Err(binding_mismatch(format!(
            "{field} omits one or more required named objects"
        )));
    }
    Ok(())
}

fn expected_artifact_digests(
    manifest: &CandidateManifest,
) -> Result<BTreeMap<&'static str, &str>, InstallationError> {
    let runtime = &manifest.runtime_launch;
    let duplicate_manifest_bindings = [
        (
            manifest.kernel_artifact_digest.as_str(),
            runtime.kernel_artifact_digest.as_str(),
        ),
        (
            manifest.store_bridge_artifact_digest.as_str(),
            runtime.store_bridge_artifact_digest.as_str(),
        ),
        (
            manifest.canonical_store_artifact_digest.as_str(),
            runtime.canonical_store_artifact_digest.as_str(),
        ),
        (
            manifest.host_artifact_digest.as_str(),
            runtime.host_artifact_digest.as_str(),
        ),
    ];
    if duplicate_manifest_bindings
        .iter()
        .any(|(manifest_digest, runtime_digest)| manifest_digest != runtime_digest)
    {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(BTreeMap::from([
        (ARTIFACT_KERNEL, manifest.kernel_artifact_digest.as_str()),
        (
            ARTIFACT_STORE_BRIDGE,
            manifest.store_bridge_artifact_digest.as_str(),
        ),
        (
            ARTIFACT_CANONICAL_STORE,
            manifest.canonical_store_artifact_digest.as_str(),
        ),
        (ARTIFACT_HOST, manifest.host_artifact_digest.as_str()),
        (ARTIFACT_ELIOTD, runtime.eliotd_artifact_digest.as_str()),
        (ARTIFACT_WATCHDOG, runtime.watchdog_artifact_digest.as_str()),
    ]))
}

fn expected_config_digests(manifest: &CandidateManifest) -> BTreeMap<&'static str, &str> {
    let runtime = &manifest.runtime_launch;
    BTreeMap::from([
        (CONFIG_STORE, manifest.config_digest.as_str()),
        (CONFIG_ELIOTD, runtime.eliotd_config_digest.as_str()),
        (
            CONFIG_ELIOTD_DESCRIPTOR,
            runtime.eliotd_descriptor_digest.as_str(),
        ),
        (
            CONFIG_STORE_BOOTSTRAP,
            runtime.store_bootstrap_descriptor_digest.as_str(),
        ),
    ])
}

fn expected_authority_digests(manifest: &CandidateManifest) -> BTreeMap<&'static str, &str> {
    let runtime = &manifest.runtime_launch;
    BTreeMap::from([
        (
            AUTHORITY_DESCRIPTOR,
            runtime.authority_descriptor_digest.as_str(),
        ),
        (
            AUTHORITY_RUNTIME_ROOTS,
            manifest.runtime_state_roots_digest.as_str(),
        ),
    ])
}

fn service_role(role: InstallationScmRole) -> InstallerServiceRole {
    match role {
        InstallationScmRole::Host => InstallerServiceRole::Host,
        InstallationScmRole::Watchdog => InstallerServiceRole::Watchdog,
    }
}

fn validate_scm_bindings(
    transaction: &InstallationTransaction,
    envelope: &SignedInstallationActivationApproval,
) -> Result<(), InstallationError> {
    if transaction.profile != InstallationProfile::SystemService {
        return Err(binding_mismatch(
            "signed activation requires the SystemService profile",
        ));
    }
    let approvals = transaction.service_registration_approvals()?;
    if approvals.len() != 2 {
        return Err(binding_mismatch(
            "transaction must contain exactly Host and Watchdog SCM approvals",
        ));
    }
    let mut roles = BTreeSet::new();
    for readback in &envelope.payload.scm_readbacks {
        let role = service_role(readback.role);
        if !roles.insert(role) {
            return Err(binding_mismatch("SCM readback roles must be unique"));
        }
        let Some(approval) = approvals.iter().find(|approval| approval.role() == role) else {
            return Err(binding_mismatch(
                "SCM readback role is not present in the transaction",
            ));
        };
        if readback.configuration_digest != approval.configuration_digest().as_str()
            || readback.registration_nonce != approval.registration_nonce().as_str()
            || readback.service_name != approval.service_name_handle().as_str()
            || readback.executable_path != approval.executable_path_handle().as_str()
        {
            return Err(binding_mismatch(
                "SCM readback does not exactly match the transaction approval",
            ));
        }
    }
    if roles.len() != approvals.len() {
        return Err(binding_mismatch(
            "SCM readbacks omit one or more transaction-approved roles",
        ));
    }
    Ok(())
}

fn require_stopped_scm_observation(
    observation: ServiceRegistrationRuntimeInspection,
) -> Result<(), InstallationError> {
    match observation {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopped() =>
        {
            Ok(())
        }
        ServiceRegistrationRuntimeInspection::Matching { .. } => Err(InstallationError::Platform(
            "SCM service is not stopped while installer owns Host admission".to_owned(),
        )),
        ServiceRegistrationRuntimeInspection::Absent => {
            Err(InstallationError::IncompleteObservation(
                "transaction-approved SCM service is absent during activation staging".to_owned(),
            ))
        }
        ServiceRegistrationRuntimeInspection::Mismatched
        | ServiceRegistrationRuntimeInspection::Unknown => {
            Err(InstallationError::IncompleteObservation(
                "SCM configuration or process observation is unknown or mismatched".to_owned(),
            ))
        }
    }
}

struct VerifiedActivationProjection {
    approval: InstallationActivationApproval,
    envelope_digest: PlatformHandle,
    payload_digest: PlatformHandle,
}

fn payload_digest(
    envelope: &SignedInstallationActivationApproval,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(&envelope.payload).map_err(|error| {
        InstallationError::CorruptRegistry {
            reason: format!("signed activation payload could not be canonicalized: {error}"),
        }
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "signed_envelope.payload_digest".to_owned(),
        reason: error.to_string(),
    })
}

fn synthetic_projection_digest(
    label: &str,
    approval: &InstallationActivationApproval,
) -> Result<PlatformHandle, InstallationError> {
    let bytes =
        serde_json::to_vec(approval).map_err(|error| InstallationError::CorruptRegistry {
            reason: format!("verified approval could not be canonicalized: {error}"),
        })?;
    let mut canonical = label.as_bytes().to_vec();
    canonical.push(0);
    canonical.extend_from_slice(&bytes);
    PlatformHandle::new(sha256_hex(&canonical)).map_err(|error| InstallationError::InvalidField {
        field: "activation_projection.synthetic_digest".to_owned(),
        reason: error.to_string(),
    })
}

/// Derives the private first-install approval from the exact transaction.
///
/// This is deliberately kept beside the signed projection machinery: the
/// bootstrap path uses the same approval binding and transaction-owned
/// projection intent, but has no detached signer because the Host is fenced
/// until this durable prefix has been admitted.
fn bootstrap_approval(
    transaction: &InstallationTransaction,
) -> Result<InstallationActivationApproval, InstallationError> {
    let manifest_digest = candidate_manifest_digest(&transaction.candidate_manifest)?;
    let approval_ref = PlatformHandle::new(sha256_hex(
        format!(
            "eliot.first-install.bootstrap-approval.v2\0{}\0{}\0{}",
            transaction.transaction_id.as_str(),
            transaction.installer_plan_digest.as_str(),
            manifest_digest.as_str(),
        )
        .as_bytes(),
    ))
    .map_err(|error| InstallationError::InvalidField {
        field: "bootstrap_approval.approval_ref".to_owned(),
        reason: error.to_string(),
    })?;
    let runtime = &transaction.candidate_manifest.runtime_launch;
    Ok(InstallationActivationApproval::from_verified_parts(
        approval_ref,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.generation.clone(),
        manifest_digest,
        runtime.descriptor_digest.clone(),
        transaction.request.required_owner.clone(),
        transaction.candidate_manifest.signature_ref.clone(),
        runtime.authority_descriptor_path.clone(),
        runtime.authority_descriptor_digest.clone(),
        runtime.authority_generation,
        runtime.authority_state_fence.clone(),
    ))
}

fn verify_and_derive_projection(
    transaction: &InstallationTransaction,
    envelope: &SignedInstallationActivationApproval,
    authority_key: &InstallationAuthorityKeySigner,
    now_ms: i64,
    signed_transaction_revision: u64,
) -> Result<VerifiedActivationProjection, InstallationError> {
    transaction.require_signed_pending_activation_effects()?;
    transaction.validate()?;

    let staging_receipts = transaction
        .effect_progress()
        .iter()
        .filter_map(|progress| progress.staging_receipt.as_ref())
        .collect::<Vec<_>>();
    if staging_receipts.len() != 1 {
        return Err(InstallationError::IncompleteObservation(
            "exactly one static package verification receipt is required".to_owned(),
        ));
    }
    let static_digest = staging_receipts[0].digest();
    let runtime = &transaction.candidate_manifest.runtime_launch;
    let context = InstallationActivationVerificationContext {
        now_ms,
        installation_id: transaction
            .installation_epoch
            .installation
            .as_str()
            .to_owned(),
        installation_epoch: transaction.installation_epoch.sequence,
        transaction_id: transaction.transaction_id.as_str().to_owned(),
        transaction_revision: signed_transaction_revision,
        static_verification_receipt_digest: static_digest.clone(),
        authority_generation: runtime.authority_generation,
        authority_state_fence: runtime.authority_state_fence.clone(),
    };
    context
        .validate()
        .map_err(|error| activation_error(&error))?;
    let trust_anchor = authority_key
        .trust_anchor(
            transaction.installation_epoch.installation.as_str(),
            eliot_platform_windows::INSTALLATION_AUTHORITY_SIGNER_ID,
        )
        .map_err(authority_key_error)?;
    let verified = trust_anchor
        .verify(envelope, &context)
        .map_err(|error| activation_error(&error))?;
    let payload = verified.payload();

    if payload.transaction_id != transaction.transaction_id.as_str()
        || payload.transaction_revision != signed_transaction_revision
        || payload.installation_id != transaction.installation_epoch.installation.as_str()
        || payload.installation_epoch != transaction.installation_epoch.sequence
        || payload.installer_plan_digest != transaction.installer_plan_digest.as_str()
        || payload.runtime_descriptor_digest != runtime.descriptor_digest.as_str()
        || payload.static_verification_receipt_digest != static_digest
        || payload.authority_generation != runtime.authority_generation
        || payload.authority_state_fence != runtime.authority_state_fence
        || payload.required_owner != transaction.request.required_owner.as_str()
    {
        return Err(InstallationError::IdentityConflict);
    }
    let expected_manifest_digest = candidate_manifest_digest(&transaction.candidate_manifest)?;
    if payload.candidate_manifest_digest != expected_manifest_digest.as_str() {
        return Err(InstallationError::IdentityConflict);
    }

    require_exact_digest_set(
        "artifact_digests",
        &payload.artifact_digests,
        &expected_artifact_digests(&transaction.candidate_manifest)?,
    )?;
    require_exact_digest_set(
        "config_digests",
        &payload.config_digests,
        &expected_config_digests(&transaction.candidate_manifest),
    )?;
    require_exact_digest_set(
        "authority_descriptor_digests",
        &payload.authority_descriptor_digests,
        &expected_authority_digests(&transaction.candidate_manifest),
    )?;
    validate_scm_bindings(transaction, envelope)?;

    if payload.elevation_evidence_digest
        != expected_elevation_evidence_digest(&transaction.precondition_evidence)?
    {
        return Err(binding_mismatch(
            "elevation evidence is not the complete transaction precondition fence",
        ));
    }
    let approval_ref =
        PlatformHandle::new(verified.envelope_digest().to_owned()).map_err(|error| {
            InstallationError::InvalidField {
                field: "signed_envelope.envelope_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
    let approval = InstallationActivationApproval::from_verified_parts(
        approval_ref,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.generation.clone(),
        expected_manifest_digest,
        runtime.descriptor_digest.clone(),
        transaction.request.required_owner.clone(),
        transaction.candidate_manifest.signature_ref.clone(),
        runtime.authority_descriptor_path.clone(),
        runtime.authority_descriptor_digest.clone(),
        runtime.authority_generation,
        runtime.authority_state_fence.clone(),
    );
    approval.validate()?;
    approval.validate_against(transaction)?;
    let envelope_digest =
        PlatformHandle::new(verified.envelope_digest().to_owned()).map_err(|error| {
            InstallationError::InvalidField {
                field: "signed_envelope.envelope_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
    Ok(VerifiedActivationProjection {
        approval,
        envelope_digest,
        payload_digest: payload_digest(envelope)?,
    })
}

#[cfg(windows)]
fn require_stopped_scm_contour(
    transaction: &InstallationTransaction,
) -> Result<(), InstallationError> {
    let root = PathBuf::from(
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .installation_root
            .as_str(),
    );
    let platform = WindowsPlatform::new(root)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    for approval in transaction.service_registration_approvals()? {
        let request = approval.service_registration_request()?;
        require_stopped_scm_observation(platform.inspect_service_registration_runtime(&request))?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn require_stopped_scm_contour(
    _transaction: &InstallationTransaction,
) -> Result<(), InstallationError> {
    Err(InstallationError::Platform(
        "signed activation requires the Windows SCM observation boundary".to_owned(),
    ))
}

impl RedbInstallationRegistry {
    fn pending_projection_matches(
        &self,
        transaction: &InstallationTransaction,
        approval: &InstallationActivationApproval,
    ) -> Result<bool, InstallationError> {
        let registry = self.load()?;
        let Some(pending) = registry.pending_activation().cloned() else {
            return Ok(false);
        };
        if !matches!(pending.state, super::PendingActivationState::Pending)
            || pending.transaction_id != transaction.transaction_id
            || pending.plan_digest != transaction.installer_plan_digest
            || pending.manifest != transaction.candidate_manifest
            || pending.approval != *approval
        {
            return Ok(false);
        }
        let approvals = transaction.service_registration_approvals()?;
        Ok(approvals.iter().all(|expected| {
            registry.service_registration_approval(&expected.generation, expected.role)
                == Some(expected)
        }))
    }

    fn quarantine_activation_projection_if_current(
        transaction_store: &mut RedbInstallationTransactionStore,
        transaction_id: &PlatformHandle,
        pending_ref: PlatformHandle,
    ) -> Result<(), InstallationError> {
        let Some(mut current) = transaction_store.load(transaction_id)? else {
            return Err(InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            });
        };
        if current.stage() != super::InstallationStage::Activating {
            return Ok(());
        }
        if current.activation_projection_intent().is_none() {
            return Err(InstallationError::IdentityConflict);
        }
        let expected = TransactionVersion::of(&current)?;
        current.quarantine_activation_projection(pending_ref)?;
        <RedbInstallationTransactionStore as Sealed>::compare_and_save(
            transaction_store,
            expected,
            &current,
        )
    }

    fn reconcile_activation_projection(
        &self,
        transaction_store: &mut RedbInstallationTransactionStore,
        transaction_id: &PlatformHandle,
        transaction: &InstallationTransaction,
        approval: &InstallationActivationApproval,
    ) -> Result<(), InstallationError> {
        let intent = transaction
            .activation_projection_intent()
            .ok_or(InstallationError::IdentityConflict)?;
        intent.validate_against_transaction(transaction)?;
        if self.pending_projection_matches(transaction, approval)? {
            return Ok(());
        }

        let registry = self.load()?;
        let mut stage_error = if registry.revision() == intent.expected_registry_revision
            && registry_projection_identity(&registry)? == intent.expected_registry_identity
        {
            self.mutate_atomic(intent.expected_registry_revision, |registry| {
                registry.stage_pending_activation_from_transaction_with_pre_activation_approval(
                    transaction,
                    approval.clone(),
                )
            })
        } else {
            Err(InstallationError::IdentityConflict)
        };
        if stage_error.is_ok() {
            return Ok(());
        }

        // The transaction CAS may have succeeded while the registry response
        // was lost, or another process may have completed the exact registry
        // projection.  Reload before deciding that the projection is a
        // conflict; an exact pending value is an idempotent success.
        if self.pending_projection_matches(transaction, approval)? {
            return Ok(());
        }
        let pending_ref = PlatformHandle::new(sha256_hex(
            format!(
                "activation-projection-recovery-v1\0{}\0{}",
                transaction.transaction_id.as_str(),
                intent.envelope_digest.as_str(),
            )
            .as_bytes(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "activation_projection.pending_ref".to_owned(),
            reason: error.to_string(),
        })?;
        if let Err(quarantine_error) = Self::quarantine_activation_projection_if_current(
            transaction_store,
            transaction_id,
            pending_ref,
        ) {
            // Preserve the first provider/CAS diagnosis.  A concurrent actor
            // may already have quarantined or advanced the transaction; never
            // retry by mutating a new actor's revision.
            if !matches!(
                quarantine_error,
                InstallationError::CompareAndSaveConflict { .. }
            ) {
                stage_error = Err(quarantine_error);
            }
        }
        stage_error
    }

    fn stage_pending_activation_with_verified_projection(
        &self,
        transaction_store: &mut RedbInstallationTransactionStore,
        transaction_id: &PlatformHandle,
        projection: VerifiedActivationProjection,
        installer_capability: &HostOwnerEpochCapability,
        expected_registry_revision: u64,
    ) -> Result<(), InstallationError> {
        let _guard = installer_capability
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let current = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if current.transaction_id != *transaction_id
            || projection.approval.transaction_id != *transaction_id
        {
            return Err(InstallationError::IdentityConflict);
        }
        match current.stage() {
            super::InstallationStage::Registering => {
                projection.approval.validate_against(&current)?;
                let registry = self.load()?;
                if registry.revision() != expected_registry_revision {
                    return Err(InstallationError::CompareAndSaveConflict {
                        expected: expected_registry_revision,
                        actual: registry.revision(),
                    });
                }
                let intent = super::InstallationActivationProjectionIntent::new(
                    &current,
                    &projection.approval,
                    projection.envelope_digest,
                    projection.payload_digest,
                    registry.revision(),
                    registry_projection_identity(&registry)?,
                )?;
                let expected_transaction = TransactionVersion::of(&current)?;
                let mut activating = current;
                activating
                    .advance_to_activating_for_signed_approval(&projection.approval, intent)?;
                <RedbInstallationTransactionStore as Sealed>::compare_and_save(
                    transaction_store,
                    expected_transaction,
                    &activating,
                )?;
                self.reconcile_activation_projection(
                    transaction_store,
                    transaction_id,
                    &activating,
                    &projection.approval,
                )
            }
            super::InstallationStage::Activating => {
                current
                    .activation_projection_intent()
                    .ok_or(InstallationError::IdentityConflict)?
                    .matches_verified(
                        &current,
                        &projection.approval,
                        &projection.envelope_digest,
                        &projection.payload_digest,
                    )?;
                self.reconcile_activation_projection(
                    transaction_store,
                    transaction_id,
                    &current,
                    &projection.approval,
                )
            }
            stage => Err(InstallationError::IllegalTransition {
                from: stage,
                to: super::InstallationStage::Activating,
            }),
        }
    }

    /// Applies the first-install bootstrap projection through the same
    /// transaction-CAS-before-registry-CAS protocol as a signed activation.
    ///
    /// The bootstrap approval is derived only from the retained transaction;
    /// it is not caller input and it carries no authority bytes.  The
    /// transaction is first advanced to `Activating` with a durable
    /// `InstallationActivationProjectionIntent`.  Only then is the registry
    /// pending projection attempted.  A retry after an unknown registry write
    /// reloads that intent and reconciles the exact projection; it never
    /// stages a second independent approval.
    pub(crate) fn stage_pending_activation_bootstrap(
        &self,
        transaction_store: &mut RedbInstallationTransactionStore,
        transaction_id: &PlatformHandle,
        expected_registry_revision: u64,
    ) -> Result<(), InstallationError> {
        let current = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if current.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        let approval = bootstrap_approval(&current)?;
        let envelope_digest = synthetic_projection_digest("bootstrap-envelope", &approval)?;
        let payload_digest = synthetic_projection_digest("bootstrap-payload", &approval)?;
        match current.stage() {
            super::InstallationStage::Registering => {
                current.require_bootstrap_effects_ready()?;
                approval.validate_against(&current)?;
                let registry = self.load()?;
                if registry.revision() != expected_registry_revision {
                    return Err(InstallationError::CompareAndSaveConflict {
                        expected: expected_registry_revision,
                        actual: registry.revision(),
                    });
                }
                let intent = super::InstallationActivationProjectionIntent::new(
                    &current,
                    &approval,
                    envelope_digest,
                    payload_digest,
                    registry.revision(),
                    registry_projection_identity(&registry)?,
                )?;
                let expected_transaction = TransactionVersion::of(&current)?;
                let mut activating = current;
                activating.advance_to_activating_for_signed_approval(&approval, intent)?;
                <RedbInstallationTransactionStore as Sealed>::compare_and_save(
                    transaction_store,
                    expected_transaction,
                    &activating,
                )?;
                self.reconcile_activation_projection(
                    transaction_store,
                    transaction_id,
                    &activating,
                    &approval,
                )
            }
            super::InstallationStage::Activating => {
                let intent = current
                    .activation_projection_intent()
                    .ok_or(InstallationError::IdentityConflict)?;
                intent.validate_against_transaction(&current)?;
                if intent.verified_approval
                    != super::InstallationActivationApprovalBinding::from_approval(&approval)
                    || intent.envelope_digest != envelope_digest
                    || intent.payload_digest != payload_digest
                {
                    return Err(InstallationError::IdentityConflict);
                }
                self.reconcile_activation_projection(
                    transaction_store,
                    transaction_id,
                    &current,
                    &approval,
                )
            }
            stage => Err(InstallationError::IllegalTransition {
                from: stage,
                to: super::InstallationStage::Activating,
            }),
        }
    }

    /// Applies one verified signed approval to the durable activation
    /// boundary.  This is the production seam shared by the detached-signature
    /// entry point and its coordinator-facing tests: the transaction CAS owns
    /// `Registering -> Activating`, and only then may the registry projection
    /// become pending.  The approval remains private to this crate, so callers
    /// cannot supply a raw stage advance or an unverified identity.
    #[cfg(test)]
    pub(crate) fn stage_pending_activation_with_verified_approval(
        &self,
        transaction_store: &mut RedbInstallationTransactionStore,
        transaction_id: &PlatformHandle,
        approval: InstallationActivationApproval,
        installer_capability: &HostOwnerEpochCapability,
        expected_registry_revision: u64,
    ) -> Result<(), InstallationError> {
        let initial = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if initial.transaction_id != *transaction_id || approval.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        let envelope_digest = synthetic_projection_digest("verified-approval-envelope", &approval)?;
        let payload_digest = synthetic_projection_digest("verified-approval-payload", &approval)?;
        self.stage_pending_activation_with_verified_projection(
            transaction_store,
            transaction_id,
            VerifiedActivationProjection {
                approval,
                envelope_digest,
                payload_digest,
            },
            installer_capability,
            expected_registry_revision,
        )
    }

    /// Verifies a detached authority-signed activation and stages the exact
    /// pending generation.  The authority key is an opaque signer loaded by
    /// `WindowsInstallationAuthorityKeyStore`; callers cannot pass a
    /// self-attested trust anchor or a caller-shaped private approval.
    ///
    /// The installer must hold the live exclusive Host-owner capability while
    /// Host and both SCM services are stopped.  The transaction is loaded and
    /// checksummed before verification and transitioned through the sealed
    /// transaction-store CAS before the registry CAS; any revision or
    /// full-byte checksum drift rejects the write.
    pub fn stage_pending_activation_signed(
        &self,
        transaction_store: &mut RedbInstallationTransactionStore,
        transaction_id: &super::PlatformHandle,
        envelope: &SignedInstallationActivationApproval,
        authority_key: &InstallationAuthorityKeySigner,
        now_ms: i64,
        installer_capability: &HostOwnerEpochCapability,
        expected_registry_revision: u64,
    ) -> Result<(), InstallationError> {
        let initial = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if initial.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        let signed_transaction_revision = match initial.stage() {
            super::InstallationStage::Registering => initial.revision(),
            super::InstallationStage::Activating => {
                initial
                    .activation_projection_intent()
                    .ok_or(InstallationError::IdentityConflict)?
                    .original_transaction_revision
            }
            stage => {
                return Err(InstallationError::IllegalTransition {
                    from: stage,
                    to: super::InstallationStage::Activating,
                });
            }
        };
        if envelope.payload.transaction_revision != signed_transaction_revision
            || envelope.payload.transaction_id != initial.transaction_id.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
        require_stopped_scm_contour(&initial)?;
        let projection = verify_and_derive_projection(
            &initial,
            envelope,
            authority_key,
            now_ms,
            signed_transaction_revision,
        )?;
        self.stage_pending_activation_with_verified_projection(
            transaction_store,
            transaction_id,
            projection,
            installer_capability,
            expected_registry_revision,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: char) -> String {
        value.to_string().repeat(64)
    }

    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into())
            .unwrap_or_else(|error| panic!("test handle must validate: {error}"))
    }

    #[test]
    fn named_digest_sets_reject_omission_alias_and_name_swap() {
        let a = digest('a');
        let b = digest('b');
        let expected = BTreeMap::from([("a", a.as_str()), ("b", b.as_str())]);
        let good = vec![
            InstallationDigestBinding {
                name: "a".to_owned(),
                digest: a.clone(),
            },
            InstallationDigestBinding {
                name: "b".to_owned(),
                digest: b.clone(),
            },
        ];
        assert!(require_exact_digest_set("test", &good, &expected).is_ok());
        assert!(require_exact_digest_set("test", &good[..1], &expected).is_err());
        let alias = vec![
            InstallationDigestBinding {
                name: "a".to_owned(),
                digest: a.clone(),
            },
            InstallationDigestBinding {
                name: "b".to_owned(),
                digest: a.clone(),
            },
        ];
        assert!(require_exact_digest_set("test", &alias, &expected).is_err());
        let swap = vec![
            InstallationDigestBinding {
                name: "a".to_owned(),
                digest: b.clone(),
            },
            InstallationDigestBinding {
                name: "b".to_owned(),
                digest: digest('a'),
            },
        ];
        assert!(require_exact_digest_set("test", &swap, &expected).is_err());
    }

    #[test]
    fn elevation_digest_is_complete_and_order_bound() {
        let first = vec![
            handle("evidence:elevation:a"),
            handle("evidence:elevation:b"),
        ];
        let reordered = vec![first[1].clone(), first[0].clone()];
        let changed = vec![first[0].clone(), handle("evidence:elevation:substituted")];
        let expected = expected_elevation_evidence_digest(&first)
            .unwrap_or_else(|error| panic!("digest must validate: {error}"));
        assert_ne!(
            expected,
            expected_elevation_evidence_digest(&reordered)
                .unwrap_or_else(|error| panic!("reordered digest must validate: {error}"))
        );
        assert_ne!(
            expected,
            expected_elevation_evidence_digest(&changed)
                .unwrap_or_else(|error| panic!("changed digest must validate: {error}"))
        );
    }

    #[test]
    fn scm_absence_mismatch_and_unknown_are_not_activation_proof() {
        for observation in [
            ServiceRegistrationRuntimeInspection::Absent,
            ServiceRegistrationRuntimeInspection::Mismatched,
            ServiceRegistrationRuntimeInspection::Unknown,
        ] {
            assert!(require_stopped_scm_observation(observation).is_err());
        }
    }
}
