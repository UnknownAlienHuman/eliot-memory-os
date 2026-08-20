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

use super::{
    CandidateManifest, HostOwnerEpochCapability, InstallationActivationApproval, InstallationError,
    InstallationProfile, InstallationTransaction, InstallationTransactionStore,
    InstallerServiceRole, PlatformHandle, RedbInstallationRegistry,
    RedbInstallationTransactionStore, candidate_manifest_digest, sha256_hex,
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
const AUTHORITY_SUPERVISION_KEY: &str = "supervision_key";

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

fn transaction_checksum(
    transaction: &InstallationTransaction,
) -> Result<String, InstallationError> {
    let bytes =
        serde_json::to_vec(transaction).map_err(|error| InstallationError::CorruptRegistry {
            reason: format!("transaction snapshot could not be canonicalized: {error}"),
        })?;
    Ok(sha256_hex(&bytes))
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

fn require_activation_nonce_evidence(
    precondition_evidence: &[PlatformHandle],
    completed_stage_refs: &[PlatformHandle],
    observed_postconditions: &[PlatformHandle],
    activation_nonce: &str,
) -> Result<(), InstallationError> {
    let nonce_digest = sha256_hex(activation_nonce.as_bytes());
    let evidence = precondition_evidence
        .iter()
        .chain(completed_stage_refs.iter())
        .chain(observed_postconditions.iter())
        .filter(|reference| reference.as_str() == nonce_digest)
        .count();
    match evidence {
        1 => Ok(()),
        0 => Err(binding_mismatch(
            "activation nonce is not bound to one durable transaction evidence digest",
        )),
        _ => Err(binding_mismatch(
            "activation nonce evidence is duplicated in the transaction",
        )),
    }
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
        (
            AUTHORITY_SUPERVISION_KEY,
            manifest.supervision_key_fingerprint.as_str(),
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

fn verify_and_derive_approval(
    transaction: &InstallationTransaction,
    envelope: &SignedInstallationActivationApproval,
    authority_key: &InstallationAuthorityKeySigner,
    now_ms: i64,
) -> Result<InstallationActivationApproval, InstallationError> {
    transaction.require_all_effects_applied()?;
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
        transaction_revision: transaction.revision(),
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
        || payload.transaction_revision != transaction.revision()
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
    require_activation_nonce_evidence(
        &transaction.precondition_evidence,
        &transaction.completed_stage_refs,
        &transaction.observed_postconditions,
        &payload.activation_nonce,
    )?;

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
    Ok(approval)
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
    /// Verifies a detached authority-signed activation and stages the exact
    /// pending generation.  The authority key is an opaque signer loaded by
    /// `WindowsInstallationAuthorityKeyStore`; callers cannot pass a
    /// self-attested trust anchor or a caller-shaped private approval.
    ///
    /// The installer must hold the live exclusive Host-owner capability while
    /// Host and both SCM services are stopped.  The transaction is loaded and
    /// checksummed before verification and reloaded inside the registry CAS;
    /// any revision or full-byte checksum drift rejects the write.
    pub fn stage_pending_activation_signed(
        &self,
        transaction_store: &RedbInstallationTransactionStore,
        transaction_id: &super::PlatformHandle,
        envelope: &SignedInstallationActivationApproval,
        authority_key: &InstallationAuthorityKeySigner,
        now_ms: i64,
        installer_capability: &HostOwnerEpochCapability,
        expected_registry_revision: u64,
    ) -> Result<(), InstallationError> {
        let _guard = installer_capability
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;

        let initial = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if initial.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        let initial_checksum = transaction_checksum(&initial)?;
        if envelope.payload.transaction_revision != initial.revision()
            || envelope.payload.transaction_id != initial.transaction_id.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
        require_stopped_scm_contour(&initial)?;

        self.mutate_atomic(expected_registry_revision, |registry| {
            let current = transaction_store.load(transaction_id)?.ok_or_else(|| {
                InstallationError::TransactionNotFound {
                    transaction_id: transaction_id.as_str().to_owned(),
                }
            })?;
            let current_checksum = transaction_checksum(&current)?;
            if current.revision() != initial.revision() {
                return Err(InstallationError::CompareAndSaveConflict {
                    expected: initial.revision(),
                    actual: current.revision(),
                });
            }
            if current_checksum != initial_checksum {
                return Err(InstallationError::IdentityConflict);
            }
            if current.transaction_id != *transaction_id {
                return Err(InstallationError::IdentityConflict);
            }
            let approval = verify_and_derive_approval(&current, envelope, authority_key, now_ms)?;
            registry.stage_pending_activation_from_transaction_with_approval(&current, approval)
        })
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
    fn activation_nonce_requires_one_transaction_evidence_reference() {
        let nonce = "c".repeat(64);
        let nonce_digest = sha256_hex(nonce.as_bytes());
        let evidence = vec![handle(nonce_digest)];
        assert!(require_activation_nonce_evidence(&evidence, &[], &[], &nonce).is_ok());
        assert!(require_activation_nonce_evidence(&evidence, &[], &[], &"d".repeat(64)).is_err());
        assert!(require_activation_nonce_evidence(&evidence, &evidence, &[], &nonce).is_err());
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
