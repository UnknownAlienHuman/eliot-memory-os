//! Original deterministic-setup effect producer and restart reconciliation.
//!
//! This module advances only the original `SetupBinding` and its existing
//! setup-effect intent table. It never chooses a replacement transaction,
//! infers owner identity from a path, or substitutes a caller Boolean for an
//! effect readback. Every profile's key material is prepared once and its
//! exact public receipt is committed to the `ServiceKeysGenerated` intent before
//! provider effects. `SystemService` also commits the native slot identity after
//! create-only reservation and before writing private key bytes. A restart
//! reopens only the exact retained receipt and never regenerates a missing key.

use std::path::{Path, PathBuf};

use eliot_config::initial_snapshot::PrivacyChoice;
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::PORTABLE_DEV_SUPERVISION_KEY_PREFIX;
use serde::Serialize;
use thiserror::Error;

use crate::{
    InstallationError, InstallationProfile, InstallationTransaction, InstallationTransactionStore,
    RedbInstallationTransactionStore, SetupAdvanceInput, SetupBinding, SetupEffectObservation,
    SetupKeyReference, SetupMilestone, UserOwnedRootLease, sha256_hex,
};

/// Refusal from the original deterministic-setup producer.
#[derive(Debug, Error)]
pub enum SetupProductionError {
    /// The selected transaction or original setup journal refused.
    #[error(transparent)]
    Installation(#[from] InstallationError),
    /// Profile-owned key provisioning or readback refused.
    #[error("profile-owned setup signing key refused: {0}")]
    SigningKey(String),
    /// A durable setup record is missing or no longer matches its original
    /// transaction, principal, profile, receipt, or observed effect.
    #[error("deterministic setup refused: {0}")]
    Refused(&'static str),
}

/// Verifies that the key reference retained in the setup binding is exactly
/// the profile-specific receipt stored in the original `ServiceKeysGenerated`
/// intent. Callers still reopen the key through the provider, which performs
/// current-principal, path, ACL and key-material readback.
pub(crate) fn validate_original_setup_key_readback(
    store: &RedbInstallationTransactionStore,
    binding: &SetupBinding,
) -> Result<(), SetupProductionError> {
    let retained = setup_key_reference(binding)?;
    let expected = match binding.profile {
        InstallationProfile::PortableDev => store
            .load_setup_portable_dev_signing_key_intent(&binding.transaction_id)?
            .map(|receipt| {
                setup_key_reference_from_portable(
                    receipt,
                    binding,
                    &retained.principal_sid,
                )
            })
            .transpose()?,
        InstallationProfile::UserMode => store
            .load_setup_user_mode_signing_key_intent(&binding.transaction_id)?
            .map(|receipt| {
                setup_key_reference_from_user_mode(receipt, binding, &retained.principal_sid)
            })
            .transpose()?,
        InstallationProfile::SystemService => {
            let Some(intent) = store.load_setup_system_service_signing_key_intent(
                &binding.transaction_id,
            )? else {
                return Err(SetupProductionError::Refused(
                    "the original SystemService setup-key intent receipt is absent",
                ));
            };
            if intent.installation_id != binding.installation_id
                || intent.confirmed_owner != binding.confirmed_owner
                || intent.receipt.slot_file_identity.is_none()
                || intent.receipt.key_id != retained.key_id.as_str()
                || intent.authorized_principal_sid != retained.principal_sid
            {
                return Err(SetupProductionError::Refused(
                    "the retained SystemService setup key differs from its original transaction, owner, caller, or native slot receipt",
                ));
            }
            let typed = eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_setup_target_ref(
                &retained.target_ref,
            )
            .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?
            .ok_or(SetupProductionError::Refused(
                "the original SystemService key does not carry the initial-snapshot purpose",
            ))?;
            if !typed.belongs_to_profile(eliot_platform_windows::InstallerRootProfile::SystemService)
                || !typed.matches_system_service_preparation_receipt(&intent.receipt)
            {
                return Err(SetupProductionError::Refused(
                    "the retained SystemService purpose reference differs from its original protected key receipt",
                ));
            }
            Some(retained.clone())
        }
    }
    .ok_or(SetupProductionError::Refused(
        "the original setup-key receipt is absent from ServiceKeysGenerated",
    ))?;
    if expected != retained {
        return Err(SetupProductionError::Refused(
            "the setup binding key reference differs from its original ServiceKeysGenerated receipt",
        ));
    }
    Ok(())
}

/// Reconciles and advances the original I3.2 setup sequence for one retained
/// transaction. The explicit installation identity is compared with the
/// immutable transaction; it does not supply an owner, profile, key, root, or
/// storage-health assertion.
pub fn prepare_deterministic_setup_for_initial_snapshot(
    store: &mut RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
    confirmed_installation_id: &str,
    privacy_choice: PrivacyChoice,
) -> Result<SetupBinding, SetupProductionError> {
    let transaction = store
        .load(transaction_id)?
        .ok_or(SetupProductionError::Refused(
            "the selected original installation transaction is absent",
        ))?;
    validate_confirmation(&transaction, transaction_id, confirmed_installation_id)?;
    let current_sid = eliot_platform_windows::WindowsSetupOwnerInitialSnapshotKeyProvider::new()
        .current_principal_sid()
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let mut binding = match store.load_setup_binding(transaction_id)? {
        Some(binding) => {
            validate_existing_binding(store, &transaction, transaction_id, &binding, &current_sid)?;
            binding
        }
        None => create_identity_binding(store, &transaction, transaction_id, &current_sid)?,
    };

    require_recorded_or_advance(
        store,
        &transaction,
        &mut binding,
        SetupMilestone::SystemOwnerEstablished,
        &current_sid,
    )?;
    ensure_service_key(store, &transaction, &mut binding, &current_sid)?;
    ensure_acl_readback(store, &transaction, &mut binding, &current_sid)?;
    ensure_privacy_choice(
        store,
        &transaction,
        &mut binding,
        &current_sid,
        privacy_choice,
    )?;
    ensure_storage_verified(store, &transaction, &mut binding)?;
    Ok(binding)
}

fn validate_confirmation(
    transaction: &InstallationTransaction,
    transaction_id: &PlatformHandle,
    confirmed_installation_id: &str,
) -> Result<(), SetupProductionError> {
    if transaction.transaction_id != *transaction_id
        || transaction.installation_epoch.installation.as_str() != confirmed_installation_id
        || transaction
            .candidate_manifest
            .runtime_launch
            .installation_epoch
            .installation
            != transaction.installation_epoch.installation
        || transaction
            .request
            .required_owner
            .as_str()
            .trim()
            .is_empty()
    {
        return Err(SetupProductionError::Refused(
            "the explicit installation confirmation does not match the original transaction",
        ));
    }
    transaction.rehydrate_profile_binding()?;
    Ok(())
}

fn validate_existing_binding(
    store: &RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    transaction_id: &PlatformHandle,
    binding: &SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<(), SetupProductionError> {
    binding.validate()?;
    let roots =
        transaction
            .profile_governed_roots
            .as_ref()
            .ok_or(SetupProductionError::Refused(
                "the transaction has no retained profile-root binding",
            ))?;
    if binding.transaction_id != *transaction_id
        || binding.installation_id != transaction.installation_epoch.installation
        || binding.profile != transaction.profile
        || binding.confirmed_owner != transaction.request.required_owner
        || binding.runtime_state_roots_digest != roots.runtime_state_roots.roots_digest
    {
        return Err(SetupProductionError::Refused(
            "the durable setup binding differs from the original transaction identity or roots",
        ));
    }
    let identity_evidence = vec![
        transaction_id.clone(),
        transaction.installation_epoch.installation.clone(),
        current_sid.clone(),
    ];
    let expected_identity = SetupBinding::new(
        transaction_id.clone(),
        transaction.installation_epoch.installation.clone(),
        transaction.profile,
        roots.runtime_state_roots.roots_digest.clone(),
        0,
        transaction.request.required_owner.clone(),
        identity_evidence,
    )?;
    if binding.observed_effects().first() != expected_identity.observed_effects().first() {
        return Err(SetupProductionError::Refused(
            "the original identity-confirmation observation does not match this principal and transaction",
        ));
    }
    let facts = (
        transaction_id.as_str(),
        transaction.installation_epoch.installation.as_str(),
        transaction.profile,
        roots.runtime_state_roots.roots_digest.as_str(),
        transaction.request.required_owner.as_str(),
        current_sid.as_str(),
    );
    let expected_intent = digest_handle("eliot.setup.identity-confirmed.intent.v1", &facts)?;
    if store.load_setup_effect_intent(
        transaction_id,
        SetupMilestone::InstallationIdentityConfirmed,
    )? != Some(expected_intent)
    {
        return Err(SetupProductionError::Refused(
            "the original identity-confirmation intent is absent or differs",
        ));
    }
    Ok(())
}

fn create_identity_binding(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    transaction_id: &PlatformHandle,
    current_sid: &PlatformHandle,
) -> Result<SetupBinding, SetupProductionError> {
    let roots =
        transaction
            .profile_governed_roots
            .as_ref()
            .ok_or(SetupProductionError::Refused(
                "the transaction has no retained profile-root binding",
            ))?;
    let installation_id = transaction.installation_epoch.installation.clone();
    let confirmed_owner = transaction.request.required_owner.clone();
    let evidence_refs = vec![
        transaction_id.clone(),
        installation_id.clone(),
        current_sid.clone(),
    ];
    let facts = (
        transaction_id.as_str(),
        installation_id.as_str(),
        transaction.profile,
        roots.runtime_state_roots.roots_digest.as_str(),
        confirmed_owner.as_str(),
        current_sid.as_str(),
    );
    let intent_digest = digest_handle("eliot.setup.identity-confirmed.intent.v1", &facts)?;
    store.record_setup_effect_intent(
        transaction_id,
        SetupMilestone::InstallationIdentityConfirmed,
        &intent_digest,
    )?;
    let binding = SetupBinding::new(
        transaction_id.clone(),
        installation_id,
        transaction.profile,
        roots.runtime_state_roots.roots_digest.clone(),
        0,
        confirmed_owner,
        evidence_refs,
    )?;
    store.create_setup_binding(&binding)?;
    let retained =
        store
            .load_setup_binding(transaction_id)?
            .ok_or(SetupProductionError::Refused(
                "the original identity-confirmation binding was not read back",
            ))?;
    if retained != binding {
        return Err(SetupProductionError::Refused(
            "the original identity-confirmation binding differs on readback",
        ));
    }
    Ok(retained)
}

fn require_recorded_or_advance(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &mut SetupBinding,
    milestone: SetupMilestone,
    current_sid: &PlatformHandle,
) -> Result<(), SetupProductionError> {
    let evidence_refs = vec![
        transaction.request.required_owner.clone(),
        transaction.installation_epoch.installation.clone(),
        current_sid.clone(),
    ];
    let facts = (
        transaction.transaction_id.as_str(),
        transaction.request.required_owner.as_str(),
        transaction.installation_epoch.installation.as_str(),
        current_sid.as_str(),
    );
    if binding.state().position() >= milestone.position() {
        ensure_existing_observation(
            binding,
            milestone,
            &evidence_refs,
            "eliot.setup.system-owner-established.v1",
            &facts,
        )?;
        return ensure_existing_intent(
            store,
            &transaction.transaction_id,
            milestone,
            "eliot.setup.system-owner-established.v1",
            &facts,
        );
    }
    if binding.state().next() != Some(milestone) {
        return Err(SetupProductionError::Refused(
            "the setup binding cannot advance to SystemOwnerEstablished in order",
        ));
    }
    advance_with_intent(
        store,
        binding,
        milestone,
        evidence_refs,
        "eliot.setup.system-owner-established.v1",
        &facts,
    )
}

fn ensure_service_key(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &mut SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<(), SetupProductionError> {
    let milestone = SetupMilestone::ServiceKeysGenerated;
    if binding.state().position() >= milestone.position() {
        validate_original_setup_key_readback(store, binding)?;
        let key_reference = setup_key_reference(binding)?;
        if key_reference.principal_sid != *current_sid {
            return Err(SetupProductionError::Refused(
                "the retained setup signing key belongs to a different Windows principal",
            ));
        }
        reopen_setup_key(transaction, binding, &key_reference)?;
        let evidence_refs = vec![
            key_reference.key_id.clone(),
            key_reference.target_ref.clone(),
            key_reference.principal_sid.clone(),
        ];
        let facts = (
            transaction.transaction_id.as_str(),
            key_reference.key_id.as_str(),
            key_reference.target_ref.as_str(),
            key_reference.principal_sid.as_str(),
        );
        ensure_existing_observation(
            binding,
            milestone,
            &evidence_refs,
            "eliot.setup.service-keys-generated.v1",
            &facts,
        )?;
        if store
            .load_setup_effect_intent(&binding.transaction_id, milestone)?
            .is_none()
        {
            return Err(SetupProductionError::Refused(
                "the original ServiceKeysGenerated intent is absent",
            ));
        }
        return Ok(());
    }
    if binding.state().next() != Some(milestone) {
        return Err(SetupProductionError::Refused(
            "the setup binding cannot advance to ServiceKeysGenerated in order",
        ));
    }

    let setup_key = match transaction.profile {
        InstallationProfile::PortableDev => {
            prepare_or_reconcile_portable_dev_key(store, transaction, binding, current_sid)?
        }
        InstallationProfile::UserMode => {
            prepare_or_reconcile_user_mode_key(store, transaction, binding, current_sid)?
        }
        InstallationProfile::SystemService => {
            prepare_or_reconcile_system_service_key(store, transaction, binding, current_sid)?
        }
    };
    let evidence_refs = vec![
        setup_key.key_id.clone(),
        setup_key.target_ref.clone(),
        setup_key.principal_sid.clone(),
    ];
    let facts = (
        transaction.transaction_id.as_str(),
        setup_key.key_id.clone(),
        setup_key.target_ref.clone(),
        setup_key.principal_sid.clone(),
    );
    advance_after_recorded_intent(
        store,
        binding,
        milestone,
        evidence_refs,
        "eliot.setup.service-keys-generated.v1",
        &facts,
        vec![setup_key],
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "original PortableDev key preparation and restart reconciliation share one durable intent boundary"
)]
fn prepare_or_reconcile_portable_dev_key(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<SetupKeyReference, SetupProductionError> {
    use eliot_platform_windows::{
        PortableDevSupervisionAuthorityKeyObservation as Observation,
        PortableDevSupervisionAuthorityKeyRequest as Request,
        PortableDevSupervisionAuthorityKeyTargetObservation as TargetObservation,
        WindowsPortableDevSupervisionAuthorityKeyProvider,
    };

    let provider = WindowsPortableDevSupervisionAuthorityKeyProvider::new();
    let roots = &transaction
        .candidate_manifest
        .runtime_launch
        .runtime_state_roots;
    if roots.profile != InstallationProfile::PortableDev {
        return Err(SetupProductionError::Refused(
            "PortableDev key provisioning requires the exact PortableDev runtime roots",
        ));
    }
    let repository_root = PathBuf::from(roots.profile_anchor_root.as_str());
    let root_lease = UserOwnedRootLease::open_existing(&repository_root)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    if root_lease.current_user_sid() != current_sid.as_str() {
        return Err(SetupProductionError::Refused(
            "the retained PortableDev root belongs to another current-user principal",
        ));
    }
    let repository_root_identity = root_lease.identity();
    let relative_path = format!(
        "{PORTABLE_DEV_SUPERVISION_KEY_PREFIX}{}.key",
        sha256_hex(transaction.transaction_id.as_str().as_bytes())
    );
    let runtime = &transaction.candidate_manifest.runtime_launch;
    let request = Request {
        transaction_id: transaction.transaction_id.as_str().to_owned(),
        effect_id: milestone_effect_id().to_owned(),
        installation_id: transaction
            .installation_epoch
            .installation
            .as_str()
            .to_owned(),
        candidate_generation: transaction
            .candidate_manifest
            .generation
            .as_str()
            .to_owned(),
        authority_generation: runtime.authority_generation,
        supervision_lease_scope_id: runtime.supervision_lease_scope_id().to_owned(),
        signer_id: binding.confirmed_owner.as_str().to_owned(),
        key_id: transaction.transaction_id.as_str().to_owned(),
        repository_root,
        repository_root_identity,
        relative_path,
    };
    let retained = store.load_setup_portable_dev_signing_key_intent(&transaction.transaction_id)?;
    if let Some(receipt) = retained {
        if receipt.request != request {
            return Err(SetupProductionError::Refused(
                "the original PortableDev key receipt differs from the current transaction or principal",
            ));
        }
        return match provider.inspect(&receipt) {
            Ok(Observation::Matching { receipt: observed }) if observed == receipt => {
                setup_key_reference_from_portable(receipt, binding, current_sid)
            }
            Ok(Observation::Matching { .. }) => Err(SetupProductionError::Refused(
                "the original PortableDev key receipt readback differs from the retained receipt",
            )),
            Ok(Observation::Absent { .. } | Observation::Mismatch { .. }) | Err(_) => {
                Err(SetupProductionError::Refused(
                    "the original PortableDev key receipt has no matching key; recovery must inspect that exact intent and may not rotate it",
                ))
            }
        };
    }
    if store
        .load_setup_effect_intent(
            &transaction.transaction_id,
            SetupMilestone::ServiceKeysGenerated,
        )?
        .is_some()
    {
        return Err(SetupProductionError::Refused(
            "ServiceKeysGenerated already has an intent without its original PortableDev receipt",
        ));
    }
    match provider
        .inspect_target(&request)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?
    {
        TargetObservation::Absent { .. } => {}
        TargetObservation::Present { .. } => {
            return Err(SetupProductionError::Refused(
                "an unreceipted PortableDev setup-key target already exists",
            ));
        }
    }
    let prepared = provider
        .prepare(request)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let receipt = prepared.receipt().clone();
    store.record_setup_portable_dev_signing_key_intent(&transaction.transaction_id, &receipt)?;
    let _outcome = provider.write_prepared(prepared);
    match provider.inspect(&receipt) {
        Ok(Observation::Matching { receipt: observed }) if observed == receipt => {
            setup_key_reference_from_portable(receipt, binding, current_sid)
        }
        Ok(Observation::Matching { .. }) => Err(SetupProductionError::Refused(
            "PortableDev setup-key readback differs from its original durable intent",
        )),
        Ok(Observation::Absent { .. } | Observation::Mismatch { .. }) | Err(_) => {
            Err(SetupProductionError::Refused(
                "PortableDev setup-key write is unresolved under its original receipt; do not generate a replacement",
            ))
        }
    }
}

fn prepare_or_reconcile_user_mode_key(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<SetupKeyReference, SetupProductionError> {
    use eliot_platform_windows::{
        UserModeSupervisionAuthorityCredentialObservation as Observation,
        UserModeSupervisionAuthorityCredentialRequest as Request,
        UserModeSupervisionAuthorityCredentialTargetObservation as TargetObservation,
        WindowsUserModeSupervisionAuthorityCredentialProvider,
    };

    let provider = WindowsUserModeSupervisionAuthorityCredentialProvider::new();
    let runtime = &transaction.candidate_manifest.runtime_launch;
    let request = Request {
        transaction_id: transaction.transaction_id.as_str().to_owned(),
        effect_id: milestone_effect_id().to_owned(),
        installation_id: transaction
            .installation_epoch
            .installation
            .as_str()
            .to_owned(),
        candidate_generation: transaction
            .candidate_manifest
            .generation
            .as_str()
            .to_owned(),
        authority_generation: runtime.authority_generation,
        supervision_lease_scope_id: runtime.supervision_lease_scope_id().to_owned(),
        signer_id: binding.confirmed_owner.as_str().to_owned(),
        key_id: transaction.transaction_id.as_str().to_owned(),
        owner_sid: current_sid.as_str().to_owned(),
    };
    if let Some(receipt) =
        store.load_setup_user_mode_signing_key_intent(&transaction.transaction_id)?
    {
        if receipt.request != request {
            return Err(SetupProductionError::Refused(
                "the original UserMode key receipt differs from the current transaction or principal",
            ));
        }
        return match provider.inspect(&receipt) {
            Ok(Observation::Matching { receipt: observed }) if *observed == receipt => {
                setup_key_reference_from_user_mode(receipt, binding, current_sid)
            }
            Ok(Observation::Matching { .. }) => Err(SetupProductionError::Refused(
                "the original UserMode key receipt readback differs from the retained receipt",
            )),
            Ok(Observation::Absent { .. } | Observation::Mismatch { .. }) | Err(_) => {
                Err(SetupProductionError::Refused(
                    "the original UserMode key receipt has no matching credential; recovery may not rotate it",
                ))
            }
        };
    }
    if store
        .load_setup_effect_intent(
            &transaction.transaction_id,
            SetupMilestone::ServiceKeysGenerated,
        )?
        .is_some()
    {
        return Err(SetupProductionError::Refused(
            "ServiceKeysGenerated already has an intent without its original UserMode receipt",
        ));
    }
    match provider
        .inspect_target(&request)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?
    {
        TargetObservation::Absent { owner_sid, .. } if owner_sid == *current_sid => {}
        TargetObservation::Absent { .. } | TargetObservation::Present { .. } => {
            return Err(SetupProductionError::Refused(
                "the UserMode setup-key target is foreign or already occupied",
            ));
        }
    }
    let prepared = provider
        .prepare(request)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let receipt = prepared.receipt().clone();
    store.record_setup_user_mode_signing_key_intent(&transaction.transaction_id, &receipt)?;
    let _outcome = provider.write_prepared(prepared);
    match provider.inspect(&receipt) {
        Ok(Observation::Matching { receipt: observed }) if *observed == receipt => {
            setup_key_reference_from_user_mode(receipt, binding, current_sid)
        }
        Ok(Observation::Matching { .. }) => Err(SetupProductionError::Refused(
            "UserMode setup-key readback differs from its original durable intent",
        )),
        Ok(Observation::Absent { .. } | Observation::Mismatch { .. }) | Err(_) => {
            Err(SetupProductionError::Refused(
                "UserMode setup-key write is unresolved under its original receipt; do not generate a replacement",
            ))
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "SystemService reservation, intent, write and exact readback must remain one ordered owner transition"
)]
fn prepare_or_reconcile_system_service_key(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<SetupKeyReference, SetupProductionError> {
    use eliot_platform_windows::WindowsInstallationAuthorityKeyStore;

    let key_root = selected_profile_key_root(transaction)?.ok_or(SetupProductionError::Refused(
        "the SystemService setup key has no transaction-selected protected root",
    ))?;
    let key_store = WindowsInstallationAuthorityKeyStore::new(&key_root)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let key_root_identity = key_store
        .root_identity()
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let transaction_key_id = transaction.transaction_id.as_str();

    if let Some(intent) =
        store.load_setup_system_service_signing_key_intent(&transaction.transaction_id)?
    {
        if intent.installation_id != transaction.installation_epoch.installation
            || intent.confirmed_owner != binding.confirmed_owner
            || intent.authorized_principal_sid != *current_sid
            || intent.receipt.key_id != transaction_key_id
            || intent.receipt.key_root_identity != key_root_identity
        {
            return Err(SetupProductionError::Refused(
                "the original SystemService protected-key receipt differs from this transaction, owner, principal, or root",
            ));
        }
        if intent.receipt.slot_file_identity.is_none() {
            return Err(SetupProductionError::Refused(
                "the original SystemService key intent has no retained slot identity; recovery may not recreate or rotate it",
            ));
        }
        let signer = key_store
            .open_prepared_receipt(&intent.receipt)
            .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
        let slot_identity =
            intent
                .receipt
                .slot_file_identity
                .ok_or(SetupProductionError::Refused(
                    "the original SystemService key intent lost its native slot identity",
                ))?;
        if signer.metadata().key_id != intent.receipt.key_id
            || signer.metadata().public_key_fingerprint != intent.receipt.public_key_fingerprint
            || signer.metadata().file_identity != slot_identity
        {
            return Err(SetupProductionError::Refused(
                "the original SystemService keyslot metadata does not match its durable preparation receipt",
            ));
        }
        return setup_key_reference_from_system_service(&signer, transaction, binding, current_sid);
    }

    if store
        .load_setup_effect_intent(
            &transaction.transaction_id,
            SetupMilestone::ServiceKeysGenerated,
        )?
        .is_some()
    {
        return Err(SetupProductionError::Refused(
            "ServiceKeysGenerated already has a non-SystemService key intent; it cannot be replaced",
        ));
    }

    key_store
        .require_absent_slot(transaction_key_id)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let prepared = key_store
        .prepare_with_key_id(transaction_key_id)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let prepared_receipt = prepared.receipt().clone();
    if prepared_receipt.key_root_identity != key_root_identity
        || prepared_receipt.slot_file_identity.is_some()
    {
        return Err(SetupProductionError::Refused(
            "the protected key provider preparation does not match its selected root",
        ));
    }
    store.record_setup_system_service_signing_key_intent(
        &transaction.transaction_id,
        &transaction.installation_epoch.installation,
        &binding.confirmed_owner,
        current_sid,
        &prepared_receipt,
    )?;

    let reserved = key_store
        .reserve_prepared(prepared)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    let reserved_receipt = reserved.receipt().clone();
    store.record_setup_system_service_signing_key_intent(
        &transaction.transaction_id,
        &transaction.installation_epoch.installation,
        &binding.confirmed_owner,
        current_sid,
        &reserved_receipt,
    )?;

    let signer = key_store
        .write_reserved(reserved)
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    if signer.metadata().key_id != reserved_receipt.key_id
        || signer.metadata().public_key_fingerprint != reserved_receipt.public_key_fingerprint
        || Some(signer.metadata().file_identity) != reserved_receipt.slot_file_identity
    {
        return Err(SetupProductionError::Refused(
            "the newly written SystemService key differs from its retained original slot receipt",
        ));
    }
    setup_key_reference_from_system_service(&signer, transaction, binding, current_sid)
}

fn setup_key_reference_from_system_service(
    signer: &eliot_platform_windows::InstallationAuthorityKeySigner,
    transaction: &InstallationTransaction,
    binding: &SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<SetupKeyReference, SetupProductionError> {
    let reference = eliot_platform_windows::WindowsSetupOwnerInitialSnapshotKeyProvider::new()
        .reference_for_setup(
            signer,
            transaction.transaction_id.as_str().to_owned(),
            binding.installation_id.as_str().to_owned(),
            binding.confirmed_owner.as_str().to_owned(),
            current_sid.as_str().to_owned(),
        )
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    Ok(SetupKeyReference {
        key_id: PlatformHandle::new(reference.key_id()).map_err(|error| {
            InstallationError::InvalidField {
                field: "setup_key.key_id".to_owned(),
                reason: error.to_string(),
            }
        })?,
        target_ref: reference
            .target_ref()
            .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?,
        // This is the actual setup-authorizing user. The opaque target carries
        // the separate physical SYSTEM key-slot principal.
        principal_sid: current_sid.clone(),
    })
}

fn setup_key_reference_from_portable(
    receipt: eliot_platform_windows::PortableDevSupervisionAuthorityKeyReceipt,
    binding: &SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<SetupKeyReference, SetupProductionError> {
    let reference =
        eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_portable_dev_receipt(
            receipt,
            binding.transaction_id.as_str().to_owned(),
            binding.installation_id.as_str().to_owned(),
            binding.confirmed_owner.as_str().to_owned(),
            current_sid.as_str().to_owned(),
        )
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    Ok(SetupKeyReference {
        key_id: PlatformHandle::new(reference.key_id())
            .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?,
        target_ref: reference
            .target_ref()
            .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?,
        principal_sid: current_sid.clone(),
    })
}

fn setup_key_reference_from_user_mode(
    receipt: eliot_platform_windows::UserModeSupervisionAuthorityCredentialReceipt,
    binding: &SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<SetupKeyReference, SetupProductionError> {
    let reference =
        eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_user_mode_receipt(
            receipt,
            binding.transaction_id.as_str().to_owned(),
            binding.installation_id.as_str().to_owned(),
            binding.confirmed_owner.as_str().to_owned(),
            current_sid.as_str().to_owned(),
        )
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    Ok(SetupKeyReference {
        key_id: PlatformHandle::new(reference.key_id())
            .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?,
        target_ref: reference
            .target_ref()
            .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?,
        principal_sid: current_sid.clone(),
    })
}

fn setup_key_reference(binding: &SetupBinding) -> Result<SetupKeyReference, SetupProductionError> {
    let mut matches = binding.key_references().iter().filter(|reference| {
        eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_setup_target_ref(
            &reference.target_ref,
        )
        .is_ok_and(|reference| reference.is_some())
    });
    let reference = matches
        .next()
        .cloned()
        .ok_or(SetupProductionError::Refused(
            "the exact purpose-bound setup signing-key reference is absent",
        ))?;
    if matches.next().is_some() {
        return Err(SetupProductionError::Refused(
            "more than one purpose-bound setup signing-key reference is retained",
        ));
    }
    Ok(reference)
}

fn reopen_setup_key(
    transaction: &InstallationTransaction,
    binding: &SetupBinding,
    reference: &SetupKeyReference,
) -> Result<(), SetupProductionError> {
    let profile = installer_root_profile(transaction.profile);
    let typed =
        eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_setup_target_ref(
            &reference.target_ref,
        )
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?
        .ok_or(SetupProductionError::Refused(
            "the retained setup key target has no initial-snapshot purpose reference",
        ))?;
    if !typed.belongs_to_profile(profile) {
        return Err(SetupProductionError::Refused(
            "the retained setup key target belongs to a different selected profile",
        ));
    }
    let key_root = selected_profile_key_root(transaction)?;
    eliot_platform_windows::WindowsSetupOwnerInitialSnapshotKeyProvider::new()
        .open(
            &reference.target_ref,
            &reference.key_id,
            &reference.principal_sid,
            transaction.transaction_id.as_str(),
            binding.installation_id.as_str(),
            binding.confirmed_owner.as_str(),
            profile,
            key_root.as_deref(),
        )
        .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
    Ok(())
}

fn ensure_acl_readback(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &mut SetupBinding,
    current_sid: &PlatformHandle,
) -> Result<(), SetupProductionError> {
    let milestone = SetupMilestone::AclsInstalled;
    let (evidence_refs, root_snapshots) = observe_profile_roots(transaction, current_sid)?;
    let facts = (
        transaction.transaction_id.as_str(),
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .roots_digest
            .as_str(),
        current_sid.as_str(),
        root_snapshots,
    );
    if binding.state().position() >= milestone.position() {
        ensure_existing_observation(
            binding,
            milestone,
            &evidence_refs,
            "eliot.setup.acls-installed.v1",
            &facts,
        )?;
        return ensure_existing_intent(
            store,
            &transaction.transaction_id,
            milestone,
            "eliot.setup.acls-installed.v1",
            &facts,
        );
    }
    if binding.state().next() != Some(milestone) {
        return Err(SetupProductionError::Refused(
            "the setup binding cannot advance to AclsInstalled in order",
        ));
    }
    advance_with_intent(
        store,
        binding,
        milestone,
        evidence_refs,
        "eliot.setup.acls-installed.v1",
        &facts,
    )
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AclReadback {
    Installer(eliot_platform_windows::InstallerRootObjectSnapshot),
    UserOwned {
        declared_root: String,
        canonical_root: String,
        file_identity: eliot_platform_windows::FileIdentity,
        principal_sid: String,
    },
}

fn observe_profile_roots(
    transaction: &InstallationTransaction,
    current_sid: &PlatformHandle,
) -> Result<(Vec<PlatformHandle>, Vec<AclReadback>), SetupProductionError> {
    use eliot_platform_windows::{
        InstallerRootPrimitiveObservation as Observation, InstallerRootPrimitiveSpec as Spec,
        WindowsInstallerRootPrimitive,
    };

    let selected =
        transaction
            .profile_governed_roots
            .as_ref()
            .ok_or(SetupProductionError::Refused(
                "the transaction has no retained profile-root binding",
            ))?;
    let runtime = &transaction
        .candidate_manifest
        .runtime_launch
        .runtime_state_roots;
    let profile = installer_root_profile(transaction.profile);
    let mut declarations = vec![
        (
            "immutable_binaries",
            PathBuf::from(selected.immutable_binaries.as_str()),
        ),
        (
            "durable_data",
            PathBuf::from(selected.durable_data.as_str()),
        ),
        ("user_config", PathBuf::from(selected.user_config.as_str())),
        ("user_cache", PathBuf::from(selected.user_cache.as_str())),
    ];
    declarations.extend(
        runtime
            .installer_root_hierarchy()?
            .into_iter()
            .map(|(field, root)| (field, PathBuf::from(root.as_str()))),
    );
    let mut unique = std::collections::BTreeSet::new();
    declarations.retain(|(_, path)| unique.insert(path.to_string_lossy().to_ascii_lowercase()));

    let mut evidence_refs = Vec::with_capacity(declarations.len());
    let mut snapshots = Vec::with_capacity(declarations.len());
    for (field, root) in declarations {
        if transaction.profile == InstallationProfile::SystemService
            && matches!(field, "user_config" | "user_cache")
        {
            let lease = UserOwnedRootLease::open_existing(&root)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            if lease.current_user_sid() != current_sid.as_str() {
                return Err(SetupProductionError::Refused(
                    "a SystemService user root belongs to a different current-user principal",
                ));
            }
            let canonical = lease
                .canonical_path()
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            evidence_refs.push(handle(&canonical.to_string_lossy())?);
            snapshots.push(AclReadback::UserOwned {
                declared_root: root.to_string_lossy().into_owned(),
                canonical_root: canonical.to_string_lossy().into_owned(),
                file_identity: lease.identity(),
                principal_sid: lease.current_user_sid().to_owned(),
            });
            continue;
        }
        let spec = Spec {
            root: root.clone(),
            installation_root: PathBuf::from(runtime.installation_root.as_str()),
            profile_anchor: PathBuf::from(runtime.profile_anchor_root.as_str()),
            profile,
        };
        let snapshot = match WindowsInstallerRootPrimitive::new()
            .inspect(&spec)
            .map_err(|error| InstallationError::Platform(error.to_string()))?
        {
            Observation::Matching(snapshot) => snapshot,
            Observation::Absent(_) | Observation::Mismatch => {
                return Err(SetupProductionError::Refused(
                    "an original profile root is absent or its ACL/object identity differs",
                ));
            }
        };
        evidence_refs.push(handle(&format!("{field}:{}", snapshot.file_index))?);
        snapshots.push(AclReadback::Installer(snapshot));
    }
    let digest = digest_handle("eliot.setup.acls-installed.readback.v1", &snapshots)?;
    evidence_refs.push(digest);
    Ok((evidence_refs, snapshots))
}

fn ensure_privacy_choice(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &mut SetupBinding,
    current_sid: &PlatformHandle,
    privacy_choice: PrivacyChoice,
) -> Result<(), SetupProductionError> {
    let milestone = SetupMilestone::PrivacyModeSelected;
    let evidence_refs = vec![
        handle(privacy_choice.as_str())?,
        current_sid.clone(),
        transaction.transaction_id.clone(),
    ];
    let facts = (
        transaction.transaction_id.as_str(),
        transaction.installation_epoch.installation.as_str(),
        privacy_choice,
        current_sid.as_str(),
    );
    if binding.state().position() >= milestone.position() {
        if binding.privacy_choice() != Some(privacy_choice) {
            return Err(SetupProductionError::Refused(
                "requested privacy differs from the original PrivacyModeSelected result",
            ));
        }
        ensure_existing_observation(
            binding,
            milestone,
            &evidence_refs,
            "eliot.setup.privacy-mode-selected.readback.v1",
            &facts,
        )?;
        return ensure_existing_intent(
            store,
            &transaction.transaction_id,
            milestone,
            "eliot.setup.privacy-mode-selected.v1",
            &facts,
        );
    }
    if binding.state().next() != Some(milestone) {
        return Err(SetupProductionError::Refused(
            "the setup binding cannot advance to PrivacyModeSelected in order",
        ));
    }
    let observation = make_observation(
        milestone,
        evidence_refs,
        "eliot.setup.privacy-mode-selected.readback.v1",
        &facts,
    )?;
    let intent_digest = digest_handle("eliot.setup.privacy-mode-selected.intent.v1", &facts)?;
    store.record_setup_effect_intent(transaction_id(transaction), milestone, &intent_digest)?;
    let expected_revision = binding.revision();
    let mut next = binding.clone();
    next.advance(SetupAdvanceInput {
        milestone,
        observation,
        key_references: Vec::new(),
        privacy_choice: Some(privacy_choice),
    })?;
    save_and_readback(store, expected_revision, &next, binding)?;
    Ok(())
}

fn ensure_storage_verified(
    store: &mut RedbInstallationTransactionStore,
    transaction: &InstallationTransaction,
    binding: &mut SetupBinding,
) -> Result<(), SetupProductionError> {
    let (receipt, host_root_identity) = read_committed_activation_receipt(transaction)?;

    let fence = receipt.commit_fence();
    let root_identity_digest = digest_handle(
        "eliot.setup.storage-verified.host-root-identity.v1",
        &host_root_identity,
    )?;
    let evidence_refs = vec![
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.generation.clone(),
        receipt.candidate_manifest_digest.clone(),
        fence.ready_receipt_digest.clone(),
        fence.store_proof_fence.clone(),
        fence.store_requirement_digest.clone(),
        fence.candidate_binding_digest.clone(),
        handle(&fence.readiness_sequence.to_string())?,
        fence.readiness_journal_checksum.clone(),
        receipt.terminal_digest().clone(),
        root_identity_digest,
    ];
    let facts = (
        &receipt.transaction_id,
        &receipt.plan_digest,
        &receipt.generation,
        &receipt.candidate_manifest_digest,
        &receipt.commit_fence,
        receipt.registry_revision,
        receipt.terminal_digest(),
        host_root_identity,
    );
    let milestone = SetupMilestone::StorageVerified;
    let domain = "eliot.setup.storage-verified.original-host-commit.v1";
    if binding.state().position() >= milestone.position() {
        ensure_existing_observation(binding, milestone, &evidence_refs, domain, &facts)?;
        return ensure_existing_intent(
            store,
            &transaction.transaction_id,
            milestone,
            domain,
            &facts,
        );
    }
    if binding.state().next() != Some(milestone) {
        return Err(SetupProductionError::Refused(
            "the setup binding cannot advance to StorageVerified in order",
        ));
    }
    advance_with_intent(store, binding, milestone, evidence_refs, domain, &facts)
}

fn read_committed_activation_receipt(
    transaction: &InstallationTransaction,
) -> Result<
    (
        crate::ActivationCommitReceipt,
        eliot_platform_windows::FileIdentity,
    ),
    SetupProductionError,
> {
    use crate::{InstallationProfile, ProtectedRootLease, RedbInstallationRegistry};

    let host_state_root = Path::new(
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str(),
    );
    let (receipt, root_identity) = match transaction.profile {
        InstallationProfile::SystemService => {
            let root = ProtectedRootLease::open_existing(host_state_root)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            let identity = root.identity();
            let registry = RedbInstallationRegistry::open_existing_at(root)?.ok_or(
                SetupProductionError::Refused("the original SystemService Host registry is absent"),
            )?;
            let receipt = registry.read_committed_activation_receipt(
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
            )?;
            drop(registry);
            let reopened = ProtectedRootLease::open_existing(host_state_root)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            if reopened.identity() != identity {
                return Err(SetupProductionError::Refused(
                    "the original SystemService Host root native identity changed during readback",
                ));
            }
            (receipt, identity)
        }
        InstallationProfile::UserMode | InstallationProfile::PortableDev => {
            let root = UserOwnedRootLease::open_existing(host_state_root)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            let live_sid =
                eliot_platform_windows::WindowsSetupOwnerInitialSnapshotKeyProvider::new()
                    .current_principal_sid()
                    .map_err(|error| SetupProductionError::SigningKey(error.to_string()))?;
            if root.current_user_sid() != live_sid.as_str() {
                return Err(SetupProductionError::Refused(
                    "the current-user Host root does not belong to the authenticated setup principal",
                ));
            }
            let identity = root.identity();
            let registry =
                RedbInstallationRegistry::open_existing_user_owned_at(root, transaction.profile)?
                    .ok_or(SetupProductionError::Refused(
                    "the original current-user Host registry is absent",
                ))?;
            let receipt = registry.read_committed_activation_receipt(
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
            )?;
            drop(registry);
            let reopened = UserOwnedRootLease::open_existing(host_state_root)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            if reopened.identity() != identity || reopened.current_user_sid() != live_sid.as_str() {
                return Err(SetupProductionError::Refused(
                    "the current-user Host root native identity or principal changed during readback",
                ));
            }
            (receipt, identity)
        }
    };
    receipt.validate_against_transaction(transaction)?;
    let retained =
        transaction
            .active_verified_receipt
            .as_ref()
            .ok_or(SetupProductionError::Refused(
                "the original transaction has no retained ActiveVerified receipt binding",
            ))?;
    retained.validate_against_transaction(transaction)?;
    if !retained.matches_receipt(&receipt) {
        return Err(SetupProductionError::Refused(
            "the reopened Host registry receipt differs from the original ActiveVerified binding",
        ));
    }
    Ok((receipt, root_identity))
}

fn advance_with_intent<T: Serialize>(
    store: &mut RedbInstallationTransactionStore,
    binding: &mut SetupBinding,
    milestone: SetupMilestone,
    evidence_refs: Vec<PlatformHandle>,
    domain: &str,
    facts: &T,
) -> Result<(), SetupProductionError> {
    let intent_digest = digest_handle(&format!("{domain}.intent"), facts)?;
    store.record_setup_effect_intent(&binding.transaction_id, milestone, &intent_digest)?;
    advance_after_intent(
        store,
        binding,
        milestone,
        evidence_refs,
        domain,
        facts,
        Vec::new(),
    )
}

fn advance_after_recorded_intent<T: Serialize>(
    store: &mut RedbInstallationTransactionStore,
    binding: &mut SetupBinding,
    milestone: SetupMilestone,
    evidence_refs: Vec<PlatformHandle>,
    domain: &str,
    facts: &T,
    key_references: Vec<SetupKeyReference>,
) -> Result<(), SetupProductionError> {
    advance_after_intent(
        store,
        binding,
        milestone,
        evidence_refs,
        domain,
        facts,
        key_references,
    )
}

fn advance_after_intent<T: Serialize>(
    store: &mut RedbInstallationTransactionStore,
    binding: &mut SetupBinding,
    milestone: SetupMilestone,
    evidence_refs: Vec<PlatformHandle>,
    domain: &str,
    facts: &T,
    key_references: Vec<SetupKeyReference>,
) -> Result<(), SetupProductionError> {
    let expected_revision = binding.revision();
    let observation = make_observation(milestone, evidence_refs, domain, facts)?;
    let mut next = binding.clone();
    next.advance(SetupAdvanceInput {
        milestone,
        observation,
        key_references,
        privacy_choice: None,
    })?;
    save_and_readback(store, expected_revision, &next, binding)
}

fn save_and_readback(
    store: &mut RedbInstallationTransactionStore,
    expected_revision: u64,
    next: &SetupBinding,
    binding: &mut SetupBinding,
) -> Result<(), SetupProductionError> {
    store.compare_and_save_setup_binding(expected_revision, next)?;
    let retained =
        store
            .load_setup_binding(&next.transaction_id)?
            .ok_or(SetupProductionError::Refused(
                "the setup milestone result was not present on mandatory readback",
            ))?;
    if retained != *next {
        return Err(SetupProductionError::Refused(
            "the setup milestone result differs from its exact original result on readback",
        ));
    }
    *binding = retained;
    Ok(())
}

fn ensure_existing_observation<T: Serialize>(
    binding: &SetupBinding,
    milestone: SetupMilestone,
    evidence_refs: &[PlatformHandle],
    domain: &str,
    facts: &T,
) -> Result<(), SetupProductionError> {
    let expected = make_observation(milestone, evidence_refs.to_vec(), domain, facts)?;
    let observed = binding.observed_effects().get(milestone.position()).ok_or(
        SetupProductionError::Refused("the original setup observation is absent"),
    )?;
    if observed != &expected {
        return Err(SetupProductionError::Refused(
            "the current setup readback differs from the exact original milestone evidence",
        ));
    }
    Ok(())
}

fn ensure_existing_intent<T: Serialize>(
    store: &RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
    milestone: SetupMilestone,
    domain: &str,
    facts: &T,
) -> Result<(), SetupProductionError> {
    let expected = digest_handle(&format!("{domain}.intent"), facts)?;
    if store.load_setup_effect_intent(transaction_id, milestone)? == Some(expected) {
        return Ok(());
    }
    Err(SetupProductionError::Refused(
        "the retained setup milestone intent differs from its original effect facts",
    ))
}

fn make_observation<T: Serialize>(
    milestone: SetupMilestone,
    evidence_refs: Vec<PlatformHandle>,
    domain: &str,
    facts: &T,
) -> Result<SetupEffectObservation, SetupProductionError> {
    Ok(SetupEffectObservation {
        effect_id: handle(milestone.effect_identity())?,
        evidence_refs: evidence_refs.clone(),
        observed_digest: digest_handle(domain, &(milestone, evidence_refs, facts))?,
    })
}

fn digest_handle<T: Serialize>(
    domain: &str,
    facts: &T,
) -> Result<PlatformHandle, SetupProductionError> {
    let encoded = serde_json::to_vec(facts).map_err(|error| InstallationError::InvalidField {
        field: "setup.effect_digest".to_owned(),
        reason: error.to_string(),
    })?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + encoded.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&encoded);
    Ok(handle(&sha256_hex(&bytes))?)
}

fn handle(value: &str) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
        field: "setup.effect_evidence".to_owned(),
        reason: error.to_string(),
    })
}

fn transaction_id(transaction: &InstallationTransaction) -> &PlatformHandle {
    &transaction.transaction_id
}

fn milestone_effect_id() -> &'static str {
    SetupMilestone::ServiceKeysGenerated.effect_identity()
}

fn installer_root_profile(
    profile: InstallationProfile,
) -> eliot_platform_windows::InstallerRootProfile {
    match profile {
        InstallationProfile::SystemService => {
            eliot_platform_windows::InstallerRootProfile::SystemService
        }
        InstallationProfile::UserMode => eliot_platform_windows::InstallerRootProfile::UserMode,
        InstallationProfile::PortableDev => {
            eliot_platform_windows::InstallerRootProfile::PortableDev
        }
    }
}

fn selected_profile_key_root(
    transaction: &InstallationTransaction,
) -> Result<Option<PathBuf>, SetupProductionError> {
    let roots =
        transaction
            .profile_governed_roots
            .as_ref()
            .ok_or(SetupProductionError::Refused(
                "the transaction has no retained profile-root binding",
            ))?;
    match transaction.profile {
        InstallationProfile::SystemService => Ok(Some(
            Path::new(roots.runtime_state_roots.profile_anchor_root.as_str())
                .join("Eliot")
                .join(eliot_platform_windows::INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE),
        )),
        InstallationProfile::UserMode => Ok(None),
        InstallationProfile::PortableDev => Ok(Some(PathBuf::from(
            roots.runtime_state_roots.profile_anchor_root.as_str(),
        ))),
    }
}
