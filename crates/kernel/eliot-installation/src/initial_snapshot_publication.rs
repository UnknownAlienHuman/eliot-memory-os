//! System Owner publication through the original deterministic-setup owner.
//!
//! The accepted integration catalogue and exact managed-change approvals are
//! written as settings in the original signed genesis configuration snapshot.
//! This module does not create a second store or trust caller-provided owner,
//! key, installation, profile, root, or setup-revision text. It reopens the
//! current installation transaction and its durable setup binding, requires
//! the six original setup effects and intents through `StorageVerified`, then
//! selects the purpose-typed protected key reference already retained by that
//! binding. The current process SID and the protected key slot are re-read
//! before signing and again before the durable snapshot is admitted.
//!
//! The caller supplies only configuration facts that the existing initial
//! snapshot contract treats as user configuration/observation values
//! (`machine_id`, `scope_id`, and `state_fence`), the bounded first-run
//! decisions, and the exact catalogue/approval values to be accepted. These
//! values are not an authority epoch or a Kernel/Host fence observation. A
//! later consumer still obtains live authority and fence state from its owning
//! subsystem.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_config::Setting;
use eliot_config::first_run::FirstRunDecision;
use eliot_config::initial_snapshot::{
    InitialConfigSnapshotTrustAnchor, InitialSnapshotError, InitialSnapshotIdentity,
    InitialSnapshotSigner, InitialSnapshotVerificationContext, PrivacyChoice,
    SignedInitialConfigSnapshot, prepare_initial_snapshot_payload_with_settings,
};
use eliot_contracts::StateFence;
use eliot_platform::PlatformHandle;
use thiserror::Error;

use crate::{
    DISCOVERY_CATALOGUE_SCHEMA, DISCOVERY_CATALOGUE_SETTING_KEY, InstallationError,
    InstallationProfile, InstallationTransactionStore, IntegrationDiscoveryCatalogue,
    MANAGED_CHANGE_APPROVALS_SCHEMA, MANAGED_CHANGE_APPROVALS_SETTING_KEY,
    ManagedChangeApprovalSet, RedbInstallationTransactionStore, SetupAdmissionError, SetupBinding,
    SetupKeyReference, SetupMilestone, VerifiedSetupBinding, verify_setup_binding,
};
use std::path::{Path, PathBuf};

const LITERAL_VALUE_PREFIX: &str = "literal:";

/// User configuration accepted into the first signed snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialSnapshotOwnerConfiguration {
    /// Machine identity supplied as configuration, not as an authority proof.
    pub machine_id: String,
    /// Scope identity supplied as configuration, not as an authority proof.
    pub scope_id: String,
    /// Privacy choice requested by this setup invocation. It must equal the
    /// earlier durable `PrivacyModeSelected` milestone; this field cannot
    /// change that recorded owner decision.
    pub privacy_choice: PrivacyChoice,
    /// State-fence configuration copied into the signed snapshot. It is not a
    /// live Host/Kernel authority observation.
    pub state_fence: StateFence,
}

/// Successful original-owner publication and mandatory durable readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialSnapshotPublicationReceipt {
    /// The exact transaction-derived genesis snapshot identity.
    pub snapshot_id: PlatformHandle,
    /// Digest of the exact retained signed envelope.
    pub envelope_digest: PlatformHandle,
    /// Key identity read from the retained protected owner key slot.
    pub signer_key_id: PlatformHandle,
    /// Setup authority reverified from the durable binding and signed bytes.
    pub authority: VerifiedSetupBinding,
}

/// Refusal from the single original System Owner snapshot publisher.
#[derive(Debug, Error)]
pub enum InitialSnapshotPublicationError {
    /// Original installation transaction or setup-binding owner refused.
    #[error(transparent)]
    Installation(#[from] InstallationError),
    /// Original setup binding and signed snapshot failed admission.
    #[error(transparent)]
    SetupAdmission(#[from] SetupAdmissionError),
    /// The configuration owner rejected the payload, signer, or signature.
    #[error(transparent)]
    Snapshot(#[from] InitialSnapshotError),
    /// Protected owner-key identity, SID, or readback refused.
    #[error(transparent)]
    ProtectedKey(#[from] eliot_platform_windows::SetupOwnerInitialSnapshotKeyError),
    /// The transaction or setup record does not prove the required original
    /// owner state for first-snapshot publication.
    #[error("initial snapshot publication refused: {0}")]
    Refused(&'static str),
    /// The system clock could not provide a finite Unix-millisecond value.
    #[error("initial snapshot publication requires an available system clock")]
    ClockUnavailable,
}

/// Publishes one owner-accepted catalogue and approval set inside the exact
/// initial signed configuration snapshot for an existing installation.
///
/// The transaction id is only a lookup key: the store reloads and checks the
/// constructor-produced installation transaction, profile roots, owner, and
/// setup binding before any signing or persistence. The initial snapshot id is
/// derived from that same durable transaction id. A caller cannot select a
/// different installation, owner, key, profile, root digest, or setup
/// revision by changing CLI text.
///
/// A retry uses the same `InitialSnapshotCreated` effect identity and binds
/// its intent to the exact canonical unsigned payload digest. If an earlier
/// response was lost, the original retained snapshot is read, compared with
/// the requested payload, reverified against the protected key pin, and then
/// the same setup binding is completed. A changed payload, key, owner, or
/// protected file identity is a refusal; this API never signs a second
/// generation for the same transaction.
///
/// # Errors
/// Returns [`InitialSnapshotPublicationError`] when the original transaction,
/// setup facts, protected key, catalogue, approval set, signature, or durable
/// readback cannot be admitted exactly.
#[allow(
    clippy::too_many_lines,
    reason = "one owner transition binds the original setup facts, persisted intent, protected signature and mandatory readback"
)]
pub fn publish_system_owner_initial_snapshot(
    store: &mut RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
    configuration: &InitialSnapshotOwnerConfiguration,
    first_run: &FirstRunDecision,
    catalogue: &IntegrationDiscoveryCatalogue,
    approvals: &ManagedChangeApprovalSet,
) -> Result<InitialSnapshotPublicationReceipt, InitialSnapshotPublicationError> {
    let transaction =
        store
            .load(transaction_id)?
            .ok_or(InitialSnapshotPublicationError::Refused(
                "the current installation transaction is absent from the selected store",
            ))?;
    let binding = store.load_setup_binding(transaction_id)?.ok_or(
        InitialSnapshotPublicationError::Refused(
            "the original deterministic-setup binding is absent",
        ),
    )?;
    validate_transaction_binding(&transaction, &binding, transaction_id)?;
    crate::setup_production::validate_original_setup_key_readback(store, &binding).map_err(
        |_| {
            InitialSnapshotPublicationError::Refused(
                "the original setup-key reference differs from its durable ServiceKeysGenerated receipt",
            )
        },
    )?;
    validate_prior_setup_facts(store, &binding)?;

    let expected_snapshot_revision = match binding.state() {
        SetupMilestone::StorageVerified if binding.revision() == 6 => 7,
        SetupMilestone::InitialSnapshotCreated if binding.revision() == 7 => 7,
        _ => {
            return Err(InitialSnapshotPublicationError::Refused(
                "setup must be at StorageVerified or reconciling its original InitialSnapshotCreated result",
            ));
        }
    };
    let platform = current_platform_handle()?;
    let now_ms = current_unix_time_ms()?;
    validate_catalogue_and_approvals(
        catalogue,
        approvals,
        &binding,
        transaction_id,
        expected_snapshot_revision,
        &platform,
        now_ms,
    )?;

    let setup_key_reference = select_setup_owner_key_reference(&binding)?;
    let profile = installer_root_profile(transaction.profile);
    let selected_key_root = setup_key_root(&transaction)?;
    let typed_reference =
        eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_setup_target_ref(
            &setup_key_reference.target_ref,
        )?
        .ok_or(InitialSnapshotPublicationError::Refused(
            "the setup signing reference does not carry the initial-snapshot purpose",
        ))?;
    if !typed_reference.belongs_to_profile(profile) {
        return Err(InitialSnapshotPublicationError::Refused(
            "the setup signing reference belongs to a different installation profile",
        ));
    }
    let provider = eliot_platform_windows::WindowsSetupOwnerInitialSnapshotKeyProvider::new();
    let signer = provider.open(
        &setup_key_reference.target_ref,
        &setup_key_reference.key_id,
        &setup_key_reference.principal_sid,
        transaction_id.as_str(),
        binding.installation_id.as_str(),
        binding.confirmed_owner.as_str(),
        profile,
        selected_key_root.as_deref(),
    )?;
    if signer.signer_id() != binding.confirmed_owner.as_str()
        || setup_key_reference.key_id.as_str() != signer.key_id()
    {
        return Err(InitialSnapshotPublicationError::Refused(
            "protected setup key identity is not the confirmed System Owner key",
        ));
    }
    let anchor = InitialConfigSnapshotTrustAnchor::new(
        binding.installation_id.as_str(),
        binding.confirmed_owner.as_str(),
        signer.key_id(),
        signer.public_key().to_vec(),
    )?;

    let identity = InitialSnapshotIdentity {
        snapshot_id: transaction_id.as_str().to_owned(),
        installation_id: binding.installation_id.as_str().to_owned(),
        profile_ref: crate::setup_binding::profile_ref(binding.profile)?,
        owner_ref: binding.confirmed_owner.as_str().to_owned(),
        // The original setup verifier's key-identity context is the confirmed
        // owner, while the detached-signature key id remains the exact
        // protected SetupKeyReference key_id.
        key_identity: binding.confirmed_owner.as_str().to_owned(),
        machine_id: configuration.machine_id.clone(),
        scope_id: configuration.scope_id.clone(),
        runtime_state_roots_digest: binding.runtime_state_roots_digest.as_str().to_owned(),
        setup_revision: expected_snapshot_revision,
        state_fence: configuration.state_fence.clone(),
    };
    let privacy = binding
        .privacy_choice()
        .ok_or(InitialSnapshotPublicationError::Refused(
            "the original PrivacyModeSelected result is absent",
        ))?;
    if privacy != configuration.privacy_choice {
        return Err(InitialSnapshotPublicationError::Refused(
            "requested privacy differs from the original PrivacyModeSelected milestone",
        ));
    }
    let settings = owner_settings(catalogue, approvals, binding.confirmed_owner.as_str())?;
    let payload =
        prepare_initial_snapshot_payload_with_settings(&identity, privacy, first_run, &settings)?;

    // Persist the exact content intent before invoking the protected signer or
    // writing the immutable signed envelope. This digest is the original
    // SetupBinding effect intent, not a second publication identity.
    let intent_digest = PlatformHandle::new(payload.digest()?).map_err(|error| {
        InstallationError::InvalidField {
            field: "initial_snapshot.intent_digest".to_owned(),
            reason: error.to_string(),
        }
    })?;
    store.record_setup_effect_intent(
        transaction_id,
        SetupMilestone::InitialSnapshotCreated,
        &intent_digest,
    )?;

    let existing_snapshot = store.load_initial_snapshot(transaction_id)?;
    let expected_snapshot = if let Some(snapshot) = existing_snapshot {
        if snapshot.payload != payload {
            return Err(InitialSnapshotPublicationError::Refused(
                "the original snapshot intent already has different retained payload bytes",
            ));
        }
        require_snapshot_matches_protected_key(&snapshot, &anchor, &identity)?;
        snapshot
    } else {
        if binding.state() == SetupMilestone::InitialSnapshotCreated {
            return Err(InitialSnapshotPublicationError::Refused(
                "the completed setup binding has no retained initial snapshot",
            ));
        }
        let snapshot = SignedInitialConfigSnapshot::sign(
            &payload,
            &ProtectedSnapshotSigner { signer: &signer },
        )?;
        require_snapshot_matches_protected_key(&snapshot, &anchor, &identity)?;
        store.create_initial_snapshot(transaction_id, &snapshot)?;
        snapshot
    };

    let retained_snapshot = store.load_initial_snapshot(transaction_id)?.ok_or(
        InitialSnapshotPublicationError::Refused(
            "the original signed snapshot was not present on mandatory readback",
        ),
    )?;
    if retained_snapshot != expected_snapshot {
        return Err(InitialSnapshotPublicationError::Refused(
            "the retained signed snapshot differs from the original effect result",
        ));
    }
    let retained_signer = provider.open(
        &setup_key_reference.target_ref,
        &setup_key_reference.key_id,
        &setup_key_reference.principal_sid,
        transaction_id.as_str(),
        binding.installation_id.as_str(),
        binding.confirmed_owner.as_str(),
        profile,
        selected_key_root.as_deref(),
    )?;
    let retained_anchor = InitialConfigSnapshotTrustAnchor::new(
        binding.installation_id.as_str(),
        binding.confirmed_owner.as_str(),
        retained_signer.key_id(),
        retained_signer.public_key().to_vec(),
    )?;
    if retained_anchor != anchor {
        return Err(InitialSnapshotPublicationError::Refused(
            "protected owner key readback changed after signing",
        ));
    }
    let verification_context = verification_context(&binding, expected_snapshot_revision)?;
    retained_anchor.verify(&retained_snapshot, &verification_context)?;

    if binding.state() == SetupMilestone::StorageVerified {
        let envelope_digest =
            PlatformHandle::new(retained_snapshot.envelope_digest()?).map_err(|error| {
                InstallationError::InvalidField {
                    field: "initial_snapshot.envelope_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        let expected_revision = binding.revision();
        let mut completed = binding;
        completed.advance(crate::SetupAdvanceInput {
            milestone: SetupMilestone::InitialSnapshotCreated,
            observation: crate::SetupEffectObservation {
                effect_id: PlatformHandle::new(
                    SetupMilestone::InitialSnapshotCreated.effect_identity(),
                )
                .map_err(|error| InstallationError::InvalidField {
                    field: "initial_snapshot.effect_id".to_owned(),
                    reason: error.to_string(),
                })?,
                evidence_refs: vec![
                    envelope_digest,
                    setup_key_reference.key_id.clone(),
                    setup_key_reference.target_ref.clone(),
                    setup_key_reference.principal_sid.clone(),
                ],
                observed_digest: PlatformHandle::new(retained_snapshot.envelope_digest()?)
                    .map_err(|error| InstallationError::InvalidField {
                        field: "initial_snapshot.observed_digest".to_owned(),
                        reason: error.to_string(),
                    })?,
            },
            key_references: Vec::new(),
            privacy_choice: None,
        })?;
        store.compare_and_save_setup_binding(expected_revision, &completed)?;
    }

    let retained_binding = store.load_setup_binding(transaction_id)?.ok_or(
        InitialSnapshotPublicationError::Refused(
            "the final setup binding was not present on mandatory readback",
        ),
    )?;
    let final_snapshot = store.load_initial_snapshot(transaction_id)?.ok_or(
        InitialSnapshotPublicationError::Refused(
            "the final signed snapshot was not present on mandatory readback",
        ),
    )?;
    let authority = verify_setup_binding(&retained_binding, &final_snapshot, &retained_anchor)?;
    let envelope_digest =
        PlatformHandle::new(final_snapshot.envelope_digest()?).map_err(|error| {
            InstallationError::InvalidField {
                field: "initial_snapshot.envelope_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
    let signer_key_id = PlatformHandle::new(retained_signer.key_id()).map_err(|error| {
        InstallationError::InvalidField {
            field: "initial_snapshot.signer_key_id".to_owned(),
            reason: error.to_string(),
        }
    })?;
    Ok(InitialSnapshotPublicationReceipt {
        snapshot_id: PlatformHandle::new(transaction_id.as_str()).map_err(|error| {
            InstallationError::InvalidField {
                field: "initial_snapshot.snapshot_id".to_owned(),
                reason: error.to_string(),
            }
        })?,
        envelope_digest,
        signer_key_id,
        authority,
    })
}

/// Reopens the original transaction, signed snapshot and profile-owned setup
/// key, then derives the trust anchor independently from current key readback.
/// This is the ordinary managed-change caller's authority entrypoint: it
/// accepts no caller-supplied owner, key, profile, root, or trust anchor.
pub fn load_system_owner_initial_snapshot_authority(
    store: &RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
) -> Result<(InitialConfigSnapshotTrustAnchor, VerifiedSetupBinding), InitialSnapshotPublicationError>
{
    let transaction =
        store
            .load(transaction_id)?
            .ok_or(InitialSnapshotPublicationError::Refused(
                "the selected installation transaction is absent",
            ))?;
    let binding = store.load_setup_binding(transaction_id)?.ok_or(
        InitialSnapshotPublicationError::Refused(
            "the original deterministic-setup binding is absent",
        ),
    )?;
    validate_transaction_binding(&transaction, &binding, transaction_id)?;
    binding.require_complete()?;
    crate::setup_production::validate_original_setup_key_readback(store, &binding).map_err(
        |_| {
            InitialSnapshotPublicationError::Refused(
                "the original setup-key reference differs from its durable ServiceKeysGenerated receipt",
            )
        },
    )?;
    validate_prior_setup_facts(store, &binding)?;
    let snapshot = store.load_initial_snapshot(transaction_id)?.ok_or(
        InitialSnapshotPublicationError::Refused("the original signed initial snapshot is absent"),
    )?;
    let setup_key_reference = select_setup_owner_key_reference(&binding)?;
    let profile = installer_root_profile(transaction.profile);
    let selected_key_root = setup_key_root(&transaction)?;
    let typed_reference =
        eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_setup_target_ref(
            &setup_key_reference.target_ref,
        )?
        .ok_or(InitialSnapshotPublicationError::Refused(
            "the setup signing reference does not carry the initial-snapshot purpose",
        ))?;
    if !typed_reference.belongs_to_profile(profile) {
        return Err(InitialSnapshotPublicationError::Refused(
            "the setup signing reference belongs to a different installation profile",
        ));
    }
    let signer = eliot_platform_windows::WindowsSetupOwnerInitialSnapshotKeyProvider::new().open(
        &setup_key_reference.target_ref,
        &setup_key_reference.key_id,
        &setup_key_reference.principal_sid,
        transaction_id.as_str(),
        binding.installation_id.as_str(),
        binding.confirmed_owner.as_str(),
        profile,
        selected_key_root.as_deref(),
    )?;
    if signer.signer_id() != binding.confirmed_owner.as_str()
        || signer.key_id() != setup_key_reference.key_id.as_str()
    {
        return Err(InitialSnapshotPublicationError::Refused(
            "the current protected key is not the exact setup owner key",
        ));
    }
    let anchor = InitialConfigSnapshotTrustAnchor::new(
        binding.installation_id.as_str(),
        binding.confirmed_owner.as_str(),
        signer.key_id(),
        signer.public_key().to_vec(),
    )?;
    let authority = verify_setup_binding(&binding, &snapshot, &anchor)?;
    Ok((anchor, authority))
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

fn setup_key_root(
    transaction: &crate::InstallationTransaction,
) -> Result<Option<PathBuf>, InitialSnapshotPublicationError> {
    let roots = transaction.profile_governed_roots.as_ref().ok_or(
        InitialSnapshotPublicationError::Refused(
            "the current transaction has no retained profile-root binding",
        ),
    )?;
    let root = match transaction.profile {
        InstallationProfile::SystemService => {
            Path::new(roots.runtime_state_roots.profile_anchor_root.as_str())
                .join("Eliot")
                .join(eliot_platform_windows::INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE)
        }
        InstallationProfile::UserMode => return Ok(None),
        InstallationProfile::PortableDev => {
            PathBuf::from(roots.runtime_state_roots.profile_anchor_root.as_str())
        }
    };
    Ok(Some(root))
}

fn validate_transaction_binding(
    transaction: &crate::InstallationTransaction,
    binding: &SetupBinding,
    transaction_id: &PlatformHandle,
) -> Result<(), InitialSnapshotPublicationError> {
    if transaction.transaction_id != *transaction_id
        || binding.transaction_id != *transaction_id
        || transaction.installation_epoch.installation != binding.installation_id
        || transaction.profile != binding.profile
        || transaction.request.required_owner != binding.confirmed_owner
    {
        return Err(InitialSnapshotPublicationError::Refused(
            "the durable setup binding does not belong to the exact current installation transaction",
        ));
    }
    transaction.rehydrate_profile_binding()?;
    let roots = transaction.profile_governed_roots.as_ref().ok_or(
        InitialSnapshotPublicationError::Refused(
            "the current transaction has no retained profile-root binding",
        ),
    )?;
    if roots.runtime_state_roots.roots_digest != binding.runtime_state_roots_digest {
        return Err(InitialSnapshotPublicationError::Refused(
            "the setup root digest differs from the current transaction's retained roots",
        ));
    }
    Ok(())
}

fn validate_prior_setup_facts(
    store: &RedbInstallationTransactionStore,
    binding: &SetupBinding,
) -> Result<(), InitialSnapshotPublicationError> {
    let milestones = SetupMilestone::all();
    if binding.observed_effects().len() < 6 {
        return Err(InitialSnapshotPublicationError::Refused(
            "the six original setup observations through StorageVerified are incomplete",
        ));
    }
    for (index, milestone) in milestones.into_iter().take(6).enumerate() {
        let Some(observation) = binding.observed_effects().get(index) else {
            return Err(InitialSnapshotPublicationError::Refused(
                "the original ordered setup observation is absent",
            ));
        };
        if observation.effect_id.as_str() != milestone.effect_identity()
            || store
                .load_setup_effect_intent(&binding.transaction_id, milestone)?
                .is_none()
        {
            return Err(InitialSnapshotPublicationError::Refused(
                "an original setup effect lacks its exact ordered observation or durable intent",
            ));
        }
    }
    Ok(())
}

fn validate_catalogue_and_approvals(
    catalogue: &IntegrationDiscoveryCatalogue,
    approvals: &ManagedChangeApprovalSet,
    binding: &SetupBinding,
    transaction_id: &PlatformHandle,
    setup_revision: u64,
    platform: &PlatformHandle,
    now_ms: u64,
) -> Result<(), InitialSnapshotPublicationError> {
    catalogue.validate()?;
    catalogue.require_seed_family_coverage()?;
    approvals.validate()?;
    if catalogue.schema.as_str() != DISCOVERY_CATALOGUE_SCHEMA
        || approvals.schema.as_str() != MANAGED_CHANGE_APPROVALS_SCHEMA
        || catalogue.accepted_by != binding.confirmed_owner
        || !catalogue
            .supported_platforms
            .iter()
            .any(|supported| supported == platform)
        || catalogue
            .expires_at_ms
            .is_some_and(|expiry| now_ms >= expiry)
    {
        return Err(InitialSnapshotPublicationError::Refused(
            "catalogue schema, owner acceptance, platform, or expiry is not current",
        ));
    }
    for approval in &approvals.approvals {
        if approval.approved_by != binding.confirmed_owner
            || approval.request.required_owner != binding.confirmed_owner
            || approval.catalogue_origin != catalogue.origin
            || approval.catalogue_revision != catalogue.revision
            || approval.snapshot_id.as_str() != transaction_id.as_str()
            || approval.profile != binding.profile
            || approval.runtime_state_roots_digest != binding.runtime_state_roots_digest
            || approval.setup_revision != setup_revision
            || now_ms >= approval.expires_at_ms
        {
            return Err(InitialSnapshotPublicationError::Refused(
                "a managed-change approval is foreign, stale, or bound to another publication",
            ));
        }
    }
    Ok(())
}

fn select_setup_owner_key_reference(
    binding: &SetupBinding,
) -> Result<SetupKeyReference, InitialSnapshotPublicationError> {
    let mut matches = Vec::new();
    for reference in binding.key_references() {
        if eliot_platform_windows::SetupOwnerInitialSnapshotKeyReference::from_setup_target_ref(
            &reference.target_ref,
        )?
        .is_some()
        {
            matches.push(reference.clone());
        }
    }
    if matches.len() != 1 {
        return Err(InitialSnapshotPublicationError::Refused(
            "setup must retain exactly one purpose-typed owner snapshot key reference",
        ));
    }
    Ok(matches.remove(0))
}

fn owner_settings(
    catalogue: &IntegrationDiscoveryCatalogue,
    approvals: &ManagedChangeApprovalSet,
    owner_ref: &str,
) -> Result<Vec<Setting>, InitialSnapshotPublicationError> {
    let catalogue_json = serde_json::to_string(catalogue)
        .map_err(|_| InitialSnapshotPublicationError::Refused("catalogue serialization failed"))?;
    let approvals_json = serde_json::to_string(approvals)
        .map_err(|_| InitialSnapshotPublicationError::Refused("approval serialization failed"))?;
    Ok(vec![
        Setting {
            key: DISCOVERY_CATALOGUE_SETTING_KEY.to_owned(),
            value_ref: format!("{LITERAL_VALUE_PREFIX}{catalogue_json}"),
            owner_ref: owner_ref.to_owned(),
        },
        Setting {
            key: MANAGED_CHANGE_APPROVALS_SETTING_KEY.to_owned(),
            value_ref: format!("{LITERAL_VALUE_PREFIX}{approvals_json}"),
            owner_ref: owner_ref.to_owned(),
        },
    ])
}

fn require_snapshot_matches_protected_key(
    snapshot: &SignedInitialConfigSnapshot,
    anchor: &InitialConfigSnapshotTrustAnchor,
    identity: &InitialSnapshotIdentity,
) -> Result<(), InitialSnapshotPublicationError> {
    if snapshot.signer_id != identity.owner_ref
        || snapshot.key_id != anchor.key_id
        || snapshot.public_key_fingerprint != anchor.public_key_fingerprint
    {
        return Err(InitialSnapshotPublicationError::Refused(
            "signed envelope identity differs from the exact protected System Owner key",
        ));
    }
    let context = InitialSnapshotVerificationContext {
        installation_id: identity.installation_id.clone(),
        profile_ref: identity.profile_ref.clone(),
        runtime_state_roots_digest: identity.runtime_state_roots_digest.clone(),
        key_identity: identity.key_identity.clone(),
        setup_revision: identity.setup_revision,
    };
    anchor.verify(snapshot, &context)?;
    Ok(())
}

fn verification_context(
    binding: &SetupBinding,
    setup_revision: u64,
) -> Result<InitialSnapshotVerificationContext, InitialSnapshotPublicationError> {
    Ok(InitialSnapshotVerificationContext {
        installation_id: binding.installation_id.as_str().to_owned(),
        profile_ref: crate::setup_binding::profile_ref(binding.profile)?,
        runtime_state_roots_digest: binding.runtime_state_roots_digest.as_str().to_owned(),
        key_identity: binding.confirmed_owner.as_str().to_owned(),
        setup_revision,
    })
}

fn current_platform_handle() -> Result<PlatformHandle, InitialSnapshotPublicationError> {
    PlatformHandle::new(format!(
        "{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
    .map_err(|_| InitialSnapshotPublicationError::Refused("current platform identity is invalid"))
}

fn current_unix_time_ms() -> Result<u64, InitialSnapshotPublicationError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InitialSnapshotPublicationError::ClockUnavailable)?;
    u64::try_from(duration.as_millis())
        .map_err(|_| InitialSnapshotPublicationError::ClockUnavailable)
}

struct ProtectedSnapshotSigner<'a> {
    signer: &'a eliot_platform_windows::ProtectedSetupOwnerInitialSnapshotSigner,
}

impl InitialSnapshotSigner for ProtectedSnapshotSigner<'_> {
    fn signer_id(&self) -> &str {
        self.signer.signer_id()
    }

    fn key_id(&self) -> &str {
        self.signer.key_id()
    }

    fn public_key_fingerprint(&self) -> &str {
        self.signer.public_key_fingerprint()
    }

    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, InitialSnapshotError> {
        self.signer
            .sign(canonical_bytes)
            .map_err(|error| InitialSnapshotError::InvalidField {
                field: "protected_setup_signer".to_owned(),
                reason: error.to_string(),
            })
    }
}
