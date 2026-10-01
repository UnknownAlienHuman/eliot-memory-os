//! Protected signing and durable publication for the first Config snapshot.
//!
//! This composes the existing protected installation key, detached Config
//! signature, and installation setup journal. It adds neither a key format
//! nor a signature scheme.

use eliot_config::initial_snapshot::{
    InitialConfigSnapshotTrustAnchor, InitialSnapshotPayload, InitialSnapshotSigner,
    InitialSnapshotVerificationContext, SignedInitialConfigSnapshot,
    VerifiedInitialConfigSnapshot,
};
use eliot_platform_windows::{
    HostOwnerEpochCapability, INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE,
    INSTALLATION_AUTHORITY_SIGNER_ID, InstallationAuthorityKeyMetadata,
    InstallationAuthorityKeySigner, WindowsInstallationAuthorityKeyStore,
    protected_program_data_root,
};
use eliot_runtime_contracts::InstallationActivationApprovalSigner;

use crate::{
    InstallationError, PlatformHandle, RedbInstallationTransactionStore, SetupAdvanceInput,
    SetupBinding, SetupEffectObservation, SetupMilestone,
};

/// The original public expectation and independent verification anchor for
/// the installation's initial-Config signing key. This record is immutable
/// and is retained in the same setup journal before initial snapshot signing.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitialSnapshotKeyRecord {
    /// Setup transaction that owns the key slot.
    pub transaction_id: PlatformHandle,
    /// Setup revision at which the key was created and observed.
    pub setup_revision: u64,
    /// Original opaque protected-key metadata returned by key creation.
    pub key_metadata: InstallationAuthorityKeyMetadata,
    /// Installation-pinned verifier anchor derived from that same signer.
    pub trust_anchor: InitialConfigSnapshotTrustAnchor,
}

impl InitialSnapshotKeyRecord {
    /// Captures the real metadata and anchor from one protected signer.
    pub fn from_signer(
        transaction_id: PlatformHandle,
        setup_revision: u64,
        signer: &InstallationAuthorityKeySigner,
        trust_anchor: InitialConfigSnapshotTrustAnchor,
    ) -> Result<Self, InstallationError> {
        let record = Self {
            transaction_id,
            setup_revision,
            key_metadata: signer.metadata().clone(),
            trust_anchor,
        };
        record.validate()?;
        Ok(record)
    }

    /// Checks that all persisted public identity fields came from one key.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(self.transaction_id.as_str(), "initial_snapshot_key.transaction_id")?;
        if self.setup_revision == 0 {
            return Err(invalid_setup("key record setup revision must be non-zero"));
        }
        let expected = self
            .key_metadata
            .expectation()
            .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
        self.trust_anchor
            .validate()
            .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
        if expected.key_id != self.trust_anchor.key_id
            || self.key_metadata.public_key != self.trust_anchor.public_key
            || self.key_metadata.public_key_fingerprint != self.trust_anchor.public_key_fingerprint
            || self.trust_anchor.signer_id != INSTALLATION_AUTHORITY_SIGNER_ID
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Adapts the retained protected key to Config's existing signer interface.
pub struct ProtectedInitialSnapshotSigner<'a> {
    protected: &'a InstallationAuthorityKeySigner,
}

impl<'a> ProtectedInitialSnapshotSigner<'a> {
    /// Uses an already-opened exact installation authority key slot.
    #[must_use]
    pub const fn new(protected: &'a InstallationAuthorityKeySigner) -> Self {
        Self { protected }
    }
}

impl InitialSnapshotSigner for ProtectedInitialSnapshotSigner<'_> {
    fn signer_id(&self) -> &str {
        INSTALLATION_AUTHORITY_SIGNER_ID
    }

    fn key_id(&self) -> &str {
        self.protected.key_id()
    }

    fn algorithm(&self) -> &str {
        eliot_config::initial_snapshot::INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM
    }

    fn public_key_fingerprint(&self) -> &str {
        self.protected.public_key_fingerprint()
    }

    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, eliot_config::initial_snapshot::InitialSnapshotError> {
        InstallationActivationApprovalSigner::sign(self.protected, canonical_bytes).map_err(
            |error| {
                eliot_config::initial_snapshot::InitialSnapshotError::SigningFailure(
                    error.to_string(),
                )
            },
        )
    }
}

/// Signs, journals, re-reads and verifies one first Config snapshot, then
/// advances the existing setup binding by its final milestone.
///
/// The exact canonical payload digest is durably recorded as the effect intent
/// before signing/publication. On restart this reuses the same intent and
/// signed snapshot. Verification uses an independently supplied installation
/// trust anchor and setup context rather than trusting key metadata embedded
/// in the snapshot.
pub fn publish_verified_initial_config_snapshot(
    store: &mut RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
    payload: &InitialSnapshotPayload,
    signer: &InstallationAuthorityKeySigner,
    trust_anchor: &InitialConfigSnapshotTrustAnchor,
    verification_context: &InitialSnapshotVerificationContext,
) -> Result<VerifiedInitialConfigSnapshot, InstallationError> {
    let setup = store
        .load_setup_binding(transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: transaction_id.as_str().to_owned(),
        })?;
    if setup.transaction_id != *transaction_id
        || setup.installation_id.as_str() != payload.installation_id
        || setup.confirmed_owner().as_str() != payload.owner_ref
        || setup.runtime_state_roots_digest().as_str() != payload.runtime_state_roots_digest
    {
        return Err(InstallationError::IdentityConflict);
    }
    let key_record = store
        .load_initial_snapshot_key(transaction_id)?
        .ok_or_else(|| InstallationError::IncompleteObservation(
            "initial Config signing key expectation is missing; recovery: reconcile the original ServiceKeysGenerated operation instead of creating or adopting a key".to_owned(),
        ))?;
    if key_record.key_metadata != *signer.metadata()
        || key_record.trust_anchor != *trust_anchor
        || key_record.setup_revision >= setup.revision()
    {
        return Err(InstallationError::IdentityConflict);
    }

    let payload_digest = payload
        .digest()
        .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
    let intent = handle(payload_digest, "initial_snapshot.intent_digest")?;
    store.record_setup_effect_intent(
        transaction_id,
        SetupMilestone::InitialSnapshotCreated,
        &intent,
    )?;

    let config_signer = ProtectedInitialSnapshotSigner::new(signer);
    let signed = SignedInitialConfigSnapshot::sign(payload, &config_signer)
        .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
    store.create_initial_snapshot(transaction_id, &signed)?;

    let persisted = store
        .load_initial_snapshot(transaction_id)?
        .ok_or_else(|| InstallationError::IncompleteObservation(
            "signed initial snapshot was not present after publication; recovery: reconcile the original setup intent and exact transaction row".to_owned(),
        ))?;
    if persisted != signed {
        return Err(InstallationError::IdentityConflict);
    }
    let verified = trust_anchor
        .verify(&persisted, verification_context)
        .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
    let envelope_digest = persisted
        .envelope_digest()
        .map_err(|error| invalid_initial_snapshot(error.to_string()))?;

    if setup.state() == SetupMilestone::InitialSnapshotCreated {
        if setup.configuration_snapshot_ref().map(PlatformHandle::as_str)
            != Some(envelope_digest.as_str())
        {
            return Err(InstallationError::IdentityConflict);
        }
        return Ok(verified);
    }
    if setup.state().next() != Some(SetupMilestone::InitialSnapshotCreated) {
        return Err(InstallationError::IncompleteObservation(
            "initial snapshot publication requires the immediately preceding setup milestone; recovery: complete setup milestones in order before publishing the snapshot".to_owned(),
        ));
    }

    let observation = SetupEffectObservation {
        effect_id: handle(
            SetupMilestone::InitialSnapshotCreated.effect_identity(),
            "initial_snapshot.effect_id",
        )?,
        evidence_refs: vec![transaction_id.clone(), intent],
        observed_digest: handle(&envelope_digest, "initial_snapshot.envelope_digest")?,
    };
    let mut advanced = setup;
    advanced.advance(SetupAdvanceInput {
        milestone: SetupMilestone::InitialSnapshotCreated,
        observation,
        key_references: Vec::new(),
        privacy_choice: None,
    })?;
    let expected_revision = advanced
        .revision()
        .checked_sub(1)
        .ok_or_else(|| invalid_setup("setup binding revision underflow"))?;
    store.compare_and_save_setup_binding(expected_revision, &advanced)?;
    Ok(verified)
}

/// Loads the retained signed envelope and returns it alongside the exact
/// verification result. Policy owners retain the signed envelope; consumers
/// verify it with their independently pinned anchor instead of trusting a
/// decoded approval string by itself.
pub fn load_verified_initial_config_snapshot(
    store: &RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
    trust_anchor: &InitialConfigSnapshotTrustAnchor,
    verification_context: &InitialSnapshotVerificationContext,
) -> Result<(SignedInitialConfigSnapshot, VerifiedInitialConfigSnapshot), InstallationError> {
    let signed = store
        .load_initial_snapshot(transaction_id)?
        .ok_or_else(|| InstallationError::IncompleteObservation(
            "signed initial snapshot is absent; recovery: resume the original setup transaction and reconcile its publication intent".to_owned(),
        ))?;
    let verified = trust_anchor
        .verify(&signed, verification_context)
        .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
    Ok((signed, verified))
}

/// Reopens the exact key slot retained during initial setup. A missing record
/// is an unknown original outcome and never falls back to key creation.
pub fn open_retained_initial_snapshot_signer(
    store: &RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
    key_store: &eliot_platform_windows::WindowsInstallationAuthorityKeyStore,
) -> Result<InstallationAuthorityKeySigner, InstallationError> {
    let record = store
        .load_initial_snapshot_key(transaction_id)?
        .ok_or_else(|| InstallationError::IncompleteObservation(
            "protected signer expectation is absent; recovery: reconcile the original key-creation transaction without regenerating or adopting a slot".to_owned(),
        ))?;
    key_store
        .open_existing(
            &record
                .key_metadata
                .expectation()
                .map_err(|error| invalid_initial_snapshot(error.to_string()))?,
        )
        .map_err(|error| invalid_initial_snapshot(error.to_string()))
}

/// Creates the installation's initial-Config signer during the existing
/// `ServiceKeysGenerated` setup effect, retaining its exact public metadata
/// before the setup milestone may advance. Recovery reopens only the exact
/// retained expectation; an intent without a metadata receipt is Unknown and
/// never triggers key regeneration or adoption.
pub fn create_or_reopen_initial_snapshot_signer(
    store: &mut RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
    host: &HostOwnerEpochCapability,
) -> Result<(InstallationAuthorityKeySigner, InitialConfigSnapshotTrustAnchor), InstallationError>
{
    let setup = store
        .load_setup_binding(transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: transaction_id.as_str().to_owned(),
        })?;
    if setup.transaction_id != *transaction_id
        || !host.is_for_installation(&setup.installation_id)
        || !matches!(
            setup.state(),
            SetupMilestone::SystemOwnerEstablished | SetupMilestone::ServiceKeysGenerated
        )
    {
        return Err(InstallationError::IdentityConflict);
    }
    let _owner_guard = host
        .live_guard()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;

    let program_data = protected_program_data_root()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let key_store = WindowsInstallationAuthorityKeyStore::new(
        program_data.join(INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE),
    )
    .map_err(|error| invalid_initial_snapshot(error.to_string()))?;

    if let Some(record) = store.load_initial_snapshot_key(transaction_id)? {
        let exact_creation_revision = record.setup_revision == setup.revision()
            && setup.state() == SetupMilestone::SystemOwnerEstablished;
        let completed_milestone_revision = record.setup_revision.checked_add(1)
            == Some(setup.revision())
            && setup.state() == SetupMilestone::ServiceKeysGenerated;
        if !exact_creation_revision && !completed_milestone_revision {
            return Err(InstallationError::IdentityConflict);
        }
        let signer = key_store
            .open_existing(
                &record
                    .key_metadata
                    .expectation()
                    .map_err(|error| invalid_initial_snapshot(error.to_string()))?,
            )
            .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
        return Ok((signer, record.trust_anchor));
    }

    if setup.state() != SetupMilestone::SystemOwnerEstablished {
        return Err(InstallationError::IncompleteObservation(
            "service-key milestone is complete but its protected signer expectation is absent; recovery: reconcile the original key-creation result without creating a replacement".to_owned(),
        ));
    }
    if store
        .load_setup_effect_intent(transaction_id, SetupMilestone::ServiceKeysGenerated)?
        .is_some()
    {
        return Err(InstallationError::IncompleteObservation(
            "service-key setup intent exists without its protected key expectation; recovery: reconcile the original key creation as Unknown; do not regenerate or adopt a slot".to_owned(),
        ));
    }

    #[derive(serde::Serialize)]
    struct KeyCreationIntent<'a> {
        transaction_id: &'a str,
        installation_id: &'a str,
        setup_revision: u64,
        milestone: SetupMilestone,
        effect: &'static str,
    }
    let intent_bytes = eliot_contracts::canonical_json_bytes(&KeyCreationIntent {
        transaction_id: transaction_id.as_str(),
        installation_id: setup.installation_id.as_str(),
        setup_revision: setup.revision(),
        milestone: SetupMilestone::ServiceKeysGenerated,
        effect: "create-initial-config-signing-key-v1",
    })
    .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
    let intent = handle(
        eliot_contracts::sha256_hex(&intent_bytes),
        "initial_snapshot_key.intent_digest",
    )?;
    store.record_setup_effect_intent(
        transaction_id,
        SetupMilestone::ServiceKeysGenerated,
        &intent,
    )?;

    let signer = key_store
        .create_new()
        .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
    let trust_anchor = signer
        .trust_anchor(
            setup.installation_id.as_str(),
            INSTALLATION_AUTHORITY_SIGNER_ID,
        )
        .map_err(|error| invalid_initial_snapshot(error.to_string()))?;
    let record = InitialSnapshotKeyRecord::from_signer(
        transaction_id.clone(),
        setup.revision(),
        &signer,
        trust_anchor.clone(),
    )?;
    store.record_initial_snapshot_key(&record)?;
    Ok((signer, trust_anchor))
}

fn handle(value: impl AsRef<str>, field: &'static str) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(value.as_ref()).map_err(|error| InstallationError::InvalidField {
        field: field.to_owned(),
        reason: error.to_string(),
    })
}

fn invalid_initial_snapshot(reason: String) -> InstallationError {
    InstallationError::InvalidField {
        field: "signed_initial_snapshot".to_owned(),
        reason,
    }
}

fn invalid_setup(reason: &'static str) -> InstallationError {
    InstallationError::InvalidField {
        field: "setup_binding.revision".to_owned(),
        reason: reason.to_owned(),
    }
}
