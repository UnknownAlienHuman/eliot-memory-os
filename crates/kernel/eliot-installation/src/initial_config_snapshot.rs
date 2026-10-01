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
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    INSTALLATION_AUTHORITY_SIGNER_ID, InstallationAuthorityKeySigner,
};
use eliot_runtime_contracts::InstallationActivationApprovalSigner;

use crate::{
    InstallationError, RedbInstallationTransactionStore, SetupAdvanceInput, SetupBinding,
    SetupEffectObservation, SetupMilestone,
};

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
