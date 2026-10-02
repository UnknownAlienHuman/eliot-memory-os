//! Setup-owner signing over the original profile-owned key providers.
//!
//! `SetupKeyReference` deliberately has only an opaque provider target, a key
//! id, and its owning Windows principal. This adapter uses that exact target
//! to carry a typed initial-snapshot purpose reference to the original profile
//! provider: the protected installation key store for `SystemService`,
//! Credential Manager for `UserMode`, or the retained repository-local key
//! receipt for `PortableDev`. The reference pins installation, confirmed
//! System Owner, the current setup-authorizing SID, the physical key-slot
//! principal, key id, public-key fingerprint, and the exact provider receipt.
//! The low-level key slot keeps its original purpose and private seed;
//! initial-configuration signing is admitted only when the original setup
//! record carries this exact typed reference.
//!
//! Documented assumption: the setup key-reference contract does not name a
//! signer purpose or public-key fingerprint. Each existing profile provider
//! supplies those facts on readback; this purpose-specific reference stores
//! that public pin in the original `SetupKeyReference.target_ref` rather than
//! adding an ambient key namespace or another trust store.

use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, InstallationActivationApprovalSigner,
    PortableDevSupervisionKeyReference, SupervisionLeaseSigner,
};
use serde::{Deserialize, Serialize};

use crate::{
    INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE, INSTALLATION_AUTHORITY_SIGNER_ID,
    InstallationAuthorityKeyError, InstallationAuthorityKeyExpectation,
    InstallationAuthorityKeyMetadata, InstallationAuthorityKeyPreparationReceipt,
    InstallationAuthorityKeySigner,
    InstallerRootProfile, WindowsInstallationAuthorityKeyStore, protected_program_data_path,
};

const SETUP_OWNER_KEY_REFERENCE_WIRE: &str = "eliot.setup-owner-initial-snapshot-key-reference.v3";

/// Exact protected-key pin stored in `SetupKeyReference.target_ref`.
///
/// The value is public metadata only. The referenced private seed stays in
/// the existing protected key slot and is re-read by the provider before each
/// signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupOwnerInitialSnapshotKeyReference {
    wire: String,
    transaction_id: String,
    installation_id: String,
    confirmed_owner: String,
    /// Current Windows principal authorized to run this setup operation.
    principal_sid: String,
    /// Physical principal that owns the underlying key material. For the
    /// SystemService profile this is SYSTEM, distinct from `principal_sid`.
    key_principal_sid: String,
    key_id: String,
    public_key_fingerprint: String,
    file_identity: Option<crate::FileIdentity>,
    user_mode_receipt: Option<crate::UserModeSupervisionAuthorityCredentialReceipt>,
    portable_dev_receipt: Option<crate::PortableDevSupervisionAuthorityKeyReceipt>,
}

impl SetupOwnerInitialSnapshotKeyReference {
    /// Builds the exact setup-purpose pin from metadata returned by the
    /// original protected installation key store.
    ///
    /// The caller must persist the resulting `target_ref`, `key_id`, and SID
    /// in the ordered `ServiceKeysGenerated` setup result before any later
    /// setup milestone is admitted.
    pub fn from_protected_key(
        metadata: &InstallationAuthorityKeyMetadata,
        transaction_id: impl Into<String>,
        installation_id: impl Into<String>,
        confirmed_owner: impl Into<String>,
        principal_sid: impl Into<String>,
    ) -> Result<Self, SetupOwnerInitialSnapshotKeyError> {
        let reference = Self {
            wire: SETUP_OWNER_KEY_REFERENCE_WIRE.to_owned(),
            transaction_id: transaction_id.into(),
            installation_id: installation_id.into(),
            confirmed_owner: confirmed_owner.into(),
            principal_sid: principal_sid.into(),
            key_principal_sid: InstallationAuthorityKeyMetadata::OWNER_SID.to_owned(),
            key_id: metadata.key_id.clone(),
            public_key_fingerprint: metadata.public_key_fingerprint.clone(),
            file_identity: Some(metadata.file_identity.clone()),
            user_mode_receipt: None,
            portable_dev_receipt: None,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Builds the initial-snapshot purpose reference from the exact original
    /// UserMode transaction receipt. The receipt remains embedded verbatim in
    /// the existing SetupKeyReference target and is reopened on every sign.
    pub fn from_user_mode_receipt(
        receipt: crate::UserModeSupervisionAuthorityCredentialReceipt,
        transaction_id: impl Into<String>,
        installation_id: impl Into<String>,
        confirmed_owner: impl Into<String>,
        principal_sid: impl Into<String>,
    ) -> Result<Self, SetupOwnerInitialSnapshotKeyError> {
        receipt
            .validate()
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
        let principal_sid = principal_sid.into();
        let reference = Self {
            wire: SETUP_OWNER_KEY_REFERENCE_WIRE.to_owned(),
            transaction_id: transaction_id.into(),
            installation_id: installation_id.into(),
            confirmed_owner: confirmed_owner.into(),
            principal_sid: principal_sid.clone(),
            key_principal_sid: principal_sid,
            key_id: receipt.request.key_id.clone(),
            public_key_fingerprint: receipt.trust_anchor.public_key_fingerprint.clone(),
            file_identity: None,
            user_mode_receipt: Some(receipt),
            portable_dev_receipt: None,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Builds the initial-snapshot purpose reference from the exact original
    /// PortableDev setup-effect receipt. Its retained repository root identity
    /// and relative key path are independently reopened by the profile-owned
    /// provider; no ProgramData or ambient path fallback is available.
    pub fn from_portable_dev_receipt(
        receipt: crate::PortableDevSupervisionAuthorityKeyReceipt,
        transaction_id: impl Into<String>,
        installation_id: impl Into<String>,
        confirmed_owner: impl Into<String>,
        principal_sid: impl Into<String>,
    ) -> Result<Self, SetupOwnerInitialSnapshotKeyError> {
        receipt
            .validate()
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
        let principal_sid = principal_sid.into();
        let reference = Self {
            wire: SETUP_OWNER_KEY_REFERENCE_WIRE.to_owned(),
            transaction_id: transaction_id.into(),
            installation_id: installation_id.into(),
            confirmed_owner: confirmed_owner.into(),
            principal_sid: principal_sid.clone(),
            key_principal_sid: principal_sid,
            key_id: receipt.request.key_id.clone(),
            public_key_fingerprint: receipt.trust_anchor.public_key_fingerprint.clone(),
            file_identity: Some(receipt.request.repository_root_identity),
            user_mode_receipt: None,
            portable_dev_receipt: Some(receipt),
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Returns the public key identity retained by the protected slot.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the principal SID which owns the setup key reference.
    #[must_use]
    pub fn principal_sid(&self) -> &str {
        &self.principal_sid
    }

    /// Returns whether this target is the exact SystemService setup purpose
    /// reference for the prepared protected-key receipt, including the
    /// original native slot identity and the separate physical key principal.
    #[must_use]
    pub fn matches_system_service_preparation_receipt(
        &self,
        receipt: &InstallationAuthorityKeyPreparationReceipt,
    ) -> bool {
        receipt.validate().is_ok()
            && receipt.slot_file_identity.is_some()
            && self.key_principal_sid == InstallationAuthorityKeyMetadata::OWNER_SID
            && self.key_id == receipt.key_id
            && self.public_key_fingerprint == receipt.public_key_fingerprint
            && self.file_identity == receipt.slot_file_identity
            && self.user_mode_receipt.is_none()
            && self.portable_dev_receipt.is_none()
    }

    /// Returns whether this retained purpose reference belongs to the exact
    /// profile selected by the original installer transaction.
    #[must_use]
    pub fn belongs_to_profile(&self, profile: InstallerRootProfile) -> bool {
        match profile {
            InstallerRootProfile::SystemService => {
                self.file_identity.is_some()
                    && self.user_mode_receipt.is_none()
                    && self.portable_dev_receipt.is_none()
                    && self.key_principal_sid == InstallationAuthorityKeyMetadata::OWNER_SID
            }
            InstallerRootProfile::UserMode => {
                self.file_identity.is_none()
                    && self.user_mode_receipt.is_some()
                    && self.portable_dev_receipt.is_none()
                    && self.key_principal_sid == self.principal_sid
            }
            InstallerRootProfile::PortableDev => {
                self.file_identity.is_some()
                    && self.user_mode_receipt.is_none()
                    && self.portable_dev_receipt.is_some()
                    && self.key_principal_sid == self.principal_sid
            }
        }
    }

    /// Encodes this exact versioned pin as the opaque provider target held by
    /// the original setup binding.
    pub fn target_ref(&self) -> Result<PlatformHandle, SetupOwnerInitialSnapshotKeyError> {
        self.validate()?;
        let encoded = serde_json::to_string(self)
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
        PlatformHandle::new(encoded).map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)
    }

    fn decode_target_ref(
        target_ref: &PlatformHandle,
    ) -> Result<Self, SetupOwnerInitialSnapshotKeyError> {
        let reference: Self = serde_json::from_str(target_ref.as_str())
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
        reference.validate()?;
        if serde_json::to_string(&reference)
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?
            != target_ref.as_str()
        {
            return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
        }
        Ok(reference)
    }

    /// Parses a target only when it uses this exact setup-owner purpose.
    ///
    /// Other `SetupKeyReference` provider targets are not interpreted here;
    /// a malformed value claiming this wire is a typed refusal.
    pub fn from_setup_target_ref(
        target_ref: &PlatformHandle,
    ) -> Result<Option<Self>, SetupOwnerInitialSnapshotKeyError> {
        let value: serde_json::Value = match serde_json::from_str(target_ref.as_str()) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        if value.get("wire").and_then(serde_json::Value::as_str)
            != Some(SETUP_OWNER_KEY_REFERENCE_WIRE)
        {
            return Ok(None);
        }
        Self::decode_target_ref(target_ref).map(Some)
    }

    fn validate(&self) -> Result<(), SetupOwnerInitialSnapshotKeyError> {
        if self.wire != SETUP_OWNER_KEY_REFERENCE_WIRE
            || self.transaction_id.trim().is_empty()
            || self.installation_id.trim().is_empty()
            || self.confirmed_owner.trim().is_empty()
            || self.principal_sid.trim() != self.principal_sid
            || !self.principal_sid.starts_with("S-")
            || self.key_principal_sid.trim() != self.key_principal_sid
            || !self.key_principal_sid.starts_with("S-")
            || self.key_id.trim().is_empty()
            || self.public_key_fingerprint.len() != 64
            || !self
                .public_key_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self
                .file_identity
                .as_ref()
                .is_some_and(|identity| identity.volume_serial_number == 0 || identity.file_index == 0)
        {
            return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
        }
        match (
            self.file_identity.is_some(),
            self.user_mode_receipt.is_some(),
            self.portable_dev_receipt.is_some(),
        ) {
            (true, false, false) => {
                if self.key_principal_sid != InstallationAuthorityKeyMetadata::OWNER_SID {
                    return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
                }
            }
            (false, true, false) => {
                let Some(receipt) = self.user_mode_receipt.as_ref() else {
                    return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
                };
                receipt
                    .validate()
                    .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
                if self.file_identity.is_some()
                    || self.portable_dev_receipt.is_some()
                    || receipt.request.transaction_id != self.transaction_id
                    || receipt.request.installation_id != self.installation_id
                    || receipt.request.key_id != self.key_id
                    || receipt.trust_anchor.public_key_fingerprint != self.public_key_fingerprint
                    || receipt.request.owner_sid != self.principal_sid
                    || self.key_principal_sid != self.principal_sid
                    || receipt.request.signer_id != self.confirmed_owner
                {
                    return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
                }
            }
            (true, false, true) => {
                let Some(receipt) = self.portable_dev_receipt.as_ref() else {
                    return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
                };
                receipt
                    .validate()
                    .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
                if self.user_mode_receipt.is_some()
                    || receipt.request.transaction_id != self.transaction_id
                    || receipt.request.installation_id != self.installation_id
                    || receipt.request.key_id != self.key_id
                    || receipt.trust_anchor.public_key_fingerprint != self.public_key_fingerprint
                    || receipt.request.signer_id != self.confirmed_owner
                    || self.key_principal_sid != self.principal_sid
                    || Some(receipt.request.repository_root_identity) != self.file_identity
                {
                    return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
                }
            }
            _ => return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference),
        }
        Ok(())
    }
}

/// Error from opening or using one setup-owner protected key reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SetupOwnerInitialSnapshotKeyError {
    /// The reference was malformed or did not match its durable setup fields.
    #[error("setup-owner initial-snapshot key reference is invalid")]
    InvalidReference,
    /// The current process SID differs from the setup authorizing principal.
    #[error("current process principal is not the setup-authorizing principal")]
    PrincipalMismatch,
    /// The protected key slot could not be read or its public pin differed.
    #[error("protected setup signing key could not be read back exactly")]
    ProtectedKeyMismatch,
    /// The selected profile-owned key root or platform identity was unavailable.
    #[error("selected profile setup signing key root is unavailable")]
    ProtectedRootUnavailable,
}

/// Reopens the existing protected installer key mechanism for one setup-owned
/// initial-snapshot signature purpose.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsSetupOwnerInitialSnapshotKeyProvider;

impl WindowsSetupOwnerInitialSnapshotKeyProvider {
    /// Creates a provider without reading or changing key state.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Reads the key named by the exact durable setup key reference.
    ///
    /// The transaction id and profile-owned root are reloaded from the original
    /// installation transaction by the caller. They are compared with the
    /// typed key target; `SystemService` alone can reach the existing protected
    /// installer slot, `UserMode` uses its exact Credential Manager receipt,
    /// and `PortableDev` uses its exact repository-local key-file receipt.
    /// The active Windows process SID is independently read before any key is
    /// opened.
    pub fn open(
        &self,
        target_ref: &PlatformHandle,
        key_id: &PlatformHandle,
        principal_sid: &PlatformHandle,
        transaction_id: &str,
        installation_id: &str,
        confirmed_owner: &str,
        profile: InstallerRootProfile,
        selected_profile_key_root: Option<&Path>,
    ) -> Result<ProtectedSetupOwnerInitialSnapshotSigner, SetupOwnerInitialSnapshotKeyError> {
        let reference = SetupOwnerInitialSnapshotKeyReference::decode_target_ref(target_ref)?;
        if reference.transaction_id != transaction_id
            || reference.key_id != key_id.as_str()
            || reference.principal_sid != principal_sid.as_str()
            || reference.installation_id != installation_id
            || reference.confirmed_owner != confirmed_owner
            || !reference.belongs_to_profile(profile)
        {
            return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
        }
        let live_sid = crate::current_process_sid()
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::ProtectedRootUnavailable)?;
        if live_sid != reference.principal_sid {
            return Err(SetupOwnerInitialSnapshotKeyError::PrincipalMismatch);
        }
        let signer = open_profile_signer(&reference, profile, selected_profile_key_root)?;
        let public_key = signer_public_key(&signer);
        if crate::sha256_hex(&public_key) != reference.public_key_fingerprint {
            return Err(SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch);
        }
        Ok(ProtectedSetupOwnerInitialSnapshotSigner {
            reference,
            profile,
            selected_profile_key_root: selected_profile_key_root.map(Path::to_path_buf),
            public_key,
        })
    }

    /// Creates the opaque provider reference for a key just read from the
    /// original protected installation key store. This is the producer seam
    /// used while recording the existing `ServiceKeysGenerated` milestone.
    pub fn reference_for_setup(
        &self,
        signer: &InstallationAuthorityKeySigner,
        transaction_id: impl Into<String>,
        installation_id: impl Into<String>,
        confirmed_owner: impl Into<String>,
        principal_sid: impl Into<String>,
    ) -> Result<SetupOwnerInitialSnapshotKeyReference, SetupOwnerInitialSnapshotKeyError> {
        let live_sid = crate::current_process_sid()
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::ProtectedRootUnavailable)?;
        let reference = SetupOwnerInitialSnapshotKeyReference::from_protected_key(
            signer.metadata(),
            transaction_id,
            installation_id,
            confirmed_owner,
            principal_sid,
        )?;
        if reference.principal_sid != live_sid {
            return Err(SetupOwnerInitialSnapshotKeyError::PrincipalMismatch);
        }
        let anchor = signer
            .trust_anchor(
                reference.installation_id.clone(),
                INSTALLATION_AUTHORITY_SIGNER_ID,
            )
            .map_err(map_key_error)?;
        if anchor.key_id != reference.key_id
            || anchor.public_key_fingerprint != reference.public_key_fingerprint
        {
            return Err(SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch);
        }
        Ok(reference)
    }

    /// Reads the active Windows process SID from the platform identity owner.
    /// The returned handle is an observation only; callers must still bind it
    /// to the exact original setup transaction and protected-key receipt.
    pub fn current_principal_sid(
        &self,
    ) -> Result<PlatformHandle, SetupOwnerInitialSnapshotKeyError> {
        let sid = crate::current_process_sid()
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::ProtectedRootUnavailable)?;
        PlatformHandle::new(sid).map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)
    }
}

/// Opaque setup-purpose view of the existing protected key signer.
///
/// It exposes only the owner-bound signer metadata and signature operation.
/// Each call reopens the exact protected slot through the original provider,
/// compares its pin with the durable setup reference, and signs only after the
/// same current process principal is observed again.
pub struct ProtectedSetupOwnerInitialSnapshotSigner {
    reference: SetupOwnerInitialSnapshotKeyReference,
    profile: InstallerRootProfile,
    selected_profile_key_root: Option<PathBuf>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for ProtectedSetupOwnerInitialSnapshotSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedSetupOwnerInitialSnapshotSigner")
            .field("reference", &self.reference)
            .field("signing_seed", &"<protected>")
            .finish_non_exhaustive()
    }
}

impl ProtectedSetupOwnerInitialSnapshotSigner {
    /// Returns the exact confirmed System Owner signer identity.
    #[must_use]
    pub fn signer_id(&self) -> &str {
        &self.reference.confirmed_owner
    }

    /// Returns the exact setup key identity.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.reference.key_id
    }

    /// Returns public key bytes read from the protected key slot.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the public key fingerprint read from the protected key slot.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> &str {
        &self.reference.public_key_fingerprint
    }

    /// Signs canonical initial-snapshot preimage bytes after exact key and
    /// principal readback through the original protected key owner.
    pub fn sign(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<Vec<u8>, SetupOwnerInitialSnapshotKeyError> {
        let current = WindowsSetupOwnerInitialSnapshotKeyProvider::new().open(
            &self.reference.target_ref()?,
            &PlatformHandle::new(self.reference.key_id.clone())
                .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?,
            &PlatformHandle::new(self.reference.principal_sid.clone())
                .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?,
            &self.reference.transaction_id,
            &self.reference.installation_id,
            &self.reference.confirmed_owner,
            self.profile,
            self.selected_profile_key_root.as_deref(),
        )?;
        if current.public_key != self.public_key {
            return Err(SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch);
        }
        let signer = open_profile_signer(
            &current.reference,
            self.profile,
            current.selected_profile_key_root.as_deref(),
        )?;
        match signer {
            SetupProfileSigner::Installation(signer) => {
                signer.sign(canonical_bytes).map_err(|_| {
                    SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch
                })
            }
            SetupProfileSigner::Supervision(signer) => signer
                .sign(canonical_bytes)
                .map_err(|_| SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch),
        }
    }
}

enum SetupProfileSigner {
    Installation(InstallationAuthorityKeySigner),
    Supervision(Ed25519SupervisionLeaseSigner),
}

fn signer_public_key(signer: &SetupProfileSigner) -> Vec<u8> {
    match signer {
        SetupProfileSigner::Installation(signer) => signer.metadata().public_key.clone(),
        SetupProfileSigner::Supervision(signer) => signer.public_key().to_vec(),
    }
}

fn open_profile_signer(
    reference: &SetupOwnerInitialSnapshotKeyReference,
    profile: InstallerRootProfile,
    selected_profile_key_root: Option<&Path>,
) -> Result<SetupProfileSigner, SetupOwnerInitialSnapshotKeyError> {
    if !reference.belongs_to_profile(profile) {
        return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
    }
    match profile {
        InstallerRootProfile::SystemService => {
            if reference.key_principal_sid != InstallationAuthorityKeyMetadata::OWNER_SID {
                return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
            }
            let selected_root = selected_profile_key_root
                .ok_or(SetupOwnerInitialSnapshotKeyError::ProtectedRootUnavailable)?;
            let expected_root = protected_key_root()?;
            if !crate::windows_paths_equal(selected_root, &expected_root) {
                return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
            }
            let store = WindowsInstallationAuthorityKeyStore::new(selected_root)
                .map_err(map_key_error)?;
            let identity = reference
                .file_identity
                .clone()
                .ok_or(SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
            let expectation = InstallationAuthorityKeyExpectation::new(
                reference.key_id.clone(),
                reference.public_key_fingerprint.clone(),
                identity,
            )
            .map_err(map_key_error)?;
            let signer = store.open_existing(&expectation).map_err(map_key_error)?;
            let metadata = signer.metadata();
            if metadata.key_id != reference.key_id
                || metadata.public_key_fingerprint != reference.public_key_fingerprint
                || Some(metadata.file_identity.clone()) != reference.file_identity
            {
                return Err(SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch);
            }
            // The original slot remains `installer-authority`; this explicit
            // setup-purpose adapter does not mutate its key id or metadata.
            let original_anchor = signer
                .trust_anchor(reference.installation_id.clone(), INSTALLATION_AUTHORITY_SIGNER_ID)
                .map_err(map_key_error)?;
            if original_anchor.public_key != metadata.public_key
                || original_anchor.key_id != reference.key_id
            {
                return Err(SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch);
            }
            Ok(SetupProfileSigner::Installation(signer))
        }
        InstallerRootProfile::UserMode => {
            if selected_profile_key_root.is_some() {
                return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
            }
            let receipt = reference
                .user_mode_receipt
                .as_ref()
                .ok_or(SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
            if receipt.request.transaction_id != reference.transaction_id
                || receipt.request.installation_id != reference.installation_id
                || receipt.request.signer_id != reference.confirmed_owner
                || receipt.request.owner_sid != reference.principal_sid
            {
                return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
            }
            let signer = crate::WindowsUserModeSupervisionAuthorityCredentialProvider::new()
                .load_signer(receipt)
                .map_err(|_| SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch)?;
            if signer.public_key().as_slice() != receipt.trust_anchor.public_key.as_slice() {
                return Err(SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch);
            }
            Ok(SetupProfileSigner::Supervision(signer))
        }
        InstallerRootProfile::PortableDev => {
            let selected_root = selected_profile_key_root
                .ok_or(SetupOwnerInitialSnapshotKeyError::ProtectedRootUnavailable)?;
            let receipt = reference
                .portable_dev_receipt
                .as_ref()
                .ok_or(SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
            if receipt.request.transaction_id != reference.transaction_id
                || receipt.request.installation_id != reference.installation_id
                || receipt.request.signer_id != reference.confirmed_owner
                || !crate::windows_paths_equal(selected_root, &receipt.request.repository_root)
            {
                return Err(SetupOwnerInitialSnapshotKeyError::InvalidReference);
            }
            let key_reference = PortableDevSupervisionKeyReference::new(
                receipt.request.relative_path.clone(),
            )
            .map_err(|_| SetupOwnerInitialSnapshotKeyError::InvalidReference)?;
            let signer = crate::WindowsPortableDevSupervisionAuthorityKeyProvider::new()
                .load_signer_for_kernel(
                    &key_reference,
                    selected_root,
                    receipt.request.repository_root_identity,
                    &receipt.trust_anchor,
                )
                .map_err(|_| SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch)?;
            if signer.public_key().as_slice() != receipt.trust_anchor.public_key.as_slice() {
                return Err(SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch);
            }
            Ok(SetupProfileSigner::Supervision(signer))
        }
    }
}

fn protected_key_root() -> Result<std::path::PathBuf, SetupOwnerInitialSnapshotKeyError> {
    let contour = protected_program_data_path("Eliot")
        .map_err(|_| SetupOwnerInitialSnapshotKeyError::ProtectedRootUnavailable)?;
    let key_root = contour.join(Path::new(INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE));
    Ok(key_root)
}

fn map_key_error(
    error: InstallationAuthorityKeyError,
) -> SetupOwnerInitialSnapshotKeyError {
    match error {
        InstallationAuthorityKeyError::IdentityMismatch
        | InstallationAuthorityKeyError::MissingOrMalformed
        | InstallationAuthorityKeyError::AlreadyExists => {
            SetupOwnerInitialSnapshotKeyError::ProtectedKeyMismatch
        }
        InstallationAuthorityKeyError::InvalidPath
        | InstallationAuthorityKeyError::InvalidKeyId
        | InstallationAuthorityKeyError::MissingRoot
        | InstallationAuthorityKeyError::ReparsePoint
        | InstallationAuthorityKeyError::AclMismatch
        | InstallationAuthorityKeyError::CryptographicFailure
        | InstallationAuthorityKeyError::PermissionDenied
        | InstallationAuthorityKeyError::Io
        | InstallationAuthorityKeyError::UnsupportedPlatform => {
            SetupOwnerInitialSnapshotKeyError::ProtectedRootUnavailable
        }
    }
}
