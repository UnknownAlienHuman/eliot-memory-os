//! Windows DPAPI-NG provider for Kernel supervision signing keys.

use std::path::{Component, Path, PathBuf};

use eliot_contracts::{ResourceGeneration, sha256_hex};
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, PORTABLE_DEV_SUPERVISION_KEY_PREFIX,
    PortableDevSupervisionKeyReference, ProvisionedSupervisionAuthority,
    SUPERVISION_AUTHORITY_HOST_SERVICE, SupervisionLeaseError, SupervisionSealedKeyFileIdentity,
    SupervisionSealedKeyReference, SupervisionTrustAnchor, UserModeSupervisionKeyReference,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::secret_store::{
    CurrentUserSupervisionCredentialObservation, CurrentUserSupervisionCredentialProvisionOutcome,
    CurrentUserSupervisionCredentialWriteReceipt, WindowsCurrentUserSupervisionCredentialProvider,
};
use crate::{
    CredentialSecret, FileIdentity, InstallerRootError, InstallerRootObjectSnapshot,
    InstallerRootPrimitiveSpec, ProtectedPathError, UserOwnedPathLease, UserOwnedRootLease,
    WindowsAdapterError, WindowsInstallerRootPrimitive, fill_system_random, resolve_service_sid,
    valid_service_sid_text,
};

const SEALED_KEY_ENVELOPE_WIRE: &str = "eliot.supervision-authority-key.v1";
const SEALED_KEY_FILE_LIMIT: u64 = 16 * 1024;

/// Exact provider failure without secret-bearing diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionAuthorityKeyError {
    InvalidBinding,
    RandomUnavailable,
    ProviderUnavailable,
    AccessDenied,
    KeyInvalid,
}

impl std::fmt::Display for SupervisionAuthorityKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "supervision authority key provider failed: {self:?}"
        )
    }
}

impl std::error::Error for SupervisionAuthorityKeyError {}

/// Ciphertext and independently derived public anchor returned to the
/// installer. The plaintext seed is zeroized before this value is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSupervisionAuthorityKey {
    pub sealed_blob: Vec<u8>,
    pub trust_anchor: SupervisionTrustAnchor,
}

/// Secret-free request for a `UserMode` Credential Manager authority key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserModeSupervisionAuthorityCredentialRequest {
    /// Durable transaction identity.
    pub transaction_id: String,
    /// Exact planned authority effect identity.
    pub effect_id: String,
    /// Installation identity pinned into the trust anchor.
    pub installation_id: String,
    /// Candidate generation owning the key.
    pub candidate_generation: String,
    /// Lifecycle generation owning the key.
    pub authority_generation: ResourceGeneration,
    /// Supervision lease scope selected by the candidate.
    pub supervision_lease_scope_id: String,
    /// Kernel signer identity.
    pub signer_id: String,
    /// Generation-specific public key identity.
    pub key_id: String,
    /// Exact current-user SID that owns Credential Manager access.
    pub owner_sid: String,
}

impl UserModeSupervisionAuthorityCredentialRequest {
    fn validate(&self) -> Result<(), SupervisionAuthorityKeyError> {
        if [
            self.transaction_id.as_str(),
            self.effect_id.as_str(),
            self.installation_id.as_str(),
            self.candidate_generation.as_str(),
            self.supervision_lease_scope_id.as_str(),
            self.signer_id.as_str(),
            self.key_id.as_str(),
        ]
        .iter()
        .any(|value| {
            value.is_empty() || *value != value.trim() || value.chars().any(char::is_control)
        }) || self.authority_generation.value() == 0
            || !self.owner_sid.starts_with("S-")
            || self.owner_sid.trim() != self.owner_sid
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(())
    }
}

/// Public, secret-free receipt for a transaction-owned `UserMode` authority key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserModeSupervisionAuthorityCredentialReceipt {
    /// Breaking receipt discriminator.
    pub wire: String,
    /// Original immutable request and owner binding.
    pub request: UserModeSupervisionAuthorityCredentialRequest,
    /// Exact purpose-bound Credential Manager target.
    pub target: PlatformHandle,
    /// Installation-pinned public Ed25519 trust anchor.
    pub trust_anchor: SupervisionTrustAnchor,
}

/// Secret-free transaction request for one disposable `PortableDev` key file.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableDevSupervisionAuthorityKeyRequest {
    /// Durable transaction identity.
    pub transaction_id: String,
    /// Exact planned authority effect identity.
    pub effect_id: String,
    /// Installation identity pinned into the trust anchor.
    pub installation_id: String,
    /// Candidate generation owning the key.
    pub candidate_generation: String,
    /// Lifecycle generation owning the key.
    pub authority_generation: ResourceGeneration,
    /// Supervision lease scope selected by the candidate.
    pub supervision_lease_scope_id: String,
    /// Kernel signer identity.
    pub signer_id: String,
    /// Generation-specific public key identity.
    pub key_id: String,
    /// Exact repository root selected by the `PortableDev` descriptor.
    pub repository_root: PathBuf,
    /// Repository-root file-object identity retained before key materialization.
    pub repository_root_identity: FileIdentity,
    /// Canonical descriptor-relative path under `.eliot-dev/state`.
    pub relative_path: String,
}

impl PortableDevSupervisionAuthorityKeyRequest {
    fn validate(&self) -> Result<(), SupervisionAuthorityKeyError> {
        if [
            self.transaction_id.as_str(),
            self.effect_id.as_str(),
            self.installation_id.as_str(),
            self.candidate_generation.as_str(),
            self.supervision_lease_scope_id.as_str(),
            self.signer_id.as_str(),
            self.key_id.as_str(),
        ]
        .iter()
        .any(|value| {
            value.is_empty() || *value != value.trim() || value.chars().any(char::is_control)
        }) || self.authority_generation.value() == 0
            || !self.repository_root.is_absolute()
            || self
                .repository_root
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || self.repository_root_identity.volume_serial_number == 0
            || self.repository_root_identity.file_index == 0
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        PortableDevSupervisionKeyReference::new(self.relative_path.clone())
            .map_err(map_contract_error)?;
        Ok(())
    }
}

/// Public, secret-free receipt for one transaction-owned `PortableDev` key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableDevSupervisionAuthorityKeyReceipt {
    /// Breaking receipt discriminator.
    pub wire: String,
    /// Original immutable request and root binding.
    pub request: PortableDevSupervisionAuthorityKeyRequest,
    /// Installation-pinned public Ed25519 trust anchor.
    pub trust_anchor: SupervisionTrustAnchor,
}

impl PortableDevSupervisionAuthorityKeyReceipt {
    fn new(
        request: PortableDevSupervisionAuthorityKeyRequest,
        trust_anchor: SupervisionTrustAnchor,
    ) -> Result<Self, SupervisionAuthorityKeyError> {
        let value = Self {
            wire: "eliot.portable-dev-supervision-authority.v1".to_owned(),
            request,
            trust_anchor,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the original transaction, repository-root identity, relative
    /// key path and public signer anchor.
    pub fn validate(&self) -> Result<(), SupervisionAuthorityKeyError> {
        self.request.validate()?;
        if self.wire != "eliot.portable-dev-supervision-authority.v1"
            || self.trust_anchor.installation_id != self.request.installation_id
            || self.trust_anchor.signer_id != self.request.signer_id
            || self.trust_anchor.key_id != self.request.key_id
            || self.trust_anchor.validate().is_err()
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(())
    }
}

/// Read-only observation of the exact repository-local `PortableDev` key path
/// before its seed has been prepared.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum PortableDevSupervisionAuthorityKeyTargetObservation {
    /// The exact path was absent beneath the selected repository-root object.
    Absent {
        /// File-object identity of the retained repository root.
        repository_root_identity: FileIdentity,
        /// Exact descriptor-relative key path.
        relative_path: String,
    },
    /// An object already occupies the create-only transaction path.
    Present {
        /// File-object identity of the retained repository root.
        repository_root_identity: FileIdentity,
        /// Exact descriptor-relative key path.
        relative_path: String,
    },
}

/// Exact post-attempt inspection against the original `PortableDev` key receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum PortableDevSupervisionAuthorityKeyObservation {
    /// No file exists at the original descriptor-relative path.
    Absent {
        /// Original transaction receipt used for inspection.
        receipt: PortableDevSupervisionAuthorityKeyReceipt,
    },
    /// The existing seed derives the original trust anchor.
    Matching {
        /// Original transaction receipt, never reconstructed from observed bytes.
        receipt: PortableDevSupervisionAuthorityKeyReceipt,
    },
    /// A present file differs from the original key or root binding.
    Mismatch {
        /// Exact descriptor-relative path requiring recovery.
        relative_path: String,
    },
}

/// Prepared `PortableDev` key kept in memory until the caller durably records
/// [`PortableDevSupervisionAuthorityKeyReceipt`].
pub struct PreparedPortableDevSupervisionAuthorityKey {
    receipt: PortableDevSupervisionAuthorityKeyReceipt,
    secret: CredentialSecret,
}

impl PreparedPortableDevSupervisionAuthorityKey {
    /// Returns the secret-free receipt that must be persisted before writing.
    #[must_use]
    pub const fn receipt(&self) -> &PortableDevSupervisionAuthorityKeyReceipt {
        &self.receipt
    }
}

/// Outcome of one create-only `PortableDev` key-file write attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum PortableDevSupervisionAuthorityKeyWriteOutcome {
    /// Exact retained-file write, durable flush and public-key readback succeeded.
    Created {
        /// Original pre-write receipt.
        receipt: PortableDevSupervisionAuthorityKeyReceipt,
    },
    /// A write was attempted but positive readback was unavailable.
    Unknown {
        /// Original pre-write receipt used for exact restart inspection.
        receipt: PortableDevSupervisionAuthorityKeyReceipt,
    },
}

impl UserModeSupervisionAuthorityCredentialReceipt {
    fn new(
        request: UserModeSupervisionAuthorityCredentialRequest,
        target: PlatformHandle,
        trust_anchor: SupervisionTrustAnchor,
    ) -> Result<Self, SupervisionAuthorityKeyError> {
        let value = Self {
            wire: "eliot.user-mode-supervision-authority.v1".to_owned(),
            request,
            target,
            trust_anchor,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the original request, transaction target, and public anchor.
    pub fn validate(&self) -> Result<(), SupervisionAuthorityKeyError> {
        self.request.validate()?;
        if self.wire != "eliot.user-mode-supervision-authority.v1"
            || !valid_user_mode_authority_target(self.target.as_str())
            || self.target.as_str() != user_mode_authority_target(&self.request)?
            || self.trust_anchor.installation_id != self.request.installation_id
            || self.trust_anchor.signer_id != self.request.signer_id
            || self.trust_anchor.key_id != self.request.key_id
            || self.trust_anchor.validate().is_err()
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(())
    }
}

/// Exact observation of the `UserMode` authority target against its original
/// transaction receipt and public trust anchor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum UserModeSupervisionAuthorityCredentialObservation {
    /// The planned target is absent under the current owner SID.
    Absent {
        /// Current-user SID performing the read.
        owner_sid: PlatformHandle,
        /// Exact target derived from transaction/effect identity.
        target: PlatformHandle,
    },
    /// The current value derives the key pinned by the persisted public anchor.
    ///
    /// The receipt is boxed because it is far larger than the SID/target pairs
    /// carried by the sibling variants. Boxing changes storage only: the
    /// retained receipt, and therefore the evidence, is byte-for-byte the same
    /// original transaction receipt and is never reconstructed from observed
    /// bytes.
    Matching {
        /// Original transaction receipt, never reconstructed from observed bytes.
        receipt: Box<UserModeSupervisionAuthorityCredentialReceipt>,
    },
    /// A present target differs from the original public key or owner binding.
    Mismatch {
        /// Current-user SID performing the read.
        owner_sid: PlatformHandle,
        /// Exact target requiring recovery.
        target: PlatformHandle,
    },
}

/// Read-only observation of the deterministic current-user authority target
/// before its seed commitment has been prepared.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum UserModeSupervisionAuthorityCredentialTargetObservation {
    /// No credential exists at the exact target under the admitted SID.
    Absent {
        /// Current-user SID performing the read.
        owner_sid: PlatformHandle,
        /// Exact target derived from the immutable transaction/effect identity.
        target: PlatformHandle,
    },
    /// A credential already occupies this create-only transaction target.
    Present {
        /// Current-user SID performing the read.
        owner_sid: PlatformHandle,
        /// Exact target derived from the immutable transaction/effect identity.
        target: PlatformHandle,
    },
}

/// Outcome of one `UserMode` authority-key write attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum UserModeSupervisionAuthorityCredentialWriteOutcome {
    /// Exact provider write and immediate readback succeeded.
    Created {
        /// Original pre-write receipt.
        receipt: UserModeSupervisionAuthorityCredentialReceipt,
    },
    /// A write was attempted but positive readback was unavailable.
    Unknown {
        /// Original pre-write receipt used for exact restart inspection.
        receipt: UserModeSupervisionAuthorityCredentialReceipt,
    },
}

/// Prepared authority seed kept only in memory until durable intent is saved.
pub struct PreparedUserModeSupervisionAuthorityCredential {
    receipt: UserModeSupervisionAuthorityCredentialReceipt,
    secret: CredentialSecret,
}

impl PreparedUserModeSupervisionAuthorityCredential {
    /// Returns the secret-free request receipt that must be persisted before
    /// [`WindowsUserModeSupervisionAuthorityCredentialProvider::write_prepared`].
    #[must_use]
    pub const fn receipt(&self) -> &UserModeSupervisionAuthorityCredentialReceipt {
        &self.receipt
    }
}

/// Current-token Credential Manager provider for `UserMode` supervision keys.
///
/// This owner uses a purpose-specific target and exact current-user SID. It
/// does not access SCM, `ProgramData`, `LocalService`, or installer-root HMAC keys.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsUserModeSupervisionAuthorityCredentialProvider {
    primitive: WindowsCurrentUserSupervisionCredentialProvider,
}

impl WindowsUserModeSupervisionAuthorityCredentialProvider {
    /// Creates a provider without opening or changing Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            primitive: WindowsCurrentUserSupervisionCredentialProvider::new(),
        }
    }

    /// Observes the deterministic create-only target before preparing a key.
    /// A present value is returned as a conflict candidate; callers must not
    /// adopt it without the original pre-write receipt.
    pub fn inspect_target(
        &self,
        request: &UserModeSupervisionAuthorityCredentialRequest,
    ) -> Result<UserModeSupervisionAuthorityCredentialTargetObservation, SupervisionAuthorityKeyError>
    {
        request.validate()?;
        let owner_sid = WindowsCurrentUserSupervisionCredentialProvider::principal_sid()
            .map_err(map_current_user_credential_error)?;
        if owner_sid.as_str() != request.owner_sid {
            return Err(SupervisionAuthorityKeyError::AccessDenied);
        }
        let target = self
            .primitive
            .target_for_effect(
                &request.installation_id,
                &request.transaction_id,
                &request.effect_id,
                &owner_sid,
            )
            .map_err(map_current_user_credential_error)?;
        match self
            .primitive
            .inspect(&target, &owner_sid)
            .map_err(map_current_user_credential_error)?
        {
            CurrentUserSupervisionCredentialObservation::Absent { owner_sid, target } => Ok(
                UserModeSupervisionAuthorityCredentialTargetObservation::Absent {
                    owner_sid,
                    target,
                },
            ),
            CurrentUserSupervisionCredentialObservation::Present { owner_sid, target } => Ok(
                UserModeSupervisionAuthorityCredentialTargetObservation::Present {
                    owner_sid,
                    target,
                },
            ),
        }
    }

    /// Generates a seed and public trust anchor before the caller commits its
    /// effect intent. The caller must retain `prepared.receipt()` durably
    /// before calling [`Self::write_prepared`].
    pub fn prepare(
        &self,
        request: UserModeSupervisionAuthorityCredentialRequest,
    ) -> Result<PreparedUserModeSupervisionAuthorityCredential, SupervisionAuthorityKeyError> {
        request.validate()?;
        let owner_sid = PlatformHandle::new(request.owner_sid.clone())
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        let target = self
            .primitive
            .target_for_effect(
                &request.installation_id,
                &request.transaction_id,
                &request.effect_id,
                &owner_sid,
            )
            .map_err(map_current_user_credential_error)?;
        let mut seed = [0_u8; 32];
        if fill_system_random(&mut seed).is_err() || seed.iter().all(|byte| *byte == 0) {
            seed.fill(0);
            return Err(SupervisionAuthorityKeyError::RandomUnavailable);
        }
        let secret_result = CredentialSecret::from_bytes(seed.to_vec());
        seed.fill(0);
        let secret =
            secret_result.map_err(|_| SupervisionAuthorityKeyError::ProviderUnavailable)?;
        let mut signer_seed = [0_u8; 32];
        signer_seed.copy_from_slice(secret.expose());
        let signer_result = Ed25519SupervisionLeaseSigner::from_secret_key(
            request.signer_id.clone(),
            request.key_id.clone(),
            signer_seed,
        );
        signer_seed.fill(0);
        let signer = signer_result.map_err(map_contract_error)?;
        let trust_anchor = SupervisionTrustAnchor::new(
            request.installation_id.clone(),
            request.signer_id.clone(),
            request.key_id.clone(),
            signer.public_key().to_vec(),
        )
        .map_err(map_contract_error)?;
        let receipt =
            UserModeSupervisionAuthorityCredentialReceipt::new(request, target, trust_anchor)?;
        Ok(PreparedUserModeSupervisionAuthorityCredential { receipt, secret })
    }

    /// Writes only the already-prepared seed and returns the original
    /// transaction receipt on both positive and ambiguous outcomes.
    pub fn write_prepared(
        &self,
        prepared: PreparedUserModeSupervisionAuthorityCredential,
    ) -> Result<UserModeSupervisionAuthorityCredentialWriteOutcome, SupervisionAuthorityKeyError>
    {
        prepared.receipt.validate()?;
        let owner_sid = PlatformHandle::new(prepared.receipt.request.owner_sid.clone())
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        let outcome = match self.primitive.write_exact_if_absent(
            &prepared.receipt.target,
            &owner_sid,
            prepared.secret,
        ) {
            Ok(outcome) => outcome,
            // The target became present after the committed Absent observation.
            // Keep the original receipt for an exact readback; never adopt
            // the object from its name or presence alone.
            Err(WindowsAdapterError::AlreadyExists) => {
                return Ok(
                    UserModeSupervisionAuthorityCredentialWriteOutcome::Unknown {
                        receipt: prepared.receipt,
                    },
                );
            }
            Err(error) => return Err(map_current_user_credential_error(error)),
        };
        match outcome {
            CurrentUserSupervisionCredentialProvisionOutcome::Created(provider_receipt)
                if provider_receipt_matches(&provider_receipt, &prepared.receipt) =>
            {
                Ok(
                    UserModeSupervisionAuthorityCredentialWriteOutcome::Created {
                        receipt: prepared.receipt,
                    },
                )
            }
            CurrentUserSupervisionCredentialProvisionOutcome::Unknown {
                owner_sid: observed_sid,
                target,
            } if observed_sid == owner_sid && target == prepared.receipt.target => Ok(
                UserModeSupervisionAuthorityCredentialWriteOutcome::Unknown {
                    receipt: prepared.receipt,
                },
            ),
            _ => Err(SupervisionAuthorityKeyError::InvalidBinding),
        }
    }

    /// Inspects only against the original pre-write receipt.
    pub fn inspect(
        &self,
        receipt: &UserModeSupervisionAuthorityCredentialReceipt,
    ) -> Result<UserModeSupervisionAuthorityCredentialObservation, SupervisionAuthorityKeyError>
    {
        receipt.validate()?;
        let owner_sid = PlatformHandle::new(receipt.request.owner_sid.clone())
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        match self
            .primitive
            .inspect(&receipt.target, &owner_sid)
            .map_err(map_current_user_credential_error)?
        {
            CurrentUserSupervisionCredentialObservation::Absent { owner_sid, target } => {
                Ok(UserModeSupervisionAuthorityCredentialObservation::Absent { owner_sid, target })
            }
            CurrentUserSupervisionCredentialObservation::Present {
                owner_sid: observed_sid,
                target: observed_target,
            } if observed_sid == owner_sid && observed_target == receipt.target => {
                match self.load_signer(receipt) {
                    Ok(_) => Ok(
                        UserModeSupervisionAuthorityCredentialObservation::Matching {
                            receipt: Box::new(receipt.clone()),
                        },
                    ),
                    Err(
                        SupervisionAuthorityKeyError::InvalidBinding
                        | SupervisionAuthorityKeyError::KeyInvalid,
                    ) => Ok(
                        UserModeSupervisionAuthorityCredentialObservation::Mismatch {
                            owner_sid,
                            target: receipt.target.clone(),
                        },
                    ),
                    Err(error) => Err(error),
                }
            }
            CurrentUserSupervisionCredentialObservation::Present { .. } => Ok(
                UserModeSupervisionAuthorityCredentialObservation::Mismatch {
                    owner_sid,
                    target: receipt.target.clone(),
                },
            ),
        }
    }

    /// Deletes only the target named by a validated positive receipt, after
    /// the provider rechecks exact bytes and proves absence after deletion.
    pub fn delete_if_matching(
        &self,
        receipt: &UserModeSupervisionAuthorityCredentialReceipt,
    ) -> Result<(), SupervisionAuthorityKeyError> {
        receipt.validate()?;
        let owner_sid = PlatformHandle::new(receipt.request.owner_sid.clone())
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        self.primitive
            .delete_if_signing_key_matches(
                &receipt.target,
                &owner_sid,
                &receipt.request.signer_id,
                &receipt.request.key_id,
                &receipt.trust_anchor.public_key,
            )
            .map_err(map_current_user_credential_error)
    }

    /// Loads a signer only when its derived public key matches the original
    /// transaction receipt's trust anchor.
    pub fn load_signer(
        &self,
        receipt: &UserModeSupervisionAuthorityCredentialReceipt,
    ) -> Result<Ed25519SupervisionLeaseSigner, SupervisionAuthorityKeyError> {
        receipt.validate()?;
        let owner_sid = PlatformHandle::new(receipt.request.owner_sid.clone())
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        let observed = self
            .primitive
            .inspect(&receipt.target, &owner_sid)
            .map_err(map_current_user_credential_error)?;
        if !matches!(
            observed,
            CurrentUserSupervisionCredentialObservation::Present {
                owner_sid: observed_sid,
                target: observed_target,
            } if observed_sid == owner_sid && observed_target == receipt.target
        ) {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let secret = self
            .primitive
            .read(&receipt.target, &owner_sid)
            .map_err(map_current_user_credential_error)?;
        if secret.expose().len() != 32 {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(secret.expose());
        let signer_result = Ed25519SupervisionLeaseSigner::from_secret_key(
            receipt.request.signer_id.clone(),
            receipt.request.key_id.clone(),
            seed,
        );
        seed.fill(0);
        let signer = signer_result.map_err(map_contract_error)?;
        if signer.public_key().as_slice() != receipt.trust_anchor.public_key.as_slice() {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(signer)
    }

    /// Loads a Kernel signer from the caller-supplied current-user Credential
    /// Manager reference and verifies it against the supplied public trust
    /// anchor. No production path provisions one; Phase-B is service-only.
    pub fn load_signer_for_kernel(
        &self,
        reference: &UserModeSupervisionKeyReference,
        trust_anchor: &SupervisionTrustAnchor,
    ) -> Result<Ed25519SupervisionLeaseSigner, SupervisionAuthorityKeyError> {
        reference.validate().map_err(map_contract_error)?;
        trust_anchor.validate().map_err(map_contract_error)?;
        let owner_sid = WindowsCurrentUserSupervisionCredentialProvider::principal_sid()
            .map_err(map_current_user_credential_error)?;
        if owner_sid.as_str() != reference.owner_sid_receipt.owner_sid {
            return Err(SupervisionAuthorityKeyError::AccessDenied);
        }
        let target = PlatformHandle::new(reference.credential_target.clone())
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        let secret = self
            .primitive
            .read(&target, &owner_sid)
            .map_err(map_current_user_credential_error)?;
        signer_for_anchor(&secret, trust_anchor)
    }
}

/// Explicitly disposable repository-local key provider for `PortableDev`.
///
/// Key bytes exist only in the retained current-user file below the selected
/// repository root. This provider has no service, `ProgramData`, Credential
/// Manager, or production fallback path.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsPortableDevSupervisionAuthorityKeyProvider;

impl WindowsPortableDevSupervisionAuthorityKeyProvider {
    /// Creates a provider without opening or changing the repository.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Observes the exact create-only key path before a key is prepared.
    pub fn inspect_target(
        &self,
        request: &PortableDevSupervisionAuthorityKeyRequest,
    ) -> Result<PortableDevSupervisionAuthorityKeyTargetObservation, SupervisionAuthorityKeyError>
    {
        request.validate()?;
        let root =
            open_portable_dev_root(&request.repository_root, request.repository_root_identity)?;
        let path = portable_dev_key_path(&root, &request.relative_path)?;
        let parent = open_portable_dev_parent(&root, &path, false)?;
        let state = match std::fs::symlink_metadata(&path) {
            Ok(_) => PortableDevSupervisionAuthorityKeyTargetObservation::Present {
                repository_root_identity: root.identity(),
                relative_path: request.relative_path.clone(),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PortableDevSupervisionAuthorityKeyTargetObservation::Absent {
                    repository_root_identity: root.identity(),
                    relative_path: request.relative_path.clone(),
                }
            }
            Err(_) => return Err(SupervisionAuthorityKeyError::ProviderUnavailable),
        };
        if let Some(parent) = &parent {
            parent
                .verify_stable_identity()
                .and_then(|()| parent.verify_path_identity())
                .map_err(map_user_owned_path_error)?;
        }
        root.verify_stable_identity()
            .and_then(|()| root.verify_path_identity())
            .map_err(map_user_owned_path_error)?;
        Ok(state)
    }

    /// Generates a key and public anchor before the caller commits the
    /// returned secret-free receipt as durable effect intent.
    pub fn prepare(
        &self,
        request: PortableDevSupervisionAuthorityKeyRequest,
    ) -> Result<PreparedPortableDevSupervisionAuthorityKey, SupervisionAuthorityKeyError> {
        request.validate()?;
        let mut seed = [0_u8; 32];
        if fill_system_random(&mut seed).is_err() || seed.iter().all(|byte| *byte == 0) {
            seed.fill(0);
            return Err(SupervisionAuthorityKeyError::RandomUnavailable);
        }
        let secret_result = CredentialSecret::from_bytes(seed.to_vec());
        seed.fill(0);
        let secret = secret_result.map_err(|_| SupervisionAuthorityKeyError::KeyInvalid)?;
        let mut signer_seed = [0_u8; 32];
        signer_seed.copy_from_slice(secret.expose());
        let signer_result = Ed25519SupervisionLeaseSigner::from_secret_key(
            request.signer_id.clone(),
            request.key_id.clone(),
            signer_seed,
        );
        signer_seed.fill(0);
        let signer = signer_result.map_err(map_contract_error)?;
        let trust_anchor = SupervisionTrustAnchor::new(
            request.installation_id.clone(),
            request.signer_id.clone(),
            request.key_id.clone(),
            signer.public_key().to_vec(),
        )
        .map_err(map_contract_error)?;
        let receipt = PortableDevSupervisionAuthorityKeyReceipt::new(request, trust_anchor)?;
        Ok(PreparedPortableDevSupervisionAuthorityKey { receipt, secret })
    }

    /// Writes only a prepared seed with create-new semantics. If a target
    /// already exists or any post-create readback is uncertain, the original
    /// receipt is returned as Unknown for read-only restart reconciliation.
    pub fn write_prepared(
        &self,
        prepared: PreparedPortableDevSupervisionAuthorityKey,
    ) -> Result<PortableDevSupervisionAuthorityKeyWriteOutcome, SupervisionAuthorityKeyError> {
        let PreparedPortableDevSupervisionAuthorityKey { receipt, secret } = prepared;
        receipt.validate()?;
        let root = open_portable_dev_root(
            &receipt.request.repository_root,
            receipt.request.repository_root_identity,
        )?;
        let path = portable_dev_key_path(&root, &receipt.request.relative_path)?;
        let parent = open_portable_dev_parent(&root, &path, true)?
            .ok_or(SupervisionAuthorityKeyError::ProviderUnavailable)?;
        let mut file = match UserOwnedPathLease::create_new(&parent, &path) {
            Ok(file) => file,
            Err(error) => {
                return match std::fs::symlink_metadata(&path) {
                    Err(metadata_error)
                        if metadata_error.kind() == std::io::ErrorKind::NotFound =>
                    {
                        Err(map_user_owned_path_error(error))
                    }
                    Ok(_) | Err(_) => {
                        Ok(PortableDevSupervisionAuthorityKeyWriteOutcome::Unknown { receipt })
                    }
                };
            }
        };
        let write_result = file.write_new_bytes(secret.expose());
        let durable_root = parent
            .verify_stable_identity()
            .and_then(|()| parent.verify_path_identity())
            .and_then(|()| root.verify_stable_identity())
            .and_then(|()| root.verify_path_identity());
        if write_result.is_err() || durable_root.is_err() {
            return Ok(PortableDevSupervisionAuthorityKeyWriteOutcome::Unknown { receipt });
        }
        match self.inspect(&receipt) {
            Ok(PortableDevSupervisionAuthorityKeyObservation::Matching { .. }) => {
                Ok(PortableDevSupervisionAuthorityKeyWriteOutcome::Created { receipt })
            }
            Ok(
                PortableDevSupervisionAuthorityKeyObservation::Absent { .. }
                | PortableDevSupervisionAuthorityKeyObservation::Mismatch { .. },
            )
            | Err(_) => Ok(PortableDevSupervisionAuthorityKeyWriteOutcome::Unknown { receipt }),
        }
    }

    /// Inspects only against the original durable receipt and trust anchor.
    pub fn inspect(
        &self,
        receipt: &PortableDevSupervisionAuthorityKeyReceipt,
    ) -> Result<PortableDevSupervisionAuthorityKeyObservation, SupervisionAuthorityKeyError> {
        receipt.validate()?;
        let request = &receipt.request;
        let root =
            open_portable_dev_root(&request.repository_root, request.repository_root_identity)?;
        let path = portable_dev_key_path(&root, &request.relative_path)?;
        let parent = open_portable_dev_parent(&root, &path, false)?;
        let Some(parent) = parent else {
            root.verify_stable_identity()
                .and_then(|()| root.verify_path_identity())
                .map_err(map_user_owned_path_error)?;
            return Ok(PortableDevSupervisionAuthorityKeyObservation::Absent {
                receipt: receipt.clone(),
            });
        };
        if let Err(error) = std::fs::symlink_metadata(&path) {
            if error.kind() == std::io::ErrorKind::NotFound {
                parent
                    .verify_stable_identity()
                    .and_then(|()| parent.verify_path_identity())
                    .and_then(|()| root.verify_stable_identity())
                    .and_then(|()| root.verify_path_identity())
                    .map_err(map_user_owned_path_error)?;
                return Ok(PortableDevSupervisionAuthorityKeyObservation::Absent {
                    receipt: receipt.clone(),
                });
            }
            return Err(SupervisionAuthorityKeyError::ProviderUnavailable);
        }
        let file =
            UserOwnedPathLease::open_existing(&parent, &path).map_err(map_user_owned_path_error)?;
        let bytes = match file.read_bounded(33) {
            Ok(bytes) => bytes,
            Err(crate::ProtectedPathError::SizeExceeded) => {
                file.verify_stable_identity()
                    .and_then(|()| file.verify_path_identity())
                    .and_then(|()| parent.verify_stable_identity())
                    .and_then(|()| parent.verify_path_identity())
                    .and_then(|()| root.verify_stable_identity())
                    .and_then(|()| root.verify_path_identity())
                    .map_err(map_user_owned_path_error)?;
                return Ok(PortableDevSupervisionAuthorityKeyObservation::Mismatch {
                    relative_path: request.relative_path.clone(),
                });
            }
            Err(error) => return Err(map_user_owned_path_error(error)),
        };
        file.verify_stable_identity()
            .and_then(|()| file.verify_path_identity())
            .and_then(|()| parent.verify_stable_identity())
            .and_then(|()| parent.verify_path_identity())
            .and_then(|()| root.verify_stable_identity())
            .and_then(|()| root.verify_path_identity())
            .map_err(map_user_owned_path_error)?;
        if bytes.len() != 32 {
            return Ok(PortableDevSupervisionAuthorityKeyObservation::Mismatch {
                relative_path: request.relative_path.clone(),
            });
        }
        let secret = CredentialSecret::from_bytes(bytes)
            .map_err(|_| SupervisionAuthorityKeyError::KeyInvalid)?;
        match signer_for_anchor(&secret, &receipt.trust_anchor) {
            Ok(_) => Ok(PortableDevSupervisionAuthorityKeyObservation::Matching {
                receipt: receipt.clone(),
            }),
            Err(
                SupervisionAuthorityKeyError::KeyInvalid
                | SupervisionAuthorityKeyError::InvalidBinding,
            ) => Ok(PortableDevSupervisionAuthorityKeyObservation::Mismatch {
                relative_path: request.relative_path.clone(),
            }),
            Err(error) => Err(error),
        }
    }

    /// Deletes only a file whose retained bytes still derive the exact
    /// transaction receipt's public key, then confirms the exact path is
    /// absent beneath the same repository-root object.
    pub fn delete_if_matching(
        &self,
        receipt: &PortableDevSupervisionAuthorityKeyReceipt,
    ) -> Result<(), SupervisionAuthorityKeyError> {
        match self.inspect(receipt)? {
            PortableDevSupervisionAuthorityKeyObservation::Matching { .. } => {}
            PortableDevSupervisionAuthorityKeyObservation::Absent { .. }
            | PortableDevSupervisionAuthorityKeyObservation::Mismatch { .. } => {
                return Err(SupervisionAuthorityKeyError::InvalidBinding);
            }
        }
        let request = &receipt.request;
        let root =
            open_portable_dev_root(&request.repository_root, request.repository_root_identity)?;
        let path = portable_dev_key_path(&root, &request.relative_path)?;
        let parent = open_portable_dev_parent(&root, &path, false)?
            .ok_or(SupervisionAuthorityKeyError::InvalidBinding)?;
        let path_lease =
            UserOwnedPathLease::open_existing(&parent, &path).map_err(map_user_owned_path_error)?;
        let expected_identity = path_lease.identity();
        let bytes = path_lease
            .read_bounded(33)
            .map_err(map_user_owned_path_error)?;
        if bytes.len() != 32 {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        signer_for_anchor(
            &CredentialSecret::from_bytes(bytes)
                .map_err(|_| SupervisionAuthorityKeyError::KeyInvalid)?,
            &receipt.trust_anchor,
        )?;
        path_lease
            .verify_stable_identity()
            .and_then(|()| path_lease.verify_path_identity())
            .and_then(|()| parent.verify_stable_identity())
            .and_then(|()| parent.verify_path_identity())
            .and_then(|()| root.verify_stable_identity())
            .and_then(|()| root.verify_path_identity())
            .map_err(map_user_owned_path_error)?;
        drop(path_lease);
        let (identity, file) =
            crate::open_no_follow_file_for_delete(&path).map_err(map_user_owned_path_error)?;
        if identity != expected_identity {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        crate::delete_owned_file_handle(file, identity).map_err(map_user_owned_path_error)?;
        parent
            .verify_stable_identity()
            .and_then(|()| parent.verify_path_identity())
            .and_then(|()| root.verify_stable_identity())
            .and_then(|()| root.verify_path_identity())
            .map_err(map_user_owned_path_error)?;
        match self.inspect(receipt)? {
            PortableDevSupervisionAuthorityKeyObservation::Absent { .. } => Ok(()),
            PortableDevSupervisionAuthorityKeyObservation::Matching { .. }
            | PortableDevSupervisionAuthorityKeyObservation::Mismatch { .. } => {
                Err(SupervisionAuthorityKeyError::InvalidBinding)
            }
        }
    }

    /// Loads a signer only from the reference below the retained `PortableDev`
    /// repository-root identity and compares the derived public key to the
    /// original descriptor trust anchor.
    pub fn load_signer_for_kernel(
        &self,
        reference: &PortableDevSupervisionKeyReference,
        repository_root: &Path,
        expected_repository_root_identity: FileIdentity,
        trust_anchor: &SupervisionTrustAnchor,
    ) -> Result<Ed25519SupervisionLeaseSigner, SupervisionAuthorityKeyError> {
        reference.validate().map_err(map_contract_error)?;
        trust_anchor.validate().map_err(map_contract_error)?;
        let root = open_portable_dev_root(repository_root, expected_repository_root_identity)?;
        let path = portable_dev_key_path(&root, &reference.relative_path)?;
        let parent = open_portable_dev_parent(&root, &path, false)?
            .ok_or(SupervisionAuthorityKeyError::ProviderUnavailable)?;
        let file =
            UserOwnedPathLease::open_existing(&parent, &path).map_err(map_user_owned_path_error)?;
        let bytes = file.read_bounded(33).map_err(map_user_owned_path_error)?;
        file.verify_stable_identity()
            .and_then(|()| file.verify_path_identity())
            .and_then(|()| parent.verify_stable_identity())
            .and_then(|()| parent.verify_path_identity())
            .and_then(|()| root.verify_stable_identity())
            .and_then(|()| root.verify_path_identity())
            .map_err(map_user_owned_path_error)?;
        if bytes.len() != 32 {
            return Err(SupervisionAuthorityKeyError::KeyInvalid);
        }
        signer_for_anchor(
            &CredentialSecret::from_bytes(bytes)
                .map_err(|_| SupervisionAuthorityKeyError::KeyInvalid)?,
            trust_anchor,
        )
    }
}

/// Stateless DPAPI-NG service-SID key provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsSupervisionAuthorityKeyProvider;

impl WindowsSupervisionAuthorityKeyProvider {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Generates one Ed25519 seed and seals it to the exact SID string.
    ///
    /// No account alias is accepted. The descriptor passed to DPAPI-NG is
    /// exactly `SID=S-1-5-80-...`.
    pub fn generate_and_seal(
        &self,
        service_sid: &str,
        installation_id: &str,
        signer_id: &str,
        key_id: &str,
    ) -> Result<SealedSupervisionAuthorityKey, SupervisionAuthorityKeyError> {
        if !valid_service_sid_text(service_sid)
            || [installation_id, signer_id, key_id]
                .iter()
                .any(|value| value.is_empty() || *value != value.trim())
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let mut seed = [0_u8; 32];
        fill_system_random(&mut seed)
            .map_err(|_| SupervisionAuthorityKeyError::RandomUnavailable)?;
        if seed.iter().all(|byte| *byte == 0) {
            return Err(SupervisionAuthorityKeyError::RandomUnavailable);
        }
        let signer = Ed25519SupervisionLeaseSigner::from_secret_key(signer_id, key_id, seed)
            .map_err(map_contract_error)?;
        let anchor = SupervisionTrustAnchor::new(
            installation_id,
            signer_id,
            key_id,
            signer.public_key().to_vec(),
        )
        .map_err(map_contract_error)?;
        let sealed = protect_for_service_sid(service_sid, &seed);
        seed.fill(0);
        let sealed_blob = sealed?;
        Ok(SealedSupervisionAuthorityKey {
            sealed_blob,
            trust_anchor: anchor,
        })
    }

    /// Unseals one seed only when the embedded descriptor is the exact
    /// installer-pinned service SID. DPAPI token admission alone is not used
    /// as the serialized provider-identity check.
    pub fn unseal(
        &self,
        expected_service_sid: &str,
        sealed_blob: &[u8],
    ) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
        if !valid_service_sid_text(expected_service_sid) || sealed_blob.is_empty() {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        unprotect_for_service_sid(expected_service_sid, sealed_blob)
    }
}

/// Immutable request used by the installer effect and its recovery path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionAuthorityKeyStoreRequest {
    pub transaction_id: String,
    pub effect_id: String,
    pub installation_plan_digest: String,
    pub installation_id: String,
    pub candidate_generation: String,
    pub authority_generation: ResourceGeneration,
    pub supervision_lease_scope_id: String,
    pub signer_id: String,
    pub key_id: String,
    pub kernel_root: PathBuf,
    pub relative_path: String,
    pub expected_host_service_sid: String,
}

impl SupervisionAuthorityKeyStoreRequest {
    fn validate(&self) -> Result<(), SupervisionAuthorityKeyError> {
        if [
            self.transaction_id.as_str(),
            self.effect_id.as_str(),
            self.installation_id.as_str(),
            self.candidate_generation.as_str(),
            self.supervision_lease_scope_id.as_str(),
            self.signer_id.as_str(),
            self.key_id.as_str(),
        ]
        .iter()
        .any(|value| value.is_empty() || *value != value.trim())
            || !valid_digest(&self.installation_plan_digest)
            || !self.kernel_root.is_absolute()
            || !valid_service_sid_text(&self.expected_host_service_sid)
            || !single_relative_component(&self.relative_path)
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(())
    }

    fn path(&self) -> PathBuf {
        self.kernel_root.join(&self.relative_path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedKeyEnvelope {
    wire: String,
    transaction_id: String,
    effect_id: String,
    installation_plan_digest: String,
    authority: ProvisionedSupervisionAuthority,
    sealed_blob: Vec<u8>,
    ownership_mac: String,
}

impl SealedKeyEnvelope {
    fn mac_payload(&self) -> Result<Vec<u8>, SupervisionAuthorityKeyError> {
        serde_json::to_vec(&(
            self.wire.as_str(),
            self.transaction_id.as_str(),
            self.effect_id.as_str(),
            self.installation_plan_digest.as_str(),
            &self.authority,
            &self.sealed_blob,
        ))
        .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)
    }

    fn validate(
        &self,
        request: &SupervisionAuthorityKeyStoreRequest,
        object: &InstallerRootObjectSnapshot,
        ownership_key: &[u8],
    ) -> Result<(), SupervisionAuthorityKeyError> {
        request.validate()?;
        self.authority.validate().map_err(map_contract_error)?;
        let Some(key_reference) = self.authority.key_reference.as_system_service() else {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        };
        if self.wire != SEALED_KEY_ENVELOPE_WIRE
            || self.transaction_id != request.transaction_id
            || self.effect_id != request.effect_id
            || self.installation_plan_digest != request.installation_plan_digest
            || self.authority.supervision_lease_scope_id != request.supervision_lease_scope_id
            || self.authority.candidate_generation != request.candidate_generation
            || self.authority.authority_generation != request.authority_generation
            || self.authority.trust_anchor.installation_id != request.installation_id
            || self.authority.trust_anchor.signer_id != request.signer_id
            || self.authority.trust_anchor.key_id != request.key_id
            || key_reference.relative_path != request.relative_path
            || key_reference.host_service_sid != request.expected_host_service_sid
            || key_reference.file_identity != file_identity(object)
            || key_reference.sealed_blob_sha256 != sha256_hex(&self.sealed_blob)
            || !constant_time_eq(
                self.ownership_mac.as_bytes(),
                hmac_sha256_hex(ownership_key, &self.mac_payload()?).as_bytes(),
            )
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(())
    }
}

/// Atomic ciphertext store used only by the sealed installer effect.
#[derive(Debug, Default)]
pub struct WindowsSupervisionAuthorityKeyStore {
    primitive: WindowsInstallerRootPrimitive,
    provider: WindowsSupervisionAuthorityKeyProvider,
}

impl WindowsSupervisionAuthorityKeyStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            primitive: WindowsInstallerRootPrimitive::new(),
            provider: WindowsSupervisionAuthorityKeyProvider::new(),
        }
    }

    /// Creates a new ciphertext file or reconciles only an HMAC-proven prior
    /// create from the same durable transaction intent.
    pub fn create_or_reconcile(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        request: &SupervisionAuthorityKeyStoreRequest,
        ownership_key: &[u8],
    ) -> Result<ProvisionedSupervisionAuthority, SupervisionAuthorityKeyError> {
        request.validate()?;
        if ownership_key.len() < 32 || ownership_key.iter().all(|byte| *byte == 0) {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let live_host_sid = resolve_service_sid(SUPERVISION_AUTHORITY_HOST_SERVICE)?;
        if live_host_sid != request.expected_host_service_sid {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let path = request.path();
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return self.inspect(spec, request, ownership_key),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SupervisionAuthorityKeyError::ProviderUnavailable),
        }
        let sealed = self.provider.generate_and_seal(
            &live_host_sid,
            &request.installation_id,
            &request.signer_id,
            &request.key_id,
        )?;
        let sealed_blob_digest = sha256_hex(&sealed.sealed_blob);
        let mut result = None;
        let create = self.primitive.create_protected_file(spec, &path, |object| {
            let reference = SupervisionSealedKeyReference::new(
                request.relative_path.clone(),
                live_host_sid.clone(),
                file_identity(object),
                sealed_blob_digest.clone(),
            )
            .map_err(|_| InstallerRootError::ReceiptMismatch)?;
            let authority = ProvisionedSupervisionAuthority::new(
                request.supervision_lease_scope_id.clone(),
                request.candidate_generation.clone(),
                request.authority_generation,
                reference,
                sealed.trust_anchor.clone(),
            )
            .map_err(|_| InstallerRootError::ReceiptMismatch)?;
            let mut envelope = SealedKeyEnvelope {
                wire: SEALED_KEY_ENVELOPE_WIRE.to_owned(),
                transaction_id: request.transaction_id.clone(),
                effect_id: request.effect_id.clone(),
                installation_plan_digest: request.installation_plan_digest.clone(),
                authority: authority.clone(),
                sealed_blob: sealed.sealed_blob.clone(),
                ownership_mac: String::new(),
            };
            envelope.ownership_mac = hmac_sha256_hex(
                ownership_key,
                &envelope
                    .mac_payload()
                    .map_err(|_| InstallerRootError::ReceiptMismatch)?,
            );
            let bytes =
                serde_json::to_vec(&envelope).map_err(|_| InstallerRootError::ReceiptMismatch)?;
            result = Some(authority);
            Ok(bytes)
        });
        match create {
            Ok(_) => result.ok_or(SupervisionAuthorityKeyError::ProviderUnavailable),
            Err(InstallerRootError::ReceiptMismatch) => self.inspect(spec, request, ownership_key),
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// Reads and validates the exact provider/file/transaction identity.
    pub fn inspect(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        request: &SupervisionAuthorityKeyStoreRequest,
        ownership_key: &[u8],
    ) -> Result<ProvisionedSupervisionAuthority, SupervisionAuthorityKeyError> {
        request.validate()?;
        let readback = self
            .primitive
            .read_protected_file(spec, &request.path(), SEALED_KEY_FILE_LIMIT)
            .map_err(map_store_error)?;
        let envelope: SealedKeyEnvelope = serde_json::from_slice(&readback.bytes)
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        envelope.validate(request, &readback.object, ownership_key)?;
        Ok(envelope.authority)
    }

    /// Reads the exact HMAC receipt and deletes only that retained file.
    pub fn delete(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        request: &SupervisionAuthorityKeyStoreRequest,
        ownership_key: &[u8],
    ) -> Result<(), SupervisionAuthorityKeyError> {
        let readback = self
            .primitive
            .read_protected_file(spec, &request.path(), SEALED_KEY_FILE_LIMIT)
            .map_err(map_store_error)?;
        let envelope: SealedKeyEnvelope = serde_json::from_slice(&readback.bytes)
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        envelope.validate(request, &readback.object, ownership_key)?;
        self.primitive
            .delete_file(&request.path(), &readback.object)
            .map_err(map_store_error)
    }

    /// Kernel-only ciphertext read and DPAPI-NG unseal after exact file and
    /// provider identity revalidation.
    pub fn unseal_for_kernel(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        kernel_root: &Path,
        authority: &ProvisionedSupervisionAuthority,
    ) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
        authority.validate().map_err(map_contract_error)?;
        let Some(key_reference) = authority.key_reference.as_system_service() else {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        };
        if !kernel_root.is_absolute() || !single_relative_component(&key_reference.relative_path) {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let path = kernel_root.join(&key_reference.relative_path);
        let readback = self
            .primitive
            .read_protected_file(spec, &path, SEALED_KEY_FILE_LIMIT)
            .map_err(map_store_error)?;
        let envelope: SealedKeyEnvelope = serde_json::from_slice(&readback.bytes)
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        if envelope.authority != *authority
            || key_reference.file_identity != file_identity(&readback.object)
            || key_reference.sealed_blob_sha256 != sha256_hex(&envelope.sealed_blob)
            || resolve_service_sid(SUPERVISION_AUTHORITY_HOST_SERVICE)?
                != key_reference.host_service_sid
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let secret = self
            .provider
            .unseal(&key_reference.host_service_sid, &envelope.sealed_blob)?;
        let signer = Ed25519SupervisionLeaseSigner::from_secret_key(
            authority.trust_anchor.signer_id.clone(),
            authority.trust_anchor.key_id.clone(),
            secret
                .expose()
                .try_into()
                .map_err(|_| SupervisionAuthorityKeyError::KeyInvalid)?,
        )
        .map_err(map_contract_error)?;
        if sha256_hex(&signer.public_key()) != authority.trust_anchor.public_key_fingerprint {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(secret)
    }
}

fn file_identity(object: &InstallerRootObjectSnapshot) -> SupervisionSealedKeyFileIdentity {
    SupervisionSealedKeyFileIdentity {
        canonical_path_digest: object.canonical_path_digest.clone(),
        volume_serial_number: object.volume_serial_number,
        file_index: object.file_index,
        security_descriptor_digest: object.security_descriptor_digest.clone(),
    }
}

fn single_relative_component(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_user_mode_authority_target(value: &str) -> bool {
    value
        .strip_prefix("eliot/supervision-authority/user-mode/v1/")
        .is_some_and(|suffix| {
            suffix.len() == 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn user_mode_authority_target(
    request: &UserModeSupervisionAuthorityCredentialRequest,
) -> Result<String, SupervisionAuthorityKeyError> {
    let mut digest = Sha256::new();
    digest.update(b"eliot-user-mode-supervision-credential-target-v1\0");
    for value in [
        request.installation_id.as_str(),
        request.transaction_id.as_str(),
        request.effect_id.as_str(),
        request.owner_sid.as_str(),
    ] {
        let length =
            u64::try_from(value.len()).map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        digest.update(length.to_le_bytes());
        digest.update(value.as_bytes());
    }
    Ok(format!(
        "eliot/supervision-authority/user-mode/v1/{:x}",
        digest.finalize()
    ))
}

fn open_portable_dev_root(
    repository_root: &Path,
    expected_identity: FileIdentity,
) -> Result<UserOwnedRootLease, SupervisionAuthorityKeyError> {
    if !repository_root.is_absolute()
        || expected_identity.volume_serial_number == 0
        || expected_identity.file_index == 0
    {
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    crate::reject_reparse_chain(repository_root, true).map_err(map_user_owned_path_error)?;
    let root =
        UserOwnedRootLease::open_existing(repository_root).map_err(map_user_owned_path_error)?;
    let canonical = root.canonical_path().map_err(map_user_owned_path_error)?;
    if root.identity() != expected_identity
        || !crate::windows_paths_equal(&canonical, repository_root)
    {
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    root.verify_stable_identity()
        .and_then(|()| root.verify_path_identity())
        .map_err(map_user_owned_path_error)?;
    Ok(root)
}

fn portable_dev_key_path(
    root: &UserOwnedRootLease,
    relative_path: &str,
) -> Result<PathBuf, SupervisionAuthorityKeyError> {
    PortableDevSupervisionKeyReference::new(relative_path.to_owned())
        .map_err(map_contract_error)?;
    let file_name = relative_path
        .strip_prefix(PORTABLE_DEV_SUPERVISION_KEY_PREFIX)
        .filter(|name| single_relative_component(name) && !name.contains('\\'))
        .ok_or(SupervisionAuthorityKeyError::InvalidBinding)?;
    let path = root.path().join(relative_path);
    if path.file_name().and_then(|value| value.to_str()) != Some(file_name)
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    Ok(path)
}

fn open_portable_dev_parent(
    root: &UserOwnedRootLease,
    key_path: &Path,
    create_supervision_directory: bool,
) -> Result<Option<UserOwnedRootLease>, SupervisionAuthorityKeyError> {
    let repository_root = root.path();
    let state_path = repository_root.join(".eliot-dev").join("state");
    let supervision_path = state_path.join("supervision");
    let expected_key_path = supervision_path.join(
        key_path
            .file_name()
            .ok_or(SupervisionAuthorityKeyError::InvalidBinding)?,
    );
    if !crate::windows_paths_equal(key_path, &expected_key_path) {
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    crate::reject_reparse_chain(key_path, false).map_err(map_user_owned_path_error)?;
    root.verify_stable_identity()
        .and_then(|()| root.verify_path_identity())
        .map_err(map_user_owned_path_error)?;

    let mut missing_ancestor = false;
    for directory in [repository_root.join(".eliot-dev"), state_path.clone()] {
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(SupervisionAuthorityKeyError::InvalidBinding),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing_ancestor = true;
                break;
            }
            Err(error) => return Err(map_io_error(&error)),
        }
    }
    if missing_ancestor {
        if create_supervision_directory {
            return Err(SupervisionAuthorityKeyError::ProviderUnavailable);
        }
        root.verify_stable_identity()
            .and_then(|()| root.verify_path_identity())
            .map_err(map_user_owned_path_error)?;
        return Ok(None);
    }

    let state_root =
        UserOwnedRootLease::open_existing(&state_path).map_err(map_user_owned_path_error)?;
    let parent = match std::fs::symlink_metadata(&supervision_path) {
        Ok(metadata) if metadata.is_dir() => Some(
            UserOwnedRootLease::open_existing(&supervision_path)
                .map_err(map_user_owned_path_error)?,
        ),
        Ok(_) => return Err(SupervisionAuthorityKeyError::InvalidBinding),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if create_supervision_directory {
                Some(
                    state_root
                        .open_or_create_child_directory("supervision")
                        .map_err(map_user_owned_path_error)?,
                )
            } else {
                None
            }
        }
        Err(error) => return Err(map_io_error(&error)),
    };
    if let Some(parent) = &parent {
        let canonical = parent.canonical_path().map_err(map_user_owned_path_error)?;
        if !crate::windows_paths_equal(&canonical, &supervision_path) {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        parent
            .verify_stable_identity()
            .and_then(|()| parent.verify_path_identity())
            .map_err(map_user_owned_path_error)?;
    }
    state_root
        .verify_stable_identity()
        .and_then(|()| state_root.verify_path_identity())
        .and_then(|()| root.verify_stable_identity())
        .and_then(|()| root.verify_path_identity())
        .map_err(map_user_owned_path_error)?;
    Ok(parent)
}

fn signer_for_anchor(
    secret: &CredentialSecret,
    trust_anchor: &SupervisionTrustAnchor,
) -> Result<Ed25519SupervisionLeaseSigner, SupervisionAuthorityKeyError> {
    trust_anchor.validate().map_err(map_contract_error)?;
    if secret.expose().len() != 32 {
        return Err(SupervisionAuthorityKeyError::KeyInvalid);
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(secret.expose());
    let signer_result = Ed25519SupervisionLeaseSigner::from_secret_key(
        trust_anchor.signer_id.clone(),
        trust_anchor.key_id.clone(),
        seed,
    );
    seed.fill(0);
    let signer = signer_result.map_err(map_contract_error)?;
    if signer.public_key().as_slice() != trust_anchor.public_key.as_slice() {
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    Ok(signer)
}

fn map_user_owned_path_error(error: ProtectedPathError) -> SupervisionAuthorityKeyError {
    match error {
        ProtectedPathError::AclMismatch | ProtectedPathError::Win32 { code: 5, .. } => {
            SupervisionAuthorityKeyError::AccessDenied
        }
        ProtectedPathError::InvalidRoot
        | ProtectedPathError::InvalidPath
        | ProtectedPathError::ReparsePoint
        | ProtectedPathError::IdentityMismatch => SupervisionAuthorityKeyError::InvalidBinding,
        ProtectedPathError::Io
        | ProtectedPathError::Win32 { .. }
        | ProtectedPathError::SizeExceeded
        | ProtectedPathError::UnsupportedPlatform => {
            SupervisionAuthorityKeyError::ProviderUnavailable
        }
    }
}

fn map_io_error(error: &std::io::Error) -> SupervisionAuthorityKeyError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => SupervisionAuthorityKeyError::AccessDenied,
        std::io::ErrorKind::NotFound => SupervisionAuthorityKeyError::InvalidBinding,
        _ => SupervisionAuthorityKeyError::ProviderUnavailable,
    }
}

fn provider_receipt_matches(
    provider: &CurrentUserSupervisionCredentialWriteReceipt,
    receipt: &UserModeSupervisionAuthorityCredentialReceipt,
) -> bool {
    provider.owner_sid.as_str() == receipt.request.owner_sid && provider.target == receipt.target
}

fn map_current_user_credential_error(error: WindowsAdapterError) -> SupervisionAuthorityKeyError {
    match error {
        WindowsAdapterError::PermissionDenied | WindowsAdapterError::AclMismatch => {
            SupervisionAuthorityKeyError::AccessDenied
        }
        WindowsAdapterError::InvalidInput
        | WindowsAdapterError::IdentityMismatch
        | WindowsAdapterError::AlreadyExists => SupervisionAuthorityKeyError::InvalidBinding,
        WindowsAdapterError::NotFound
        | WindowsAdapterError::Unavailable
        | WindowsAdapterError::Timeout
        | WindowsAdapterError::Failed
        | WindowsAdapterError::RevertToSelf { .. } => {
            SupervisionAuthorityKeyError::ProviderUnavailable
        }
    }
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    format!("{:x}", outer.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn map_store_error(error: InstallerRootError) -> SupervisionAuthorityKeyError {
    match error {
        InstallerRootError::SecurityMismatch | InstallerRootError::IdentityMismatch => {
            SupervisionAuthorityKeyError::InvalidBinding
        }
        InstallerRootError::NotElevated => SupervisionAuthorityKeyError::AccessDenied,
        _ => SupervisionAuthorityKeyError::ProviderUnavailable,
    }
}

fn map_contract_error(_error: SupervisionLeaseError) -> SupervisionAuthorityKeyError {
    SupervisionAuthorityKeyError::KeyInvalid
}

fn provider_error() -> SupervisionAuthorityKeyError {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(5) => SupervisionAuthorityKeyError::AccessDenied,
        _ => SupervisionAuthorityKeyError::ProviderUnavailable,
    }
}

fn protection_descriptor(service_sid: &str) -> Result<String, SupervisionAuthorityKeyError> {
    if !valid_service_sid_text(service_sid) {
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    Ok(format!("SID={service_sid}"))
}

#[cfg(windows)]
fn protect_for_service_sid(
    service_sid: &str,
    secret: &[u8],
) -> Result<Vec<u8>, SupervisionAuthorityKeyError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_SILENT_FLAG, NCryptCloseProtectionDescriptor, NCryptCreateProtectionDescriptor,
        NCryptProtectSecret,
    };
    let descriptor = protection_descriptor(service_sid)?
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut handle = std::ptr::null_mut();
    let created =
        unsafe { NCryptCreateProtectionDescriptor(descriptor.as_ptr(), 0, &raw mut handle) };
    if created < 0 || handle.is_null() {
        return Err(provider_error());
    }
    let mut output = std::ptr::null_mut();
    let mut output_len = 0_u32;
    let status = unsafe {
        NCryptProtectSecret(
            handle,
            NCRYPT_SILENT_FLAG,
            secret.as_ptr(),
            u32::try_from(secret.len())
                .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?,
            std::ptr::null(),
            std::ptr::null_mut(),
            &raw mut output,
            &raw mut output_len,
        )
    };
    unsafe {
        NCryptCloseProtectionDescriptor(handle);
    }
    if status < 0 || output.is_null() || output_len == 0 {
        if !output.is_null() {
            unsafe { LocalFree(output.cast()) };
        }
        return Err(provider_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output, usize::try_from(output_len).unwrap_or(0)).to_vec()
    };
    unsafe { LocalFree(output.cast()) };
    if bytes.is_empty() {
        Err(SupervisionAuthorityKeyError::ProviderUnavailable)
    } else {
        Ok(bytes)
    }
}

#[cfg(not(windows))]
fn protect_for_service_sid(
    _service_sid: &str,
    _secret: &[u8],
) -> Result<Vec<u8>, SupervisionAuthorityKeyError> {
    Err(SupervisionAuthorityKeyError::ProviderUnavailable)
}

#[cfg(windows)]
fn unprotect_for_service_sid(
    expected_service_sid: &str,
    sealed_blob: &[u8],
) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING, NCRYPT_SILENT_FLAG,
        NCryptCloseProtectionDescriptor, NCryptGetProtectionDescriptorInfo, NCryptUnprotectSecret,
    };
    let expected_descriptor = protection_descriptor(expected_service_sid)?;
    let mut handle = std::ptr::null_mut();
    let mut output = std::ptr::null_mut();
    let mut output_len = 0_u32;
    let status = unsafe {
        NCryptUnprotectSecret(
            &raw mut handle,
            NCRYPT_SILENT_FLAG,
            sealed_blob.as_ptr(),
            u32::try_from(sealed_blob.len())
                .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?,
            std::ptr::null(),
            std::ptr::null_mut(),
            &raw mut output,
            &raw mut output_len,
        )
    };
    if status < 0 || handle.is_null() || output.is_null() || output_len == 0 {
        if !handle.is_null() {
            unsafe { NCryptCloseProtectionDescriptor(handle) };
        }
        if !output.is_null() {
            unsafe { LocalFree(output.cast()) };
        }
        return Err(provider_error());
    }
    let mut descriptor_ptr = std::ptr::null_mut();
    let descriptor_status = unsafe {
        NCryptGetProtectionDescriptorInfo(
            handle,
            std::ptr::null(),
            NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING,
            &raw mut descriptor_ptr,
        )
    };
    let descriptor = if descriptor_status < 0 || descriptor_ptr.is_null() {
        None
    } else {
        let wide = descriptor_ptr.cast::<u16>();
        let mut length = 0_usize;
        while unsafe { *wide.add(length) } != 0 {
            length += 1;
        }
        Some(
            unsafe { std::ffi::OsString::from_wide(std::slice::from_raw_parts(wide, length)) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    if !descriptor_ptr.is_null() {
        unsafe { LocalFree(descriptor_ptr) };
    }
    unsafe { NCryptCloseProtectionDescriptor(handle) };
    if descriptor.as_deref() != Some(expected_descriptor.as_str()) {
        unsafe { LocalFree(output.cast()) };
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output, usize::try_from(output_len).unwrap_or(0)).to_vec()
    };
    unsafe { LocalFree(output.cast()) };
    if bytes.len() != 32 || bytes.iter().all(|byte| *byte == 0) {
        return Err(SupervisionAuthorityKeyError::KeyInvalid);
    }
    Ok(CredentialSecret(bytes))
}

#[cfg(not(windows))]
fn unprotect_for_service_sid(
    _expected_service_sid: &str,
    _sealed_blob: &[u8],
) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
    Err(SupervisionAuthorityKeyError::ProviderUnavailable)
}

impl From<WindowsAdapterError> for SupervisionAuthorityKeyError {
    fn from(error: WindowsAdapterError) -> Self {
        match error {
            WindowsAdapterError::PermissionDenied => Self::AccessDenied,
            WindowsAdapterError::InvalidInput | WindowsAdapterError::IdentityMismatch => {
                Self::InvalidBinding
            }
            _ => Self::ProviderUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_descriptor_requires_exact_service_sid_text() {
        assert_eq!(
            protection_descriptor("S-1-5-80-1-2-3-4-5")
                .unwrap_or_else(|error| panic!("descriptor: {error}")),
            "SID=S-1-5-80-1-2-3-4-5"
        );
        assert!(protection_descriptor("NT SERVICE\\EliotHost").is_err());
        assert!(protection_descriptor("S-1-5-19").is_err());
    }
}
