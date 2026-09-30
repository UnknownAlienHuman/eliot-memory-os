//! Public identity for the installer-provisioned supervision signing authority.
//!
//! The contract contains only profile-specific non-secret signing-key
//! references and a public trust anchor. Signing key bytes never cross this
//! boundary.

use eliot_contracts::{ResourceGeneration, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    RegisteredActivityWakePolicy, SupervisionLeaseError, SupervisionObservationScope,
    SupervisionTrustAnchor, WatchdogAdmissionTemplate, canonical_observation_scope,
    canonical_wake_policy,
};

/// Current Windows provider used for service-SID-bound key sealing.
pub const WINDOWS_SERVICE_SID_DPAPI_NG_PROVIDER: &str = "windows-dpapi-ng-service-sid-v1";
/// Current-user Windows Credential Manager provider for `UserMode` authority.
pub const WINDOWS_CURRENT_USER_CREDENTIAL_MANAGER_PROVIDER: &str =
    "windows-credential-manager-current-user-v1";
/// Repository-local disposable provider for `PortableDev` authority.
pub const PORTABLE_DEV_DISPOSABLE_KEY_PROVIDER: &str = "repository-local-disposable-v1";
/// Reserved Credential Manager target namespace for `UserMode` supervision keys.
pub const USER_MODE_SUPERVISION_CREDENTIAL_TARGET_PREFIX: &str =
    "eliot/supervision-authority/user-mode/v1/";
/// Required repository-local contour for disposable `PortableDev` supervision keys.
pub const PORTABLE_DEV_SUPERVISION_KEY_PREFIX: &str = ".eliot-dev/state/supervision/";
/// Exact SCM service identity whose token admits Kernel key unsealing.
pub const SUPERVISION_AUTHORITY_HOST_SERVICE: &str = "EliotHost";
/// SCM `SERVICE_SID_TYPE_UNRESTRICTED` selected by the installer.
pub const SUPERVISION_AUTHORITY_SERVICE_SID_TYPE: u32 = 1;

/// Exact protected ciphertext-file identity retained by the installer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionSealedKeyFileIdentity {
    /// SHA-256 of the canonical final path observed from the retained handle.
    pub canonical_path_digest: String,
    /// NTFS volume serial number observed from the retained handle.
    pub volume_serial_number: u32,
    /// NTFS file index observed from the retained handle.
    pub file_index: u64,
    /// SHA-256 of the exact protected security descriptor.
    pub security_descriptor_digest: String,
}

impl SupervisionSealedKeyFileIdentity {
    /// Validates the complete protected file identity.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        digest(
            &self.canonical_path_digest,
            "sealed_key.canonical_path_digest",
        )?;
        if self.volume_serial_number == 0 || self.file_index == 0 {
            return Err(invalid(
                "sealed key file volume serial and file index must be non-zero",
            ));
        }
        digest(
            &self.security_descriptor_digest,
            "sealed_key.security_descriptor_digest",
        )
    }
}

/// Typed non-secret reference to a DPAPI-NG sealed signing key.
///
/// `relative_path` is resolved only below the already approved Kernel work
/// root. Absolute paths, parent traversal and platform separator aliases are
/// rejected so a serialized reference cannot select an ambient key file.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionSealedKeyReference {
    /// Exact provider discriminator; no provider fallback is permitted.
    pub provider: String,
    /// Canonical path below the approved Kernel work root.
    pub relative_path: String,
    /// Exact SCM service name configured with a service SID.
    pub host_service_name: String,
    /// Exact `NT SERVICE\\EliotHost` SID observed after SCM configuration.
    pub host_service_sid: String,
    /// Exact SCM service SID type read back by the installer.
    pub service_sid_type: u32,
    /// Retained identity of the ciphertext file.
    pub file_identity: SupervisionSealedKeyFileIdentity,
    /// SHA-256 of only the DPAPI-NG protected blob, never plaintext bytes.
    pub sealed_blob_sha256: String,
    /// Digest of every provider-identity field above.
    pub provider_identity_digest: String,
}

impl SupervisionSealedKeyReference {
    /// Constructs and seals one exact provider identity.
    pub fn new(
        relative_path: impl Into<String>,
        host_service_sid: impl Into<String>,
        file_identity: SupervisionSealedKeyFileIdentity,
        sealed_blob_sha256: impl Into<String>,
    ) -> Result<Self, SupervisionLeaseError> {
        let mut value = Self {
            provider: WINDOWS_SERVICE_SID_DPAPI_NG_PROVIDER.to_owned(),
            relative_path: relative_path.into(),
            host_service_name: SUPERVISION_AUTHORITY_HOST_SERVICE.to_owned(),
            host_service_sid: host_service_sid.into(),
            service_sid_type: SUPERVISION_AUTHORITY_SERVICE_SID_TYPE,
            file_identity,
            sealed_blob_sha256: sealed_blob_sha256.into(),
            provider_identity_digest: String::new(),
        };
        value.provider_identity_digest = value.computed_identity_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// Computes the provider identity without its self-digest.
    pub fn computed_identity_digest(&self) -> Result<String, SupervisionLeaseError> {
        let bytes = serde_json::to_vec(&(
            self.provider.as_str(),
            self.relative_path.as_str(),
            self.host_service_name.as_str(),
            self.host_service_sid.as_str(),
            self.service_sid_type,
            &self.file_identity,
            self.sealed_blob_sha256.as_str(),
        ))
        .map_err(|error| invalid(format!("sealed key identity serialization failed: {error}")))?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates the provider, service-SID and protected-file binding.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        if self.provider != WINDOWS_SERVICE_SID_DPAPI_NG_PROVIDER {
            return Err(invalid("unsupported supervision sealed-key provider"));
        }
        validate_relative_key_path(&self.relative_path)?;
        if self.host_service_name != SUPERVISION_AUTHORITY_HOST_SERVICE {
            return Err(invalid("supervision key is not bound to EliotHost"));
        }
        validate_service_sid(&self.host_service_sid)?;
        if self.service_sid_type != SUPERVISION_AUTHORITY_SERVICE_SID_TYPE {
            return Err(invalid("EliotHost service SID type is not exact"));
        }
        self.file_identity.validate()?;
        digest(&self.sealed_blob_sha256, "sealed_key.sealed_blob_sha256")?;
        digest(
            &self.provider_identity_digest,
            "sealed_key.provider_identity_digest",
        )?;
        if self.provider_identity_digest != self.computed_identity_digest()? {
            return Err(invalid("sealed key provider identity digest mismatch"));
        }
        Ok(())
    }
}

/// Read-back receipt binding a `UserMode` supervision key to its Windows user.
///
/// This records the account SID observed by the current-user Credential
/// Manager provider. The installer/provider owns the OS read-back which makes
/// the receipt truthful; this dependency-light contract checks its exact SID
/// shape and binds it into the provision receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionOwnerSidReceipt {
    /// Exact Windows account SID observed by the current-user provider.
    pub owner_sid: String,
}

impl SupervisionOwnerSidReceipt {
    /// Constructs and validates one exact Windows account SID receipt.
    pub fn new(owner_sid: impl Into<String>) -> Result<Self, SupervisionLeaseError> {
        let value = Self {
            owner_sid: owner_sid.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates that the receipt identifies a user account SID.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        validate_user_sid(&self.owner_sid)
    }
}

/// Typed non-secret `UserMode` reference to a current-user Credential Manager key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserModeSupervisionKeyReference {
    /// Exact provider discriminator; no provider fallback is permitted.
    pub provider: String,
    /// Unpredictable target in the reserved supervision-key namespace.
    pub credential_target: String,
    /// Current Windows account SID observed by the provider on read-back.
    pub owner_sid_receipt: SupervisionOwnerSidReceipt,
}

impl UserModeSupervisionKeyReference {
    /// Constructs and validates one current-user Credential Manager reference.
    pub fn new(
        credential_target: impl Into<String>,
        owner_sid_receipt: SupervisionOwnerSidReceipt,
    ) -> Result<Self, SupervisionLeaseError> {
        let value = Self {
            provider: WINDOWS_CURRENT_USER_CREDENTIAL_MANAGER_PROVIDER.to_owned(),
            credential_target: credential_target.into(),
            owner_sid_receipt,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates provider, reserved target namespace and current-user receipt.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        if self.provider != WINDOWS_CURRENT_USER_CREDENTIAL_MANAGER_PROVIDER {
            return Err(invalid("unsupported UserMode supervision-key provider"));
        }
        validate_supervision_credential_target(&self.credential_target)?;
        self.owner_sid_receipt.validate()
    }
}

/// Typed non-secret reference to an explicitly disposable `PortableDev` key file.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableDevSupervisionKeyReference {
    /// Exact provider discriminator; it declares a disposable repository-local key.
    pub provider: String,
    /// Canonical path below the repository-local `.eliot-dev/state` contour.
    pub relative_path: String,
}

impl PortableDevSupervisionKeyReference {
    /// Constructs and validates one disposable repository-local key reference.
    pub fn new(relative_path: impl Into<String>) -> Result<Self, SupervisionLeaseError> {
        let value = Self {
            provider: PORTABLE_DEV_DISPOSABLE_KEY_PROVIDER.to_owned(),
            relative_path: relative_path.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the disposable provider and exact repository-local contour.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        if self.provider != PORTABLE_DEV_DISPOSABLE_KEY_PROVIDER {
            return Err(invalid("unsupported PortableDev supervision-key provider"));
        }
        validate_relative_key_path(&self.relative_path)?;
        if !self
            .relative_path
            .starts_with(PORTABLE_DEV_SUPERVISION_KEY_PREFIX)
            || self.relative_path.len() == PORTABLE_DEV_SUPERVISION_KEY_PREFIX.len()
        {
            return Err(invalid(
                "PortableDev supervision key must remain below the repository-local disposable state contour",
            ));
        }
        Ok(())
    }
}

/// Profile-specific, non-secret reference to the supervision signing authority.
///
/// The untagged wire representation keeps existing v2 `SystemService` references
/// byte-shape compatible: their provider and service-SID fields still identify
/// the existing struct. The other strict provider structs carry only fields
/// owned by their own profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SupervisionAuthorityKeyReference {
    /// Existing DPAPI-NG key sealed for the exact `EliotHost` service SID.
    SystemService(SupervisionSealedKeyReference),
    /// Current-user Credential Manager key bound to an owner-SID receipt.
    UserMode(UserModeSupervisionKeyReference),
    /// Disposable repository-local key for `PortableDev` only.
    PortableDev(PortableDevSupervisionKeyReference),
}

impl SupervisionAuthorityKeyReference {
    /// Validates one exact profile-specific provider reference.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        match self {
            Self::SystemService(reference) => reference.validate(),
            Self::UserMode(reference) => reference.validate(),
            Self::PortableDev(reference) => reference.validate(),
        }
    }

    /// Wraps an already validated `SystemService` DPAPI-NG reference.
    pub fn system_service(
        reference: SupervisionSealedKeyReference,
    ) -> Result<Self, SupervisionLeaseError> {
        reference.validate()?;
        Ok(Self::SystemService(reference))
    }

    /// Constructs one `UserMode` current-user reference; no caller builds one.
    pub fn user_mode(
        credential_target: impl Into<String>,
        owner_sid_receipt: SupervisionOwnerSidReceipt,
    ) -> Result<Self, SupervisionLeaseError> {
        Ok(Self::UserMode(UserModeSupervisionKeyReference::new(
            credential_target,
            owner_sid_receipt,
        )?))
    }

    /// Constructs one disposable `PortableDev` reference; no caller builds one.
    pub fn portable_dev(relative_path: impl Into<String>) -> Result<Self, SupervisionLeaseError> {
        Ok(Self::PortableDev(PortableDevSupervisionKeyReference::new(
            relative_path,
        )?))
    }

    /// Returns the service-SID-bound reference only for `SystemService`.
    pub fn as_system_service(&self) -> Option<&SupervisionSealedKeyReference> {
        match self {
            Self::SystemService(reference) => Some(reference),
            Self::UserMode(_) | Self::PortableDev(_) => None,
        }
    }

    /// Returns the exact provider discriminator for this reference variant.
    pub fn provider(&self) -> &str {
        match self {
            Self::SystemService(reference) => &reference.provider,
            Self::UserMode(reference) => &reference.provider,
            Self::PortableDev(reference) => &reference.provider,
        }
    }
}

impl From<SupervisionSealedKeyReference> for SupervisionAuthorityKeyReference {
    fn from(value: SupervisionSealedKeyReference) -> Self {
        Self::SystemService(value)
    }
}

impl From<UserModeSupervisionKeyReference> for SupervisionAuthorityKeyReference {
    fn from(value: UserModeSupervisionKeyReference) -> Self {
        Self::UserMode(value)
    }
}

impl From<PortableDevSupervisionKeyReference> for SupervisionAuthorityKeyReference {
    fn from(value: PortableDevSupervisionKeyReference) -> Self {
        Self::PortableDev(value)
    }
}

/// Public result of the installer-owned supervision authority effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedSupervisionAuthority {
    /// Strict public contract revision.
    pub contract_version: u16,
    /// Stable scope identity selected by the immutable generation plan.
    pub supervision_lease_scope_id: String,
    /// Immutable observation scope bound by the installer to this authority.
    pub observation_scope: SupervisionObservationScope,
    /// Immutable wake policy bound by the installer to this authority.
    pub wake_policy: RegisteredActivityWakePolicy,
    /// Candidate generation identity that owns this authority.
    pub candidate_generation: String,
    /// Exact lifecycle generation bound to the key and lease.
    pub authority_generation: ResourceGeneration,
    /// Non-secret, strictly validated profile-specific key reference.
    pub key_reference: SupervisionAuthorityKeyReference,
    /// Installation-pinned public Ed25519 trust anchor.
    pub trust_anchor: SupervisionTrustAnchor,
    /// Digest of the canonical public Watchdog admission template.
    pub watchdog_admission_template_digest: String,
    /// Digest of every field above, retained as the public provision receipt.
    pub provision_receipt_digest: String,
}

impl ProvisionedSupervisionAuthority {
    /// Current strict contract revision.
    ///
    /// Existing v2 `SystemService` key-reference JSON remains readable and keeps
    /// its original serialized receipt input shape; the two added provider
    /// variants use their own strict, provider-discriminated object shapes.
    pub const CONTRACT_VERSION: u16 = 2;

    /// Constructs a complete provision result and computes its public receipt.
    pub fn new(
        supervision_lease_scope_id: impl Into<String>,
        candidate_generation: impl Into<String>,
        authority_generation: ResourceGeneration,
        key_reference: impl Into<SupervisionAuthorityKeyReference>,
        trust_anchor: SupervisionTrustAnchor,
    ) -> Result<Self, SupervisionLeaseError> {
        let mut value = Self {
            contract_version: Self::CONTRACT_VERSION,
            supervision_lease_scope_id: supervision_lease_scope_id.into(),
            observation_scope: canonical_observation_scope(),
            wake_policy: canonical_wake_policy(),
            candidate_generation: candidate_generation.into(),
            authority_generation,
            key_reference: key_reference.into(),
            trust_anchor,
            watchdog_admission_template_digest: String::new(),
            provision_receipt_digest: String::new(),
        };
        value.watchdog_admission_template_digest = value
            .watchdog_admission_template()?
            .digest()
            .map_err(|error| invalid(error.to_string()))?;
        value.provision_receipt_digest = value.computed_receipt_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// Reconstructs the one canonical public Watchdog admission template.
    pub fn watchdog_admission_template(
        &self,
    ) -> Result<WatchdogAdmissionTemplate, SupervisionLeaseError> {
        let mut template = WatchdogAdmissionTemplate::new(
            self.trust_anchor.installation_id.clone(),
            self.candidate_generation.clone(),
            self.supervision_lease_scope_id.clone(),
            self.trust_anchor.clone(),
        )
        .map_err(|error| invalid(error.to_string()))?;
        template.observation_scope = self.observation_scope.clone();
        template.wake_policy = self.wake_policy.clone();
        template
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        Ok(template)
    }

    /// Computes the public provision receipt without its self-digest.
    pub fn computed_receipt_digest(&self) -> Result<String, SupervisionLeaseError> {
        let bytes = serde_json::to_vec(&(
            self.contract_version,
            self.supervision_lease_scope_id.as_str(),
            &self.observation_scope,
            &self.wake_policy,
            self.candidate_generation.as_str(),
            self.authority_generation,
            &self.key_reference,
            &self.trust_anchor,
            self.watchdog_admission_template_digest.as_str(),
        ))
        .map_err(|error| {
            invalid(format!(
                "supervision authority serialization failed: {error}"
            ))
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates the full installation, lifecycle and key-provider binding.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        if self.contract_version != Self::CONTRACT_VERSION {
            return Err(invalid(
                "unsupported provisioned supervision authority version",
            ));
        }
        non_empty(
            &self.supervision_lease_scope_id,
            "supervision_lease_scope_id",
        )?;
        self.observation_scope
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.wake_policy
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if self.observation_scope != canonical_observation_scope()
            || self.wake_policy != canonical_wake_policy()
        {
            return Err(invalid(
                "provisioned supervision authority uses a non-canonical observation policy",
            ));
        }
        non_empty(&self.candidate_generation, "candidate_generation")?;
        self.key_reference.validate()?;
        self.trust_anchor.validate()?;
        digest(
            &self.watchdog_admission_template_digest,
            "watchdog_admission_template_digest",
        )?;
        if self.watchdog_admission_template_digest
            != self
                .watchdog_admission_template()?
                .digest()
                .map_err(|error| invalid(error.to_string()))?
        {
            return Err(invalid("Watchdog admission template digest mismatch"));
        }
        digest(&self.provision_receipt_digest, "provision_receipt_digest")?;
        if self.provision_receipt_digest != self.computed_receipt_digest()? {
            return Err(invalid("supervision authority provision receipt mismatch"));
        }
        Ok(())
    }
}

fn validate_relative_key_path(value: &str) -> Result<(), SupervisionLeaseError> {
    let segments = value.split('/').collect::<Vec<_>>();
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains(['\\', ':'])
        || segments.iter().any(|segment| {
            segment.is_empty()
                || matches!(*segment, "." | "..")
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        })
    {
        return Err(invalid(
            "supervision key path must be canonical and relative to its admitted profile root",
        ));
    }
    Ok(())
}

fn validate_supervision_credential_target(value: &str) -> Result<(), SupervisionLeaseError> {
    let Some(token) = value.strip_prefix(USER_MODE_SUPERVISION_CREDENTIAL_TARGET_PREFIX) else {
        return Err(invalid(
            "UserMode supervision key target is outside its reserved Credential Manager namespace",
        ));
    };
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "UserMode supervision key target must have one lowercase SHA-256 token",
        ));
    }
    Ok(())
}

fn validate_user_sid(value: &str) -> Result<(), SupervisionLeaseError> {
    let Some(tail) = value
        .strip_prefix("S-1-5-21-")
        .or_else(|| value.strip_prefix("S-1-12-1-"))
    else {
        return Err(invalid(
            "UserMode supervision authority requires a Windows account SID",
        ));
    };
    let components = tail.split('-').collect::<Vec<_>>();
    if components.len() != 4
        || components.iter().any(|component| {
            component.is_empty()
                || (component.len() > 1 && component.starts_with('0'))
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || component.parse::<u32>().is_err()
        })
    {
        return Err(invalid("UserMode owner SID receipt is malformed"));
    }
    Ok(())
}

fn validate_service_sid(value: &str) -> Result<(), SupervisionLeaseError> {
    let Some(tail) = value.strip_prefix("S-1-5-80-") else {
        return Err(invalid("supervision authority requires an NT SERVICE SID"));
    };
    let components = tail.split('-').collect::<Vec<_>>();
    if components.len() != 5
        || components.iter().any(|component| {
            component.is_empty()
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || component.parse::<u32>().is_err()
        })
    {
        return Err(invalid("supervision authority service SID is malformed"));
    }
    Ok(())
}

fn digest(value: &str, field: &str) -> Result<(), SupervisionLeaseError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{field} must be lowercase SHA-256")));
    }
    Ok(())
}

fn non_empty(value: &str, field: &str) -> Result<(), SupervisionLeaseError> {
    if value.is_empty() || value != value.trim() || value.chars().any(char::is_control) {
        return Err(invalid(format!("{field} must be non-empty canonical text")));
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> SupervisionLeaseError {
    SupervisionLeaseError::InvalidContext(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_key_reference_mut(
        authority: &mut ProvisionedSupervisionAuthority,
    ) -> &mut SupervisionSealedKeyReference {
        match &mut authority.key_reference {
            SupervisionAuthorityKeyReference::SystemService(reference) => reference,
            SupervisionAuthorityKeyReference::UserMode(_)
            | SupervisionAuthorityKeyReference::PortableDev(_) => {
                panic!("expected a SystemService key reference")
            }
        }
    }

    fn authority() -> ProvisionedSupervisionAuthority {
        let file = SupervisionSealedKeyFileIdentity {
            canonical_path_digest: "1".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "2".repeat(64),
        };
        let reference = SupervisionSealedKeyReference::new(
            "supervision/authority-1.sealed",
            "S-1-5-80-1-2-3-4-5",
            file,
            "3".repeat(64),
        )
        .unwrap_or_else(|error| panic!("key reference: {error}"));
        let signer = crate::Ed25519SupervisionLeaseSigner::from_secret_key(
            "eliot-kernel",
            "supervision-key-1",
            [9; 32],
        )
        .unwrap_or_else(|error| panic!("signer: {error}"));
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            "eliot-kernel",
            "supervision-key-1",
            signer.public_key().to_vec(),
        )
        .unwrap_or_else(|error| panic!("anchor: {error}"));
        ProvisionedSupervisionAuthority::new(
            "lease-1",
            "generation-1",
            ResourceGeneration::genesis(),
            reference,
            anchor,
        )
        .unwrap_or_else(|error| panic!("authority: {error}"))
    }

    #[test]
    fn provisioned_authority_rejects_absolute_and_ambient_key_paths() {
        for path in [
            r"C:\ProgramData\Eliot\key.bin",
            "../key.bin",
            "supervision//key.bin",
        ] {
            let mut value = authority();
            let reference = service_key_reference_mut(&mut value);
            reference.relative_path = path.to_owned();
            reference.provider_identity_digest = reference
                .computed_identity_digest()
                .unwrap_or_else(|error| panic!("identity: {error}"));
            value.provision_receipt_digest = value
                .computed_receipt_digest()
                .unwrap_or_else(|error| panic!("receipt: {error}"));
            assert!(value.validate().is_err(), "accepted {path}");
        }
    }

    #[test]
    fn provisioned_authority_rejects_service_sid_and_provider_substitution() {
        let mut value = authority();
        let reference = service_key_reference_mut(&mut value);
        reference.host_service_sid = "S-1-5-19".to_owned();
        reference.provider_identity_digest = reference
            .computed_identity_digest()
            .unwrap_or_else(|error| panic!("identity: {error}"));
        value.provision_receipt_digest = value
            .computed_receipt_digest()
            .unwrap_or_else(|error| panic!("receipt: {error}"));
        assert!(value.validate().is_err());

        let mut value = authority();
        let reference = service_key_reference_mut(&mut value);
        reference.provider = "windows-credential-manager".to_owned();
        reference.provider_identity_digest = reference
            .computed_identity_digest()
            .unwrap_or_else(|error| panic!("identity: {error}"));
        value.provision_receipt_digest = value
            .computed_receipt_digest()
            .unwrap_or_else(|error| panic!("receipt: {error}"));
        assert!(value.validate().is_err());
    }

    #[test]
    fn provisioned_authority_rejects_stale_receipt_after_lifecycle_change() {
        let mut value = authority();
        value.candidate_generation = "generation-2".to_owned();
        assert!(value.validate().is_err());
    }
}
