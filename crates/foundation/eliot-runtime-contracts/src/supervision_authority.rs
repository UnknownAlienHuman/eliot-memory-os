//! Public identity for the installer-provisioned supervision signing authority.
//!
//! The contract contains only a DPAPI-NG ciphertext locator and public trust
//! anchor. Signing key bytes never cross this boundary.

use eliot_contracts::{ResourceGeneration, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{SupervisionLeaseError, SupervisionTrustAnchor, WatchdogAdmissionTemplate};

/// Current Windows provider used for service-SID-bound key sealing.
pub const WINDOWS_SERVICE_SID_DPAPI_NG_PROVIDER: &str = "windows-dpapi-ng-service-sid-v1";
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

/// Public result of the installer-owned supervision authority effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedSupervisionAuthority {
    /// Strict public contract revision.
    pub contract_version: u16,
    /// Stable lease identity selected by the immutable generation plan.
    pub supervision_lease_id: String,
    /// Candidate generation identity that owns this authority.
    pub candidate_generation: String,
    /// Exact lifecycle generation bound to the key and lease.
    pub authority_generation: ResourceGeneration,
    /// Non-secret, Kernel-root-relative sealed-key reference.
    pub key_reference: SupervisionSealedKeyReference,
    /// Installation-pinned public Ed25519 trust anchor.
    pub trust_anchor: SupervisionTrustAnchor,
    /// Digest of the canonical public Watchdog admission template.
    pub watchdog_admission_template_digest: String,
    /// Digest of every field above, retained as the public provision receipt.
    pub provision_receipt_digest: String,
}

impl ProvisionedSupervisionAuthority {
    /// Current strict contract revision.
    pub const CONTRACT_VERSION: u16 = 1;

    /// Constructs a complete provision result and computes its public receipt.
    pub fn new(
        supervision_lease_id: impl Into<String>,
        candidate_generation: impl Into<String>,
        authority_generation: ResourceGeneration,
        key_reference: SupervisionSealedKeyReference,
        trust_anchor: SupervisionTrustAnchor,
    ) -> Result<Self, SupervisionLeaseError> {
        let mut value = Self {
            contract_version: Self::CONTRACT_VERSION,
            supervision_lease_id: supervision_lease_id.into(),
            candidate_generation: candidate_generation.into(),
            authority_generation,
            key_reference,
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
        WatchdogAdmissionTemplate::new(
            self.trust_anchor.installation_id.clone(),
            self.candidate_generation.clone(),
            self.supervision_lease_id.clone(),
            self.trust_anchor.clone(),
        )
        .map_err(|error| invalid(error.to_string()))
    }

    /// Computes the public provision receipt without its self-digest.
    pub fn computed_receipt_digest(&self) -> Result<String, SupervisionLeaseError> {
        let bytes = serde_json::to_vec(&(
            self.contract_version,
            self.supervision_lease_id.as_str(),
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
        non_empty(&self.supervision_lease_id, "supervision_lease_id")?;
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
            "sealed key path must be canonical and relative to the Kernel root",
        ));
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
            value.key_reference.relative_path = path.to_owned();
            value.key_reference.provider_identity_digest = value
                .key_reference
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
        value.key_reference.host_service_sid = "S-1-5-19".to_owned();
        value.key_reference.provider_identity_digest = value
            .key_reference
            .computed_identity_digest()
            .unwrap_or_else(|error| panic!("identity: {error}"));
        value.provision_receipt_digest = value
            .computed_receipt_digest()
            .unwrap_or_else(|error| panic!("receipt: {error}"));
        assert!(value.validate().is_err());

        let mut value = authority();
        value.key_reference.provider = "windows-credential-manager".to_owned();
        value.key_reference.provider_identity_digest = value
            .key_reference
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
