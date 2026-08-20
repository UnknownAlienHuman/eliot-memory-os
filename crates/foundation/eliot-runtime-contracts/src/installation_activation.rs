//! Canonical authenticated installation-activation approval.
//!
//! This contract is deliberately separate from semantic authority receipts.
//! It is the installer-owned admission boundary for one exact transaction and
//! one exact approved generation.  A producer signs the complete payload with
//! an Ed25519 key.  A consumer verifies the detached signature against an
//! installation-pinned trust anchor and receives a sealed
//! [`VerifiedInstallationActivationApproval`].

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use eliot_contracts::{
    ContractVersion, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};

/// Stable schema marker for an authenticated installation activation.
pub const INSTALLATION_ACTIVATION_SCHEMA: &str = "eliot.installation-activation.v1";
/// Stable contract identity for the installation activation surface.
pub const INSTALLATION_ACTIVATION_CONTRACT_NAME: &str =
    "eliot.foundation.runtime-contracts.installation-activation";
/// Current contract revision for the installation activation surface.
pub const INSTALLATION_ACTIVATION_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Fixed signature algorithm admitted by this contract.
pub const INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM: &str = "Ed25519";
/// Ed25519 public-key size in bytes.
pub const INSTALLATION_ACTIVATION_PUBLIC_KEY_BYTES: usize = 32;
/// Ed25519 signature size in bytes.
pub const INSTALLATION_ACTIVATION_SIGNATURE_BYTES: usize = 64;
/// The nonce is a full 256-bit value represented as 64 lowercase hex digits.
pub const INSTALLATION_ACTIVATION_NONCE_BYTES: usize = 32;

/// Canonical SCM role covered by an installation approval.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationScmRole {
    /// The Host SCM service.
    Host,
    /// The sibling Watchdog SCM service.
    Watchdog,
}

impl InstallationScmRole {
    /// Returns the canonical Windows service name for this role.
    pub const fn service_name(self) -> &'static str {
        match self {
            Self::Host => "EliotHost",
            Self::Watchdog => "EliotWatchdog",
        }
    }
}

/// One named digest included in an installation approval.
///
/// Names are part of the signed payload.  They prevent a consumer from
/// treating a digest for one artifact/configuration/descriptor as a digest for
/// another one.  Each category rejects duplicate names.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationDigestBinding {
    /// Stable provider-neutral identity of the bound object.
    pub name: String,
    /// Lowercase SHA-256 digest of the exact object bytes.
    pub digest: String,
}

impl InstallationDigestBinding {
    fn validate(&self, field: &str) -> Result<(), InstallationActivationError> {
        non_empty_text(&self.name, &format!("{field}.name"))?;
        validate_sha256(&self.digest, &format!("{field}.digest"))
    }
}

/// Exact SCM configuration and readback evidence for one service role.
///
/// The installer creates this evidence only after SCM configuration has been
/// read back.  Host and Watchdog must both be present exactly once for a
/// `SystemService` approval.  The shape is provider-neutral so the contract does
/// not depend on the Windows adapter crate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationScmReadback {
    /// The uniquely covered SCM role.
    pub role: InstallationScmRole,
    /// Exact SCM service name returned by readback.
    pub service_name: String,
    /// Exact service executable path returned by readback.
    pub executable_path: String,
    /// Exact service account returned by readback.
    pub account: String,
    /// SHA-256 digest of the exact SCM configuration/readback projection.
    pub configuration_digest: String,
    /// Per-registration 256-bit nonce rendered in the service bootstrap.
    pub registration_nonce: String,
}

impl InstallationScmReadback {
    /// Validates one role's canonical service shape and evidence.
    pub fn validate(&self) -> Result<(), InstallationActivationError> {
        non_empty_text(&self.service_name, "scm_readback.service_name")?;
        non_empty_text(&self.executable_path, "scm_readback.executable_path")?;
        non_empty_text(&self.account, "scm_readback.account")?;
        validate_sha256(
            &self.configuration_digest,
            "scm_readback.configuration_digest",
        )?;
        validate_nonce(&self.registration_nonce, "scm_readback.registration_nonce")?;
        if self.service_name != self.role.service_name() {
            return Err(invalid_field(
                "scm_readback.service_name",
                "does not match the canonical role service name",
            ));
        }
        if self.account != "LocalService" {
            return Err(invalid_field(
                "scm_readback.account",
                "must be the canonical LocalService account",
            ));
        }
        let expected_image = match self.role {
            InstallationScmRole::Host => "eliot-host.exe",
            InstallationScmRole::Watchdog => "eliot-watchdog.exe",
        };
        let observed_image = self
            .executable_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default();
        if !observed_image.eq_ignore_ascii_case(expected_image) {
            return Err(invalid_field(
                "scm_readback.executable_path",
                "does not select the canonical role image",
            ));
        }
        Ok(())
    }
}

/// The complete unsigned installation activation payload.
///
/// Every field is included in [`Self::canonical_bytes`].  The payload carries
/// both the immutable transaction/generation bindings and the authoritative
/// SCM readback produced by the elevated installer.  It is not itself an
/// authority receipt and does not authorize semantic writes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationActivationPayload {
    /// Sole installation transaction identity.
    pub transaction_id: String,
    /// Exact durable transaction revision observed by the authority.
    pub transaction_revision: u64,
    /// Stable installation identity.
    pub installation_id: String,
    /// Monotonic installation epoch for this installation lineage.
    pub installation_epoch: u64,
    /// Digest of the immutable installer plan.
    pub installer_plan_digest: String,
    /// Digest of the exact candidate manifest bytes.
    pub candidate_manifest_digest: String,
    /// Digest of the exact runtime launch descriptor bytes.
    pub runtime_descriptor_digest: String,
    /// Digest of the complete static-verification receipt which proved the
    /// staged package, artifacts, configuration and authority descriptors.
    pub static_verification_receipt_digest: String,
    /// All approved artifact image/configuration-independent digests.
    pub artifact_digests: Vec<InstallationDigestBinding>,
    /// All approved configuration digests.
    pub config_digests: Vec<InstallationDigestBinding>,
    /// All approved authority descriptor digests.
    pub authority_descriptor_digests: Vec<InstallationDigestBinding>,
    /// Exact Host and Watchdog SCM readback projections.
    pub scm_readbacks: Vec<InstallationScmReadback>,
    /// Owner required to perform/admit this installation transaction.
    pub required_owner: String,
    /// Digest of independently observed elevation/owner evidence.
    pub elevation_evidence_digest: String,
    /// Authority resource generation bound to the candidate.
    pub authority_generation: ResourceGeneration,
    /// Exact authority fence bound to the candidate.
    pub authority_state_fence: StateFence,
    /// Fresh, one-shot 256-bit Kernel activation nonce.
    pub activation_nonce: String,
    /// Signed validity-window start in Unix milliseconds.
    pub issued_at_ms: i64,
    /// Signed validity-window end in Unix milliseconds (exclusive).
    pub expires_at_ms: i64,
}

impl InstallationActivationPayload {
    /// Validates all identity, digest, role, nonce, generation and time-shape
    /// invariants without consulting a trust anchor or wall clock.
    pub fn validate(&self) -> Result<(), InstallationActivationError> {
        non_empty_text(&self.transaction_id, "transaction_id")?;
        non_empty_text(&self.installation_id, "installation_id")?;
        non_empty_text(&self.required_owner, "required_owner")?;
        if self.transaction_revision == 0 {
            return Err(invalid_field(
                "transaction_revision",
                "must be greater than zero",
            ));
        }
        if self.installation_epoch == 0 {
            return Err(invalid_field(
                "installation_epoch",
                "must be greater than zero",
            ));
        }
        validate_sha256(&self.installer_plan_digest, "installer_plan_digest")?;
        validate_sha256(&self.candidate_manifest_digest, "candidate_manifest_digest")?;
        validate_sha256(&self.runtime_descriptor_digest, "runtime_descriptor_digest")?;
        validate_sha256(
            &self.static_verification_receipt_digest,
            "static_verification_receipt_digest",
        )?;
        validate_named_digests(&self.artifact_digests, "artifact_digests")?;
        validate_named_digests(&self.config_digests, "config_digests")?;
        validate_named_digests(
            &self.authority_descriptor_digests,
            "authority_descriptor_digests",
        )?;
        if self.scm_readbacks.len() != 2 {
            return Err(invalid_field(
                "scm_readbacks",
                "must contain exactly one Host and one Watchdog role",
            ));
        }
        let mut seen_roles = [false; 2];
        for readback in &self.scm_readbacks {
            readback.validate()?;
            let index = match readback.role {
                InstallationScmRole::Host => 0,
                InstallationScmRole::Watchdog => 1,
            };
            if std::mem::replace(&mut seen_roles[index], true) {
                return Err(invalid_field("scm_readbacks.role", "duplicate SCM role"));
            }
        }
        if seen_roles != [true, true] {
            return Err(invalid_field(
                "scm_readbacks.role",
                "Host and Watchdog are both required",
            ));
        }
        validate_sha256(&self.elevation_evidence_digest, "elevation_evidence_digest")?;
        if self.authority_generation.value() == 0 {
            return Err(invalid_field(
                "authority_generation",
                "must be greater than zero",
            ));
        }
        self.authority_state_fence
            .validate()
            .map_err(|error| invalid_field("authority_state_fence", error.to_string()))?;
        if self.authority_state_fence.resource_generation != self.authority_generation {
            return Err(invalid_field(
                "authority_state_fence",
                "resource generation must equal authority_generation",
            ));
        }
        validate_nonce(&self.activation_nonce, "activation_nonce")?;
        if self.issued_at_ms <= 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(invalid_field(
                "issued_at_ms/expires_at_ms",
                "must be a positive, non-empty validity interval",
            ));
        }
        Ok(())
    }

    /// Returns the canonical bytes covered by the payload digest and
    /// signature.  The schema/version wrapper is part of the signed bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InstallationActivationError> {
        self.validate()?;
        canonical_json_bytes(&CanonicalPayload {
            schema: INSTALLATION_ACTIVATION_SCHEMA,
            contract_version: INSTALLATION_ACTIVATION_CONTRACT_VERSION,
            payload: self,
        })
        .map_err(|error| InstallationActivationError::Canonicalization(error.to_string()))
    }

    /// Returns the lowercase SHA-256 digest of [`Self::canonical_bytes`].
    pub fn digest(&self) -> Result<String, InstallationActivationError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Signs this payload using an explicit Ed25519 signer.
    pub fn sign<S: InstallationActivationApprovalSigner>(
        &self,
        signer: &S,
    ) -> Result<SignedInstallationActivationApproval, InstallationActivationError> {
        if signer.algorithm() != INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM {
            return Err(InstallationActivationError::UnsupportedAlgorithm(
                signer.algorithm().to_owned(),
            ));
        }
        non_empty_text(signer.signer_id(), "signer_id")?;
        non_empty_text(signer.key_id(), "key_id")?;
        let payload_bytes = self.canonical_bytes()?;
        let payload_sha256 = sha256_hex(&payload_bytes);
        let preimage = SignedInstallationActivationPreimage {
            schema: INSTALLATION_ACTIVATION_SCHEMA,
            contract_version: INSTALLATION_ACTIVATION_CONTRACT_VERSION,
            payload: self,
            payload_sha256: &payload_sha256,
            signer_id: signer.signer_id(),
            key_id: signer.key_id(),
            algorithm: signer.algorithm(),
            public_key_fingerprint: signer.public_key_fingerprint(),
        };
        let bytes = canonical_json_bytes(&preimage)
            .map_err(|error| InstallationActivationError::Canonicalization(error.to_string()))?;
        let signature = signer.sign(&bytes)?;
        if signature.len() != INSTALLATION_ACTIVATION_SIGNATURE_BYTES {
            return Err(InstallationActivationError::InvalidSignatureLength {
                observed: signature.len(),
            });
        }
        Ok(SignedInstallationActivationApproval {
            payload: self.clone(),
            payload_sha256,
            signer_id: signer.signer_id().to_owned(),
            key_id: signer.key_id().to_owned(),
            algorithm: signer.algorithm().to_owned(),
            public_key_fingerprint: signer.public_key_fingerprint().to_owned(),
            signature: encode_hex(&signature),
        })
    }
}

#[derive(Serialize)]
struct CanonicalPayload<'a> {
    schema: &'static str,
    contract_version: ContractVersion,
    payload: &'a InstallationActivationPayload,
}

#[derive(Serialize)]
struct SignedInstallationActivationPreimage<'a> {
    schema: &'static str,
    contract_version: ContractVersion,
    payload: &'a InstallationActivationPayload,
    payload_sha256: &'a str,
    signer_id: &'a str,
    key_id: &'a str,
    algorithm: &'a str,
    public_key_fingerprint: &'a str,
}

/// Detached Ed25519-signed installation activation envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedInstallationActivationApproval {
    /// Complete immutable signed payload.
    pub payload: InstallationActivationPayload,
    /// Lowercase SHA-256 of the canonical payload bytes.
    pub payload_sha256: String,
    /// Stable authority signer identity.
    pub signer_id: String,
    /// External key reference selected by the authority.
    pub key_id: String,
    /// Must equal [`INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM`].
    pub algorithm: String,
    /// Lowercase SHA-256 fingerprint of the signing public key.
    pub public_key_fingerprint: String,
    /// Lowercase hexadecimal detached Ed25519 signature.
    pub signature: String,
}

impl SignedInstallationActivationApproval {
    /// Validates envelope shape, payload digest and all signed metadata.  The
    /// trust anchor is required separately for cryptographic verification.
    pub fn validate(&self) -> Result<(), InstallationActivationError> {
        self.payload.validate()?;
        non_empty_text(&self.signer_id, "signer_id")?;
        non_empty_text(&self.key_id, "key_id")?;
        if self.algorithm != INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM {
            return Err(InstallationActivationError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }
        validate_sha256(&self.public_key_fingerprint, "public_key_fingerprint")?;
        let expected = self.payload.digest()?;
        if self.payload_sha256 != expected {
            return Err(InstallationActivationError::DigestMismatch {
                field: "payload_sha256",
            });
        }
        decode_hex::<{ INSTALLATION_ACTIVATION_SIGNATURE_BYTES }>(&self.signature, "signature")?;
        // Re-serialize the preimage here so envelope metadata is also bound by
        // the detached signature and cannot be swapped after signing.
        self.preimage_bytes()
            .map(|_| ())
            .map_err(|error| InstallationActivationError::Canonicalization(error.to_string()))
    }

    fn preimage_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        canonical_json_bytes(&SignedInstallationActivationPreimage {
            schema: INSTALLATION_ACTIVATION_SCHEMA,
            contract_version: INSTALLATION_ACTIVATION_CONTRACT_VERSION,
            payload: &self.payload,
            payload_sha256: &self.payload_sha256,
            signer_id: &self.signer_id,
            key_id: &self.key_id,
            algorithm: &self.algorithm,
            public_key_fingerprint: &self.public_key_fingerprint,
        })
    }

    /// Returns the digest of the canonical envelope, including the detached
    /// signature.  This is useful as durable approval evidence.
    pub fn envelope_digest(&self) -> Result<String, InstallationActivationError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| InstallationActivationError::Canonicalization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Producer-side signing boundary for installation approvals.
pub trait InstallationActivationApprovalSigner {
    /// Stable producer identity.
    fn signer_id(&self) -> &str;
    /// External key reference.
    fn key_id(&self) -> &str;
    /// Signature algorithm identifier.
    fn algorithm(&self) -> &str {
        INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM
    }
    /// Public-key fingerprint included in the signed preimage.
    fn public_key_fingerprint(&self) -> &str;
    /// Signs canonical preimage bytes and returns exactly 64 Ed25519 bytes.
    fn sign(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, InstallationActivationError>;
}

/// In-memory Ed25519 signer for explicit test/provider key material.
///
/// Production code may implement [`InstallationActivationApprovalSigner`]
/// over a protected key provider.  Private key bytes are never serialized into
/// the approval contract.
pub struct Ed25519InstallationActivationApprovalSigner {
    signer_id: String,
    key_id: String,
    public_key_fingerprint: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519InstallationActivationApprovalSigner {
    /// Constructs a signer from explicitly supplied secret material.
    pub fn from_secret_key(
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
        secret_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    ) -> Result<Self, InstallationActivationError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        let public_key_fingerprint = sha256_hex(&signing_key.verifying_key().to_bytes());
        let signer = Self {
            signer_id: signer_id.into(),
            key_id: key_id.into(),
            public_key_fingerprint,
            signing_key,
        };
        non_empty_text(&signer.signer_id, "signer_id")?;
        non_empty_text(&signer.key_id, "key_id")?;
        Ok(signer)
    }

    /// Returns the public verification key for trust-anchor provisioning.
    pub fn public_key(&self) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl InstallationActivationApprovalSigner for Ed25519InstallationActivationApprovalSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }

    fn sign(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, InstallationActivationError> {
        Ok(self.signing_key.sign(canonical_payload).to_bytes().to_vec())
    }
}

/// Installation-pinned public trust anchor for activation verification.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationActivationApprovalTrustAnchor {
    /// Installation identity to which this key is pinned.
    pub installation_id: String,
    /// Expected authority signer identity.
    pub signer_id: String,
    /// Expected external key reference.
    pub key_id: String,
    /// Expected signature algorithm.
    pub algorithm: String,
    /// Public verification key provisioned out of band.
    pub public_key: Vec<u8>,
    /// Lowercase SHA-256 fingerprint of [`Self::public_key`].
    pub public_key_fingerprint: String,
}

impl InstallationActivationApprovalTrustAnchor {
    /// Constructs and fingerprints an installation-pinned public key.
    pub fn new(
        installation_id: impl Into<String>,
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: Vec<u8>,
    ) -> Result<Self, InstallationActivationError> {
        let anchor = Self {
            installation_id: installation_id.into(),
            signer_id: signer_id.into(),
            key_id: key_id.into(),
            algorithm: INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM.to_owned(),
            public_key_fingerprint: sha256_hex(&public_key),
            public_key,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    /// Validates key length, curve encoding, algorithm and fingerprint.
    pub fn validate(&self) -> Result<(), InstallationActivationError> {
        non_empty_text(&self.installation_id, "trust_anchor.installation_id")?;
        non_empty_text(&self.signer_id, "trust_anchor.signer_id")?;
        non_empty_text(&self.key_id, "trust_anchor.key_id")?;
        if self.algorithm != INSTALLATION_ACTIVATION_SIGNATURE_ALGORITHM {
            return Err(InstallationActivationError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }
        if self.public_key.len() != INSTALLATION_ACTIVATION_PUBLIC_KEY_BYTES {
            return Err(InstallationActivationError::InvalidPublicKeyLength {
                observed: self.public_key.len(),
            });
        }
        validate_sha256(
            &self.public_key_fingerprint,
            "trust_anchor.public_key_fingerprint",
        )?;
        if sha256_hex(&self.public_key) != self.public_key_fingerprint {
            return Err(InstallationActivationError::TrustAnchorFingerprintMismatch);
        }
        VerifyingKey::from_bytes(self.public_key.as_slice().try_into().map_err(|_| {
            InstallationActivationError::InvalidPublicKeyLength {
                observed: self.public_key.len(),
            }
        })?)
        .map_err(|error| InstallationActivationError::InvalidPublicKey(error.to_string()))?;
        Ok(())
    }

    /// Verifies an envelope against this anchor and an independently observed
    /// installation/transaction/fence context.
    pub fn verify(
        &self,
        envelope: &SignedInstallationActivationApproval,
        context: &InstallationActivationVerificationContext,
    ) -> Result<VerifiedInstallationActivationApproval, InstallationActivationError> {
        self.validate()?;
        context.validate()?;
        envelope.validate()?;
        if envelope.signer_id != self.signer_id {
            return Err(InstallationActivationError::TrustAnchorMismatch(
                "signer_id",
            ));
        }
        if envelope.key_id != self.key_id {
            return Err(InstallationActivationError::TrustAnchorMismatch("key_id"));
        }
        if envelope.algorithm != self.algorithm {
            return Err(InstallationActivationError::TrustAnchorMismatch(
                "algorithm",
            ));
        }
        if envelope.public_key_fingerprint != self.public_key_fingerprint {
            return Err(InstallationActivationError::TrustAnchorMismatch(
                "public_key_fingerprint",
            ));
        }
        let payload = &envelope.payload;
        if payload.installation_id != self.installation_id
            || payload.installation_id != context.installation_id
        {
            return Err(InstallationActivationError::InstallationIdentityMismatch);
        }
        if payload.transaction_id != context.transaction_id
            || payload.transaction_revision != context.transaction_revision
            || payload.static_verification_receipt_digest
                != context.static_verification_receipt_digest
            || payload.installation_epoch != context.installation_epoch
            || payload.authority_generation != context.authority_generation
            || payload.authority_state_fence != context.authority_state_fence
        {
            return Err(InstallationActivationError::BindingMismatch);
        }
        if context.now_ms < payload.issued_at_ms || context.now_ms >= payload.expires_at_ms {
            return Err(InstallationActivationError::Expired);
        }
        let signature = decode_hex::<{ INSTALLATION_ACTIVATION_SIGNATURE_BYTES }>(
            &envelope.signature,
            "signature",
        )?;
        let public_key: &[u8; INSTALLATION_ACTIVATION_PUBLIC_KEY_BYTES] =
            self.public_key.as_slice().try_into().map_err(|_| {
                InstallationActivationError::InvalidPublicKeyLength {
                    observed: self.public_key.len(),
                }
            })?;
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|error| InstallationActivationError::InvalidPublicKey(error.to_string()))?;
        let signature = Signature::from_bytes(&signature);
        let bytes = envelope
            .preimage_bytes()
            .map_err(|error| InstallationActivationError::Canonicalization(error.to_string()))?;
        verifying_key
            .verify_strict(&bytes, &signature)
            .map_err(|error| InstallationActivationError::SignatureInvalid(error.to_string()))?;
        Ok(VerifiedInstallationActivationApproval {
            payload: payload.clone(),
            payload_sha256: envelope.payload_sha256.clone(),
            envelope_sha256: envelope.envelope_digest()?,
            signer_id: envelope.signer_id.clone(),
            key_id: envelope.key_id.clone(),
            algorithm: envelope.algorithm.clone(),
            public_key_fingerprint: envelope.public_key_fingerprint.clone(),
            signature: envelope.signature.clone(),
        })
    }
}

/// Independently observed values bound by the installation trust-anchor
/// verifier.  The transaction/SCM owner supplies this context after reading
/// its durable state; the context is not an authority receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationActivationVerificationContext {
    /// Current wall-clock time in Unix milliseconds.
    pub now_ms: i64,
    /// Expected installation identity.
    pub installation_id: String,
    /// Expected installation epoch.
    pub installation_epoch: u64,
    /// Expected transaction identity.
    pub transaction_id: String,
    /// Expected durable transaction revision.
    pub transaction_revision: u64,
    /// Expected digest of the independently admitted complete
    /// static-verification receipt.
    pub static_verification_receipt_digest: String,
    /// Expected authority generation.
    pub authority_generation: ResourceGeneration,
    /// Expected authority fence.
    pub authority_state_fence: StateFence,
}

impl InstallationActivationVerificationContext {
    /// Validates independent context shape before comparison.
    pub fn validate(&self) -> Result<(), InstallationActivationError> {
        if self.now_ms <= 0 {
            return Err(invalid_field("now_ms", "must be positive"));
        }
        non_empty_text(&self.installation_id, "installation_id")?;
        non_empty_text(&self.transaction_id, "transaction_id")?;
        if self.installation_epoch == 0 || self.transaction_revision == 0 {
            return Err(invalid_field(
                "installation_epoch/transaction_revision",
                "must be greater than zero",
            ));
        }
        validate_sha256(
            &self.static_verification_receipt_digest,
            "static_verification_receipt_digest",
        )?;
        if self.authority_generation.value() == 0 {
            return Err(invalid_field(
                "authority_generation",
                "must be greater than zero",
            ));
        }
        self.authority_state_fence
            .validate()
            .map_err(|error| invalid_field("authority_state_fence", error.to_string()))?;
        if self.authority_state_fence.resource_generation != self.authority_generation {
            return Err(invalid_field(
                "authority_state_fence",
                "resource generation must equal authority_generation",
            ));
        }
        Ok(())
    }
}

/// Sealed, trust-anchor-verified installation activation.
///
/// The fields are private and there is intentionally no public constructor,
/// deserializer or serializer.  A caller can obtain this type only through
/// [`InstallationActivationApprovalTrustAnchor::verify`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInstallationActivationApproval {
    payload: InstallationActivationPayload,
    payload_sha256: String,
    envelope_sha256: String,
    signer_id: String,
    key_id: String,
    algorithm: String,
    public_key_fingerprint: String,
    signature: String,
}

impl VerifiedInstallationActivationApproval {
    /// Returns the authenticated complete payload.
    pub fn payload(&self) -> &InstallationActivationPayload {
        &self.payload
    }

    /// Returns the authenticated canonical payload digest.
    pub fn payload_digest(&self) -> &str {
        &self.payload_sha256
    }

    /// Returns the canonical signed-envelope digest.
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_sha256
    }

    /// Returns the authenticated signer identity.
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// Returns the authenticated external key reference.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the authenticated signature algorithm.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the authenticated public-key fingerprint.
    pub fn public_key_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }

    /// Returns the authenticated detached signature.
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

/// Verification trait for an installation activation trust anchor.
pub trait InstallationActivationApprovalVerifier {
    /// Verifies envelope shape, signer/anchor identity, digest, signature,
    /// time and independent transaction/fence bindings.
    fn verify(
        &self,
        envelope: &SignedInstallationActivationApproval,
        context: &InstallationActivationVerificationContext,
    ) -> Result<VerifiedInstallationActivationApproval, InstallationActivationError>;
}

impl InstallationActivationApprovalVerifier for InstallationActivationApprovalTrustAnchor {
    fn verify(
        &self,
        envelope: &SignedInstallationActivationApproval,
        context: &InstallationActivationVerificationContext,
    ) -> Result<VerifiedInstallationActivationApproval, InstallationActivationError> {
        InstallationActivationApprovalTrustAnchor::verify(self, envelope, context)
    }
}

/// Errors raised by installation activation construction or verification.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InstallationActivationError {
    /// A field failed strict shape validation.
    #[error("invalid installation activation field {field}: {reason}")]
    InvalidField { field: String, reason: String },
    /// Canonical JSON serialization failed.
    #[error("installation activation canonicalization failed: {0}")]
    Canonicalization(String),
    /// Signature algorithm is not admitted.
    #[error("unsupported installation activation signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// A canonical digest did not match the payload bytes.
    #[error("installation activation digest mismatch for {field}")]
    DigestMismatch { field: &'static str },
    /// A hex field was malformed.
    #[error("{field} must be lowercase hexadecimal with exactly {expected} bytes")]
    InvalidHex { field: String, expected: usize },
    /// Signature length was not exactly Ed25519's 64 bytes.
    #[error("invalid installation activation signature length: {observed}")]
    InvalidSignatureLength { observed: usize },
    /// Public key length was not exactly Ed25519's 32 bytes.
    #[error("invalid installation activation public-key length: {observed}")]
    InvalidPublicKeyLength { observed: usize },
    /// Public key failed curve validation.
    #[error("invalid installation activation public key: {0}")]
    InvalidPublicKey(String),
    /// Anchor fingerprint did not match its provisioned public key.
    #[error("installation activation trust-anchor fingerprint mismatch")]
    TrustAnchorFingerprintMismatch,
    /// Envelope metadata did not match the pinned trust anchor.
    #[error("installation activation trust-anchor mismatch for {0}")]
    TrustAnchorMismatch(&'static str),
    /// Installation identity did not match the anchor/context.
    #[error("installation activation installation identity mismatch")]
    InstallationIdentityMismatch,
    /// Transaction, revision, generation or fence did not match context.
    #[error("installation activation binding mismatch")]
    BindingMismatch,
    /// Signed validity window is expired or not yet valid.
    #[error("installation activation is expired or not yet valid")]
    Expired,
    /// Detached signature failed strict Ed25519 verification.
    #[error("invalid installation activation signature: {0}")]
    SignatureInvalid(String),
}

fn invalid_field(
    field: impl Into<String>,
    reason: impl Into<String>,
) -> InstallationActivationError {
    InstallationActivationError::InvalidField {
        field: field.into(),
        reason: reason.into(),
    }
}

fn non_empty_text(value: &str, field: &str) -> Result<(), InstallationActivationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid_field(
            field,
            "must be non-blank and free of control characters",
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), InstallationActivationError> {
    decode_hex::<32>(value, field).map(|_| ())
}

fn validate_nonce(value: &str, field: &str) -> Result<(), InstallationActivationError> {
    let decoded = decode_hex::<{ INSTALLATION_ACTIVATION_NONCE_BYTES }>(value, field)?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(invalid_field(field, "must not be all zero"));
    }
    Ok(())
}

fn validate_named_digests(
    values: &[InstallationDigestBinding],
    field: &str,
) -> Result<(), InstallationActivationError> {
    if values.is_empty() {
        return Err(invalid_field(field, "must not be empty"));
    }
    let mut names = std::collections::BTreeSet::new();
    for value in values {
        value.validate(field)?;
        if !names.insert(value.name.as_str()) {
            return Err(invalid_field(field, "duplicate digest binding name"));
        }
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex<const N: usize>(
    value: &str,
    field: &str,
) -> Result<[u8; N], InstallationActivationError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallationActivationError::InvalidHex {
            field: field.to_owned(),
            expected: N,
        });
    }
    let bytes = value.as_bytes();
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let high = hex_value(bytes[index * 2]);
        let low = hex_value(bytes[index * 2 + 1]);
        *slot = (high << 4) | low;
    }
    Ok(output)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

/// Compatibility alias for callers that use the shorter signed-envelope name.
pub type SignedInstallationActivation = SignedInstallationActivationApproval;
/// Compatibility alias for the producer-side signing boundary.
pub trait InstallationActivationSigner: InstallationActivationApprovalSigner {}
impl<T: InstallationActivationApprovalSigner + ?Sized> InstallationActivationSigner for T {}
/// Compatibility alias for the trust-anchor name used by runtime consumers.
pub type InstallationActivationTrustAnchor = InstallationActivationApprovalTrustAnchor;
/// Compatibility alias for the verifier trait used by runtime consumers.
pub trait InstallationActivationVerifier: InstallationActivationApprovalVerifier {}
impl<T: InstallationActivationApprovalVerifier + ?Sized> InstallationActivationVerifier for T {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::similar_names)]
mod tests {
    use super::*;
    use eliot_contracts::AuthorityEpoch;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn nonce(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn payload() -> InstallationActivationPayload {
        InstallationActivationPayload {
            transaction_id: "tx-1".to_owned(),
            transaction_revision: 7,
            installation_id: "installation-1".to_owned(),
            installation_epoch: 3,
            installer_plan_digest: digest('1'),
            candidate_manifest_digest: digest('2'),
            runtime_descriptor_digest: digest('3'),
            static_verification_receipt_digest: digest('d'),
            artifact_digests: vec![InstallationDigestBinding {
                name: "eliot-host.exe".to_owned(),
                digest: digest('4'),
            }],
            config_digests: vec![InstallationDigestBinding {
                name: "host-config".to_owned(),
                digest: digest('5'),
            }],
            authority_descriptor_digests: vec![InstallationDigestBinding {
                name: "authority-handoff".to_owned(),
                digest: digest('6'),
            }],
            scm_readbacks: vec![
                InstallationScmReadback {
                    role: InstallationScmRole::Host,
                    service_name: "EliotHost".to_owned(),
                    executable_path: r"C:\ProgramData\Eliot\eliot-host.exe".to_owned(),
                    account: "LocalService".to_owned(),
                    configuration_digest: digest('7'),
                    registration_nonce: nonce('a'),
                },
                InstallationScmReadback {
                    role: InstallationScmRole::Watchdog,
                    service_name: "EliotWatchdog".to_owned(),
                    executable_path: r"C:\ProgramData\Eliot\eliot-watchdog.exe".to_owned(),
                    account: "LocalService".to_owned(),
                    configuration_digest: digest('8'),
                    registration_nonce: nonce('b'),
                },
            ],
            required_owner: "SystemOwner".to_owned(),
            elevation_evidence_digest: digest('9'),
            authority_generation: ResourceGeneration::new(4).expect("generation"),
            authority_state_fence: StateFence::new(
                AuthorityEpoch::new(5).expect("epoch"),
                ResourceGeneration::new(4).expect("generation"),
            ),
            activation_nonce: nonce('c'),
            issued_at_ms: 1_000,
            expires_at_ms: 5_000,
        }
    }

    fn signer() -> Ed25519InstallationActivationApprovalSigner {
        Ed25519InstallationActivationApprovalSigner::from_secret_key(
            "installer-authority",
            "key-1",
            [7; ed25519_dalek::SECRET_KEY_LENGTH],
        )
        .expect("signer")
    }

    fn context() -> InstallationActivationVerificationContext {
        let value = payload();
        InstallationActivationVerificationContext {
            now_ms: 2_000,
            installation_id: value.installation_id,
            installation_epoch: value.installation_epoch,
            transaction_id: value.transaction_id,
            transaction_revision: value.transaction_revision,
            static_verification_receipt_digest: value.static_verification_receipt_digest,
            authority_generation: value.authority_generation,
            authority_state_fence: value.authority_state_fence,
        }
    }

    fn anchor() -> InstallationActivationApprovalTrustAnchor {
        let signer = signer();
        InstallationActivationApprovalTrustAnchor::new(
            "installation-1",
            signer.signer_id.clone(),
            signer.key_id.clone(),
            signer.public_key().to_vec(),
        )
        .expect("anchor")
    }

    #[test]
    fn signed_activation_round_trips_through_strict_anchor() {
        let payload = payload();
        let signer = signer();
        let signed = payload.sign(&signer).expect("sign");
        let encoded = serde_json::to_vec(&signed).expect("encode");
        let decoded: SignedInstallationActivationApproval =
            serde_json::from_slice(&encoded).expect("decode");
        let verified = anchor()
            .verify(&decoded, &context())
            .expect("verified approval");
        assert_eq!(verified.payload(), &payload);
        assert_eq!(verified.signer_id(), "installer-authority");
        assert_eq!(verified.key_id(), "key-1");
        assert_eq!(verified.payload_digest(), payload.digest().expect("digest"));
    }

    #[test]
    fn altered_payload_or_signed_metadata_fails_signature_verification() {
        let signer = signer();
        let signed = payload().sign(&signer).expect("sign");

        let mut altered_payload = signed.clone();
        altered_payload.payload.transaction_revision += 1;
        assert!(anchor().verify(&altered_payload, &context()).is_err());

        let mut altered_key = signed.clone();
        altered_key.key_id = "other-key".to_owned();
        assert!(anchor().verify(&altered_key, &context()).is_err());

        let mut altered_fingerprint = signed;
        altered_fingerprint.public_key_fingerprint = digest('f');
        assert!(anchor().verify(&altered_fingerprint, &context()).is_err());
    }

    #[test]
    fn malformed_roles_duplicates_digests_and_zero_nonce_fail_closed() {
        let mut duplicate_role = payload();
        duplicate_role.scm_readbacks[1].role = InstallationScmRole::Host;
        assert!(duplicate_role.validate().is_err());

        let mut duplicate_digest = payload();
        duplicate_digest
            .artifact_digests
            .push(InstallationDigestBinding {
                name: "eliot-host.exe".to_owned(),
                digest: digest('a'),
            });
        assert!(duplicate_digest.validate().is_err());

        let mut zero_nonce = payload();
        zero_nonce.activation_nonce = nonce('0');
        assert!(zero_nonce.validate().is_err());
    }

    #[test]
    fn static_verification_receipt_is_mandatory_and_exactly_bound() {
        let mut malformed_payload = payload();
        malformed_payload.static_verification_receipt_digest = "ABC".to_owned();
        assert!(malformed_payload.validate().is_err());

        let mut malformed_context = context();
        malformed_context.static_verification_receipt_digest = "ABC".to_owned();
        assert!(malformed_context.validate().is_err());

        let authority_signer = signer();
        let signed = payload().sign(&authority_signer).expect("sign");
        let mut substituted_payload = signed.clone();
        substituted_payload
            .payload
            .static_verification_receipt_digest = digest('e');
        substituted_payload.payload_sha256 = substituted_payload
            .payload
            .digest()
            .expect("substituted payload digest");
        let mut substituted_context = context();
        substituted_context.static_verification_receipt_digest = digest('e');
        assert!(matches!(
            anchor().verify(&substituted_payload, &substituted_context),
            Err(InstallationActivationError::SignatureInvalid(_))
        ));

        let mut mismatched_context = context();
        mismatched_context.static_verification_receipt_digest = digest('e');
        assert_eq!(
            anchor().verify(&signed, &mismatched_context),
            Err(InstallationActivationError::BindingMismatch)
        );
    }

    #[test]
    fn anchor_rejects_expiry_not_yet_valid_and_context_mismatch() {
        let signer = signer();
        let mut not_yet_valid = payload();
        not_yet_valid.issued_at_ms = 3_000;
        not_yet_valid.expires_at_ms = 5_000;
        let signed = not_yet_valid.sign(&signer).expect("sign");
        assert!(anchor().verify(&signed, &context()).is_err());

        let mut expired = payload();
        expired.expires_at_ms = 1_500;
        let signed = expired.sign(&signer).expect("sign");
        assert!(anchor().verify(&signed, &context()).is_err());

        let signed = payload().sign(&signer).expect("sign");
        let mut wrong_context = context();
        wrong_context.transaction_revision += 1;
        assert!(anchor().verify(&signed, &wrong_context).is_err());
    }

    #[test]
    fn payload_canonical_bytes_bind_every_field() {
        let payload = payload();
        let baseline = payload.digest().expect("digest");
        let mut altered = payload;
        altered.static_verification_receipt_digest = digest('e');
        assert_ne!(altered.digest().expect("digest"), baseline);
    }
}
