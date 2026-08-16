//! Canonical authenticated supervision-lease contract.
//!
//! A lease is an observation/supervision capability, not process or semantic
//! authority.  The payload is intentionally complete: every value which can
//! affect admission is covered by the canonical digest and the Ed25519
//! signature.  A producer supplies a [`SupervisionLeaseSigner`]; a consumer
//! supplies an installation-pinned [`SupervisionTrustAnchor`] and current
//! [`SupervisionLeaseVerificationContext`].

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use eliot_contracts::{
    AuthorityEpoch, ContractVersion, ResourceGeneration, StateFence, canonical_json_bytes,
    sha256_hex,
};

use super::{LeaseState, RuntimeContractError};

/// Stable schema marker for the signed supervision-lease payload.
pub const SUPERVISION_LEASE_SCHEMA: &str = "eliot.supervision-lease.v1";
/// Stable contract identity for this lease surface.
pub const SUPERVISION_LEASE_CONTRACT_NAME: &str =
    "eliot.foundation.runtime-contracts.supervision-lease";
/// Current contract revision for the lease surface.
pub const SUPERVISION_LEASE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Fixed signature algorithm admitted by this contract.
pub const SUPERVISION_LEASE_SIGNATURE_ALGORITHM: &str = "Ed25519";
/// Ed25519 public-key size in bytes.
pub const SUPERVISION_LEASE_PUBLIC_KEY_BYTES: usize = 32;
/// Ed25519 signature size in bytes.
pub const SUPERVISION_LEASE_SIGNATURE_BYTES: usize = 64;

/// The disposition attached to a terminal lease state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupervisionLeaseTerminalDisposition {
    /// The lease was deliberately released.
    Released,
    /// The lease reached its expiry.
    Expired,
    /// The lease was revoked by its authority owner.
    Revoked,
    /// A newer activation superseded the lease.
    Superseded,
    /// The lease lifecycle was closed.
    Closed,
}

/// Observation scope and declared coverage for a supervision lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionObservationScope {
    /// Registered target identities covered by the sensor.
    pub targets: Vec<String>,
    /// Stable sensor profile identity.
    pub sensor_profile: String,
    /// Explicit coverage claims; an empty claim is never accepted.
    pub claimed_coverage: Vec<String>,
    /// Governance axis under which the observation is admitted.
    pub governance_axis: String,
}

impl SupervisionObservationScope {
    fn validate(&self) -> Result<(), RuntimeContractError> {
        non_empty_text_list(&self.targets, "observation_scope.targets")?;
        non_empty_text(&self.sensor_profile, "observation_scope.sensor_profile")?;
        non_empty_text_list(&self.claimed_coverage, "observation_scope.claimed_coverage")?;
        non_empty_text(&self.governance_axis, "observation_scope.governance_axis")
    }
}

/// Target, module and process generation identities covered by a lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionGenerationBinding {
    /// Stable target identity.
    pub target_id: String,
    /// Target generation observed by the producer.
    pub target_generation: ResourceGeneration,
    /// Stable module identity.
    pub module_id: String,
    /// Module generation observed by the producer.
    pub module_generation: ResourceGeneration,
    /// Stable process lineage identity.
    pub process_id: String,
    /// Process generation observed by the producer.
    pub process_generation: ResourceGeneration,
}

/// Signed mirror identity proving which committed ORS revision backed a lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionOrsMirrorBinding {
    /// Stable ORS record identity.
    pub record_id: String,
    /// Exact lease subject represented by this ORS record.
    pub subject_lease_id: String,
    /// Positive monotonic lease revision in the ORS record.
    pub lease_revision: u64,
    /// SHA-256 of the committed ORS receipt which admitted this revision.
    pub committed_receipt_sha256: String,
    /// Optional SHA-256 of the immediately previous revision.
    pub previous_revision_sha256: Option<String>,
}

impl SupervisionOrsMirrorBinding {
    fn validate(&self) -> Result<(), RuntimeContractError> {
        non_empty_text(&self.record_id, "ors_mirror.record_id")?;
        non_empty_text(&self.subject_lease_id, "ors_mirror.subject_lease_id")?;
        if self.lease_revision == 0 {
            return Err(invalid_lease_field(
                "ors_mirror.lease_revision",
                "must be greater than zero",
            ));
        }
        if !is_sha256_hex(&self.committed_receipt_sha256) {
            return Err(invalid_lease_field(
                "ors_mirror.committed_receipt_sha256",
                "must be a lowercase SHA-256 digest",
            ));
        }
        if let Some(previous) = &self.previous_revision_sha256
            && !is_sha256_hex(previous)
        {
            return Err(invalid_lease_field(
                "ors_mirror.previous_revision_sha256",
                "must be absent or a lowercase SHA-256 digest",
            ));
        }
        Ok(())
    }
}

impl SupervisionGenerationBinding {
    fn validate(&self) -> Result<(), RuntimeContractError> {
        non_empty_text(&self.target_id, "generation_binding.target_id")?;
        non_empty_text(&self.module_id, "generation_binding.module_id")?;
        non_empty_text(&self.process_id, "generation_binding.process_id")?;
        if self.target_generation.value() == 0 {
            return Err(invalid_lease_field(
                "generation_binding.target_generation",
                "must be greater than zero",
            ));
        }
        if self.module_generation.value() == 0 {
            return Err(invalid_lease_field(
                "generation_binding.module_generation",
                "must be greater than zero",
            ));
        }
        if self.process_generation.value() == 0 {
            return Err(invalid_lease_field(
                "generation_binding.process_generation",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Policy controlling wake-up of registered activity from an observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RegisteredActivityWakePolicy {
    /// No registered activity may be woken by this lease.
    Disabled,
    /// Wake one registered activity within the supplied bounded interval.
    Registered {
        /// Registered activity identity.
        activity_id: String,
        /// Maximum interval between permitted wake observations.
        max_wake_interval_ms: u64,
    },
}

impl RegisteredActivityWakePolicy {
    fn validate(&self) -> Result<(), RuntimeContractError> {
        match self {
            Self::Disabled => Ok(()),
            Self::Registered {
                activity_id,
                max_wake_interval_ms,
            } => {
                non_empty_text(activity_id, "wake_policy.activity_id")?;
                if *max_wake_interval_ms == 0 {
                    return Err(invalid_lease_field(
                        "wake_policy.max_wake_interval_ms",
                        "must be greater than zero",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Canonical signed lease payload.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLease {
    /// Strict wire schema marker.
    pub schema: String,
    /// Strict contract identity name.
    pub contract_name: String,
    /// Strict contract identity revision.
    pub contract_version: ContractVersion,
    /// Stable lease identity.
    pub lease_id: String,
    /// Observation scope reference.
    pub scope_ref: String,
    /// Targets, sensor profile, coverage and governance axis.
    pub observation_scope: SupervisionObservationScope,
    /// Installation identity which owns the lease.
    pub installation_id: String,
    /// Host epoch captured atomically with activation.
    pub host_epoch: AuthorityEpoch,
    /// Activation identity which issued the lease.
    pub activation_id: String,
    /// Activation generation selected by Host/Kernel.
    pub activation_generation: ResourceGeneration,
    /// Kernel authority epoch.
    pub kernel_epoch: AuthorityEpoch,
    /// Watchdog authority epoch.
    pub watchdog_epoch: AuthorityEpoch,
    /// Target/module/process generation binding.
    pub generation_binding: SupervisionGenerationBinding,
    /// State fence captured with the activation.
    pub state_fence: StateFence,
    /// Committed ORS mirror receipt and revision binding.
    pub ors_mirror: SupervisionOrsMirrorBinding,
    /// Inclusive issue time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Exclusive expiry time in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Absolute renewal deadline in Unix milliseconds.
    pub renew_before_ms: u64,
    /// Registered-activity wake policy.
    pub wake_policy: RegisteredActivityWakePolicy,
    /// Current lease lifecycle state.
    pub state: LeaseState,
    /// Required terminal disposition for terminal states.
    pub terminal_disposition: Option<SupervisionLeaseTerminalDisposition>,
    /// Human-readable revocation reason; present only for revoked leases.
    pub revocation_reason: Option<String>,
    /// Explicit revocation identity when the lease is revoked.
    pub revocation_id: Option<String>,
    /// Authority epoch at which revocation took effect.
    pub revocation_epoch: Option<AuthorityEpoch>,
}

impl SupervisionLease {
    /// Validates the complete unsigned payload and all cross-field bindings.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.schema != SUPERVISION_LEASE_SCHEMA {
            return Err(invalid_lease_field("schema", "unsupported schema"));
        }
        if self.contract_name != SUPERVISION_LEASE_CONTRACT_NAME {
            return Err(invalid_lease_field(
                "contract_name",
                "unsupported contract identity",
            ));
        }
        if self.contract_version != SUPERVISION_LEASE_CONTRACT_VERSION {
            return Err(invalid_lease_field(
                "contract_version",
                "unsupported contract revision",
            ));
        }
        non_empty_text(&self.lease_id, "lease_id")?;
        non_empty_text(&self.scope_ref, "scope_ref")?;
        self.observation_scope.validate()?;
        non_empty_text(&self.installation_id, "installation_id")?;
        non_empty_text(&self.activation_id, "activation_id")?;
        if self.host_epoch.value() == 0 {
            return Err(invalid_lease_field(
                "host_epoch",
                "must be greater than zero",
            ));
        }
        if self.activation_generation.value() == 0 {
            return Err(invalid_lease_field(
                "activation_generation",
                "must be greater than zero",
            ));
        }
        if self.kernel_epoch.value() == 0 {
            return Err(invalid_lease_field(
                "kernel_epoch",
                "must be greater than zero",
            ));
        }
        if self.watchdog_epoch.value() == 0 {
            return Err(invalid_lease_field(
                "watchdog_epoch",
                "must be greater than zero",
            ));
        }
        self.generation_binding.validate()?;
        self.ors_mirror.validate()?;
        if self.ors_mirror.subject_lease_id != self.lease_id {
            return Err(invalid_lease_field(
                "ors_mirror.subject_lease_id",
                "must identify this lease",
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| invalid_lease_field("state_fence", error.to_string()))?;
        if self.state_fence.authority_epoch != self.kernel_epoch {
            return Err(invalid_lease_field(
                "state_fence.authority_epoch",
                "must equal kernel_epoch",
            ));
        }
        if self.state_fence.resource_generation != self.activation_generation {
            return Err(invalid_lease_field(
                "state_fence.resource_generation",
                "must equal activation_generation",
            ));
        }
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(invalid_lease_field(
                "issued_at_ms/expires_at_ms",
                "must be a positive ordered interval",
            ));
        }
        if self.renew_before_ms <= self.issued_at_ms || self.renew_before_ms >= self.expires_at_ms {
            return Err(invalid_lease_field(
                "renew_before_ms",
                "must be strictly between issue and expiry",
            ));
        }
        self.wake_policy.validate()?;
        self.validate_disposition()
    }

    fn validate_disposition(&self) -> Result<(), RuntimeContractError> {
        let expected = match self.state {
            LeaseState::Released => Some(SupervisionLeaseTerminalDisposition::Released),
            LeaseState::Expired => Some(SupervisionLeaseTerminalDisposition::Expired),
            LeaseState::Revoked => Some(SupervisionLeaseTerminalDisposition::Revoked),
            LeaseState::Superseded => Some(SupervisionLeaseTerminalDisposition::Superseded),
            LeaseState::Closed => Some(SupervisionLeaseTerminalDisposition::Closed),
            LeaseState::Requested
            | LeaseState::Active
            | LeaseState::Expiring
            | LeaseState::Reconciling => None,
        };
        if self.terminal_disposition != expected {
            return Err(invalid_lease_field(
                "terminal_disposition",
                "does not match lease state",
            ));
        }
        if self.state == LeaseState::Revoked {
            if self
                .revocation_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
            {
                return Err(invalid_lease_field(
                    "revocation_reason",
                    "is required for revoked leases",
                ));
            }
            if self
                .revocation_id
                .as_deref()
                .is_none_or(|id| id.trim().is_empty())
                || self.revocation_epoch.is_none_or(|epoch| epoch.value() == 0)
            {
                return Err(invalid_lease_field(
                    "revocation_id/revocation_epoch",
                    "are required for revoked leases",
                ));
            }
        } else if self.revocation_reason.is_some() {
            return Err(invalid_lease_field(
                "revocation_reason",
                "is only valid for revoked leases",
            ));
        } else if self.revocation_id.is_some() || self.revocation_epoch.is_some() {
            return Err(invalid_lease_field(
                "revocation_id/revocation_epoch",
                "are only valid for revoked leases",
            ));
        }
        Ok(())
    }

    /// Returns canonical bytes which the producer must sign.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SupervisionLeaseError> {
        self.validate()
            .map_err(SupervisionLeaseError::InvalidPayload)?;
        canonical_json_bytes(self)
            .map_err(|error| SupervisionLeaseError::Canonicalization(error.to_string()))
    }

    /// Returns the lowercase SHA-256 digest of [`Self::canonical_bytes`].
    pub fn digest(&self) -> Result<String, SupervisionLeaseError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Signs this payload using an explicit, non-persisted signer/key provider.
    pub fn sign<S: SupervisionLeaseSigner>(
        &self,
        signer: &S,
    ) -> Result<SignedSupervisionLease, SupervisionLeaseError> {
        if signer.algorithm() != SUPERVISION_LEASE_SIGNATURE_ALGORITHM {
            return Err(SupervisionLeaseError::UnsupportedAlgorithm(
                signer.algorithm().to_owned(),
            ));
        }
        non_empty_text_for_lease(signer.signer_id(), "signer_id")?;
        non_empty_text_for_lease(signer.key_id(), "key_id")?;
        let bytes = self.canonical_bytes()?;
        let signature = signer.sign(&bytes)?;
        if signature.len() != SUPERVISION_LEASE_SIGNATURE_BYTES {
            return Err(SupervisionLeaseError::InvalidSignatureLength {
                observed: signature.len(),
            });
        }
        Ok(SignedSupervisionLease {
            payload: self.clone(),
            payload_sha256: sha256_hex(&bytes),
            signer_id: signer.signer_id().to_owned(),
            key_id: signer.key_id().to_owned(),
            algorithm: signer.algorithm().to_owned(),
            signature: encode_hex(&signature),
        })
    }
}

/// Authenticated supervision-lease envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSupervisionLease {
    /// Complete signed payload.
    pub payload: SupervisionLease,
    /// Lowercase SHA-256 of canonical payload bytes.
    pub payload_sha256: String,
    /// Stable producer identity.
    pub signer_id: String,
    /// External key reference selected by the producer.
    pub key_id: String,
    /// Must equal [`SUPERVISION_LEASE_SIGNATURE_ALGORITHM`].
    pub algorithm: String,
    /// Lowercase hexadecimal Ed25519 signature over canonical payload bytes.
    pub signature: String,
}

impl SignedSupervisionLease {
    /// Validates envelope shape and payload/digest consistency without a trust anchor.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        self.payload
            .validate()
            .map_err(SupervisionLeaseError::InvalidPayload)?;
        non_empty_text_for_lease(&self.signer_id, "signer_id")?;
        non_empty_text_for_lease(&self.key_id, "key_id")?;
        if self.algorithm != SUPERVISION_LEASE_SIGNATURE_ALGORITHM {
            return Err(SupervisionLeaseError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }
        let expected = self.payload.digest()?;
        if self.payload_sha256 != expected {
            return Err(SupervisionLeaseError::DigestMismatch);
        }
        decode_hex::<{ SUPERVISION_LEASE_SIGNATURE_BYTES }>(&self.signature, "signature")?;
        Ok(())
    }

    /// Returns the lowercase SHA-256 digest of the canonical signed envelope.
    pub fn envelope_digest(&self) -> Result<String, SupervisionLeaseError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| SupervisionLeaseError::Canonicalization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Producer-side signing boundary.  Implementations may delegate to a KMS/HSM;
/// private key bytes never appear in the lease contract or envelope.
pub trait SupervisionLeaseSigner {
    /// Stable producer identity.
    fn signer_id(&self) -> &str;
    /// External key reference.
    fn key_id(&self) -> &str;
    /// Signature algorithm identifier.
    fn algorithm(&self) -> &str {
        SUPERVISION_LEASE_SIGNATURE_ALGORITHM
    }
    /// Signs canonical payload bytes and returns exactly 64 Ed25519 bytes.
    fn sign(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, SupervisionLeaseError>;
}

/// In-memory Ed25519 signer for an explicit producer key-provider input.
///
/// This type is deliberately not serializable.  Production callers may instead
/// implement [`SupervisionLeaseSigner`] over a protected key provider.
pub struct Ed25519SupervisionLeaseSigner {
    signer_id: String,
    key_id: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519SupervisionLeaseSigner {
    /// Builds a signer from secret material supplied explicitly by the caller.
    pub fn from_secret_key(
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
        secret_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    ) -> Result<Self, SupervisionLeaseError> {
        let signer_id = signer_id.into();
        let key_id = key_id.into();
        non_empty_text_for_lease(&signer_id, "signer_id")?;
        non_empty_text_for_lease(&key_id, "key_id")?;
        Ok(Self {
            signer_id,
            key_id,
            signing_key: ed25519_dalek::SigningKey::from_bytes(&secret_key),
        })
    }

    /// Returns the public verification key for external trust-anchor provisioning.
    pub fn public_key(&self) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl SupervisionLeaseSigner for Ed25519SupervisionLeaseSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, SupervisionLeaseError> {
        Ok(self.signing_key.sign(canonical_payload).to_bytes().to_vec())
    }
}

/// Installation-pinned external trust anchor for lease verification.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionTrustAnchor {
    /// Installation identity to which this key is pinned.
    pub installation_id: String,
    /// Expected producer identity.
    pub signer_id: String,
    /// Expected external key reference.
    pub key_id: String,
    /// Expected signature algorithm.
    pub algorithm: String,
    /// Public verification key supplied out-of-band, never read from a lease.
    pub public_key: Vec<u8>,
    /// Lowercase SHA-256 fingerprint of [`Self::public_key`].
    pub public_key_fingerprint: String,
}

impl SupervisionTrustAnchor {
    /// Constructs and fingerprints an external public trust anchor.
    pub fn new(
        installation_id: impl Into<String>,
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: Vec<u8>,
    ) -> Result<Self, SupervisionLeaseError> {
        let anchor = Self {
            installation_id: installation_id.into(),
            signer_id: signer_id.into(),
            key_id: key_id.into(),
            algorithm: SUPERVISION_LEASE_SIGNATURE_ALGORITHM.to_owned(),
            public_key_fingerprint: sha256_hex(&public_key),
            public_key,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    /// Validates key length, algorithm and externally supplied fingerprint.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        non_empty_text_for_lease(&self.installation_id, "trust_anchor.installation_id")?;
        non_empty_text_for_lease(&self.signer_id, "trust_anchor.signer_id")?;
        non_empty_text_for_lease(&self.key_id, "trust_anchor.key_id")?;
        if self.algorithm != SUPERVISION_LEASE_SIGNATURE_ALGORITHM {
            return Err(SupervisionLeaseError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }
        if self.public_key.len() != SUPERVISION_LEASE_PUBLIC_KEY_BYTES {
            return Err(SupervisionLeaseError::InvalidPublicKeyLength {
                observed: self.public_key.len(),
            });
        }
        decode_hex::<32>(
            &self.public_key_fingerprint,
            "trust_anchor.public_key_fingerprint",
        )?;
        if sha256_hex(&self.public_key) != self.public_key_fingerprint {
            return Err(SupervisionLeaseError::TrustAnchorFingerprintMismatch);
        }
        VerifyingKey::from_bytes(&self.public_key.as_slice().try_into().map_err(|_| {
            SupervisionLeaseError::InvalidPublicKeyLength {
                observed: self.public_key.len(),
            }
        })?)
        .map_err(|error| SupervisionLeaseError::InvalidPublicKey(error.to_string()))?;
        Ok(())
    }

    /// Returns the externally provisioned public-key fingerprint.
    pub fn public_key_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }
}

/// Independently observed lifecycle state which a consumer must bind before it
/// admits a signed lease.  Revocation identity and epoch are part of the
/// state binding so an active lease cannot be replayed after an authority
/// revokes it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseActiveStateBinding {
    /// Current lifecycle state selected by the installation authority.
    pub state: LeaseState,
    /// Stable revocation identity when the current state is revoked.
    pub revocation_id: Option<String>,
    /// Kernel authority epoch at which revocation took effect.
    pub revocation_epoch: Option<AuthorityEpoch>,
}

impl SupervisionLeaseActiveStateBinding {
    fn validate(&self) -> Result<(), SupervisionLeaseError> {
        if self.state == LeaseState::Revoked {
            if self
                .revocation_id
                .as_deref()
                .is_none_or(|id| id.trim().is_empty())
                || self.revocation_epoch.is_none_or(|epoch| epoch.value() == 0)
            {
                return Err(SupervisionLeaseError::InvalidContext(
                    "revoked active-state binding requires revocation identity and epoch"
                        .to_owned(),
                ));
            }
        } else if self.revocation_id.is_some() || self.revocation_epoch.is_some() {
            return Err(SupervisionLeaseError::InvalidContext(
                "revocation identity and epoch are only valid for revoked state".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Current values a consumer must bind before accepting a verified lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseVerificationContext {
    /// Current wall-clock time in Unix milliseconds.
    pub now_ms: u64,
    /// Exact lease identity currently admitted by the installation authority.
    pub lease_id: String,
    /// Current Host authority epoch.
    pub host_epoch: AuthorityEpoch,
    /// Current activation identity.
    pub activation_id: String,
    /// Current activation generation.
    pub activation_generation: ResourceGeneration,
    /// Current Kernel epoch.
    pub kernel_epoch: AuthorityEpoch,
    /// Current Watchdog epoch.
    pub watchdog_epoch: AuthorityEpoch,
    /// Exact current Kernel-owned state fence.
    pub state_fence: StateFence,
    /// Exact current lease scope reference.
    pub scope_ref: String,
    /// Full observation scope independently selected by admission.
    pub observation_scope: SupervisionObservationScope,
    /// Exact current target identity.
    pub target_id: String,
    /// Exact current module identity.
    pub module_id: String,
    /// Exact current process lineage identity.
    pub process_id: String,
    /// Current target generation.
    pub target_generation: ResourceGeneration,
    /// Current module generation.
    pub module_generation: ResourceGeneration,
    /// Current process generation.
    pub process_generation: ResourceGeneration,
    /// Exact fingerprint independently selected by installation admission.
    pub public_key_fingerprint: String,
    /// Exact committed ORS mirror selected by installation admission.
    pub ors_mirror: SupervisionOrsMirrorBinding,
    /// Exact current active/revocation state selected by admission.
    pub active_state: SupervisionLeaseActiveStateBinding,
}

impl SupervisionLeaseVerificationContext {
    /// Validates the current values before they are used for lease admission.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        if self.now_ms == 0 {
            return Err(SupervisionLeaseError::InvalidContext(
                "now_ms must be greater than zero".to_owned(),
            ));
        }
        non_empty_text_for_lease(&self.lease_id, "context.lease_id")?;
        non_empty_text_for_lease(&self.activation_id, "context.activation_id")?;
        non_empty_text_for_lease(&self.scope_ref, "context.scope_ref")?;
        non_empty_text_for_lease(&self.target_id, "context.target_id")?;
        non_empty_text_for_lease(&self.module_id, "context.module_id")?;
        non_empty_text_for_lease(&self.process_id, "context.process_id")?;
        self.observation_scope
            .validate()
            .map_err(|error| SupervisionLeaseError::InvalidContext(error.to_string()))?;
        if self.state_fence.validate().is_err() {
            return Err(SupervisionLeaseError::InvalidContext(
                "state_fence is invalid".to_owned(),
            ));
        }
        if self.state_fence.authority_epoch != self.kernel_epoch {
            return Err(SupervisionLeaseError::InvalidContext(
                "state_fence authority must equal kernel_epoch".to_owned(),
            ));
        }
        if self.state_fence.resource_generation != self.activation_generation {
            return Err(SupervisionLeaseError::InvalidContext(
                "state_fence generation must equal activation_generation".to_owned(),
            ));
        }
        if !is_sha256_hex(&self.public_key_fingerprint) {
            return Err(SupervisionLeaseError::InvalidContext(
                "public_key_fingerprint must be lowercase SHA-256".to_owned(),
            ));
        }
        self.ors_mirror
            .validate()
            .map_err(|error| SupervisionLeaseError::InvalidContext(error.to_string()))?;
        if self.ors_mirror.subject_lease_id != self.lease_id {
            return Err(SupervisionLeaseError::InvalidContext(
                "ORS mirror subject must equal context.lease_id".to_owned(),
            ));
        }
        self.active_state.validate()?;
        for (field, value) in [
            ("context.host_epoch", self.host_epoch.value()),
            (
                "context.activation_generation",
                self.activation_generation.value(),
            ),
            ("context.kernel_epoch", self.kernel_epoch.value()),
            ("context.watchdog_epoch", self.watchdog_epoch.value()),
            ("context.target_generation", self.target_generation.value()),
            ("context.module_generation", self.module_generation.value()),
            (
                "context.process_generation",
                self.process_generation.value(),
            ),
        ] {
            if value == 0 {
                return Err(SupervisionLeaseError::InvalidContext(format!(
                    "{field} must be greater than zero"
                )));
            }
        }
        Ok(())
    }
}

/// Verified lease newtype.  It can only be constructed by a trust-anchor verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSupervisionLease {
    payload: SupervisionLease,
    payload_sha256: String,
    envelope_sha256: String,
    signer_id: String,
    key_id: String,
    algorithm: String,
    signature: String,
    public_key_fingerprint: String,
}

impl VerifiedSupervisionLease {
    /// Returns the authenticated, current payload.
    pub fn payload(&self) -> &SupervisionLease {
        &self.payload
    }

    /// Returns the authenticated legacy lease projection.
    pub fn lease(&self) -> &SupervisionLease {
        &self.payload
    }

    /// Returns the authenticated canonical payload digest.
    pub fn payload_digest(&self) -> Result<String, SupervisionLeaseError> {
        Ok(self.payload_sha256.clone())
    }

    /// Returns the authenticated committed ORS lease revision.
    pub const fn lease_revision(&self) -> u64 {
        self.payload.ors_mirror.lease_revision
    }

    /// Returns the canonical signed-envelope digest.
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_sha256
    }

    /// Returns the authenticated producer identity.
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// Returns the authenticated external key reference.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the fixed signature algorithm identifier.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the encoded signature over the canonical payload.
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Returns the installation-pinned public-key fingerprint used to verify.
    pub fn public_key_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }
}

/// Pure verifier boundary for signed supervision leases.
pub trait SupervisionLeaseVerifier {
    /// Verifies envelope shape, trust-anchor identity, digest, signature, time and fences.
    fn verify(
        &self,
        envelope: &SignedSupervisionLease,
        context: &SupervisionLeaseVerificationContext,
    ) -> Result<VerifiedSupervisionLease, SupervisionLeaseError>;
}

impl SupervisionLeaseVerifier for SupervisionTrustAnchor {
    fn verify(
        &self,
        envelope: &SignedSupervisionLease,
        context: &SupervisionLeaseVerificationContext,
    ) -> Result<VerifiedSupervisionLease, SupervisionLeaseError> {
        self.validate()?;
        context.validate()?;
        envelope.validate()?;
        if envelope.signer_id != self.signer_id {
            return Err(SupervisionLeaseError::TrustAnchorMismatch("signer_id"));
        }
        if envelope.key_id != self.key_id {
            return Err(SupervisionLeaseError::TrustAnchorMismatch("key_id"));
        }
        if envelope.algorithm != self.algorithm {
            return Err(SupervisionLeaseError::TrustAnchorMismatch("algorithm"));
        }
        if self.public_key_fingerprint != context.public_key_fingerprint {
            return Err(SupervisionLeaseError::TrustAnchorMismatch(
                "public_key_fingerprint",
            ));
        }
        let payload = &envelope.payload;
        if payload.lease_id != context.lease_id {
            return Err(SupervisionLeaseError::LeaseIdentityMismatch);
        }
        if payload.installation_id != self.installation_id {
            return Err(SupervisionLeaseError::TrustAnchorMismatch(
                "installation_id",
            ));
        }
        if payload.host_epoch != context.host_epoch
            || payload.activation_generation != context.activation_generation
            || payload.activation_id != context.activation_id
            || payload.kernel_epoch != context.kernel_epoch
            || payload.watchdog_epoch != context.watchdog_epoch
            || payload.state_fence != context.state_fence
            || payload.scope_ref != context.scope_ref
            || payload.observation_scope != context.observation_scope
        {
            return Err(SupervisionLeaseError::EpochOrActivationMismatch);
        }
        let binding = &payload.generation_binding;
        if binding.target_id != context.target_id
            || binding.module_id != context.module_id
            || binding.process_id != context.process_id
            || binding.target_generation != context.target_generation
            || binding.module_generation != context.module_generation
            || binding.process_generation != context.process_generation
        {
            return Err(SupervisionLeaseError::GenerationMismatch);
        }
        if payload.ors_mirror != context.ors_mirror {
            return Err(SupervisionLeaseError::OrsMirrorMismatch);
        }
        if payload.state != context.active_state.state
            || payload.revocation_id != context.active_state.revocation_id
            || payload.revocation_epoch != context.active_state.revocation_epoch
        {
            return Err(SupervisionLeaseError::ActiveStateMismatch);
        }
        if payload.state != LeaseState::Active || payload.terminal_disposition.is_some() {
            return Err(SupervisionLeaseError::InactiveLease);
        }
        if context.now_ms < payload.issued_at_ms || context.now_ms >= payload.expires_at_ms {
            return Err(SupervisionLeaseError::Expired);
        }
        let signature =
            decode_hex::<{ SUPERVISION_LEASE_SIGNATURE_BYTES }>(&envelope.signature, "signature")?;
        let public_key: &[u8; SUPERVISION_LEASE_PUBLIC_KEY_BYTES] =
            self.public_key.as_slice().try_into().map_err(|_| {
                SupervisionLeaseError::InvalidPublicKeyLength {
                    observed: self.public_key.len(),
                }
            })?;
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|error| SupervisionLeaseError::InvalidPublicKey(error.to_string()))?;
        let signature = Signature::from_bytes(&signature);
        let bytes = payload.canonical_bytes()?;
        verifying_key
            .verify_strict(&bytes, &signature)
            .map_err(|error| SupervisionLeaseError::SignatureInvalid(error.to_string()))?;
        Ok(VerifiedSupervisionLease {
            payload: payload.clone(),
            payload_sha256: envelope.payload_sha256.clone(),
            envelope_sha256: envelope.envelope_digest()?,
            signer_id: envelope.signer_id.clone(),
            key_id: envelope.key_id.clone(),
            algorithm: envelope.algorithm.clone(),
            signature: envelope.signature.clone(),
            public_key_fingerprint: self.public_key_fingerprint.clone(),
        })
    }
}

/// Errors raised by signed lease construction and verification.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SupervisionLeaseError {
    /// Payload failed canonical runtime validation.
    #[error("invalid supervision lease payload: {0}")]
    InvalidPayload(RuntimeContractError),
    /// Canonical serialization failed.
    #[error("supervision lease canonicalization failed: {0}")]
    Canonicalization(String),
    /// A required identity field is invalid.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: String },
    /// Signature algorithm is not admitted.
    #[error("unsupported supervision lease signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Signed digest did not match canonical payload bytes.
    #[error("supervision lease payload digest mismatch")]
    DigestMismatch,
    /// Signature length is not exactly Ed25519's 64 bytes.
    #[error("invalid supervision lease signature length: {observed}")]
    InvalidSignatureLength { observed: usize },
    /// Public-key length is not exactly Ed25519's 32 bytes.
    #[error("invalid supervision lease public-key length: {observed}")]
    InvalidPublicKeyLength { observed: usize },
    /// Hex field was malformed.
    #[error("{field} must be lowercase hexadecimal with exactly {expected} bytes")]
    InvalidHex { field: String, expected: usize },
    /// Public key failed curve validation.
    #[error("invalid supervision lease public key: {0}")]
    InvalidPublicKey(String),
    /// Signature failed strict Ed25519 verification.
    #[error("invalid supervision lease signature: {0}")]
    SignatureInvalid(String),
    /// Trust anchor fingerprint does not match its external public key.
    #[error("supervision trust-anchor fingerprint mismatch")]
    TrustAnchorFingerprintMismatch,
    /// Envelope identity did not match the installation-pinned anchor.
    #[error("supervision trust-anchor mismatch for {0}")]
    TrustAnchorMismatch(&'static str),
    /// Current epoch or activation identity did not match the signed payload.
    #[error("supervision lease epoch or activation mismatch")]
    EpochOrActivationMismatch,
    /// Signed lease identity did not match the independently admitted lease.
    #[error("supervision lease identity mismatch")]
    LeaseIdentityMismatch,
    /// Current target/module/process generation did not match the signed payload.
    #[error("supervision lease generation mismatch")]
    GenerationMismatch,
    /// Signed ORS mirror did not match the independently admitted revision.
    #[error("supervision lease ORS mirror mismatch")]
    OrsMirrorMismatch,
    /// Signed lease lifecycle state did not match current admission state.
    #[error("supervision lease active-state or revocation mismatch")]
    ActiveStateMismatch,
    /// Lease is not active at the verification boundary.
    #[error("supervision lease is not active")]
    InactiveLease,
    /// Lease is outside its signed validity window.
    #[error("supervision lease is expired or not yet valid")]
    Expired,
    /// Verification context is incomplete or invalid.
    #[error("invalid supervision lease verification context: {0}")]
    InvalidContext(String),
    /// Producer returned a signature which cannot be represented by the contract.
    #[error("signer returned a non-Ed25519 signature")]
    SignerOutput,
    /// Producer-side signing failed.
    #[error("supervision lease signing failed: {0}")]
    Signing(String),
}

fn invalid_lease_field(field: &'static str, reason: impl Into<String>) -> RuntimeContractError {
    // RuntimeContractError carries static field labels for stable diagnostics;
    // detailed dynamic reasons are intentionally collapsed at this boundary.
    let _ = reason.into();
    RuntimeContractError::InvalidField {
        field,
        reason: "supervision lease invariant failed",
    }
}

fn non_empty_text(value: &str, field: &'static str) -> Result<(), RuntimeContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid_lease_field(field, "invalid text"));
    }
    Ok(())
}

fn non_empty_text_list(values: &[String], field: &'static str) -> Result<(), RuntimeContractError> {
    if values.is_empty() {
        return Err(invalid_lease_field(field, "must not be empty"));
    }
    for value in values {
        non_empty_text(value, field)?;
    }
    Ok(())
}

fn non_empty_text_for_lease(value: &str, field: &str) -> Result<(), SupervisionLeaseError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SupervisionLeaseError::InvalidText {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

fn decode_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N], SupervisionLeaseError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SupervisionLeaseError::InvalidHex {
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
