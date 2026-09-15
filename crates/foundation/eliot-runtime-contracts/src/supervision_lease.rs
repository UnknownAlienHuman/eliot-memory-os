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
    AuthorityEpoch, ContractVersion, EpochId, ResourceGeneration, StateFence, canonical_json_bytes,
    sha256_hex,
};

use super::{HealthDimension, LeaseState, RuntimeContractError};

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
    pub(crate) fn validate(&self) -> Result<(), RuntimeContractError> {
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

/// Signed binding to an ORS-reserved revision and its predecessor receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionOrsMirrorBinding {
    /// Stable ORS record identity.
    pub record_id: String,
    /// Exact lease subject represented by this ORS record.
    pub subject_lease_id: String,
    /// Positive monotonic lease revision in the ORS record.
    pub lease_revision: u64,
    /// SHA-256 of the ORS commit ticket reserved before this payload was signed.
    pub ticket_sha256: String,
    /// Optional SHA-256 of the immediately previous committed ORS receipt.
    pub previous_receipt_sha256: Option<String>,
}

impl SupervisionOrsMirrorBinding {
    pub(crate) fn validate(&self) -> Result<(), RuntimeContractError> {
        non_empty_text(&self.record_id, "ors_mirror.record_id")?;
        non_empty_text(&self.subject_lease_id, "ors_mirror.subject_lease_id")?;
        if self.lease_revision == 0 {
            return Err(invalid_lease_field(
                "ors_mirror.lease_revision",
                "must be greater than zero",
            ));
        }
        if !is_sha256_hex(&self.ticket_sha256) {
            return Err(invalid_lease_field(
                "ors_mirror.ticket_sha256",
                "must be a lowercase SHA-256 digest",
            ));
        }
        if let Some(previous) = &self.previous_receipt_sha256
            && !is_sha256_hex(previous)
        {
            return Err(invalid_lease_field(
                "ors_mirror.previous_receipt_sha256",
                "must be absent or a lowercase SHA-256 digest",
            ));
        }
        if (self.lease_revision == 1) != self.previous_receipt_sha256.is_none() {
            return Err(invalid_lease_field(
                "ors_mirror.previous_receipt_sha256",
                "must be absent only for the first revision",
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
    pub(crate) fn validate(&self) -> Result<(), RuntimeContractError> {
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
    /// Kernel authority epoch (lineage-aware exact tuple).
    pub kernel_epoch: EpochId,
    /// Watchdog authority epoch.
    pub watchdog_epoch: AuthorityEpoch,
    /// Target/module/process generation binding.
    pub generation_binding: SupervisionGenerationBinding,
    /// State fence captured with the activation.
    pub state_fence: StateFence,
    /// ORS ticket, predecessor receipt and monotonic revision binding.
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
        // `EpochId` is always a validated non-zero `(lineage_id, sequence)`
        // tuple by construction; no scalar zero check (Implements #64).
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
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&self.kernel_epoch)
        {
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
    /// Current Kernel epoch (lineage-aware exact tuple).
    pub kernel_epoch: EpochId,
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
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&self.kernel_epoch)
        {
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
        // `EpochId` kernel epoch is always a validated non-zero tuple;
        // only scalar contours retain zero checks (Implements #64).
        for (field, value) in [
            ("context.host_epoch", self.host_epoch.value()),
            (
                "context.activation_generation",
                self.activation_generation.value(),
            ),
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

/// ORS predecessor values bound by a signed terminal transition.
///
/// This value is not authority by itself.  A terminal verifier binds it to an
/// exact verified active envelope, and ORS must still compare it with the
/// current durable receipt before committing the transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeasePredecessorProof {
    /// Stable lease identity of the active predecessor.
    pub lease_id: String,
    /// ORS record identity of the active predecessor.
    pub record_id: String,
    /// Positive ORS revision of the active predecessor.
    pub lease_revision: u64,
    /// Canonical digest of the active predecessor's committed ORS receipt.
    pub receipt_sha256: String,
    /// Canonical digest of the active predecessor's signed envelope.
    pub envelope_sha256: String,
}

impl SupervisionLeasePredecessorProof {
    /// Validates shape only; ORS performs the authoritative durable comparison.
    pub fn validate(&self) -> Result<(), SupervisionLeaseError> {
        non_empty_text_for_lease(&self.lease_id, "predecessor.lease_id")?;
        non_empty_text_for_lease(&self.record_id, "predecessor.record_id")?;
        if self.lease_revision == 0 {
            return Err(SupervisionLeaseError::InvalidContext(
                "predecessor.lease_revision must be greater than zero".to_owned(),
            ));
        }
        if !is_sha256_hex(&self.receipt_sha256) {
            return Err(SupervisionLeaseError::InvalidContext(
                "predecessor.receipt_sha256 must be lowercase SHA-256".to_owned(),
            ));
        }
        if !is_sha256_hex(&self.envelope_sha256) {
            return Err(SupervisionLeaseError::InvalidContext(
                "predecessor.envelope_sha256 must be lowercase SHA-256".to_owned(),
            ));
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

/// Sealed verification token for a signed terminal transition.
///
/// It cannot be constructed from a caller-authored terminal context.  The
/// installation trust anchor authenticates the terminal envelope and binds it
/// to an exact prior [`VerifiedSupervisionLease`] plus an ORS predecessor proof.
/// ORS remains responsible for comparing that proof with durable current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSupervisionLeaseTerminalTransition {
    prior_active: VerifiedSupervisionLease,
    predecessor: SupervisionLeasePredecessorProof,
    terminal_envelope: SignedSupervisionLease,
}

impl VerifiedSupervisionLeaseTerminalTransition {
    /// Returns the exact authenticated active predecessor.
    pub fn prior_active(&self) -> &VerifiedSupervisionLease {
        &self.prior_active
    }

    /// Returns the predecessor values which ORS must compare durably.
    pub fn predecessor(&self) -> &SupervisionLeasePredecessorProof {
        &self.predecessor
    }

    /// Returns the authenticated terminal signed envelope.
    pub fn envelope(&self) -> &SignedSupervisionLease {
        &self.terminal_envelope
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

impl SupervisionTrustAnchor {
    /// Authenticates a terminal revision against an exact verified active
    /// predecessor without widening the active admission verifier.
    #[allow(
        clippy::too_many_lines,
        reason = "terminal authentication must bind anchor, predecessor, lineage and signature"
    )]
    pub fn verify_terminal_transition(
        &self,
        prior_active: &VerifiedSupervisionLease,
        terminal_envelope: &SignedSupervisionLease,
        predecessor: &SupervisionLeasePredecessorProof,
    ) -> Result<VerifiedSupervisionLeaseTerminalTransition, SupervisionLeaseError> {
        self.validate()?;
        predecessor.validate()?;
        terminal_envelope.validate()?;

        if prior_active.signer_id != self.signer_id
            || prior_active.key_id != self.key_id
            || prior_active.algorithm != self.algorithm
            || prior_active.public_key_fingerprint != self.public_key_fingerprint
            || prior_active.payload.installation_id != self.installation_id
        {
            return Err(SupervisionLeaseError::TrustAnchorMismatch(
                "active_predecessor",
            ));
        }
        if terminal_envelope.signer_id != self.signer_id {
            return Err(SupervisionLeaseError::TrustAnchorMismatch("signer_id"));
        }
        if terminal_envelope.key_id != self.key_id {
            return Err(SupervisionLeaseError::TrustAnchorMismatch("key_id"));
        }
        if terminal_envelope.algorithm != self.algorithm {
            return Err(SupervisionLeaseError::TrustAnchorMismatch("algorithm"));
        }

        let prior = &prior_active.payload;
        let terminal = &terminal_envelope.payload;
        if prior.state != LeaseState::Active || prior.terminal_disposition.is_some() {
            return Err(SupervisionLeaseError::InactiveLease);
        }
        if !matches!(
            terminal.state,
            LeaseState::Released
                | LeaseState::Expired
                | LeaseState::Revoked
                | LeaseState::Superseded
                | LeaseState::Closed
        ) {
            return Err(SupervisionLeaseError::InactiveLease);
        }
        if predecessor.lease_id != prior.lease_id
            || predecessor.record_id != prior.ors_mirror.record_id
            || predecessor.lease_revision != prior.ors_mirror.lease_revision
            || predecessor.envelope_sha256 != prior_active.envelope_sha256
        {
            return Err(SupervisionLeaseError::TerminalTransitionMismatch(
                "active predecessor",
            ));
        }
        let expected_revision = predecessor.lease_revision.checked_add(1).ok_or(
            SupervisionLeaseError::TerminalTransitionMismatch("revision overflow"),
        )?;
        if terminal.ors_mirror.lease_revision != expected_revision
            || terminal.ors_mirror.previous_receipt_sha256.as_deref()
                != Some(predecessor.receipt_sha256.as_str())
            || terminal.ors_mirror.record_id == predecessor.record_id
        {
            return Err(SupervisionLeaseError::TerminalTransitionMismatch(
                "ORS predecessor binding",
            ));
        }
        if terminal.lease_id != prior.lease_id
            || terminal.ors_mirror.subject_lease_id != prior.lease_id
            || terminal.scope_ref != prior.scope_ref
            || terminal.observation_scope != prior.observation_scope
            || terminal.installation_id != prior.installation_id
            || terminal.host_epoch != prior.host_epoch
            || terminal.activation_id != prior.activation_id
            || terminal.activation_generation != prior.activation_generation
            || terminal.kernel_epoch != prior.kernel_epoch
            || terminal.watchdog_epoch != prior.watchdog_epoch
            || terminal.generation_binding != prior.generation_binding
            || terminal.state_fence != prior.state_fence
            || terminal.issued_at_ms != prior.issued_at_ms
            || terminal.expires_at_ms != prior.expires_at_ms
            || terminal.renew_before_ms != prior.renew_before_ms
            || terminal.wake_policy != prior.wake_policy
        {
            return Err(SupervisionLeaseError::TerminalTransitionMismatch(
                "lease lineage",
            ));
        }

        let signature = decode_hex::<{ SUPERVISION_LEASE_SIGNATURE_BYTES }>(
            &terminal_envelope.signature,
            "signature",
        )?;
        let public_key: &[u8; SUPERVISION_LEASE_PUBLIC_KEY_BYTES] =
            self.public_key.as_slice().try_into().map_err(|_| {
                SupervisionLeaseError::InvalidPublicKeyLength {
                    observed: self.public_key.len(),
                }
            })?;
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|error| SupervisionLeaseError::InvalidPublicKey(error.to_string()))?;
        verifying_key
            .verify_strict(
                &terminal.canonical_bytes()?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|error| SupervisionLeaseError::SignatureInvalid(error.to_string()))?;

        Ok(VerifiedSupervisionLeaseTerminalTransition {
            prior_active: prior_active.clone(),
            predecessor: predecessor.clone(),
            terminal_envelope: terminal_envelope.clone(),
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
    /// Terminal revision does not bind the exact verified active predecessor.
    #[error("supervision lease terminal transition mismatch for {0}")]
    TerminalTransitionMismatch(&'static str),
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

// ============================================================================
// Daemon-heartbeat supervision-lease renewal contract (issue #88, wave 1).
//
// Issue #88, first sentence: `eliotd` owns an independent 5-second cadence
// whose health branch calls only `KernelTransitionPort::health`, which returns
// `StoreHealth`. That poll carries no lease identity, revision, progress
// cursor, or monotonic evidence, so it can never renew supervision authority.
// This section defines the only renewal evidence the daemon may submit
// instead: a [`DaemonProgressObservation`] bound to the exact current lease
// predecessor (never `StoreHealth`; this type has no `StoreHealth` field by
// construction), the renewal terms owned by
// [`DaemonSupervisionRenewalPolicy`], and the pure renewal join
// ([`evaluate_daemon_supervision_renewal`]) the Kernel owner (wave 2) applies
// against its exact current state. The daemon producer (wave 3) submits
// observations; it never decides renewal. Watchdog consumes renewed
// leases/receipts and can never extend them.
//
// Wave-1 scope notes:
// - Cadence timing (the 5-second producer tick) stays with the wave-3 daemon
//   producer; this contract owns only the renewal bounds
//   (`validity_ms`/`renew_after_ms`), observation freshness, and monotonicity.
// - No timing constants are duplicated here: the policy carries no `Default`
//   and no `60_000`/`30_000` literals, so wave 2 can adopt it as the single
//   timing owner without a parallel default.
// - The daemon never supplies lease expiry: [`DaemonProgressObservation`]
//   has no expiry field (see `must_not_include: caller-selected lease
//   expiry`); the Kernel computes expiry from its own window.

/// Domain separator for the daemon supervision heartbeat observation.
pub const DAEMON_SUPERVISION_HEARTBEAT_DOMAIN: &str =
    "eliot.runtime.eliotd-supervision-heartbeat.v1";
/// Stable schema marker for the daemon supervision heartbeat observation.
pub const DAEMON_SUPERVISION_HEARTBEAT_SCHEMA: &str = "eliot.daemon-supervision-heartbeat.v1";
/// Stable contract identity for the daemon supervision heartbeat surface.
pub const DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_NAME: &str =
    "eliot.foundation.runtime-contracts.daemon-supervision-heartbeat";
/// Current contract revision for the daemon supervision heartbeat surface.
pub const DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_VERSION: ContractVersion =
    ContractVersion::new(1, 0, 0);
/// Maximum process/transport evidence handles carried by one observation.
pub const DAEMON_HEARTBEAT_MAX_EVIDENCE_REFS: usize = 8;
/// Maximum per-channel accepted cursors tracked in the current state (one per
/// progress channel).
pub const DAEMON_HEARTBEAT_MAX_CHANNEL_CURSORS: usize = 3;

/// Closed progress dispositions for a daemon heartbeat observation.
///
/// Only the first five dispositions are renewal-eligible, each under its own
/// rule enforced by [`evaluate_daemon_supervision_renewal`]. [`Self::NoProgress`]
/// and [`Self::ObservationGap`] never renew: a health-only signal (the issue
/// #88 `StoreHealth` poll shape) therefore cannot extend supervision authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DaemonProgressDisposition {
    /// Observed claim/dispatch/apply cursor advanced past the accepted cursor.
    ForwardProgress,
    /// Explicitly admitted idle with no hidden pending effect.
    IdleAdmitted,
    /// Blocked on a named dependency revision/condition.
    WaitingOnNamedDependency,
    /// Draining exact reconciliation obligations; admits no new work.
    Draining,
    /// Progress with a failed health dimension; dimensions stay separate.
    DegradedProgress,
    /// Daemon alive but no authenticated progress evidence.
    NoProgress,
    /// Observation continuity broken; a fresh observation is required.
    ObservationGap,
}

impl DaemonProgressDisposition {
    /// Returns whether this disposition may renew under its own rule.
    #[must_use]
    pub const fn is_renewal_eligible(self) -> bool {
        !matches!(self, Self::NoProgress | Self::ObservationGap)
    }
}

/// Bounded progress channel whose cursor an observation reports.
///
/// One observation carries exactly one channel cursor; the Kernel tracks the
/// accepted cursor per channel so claim, dispatch, and apply heartbeats
/// interleave without sharing a cursor.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DaemonProgressChannel {
    /// Agent activation claim progress.
    Claim,
    /// Dispatch progress.
    Dispatch,
    /// Apply progress.
    Apply,
}

/// Accepted cursor for one progress channel.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonChannelCursor {
    /// Channel this cursor belongs to.
    pub channel: DaemonProgressChannel,
    /// Last cursor accepted by the Kernel for this channel.
    pub cursor: u64,
}

/// Independent health dimensions carried as evidence with an observation.
///
/// Store health may be included as the `store_dependency` dimension, but it
/// is never the renewal signal: renewal requires an eligible
/// [`DaemonProgressDisposition`] plus cursor evidence. Daemon, transport,
/// Store-dependency, and application-readiness dimensions are never copied
/// into one another.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonHeartbeatHealth {
    /// Daemon process liveness dimension.
    pub daemon: HealthDimension,
    /// Authenticated transport continuity dimension.
    pub transport: HealthDimension,
    /// Store process/bridge dependency dimension (evidence only).
    pub store_dependency: HealthDimension,
    /// Governor application-readiness dimension (evidence only).
    pub app_readiness: HealthDimension,
}

impl DaemonHeartbeatHealth {
    /// Fully healthy evidence vector.
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            daemon: HealthDimension::Healthy,
            transport: HealthDimension::Healthy,
            store_dependency: HealthDimension::Healthy,
            app_readiness: HealthDimension::Healthy,
        }
    }

    /// Returns true when any dimension reports failure.
    #[must_use]
    pub const fn has_failed_dimension(self) -> bool {
        matches!(self.daemon, HealthDimension::Failed)
            || matches!(self.transport, HealthDimension::Failed)
            || matches!(self.store_dependency, HealthDimension::Failed)
            || matches!(self.app_readiness, HealthDimension::Failed)
    }
}

/// Daemon heartbeat/progress observation submitted for lease renewal.
///
/// This is a candidate statement about the daemon's own current generation;
/// it decides nothing. It binds the daemon process/generation lineage, the
/// lineaged authority epoch and state fence, the current lease
/// ID/revision/predecessor receipt, boot and ephemeral transport-session
/// evidence, one progress cursor, monotonic and wall-clock evidence, and
/// independent health dimensions. It deliberately has no `StoreHealth`
/// field and no expiry field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonProgressObservation {
    /// Strict wire schema marker.
    pub schema: String,
    /// Strict contract identity name.
    pub contract_name: String,
    /// Strict contract identity revision.
    pub contract_version: ContractVersion,
    /// Idempotency identity for this exact observation revision.
    pub observation_id: String,
    /// Installation identity owning the daemon generation.
    pub installation_id: String,
    /// Activation identity which issued the current lease.
    pub activation_id: String,
    /// Activation generation selected by Host/Kernel.
    pub activation_generation: ResourceGeneration,
    /// Target/module/process generation binding of the observing daemon.
    pub generation_binding: SupervisionGenerationBinding,
    /// Bounded daemon artifact identity.
    pub daemon_artifact_id: String,
    /// Lowercase SHA-256 digest of the active daemon configuration.
    pub daemon_config_digest: String,
    /// Kernel authority epoch (lineage-aware exact tuple).
    pub kernel_epoch: EpochId,
    /// Exact Kernel-owned state fence.
    pub state_fence: StateFence,
    /// Boot identity; a new boot invalidates prior monotonic observations.
    pub boot_id: String,
    /// Ephemeral transport-session evidence; never a durable Session identity
    /// (durable process/session binding is owned by #79).
    pub transport_session_evidence: String,
    /// Ephemeral connection handle; diagnostic only, never renewal identity.
    pub transport_connection_evidence: String,
    /// Current supervision lease identity cited by the daemon.
    pub lease_id: String,
    /// Current supervision lease revision cited by the daemon.
    pub lease_revision: u64,
    /// Digest of the current ORS receipt cited as predecessor.
    pub predecessor_receipt_sha256: String,
    /// Progress channel this observation reports.
    pub progress_channel: DaemonProgressChannel,
    /// Observed cursor for the channel.
    pub progress_cursor: u64,
    /// Previously accepted cursor for the channel.
    pub previous_progress_cursor: u64,
    /// Monotonic-compatible observation time in milliseconds.
    pub observed_monotonic_ms: u64,
    /// Wall-clock observation time in Unix milliseconds (diagnostic).
    pub observed_wall_ms: u64,
    /// Progress disposition governing renewal eligibility.
    pub disposition: DaemonProgressDisposition,
    /// Explicit current idle contract; required for `IDLE_ADMITTED` only.
    pub idle_contract_id: Option<String>,
    /// Named dependency revision/condition; required for
    /// `WAITING_ON_NAMED_DEPENDENCY` only.
    pub waiting_on_dependency: Option<String>,
    /// Bounded process/transport evidence handles (no task content, no model
    /// output, no log prose, no metrics payload).
    pub evidence_refs: Vec<String>,
    /// Independent health dimensions (evidence only, never renewal authority).
    pub health: DaemonHeartbeatHealth,
    /// Whether Watchdog coverage is currently observed.
    pub watchdog_covered: bool,
}

impl DaemonProgressObservation {
    /// Validates shape and cross-field bindings without consulting authority.
    pub fn validate(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        self.validate_identity()?;
        self.validate_lineage()?;
        self.validate_timing_and_cursor()?;
        self.validate_disposition_shape()?;
        if self.evidence_refs.len() > DAEMON_HEARTBEAT_MAX_EVIDENCE_REFS {
            return Err(heartbeat_shape(
                "observation.evidence_refs: exceeds the bounded evidence limit",
            ));
        }
        for evidence in &self.evidence_refs {
            heartbeat_text(evidence, "observation.evidence_refs")?;
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        if self.schema != DAEMON_SUPERVISION_HEARTBEAT_SCHEMA {
            return Err(heartbeat_shape("schema: unsupported schema"));
        }
        if self.contract_name != DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_NAME {
            return Err(heartbeat_shape(
                "contract_name: unsupported contract identity",
            ));
        }
        if self.contract_version != DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_VERSION {
            return Err(heartbeat_shape(
                "contract_version: unsupported contract revision",
            ));
        }
        heartbeat_text(&self.observation_id, "observation.observation_id")?;
        heartbeat_text(&self.installation_id, "observation.installation_id")?;
        heartbeat_text(&self.activation_id, "observation.activation_id")?;
        if self.activation_generation.value() == 0 {
            return Err(heartbeat_shape(
                "observation.activation_generation: must be greater than zero",
            ));
        }
        self.generation_binding
            .validate()
            .map_err(|error| heartbeat_shape(format!("observation: {error}")))?;
        heartbeat_text(&self.daemon_artifact_id, "observation.daemon_artifact_id")?;
        heartbeat_digest(
            &self.daemon_config_digest,
            "observation.daemon_config_digest",
        )
    }

    fn validate_lineage(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        // `EpochId` is always a validated non-zero `(lineage_id, sequence)`
        // tuple by construction; no scalar zero check (Implements #64).
        self.state_fence
            .validate()
            .map_err(|error| heartbeat_shape(format!("observation.state_fence: {error}")))?;
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&self.kernel_epoch)
        {
            return Err(heartbeat_shape(
                "observation.state_fence.authority_epoch: must equal kernel_epoch",
            ));
        }
        if self.state_fence.resource_generation != self.activation_generation {
            return Err(heartbeat_shape(
                "observation.state_fence.resource_generation: must equal activation_generation",
            ));
        }
        heartbeat_text(&self.boot_id, "observation.boot_id")?;
        heartbeat_text(
            &self.transport_session_evidence,
            "observation.transport_session_evidence",
        )?;
        heartbeat_text(
            &self.transport_connection_evidence,
            "observation.transport_connection_evidence",
        )?;
        heartbeat_text(&self.lease_id, "observation.lease_id")?;
        if self.lease_revision == 0 {
            return Err(heartbeat_shape(
                "observation.lease_revision: must be greater than zero",
            ));
        }
        heartbeat_digest(
            &self.predecessor_receipt_sha256,
            "observation.predecessor_receipt_sha256",
        )
    }

    fn validate_timing_and_cursor(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        if self.observed_monotonic_ms == 0 {
            return Err(heartbeat_shape(
                "observation.observed_monotonic_ms: monotonic evidence is required",
            ));
        }
        if self.observed_wall_ms == 0 {
            return Err(heartbeat_shape(
                "observation.observed_wall_ms: wall-clock evidence is required",
            ));
        }
        if self.progress_cursor < self.previous_progress_cursor {
            return Err(heartbeat_shape(
                "observation.progress_cursor: must not regress its own previous cursor",
            ));
        }
        Ok(())
    }

    fn validate_disposition_shape(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        match self.disposition {
            DaemonProgressDisposition::IdleAdmitted => {
                if self
                    .idle_contract_id
                    .as_deref()
                    .is_none_or(|contract| contract.trim().is_empty())
                {
                    return Err(heartbeat_shape(
                        "observation.idle_contract_id: is required for IDLE_ADMITTED",
                    ));
                }
            }
            DaemonProgressDisposition::WaitingOnNamedDependency => {
                if self
                    .waiting_on_dependency
                    .as_deref()
                    .is_none_or(|dependency| dependency.trim().is_empty())
                {
                    return Err(heartbeat_shape(
                        "observation.waiting_on_dependency: is required for WAITING_ON_NAMED_DEPENDENCY",
                    ));
                }
            }
            DaemonProgressDisposition::ForwardProgress
            | DaemonProgressDisposition::Draining
            | DaemonProgressDisposition::DegradedProgress
            | DaemonProgressDisposition::NoProgress
            | DaemonProgressDisposition::ObservationGap => {
                if self.idle_contract_id.is_some() {
                    return Err(heartbeat_shape(
                        "observation.idle_contract_id: is only valid for IDLE_ADMITTED",
                    ));
                }
                if self.waiting_on_dependency.is_some() {
                    return Err(heartbeat_shape(
                        "observation.waiting_on_dependency: is only valid for WAITING_ON_NAMED_DEPENDENCY",
                    ));
                }
            }
        }
        if self.evidence_refs.len() > DAEMON_HEARTBEAT_MAX_EVIDENCE_REFS {
            return Err(heartbeat_shape(
                "observation.evidence_refs: exceeds the bounded evidence limit",
            ));
        }
        for evidence in &self.evidence_refs {
            heartbeat_text(evidence, "observation.evidence_refs")?;
        }
        Ok(())
    }

    /// Returns the lowercase SHA-256 digest of the canonical observation bytes.
    ///
    /// The Kernel uses this digest as the idempotency record for exact replay
    /// versus identity-conflict detection.
    pub fn digest(&self) -> Result<String, DaemonSupervisionHeartbeatError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| heartbeat_shape(format!("observation canonicalization: {error}")))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Renewal request joining one observation with its cited ORS predecessor.
///
/// The cited [`SupervisionLeasePredecessorProof`] is the daemon's claim about
/// the current predecessor; the Kernel compares it with its exact durable
/// predecessor before any renewal. The observation must bind this cited
/// predecessor field-for-field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSupervisionRenewalRequest {
    /// Idempotency identity; must equal the observation identity.
    pub request_id: String,
    /// Candidate progress observation from the daemon generation.
    pub observation: DaemonProgressObservation,
    /// Predecessor cited by the daemon as the current ORS revision.
    pub predecessor: SupervisionLeasePredecessorProof,
}

impl DaemonSupervisionRenewalRequest {
    /// Validates shape and the observation/predecessor binding.
    pub fn validate(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        heartbeat_text(&self.request_id, "request.request_id")?;
        self.observation.validate()?;
        self.predecessor
            .validate()
            .map_err(|error| heartbeat_shape(format!("request.predecessor: {error}")))?;
        if self.observation.observation_id != self.request_id {
            return Err(heartbeat_shape(
                "request.request_id: must equal observation.observation_id",
            ));
        }
        if self.observation.lease_id != self.predecessor.lease_id
            || self.observation.lease_revision != self.predecessor.lease_revision
            || self.observation.predecessor_receipt_sha256 != self.predecessor.receipt_sha256
        {
            return Err(heartbeat_shape(
                "request: observation is not bound to its cited predecessor",
            ));
        }
        Ok(())
    }
}

/// Exact Kernel-owned current state the renewal join compares against.
///
/// Every field is current authority selected by the Kernel owner: the exact
/// durable ORS predecessor, lineage identities, boot/session binding, lease
/// window, per-channel accepted cursors, admitted idle contract, last
/// monotonic evidence, idempotency record, and reconciliation flag.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSupervisionCurrentState {
    /// Exact current durable ORS predecessor (Kernel-owned).
    pub predecessor: SupervisionLeasePredecessorProof,
    /// Current installation identity.
    pub installation_id: String,
    /// Current activation identity.
    pub activation_id: String,
    /// Current activation generation.
    pub activation_generation: ResourceGeneration,
    /// Current Kernel epoch (lineage-aware exact tuple).
    pub kernel_epoch: EpochId,
    /// Exact current Kernel-owned state fence.
    pub state_fence: StateFence,
    /// Current target/module/process generation binding.
    pub generation_binding: SupervisionGenerationBinding,
    /// Current boot identity.
    pub boot_id: String,
    /// Current transport-session binding (explicit rebinding on reconnect).
    pub transport_session_evidence: String,
    /// Inclusive lease issue time in Unix milliseconds (Kernel-owned).
    pub lease_issued_at_ms: u64,
    /// Exclusive lease expiry time in Unix milliseconds (Kernel-owned).
    pub lease_expires_at_ms: u64,
    /// Per-channel accepted cursors (at most one entry per channel).
    pub accepted_cursors: Vec<DaemonChannelCursor>,
    /// Currently admitted idle contract, when one is admitted.
    pub admitted_idle_contract: Option<String>,
    /// Last accepted monotonic evidence in milliseconds.
    pub last_monotonic_ms: u64,
    /// Request identity of the last recorded renewal decision, if any.
    pub last_request_id: Option<String>,
    /// Canonical digest of the last recorded observation, if any.
    pub last_observation_sha256: Option<String>,
    /// Successor revision created by the last recorded renewal, if any.
    pub last_successor_revision: Option<u64>,
    /// True while an unknown ORS/live-receipt publication outcome is still
    /// unreconciled; blocks every new successor until exact reconciliation.
    pub reconciliation_pending: bool,
}

impl DaemonSupervisionCurrentState {
    /// Returns the accepted cursor for a channel, or zero when unseen.
    #[must_use]
    pub fn accepted_cursor(&self, channel: DaemonProgressChannel) -> u64 {
        self.accepted_cursors
            .iter()
            .find(|entry| entry.channel == channel)
            .map_or(0, |entry| entry.cursor)
    }

    /// Validates shape and cross-field bindings of the current state.
    pub fn validate(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        self.predecessor
            .validate()
            .map_err(|error| heartbeat_shape(format!("current.predecessor: {error}")))?;
        heartbeat_text(&self.installation_id, "current.installation_id")?;
        heartbeat_text(&self.activation_id, "current.activation_id")?;
        if self.activation_generation.value() == 0 {
            return Err(heartbeat_shape(
                "current.activation_generation: must be greater than zero",
            ));
        }
        self.generation_binding
            .validate()
            .map_err(|error| heartbeat_shape(format!("current: {error}")))?;
        self.state_fence
            .validate()
            .map_err(|error| heartbeat_shape(format!("current.state_fence: {error}")))?;
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&self.kernel_epoch)
        {
            return Err(heartbeat_shape(
                "current.state_fence.authority_epoch: must equal kernel_epoch",
            ));
        }
        if self.state_fence.resource_generation != self.activation_generation {
            return Err(heartbeat_shape(
                "current.state_fence.resource_generation: must equal activation_generation",
            ));
        }
        heartbeat_text(&self.boot_id, "current.boot_id")?;
        heartbeat_text(
            &self.transport_session_evidence,
            "current.transport_session_evidence",
        )?;
        if self.lease_issued_at_ms == 0 || self.lease_expires_at_ms <= self.lease_issued_at_ms {
            return Err(heartbeat_shape(
                "current.lease_issued_at_ms/lease_expires_at_ms: must be a positive ordered interval",
            ));
        }
        if self.accepted_cursors.len() > DAEMON_HEARTBEAT_MAX_CHANNEL_CURSORS {
            return Err(heartbeat_shape(
                "current.accepted_cursors: at most one entry per progress channel",
            ));
        }
        for (index, entry) in self.accepted_cursors.iter().enumerate() {
            if self.accepted_cursors[..index]
                .iter()
                .any(|prior| prior.channel == entry.channel)
            {
                return Err(heartbeat_shape(
                    "current.accepted_cursors: duplicate channel entry",
                ));
            }
        }
        if let Some(contract) = &self.admitted_idle_contract {
            heartbeat_text(contract, "current.admitted_idle_contract")?;
        }
        match (&self.last_request_id, &self.last_observation_sha256) {
            (None, None) => {}
            (Some(request_id), Some(digest)) => {
                heartbeat_text(request_id, "current.last_request_id")?;
                heartbeat_digest(digest, "current.last_observation_sha256")?;
            }
            _ => {
                return Err(heartbeat_shape(
                    "current: last request identity and observation digest must be recorded together",
                ));
            }
        }
        if self.last_successor_revision.is_some() && self.last_request_id.is_none() {
            return Err(heartbeat_shape(
                "current: recorded successor requires a recorded request identity",
            ));
        }
        Ok(())
    }
}

/// Single-owner renewal terms and bounds.
///
/// Wave 2 adopts this policy as the one timing owner for daemon supervision
/// renewal. It carries no defaults so no parallel timing constants can drift
/// beside the Kernel constants it replaces.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSupervisionRenewalPolicy {
    /// Lease validity duration in milliseconds.
    pub validity_ms: u64,
    /// Renewal becomes due this long after issue, in milliseconds.
    pub renew_after_ms: u64,
    /// Maximum age of the wall-clock observation at decision time.
    pub max_observation_age_ms: u64,
    /// Maximum accepted future skew of the wall-clock observation.
    pub max_wall_skew_ms: u64,
    /// Whether observed Watchdog coverage is required for renewal.
    pub require_watchdog_coverage: bool,
}

impl DaemonSupervisionRenewalPolicy {
    /// Validates that the bounds form one coherent strict window.
    pub fn validate(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        if self.validity_ms == 0 {
            return Err(heartbeat_shape(
                "policy.validity_ms: must be greater than zero",
            ));
        }
        if self.renew_after_ms == 0 || self.renew_after_ms >= self.validity_ms {
            return Err(heartbeat_shape(
                "policy.renew_after_ms: must be strictly between zero and validity",
            ));
        }
        if self.max_observation_age_ms == 0 || self.max_observation_age_ms > self.validity_ms {
            return Err(heartbeat_shape(
                "policy.max_observation_age_ms: must be within the validity window",
            ));
        }
        if self.max_wall_skew_ms == 0 {
            return Err(heartbeat_shape(
                "policy.max_wall_skew_ms: must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Returns the absolute renewal deadline for a lease issue time.
    pub const fn renew_before_ms(&self, issued_at_ms: u64) -> Option<u64> {
        match issued_at_ms.checked_add(self.renew_after_ms) {
            Some(deadline) => Some(deadline),
            None => None,
        }
    }
}

/// Kernel renewal decision outcomes.
///
/// Only [`Self::Renewed`] creates a successor revision. [`Self::ExactReplay`]
/// echoes a recorded decision without a new transition. [`Self::NotDue`]
/// performs no ORS transition and mirrors the existing `renew_before_ms`
/// threshold gate. [`Self::DegradedNoRenewal`] records explicit degradation
/// without a successor. [`Self::ReconciliationRequired`] blocks a new
/// successor until the unknown durable outcome is reconciled by exact lease
/// operation identity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DaemonSupervisionRenewalOutcome {
    /// Exactly one successor revision is admitted.
    Renewed,
    /// Exact replay of a recorded request; no new transition.
    ExactReplay,
    /// Genuine observation before the renewal deadline; no transition.
    NotDue,
    /// Explicit degradation recorded; no successor revision.
    DegradedNoRenewal,
    /// Unknown durable outcome; reconcile before any new successor.
    ReconciliationRequired,
}

impl DaemonSupervisionRenewalOutcome {
    /// Returns the stable wire name of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Renewed => "RENEWED",
            Self::ExactReplay => "EXACT_REPLAY",
            Self::NotDue => "NOT_DUE",
            Self::DegradedNoRenewal => "DEGRADED_NO_RENEWAL",
            Self::ReconciliationRequired => "RECONCILIATION_REQUIRED",
        }
    }
}

/// Kernel renewal decision for one request identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSupervisionRenewalDecision {
    /// Request identity this decision answers.
    pub request_id: String,
    /// Lease identity under decision.
    pub lease_id: String,
    /// Decision outcome.
    pub outcome: DaemonSupervisionRenewalOutcome,
    /// Predecessor revision the decision was taken against.
    pub predecessor_revision: u64,
    /// Admitted successor revision; present only for a renewal-shaped outcome.
    pub successor_revision: Option<u64>,
    /// Digest of the predecessor receipt the decision was taken against.
    pub predecessor_receipt_sha256: String,
}

impl DaemonSupervisionRenewalDecision {
    /// Validates the decision shape and successor binding.
    pub fn validate(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        heartbeat_text(&self.request_id, "decision.request_id")?;
        heartbeat_text(&self.lease_id, "decision.lease_id")?;
        if self.predecessor_revision == 0 {
            return Err(heartbeat_shape(
                "decision.predecessor_revision: must be greater than zero",
            ));
        }
        heartbeat_digest(
            &self.predecessor_receipt_sha256,
            "decision.predecessor_receipt_sha256",
        )?;
        match self.successor_revision {
            Some(successor) => {
                let expected = self.predecessor_revision.checked_add(1).ok_or_else(|| {
                    heartbeat_shape("decision.successor_revision: revision overflows")
                })?;
                if successor != expected {
                    return Err(heartbeat_shape(
                        "decision.successor_revision: must be exactly one past the predecessor",
                    ));
                }
            }
            None => {
                if self.outcome == DaemonSupervisionRenewalOutcome::Renewed {
                    return Err(heartbeat_shape(
                        "decision.successor_revision: is required for RENEWED",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Durable renewal receipt proving what the renewal join decided.
///
/// Wave 2 fills the successor and live-receipt digests from the committed ORS
/// revision; a renewal receipt admits exactly one successor bound to the exact
/// predecessor, and a non-renewal receipt carries no successor digests.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSupervisionRenewalReceipt {
    /// Request identity this receipt proves.
    pub request_id: String,
    /// Lease identity under renewal.
    pub lease_id: String,
    /// Decided outcome.
    pub outcome: DaemonSupervisionRenewalOutcome,
    /// Predecessor revision the decision was taken against.
    pub predecessor_revision: u64,
    /// Admitted successor revision, when a successor was admitted.
    pub successor_revision: Option<u64>,
    /// Digest of the predecessor receipt.
    pub predecessor_receipt_sha256: String,
    /// Digest of the committed successor receipt, when admitted.
    pub successor_receipt_sha256: Option<String>,
    /// Digest of the published live receipt, when admitted.
    pub live_receipt_sha256: Option<String>,
}

impl DaemonSupervisionRenewalReceipt {
    /// Validates the receipt shape and successor/live-receipt coherence.
    pub fn validate(&self) -> Result<(), DaemonSupervisionHeartbeatError> {
        heartbeat_text(&self.request_id, "receipt.request_id")?;
        heartbeat_text(&self.lease_id, "receipt.lease_id")?;
        if self.predecessor_revision == 0 {
            return Err(heartbeat_shape(
                "receipt.predecessor_revision: must be greater than zero",
            ));
        }
        heartbeat_digest(
            &self.predecessor_receipt_sha256,
            "receipt.predecessor_receipt_sha256",
        )?;
        match (
            self.successor_revision,
            &self.successor_receipt_sha256,
            &self.live_receipt_sha256,
        ) {
            (Some(successor), Some(successor_receipt), Some(live_receipt)) => {
                let expected = self.predecessor_revision.checked_add(1).ok_or_else(|| {
                    heartbeat_shape("receipt.successor_revision: revision overflows")
                })?;
                if successor != expected {
                    return Err(heartbeat_shape(
                        "receipt.successor_revision: must be exactly one past the predecessor",
                    ));
                }
                heartbeat_digest(successor_receipt, "receipt.successor_receipt_sha256")?;
                heartbeat_digest(live_receipt, "receipt.live_receipt_sha256")?;
            }
            (None, None, None) => {
                if self.outcome == DaemonSupervisionRenewalOutcome::Renewed {
                    return Err(heartbeat_shape(
                        "receipt: RENEWED requires successor and live-receipt digests",
                    ));
                }
            }
            _ => {
                return Err(heartbeat_shape(
                    "receipt: successor revision and digests must be present together",
                ));
            }
        }
        Ok(())
    }
}

/// Typed refusal reasons for daemon supervision heartbeat renewal.
///
/// Every non-success identifies whether a new observation, a new activation,
/// a dependency change, or operator recovery is permitted: shape and
/// predecessor/generation/epoch/boot/timing refusals permit a corrected
/// observation; [`Self::SupervisionLeaseExpired`] requires a new admitted
/// lease/activation path (an old heartbeat can never revive an expired
/// lease); [`Self::IdentityConflict`] requires a fresh request identity.
/// Renewal never fabricates daemon death, Store failure, or semantic
/// resolution.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaemonSupervisionHeartbeatError {
    /// Observation, request, current state, or policy shape is invalid.
    #[error("invalid daemon supervision heartbeat: {0}")]
    InvalidHeartbeatShape(String),
    /// Same request identity with a changed observation revision.
    #[error("daemon heartbeat identity conflict for request {request_id}")]
    IdentityConflict {
        /// Conflicting request identity.
        request_id: String,
    },
    /// Daemon installation/activation/generation lineage mismatch.
    #[error("daemon heartbeat generation mismatch")]
    DaemonGenerationMismatch,
    /// Transport-session binding mismatch (reconnect needs explicit rebinding).
    #[error("daemon heartbeat transport binding mismatch")]
    TransportBindingMismatch,
    /// Cited predecessor is not the exact current ORS predecessor.
    #[error("daemon heartbeat predecessor mismatch for {0}")]
    SupervisionLeasePredecessorMismatch(&'static str),
    /// Genuine observation answered before the deadline at a protocol
    /// boundary that only passes errors; the pure join instead returns an
    /// [`DaemonSupervisionRenewalOutcome::NotDue`] decision and never emits
    /// this variant.
    #[error("supervision lease renewal not due")]
    SupervisionLeaseNotDue,
    /// Decision time reached the Kernel-owned lease expiry.
    #[error("supervision lease expired")]
    SupervisionLeaseExpired,
    /// Lineaged authority epoch mismatch.
    #[error("stale authority epoch")]
    StaleAuthorityEpoch,
    /// State-fence mismatch.
    #[error("stale state fence")]
    StaleStateFence,
    /// Boot identity changed; prior monotonic evidence is invalid.
    #[error("boot identity changed")]
    BootIdentityChanged,
    /// Cursor regressed or is not bound to the accepted predecessor.
    #[error("progress cursor regression")]
    ProgressCursorRegression,
    /// Disposition/cursor evidence is insufficient for renewal.
    #[error("progress evidence insufficient")]
    ProgressEvidenceInsufficient,
    /// Rolled-back, late, or skewed timing evidence, or an explicit gap.
    #[error("observation gap")]
    ObservationGap,
    /// Required Watchdog coverage is not observed.
    #[error("watchdog coverage unavailable")]
    WatchdogCoverageUnavailable,
    /// Durable renewal outcome is unknown; reconcile by exact lease operation
    /// identity before another successor. Constructed by the Kernel/transport
    /// owner on the persistence boundary; the pure join reports
    /// [`DaemonSupervisionRenewalOutcome::ReconciliationRequired`] instead and
    /// never emits this variant.
    #[error("renewal outcome unknown")]
    RenewalOutcomeUnknown,
}

impl DaemonSupervisionHeartbeatError {
    /// Returns the stable wire code for this refusal reason.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidHeartbeatShape(_) => "INVALID_HEARTBEAT_SHAPE",
            Self::IdentityConflict { .. } => "IDENTITY_CONFLICT",
            Self::DaemonGenerationMismatch => "DAEMON_GENERATION_MISMATCH",
            Self::TransportBindingMismatch => "TRANSPORT_BINDING_MISMATCH",
            Self::SupervisionLeasePredecessorMismatch(_) => {
                "SUPERVISION_LEASE_PREDECESSOR_MISMATCH"
            }
            Self::SupervisionLeaseNotDue => "SUPERVISION_LEASE_NOT_DUE",
            Self::SupervisionLeaseExpired => "SUPERVISION_LEASE_EXPIRED",
            Self::StaleAuthorityEpoch => "STALE_AUTHORITY_EPOCH",
            Self::StaleStateFence => "STALE_STATE_FENCE",
            Self::BootIdentityChanged => "BOOT_IDENTITY_CHANGED",
            Self::ProgressCursorRegression => "PROGRESS_CURSOR_REGRESSION",
            Self::ProgressEvidenceInsufficient => "PROGRESS_EVIDENCE_INSUFFICIENT",
            Self::ObservationGap => "OBSERVATION_GAP",
            Self::WatchdogCoverageUnavailable => "WATCHDOG_COVERAGE_UNAVAILABLE",
            Self::RenewalOutcomeUnknown => "RENEWAL_OUTCOME_UNKNOWN",
        }
    }
}

fn heartbeat_shape(reason: impl Into<String>) -> DaemonSupervisionHeartbeatError {
    DaemonSupervisionHeartbeatError::InvalidHeartbeatShape(reason.into())
}

fn heartbeat_text(value: &str, field: &str) -> Result<(), DaemonSupervisionHeartbeatError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(heartbeat_shape(format!(
            "{field}: must be non-blank and free of control characters"
        )));
    }
    Ok(())
}

fn heartbeat_digest(value: &str, field: &str) -> Result<(), DaemonSupervisionHeartbeatError> {
    if !is_sha256_hex(value) {
        return Err(heartbeat_shape(format!(
            "{field}: must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn renewal_decision(
    request: &DaemonSupervisionRenewalRequest,
    current: &DaemonSupervisionCurrentState,
    outcome: DaemonSupervisionRenewalOutcome,
    successor_revision: Option<u64>,
) -> DaemonSupervisionRenewalDecision {
    DaemonSupervisionRenewalDecision {
        request_id: request.request_id.clone(),
        lease_id: request.observation.lease_id.clone(),
        outcome,
        predecessor_revision: current.predecessor.lease_revision,
        successor_revision,
        predecessor_receipt_sha256: current.predecessor.receipt_sha256.clone(),
    }
}

/// Pure renewal join: decides one heartbeat request against exact current state.
///
/// `now_ms` is the injected Kernel clock (milliseconds); this function
/// performs no IO and reads no clock. Check order is load-bearing and pinned
/// by contract tests: shape, idempotent replay/identity-conflict, exact
/// predecessor binding (foreign versus stale carry distinct
/// [`DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch`]
/// details), daemon generation lineage, authority epoch/fence, boot/session
/// binding, lease expiry, monotonic continuity and observation freshness,
/// renewal deadline, disposition eligibility, Watchdog coverage,
/// reconciliation, and finally explicit degradation versus renewal.
///
/// A health-only observation (the issue #88 `StoreHealth` poll shape, i.e. a
/// `NO_PROGRESS` disposition with no cursor evidence) is refused with
/// [`DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient`]: Store
/// health polling can never silently renew supervision authority.
#[allow(
    clippy::too_many_lines,
    reason = "renewal join must evaluate the full ordered refusal taxonomy in one pure function"
)]
pub fn evaluate_daemon_supervision_renewal(
    request: &DaemonSupervisionRenewalRequest,
    current: &DaemonSupervisionCurrentState,
    policy: &DaemonSupervisionRenewalPolicy,
    now_ms: u64,
) -> Result<DaemonSupervisionRenewalDecision, DaemonSupervisionHeartbeatError> {
    request.validate()?;
    current.validate()?;
    policy.validate()?;
    if now_ms == 0 {
        return Err(heartbeat_shape("now_ms: must be greater than zero"));
    }
    let observation = &request.observation;
    let observation_sha256 = observation.digest()?;

    if current.last_request_id.as_deref() == Some(request.request_id.as_str()) {
        if current.last_observation_sha256.as_deref() == Some(observation_sha256.as_str()) {
            return Ok(renewal_decision(
                request,
                current,
                DaemonSupervisionRenewalOutcome::ExactReplay,
                current.last_successor_revision,
            ));
        }
        return Err(DaemonSupervisionHeartbeatError::IdentityConflict {
            request_id: request.request_id.clone(),
        });
    }

    let expected = &current.predecessor;
    let cited = &request.predecessor;
    if cited.lease_id != expected.lease_id {
        return Err(
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("lease_id"),
        );
    }
    if cited.record_id != expected.record_id {
        return Err(
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("record_id"),
        );
    }
    if cited.lease_revision != expected.lease_revision {
        return Err(
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("lease_revision"),
        );
    }
    if cited.receipt_sha256 != expected.receipt_sha256 {
        return Err(
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("receipt_sha256"),
        );
    }
    if cited.envelope_sha256 != expected.envelope_sha256 {
        return Err(
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("envelope_sha256"),
        );
    }

    if observation.installation_id != current.installation_id
        || observation.activation_id != current.activation_id
        || observation.activation_generation != current.activation_generation
        || observation.generation_binding != current.generation_binding
    {
        return Err(DaemonSupervisionHeartbeatError::DaemonGenerationMismatch);
    }

    if !observation
        .kernel_epoch
        .is_same_authority(&current.kernel_epoch)
    {
        return Err(DaemonSupervisionHeartbeatError::StaleAuthorityEpoch);
    }
    if observation.state_fence != current.state_fence {
        return Err(DaemonSupervisionHeartbeatError::StaleStateFence);
    }

    if observation.boot_id != current.boot_id {
        return Err(DaemonSupervisionHeartbeatError::BootIdentityChanged);
    }
    if observation.transport_session_evidence != current.transport_session_evidence {
        return Err(DaemonSupervisionHeartbeatError::TransportBindingMismatch);
    }

    if now_ms >= current.lease_expires_at_ms {
        return Err(DaemonSupervisionHeartbeatError::SupervisionLeaseExpired);
    }

    if observation.observed_monotonic_ms < current.last_monotonic_ms {
        return Err(DaemonSupervisionHeartbeatError::ObservationGap);
    }
    if observation.observed_wall_ms > now_ms {
        if observation.observed_wall_ms - now_ms > policy.max_wall_skew_ms {
            return Err(DaemonSupervisionHeartbeatError::ObservationGap);
        }
    } else if now_ms - observation.observed_wall_ms > policy.max_observation_age_ms {
        return Err(DaemonSupervisionHeartbeatError::ObservationGap);
    }

    let renew_before_ms = current
        .lease_issued_at_ms
        .checked_add(policy.renew_after_ms)
        .ok_or_else(|| heartbeat_shape("policy: renewal deadline overflows"))?;
    if now_ms < renew_before_ms {
        return Ok(renewal_decision(
            request,
            current,
            DaemonSupervisionRenewalOutcome::NotDue,
            None,
        ));
    }

    let accepted = current.accepted_cursor(observation.progress_channel);
    if observation.previous_progress_cursor != accepted {
        return Err(DaemonSupervisionHeartbeatError::ProgressCursorRegression);
    }
    match observation.disposition {
        DaemonProgressDisposition::ForwardProgress => {
            if observation.progress_cursor <= accepted {
                return Err(DaemonSupervisionHeartbeatError::ProgressCursorRegression);
            }
        }
        DaemonProgressDisposition::IdleAdmitted => {
            if current.admitted_idle_contract.as_deref() != observation.idle_contract_id.as_deref()
            {
                return Err(DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient);
            }
            if observation.progress_cursor != accepted {
                return Err(DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient);
            }
        }
        DaemonProgressDisposition::WaitingOnNamedDependency
        | DaemonProgressDisposition::Draining
        | DaemonProgressDisposition::DegradedProgress => {}
        DaemonProgressDisposition::NoProgress => {
            return Err(DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient);
        }
        DaemonProgressDisposition::ObservationGap => {
            return Err(DaemonSupervisionHeartbeatError::ObservationGap);
        }
    }

    if policy.require_watchdog_coverage && !observation.watchdog_covered {
        return Err(DaemonSupervisionHeartbeatError::WatchdogCoverageUnavailable);
    }

    if current.reconciliation_pending {
        return Ok(renewal_decision(
            request,
            current,
            DaemonSupervisionRenewalOutcome::ReconciliationRequired,
            None,
        ));
    }

    if observation.disposition == DaemonProgressDisposition::DegradedProgress
        && observation.health.has_failed_dimension()
    {
        return Ok(renewal_decision(
            request,
            current,
            DaemonSupervisionRenewalOutcome::DegradedNoRenewal,
            None,
        ));
    }

    let successor_revision = expected
        .lease_revision
        .checked_add(1)
        .ok_or_else(|| heartbeat_shape("current.predecessor.lease_revision: revision overflows"))?;
    Ok(renewal_decision(
        request,
        current,
        DaemonSupervisionRenewalOutcome::Renewed,
        Some(successor_revision),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod daemon_heartbeat_tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochLineageId, ResourceGeneration, StateFence, TaskRevision};

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    /// Lineage-A fixture epoch for tests (canonical UUID lineage, no scalar).
    fn test_epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn generation(value: u64) -> ResourceGeneration {
        ResourceGeneration::new(value).expect("non-zero test generation")
    }

    fn generation_binding() -> SupervisionGenerationBinding {
        SupervisionGenerationBinding {
            target_id: "eliotd".to_owned(),
            target_generation: generation(1),
            module_id: "eliotd".to_owned(),
            module_generation: generation(2),
            process_id: "process-1".to_owned(),
            process_generation: generation(5),
        }
    }

    /// Genuine forward-progress observation due at `DUE_NOW_MS`.
    fn observation() -> DaemonProgressObservation {
        let kernel_epoch = test_epoch(4);
        let activation_generation = generation(3);
        DaemonProgressObservation {
            schema: DAEMON_SUPERVISION_HEARTBEAT_SCHEMA.to_owned(),
            contract_name: DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_NAME.to_owned(),
            contract_version: DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_VERSION,
            observation_id: "obs-1".to_owned(),
            installation_id: "installation-1".to_owned(),
            activation_id: "activation-1".to_owned(),
            activation_generation,
            generation_binding: generation_binding(),
            daemon_artifact_id: "eliotd-artifact-1".to_owned(),
            daemon_config_digest: digest('c'),
            kernel_epoch: kernel_epoch.clone(),
            state_fence: StateFence::new(kernel_epoch, activation_generation),
            boot_id: "boot-1".to_owned(),
            transport_session_evidence: "session-1".to_owned(),
            transport_connection_evidence: "connection-1".to_owned(),
            lease_id: "lease-1".to_owned(),
            lease_revision: 7,
            predecessor_receipt_sha256: digest('d'),
            progress_channel: DaemonProgressChannel::Claim,
            progress_cursor: 8,
            previous_progress_cursor: 7,
            observed_monotonic_ms: 2_000,
            observed_wall_ms: DUE_NOW_MS,
            disposition: DaemonProgressDisposition::ForwardProgress,
            idle_contract_id: None,
            waiting_on_dependency: None,
            evidence_refs: vec![
                "process:process-1:alive".to_owned(),
                "transport:session-1:bound".to_owned(),
            ],
            health: DaemonHeartbeatHealth::healthy(),
            watchdog_covered: true,
        }
    }

    fn predecessor() -> SupervisionLeasePredecessorProof {
        SupervisionLeasePredecessorProof {
            lease_id: "lease-1".to_owned(),
            record_id: "record-1".to_owned(),
            lease_revision: 7,
            receipt_sha256: digest('d'),
            envelope_sha256: digest('e'),
        }
    }

    fn request() -> DaemonSupervisionRenewalRequest {
        DaemonSupervisionRenewalRequest {
            request_id: "obs-1".to_owned(),
            observation: observation(),
            predecessor: predecessor(),
        }
    }

    fn current() -> DaemonSupervisionCurrentState {
        let kernel_epoch = test_epoch(4);
        let activation_generation = generation(3);
        DaemonSupervisionCurrentState {
            predecessor: predecessor(),
            installation_id: "installation-1".to_owned(),
            activation_id: "activation-1".to_owned(),
            activation_generation,
            kernel_epoch: kernel_epoch.clone(),
            state_fence: StateFence::new(kernel_epoch, activation_generation),
            generation_binding: generation_binding(),
            boot_id: "boot-1".to_owned(),
            transport_session_evidence: "session-1".to_owned(),
            lease_issued_at_ms: 1_000,
            lease_expires_at_ms: 61_000,
            accepted_cursors: vec![DaemonChannelCursor {
                channel: DaemonProgressChannel::Claim,
                cursor: 7,
            }],
            admitted_idle_contract: None,
            last_monotonic_ms: 1_500,
            last_request_id: None,
            last_observation_sha256: None,
            last_successor_revision: None,
            reconciliation_pending: false,
        }
    }

    fn policy() -> DaemonSupervisionRenewalPolicy {
        DaemonSupervisionRenewalPolicy {
            validity_ms: 60_000,
            renew_after_ms: 30_000,
            max_observation_age_ms: 10_000,
            max_wall_skew_ms: 5_000,
            require_watchdog_coverage: false,
        }
    }

    /// Issue window is `[1_000, 61_000)` with `renew_after_ms = 30_000`, so
    /// renewal is due exactly at this instant.
    const DUE_NOW_MS: u64 = 31_000;

    fn decide(
        request: &DaemonSupervisionRenewalRequest,
        current: &DaemonSupervisionCurrentState,
        policy: &DaemonSupervisionRenewalPolicy,
        now_ms: u64,
    ) -> Result<DaemonSupervisionRenewalDecision, DaemonSupervisionHeartbeatError> {
        let decision = evaluate_daemon_supervision_renewal(request, current, policy, now_ms)?;
        decision.validate()?;
        Ok(decision)
    }

    #[test]
    fn genuine_forward_progress_renews_exactly_one_revision() {
        let decision = decide(&request(), &current(), &policy(), DUE_NOW_MS).expect("renewal");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);
        assert_eq!(decision.predecessor_revision, 7);
        assert_eq!(decision.successor_revision, Some(8));
        assert_eq!(decision.predecessor_receipt_sha256, digest('d'));
    }

    #[test]
    fn forward_progress_before_renew_after_is_not_due_without_transition() {
        let now_ms = 5_000;
        let mut request = request();
        request.observation.observed_wall_ms = now_ms;
        let decision = decide(&request, &current(), &policy(), now_ms).expect("not due");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::NotDue);
        assert_eq!(decision.successor_revision, None);
    }

    #[test]
    fn identity_binding_is_checked_before_the_due_gate() {
        // A stale predecessor presented early must fail closed, not read NOT_DUE.
        let now_ms = 5_000;
        let mut request = request();
        request.observation.observed_wall_ms = now_ms;
        request.observation.lease_revision = 6;
        request.predecessor.lease_revision = 6;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&request, &current(), &policy(), now_ms),
            Err(
                DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch(
                    "lease_revision"
                )
            )
        );
    }

    #[test]
    fn exact_replay_echoes_the_recorded_successor() {
        let observation_sha256 = observation().digest().expect("observation digest");
        let mut current = current();
        current.last_request_id = Some("obs-1".to_owned());
        current.last_observation_sha256 = Some(observation_sha256);
        current.last_successor_revision = Some(8);
        let decision = decide(&request(), &current, &policy(), DUE_NOW_MS).expect("exact replay");
        assert_eq!(
            decision.outcome,
            DaemonSupervisionRenewalOutcome::ExactReplay
        );
        assert_eq!(decision.successor_revision, Some(8));
    }

    #[test]
    fn same_request_identity_with_changed_observation_is_identity_conflict() {
        let observation_sha256 = observation().digest().expect("observation digest");
        let mut current = current();
        current.last_request_id = Some("obs-1".to_owned());
        current.last_observation_sha256 = Some(observation_sha256);
        let mut request = request();
        request.observation.progress_cursor = 9;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&request, &current, &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::IdentityConflict {
                request_id: "obs-1".to_owned(),
            })
        );
    }

    #[test]
    fn foreign_lease_and_stale_revision_carry_distinct_predecessor_reasons() {
        let mut foreign = request();
        foreign.observation.lease_id = "lease-foreign".to_owned();
        foreign.predecessor.lease_id = "lease-foreign".to_owned();
        let foreign_reason =
            evaluate_daemon_supervision_renewal(&foreign, &current(), &policy(), DUE_NOW_MS)
                .expect_err("foreign lease must be refused");

        let mut stale = request();
        stale.observation.lease_revision = 6;
        stale.predecessor.lease_revision = 6;
        let stale_reason =
            evaluate_daemon_supervision_renewal(&stale, &current(), &policy(), DUE_NOW_MS)
                .expect_err("stale revision must be refused");

        let mut receipt = request();
        receipt.observation.predecessor_receipt_sha256 = digest('f');
        receipt.predecessor.receipt_sha256 = digest('f');
        let receipt_reason =
            evaluate_daemon_supervision_renewal(&receipt, &current(), &policy(), DUE_NOW_MS)
                .expect_err("stale receipt must be refused");

        assert_eq!(
            foreign_reason,
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("lease_id")
        );
        assert_eq!(
            stale_reason,
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("lease_revision")
        );
        assert_eq!(
            receipt_reason,
            DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("receipt_sha256")
        );
        assert_ne!(foreign_reason, stale_reason);
        assert_ne!(stale_reason, receipt_reason);
    }

    #[test]
    fn stale_generation_epoch_and_fence_are_refused_with_distinct_reasons() {
        let mut stale_generation = request();
        stale_generation
            .observation
            .generation_binding
            .process_generation = generation(6);
        assert_eq!(
            evaluate_daemon_supervision_renewal(
                &stale_generation,
                &current(),
                &policy(),
                DUE_NOW_MS
            ),
            Err(DaemonSupervisionHeartbeatError::DaemonGenerationMismatch)
        );

        let mut stale_epoch = request();
        let epoch = test_epoch(5);
        stale_epoch.observation.kernel_epoch = epoch.clone();
        stale_epoch.observation.state_fence = StateFence::new(epoch, generation(3));
        assert_eq!(
            evaluate_daemon_supervision_renewal(&stale_epoch, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::StaleAuthorityEpoch)
        );

        let mut stale_fence = request();
        let mut fence = StateFence::new(test_epoch(4), generation(3));
        fence.task_revision = Some(TaskRevision::new(9).expect("task revision"));
        stale_fence.observation.state_fence = fence;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&stale_fence, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::StaleStateFence)
        );
    }

    #[test]
    fn boot_and_session_change_invalidate_old_observations() {
        let mut rebooted = request();
        rebooted.observation.boot_id = "boot-2".to_owned();
        assert_eq!(
            evaluate_daemon_supervision_renewal(&rebooted, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::BootIdentityChanged)
        );

        let mut reconnected = request();
        reconnected.observation.transport_session_evidence = "session-2".to_owned();
        assert_eq!(
            evaluate_daemon_supervision_renewal(&reconnected, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::TransportBindingMismatch)
        );
    }

    #[test]
    fn connection_handle_rotation_alone_keeps_no_renewal_identity() {
        // The connection handle is diagnostic evidence; the session binding is
        // the renewal identity, so rotating only the connection still renews.
        let mut request = request();
        request.observation.transport_connection_evidence = "connection-2".to_owned();
        let decision = decide(&request, &current(), &policy(), DUE_NOW_MS).expect("renewal");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);
    }

    #[test]
    fn expired_lease_requires_a_new_admission_path() {
        assert_eq!(
            evaluate_daemon_supervision_renewal(&request(), &current(), &policy(), 61_000),
            Err(DaemonSupervisionHeartbeatError::SupervisionLeaseExpired)
        );
    }

    #[test]
    fn rollback_and_late_observations_are_gaps() {
        let mut rollback = request();
        rollback.observation.observed_monotonic_ms = 1_000;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&rollback, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::ObservationGap)
        );

        let mut late = request();
        late.observation.observed_wall_ms = DUE_NOW_MS - 10_001;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&late, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::ObservationGap)
        );
    }

    #[test]
    fn health_only_observation_never_renews() {
        // Issue #88 first sentence: the 5s cadence health poll (`StoreHealth`,
        // process survival, transport traffic) carries no progress evidence.
        // A heartbeat with that shape (`NO_PROGRESS`, no cursor advance) must
        // be refused even when every other binding is exact and renewal is due.
        let mut no_progress = request();
        no_progress.observation.disposition = DaemonProgressDisposition::NoProgress;
        no_progress.observation.progress_cursor = 7;
        no_progress.observation.previous_progress_cursor = 7;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&no_progress, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient)
        );

        let mut gap = no_progress.clone();
        gap.observation.disposition = DaemonProgressDisposition::ObservationGap;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&gap, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::ObservationGap)
        );
    }

    #[test]
    fn forward_progress_requires_a_cursor_newer_than_accepted() {
        let mut replayed_cursor = request();
        replayed_cursor.observation.progress_cursor = 7;
        replayed_cursor.observation.previous_progress_cursor = 7;
        assert_eq!(
            evaluate_daemon_supervision_renewal(
                &replayed_cursor,
                &current(),
                &policy(),
                DUE_NOW_MS
            ),
            Err(DaemonSupervisionHeartbeatError::ProgressCursorRegression)
        );

        let mut unbound_previous = request();
        unbound_previous.observation.previous_progress_cursor = 6;
        unbound_previous.observation.progress_cursor = 8;
        assert_eq!(
            evaluate_daemon_supervision_renewal(
                &unbound_previous,
                &current(),
                &policy(),
                DUE_NOW_MS
            ),
            Err(DaemonSupervisionHeartbeatError::ProgressCursorRegression)
        );
    }

    #[test]
    fn idle_admitted_renews_only_with_the_exact_contract_and_no_hidden_effect() {
        let mut idle = request();
        idle.observation.disposition = DaemonProgressDisposition::IdleAdmitted;
        idle.observation.idle_contract_id = Some("idle-1".to_owned());
        idle.observation.progress_cursor = 7;
        idle.observation.previous_progress_cursor = 7;
        let mut admitted = current();
        admitted.admitted_idle_contract = Some("idle-1".to_owned());
        let decision = decide(&idle, &admitted, &policy(), DUE_NOW_MS).expect("idle renewal");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);

        // No admitted contract on the authority side: process survival alone
        // never renews.
        assert_eq!(
            evaluate_daemon_supervision_renewal(&idle, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient)
        );

        // Hidden pending effect while claiming idle.
        let mut hidden_effect = idle.clone();
        hidden_effect.observation.progress_cursor = 8;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&hidden_effect, &admitted, &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient)
        );

        // Missing idle contract is a shape refusal, not silent acceptance.
        let mut missing_contract = idle.clone();
        missing_contract.observation.idle_contract_id = None;
        assert!(matches!(
            evaluate_daemon_supervision_renewal(
                &missing_contract,
                &admitted,
                &policy(),
                DUE_NOW_MS
            ),
            Err(DaemonSupervisionHeartbeatError::InvalidHeartbeatShape(_))
        ));
    }

    #[test]
    fn waiting_names_its_dependency_and_draining_renews_when_due() {
        let mut unnamed = request();
        unnamed.observation.disposition = DaemonProgressDisposition::WaitingOnNamedDependency;
        assert!(matches!(
            evaluate_daemon_supervision_renewal(&unnamed, &current(), &policy(), DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::InvalidHeartbeatShape(_))
        ));

        let mut waiting = request();
        waiting.observation.disposition = DaemonProgressDisposition::WaitingOnNamedDependency;
        waiting.observation.waiting_on_dependency = Some("store:revision-9:ready".to_owned());
        waiting.observation.progress_cursor = 7;
        waiting.observation.previous_progress_cursor = 7;
        let decision = decide(&waiting, &current(), &policy(), DUE_NOW_MS).expect("waiting");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);

        let mut draining = request();
        draining.observation.disposition = DaemonProgressDisposition::Draining;
        draining.observation.progress_cursor = 7;
        draining.observation.previous_progress_cursor = 7;
        let decision = decide(&draining, &current(), &policy(), DUE_NOW_MS).expect("draining");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);
    }

    #[test]
    fn store_degradation_stays_separate_from_lease_disposition() {
        // Store unavailable with daemon progress alive renews the lease; the
        // Store failure stays visible only in its own health dimension.
        let mut store_down = request();
        store_down.observation.health.store_dependency = HealthDimension::Failed;
        let decision =
            decide(&store_down, &current(), &policy(), DUE_NOW_MS).expect("store-degraded");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);
        assert_eq!(decision.successor_revision, Some(8));

        // An explicitly degraded observation with a failed dimension records
        // degradation instead of taking a successor revision.
        let mut degraded = request();
        degraded.observation.disposition = DaemonProgressDisposition::DegradedProgress;
        degraded.observation.health.transport = HealthDimension::Failed;
        degraded.observation.progress_cursor = 7;
        degraded.observation.previous_progress_cursor = 7;
        let decision = decide(&degraded, &current(), &policy(), DUE_NOW_MS).expect("degraded");
        assert_eq!(
            decision.outcome,
            DaemonSupervisionRenewalOutcome::DegradedNoRenewal
        );
        assert_eq!(decision.successor_revision, None);
    }

    #[test]
    fn unreconciled_durable_outcome_blocks_a_new_successor() {
        let mut current = current();
        current.reconciliation_pending = true;
        let decision = decide(&request(), &current, &policy(), DUE_NOW_MS).expect("reconcile");
        assert_eq!(
            decision.outcome,
            DaemonSupervisionRenewalOutcome::ReconciliationRequired
        );
        assert_eq!(decision.successor_revision, None);
    }

    #[test]
    fn required_watchdog_coverage_is_enforced() {
        let mut policy = policy();
        policy.require_watchdog_coverage = true;
        let mut uncovered = request();
        uncovered.observation.watchdog_covered = false;
        assert_eq!(
            evaluate_daemon_supervision_renewal(&uncovered, &current(), &policy, DUE_NOW_MS),
            Err(DaemonSupervisionHeartbeatError::WatchdogCoverageUnavailable)
        );
        let decision = decide(&request(), &current(), &policy, DUE_NOW_MS).expect("covered");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);
    }

    #[test]
    fn observation_must_bind_its_cited_predecessor() {
        let mut unbound = request();
        unbound.observation.lease_revision = 6;
        assert!(matches!(
            unbound.validate(),
            Err(DaemonSupervisionHeartbeatError::InvalidHeartbeatShape(_))
        ));
    }

    #[test]
    fn policy_bounds_are_enforced() {
        let mut renew_never_due = policy();
        renew_never_due.renew_after_ms = renew_never_due.validity_ms;
        assert!(matches!(
            renew_never_due.validate(),
            Err(DaemonSupervisionHeartbeatError::InvalidHeartbeatShape(_))
        ));

        let mut zero_validity = policy();
        zero_validity.validity_ms = 0;
        assert!(matches!(
            zero_validity.validate(),
            Err(DaemonSupervisionHeartbeatError::InvalidHeartbeatShape(_))
        ));

        assert_eq!(policy().renew_before_ms(1_000), Some(31_000));
    }

    #[test]
    fn unknown_fields_including_store_health_are_rejected() {
        let mut value = serde_json::to_value(observation()).expect("observation value");
        value["store_health"] = serde_json::json!({"status": "healthy"});
        assert!(serde_json::from_value::<DaemonProgressObservation>(value).is_err());
        assert!(
            serde_json::to_value(observation())
                .expect("observation value")
                .get("store_health")
                .is_none()
        );
    }

    #[test]
    fn roundtrip_schema_and_wire_codes_are_stable() {
        let request = request();
        let encoded = serde_json::to_string(&request).expect("request encoding");
        assert_eq!(
            serde_json::from_str::<DaemonSupervisionRenewalRequest>(&encoded).expect("roundtrip"),
            request
        );
        let receipt = DaemonSupervisionRenewalReceipt {
            request_id: "obs-1".to_owned(),
            lease_id: "lease-1".to_owned(),
            outcome: DaemonSupervisionRenewalOutcome::Renewed,
            predecessor_revision: 7,
            successor_revision: Some(8),
            predecessor_receipt_sha256: digest('d'),
            successor_receipt_sha256: Some(digest('f')),
            live_receipt_sha256: Some(digest('9')),
        };
        receipt.validate().expect("receipt");
        assert!(
            !serde_json::to_vec(&schemars::schema_for!(DaemonProgressObservation))
                .expect("observation schema")
                .is_empty()
        );

        let codes = [
            (
                DaemonSupervisionHeartbeatError::InvalidHeartbeatShape("shape".to_owned()),
                "INVALID_HEARTBEAT_SHAPE",
            ),
            (
                DaemonSupervisionHeartbeatError::IdentityConflict {
                    request_id: "obs-1".to_owned(),
                },
                "IDENTITY_CONFLICT",
            ),
            (
                DaemonSupervisionHeartbeatError::DaemonGenerationMismatch,
                "DAEMON_GENERATION_MISMATCH",
            ),
            (
                DaemonSupervisionHeartbeatError::TransportBindingMismatch,
                "TRANSPORT_BINDING_MISMATCH",
            ),
            (
                DaemonSupervisionHeartbeatError::SupervisionLeasePredecessorMismatch("lease_id"),
                "SUPERVISION_LEASE_PREDECESSOR_MISMATCH",
            ),
            (
                DaemonSupervisionHeartbeatError::SupervisionLeaseNotDue,
                "SUPERVISION_LEASE_NOT_DUE",
            ),
            (
                DaemonSupervisionHeartbeatError::SupervisionLeaseExpired,
                "SUPERVISION_LEASE_EXPIRED",
            ),
            (
                DaemonSupervisionHeartbeatError::StaleAuthorityEpoch,
                "STALE_AUTHORITY_EPOCH",
            ),
            (
                DaemonSupervisionHeartbeatError::StaleStateFence,
                "STALE_STATE_FENCE",
            ),
            (
                DaemonSupervisionHeartbeatError::BootIdentityChanged,
                "BOOT_IDENTITY_CHANGED",
            ),
            (
                DaemonSupervisionHeartbeatError::ProgressCursorRegression,
                "PROGRESS_CURSOR_REGRESSION",
            ),
            (
                DaemonSupervisionHeartbeatError::ProgressEvidenceInsufficient,
                "PROGRESS_EVIDENCE_INSUFFICIENT",
            ),
            (
                DaemonSupervisionHeartbeatError::ObservationGap,
                "OBSERVATION_GAP",
            ),
            (
                DaemonSupervisionHeartbeatError::WatchdogCoverageUnavailable,
                "WATCHDOG_COVERAGE_UNAVAILABLE",
            ),
            (
                DaemonSupervisionHeartbeatError::RenewalOutcomeUnknown,
                "RENEWAL_OUTCOME_UNKNOWN",
            ),
        ];
        let mut seen = std::collections::HashSet::new();
        for (error, code) in codes {
            assert_eq!(error.code(), code);
            assert!(seen.insert(code), "wire code must be unique");
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn per_channel_cursors_track_independently() {
        let mut current = current();
        current.accepted_cursors.push(DaemonChannelCursor {
            channel: DaemonProgressChannel::Dispatch,
            cursor: 41,
        });
        assert_eq!(current.accepted_cursor(DaemonProgressChannel::Claim), 7);
        assert_eq!(current.accepted_cursor(DaemonProgressChannel::Dispatch), 41);
        assert_eq!(current.accepted_cursor(DaemonProgressChannel::Apply), 0);

        let mut dispatch = request();
        dispatch.observation.progress_channel = DaemonProgressChannel::Dispatch;
        dispatch.observation.progress_cursor = 42;
        dispatch.observation.previous_progress_cursor = 41;
        let decision =
            decide(&dispatch, &current, &policy(), DUE_NOW_MS).expect("dispatch renewal");
        assert_eq!(decision.outcome, DaemonSupervisionRenewalOutcome::Renewed);

        let mut duplicate = current.clone();
        duplicate.accepted_cursors.push(DaemonChannelCursor {
            channel: DaemonProgressChannel::Claim,
            cursor: 7,
        });
        assert!(duplicate.validate().is_err());
    }
}
