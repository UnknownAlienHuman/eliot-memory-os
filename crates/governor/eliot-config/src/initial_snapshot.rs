//! Signed initial configuration snapshot for deterministic setup completion.
//!
//! I3.2 (`docs/architecture/I03-02-deterministic-setup-before-agents.md`)
//! requires the first signed configuration snapshot to be created after the
//! trust root, service keys, ACLs and privacy selection are established, and
//! before any agent authority exists. This module owns that snapshot's
//! payload, envelope and trust-anchor verification inside the configuration
//! owner. It follows the established detached-signature envelope contract
//! (`SignedInstallationActivationApproval` in `eliot-runtime-contracts`):
//! canonical JSON bytes, a schema marker, and an Ed25519 detached signature
//! verified against a trust anchor held outside the untrusted snapshot.
//!
//! The module is pure: it validates candidates and produces typed decisions.
//! It does not read sources, persist snapshots, publish state, or start jobs.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use eliot_contracts::{ContractVersion, StateFence, canonical_json_bytes, sha256_hex};

use crate::first_run::FirstRunDecision;
use crate::{
    ConfigPolicySnapshot, HumanOwner, PolicyFence, PolicyRevision, Setting, SourceCompleteness,
};

/// Stable schema marker for the signed initial configuration snapshot.
pub const INITIAL_SNAPSHOT_SCHEMA: &str = "eliot.initial-config-snapshot.v1";
/// Fixed signature algorithm admitted by this contract.
///
/// This is the established Ed25519 envelope format; no second crypto format
/// is introduced.
pub const INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM: &str = "Ed25519";
/// Ed25519 public-key size in bytes.
pub const INITIAL_SNAPSHOT_PUBLIC_KEY_BYTES: usize = 32;
/// Ed25519 signature size in bytes.
pub const INITIAL_SNAPSHOT_SIGNATURE_BYTES: usize = 64;
/// Breaking wire revision for the signed initial snapshot envelope.
pub const INITIAL_SNAPSHOT_WIRE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Setting key carrying the confirmed privacy mode selection.
pub const PRIVACY_MODE_KEY: &str = "privacy.mode";

/// The privacy mode selected during deterministic setup (I3.2 milestone 5).
///
/// Privacy is a policy choice owned by the configuration owner; the setup
/// binding references the same selection, and the signed initial snapshot
/// carries it into the immutable configuration payload.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyChoice {
    /// No data leaves the local machine; no remote model routes.
    LocalOnly,
    /// Consent-governed ELIOT Research participation; no hidden paid routes.
    Standard,
}

impl PrivacyChoice {
    /// Canonical settings value for this privacy mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "LOCAL_ONLY",
            Self::Standard => "STANDARD",
        }
    }

    /// Parses the canonical settings value.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError::InvalidField`] for an unknown mode.
    pub fn parse(value: &str) -> Result<Self, InitialSnapshotError> {
        match value {
            "LOCAL_ONLY" => Ok(Self::LocalOnly),
            "STANDARD" => Ok(Self::Standard),
            other => Err(InitialSnapshotError::InvalidField {
                field: "privacy.mode".to_owned(),
                reason: format!("unknown privacy mode {other}"),
            }),
        }
    }

    /// Projects this privacy mode as one immutable configuration setting.
    #[must_use]
    pub fn to_setting(self, owner_ref: &str) -> crate::Setting {
        crate::Setting {
            key: PRIVACY_MODE_KEY.to_owned(),
            value_ref: format!("literal:{}", self.as_str()),
            owner_ref: owner_ref.to_owned(),
        }
    }
}

/// The confirmed setup identity bound into the initial configuration payload.
///
/// Every value is an observed or user-confirmed fact from the installation
/// owner; this type never invents an identity, a root, or a key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialSnapshotIdentity {
    /// Identity of the immutable configuration snapshot being prepared.
    pub snapshot_id: String,
    /// Installation identity confirmed at setup milestone 1.
    pub installation_id: String,
    /// Selected profile reference (provider-neutral text).
    pub profile_ref: String,
    /// Confirmed System Owner reference and settings owner.
    pub owner_ref: String,
    /// Active key identity bound to the established trust root.
    pub key_identity: String,
    /// Machine identity the snapshot applies to.
    pub machine_id: String,
    /// Scope identity the snapshot applies to.
    pub scope_id: String,
    /// Digest of the exact profile-bound runtime root topology.
    pub runtime_state_roots_digest: String,
    /// Setup binding revision at milestone 7.
    pub setup_revision: u64,
    /// Observed state fence carried by the genesis configuration generation.
    pub state_fence: StateFence,
}

impl InitialSnapshotIdentity {
    fn validate(&self) -> Result<(), InitialSnapshotError> {
        non_empty_text(&self.snapshot_id, "identity.snapshot_id")?;
        non_empty_text(&self.installation_id, "identity.installation_id")?;
        non_empty_text(&self.profile_ref, "identity.profile_ref")?;
        non_empty_text(&self.owner_ref, "identity.owner_ref")?;
        non_empty_text(&self.key_identity, "identity.key_identity")?;
        non_empty_text(&self.machine_id, "identity.machine_id")?;
        non_empty_text(&self.scope_id, "identity.scope_id")?;
        validate_sha256(
            &self.runtime_state_roots_digest,
            "identity.runtime_state_roots_digest",
        )?;
        if self.setup_revision == 0 {
            return Err(invalid_field("identity.setup_revision", "must be non-zero"));
        }
        self.state_fence
            .validate()
            .map_err(|error| invalid_field("identity.state_fence", error.to_string()))?;
        Ok(())
    }
}

/// Builds the deterministic first signed configuration payload from the
/// confirmed setup choices.
///
/// The confirmed privacy mode and the first-run per-role decisions are fed
/// into the existing [`ConfigPolicySnapshot`] payload at the genesis policy
/// revision, so the immutable configuration carries exactly what the user
/// confirmed. Omitted model roles stay `UNASSIGNED`: no model subscription is
/// required and no model is executed to prepare the payload.
///
/// A `LocalOnly` privacy selection combined with any paid model route is
/// refused: a provider route must never silently expand privacy or cost
/// beyond the confirmed choice.
///
/// # Errors
/// Returns [`InitialSnapshotError`] when the identity is incomplete, the
/// choices contradict each other, or the resulting payload is invalid.
pub fn prepare_initial_snapshot_payload(
    identity: &InitialSnapshotIdentity,
    privacy: PrivacyChoice,
    first_run: &FirstRunDecision,
) -> Result<InitialSnapshotPayload, InitialSnapshotError> {
    prepare_initial_snapshot_payload_with_settings(identity, privacy, first_run, &[])
}

/// Builds the deterministic first signed configuration payload and appends
/// settings accepted by the authenticated installation owner.
///
/// Additional settings stay in the same immutable genesis snapshot. Each must
/// be owned by the same confirmed owner as the base first-run settings, and a
/// key may appear only once across the complete snapshot. The payload digest
/// is recalculated only after the final settings set has been validated.
///
/// This helper does not authenticate the owner or decide which settings are
/// admissible. The installation publication owner must establish that
/// authority before calling it and must pass the exact bytes to the protected
/// signer and original durable snapshot store.
///
/// # Errors
/// Returns [`InitialSnapshotError`] when the identity, choices, or appended
/// settings are invalid or conflict with the first-run settings.
pub fn prepare_initial_snapshot_payload_with_settings(
    identity: &InitialSnapshotIdentity,
    privacy: PrivacyChoice,
    first_run: &FirstRunDecision,
    additional_settings: &[Setting],
) -> Result<InitialSnapshotPayload, InitialSnapshotError> {
    identity.validate()?;
    if matches!(privacy, PrivacyChoice::LocalOnly) && first_run.has_paid_route() {
        return Err(InitialSnapshotError::PrivacyChoiceConflict {
            reason: "LOCAL_ONLY selects no remote model route".to_owned(),
        });
    }
    let revision = PolicyRevision::genesis();
    let mut settings = crate::first_run::to_settings(first_run, &identity.owner_ref);
    settings.push(privacy.to_setting(&identity.owner_ref));
    for setting in additional_settings {
        non_empty_text(&setting.key, "snapshot.settings.key")?;
        non_empty_text(&setting.value_ref, "snapshot.settings.value_ref")?;
        non_empty_text(&setting.owner_ref, "snapshot.settings.owner_ref")?;
        if setting.owner_ref != identity.owner_ref {
            return Err(InitialSnapshotError::BindingMismatch);
        }
        if settings.iter().any(|existing| existing.key == setting.key) {
            return Err(InitialSnapshotError::InvalidField {
                field: "snapshot.settings".to_owned(),
                reason: format!("setting key {} is already present", setting.key),
            });
        }
        settings.push(setting.clone());
    }
    let snapshot = ConfigPolicySnapshot {
        snapshot_id: identity.snapshot_id.clone(),
        machine_id: identity.machine_id.clone(),
        scope_id: identity.scope_id.clone(),
        revision,
        source_completeness: SourceCompleteness::Complete,
        settings,
        policy_owner: HumanOwner {
            owner_ref: identity.owner_ref.clone(),
        },
        policy_fence: PolicyFence {
            policy_snapshot_id: identity.snapshot_id.clone(),
            state_fence: identity.state_fence.clone(),
        },
        state_fence: identity.state_fence.clone(),
        parent_snapshot_id: None,
        rollback_of: None,
    };
    snapshot
        .validate()
        .map_err(|error| invalid_field("snapshot", error.to_string()))?;
    let canonical = canonical_json_bytes(&snapshot)
        .map_err(|error| InitialSnapshotError::Canonicalization(error.to_string()))?;
    let payload = InitialSnapshotPayload {
        snapshot_id: identity.snapshot_id.clone(),
        snapshot_canonical_sha256: sha256_hex(&canonical),
        snapshot,
        installation_id: identity.installation_id.clone(),
        profile_ref: identity.profile_ref.clone(),
        owner_ref: identity.owner_ref.clone(),
        key_identity: identity.key_identity.clone(),
        runtime_state_roots_digest: identity.runtime_state_roots_digest.clone(),
        setup_revision: identity.setup_revision,
    };
    payload.validate()?;
    Ok(payload)
}

/// The complete unsigned initial snapshot payload admitted by the config owner.
///
/// Every field is included in [`Self::canonical_bytes`]. The payload binds the
/// exact canonical bytes of the immutable configuration snapshot, the
/// installation/profile/owner identity, the active key identity, the root
/// binding and the setup revision. It is not itself an authority receipt and
/// does not authorize semantic writes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialSnapshotPayload {
    /// Stable snapshot identity.
    pub snapshot_id: String,
    /// Lowercase SHA-256 of the exact canonical `snapshot` bytes.
    pub snapshot_canonical_sha256: String,
    /// The immutable configuration and policy payload for this installation.
    pub snapshot: ConfigPolicySnapshot,
    /// Installation identity confirmed at setup milestone 1.
    pub installation_id: String,
    /// Selected profile reference (provider-neutral text).
    pub profile_ref: String,
    /// Confirmed System Owner reference.
    pub owner_ref: String,
    /// Active key identity bound to the established trust root.
    pub key_identity: String,
    /// Digest of the exact profile-bound runtime root topology.
    pub runtime_state_roots_digest: String,
    /// Setup binding revision at milestone 7.
    pub setup_revision: u64,
}

impl InitialSnapshotPayload {
    /// Validates the complete payload without consulting a trust anchor.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the payload is malformed, the
    /// snapshot bytes digest mismatches, or the snapshot is not the genesis
    /// policy revision.
    pub fn validate(&self) -> Result<(), InitialSnapshotError> {
        non_empty_text(&self.snapshot_id, "snapshot_id")?;
        non_empty_text(&self.installation_id, "installation_id")?;
        non_empty_text(&self.profile_ref, "profile_ref")?;
        non_empty_text(&self.owner_ref, "owner_ref")?;
        non_empty_text(&self.key_identity, "key_identity")?;
        validate_sha256(&self.snapshot_canonical_sha256, "snapshot_canonical_sha256")?;
        validate_sha256(
            &self.runtime_state_roots_digest,
            "runtime_state_roots_digest",
        )?;
        if self.setup_revision == 0 {
            return Err(invalid_field("setup_revision", "must be non-zero"));
        }
        self.snapshot
            .validate()
            .map_err(|error| invalid_field("snapshot", error.to_string()))?;
        if self.snapshot.revision != PolicyRevision::genesis() {
            return Err(invalid_field(
                "snapshot.revision",
                "the initial configuration snapshot must carry the genesis policy revision",
            ));
        }
        let canonical = canonical_json_bytes(&self.snapshot)
            .map_err(|error| InitialSnapshotError::Canonicalization(error.to_string()))?;
        if sha256_hex(&canonical) != self.snapshot_canonical_sha256 {
            return Err(InitialSnapshotError::DigestMismatch {
                field: "snapshot_canonical_sha256",
            });
        }
        self.privacy_choice()?;
        Ok(())
    }

    /// Returns the canonical bytes covered by the payload digest.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when validation or canonicalization
    /// fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InitialSnapshotError> {
        self.validate()?;
        canonical_json_bytes(&CanonicalPayload {
            schema: INITIAL_SNAPSHOT_SCHEMA,
            contract_version: INITIAL_SNAPSHOT_WIRE_VERSION,
            payload: self,
        })
        .map_err(|error| InitialSnapshotError::Canonicalization(error.to_string()))
    }

    /// Returns the lowercase SHA-256 digest of [`Self::canonical_bytes`].
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the payload is invalid.
    pub fn digest(&self) -> Result<String, InitialSnapshotError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Extracts the confirmed privacy mode selection from the snapshot settings.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the privacy mode setting is absent
    /// or carries an unknown value.
    pub fn privacy_choice(&self) -> Result<PrivacyChoice, InitialSnapshotError> {
        let setting = self
            .snapshot
            .settings
            .iter()
            .find(|setting| setting.key == PRIVACY_MODE_KEY)
            .ok_or_else(|| {
                invalid_field(
                    "snapshot.settings.privacy.mode",
                    "the initial snapshot must carry the confirmed privacy mode selection",
                )
            })?;
        let value = setting.value_ref.strip_prefix("literal:").ok_or_else(|| {
            invalid_field(
                "snapshot.settings.privacy.mode",
                "must carry a literal privacy mode value",
            )
        })?;
        PrivacyChoice::parse(value)
    }
}

#[derive(Serialize)]
struct CanonicalPayload<'a> {
    schema: &'static str,
    contract_version: ContractVersion,
    payload: &'a InitialSnapshotPayload,
}

#[derive(Serialize)]
struct SignedInitialSnapshotPreimage<'a> {
    schema: &'static str,
    contract_version: ContractVersion,
    payload: &'a InitialSnapshotPayload,
    payload_sha256: &'a str,
    signer_id: &'a str,
    key_id: &'a str,
    algorithm: &'a str,
    public_key_fingerprint: &'a str,
}

/// Detached Ed25519-signed initial configuration snapshot envelope.
///
/// The verifier's trusted key reference lives in
/// [`InitialConfigSnapshotTrustAnchor`], outside this untrusted snapshot: a
/// signature verified only against a key supplied inside the same file proves
/// nothing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedInitialConfigSnapshot {
    /// Complete immutable signed payload.
    pub payload: InitialSnapshotPayload,
    /// Lowercase SHA-256 of the canonical payload bytes.
    pub payload_sha256: String,
    /// Stable authority signer identity.
    pub signer_id: String,
    /// External key reference selected by the authority.
    pub key_id: String,
    /// Must equal [`INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM`].
    pub algorithm: String,
    /// Lowercase SHA-256 fingerprint of the signing public key.
    pub public_key_fingerprint: String,
    /// Lowercase hexadecimal detached Ed25519 signature.
    pub signature: String,
}

impl SignedInitialConfigSnapshot {
    /// Validates envelope shape and payload digest without the trust anchor.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the envelope or payload is
    /// malformed.
    pub fn validate(&self) -> Result<(), InitialSnapshotError> {
        self.payload.validate()?;
        non_empty_text(&self.signer_id, "signer_id")?;
        non_empty_text(&self.key_id, "key_id")?;
        if self.algorithm != INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM {
            return Err(InitialSnapshotError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }
        validate_sha256(&self.public_key_fingerprint, "public_key_fingerprint")?;
        let expected = self.payload.digest()?;
        if self.payload_sha256 != expected {
            return Err(InitialSnapshotError::DigestMismatch {
                field: "payload_sha256",
            });
        }
        decode_hex::<{ INITIAL_SNAPSHOT_SIGNATURE_BYTES }>(&self.signature, "signature")?;
        // Re-serialize the preimage here so envelope metadata is also bound by
        // the detached signature and cannot be swapped after signing.
        self.preimage_bytes()
            .map(|_| ())
            .map_err(|error| InitialSnapshotError::Canonicalization(error.to_string()))
    }

    fn preimage_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        canonical_json_bytes(&SignedInitialSnapshotPreimage {
            schema: INITIAL_SNAPSHOT_SCHEMA,
            contract_version: INITIAL_SNAPSHOT_WIRE_VERSION,
            payload: &self.payload,
            payload_sha256: &self.payload_sha256,
            signer_id: &self.signer_id,
            key_id: &self.key_id,
            algorithm: &self.algorithm,
            public_key_fingerprint: &self.public_key_fingerprint,
        })
    }

    /// Returns the digest of the canonical envelope, including the detached
    /// signature. This is the value a setup binding records as its final
    /// configuration reference.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the envelope is invalid.
    pub fn envelope_digest(&self) -> Result<String, InitialSnapshotError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| InitialSnapshotError::Canonicalization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Signs an admitted payload with an explicit Ed25519 signer.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the signer is unsupported or the
    /// signature length is invalid.
    pub fn sign<S: InitialSnapshotSigner>(
        payload: &InitialSnapshotPayload,
        signer: &S,
    ) -> Result<SignedInitialConfigSnapshot, InitialSnapshotError> {
        payload.validate()?;
        if signer.algorithm() != INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM {
            return Err(InitialSnapshotError::UnsupportedAlgorithm(
                signer.algorithm().to_owned(),
            ));
        }
        non_empty_text(signer.signer_id(), "signer_id")?;
        non_empty_text(signer.key_id(), "key_id")?;
        if signer.signer_id() != payload.owner_ref {
            return Err(InitialSnapshotError::BindingMismatch);
        }
        let payload_bytes = payload.canonical_bytes()?;
        let payload_sha256 = sha256_hex(&payload_bytes);
        let preimage = SignedInitialSnapshotPreimage {
            schema: INITIAL_SNAPSHOT_SCHEMA,
            contract_version: INITIAL_SNAPSHOT_WIRE_VERSION,
            payload,
            payload_sha256: &payload_sha256,
            signer_id: signer.signer_id(),
            key_id: signer.key_id(),
            algorithm: signer.algorithm(),
            public_key_fingerprint: signer.public_key_fingerprint(),
        };
        let bytes = canonical_json_bytes(&preimage)
            .map_err(|error| InitialSnapshotError::Canonicalization(error.to_string()))?;
        let signature = signer.sign(&bytes)?;
        if signature.len() != INITIAL_SNAPSHOT_SIGNATURE_BYTES {
            return Err(InitialSnapshotError::InvalidSignatureLength {
                observed: signature.len(),
            });
        }
        Ok(SignedInitialConfigSnapshot {
            payload: payload.clone(),
            payload_sha256,
            signer_id: signer.signer_id().to_owned(),
            key_id: signer.key_id().to_owned(),
            algorithm: signer.algorithm().to_owned(),
            public_key_fingerprint: signer.public_key_fingerprint().to_owned(),
            signature: encode_hex(&signature),
        })
    }
}

/// Installation-pinned public trust anchor for initial snapshot verification.
///
/// The verifier's trusted key reference is held here, outside the untrusted
/// [`SignedInitialConfigSnapshot`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialConfigSnapshotTrustAnchor {
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

impl InitialConfigSnapshotTrustAnchor {
    /// Constructs and fingerprints an installation-pinned public key.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the key or fingerprint is invalid.
    pub fn new(
        installation_id: impl Into<String>,
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: Vec<u8>,
    ) -> Result<Self, InitialSnapshotError> {
        let anchor = Self {
            installation_id: installation_id.into(),
            signer_id: signer_id.into(),
            key_id: key_id.into(),
            algorithm: INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM.to_owned(),
            public_key_fingerprint: sha256_hex(&public_key),
            public_key,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    /// Validates key length, curve encoding, algorithm and fingerprint.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the anchor is malformed.
    pub fn validate(&self) -> Result<(), InitialSnapshotError> {
        non_empty_text(&self.installation_id, "trust_anchor.installation_id")?;
        non_empty_text(&self.signer_id, "trust_anchor.signer_id")?;
        non_empty_text(&self.key_id, "trust_anchor.key_id")?;
        if self.algorithm != INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM {
            return Err(InitialSnapshotError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }
        if self.public_key.len() != INITIAL_SNAPSHOT_PUBLIC_KEY_BYTES {
            return Err(InitialSnapshotError::InvalidPublicKeyLength {
                observed: self.public_key.len(),
            });
        }
        validate_sha256(
            &self.public_key_fingerprint,
            "trust_anchor.public_key_fingerprint",
        )?;
        if sha256_hex(&self.public_key) != self.public_key_fingerprint {
            return Err(InitialSnapshotError::TrustAnchorFingerprintMismatch);
        }
        VerifyingKey::from_bytes(self.public_key.as_slice().try_into().map_err(|_| {
            InitialSnapshotError::InvalidPublicKeyLength {
                observed: self.public_key.len(),
            }
        })?)
        .map_err(|error| InitialSnapshotError::InvalidPublicKey(error.to_string()))?;
        Ok(())
    }

    /// Verifies a snapshot against this anchor and an independently observed
    /// context.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the envelope, anchor identity,
    /// context bindings, or signature is invalid.
    pub fn verify(
        &self,
        snapshot: &SignedInitialConfigSnapshot,
        context: &InitialSnapshotVerificationContext,
    ) -> Result<VerifiedInitialConfigSnapshot, InitialSnapshotError> {
        self.validate()?;
        context.validate()?;
        snapshot.validate()?;
        if snapshot.signer_id != self.signer_id {
            return Err(InitialSnapshotError::TrustAnchorMismatch("signer_id"));
        }
        if snapshot.key_id != self.key_id {
            return Err(InitialSnapshotError::TrustAnchorMismatch("key_id"));
        }
        if snapshot.algorithm != self.algorithm {
            return Err(InitialSnapshotError::TrustAnchorMismatch("algorithm"));
        }
        if snapshot.public_key_fingerprint != self.public_key_fingerprint {
            return Err(InitialSnapshotError::TrustAnchorMismatch(
                "public_key_fingerprint",
            ));
        }
        let payload = &snapshot.payload;
        if payload.installation_id != self.installation_id
            || payload.installation_id != context.installation_id
        {
            return Err(InitialSnapshotError::InstallationIdentityMismatch);
        }
        if payload.profile_ref != context.profile_ref
            || payload.runtime_state_roots_digest != context.runtime_state_roots_digest
            || payload.key_identity != context.key_identity
            || payload.setup_revision != context.setup_revision
        {
            return Err(InitialSnapshotError::BindingMismatch);
        }
        let signature =
            decode_hex::<{ INITIAL_SNAPSHOT_SIGNATURE_BYTES }>(&snapshot.signature, "signature")?;
        let public_key: &[u8; INITIAL_SNAPSHOT_PUBLIC_KEY_BYTES] =
            self.public_key.as_slice().try_into().map_err(|_| {
                InitialSnapshotError::InvalidPublicKeyLength {
                    observed: self.public_key.len(),
                }
            })?;
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|error| InitialSnapshotError::InvalidPublicKey(error.to_string()))?;
        let signature = Signature::from_bytes(&signature);
        let bytes = snapshot
            .preimage_bytes()
            .map_err(|error| InitialSnapshotError::Canonicalization(error.to_string()))?;
        verifying_key
            .verify_strict(&bytes, &signature)
            .map_err(|error| InitialSnapshotError::SignatureInvalid(error.to_string()))?;
        Ok(VerifiedInitialConfigSnapshot::new(
            payload.clone(),
            snapshot.envelope_digest()?,
            snapshot.signer_id.clone(),
            snapshot.key_id.clone(),
            snapshot.public_key_fingerprint.clone(),
            snapshot.signature.clone(),
        ))
    }
}

/// Independently observed values bound by the initial snapshot verifier.
///
/// The setup owner supplies this context after reading its durable state; the
/// context is not an authority receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialSnapshotVerificationContext {
    /// Expected installation identity.
    pub installation_id: String,
    /// Expected profile reference.
    pub profile_ref: String,
    /// Expected runtime state roots digest.
    pub runtime_state_roots_digest: String,
    /// Expected active key identity.
    pub key_identity: String,
    /// Expected setup binding revision.
    pub setup_revision: u64,
}

impl InitialSnapshotVerificationContext {
    /// Validates the independent context shape before comparison.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the context is incomplete.
    pub fn validate(&self) -> Result<(), InitialSnapshotError> {
        non_empty_text(&self.installation_id, "context.installation_id")?;
        non_empty_text(&self.profile_ref, "context.profile_ref")?;
        non_empty_text(&self.key_identity, "context.key_identity")?;
        validate_sha256(
            &self.runtime_state_roots_digest,
            "context.runtime_state_roots_digest",
        )?;
        if self.setup_revision == 0 {
            return Err(invalid_field("context.setup_revision", "must be non-zero"));
        }
        Ok(())
    }
}

/// Sealed, trust-anchor-verified initial configuration snapshot.
///
/// The fields are private and there is intentionally no public constructor or
/// deserializer. A caller can obtain this type only through
/// [`InitialConfigSnapshotTrustAnchor::verify`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInitialConfigSnapshot {
    payload: InitialSnapshotPayload,
    envelope_sha256: String,
    signer_id: String,
    key_id: String,
    public_key_fingerprint: String,
    signature: String,
}

impl VerifiedInitialConfigSnapshot {
    #[allow(clippy::too_many_arguments)]
    fn new(
        payload: InitialSnapshotPayload,
        envelope_sha256: String,
        signer_id: String,
        key_id: String,
        public_key_fingerprint: String,
        signature: String,
    ) -> Self {
        Self {
            payload,
            envelope_sha256,
            signer_id,
            key_id,
            public_key_fingerprint,
            signature,
        }
    }

    /// Returns the authenticated complete payload.
    #[must_use]
    pub const fn payload(&self) -> &InitialSnapshotPayload {
        &self.payload
    }

    /// Returns the authenticated canonical envelope digest.
    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_sha256
    }

    /// Returns the authenticated signer identity.
    #[must_use]
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// Returns the authenticated external key reference.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the authenticated public-key fingerprint.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }

    /// Returns the authenticated detached signature.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

/// Producer-side signing boundary for initial snapshots.
///
/// Production code implements [`InitialSnapshotSigner`] over a protected key
/// provider. Private key bytes are never serialized into the snapshot contract.
pub trait InitialSnapshotSigner {
    /// Stable producer identity.
    fn signer_id(&self) -> &str;
    /// External key reference.
    fn key_id(&self) -> &str;
    /// Signature algorithm identifier.
    fn algorithm(&self) -> &str {
        INITIAL_SNAPSHOT_SIGNATURE_ALGORITHM
    }
    /// Public-key fingerprint included in the signed preimage.
    fn public_key_fingerprint(&self) -> &str;
    /// Signs canonical preimage bytes and returns exactly 64 Ed25519 bytes.
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, InitialSnapshotError>;
}

/// In-memory Ed25519 signer for explicit key material.
///
/// Production code may implement [`InitialSnapshotSigner`] over a protected
/// key provider. Private key bytes are never serialized into the snapshot
/// contract.
pub struct Ed25519InitialSnapshotSigner {
    signer_id: String,
    key_id: String,
    public_key_fingerprint: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519InitialSnapshotSigner {
    /// Constructs a signer from explicitly supplied secret material.
    ///
    /// # Errors
    /// Returns [`InitialSnapshotError`] when the signer identity is blank.
    pub fn from_secret_key(
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
        secret_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    ) -> Result<Self, InitialSnapshotError> {
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
    #[must_use]
    pub fn public_key(&self) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl InitialSnapshotSigner for Ed25519InitialSnapshotSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }

    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, InitialSnapshotError> {
        Ok(self.signing_key.sign(canonical_bytes).to_bytes().to_vec())
    }
}

/// Errors raised by initial snapshot construction or verification.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InitialSnapshotError {
    /// A field failed strict shape validation.
    #[error("invalid initial snapshot field {field}: {reason}")]
    InvalidField {
        /// Field path rejected by validation.
        field: String,
        /// Stable reason for rejecting the field.
        reason: String,
    },
    /// Canonical JSON serialization failed.
    #[error("initial snapshot canonicalization failed: {0}")]
    Canonicalization(String),
    /// Signature algorithm is not admitted.
    #[error("unsupported initial snapshot signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// A canonical digest did not match the payload bytes.
    #[error("initial snapshot digest mismatch for {field}")]
    DigestMismatch {
        /// Field whose digest mismatched.
        field: &'static str,
    },
    /// A hex field was malformed.
    #[error("{field} must be lowercase hexadecimal with exactly {expected} bytes")]
    InvalidHex {
        /// Field path rejected by validation.
        field: String,
        /// Expected byte count.
        expected: usize,
    },
    /// Signature length was not exactly Ed25519's 64 bytes.
    #[error("invalid initial snapshot signature length: {observed}")]
    InvalidSignatureLength {
        /// Observed signature length in bytes.
        observed: usize,
    },
    /// Public key length was not exactly Ed25519's 32 bytes.
    #[error("invalid initial snapshot public-key length: {observed}")]
    InvalidPublicKeyLength {
        /// Observed public key length in bytes.
        observed: usize,
    },
    /// Public key failed curve validation.
    #[error("invalid initial snapshot public key: {0}")]
    InvalidPublicKey(String),
    /// Anchor fingerprint did not match its provisioned public key.
    #[error("initial snapshot trust-anchor fingerprint mismatch")]
    TrustAnchorFingerprintMismatch,
    /// Envelope metadata did not match the pinned trust anchor.
    #[error("initial snapshot trust-anchor mismatch for {0}")]
    TrustAnchorMismatch(&'static str),
    /// Installation identity did not match the anchor or context.
    #[error(
        "initial snapshot installation identity mismatch; recovery: re-run deterministic setup for this installation through the installation owner and do not admit an agent"
    )]
    InstallationIdentityMismatch,
    /// Profile, root, key identity, or setup revision did not match context.
    #[error(
        "initial snapshot binding mismatch; recovery: re-sign the initial configuration through the installation owner for the observed profile, runtime root, active key identity and setup revision, then re-read it before admitting an agent"
    )]
    BindingMismatch,
    /// Detached signature failed strict Ed25519 verification.
    #[error(
        "invalid initial snapshot signature: {0}; recovery: restore the published initial configuration from the installation owner's protected journal and verify it against the installation-pinned trust anchor before admitting an agent"
    )]
    SignatureInvalid(String),
    /// The confirmed privacy choice contradicts the confirmed model routes.
    #[error("initial snapshot privacy choice conflict: {reason}")]
    PrivacyChoiceConflict {
        /// Why the two confirmed choices cannot hold together.
        reason: String,
    },
}

fn invalid_field(field: impl Into<String>, reason: impl Into<String>) -> InitialSnapshotError {
    InitialSnapshotError::InvalidField {
        field: field.into(),
        reason: reason.into(),
    }
}

fn non_empty_text(value: &str, field: &str) -> Result<(), InitialSnapshotError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid_field(
            field,
            "must be non-blank and free of control characters",
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), InitialSnapshotError> {
    decode_hex::<32>(value, field).map(|_| ())
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

fn decode_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N], InitialSnapshotError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InitialSnapshotError::InvalidHex {
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
