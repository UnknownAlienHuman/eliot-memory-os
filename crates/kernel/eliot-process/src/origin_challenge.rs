//! P-03 origin-challenge authority cell for observed-process control.
//!
//! Issue #1960 (I3.4): neutral process-origin observation never authorizes
//! kill, adoption, mutation, or credential attachment. Control additionally
//! requires a current Kernel-issued [`OriginChallenge`] bound to the exact
//! observed origin digest, the exact OS physical identity
//! ([`PhysicalProcessBinding`]: pid plus process start identity plus image
//! plus executor job), installation and managed generation, the admitted
//! [`StateFence`] and authority epoch, exactly one allowed operation class,
//! and a non-reusable nonce.
//!
//! The Kernel-owned [`OriginChallengeAuthority`] is the only minter and
//! decision point. It authenticates with the same [`KernelDispatchKey`] as
//! dispatch permits under a disjoint domain separator, so no parallel key
//! material exists anywhere. There is deliberately no daemon-minted issuer:
//! possession of a challenge proves nothing without the Kernel-owned instance
//! and its live issuance record. Governor observation and policy projection
//! stay in `eliotd` (`process_origin.rs`); this cell owns neutral mechanics
//! only and depends on nothing Governor-owned.

use super::{
    ContractError, DispatchAuthorityId, Generation, KernelDispatchKey, PhysicalProcessBinding,
};
use eliot_contracts::{EpochId, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Schema identity for origin-challenge wire material.
pub const ORIGIN_CHALLENGE_SCHEMA_VERSION: &str = "eliot-origin-challenge-v1";

/// Domain separator binding every tag and digest to this cell (never to the
/// dispatch-permit domain sharing the same Kernel key).
const ORIGIN_CHALLENGE_DOMAIN: &str = "eliot-origin-challenge-v1";

/// Maximum lifetime of one origin challenge: one hour in milliseconds.
const MAX_CHALLENGE_WINDOW_MS: u64 = 3_600_000;

/// Maximum accepted installation identity length.
const MAX_INSTALLATION_ID_LEN: usize = 128;

/// Maximum accepted nonce length.
const MAX_NONCE_LEN: usize = 128;

/// Control operation class scoped by one challenge (I3.4
/// `allowed_operation_classes`). Read-only status and observation probes take
/// no challenge and never appear here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginControlOperation {
    /// Stop the observed process.
    Kill,
    /// Adopt the observed process into managed lineage.
    Adopt,
    /// Mutate the observed process.
    Mutate,
    /// Attach a credential to the observed process.
    AttachCredential,
}

impl OriginControlOperation {
    /// Stable operation-class label used inside digests and proof tokens.
    #[must_use]
    pub const fn operation_label(self) -> &'static str {
        match self {
            Self::Kill => "kill",
            Self::Adopt => "adopt",
            Self::Mutate => "mutate",
            Self::AttachCredential => "attach-credential",
        }
    }
}

/// Neutral request for a Kernel-issued origin challenge.
///
/// Built by the daemon consumer from a validated Governor observation plus the
/// exact OS physical identity. Completeness only: issuance and every authority
/// check happen in [`OriginChallengeAuthority::issue`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginChallengeRequest {
    physical: PhysicalProcessBinding,
    installation_id: String,
    origin_digest: String,
    generation: Generation,
    state_fence: StateFence,
    operation: OriginControlOperation,
    request_nonce: String,
}

impl OriginChallengeRequest {
    /// Builds a challenge request; every authority evaluation still happens
    /// in the Kernel-owned authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        physical: PhysicalProcessBinding,
        installation_id: impl Into<String>,
        origin_digest: impl Into<String>,
        generation: Generation,
        state_fence: StateFence,
        operation: OriginControlOperation,
        request_nonce: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let request = Self {
            physical,
            installation_id: validate_token(
                "installation_id",
                installation_id.into(),
                MAX_INSTALLATION_ID_LEN,
            )?,
            origin_digest: validate_origin_digest(origin_digest.into())?,
            generation,
            state_fence,
            operation,
            request_nonce: validate_token("request_nonce", request_nonce.into(), MAX_NONCE_LEN)?,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the request as complete packaging, never as authority.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_token(
            "installation_id",
            self.installation_id.clone(),
            MAX_INSTALLATION_ID_LEN,
        )?;
        validate_origin_digest(self.origin_digest.clone())?;
        validate_token("request_nonce", self.request_nonce.clone(), MAX_NONCE_LEN)?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch)?;
        if self.state_fence.resource_generation.value() != self.generation.get() {
            return Err(ContractError::FenceMismatch);
        }
        Ok(())
    }

    /// Returns the exact OS physical identity the challenge must bind.
    pub fn physical(&self) -> &PhysicalProcessBinding {
        &self.physical
    }

    /// Returns the installation identity the challenge must bind.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Returns the Governor observation digest the challenge must bind.
    pub fn origin_digest(&self) -> &str {
        &self.origin_digest
    }

    /// Returns the managed generation the challenge must bind.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the admitted fence the challenge must bind.
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the single allowed operation class.
    pub const fn operation(&self) -> OriginControlOperation {
        self.operation
    }

    /// Returns the caller-supplied one-shot nonce.
    pub fn request_nonce(&self) -> &str {
        &self.request_nonce
    }
}

/// Kernel-issued origin challenge: the single control capability in this cell.
///
/// It authorizes exactly one observed origin under exactly one fence, for
/// exactly one operation class, while current. It has no public field
/// constructor, no `Clone`, and no `Deserialize`: only the Kernel-owned
/// authority can mint one. The secret-bound authentication tag plus the live
/// issuer record carry authority; every other field is evidence.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginChallenge {
    schema_version: String,
    authority_id: DispatchAuthorityId,
    challenge_id: String,
    origin_digest: String,
    physical_digest: String,
    installation_id: String,
    generation: Generation,
    state_fence: StateFence,
    operation: OriginControlOperation,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    nonce: String,
    authentication_tag: String,
    challenge_digest: String,
}

#[derive(Serialize)]
struct UnsignedChallenge<'a> {
    domain: &'a str,
    schema_version: &'a str,
    authority_id: &'a DispatchAuthorityId,
    challenge_id: &'a str,
    origin_digest: &'a str,
    physical_digest: &'a str,
    installation_id: &'a str,
    generation: Generation,
    state_fence: &'a StateFence,
    operation: OriginControlOperation,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    nonce: &'a str,
}

impl OriginChallenge {
    fn unsigned(&self) -> UnsignedChallenge<'_> {
        UnsignedChallenge {
            domain: ORIGIN_CHALLENGE_DOMAIN,
            schema_version: &self.schema_version,
            authority_id: &self.authority_id,
            challenge_id: &self.challenge_id,
            origin_digest: &self.origin_digest,
            physical_digest: &self.physical_digest,
            installation_id: &self.installation_id,
            generation: self.generation,
            state_fence: &self.state_fence,
            operation: self.operation,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            nonce: &self.nonce,
        }
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.schema_version != ORIGIN_CHALLENGE_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: ORIGIN_CHALLENGE_SCHEMA_VERSION,
                observed: self.schema_version.clone(),
            });
        }
        validate_origin_digest(self.origin_digest.clone())?;
        validate_hex_digest(&self.physical_digest)?;
        validate_hex_digest(&self.authentication_tag)?;
        validate_hex_digest(&self.challenge_digest)?;
        if self.issued_at_unix_ms == 0 || self.expires_at_unix_ms < self.issued_at_unix_ms {
            return Err(ContractError::InvalidValue {
                field: "origin_challenge_window",
                reason: "issue time must be non-zero and precede expiry",
            });
        }
        let expected = challenge_digest(&self.unsigned(), &self.authentication_tag)?;
        if self.challenge_digest != expected {
            return Err(ContractError::DigestMismatch {
                field: "challenge_digest",
                expected,
                observed: self.challenge_digest.clone(),
            });
        }
        Ok(())
    }

    /// Returns the issuer-assigned challenge identity.
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    /// Returns the single allowed operation class.
    pub const fn operation(&self) -> OriginControlOperation {
        self.operation
    }

    /// Returns the bound observation digest.
    pub fn origin_digest(&self) -> &str {
        &self.origin_digest
    }

    /// Returns the issuance time.
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    /// Returns the expiry time (inclusive).
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Returns the stable content digest; all other authority material stays opaque.
    pub fn digest(&self) -> &str {
        &self.challenge_digest
    }
}

/// Sealed daemon→Kernel presentation: one request plus its Kernel-issued challenge.
///
/// The presentation cannot be cloned or deserialized. It is built only from a
/// request whose binding matches the challenge field-for-field; the Kernel
/// authority still re-checks issuance, revocation, tag, currency, fence, and
/// the live epoch before any control effect.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginControlPresentation {
    schema_version: String,
    request: OriginChallengeRequest,
    challenge: OriginChallenge,
    presentation_digest: String,
}

impl OriginControlPresentation {
    /// Seals a request with its challenge after checking completeness binding.
    ///
    /// Packaging only: issuance, revocation, currency, and the live epoch are
    /// evaluated exclusively by [`OriginChallengeAuthority::decide`].
    pub fn new(
        request: OriginChallengeRequest,
        challenge: OriginChallenge,
    ) -> Result<Self, ContractError> {
        request.validate()?;
        challenge.validate_shape()?;
        check_binding(&request, &challenge)?;
        let mut presentation = Self {
            schema_version: ORIGIN_CHALLENGE_SCHEMA_VERSION.to_owned(),
            request,
            challenge,
            presentation_digest: String::new(),
        };
        presentation.presentation_digest = presentation.compute_digest()?;
        Ok(presentation)
    }

    /// Validates packaging binding without touching authority state.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != ORIGIN_CHALLENGE_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: ORIGIN_CHALLENGE_SCHEMA_VERSION,
                observed: self.schema_version.clone(),
            });
        }
        self.request.validate()?;
        self.challenge.validate_shape()?;
        check_binding(&self.request, &self.challenge)?;
        let expected = self.compute_digest()?;
        if self.presentation_digest != expected {
            return Err(ContractError::DigestMismatch {
                field: "presentation_digest",
                expected,
                observed: self.presentation_digest.clone(),
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, ContractError> {
        #[derive(Serialize)]
        struct UnsignedPresentation<'a> {
            domain: &'a str,
            schema_version: &'a str,
            request: &'a OriginChallengeRequest,
            challenge_digest: &'a str,
        }
        let bytes = serde_json::to_vec(&UnsignedPresentation {
            domain: ORIGIN_CHALLENGE_DOMAIN,
            schema_version: &self.schema_version,
            request: &self.request,
            challenge_digest: &self.challenge.challenge_digest,
        })
        .map_err(|error| ContractError::Serialization(error.to_string()))?;
        Ok(hash_bytes(&bytes))
    }

    /// Returns the sealed request.
    pub fn request(&self) -> &OriginChallengeRequest {
        &self.request
    }

    /// Returns the sealed challenge.
    pub fn challenge(&self) -> &OriginChallenge {
        &self.challenge
    }
}

/// Kernel-minted proof that one presented origin control was decided.
///
/// Returned solely by [`OriginChallengeAuthority::decide`]. Opaque: private
/// fields, no public constructor, no `Deserialize`. The Kernel dispatch site
/// attaches it to the exact effect call as proof that the governed path
/// evaluated authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginControlGrant {
    challenge_id: String,
    operation: OriginControlOperation,
    decided_at_unix_ms: u64,
    grant_digest: String,
}

impl OriginControlGrant {
    /// Returns the evaluated challenge identity.
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    /// Returns the authorized operation class.
    pub const fn operation(&self) -> OriginControlOperation {
        self.operation
    }

    /// Returns the decision time.
    pub const fn decided_at_unix_ms(&self) -> u64 {
        self.decided_at_unix_ms
    }

    /// Returns the secret-bound decision tag.
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }

    fn mint(
        key: &KernelDispatchKey,
        challenge: &OriginChallenge,
        now_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        #[derive(Serialize)]
        struct GrantMaterial<'a> {
            domain: &'a str,
            authentication_tag: &'a str,
            operation: OriginControlOperation,
            decided_at_unix_ms: u64,
        }
        let bytes = serde_json::to_vec(&GrantMaterial {
            domain: ORIGIN_CHALLENGE_DOMAIN,
            authentication_tag: &challenge.authentication_tag,
            operation: challenge.operation,
            decided_at_unix_ms: now_unix_ms,
        })
        .map_err(|error| ContractError::Serialization(error.to_string()))?;
        let grant_digest = keyed_hex(key, &bytes);
        Ok(Self {
            challenge_id: challenge.challenge_id.clone(),
            operation: challenge.operation,
            decided_at_unix_ms: now_unix_ms,
            grant_digest,
        })
    }
}

/// One issued challenge as recorded by the Kernel-owned authority.
#[derive(Clone, Debug, Eq, PartialEq)]
struct IssuedOriginChallenge {
    origin_digest: String,
    physical_digest: String,
    installation_id: String,
    generation: Generation,
    state_fence: StateFence,
    operation: OriginControlOperation,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    revoked: bool,
}

/// Kernel-owned issuer and decision point for origin challenges.
///
/// The production instance lives in the Kernel service (P-07 owns the instance
/// and the durable nonce journal); this pure model makes issue/verify/decide
/// ordering executable and independently testable. The daemon never holds an
/// instance and never sees the key: it builds [`OriginChallengeRequest`] values
/// and transports opaque [`OriginChallenge`] bytes.
pub struct OriginChallengeAuthority {
    authority_id: DispatchAuthorityId,
    key: KernelDispatchKey,
    next_sequence: u64,
    issued: BTreeMap<String, IssuedOriginChallenge>,
    consumed_nonces: BTreeSet<String>,
}

impl OriginChallengeAuthority {
    /// Activates one authority instance around Kernel-owned secret material.
    pub fn activate(authority_id: DispatchAuthorityId, key: KernelDispatchKey) -> Self {
        Self {
            authority_id,
            key,
            next_sequence: 1,
            issued: BTreeMap::new(),
            consumed_nonces: BTreeSet::new(),
        }
    }

    /// Returns the authority identity stamped into minted challenges.
    pub fn authority_id(&self) -> &DispatchAuthorityId {
        &self.authority_id
    }

    /// Returns how many challenges this authority has issued.
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }

    /// Issues one challenge bound to exactly one observed origin.
    ///
    /// Validates the request, enforces a short-lived window, stamps a fresh
    /// challenge identity with the secret-bound tag, and records the mint.
    /// The returned challenge verifies only against this authority: same key
    /// plus a live unrevoked record.
    pub fn issue(
        &mut self,
        request: &OriginChallengeRequest,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<OriginChallenge, ContractError> {
        request.validate()?;
        if issued_at_unix_ms == 0 || expires_at_unix_ms < issued_at_unix_ms {
            return Err(ContractError::InvalidValue {
                field: "origin_challenge_window",
                reason: "issue time must be non-zero and precede expiry",
            });
        }
        if expires_at_unix_ms - issued_at_unix_ms > MAX_CHALLENGE_WINDOW_MS {
            return Err(ContractError::InvalidValue {
                field: "origin_challenge_window",
                reason: "challenge window must not exceed one hour",
            });
        }
        if self.issued.contains_key(&request.request_nonce) {
            return Err(ContractError::DuplicateValue {
                field: "request_nonce",
            });
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(ContractError::InvalidValue {
            field: "origin_challenge_sequence",
            reason: "sequence exhausted",
        })?;
        let challenge_id = format!("{}#{sequence:08x}", self.authority_id.as_str());
        let physical_digest = physical_digest(&request.physical);
        let mut challenge = OriginChallenge {
            schema_version: ORIGIN_CHALLENGE_SCHEMA_VERSION.to_owned(),
            authority_id: self.authority_id.clone(),
            challenge_id: challenge_id.clone(),
            origin_digest: request.origin_digest.clone(),
            physical_digest: physical_digest.clone(),
            installation_id: request.installation_id.clone(),
            generation: request.generation,
            state_fence: request.state_fence.clone(),
            operation: request.operation,
            issued_at_unix_ms,
            expires_at_unix_ms,
            nonce: request.request_nonce.clone(),
            authentication_tag: String::new(),
            challenge_digest: String::new(),
        };
        challenge.authentication_tag = keyed_hex(&self.key, &unsigned_bytes(&challenge)?);
        challenge.challenge_digest =
            challenge_digest(&challenge.unsigned(), &challenge.authentication_tag)?;
        challenge.validate_shape()?;
        self.issued.insert(
            request.request_nonce.clone(),
            IssuedOriginChallenge {
                origin_digest: request.origin_digest.clone(),
                physical_digest,
                installation_id: request.installation_id.clone(),
                generation: request.generation,
                state_fence: request.state_fence.clone(),
                operation: request.operation,
                issued_at_unix_ms,
                expires_at_unix_ms,
                revoked: false,
            },
        );
        Ok(challenge)
    }

    /// Revokes an issued challenge by its caller nonce: it decides never again.
    pub fn revoke(&mut self, request_nonce: &str) -> Result<(), ContractError> {
        match self.issued.get_mut(request_nonce) {
            Some(entry) => {
                entry.revoked = true;
                Ok(())
            }
            None => Err(ContractError::InvalidValue {
                field: "request_nonce",
                reason: "unknown challenge nonce",
            }),
        }
    }

    /// Verifies a presentation without consuming it: issuance, tag, currency,
    /// exact origin/physical/installation/fence binds, live epoch, and the
    /// single allowed operation class.
    pub fn verify(
        &self,
        presentation: &OriginControlPresentation,
        active_epoch: &EpochId,
        now_unix_ms: u64,
    ) -> Result<(), ContractError> {
        presentation.validate()?;
        let challenge = &presentation.challenge;
        let request = &presentation.request;
        if challenge.authority_id != self.authority_id {
            return Err(ContractError::DispatchAuthenticationFailed);
        }
        let entry = self
            .issued
            .get(&challenge.nonce)
            .ok_or(ContractError::DispatchPermitRequired)?;
        if entry.revoked {
            return Err(ContractError::InvalidValue {
                field: "origin_challenge_id",
                reason: "challenge was revoked",
            });
        }
        if entry.origin_digest != challenge.origin_digest
            || entry.physical_digest != challenge.physical_digest
            || entry.installation_id != challenge.installation_id
            || entry.generation != challenge.generation
            || entry.operation != challenge.operation
            || entry.issued_at_unix_ms != challenge.issued_at_unix_ms
            || entry.expires_at_unix_ms != challenge.expires_at_unix_ms
        {
            return Err(ContractError::DispatchAuthenticationFailed);
        }
        let expected_tag = keyed_hex(&self.key, &unsigned_bytes(challenge)?);
        if expected_tag != challenge.authentication_tag {
            return Err(ContractError::DispatchAuthenticationFailed);
        }
        if now_unix_ms < challenge.issued_at_unix_ms || now_unix_ms > challenge.expires_at_unix_ms {
            return Err(ContractError::ExpiredDispatchPermit);
        }
        if challenge.origin_digest != request.origin_digest {
            return Err(ContractError::DigestMismatch {
                field: "origin_digest",
                expected: challenge.origin_digest.clone(),
                observed: request.origin_digest.clone(),
            });
        }
        if challenge.physical_digest != physical_digest(&request.physical) {
            return Err(ContractError::IdentityMismatch);
        }
        if challenge.installation_id != request.installation_id {
            return Err(ContractError::IdentityMismatch);
        }
        if !fences_match_exact(&challenge.state_fence, &request.state_fence) {
            return Err(ContractError::StaleStateFence);
        }
        if !StateFence::authorizes_canonical(&challenge.state_fence.authority_epoch, active_epoch) {
            return Err(ContractError::StaleAuthorityEpoch);
        }
        if challenge.operation != request.operation {
            return Err(ContractError::InvalidValue {
                field: "origin_operation",
                reason: "challenge does not allow this operation class",
            });
        }
        Ok(())
    }

    /// The exclusive control-authority decision: verifies and consumes the
    /// challenge exactly once, then mints the [`OriginControlGrant`] proof.
    pub fn decide(
        &mut self,
        presentation: &OriginControlPresentation,
        active_epoch: &EpochId,
        now_unix_ms: u64,
    ) -> Result<OriginControlGrant, ContractError> {
        self.verify(presentation, active_epoch, now_unix_ms)?;
        if !self
            .consumed_nonces
            .insert(presentation.challenge.nonce.clone())
        {
            return Err(ContractError::DispatchPermitConsumed);
        }
        OriginControlGrant::mint(&self.key, &presentation.challenge, now_unix_ms)
    }

    /// Returns how many challenges were consumed by decisions.
    pub fn consumed_count(&self) -> usize {
        self.consumed_nonces.len()
    }
}

fn validate_token(
    field: &'static str,
    value: String,
    max_len: usize,
) -> Result<String, ContractError> {
    if value.trim().is_empty()
        || value.len() > max_len
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'#' | b'-' | b'.' | b'_' | b':'))
        })
    {
        return Err(ContractError::InvalidOpaqueValue { field });
    }
    Ok(value)
}

/// Checks request↔challenge binding for packaging; authority state untouched.
fn check_binding(
    request: &OriginChallengeRequest,
    challenge: &OriginChallenge,
) -> Result<(), ContractError> {
    if challenge.origin_digest != request.origin_digest
        || challenge.physical_digest != physical_digest(&request.physical)
        || challenge.installation_id != request.installation_id
        || challenge.generation != request.generation
        || !fences_match_exact(&challenge.state_fence, &request.state_fence)
        || challenge.operation != request.operation
        || challenge.nonce != request.request_nonce
    {
        return Err(ContractError::DispatchBindingMismatch);
    }
    Ok(())
}

fn validate_origin_digest(value: String) -> Result<String, ContractError> {
    validate_hex_digest(&value)?;
    Ok(value)
}

fn validate_hex_digest(value: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ContractError::InvalidValue {
            field: "origin_hex_digest",
            reason: "must be a 64-character lowercase hexadecimal digest",
        });
    }
    Ok(())
}

/// Binds pid plus process start identity plus image plus executor job.
fn physical_digest(physical: &PhysicalProcessBinding) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(&physical.process_id().to_be_bytes());
    material.push(0);
    material.extend_from_slice(&physical.start_time_100ns().to_be_bytes());
    material.push(0);
    material.extend_from_slice(physical.image_path().as_bytes());
    material.push(0);
    material.extend_from_slice(physical.executor_job_name().as_bytes());
    hash_bytes(&material)
}

fn unsigned_bytes(challenge: &OriginChallenge) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(&challenge.unsigned())
        .map_err(|error| ContractError::Serialization(error.to_string()))
}

fn keyed_hex(key: &KernelDispatchKey, bytes: &[u8]) -> String {
    blake3::keyed_hash(key.as_bytes(), bytes)
        .to_hex()
        .to_string()
}

fn challenge_digest(unsigned: &UnsignedChallenge<'_>, tag: &str) -> Result<String, ContractError> {
    let bytes = serde_json::to_vec(&(unsigned, tag))
        .map_err(|error| ContractError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ISSUED_AT: u64 = 1_700_000_000_000;
    const EXPIRES_AT: u64 = 1_700_000_060_000;
    const NOW: u64 = 1_700_000_030_000;

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            test_epoch(),
            ResourceGeneration::new(3).expect("generation"),
        )
    }

    fn test_physical() -> PhysicalProcessBinding {
        PhysicalProcessBinding::new(
            4242,
            133_081_756_927_500_000,
            "C:\\svc\\worker.exe",
            "executor-job-1",
        )
        .expect("physical identity")
    }

    fn test_request() -> OriginChallengeRequest {
        OriginChallengeRequest::new(
            test_physical(),
            "installation-7",
            "a".repeat(64),
            Generation::new(3).expect("generation"),
            test_fence(),
            OriginControlOperation::Kill,
            "nonce-0001",
        )
        .expect("challenge request")
    }

    fn test_authority() -> OriginChallengeAuthority {
        OriginChallengeAuthority::activate(
            DispatchAuthorityId::new("kernel-origin-test").expect("authority id"),
            KernelDispatchKey::from_secret_bytes([7_u8; 32]).expect("kernel key"),
        )
    }

    fn present(
        authority: &mut OriginChallengeAuthority,
        request: OriginChallengeRequest,
    ) -> OriginControlPresentation {
        let challenge = authority
            .issue(&request, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues the challenge");
        OriginControlPresentation::new(request, challenge).expect("presentation seals")
    }

    #[test]
    fn kernel_issue_and_decide_authorizes_exact_control() {
        let mut authority = test_authority();
        let request = test_request();
        let presentation = present(&mut authority, request);
        let grant = authority
            .decide(&presentation, &test_epoch(), NOW)
            .expect("kernel decides");
        assert_eq!(grant.operation(), OriginControlOperation::Kill);
        assert_eq!(grant.decided_at_unix_ms(), NOW);
        assert_eq!(authority.consumed_count(), 1);
    }

    #[test]
    fn challenge_minted_outside_this_authority_never_authorizes() {
        let request = test_request();
        // Attacker-controlled shape with a guessed tag: packaging already
        // fails on the content binding. No mint, no tag.
        let forged = OriginChallenge {
            schema_version: ORIGIN_CHALLENGE_SCHEMA_VERSION.to_owned(),
            authority_id: DispatchAuthorityId::new("kernel-origin-test").expect("authority id"),
            challenge_id: "kernel-origin-test#00000001".to_owned(),
            origin_digest: request.origin_digest.clone(),
            physical_digest: physical_digest(&request.physical),
            installation_id: request.installation_id.clone(),
            generation: request.generation,
            state_fence: request.state_fence.clone(),
            operation: request.operation,
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            nonce: "attacker-nonce".to_owned(),
            authentication_tag: "0".repeat(64),
            challenge_digest: "1".repeat(64),
        };
        assert!(OriginControlPresentation::new(request, forged).is_err());
        // Well-shaped challenge minted by a different Kernel authority
        // instance (different key): the tag is not issuer-bound here.
        let mut other = OriginChallengeAuthority::activate(
            DispatchAuthorityId::new("other-kernel").expect("authority id"),
            KernelDispatchKey::from_secret_bytes([9_u8; 32]).expect("kernel key"),
        );
        let other_challenge = other
            .issue(&test_request(), ISSUED_AT, EXPIRES_AT)
            .expect("other authority issues");
        let presentation =
            OriginControlPresentation::new(test_request(), other_challenge).expect("seals");
        let authority = test_authority();
        assert!(matches!(
            authority.verify(&presentation, &test_epoch(), NOW),
            Err(ContractError::DispatchAuthenticationFailed)
        ));
    }

    #[test]
    fn consumed_challenge_never_decides_twice() {
        let mut authority = test_authority();
        let presentation = present(&mut authority, test_request());
        authority
            .decide(&presentation, &test_epoch(), NOW)
            .expect("first decision");
        assert!(matches!(
            authority.decide(&presentation, &test_epoch(), NOW),
            Err(ContractError::DispatchPermitConsumed)
        ));
    }

    #[test]
    fn revoked_challenge_never_decides() {
        let mut authority = test_authority();
        let presentation = present(&mut authority, test_request());
        authority.revoke("nonce-0001").expect("revocation records");
        assert!(matches!(
            authority.decide(&presentation, &test_epoch(), NOW),
            Err(ContractError::InvalidValue { .. })
        ));
    }

    #[test]
    fn expired_challenge_never_decides() {
        let mut authority = test_authority();
        let presentation = present(&mut authority, test_request());
        assert!(matches!(
            authority.decide(&presentation, &test_epoch(), EXPIRES_AT + 1),
            Err(ContractError::ExpiredDispatchPermit)
        ));
    }

    #[test]
    fn wrong_operation_class_never_decides() {
        let mut authority = test_authority();
        let request = test_request();
        let challenge = authority
            .issue(&request, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues kill");
        // A kill challenge cannot be resealed for adopt: packaging rejects the
        // class mismatch before any authority state is touched.
        let mut adopt_request = test_request();
        adopt_request.operation = OriginControlOperation::Adopt;
        assert!(matches!(
            OriginControlPresentation::new(adopt_request, challenge),
            Err(ContractError::DispatchBindingMismatch)
        ));
    }

    #[test]
    fn mismatched_physical_identity_never_decides() {
        let mut authority = test_authority();
        let request = test_request();
        let challenge = authority
            .issue(&request, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues");
        // Same observation digest but a different OS process (PID reuse): the
        // packaging bind rejects before authority state is touched.
        let mut other = test_request();
        other.physical = PhysicalProcessBinding::new(
            9999,
            133_081_756_927_500_000,
            "C:\\svc\\worker.exe",
            "executor-job-1",
        )
        .expect("other physical identity");
        assert!(matches!(
            OriginControlPresentation::new(other, challenge),
            Err(ContractError::DispatchBindingMismatch)
        ));
    }

    #[test]
    fn stale_epoch_never_decides() {
        let mut authority = test_authority();
        let presentation = present(&mut authority, test_request());
        let other_epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(2).expect("sequence"),
        )
        .expect("epoch");
        assert!(matches!(
            authority.decide(&presentation, &other_epoch, NOW),
            Err(ContractError::StaleAuthorityEpoch)
        ));
    }

    #[test]
    fn path_port_only_request_without_valid_digest_fails() {
        let fence = test_fence();
        let bad = OriginChallengeRequest::new(
            test_physical(),
            "installation-7",
            "not-a-digest",
            Generation::new(3).expect("generation"),
            fence,
            OriginControlOperation::Kill,
            "nonce-0002",
        );
        assert!(matches!(bad, Err(ContractError::InvalidValue { .. })));
    }
}
