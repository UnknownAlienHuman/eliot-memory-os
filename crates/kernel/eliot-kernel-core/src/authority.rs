//! Private authority issuance and non-forgeable authority receipts.
//!
//! Authority is never derived from content, confidence or a role name. It is
//! issued only by the Kernel, which holds the private [`KernelAuthorityKey`],
//! and it is consumed by re-checking an exact route fence, an exact epoch
//! binding and a keyed-MAC tag that a consumer cannot reproduce.
//!
//! The tag is a Blake3 keyed hash over the canonical bytes of the unsigned
//! receipt. Because the key stays inside the Kernel process, a consumer may
//! verify a receipt (through the Kernel) but may never forge one.
//!
//! The bound epoch is the lineage-aware [`EpochId`] tuple (I6.10), never a
//! bare sequence counter: the MAC payload carries both `lineage_id` and
//! `sequence`, so two receipts minted at equal sequences under different
//! lineages have different tags and never authorize each other.

use std::fmt;
use std::num::NonZeroU64;

use eliot_contracts::{ContractId, EpochId, ResourceGeneration, canonical_json_bytes};
use eliot_receipts::{EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::RouteScope;
use crate::error::{KernelError, validate_text};

const KEY_CONTEXT: &str = "eliot-kernel-core authority key v1";

/// The Kernel's private authority-issuance key.
///
/// The key never implements [`Serialize`] and its [`Debug`] output is
/// redacted, so it cannot cross a log, report or transport boundary. It is the
/// sole input that makes a receipt forge-resistant.
#[derive(Clone)]
pub struct KernelAuthorityKey([u8; 32]);

impl KernelAuthorityKey {
    /// Adopts an exact 32-byte key supplied by a platform secret provider.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives a 32-byte key from a higher-entropy secret using Blake3.
    ///
    /// This lets the Kernel adopt a DPAPI/Credential-Manager secret of
    /// arbitrary length without weakening the receipt to a raw password.
    #[must_use]
    pub fn derive_from_secret(secret: &[u8]) -> Self {
        Self(blake3::derive_key(KEY_CONTEXT, secret))
    }

    /// Returns the raw key bytes for internal MAC computation.
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for KernelAuthorityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KernelAuthorityKey(<redacted>)")
    }
}

/// The unsigned, canonical payload over which an authority receipt is keyed.
///
/// The payload binds the exact lineage-aware epoch tuple: `lineage_id` and
/// `sequence` both enter the canonical bytes, so the MAC tag distinguishes
/// lineages that happen to share a sequence number.
#[derive(Serialize)]
struct UnsignedAuthorityReceipt<'a> {
    authority_id: &'a ContractId,
    authority_owner: &'a str,
    authority_epoch: &'a EpochId,
    route_scope: &'a RouteScope,
    resource_generation: ResourceGeneration,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
}

/// A non-forgeable authority receipt issued by the Kernel.
///
/// The `tag` is a Blake3 keyed MAC over the canonical unsigned payload. Any
/// change to a binding field invalidates the tag, and a consumer without the
/// private key cannot produce a valid tag at all.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityReceipt {
    authority_id: ContractId,
    authority_owner: String,
    authority_epoch: EpochId,
    route_scope: RouteScope,
    resource_generation: ResourceGeneration,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
    tag: String,
}

impl AuthorityReceipt {
    /// Verifies the cryptographic tag without mutating state.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::ForgedReceipt`] when the tag does not match the
    /// canonical payload under the private key.
    pub fn verify_tag(&self, key: &KernelAuthorityKey) -> Result<(), KernelError> {
        let expected = self.compute_tag(key)?;
        let expected_bytes = decode_hex(&expected)?;
        let observed_bytes = decode_hex(&self.tag)?;
        if !constant_time_eq(&expected_bytes, &observed_bytes) {
            return Err(KernelError::ForgedReceipt);
        }
        Ok(())
    }

    fn compute_tag(&self, key: &KernelAuthorityKey) -> Result<String, KernelError> {
        let unsigned = UnsignedAuthorityReceipt {
            authority_id: &self.authority_id,
            authority_owner: &self.authority_owner,
            authority_epoch: &self.authority_epoch,
            route_scope: &self.route_scope,
            resource_generation: self.resource_generation,
            allowed_effect: self.allowed_effect,
            proof_ceiling: self.proof_ceiling,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        };
        let bytes = canonical_json_bytes(&unsigned).map_err(|_| KernelError::InvalidField {
            field: "authority_receipt",
            reason: "canonical serialization failed",
        })?;
        Ok(encode_hex(
            blake3::keyed_hash(key.as_bytes(), &bytes).as_bytes(),
        ))
    }

    /// Returns the authority identity.
    #[must_use]
    pub fn authority_id(&self) -> &ContractId {
        &self.authority_id
    }

    /// Returns the authority owner.
    #[must_use]
    pub fn authority_owner(&self) -> &str {
        &self.authority_owner
    }

    /// Returns the bound authority epoch tuple.
    #[must_use]
    pub fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the exact route this receipt covers.
    #[must_use]
    pub fn route_scope(&self) -> &RouteScope {
        &self.route_scope
    }

    /// Returns the bound resource generation.
    #[must_use]
    pub const fn resource_generation(&self) -> ResourceGeneration {
        self.resource_generation
    }

    /// Returns the allowed effect class.
    #[must_use]
    pub const fn allowed_effect(&self) -> EffectClass {
        self.allowed_effect
    }

    /// Returns the proof ceiling.
    #[must_use]
    pub const fn proof_ceiling(&self) -> ProofCeiling {
        self.proof_ceiling
    }

    /// Returns the issue timestamp in Unix milliseconds.
    #[must_use]
    pub const fn issued_at_ms(&self) -> i64 {
        self.issued_at_ms
    }

    /// Returns the expiry timestamp, if one was issued.
    #[must_use]
    pub const fn expires_at_ms(&self) -> Option<i64> {
        self.expires_at_ms
    }
}

/// A request to issue an authority receipt.
#[derive(Clone, Debug)]
pub struct AuthorityGrantRequest {
    authority_id: ContractId,
    authority_owner: String,
    route_scope: RouteScope,
    resource_generation: ResourceGeneration,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
}

impl AuthorityGrantRequest {
    /// Creates and validates an authority-grant request.
    ///
    /// # Errors
    ///
    /// Returns an error for a blank owner, a zero resource generation, or an
    /// expiry that is not strictly later than issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: ContractId,
        authority_owner: impl Into<String>,
        route_scope: RouteScope,
        resource_generation: ResourceGeneration,
        allowed_effect: EffectClass,
        proof_ceiling: ProofCeiling,
        issued_at_ms: i64,
        expires_at_ms: Option<i64>,
    ) -> Result<Self, KernelError> {
        let authority_owner = authority_owner.into();
        validate_text(&authority_owner, "authority_owner")?;
        if resource_generation.value() == 0 {
            return Err(KernelError::InvalidField {
                field: "resource_generation",
                reason: "must be greater than zero",
            });
        }
        if let Some(expires) = expires_at_ms
            && expires <= issued_at_ms
        {
            return Err(KernelError::InvalidField {
                field: "expires_at_ms",
                reason: "expiry must be strictly later than issuance",
            });
        }
        Ok(Self {
            authority_id,
            authority_owner,
            route_scope,
            resource_generation,
            allowed_effect,
            proof_ceiling,
            issued_at_ms,
            expires_at_ms,
        })
    }
}

/// The verified authority extracted after a receipt is consumed.
///
/// This value is produced only by [`KernelAuthority::consume`], which checks
/// the tag, epoch, route and expiry first. It therefore carries no forging
/// surface and no key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityGrant {
    authority_id: ContractId,
    authority_owner: String,
    authority_epoch: EpochId,
    route_scope: RouteScope,
    resource_generation: ResourceGeneration,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    expires_at_ms: Option<i64>,
}

impl AuthorityGrant {
    /// Returns the authority identity.
    #[must_use]
    pub fn authority_id(&self) -> &ContractId {
        &self.authority_id
    }

    /// Returns the authority owner.
    #[must_use]
    pub fn authority_owner(&self) -> &str {
        &self.authority_owner
    }

    /// Returns the bound authority epoch tuple.
    #[must_use]
    pub fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the exact route this grant covers.
    #[must_use]
    pub fn route_scope(&self) -> &RouteScope {
        &self.route_scope
    }

    /// Returns the bound resource generation.
    #[must_use]
    pub const fn resource_generation(&self) -> ResourceGeneration {
        self.resource_generation
    }

    /// Returns the allowed effect class.
    #[must_use]
    pub const fn allowed_effect(&self) -> EffectClass {
        self.allowed_effect
    }

    /// Returns the proof ceiling.
    #[must_use]
    pub const fn proof_ceiling(&self) -> ProofCeiling {
        self.proof_ceiling
    }

    /// Returns whether this grant permits an effect of `class` at or below
    /// `ceiling` without overclaiming proof.
    #[must_use]
    pub fn permits(&self, class: EffectClass, ceiling: ProofCeiling) -> bool {
        effect_rank(class) <= effect_rank(self.allowed_effect)
            && ceiling.is_at_most(self.proof_ceiling)
    }
}

/// The Kernel's authority-issuance and consumption state.
///
/// The same object both issues and consumes authority so that the private key
/// never leaves the Kernel. Consumers never obtain the key; they present a
/// receipt back to the Kernel, which verifies it through this object.
///
/// Cloning shares the key within one trusted process; the key is still never
/// serialized or exposed through a log or transport boundary.
#[derive(Clone)]
pub struct KernelAuthority {
    key: KernelAuthorityKey,
    current_epoch: EpochId,
}

impl KernelAuthority {
    /// Creates the Kernel authority holder at a given lineage-aware epoch.
    #[must_use]
    pub fn new(key: KernelAuthorityKey, current_epoch: EpochId) -> Self {
        Self { key, current_epoch }
    }

    /// Returns the epoch tuple currently being fenced.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch.clone()
    }

    /// Issues a non-forgeable authority receipt at the current epoch tuple.
    ///
    /// The receipt binds the exact `(lineage_id, sequence)` tuple into the
    /// MAC payload: a receipt minted under one lineage never verifies as
    /// current under another, even at an equal sequence.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is invalid or canonical serialization
    /// fails.
    pub fn issue(&self, request: AuthorityGrantRequest) -> Result<AuthorityReceipt, KernelError> {
        let receipt = AuthorityReceipt {
            authority_id: request.authority_id,
            authority_owner: request.authority_owner,
            authority_epoch: self.current_epoch.clone(),
            route_scope: request.route_scope,
            resource_generation: request.resource_generation,
            allowed_effect: request.allowed_effect,
            proof_ceiling: request.proof_ceiling,
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            tag: String::new(),
        };
        let tag = receipt.compute_tag(&self.key)?;
        Ok(AuthorityReceipt { tag, ..receipt })
    }

    /// Consumes a receipt, returning verified authority only when it is
    /// authentic, current, route-exact and unexpired.
    ///
    /// Exact tuple equality is the currency rule: a receipt from another
    /// lineage is [`KernelError::StaleEpochTuple`] carrying both complete
    /// tuples, whether its sequence is smaller, equal or larger — it is
    /// unrelated, never merely out of order. A receipt from the active
    /// lineage at a different sequence is [`KernelError::StaleEpoch`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::ForgedReceipt`], [`KernelError::StaleEpochTuple`],
    /// [`KernelError::StaleEpoch`], [`KernelError::RouteMismatch`] or
    /// [`KernelError::Expired`] as the first applicable rejection.
    pub fn consume(
        &self,
        receipt: &AuthorityReceipt,
        expected_route: &RouteScope,
        now_ms: i64,
    ) -> Result<AuthorityGrant, KernelError> {
        receipt.verify_tag(&self.key)?;
        if !receipt
            .authority_epoch
            .is_same_authority(&self.current_epoch)
        {
            if receipt.authority_epoch.lineage_id != self.current_epoch.lineage_id {
                return Err(KernelError::StaleEpochTuple {
                    observed: receipt.authority_epoch.clone(),
                    active: self.current_epoch.clone(),
                });
            }
            return Err(KernelError::StaleEpoch {
                observed: receipt.authority_epoch.sequence.get(),
                active: self.current_epoch.sequence.get(),
            });
        }
        if receipt.route_scope() != expected_route {
            return Err(KernelError::RouteMismatch);
        }
        if let Some(expires) = receipt.expires_at_ms
            && expires <= now_ms
        {
            return Err(KernelError::Expired {
                expires_at_ms: expires,
            });
        }
        Ok(AuthorityGrant {
            authority_id: receipt.authority_id.clone(),
            authority_owner: receipt.authority_owner.clone(),
            authority_epoch: receipt.authority_epoch.clone(),
            route_scope: receipt.route_scope.clone(),
            resource_generation: receipt.resource_generation,
            allowed_effect: receipt.allowed_effect,
            proof_ceiling: receipt.proof_ceiling,
            expires_at_ms: receipt.expires_at_ms,
        })
    }

    /// Fences the current epoch and raises the next sequence in the same
    /// lineage.
    ///
    /// After this call, every previously issued receipt becomes stale and can
    /// no longer be consumed. Cross-lineage advancement is impossible by
    /// construction: the new tuple keeps the fenced lineage.
    ///
    /// # Errors
    ///
    /// Returns an error when the sequence counter cannot advance.
    pub fn advance_epoch(&mut self) -> Result<EpochId, KernelError> {
        let next_sequence =
            self.current_epoch
                .sequence
                .get()
                .checked_add(1)
                .ok_or(KernelError::InvalidField {
                    field: "authority_epoch",
                    reason: "sequence overflow",
                })?;
        let next = EpochId::new(
            self.current_epoch.lineage_id.clone(),
            NonZeroU64::new(next_sequence).ok_or(KernelError::InvalidField {
                field: "authority_epoch",
                reason: "sequence overflow",
            })?,
        )
        .map_err(|_| KernelError::InvalidField {
            field: "authority_epoch",
            reason: "invalid canonical epoch",
        })?;
        self.current_epoch = next.clone();
        Ok(next)
    }

    /// Fast-forwards the authority fence to a validated durable epoch tuple.
    ///
    /// Recovery must not replay one in-memory increment per persisted epoch:
    /// the durable epoch is already the linearized value, so synchronizing to
    /// it directly is both bounded and equivalent for receipt fencing. The
    /// target must be the current tuple or a same-lineage forward adoption;
    /// a regression is [`KernelError::StaleEpoch`] and a cross-lineage target
    /// is [`KernelError::StaleEpochTuple`], never an implicit lineage switch.
    pub fn synchronize_epoch(&mut self, target: EpochId) -> Result<EpochId, KernelError> {
        if target.is_same_authority(&self.current_epoch) {
            return Ok(target);
        }
        if target.lineage_id != self.current_epoch.lineage_id {
            return Err(KernelError::StaleEpochTuple {
                observed: target,
                active: self.current_epoch.clone(),
            });
        }
        if target.sequence.get() < self.current_epoch.sequence.get() {
            return Err(KernelError::StaleEpoch {
                observed: target.sequence.get(),
                active: self.current_epoch.sequence.get(),
            });
        }
        self.current_epoch = target.clone();
        Ok(target)
    }
}

/// Orders the effect classes so `Read` is the weakest and `ExternalEffect` the
/// strongest. A grant permits only classes at or below its own.
fn effect_rank(effect: EffectClass) -> u8 {
    match effect {
        EffectClass::Read => 0,
        EffectClass::Candidate => 1,
        EffectClass::ReversibleMutation => 2,
        EffectClass::ExternalEffect => 3,
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Result<[u8; 32], KernelError> {
    let mut bytes = [0u8; 32];
    let raw = value.as_bytes();
    if raw.len() != 64
        || !raw
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(KernelError::InvalidField {
            field: "authority_receipt.tag",
            reason: "must be a lowercase hexadecimal digest",
        });
    }
    for index in 0..32 {
        bytes[index] = (hex_nibble(raw[index * 2]) << 4) | hex_nibble(raw[index * 2 + 1]);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut accumulator = 0u8;
    for index in 0..32 {
        accumulator |= left[index] ^ right[index];
    }
    accumulator == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn genesis_epoch() -> Result<EpochId, KernelError> {
        let lineage_id =
            EpochLineageId::new(TEST_LINEAGE).map_err(|_| KernelError::InvalidField {
                field: "lineage_id",
                reason: "must be a canonical UUID lineage",
            })?;
        EpochId::new(lineage_id, NonZeroU64::MIN).map_err(|_| KernelError::InvalidField {
            field: "epoch_id",
            reason: "invalid canonical epoch",
        })
    }

    fn key() -> KernelAuthorityKey {
        KernelAuthorityKey::from_bytes([7u8; 32])
    }

    fn request() -> Result<AuthorityGrantRequest, KernelError> {
        AuthorityGrantRequest::new(
            ContractId::new("authority-1")?,
            "kernel",
            RouteScope::new("daemon")?,
            ResourceGeneration::genesis(),
            EffectClass::ReversibleMutation,
            ProofCeiling::ScopedVerification,
            100,
            Some(1_000),
        )
    }

    #[test]
    fn issued_receipt_consumes_to_the_same_grant() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(key(), genesis_epoch()?);
        let receipt = authority.issue(request()?)?;
        let route = RouteScope::new("daemon")?;
        let grant = authority.consume(&receipt, &route, 500)?;
        assert_eq!(grant.authority_epoch(), &genesis_epoch()?);
        assert_eq!(grant.route_scope(), &route);
        assert!(grant.permits(
            EffectClass::ReversibleMutation,
            ProofCeiling::ScopedVerification
        ));
        assert!(!grant.permits(
            EffectClass::ExternalEffect,
            ProofCeiling::ScopedVerification
        ));
        Ok(())
    }

    #[test]
    fn tampered_receipt_is_forged() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(key(), genesis_epoch()?);
        let mut receipt = authority.issue(request()?)?;
        receipt.allowed_effect = EffectClass::ExternalEffect;
        let route = RouteScope::new("daemon")?;
        assert!(matches!(
            authority.consume(&receipt, &route, 500),
            Err(KernelError::ForgedReceipt)
        ));
        Ok(())
    }

    #[test]
    fn a_different_key_cannot_consume_the_receipt() -> Result<(), KernelError> {
        let issuer = KernelAuthority::new(key(), genesis_epoch()?);
        let receipt = issuer.issue(request()?)?;
        let other =
            KernelAuthority::new(KernelAuthorityKey::from_bytes([9u8; 32]), genesis_epoch()?);
        let route = RouteScope::new("daemon")?;
        assert!(matches!(
            other.consume(&receipt, &route, 500),
            Err(KernelError::ForgedReceipt)
        ));
        Ok(())
    }

    #[test]
    fn stale_epoch_and_wrong_route_are_rejected() -> Result<(), KernelError> {
        let mut authority = KernelAuthority::new(key(), genesis_epoch()?);
        let receipt = authority.issue(request()?)?;
        authority.advance_epoch()?;
        let route = RouteScope::new("daemon")?;
        assert!(matches!(
            authority.consume(&receipt, &route, 500),
            Err(KernelError::StaleEpoch { .. })
        ));

        let authority = KernelAuthority::new(key(), genesis_epoch()?);
        let receipt = authority.issue(request()?)?;
        let wrong_route = RouteScope::new("store_bridge")?;
        assert!(matches!(
            authority.consume(&receipt, &wrong_route, 500),
            Err(KernelError::RouteMismatch)
        ));
        Ok(())
    }

    #[test]
    fn expired_receipt_is_rejected() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(key(), genesis_epoch()?);
        let receipt = authority.issue(request()?)?;
        let route = RouteScope::new("daemon")?;
        assert!(matches!(
            authority.consume(&receipt, &route, 2_000),
            Err(KernelError::Expired { .. })
        ));
        Ok(())
    }

    #[test]
    fn key_debug_is_redacted() {
        assert_eq!(format!("{:?}", key()), "KernelAuthorityKey(<redacted>)");
    }

    #[test]
    fn derive_key_is_stable_for_a_secret() {
        let a = KernelAuthorityKey::derive_from_secret(b"secret");
        let b = KernelAuthorityKey::derive_from_secret(b"secret");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
