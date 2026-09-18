//! Kernel-side provider-capability verifier (T9-04 supplier core, issue #1108).
//!
//! Pure types plus validation for the seven Kernel-verified provider proof
//! kinds consumed by the supplier surface (M2 binding, issue #22 comment
//! 5659245939): the supplier is Kernel over one authenticated front-door
//! session, and every proof kind is verified by lookup of the Kernel/ORS
//! operation record bound to the exact attempt plus operation (T4
//! `ProviderExecutionBinding`), with the Governor current route and capacity
//! revisions carried only as presented inputs. No behavior, no stores, no IO:
//! persistence, lookup, and daemon composition land outside this file. Kernel
//! validates identity, epoch, presented revisions, and digest equality only;
//! it never interprets task semantics, provider policy, payload meaning, or
//! finish.
//!
//! There is no signing, no token minting, no trust service, and no user
//! authentication here (user auth is forbidden by issue #1376): the only
//! authority is the durable Kernel/ORS claim row plus the live authority
//! epoch, compared by exact string and `is_same_authority` equality. A saved
//! `Verified` verdict is never authority on its own: restore re-queries
//! Kernel through this same verifier, so a replayed receipt without a live
//! durable binding still fails closed.
//!
//! The capability itself is constructed only in daemon composition (a later
//! wave owns that call site): the daemon resolves the claim row through the
//! ORS read projection, presents the Governor revisions it observed, and
//! calls [`verify_provider_capability`]. Depending on `eliot-governor` from
//! this C1 crate would invert the I2.3 dependency direction (C4 → C3 → C2 →
//! C1 → C0), so the Governor revisions ride here as opaque strings compared
//! for equality only, exactly like the T9-02 executable join carries the
//! owner digest by value (`native_worker_claim.rs`) and the T9-03 replay
//! transport carries its authority by value (`native_worker_replay.rs`).
//!
//! Residual: ORS carries no `executable_binding_digest` column on the claim
//! row (no write migration in this slice), so the executable digest is
//! presented per call and compared for equality against the durable binding
//! material loaded from Kernel/ORS — never trusted by value — mirroring the
//! T9-02 presented-expectation pattern (`revoked` stays false until a
//! Governor revocation feed exists; withdrawal is observed only as
//! digest/revision disagreement).

use eliot_contracts::EpochId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity for the Kernel-owned provider-capability verifier.
///
/// Versioned as a string so a future capability contour bump follows the
/// explicit-reject precedent of the claim wire (v1 → v2) and the replay wire
/// (new family starts at v1): an unknown contour is rejected, never promoted.
pub const PROVIDER_CAPABILITY_WIRE_VERSION: &str = "eliot-kernel-provider-capability/v1";

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates bounded wire text without carrying platform or secret material.
///
/// Mirrors the crate-internal `validate_text` bounds (non-blank, no control
/// characters, at most 1024 UTF-8 bytes) while reporting the file-local typed
/// error, keeping this module free of `KernelServiceError` coupling.
fn validate_wire_text(value: &str) -> Result<(), ProviderCapabilityError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > 1024 {
        return Err(ProviderCapabilityError::MalformedRequest);
    }
    Ok(())
}

/// Kernel-owned provider proof kind.
///
/// Mirrors the seven coordinator proof-kind names
/// (`eliot-agent-coordinator`, MGR02 T9-05 owns that surface) without
/// importing coordinator semantics: Kernel names the slot being proven and
/// verifies its binding, nothing more.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderProofKind {
    /// Admission of one provider execution unit.
    Admission,
    /// Cancellation of one provider execution unit.
    Cancellation,
    /// Worker fence binding for one provider execution unit.
    WorkerFence,
    /// Reassignment of one provider execution unit.
    Reassignment,
    /// Result of one provider execution unit.
    Result,
    /// Unknown outcome under one provider execution unit.
    UnknownOutcome,
    /// Exact start correlation of one provider execution unit.
    Binding,
}

/// Presented provider-capability proof for exactly one Kernel-owned operation.
///
/// Every identity field is caller-presented evidence: the daemon composition
/// resolves the durable claim row first (exact `claim_id` key lookup, then
/// the attempt/operation reverse projection) and hands the loaded row fields
/// to [`verify_provider_capability`] alongside this request. Nothing here is
/// trusted by value.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilityRequest {
    /// Durable claim identity the proof is presented under.
    pub claim_id: String,
    /// Attempt identity the proof claims to bind.
    pub attempt_id: String,
    /// Exact external-effect operation identity the proof claims to bind.
    pub operation_id: String,
    /// Which of the seven proof slots is being proven.
    pub proof_kind: ProviderProofKind,
    /// Opaque provider proof reference, carried without interpretation.
    pub proof_ref: String,
    /// Lowercase SHA-256 over the canonical proof payload bytes.
    pub canonical_payload_sha256: String,
    /// Presented claim binding digest, compared against the durable row.
    pub binding_digest: String,
    /// Presented executable binding digest, compared per call (no ORS
    /// column; see the module residual).
    pub executable_binding_digest: String,
    /// Presented Governor current route revision, compared for equality.
    pub route_revision: String,
    /// Presented Governor current capacity revision, compared for equality.
    pub capacity_revision: String,
}

impl ProviderCapabilityRequest {
    /// Validates the closed request shape without consulting any authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderCapabilityError::MalformedRequest`] for blank,
    /// control-bearing, or overlong text (including a malformed
    /// binding/executable digest shape) and
    /// [`ProviderCapabilityError::InvalidPayloadDigest`] for a malformed
    /// canonical payload digest.
    pub fn validate(&self) -> Result<(), ProviderCapabilityError> {
        for text in [
            &self.claim_id,
            &self.attempt_id,
            &self.operation_id,
            &self.proof_ref,
            &self.binding_digest,
            &self.executable_binding_digest,
            &self.route_revision,
            &self.capacity_revision,
        ] {
            validate_wire_text(text)?;
        }
        if !is_lowercase_sha256(&self.canonical_payload_sha256) {
            return Err(ProviderCapabilityError::InvalidPayloadDigest);
        }
        if !is_lowercase_sha256(&self.binding_digest)
            || !is_lowercase_sha256(&self.executable_binding_digest)
        {
            return Err(ProviderCapabilityError::MalformedRequest);
        }
        Ok(())
    }
}

/// Current Governor revision inputs plus live Kernel authority one capability
/// proof is checked against.
///
/// The route builds this from live records at verification time: the
/// revisions are what Governor currently presents, and `revoked` carries
/// observed invalidation evidence. Kernel never mints this value; it only
/// refuses presented proofs that disagree with it. Follows the
/// `NativeWorkerExecutableExpectation` / `NativeWorkerReplayExpectation`
/// precedent: `revoked` stays false while no revocation feed exists, so
/// withdrawal is observed only as digest/revision disagreement.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilityExpectation {
    /// Governor-presented current route revision.
    pub current_route_revision: String,
    /// Governor-presented current capacity revision.
    pub current_capacity_revision: String,
    /// Live Kernel authority epoch the proof must be current under.
    pub live_authority_epoch: EpochId,
    /// True when current records show the binding withdrawn or superseded.
    pub revoked: bool,
}

impl ProviderCapabilityExpectation {
    /// Validates the closed expectation shape.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderCapabilityError::MalformedRequest`] for blank,
    /// control-bearing, or overlong revision text.
    pub fn validate(&self) -> Result<(), ProviderCapabilityError> {
        validate_wire_text(&self.current_route_revision)?;
        validate_wire_text(&self.current_capacity_revision)?;
        Ok(())
    }
}

/// Typed reason one provider-capability proof was not verified.
///
/// Every variant names its cause; a stale, foreign, or unknown presentation
/// is rejected, never default-accepted. `UnknownClaim` is constructed by the
/// daemon composition when the ORS claim lookup misses (no durable row under
/// the presented identity); the pure [`verify_provider_capability`] below
/// reports a blank claim identity as `MalformedRequest` instead, since a
/// presentation that does not even name an identity never reaches lookup.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderCapabilityError {
    /// No durable Kernel/ORS claim row exists under the presented identity.
    #[error("unknown provider claim")]
    UnknownClaim,
    /// Presented attempt does not exactly match the durable claim binding.
    #[error("foreign attempt for the bound claim")]
    ForeignAttempt,
    /// Presented operation does not exactly match the durable claim binding.
    #[error("foreign operation for the bound claim")]
    ForeignOperation,
    /// Presented authority epoch disagrees with the live Kernel epoch.
    #[error("stale authority epoch")]
    StaleEpoch,
    /// Presented route revision disagrees with the current Governor revision.
    #[error("stale route revision")]
    StaleRoute,
    /// Presented capacity revision disagrees with the current Governor revision.
    #[error("stale capacity revision")]
    StaleCapacity,
    /// Presented binding or executable digest disagrees with durable material.
    #[error("binding digest mismatch")]
    DigestMismatch,
    /// Current records show the binding withdrawn or superseded.
    #[error("provider capability revoked")]
    Revoked,
    /// Canonical payload digest is not a lowercase SHA-256 digest.
    #[error("invalid canonical payload digest")]
    InvalidPayloadDigest,
    /// Request or expectation shape is blank, control-bearing, or overlong.
    #[error("malformed provider capability presentation")]
    MalformedRequest,
}

/// Verifies one presented provider-capability proof against durable Kernel
/// authority plus presented Governor currentness.
///
/// The daemon composition loads the claim row (exact `claim_id` key, then
/// the attempt/operation reverse projection) and passes the durable row
/// fields as the `loaded_*` parameters; this function compares the presented
/// request against them and against the live epoch, following the T9-02
/// presented-expectation pattern. The presented binding and executable
/// digests are compared for equality against the loaded durable material —
/// recomputed at claim admission via the claim binding digest, never trusted
/// by value here. Epoch agreement always goes through `is_same_authority`,
/// never through a raw sequence comparison. A stale binding — foreign
/// attempt/operation, advanced epoch, changed route/capacity revision,
/// changed digest, or withdrawn authority — is refused; it needs a new
/// admission, never a local repair.
///
/// # Errors
///
/// Returns the typed [`ProviderCapabilityError`] naming the first failed
/// gate, checked in this order: presentation shape, revocation, exact
/// attempt match, exact operation match, epoch currency (expectation epoch
/// versus the live `live_epoch` parameter), route revision, capacity
/// revision, then binding/executable digest equality.
pub fn verify_provider_capability(
    request: &ProviderCapabilityRequest,
    expectation: &ProviderCapabilityExpectation,
    loaded_claim_attempt_id: &str,
    loaded_claim_operation_id: &str,
    loaded_claim_binding_digest: &str,
    loaded_claim_executable_digest: &str,
    live_epoch: &EpochId,
) -> Result<(), ProviderCapabilityError> {
    request.validate()?;
    expectation.validate()?;
    if expectation.revoked {
        return Err(ProviderCapabilityError::Revoked);
    }
    if request.attempt_id != loaded_claim_attempt_id {
        return Err(ProviderCapabilityError::ForeignAttempt);
    }
    if request.operation_id != loaded_claim_operation_id {
        return Err(ProviderCapabilityError::ForeignOperation);
    }
    if !expectation
        .live_authority_epoch
        .is_same_authority(live_epoch)
    {
        return Err(ProviderCapabilityError::StaleEpoch);
    }
    if request.route_revision != expectation.current_route_revision {
        return Err(ProviderCapabilityError::StaleRoute);
    }
    if request.capacity_revision != expectation.current_capacity_revision {
        return Err(ProviderCapabilityError::StaleCapacity);
    }
    if request.binding_digest != loaded_claim_binding_digest
        || request.executable_binding_digest != loaded_claim_executable_digest
    {
        return Err(ProviderCapabilityError::DigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod provider_capability_tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("test epoch")
    }

    struct Fixture {
        request: ProviderCapabilityRequest,
        expectation: ProviderCapabilityExpectation,
        attempt_id: String,
        operation_id: String,
        binding_digest: String,
        executable_digest: String,
        live_epoch: EpochId,
    }

    fn valid_fixture() -> Fixture {
        Fixture {
            request: ProviderCapabilityRequest {
                claim_id: "claim-t9-04-1".to_owned(),
                attempt_id: "attempt-t9-04-1".to_owned(),
                operation_id: "op-t9-04-1".to_owned(),
                proof_kind: ProviderProofKind::Result,
                proof_ref: "proof-ref-t9-04-1".to_owned(),
                canonical_payload_sha256: "c".repeat(64),
                binding_digest: "b".repeat(64),
                executable_binding_digest: "e".repeat(64),
                route_revision: "route-rev-7".to_owned(),
                capacity_revision: "capacity-rev-3".to_owned(),
            },
            expectation: ProviderCapabilityExpectation {
                current_route_revision: "route-rev-7".to_owned(),
                current_capacity_revision: "capacity-rev-3".to_owned(),
                live_authority_epoch: test_epoch(1),
                revoked: false,
            },
            attempt_id: "attempt-t9-04-1".to_owned(),
            operation_id: "op-t9-04-1".to_owned(),
            binding_digest: "b".repeat(64),
            executable_digest: "e".repeat(64),
            live_epoch: test_epoch(1),
        }
    }

    fn verify(fixture: &Fixture) -> Result<(), ProviderCapabilityError> {
        verify_provider_capability(
            &fixture.request,
            &fixture.expectation,
            fixture.attempt_id.as_str(),
            fixture.operation_id.as_str(),
            fixture.binding_digest.as_str(),
            fixture.executable_digest.as_str(),
            &fixture.live_epoch,
        )
    }

    #[test]
    fn valid_capability_verifies_for_all_seven_proof_kinds() {
        let kinds = [
            ProviderProofKind::Admission,
            ProviderProofKind::Cancellation,
            ProviderProofKind::WorkerFence,
            ProviderProofKind::Reassignment,
            ProviderProofKind::Result,
            ProviderProofKind::UnknownOutcome,
            ProviderProofKind::Binding,
        ];
        for kind in kinds {
            let mut fixture = valid_fixture();
            fixture.request.proof_kind = kind;
            assert_eq!(verify(&fixture), Ok(()), "proof kind {kind:?}");
        }
    }

    #[test]
    fn foreign_attempt_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.request.attempt_id = "attempt-foreign".to_owned();
        assert_eq!(
            verify(&fixture),
            Err(ProviderCapabilityError::ForeignAttempt)
        );
    }

    #[test]
    fn foreign_operation_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.request.operation_id = "op-foreign".to_owned();
        assert_eq!(
            verify(&fixture),
            Err(ProviderCapabilityError::ForeignOperation)
        );
    }

    #[test]
    fn stale_epoch_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.live_epoch = test_epoch(2);
        assert_eq!(verify(&fixture), Err(ProviderCapabilityError::StaleEpoch));
    }

    #[test]
    fn stale_route_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.request.route_revision = "route-rev-8".to_owned();
        assert_eq!(verify(&fixture), Err(ProviderCapabilityError::StaleRoute));
    }

    #[test]
    fn digest_mismatch_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.request.executable_binding_digest = "f".repeat(64);
        assert_eq!(
            verify(&fixture),
            Err(ProviderCapabilityError::DigestMismatch)
        );
    }

    #[test]
    fn revoked_binding_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.expectation.revoked = true;
        assert_eq!(verify(&fixture), Err(ProviderCapabilityError::Revoked));
    }

    #[test]
    fn malformed_payload_digest_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.request.canonical_payload_sha256 = "not-a-digest".to_owned();
        assert_eq!(
            verify(&fixture),
            Err(ProviderCapabilityError::InvalidPayloadDigest)
        );
    }
}
