//! Governor-issued learning admission permits (I12.24, #1869).
//!
//! Owner-issued, digest-bound, fence-checked permits for learning-overlay and
//! reusable-candidate influence. This module follows the established
//! Kernel `DispatchPermit` pattern (`I10-08-02`): the owner mints; the
//! consumer validates against the current fence and epochs before use;
//! missing, expired, or mismatched permits are refused (`STALE_STATE_FENCE`,
//! `STALE_AUTHORITY_EPOCH`) and never refreshed silently.
//!
//! Authentication boundary (deliberate):
//! - [`LearningAdmissionClaim`] is requester-supplied and serializable: it is
//!   the *request*, never proof.
//! - [`LearningAdmissionPermit`] has private fields and no `Serialize` impl:
//!   only [`issue_learning_admission`] can construct it, and only after live
//!   admission checks against the [`Governor`] owner. External crates cannot
//!   forge one; they cannot even name its digest preimage fields.
//! - [`VerifiedLearningAdmission`] is lifetime-bound to the verified permit
//!   and constructible only via [`verify_learning_admission`], which rebinds
//!   the permit to the *current* owner epoch/generation and the presented
//!   fence. Epoch rotation or fence drift invalidates old permits.
//!
//! The module is stateless: no registry, no second scheduler, no durable
//! writes. Permit lifetime is bounded by epoch/fence/overlay expiry; there is
//! no wall-clock field here (the crate carries no clock dependency) and no
//! one-shot nonce (no registry to consume it). Overlay wall-clock expiry is
//! enforced by the retrieval gate holding the overlay record.

use blake3::Hasher;
use eliot_contracts::{EpochId, ResourceGeneration, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Governor, GovernorState};

/// Stable identity of this admission contract.
pub const LEARNING_ADMISSION_CONTRACT: &str = "eliot.governor.learning-admission";
/// Wire revision of the claim shape accepted by [`issue_learning_admission`].
pub const LEARNING_ADMISSION_SCHEMA_VERSION: u32 = 1;
/// Digest domain separator for permit binding (see APPENDIX-P: canonical
/// hashes use normalized versioned serialization).
const PERMIT_DIGEST_DOMAIN: &str = "eliot.governor.learning-admission.permit.v1";

/// Requester-supplied learning admission claim: the request, never proof.
///
/// Binds the source campaign, the target task, the exact [`StateFence`] the
/// influence was admitted under, at least one influence subject (overlay
/// and/or reusable candidate), and the revalidation refs from I12.24 (scope,
/// authority, retention, evaluator, rollback).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningAdmissionClaim {
    pub schema_version: u32,
    pub source_campaign_id: String,
    pub target_task_id: String,
    pub fence: StateFence,
    pub overlay_id: Option<String>,
    pub candidate_id: Option<String>,
    pub scope_ref: String,
    pub authority_ref: String,
    pub retention_ref: String,
    pub evaluator_ref: String,
    pub rollback_ref: String,
}

impl LearningAdmissionClaim {
    /// Shape validation only; owner checks happen in
    /// [`issue_learning_admission`].
    pub fn validate(&self) -> Result<(), LearningAdmissionError> {
        if self.schema_version != LEARNING_ADMISSION_SCHEMA_VERSION {
            return Err(LearningAdmissionError::UnsupportedSchema {
                version: self.schema_version,
            });
        }
        for (field, value) in [
            ("source_campaign_id", &self.source_campaign_id),
            ("target_task_id", &self.target_task_id),
            ("scope_ref", &self.scope_ref),
            ("authority_ref", &self.authority_ref),
            ("retention_ref", &self.retention_ref),
            ("evaluator_ref", &self.evaluator_ref),
            ("rollback_ref", &self.rollback_ref),
        ] {
            if value.trim().is_empty() {
                return Err(LearningAdmissionError::MissingField(field));
            }
        }
        if self
            .overlay_id
            .as_ref()
            .is_none_or(|id| id.trim().is_empty())
            && self
                .candidate_id
                .as_ref()
                .is_none_or(|id| id.trim().is_empty())
        {
            return Err(LearningAdmissionError::NoInfluenceSubject);
        }
        self.fence
            .validate()
            .map_err(|_| LearningAdmissionError::InvalidFence)?;
        Ok(())
    }
}

/// Fail-closed learning admission errors. Stale epoch, stale fence, and
/// digest mismatch are distinct refusals; none refreshes silently.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LearningAdmissionError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("unsupported claim schema version: {version}")]
    UnsupportedSchema { version: u32 },
    #[error("claim binds neither an overlay nor a reusable candidate")]
    NoInfluenceSubject,
    #[error("claim fence is invalid")]
    InvalidFence,
    #[error("governor is not in an admitting state")]
    GovernorNotAdmitting,
    #[error("claim epoch is not the live authority epoch")]
    StaleAuthorityEpoch,
    #[error("claim generation is not the live resource generation")]
    GenerationMismatch,
    #[error("permit digest does not match live owner state: tampered or stale epoch")]
    DigestMismatch,
    #[error("presented fence does not exactly match the admitted fence")]
    StaleStateFence,
}

/// Owner-issued learning admission permit.
///
/// Fields are private and there is intentionally no `Serialize` impl: a
/// permit is in-process owner evidence, not caller-owned data. The digest
/// binds the live authority epoch, the live resource generation, the exact
/// fence, and every claim field, so any tampering or epoch rotation
/// invalidates it at [`verify_learning_admission`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearningAdmissionPermit {
    source_campaign_id: String,
    target_task_id: String,
    fence: StateFence,
    overlay_id: Option<String>,
    candidate_id: Option<String>,
    scope_ref: String,
    authority_ref: String,
    retention_ref: String,
    evaluator_ref: String,
    rollback_ref: String,
    digest: String,
}

impl LearningAdmissionPermit {
    pub fn source_campaign_id(&self) -> &str {
        &self.source_campaign_id
    }
    pub fn target_task_id(&self) -> &str {
        &self.target_task_id
    }
    pub fn fence(&self) -> &StateFence {
        &self.fence
    }
    pub fn overlay_id(&self) -> Option<&str> {
        self.overlay_id.as_deref()
    }
    pub fn candidate_id(&self) -> Option<&str> {
        self.candidate_id.as_deref()
    }
    pub fn scope_ref(&self) -> &str {
        &self.scope_ref
    }
    pub fn authority_ref(&self) -> &str {
        &self.authority_ref
    }
    pub fn retention_ref(&self) -> &str {
        &self.retention_ref
    }
    pub fn evaluator_ref(&self) -> &str {
        &self.evaluator_ref
    }
    pub fn rollback_ref(&self) -> &str {
        &self.rollback_ref
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// States in which the Governor owner admits learning influence.
fn admitting(state: GovernorState) -> bool {
    matches!(
        state,
        GovernorState::Starting | GovernorState::Ready | GovernorState::Degraded
    )
}

fn permit_digest(
    epoch: &EpochId,
    generation: ResourceGeneration,
    claim: &LearningAdmissionClaim,
) -> String {
    let mut hasher = Hasher::new();
    hasher.update(PERMIT_DIGEST_DOMAIN.as_bytes());
    hasher.update(b"\0");
    hasher.update(claim.fence.authority_epoch.lineage_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(&claim.fence.authority_epoch.sequence.get().to_le_bytes());
    hasher.update(b"\0");
    hasher.update(epoch.lineage_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(&epoch.sequence.get().to_le_bytes());
    hasher.update(b"\0");
    hasher.update(&generation.value().to_le_bytes());
    hasher.update(b"\0");
    hasher.update(&claim.fence.resource_generation.value().to_le_bytes());
    hasher.update(b"\0");
    for part in [
        claim.source_campaign_id.as_str(),
        claim.target_task_id.as_str(),
        claim.overlay_id.as_deref().unwrap_or(""),
        claim.candidate_id.as_deref().unwrap_or(""),
        claim.scope_ref.as_str(),
        claim.authority_ref.as_str(),
        claim.retention_ref.as_str(),
        claim.evaluator_ref.as_str(),
        claim.rollback_ref.as_str(),
    ] {
        hasher.update(part.trim().as_bytes());
        hasher.update(b"\0");
    }
    for revision in [
        claim.fence.task_revision.map(|value| value.value()),
        claim.fence.policy_revision.map(|value| value.value()),
        claim.fence.integration_revision.map(|value| value.value()),
    ] {
        match revision {
            Some(value) => {
                hasher.update(&value.to_le_bytes());
            }
            None => {
                hasher.update(b"none");
            }
        }
        hasher.update(b"\0");
    }
    hasher.finalize().to_hex().to_string()
}

/// Mint a learning admission permit after live owner checks.
///
/// Refuses unless the Governor is admitting, the claim fence carries the
/// live authority epoch and generation, and the claim shape validates. The
/// returned permit is bound to the live epoch: rotation invalidates it.
pub fn issue_learning_admission(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    claim.validate()?;
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    let live_epoch = &governor.config().authority_epoch;
    let live_generation = governor.config().resource_generation;
    if !claim.fence.authority_epoch.is_same_authority(live_epoch) {
        return Err(LearningAdmissionError::StaleAuthorityEpoch);
    }
    if claim.fence.resource_generation != live_generation {
        return Err(LearningAdmissionError::GenerationMismatch);
    }
    let digest = permit_digest(live_epoch, live_generation, claim);
    Ok(LearningAdmissionPermit {
        source_campaign_id: claim.source_campaign_id.trim().to_string(),
        target_task_id: claim.target_task_id.trim().to_string(),
        fence: claim.fence.clone(),
        overlay_id: claim
            .overlay_id
            .clone()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty()),
        candidate_id: claim
            .candidate_id
            .clone()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty()),
        scope_ref: claim.scope_ref.trim().to_string(),
        authority_ref: claim.authority_ref.trim().to_string(),
        retention_ref: claim.retention_ref.trim().to_string(),
        evaluator_ref: claim.evaluator_ref.trim().to_string(),
        rollback_ref: claim.rollback_ref.trim().to_string(),
        digest,
    })
}

/// Lifetime-bound verified handle: proof that `permit` was re-bound to the
/// current owner state and `current_fence`.
///
/// The private field means only this module constructs it, and only via
/// [`verify_learning_admission`]. It borrows the permit: verification cannot
/// outlive the evidence it verified. No `Serialize` impl by design.
#[derive(Debug)]
pub struct VerifiedLearningAdmission<'a> {
    permit: &'a LearningAdmissionPermit,
}

impl<'a> VerifiedLearningAdmission<'a> {
    /// The verified permit. All bound values read through here are
    /// owner-authenticated for the fence verified alongside.
    pub fn permit(&self) -> &'a LearningAdmissionPermit {
        self.permit
    }
}

/// Rebind a presented permit to the current owner state and fence.
///
/// Refuses when the Governor is not admitting, when the digest does not
/// recompute under the *live* epoch/generation (tampered fields or rotated
/// epoch), or when `current_fence` does not exactly match the admitted
/// fence (drifted task/policy/integration revision or epoch).
pub fn verify_learning_admission<'a>(
    governor: &Governor,
    permit: &'a LearningAdmissionPermit,
    current_fence: &StateFence,
) -> Result<VerifiedLearningAdmission<'a>, LearningAdmissionError> {
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    let live_epoch = &governor.config().authority_epoch;
    let live_generation = governor.config().resource_generation;
    let claim = LearningAdmissionClaim {
        schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: permit.source_campaign_id.clone(),
        target_task_id: permit.target_task_id.clone(),
        fence: permit.fence.clone(),
        overlay_id: permit.overlay_id.clone(),
        candidate_id: permit.candidate_id.clone(),
        scope_ref: permit.scope_ref.clone(),
        authority_ref: permit.authority_ref.clone(),
        retention_ref: permit.retention_ref.clone(),
        evaluator_ref: permit.evaluator_ref.clone(),
        rollback_ref: permit.rollback_ref.clone(),
    };
    if permit_digest(live_epoch, live_generation, &claim) != permit.digest {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !fences_match_exact(current_fence, &permit.fence) {
        return Err(LearningAdmissionError::StaleStateFence);
    }
    Ok(VerifiedLearningAdmission { permit })
}
