//! Governor-issued learning admission permits and tickets (I12.24, #1869).
//!
//! Owner-issued, digest-bound, fence-checked admission for learning-overlay
//! and reusable-candidate influence. This module follows the established
//! Kernel `DispatchPermit` pattern (`I10-08-02`): the owner mints; the
//! consumer validates against the current fence and epochs before use;
//! missing, expired, or mismatched admission is refused
//! (`STALE_STATE_FENCE`, `STALE_AUTHORITY_EPOCH`) and never refreshed
//! silently.
//!
//! Two shapes, one meaning, split by travel:
//!
//! - [`LearningAdmissionPermit`] is the opaque in-process handle: private
//!   fields, no `Serialize` impl. Only [`issue_learning_admission`] can
//!   construct it, and only after live admission checks against the
//!   [`Governor`] owner. External crates cannot forge one.
//! - [`LearningAdmissionTicket`] (contract type, serializable) is the wire
//!   twin for process boundaries the opaque handle cannot cross
//!   (out-of-process host dispatch, guest envelope). It carries the exact
//!   same bound fields and the exact same digest, minted by
//!   [`issue_learning_ticket`] under the exact same live checks. See the
//!   ticket contract docs for the honest boundary statement: digest
//!   recomputation detects tampering, transplanting, and rotation, while
//!   wall-clock expiry and stale-together replay remain native/contour
//!   responsibilities.
//!
//! [`VerifiedLearningAdmission`] is lifetime-bound to the verified permit
//! and constructible only via [`verify_learning_admission`], which rebinds
//! the permit to the *current* owner epoch/generation and the presented
//! fence. Epoch rotation or fence drift invalidates old permits.
//!
//! The module is stateless: no registry, no second scheduler, no durable
//! writes. Permit lifetime is bounded by epoch/fence/overlay expiry; there is
//! no wall-clock field here (the crate carries no clock dependency) and no
//! one-shot nonce (no registry to consume it). Overlay wall-clock expiry is
//! enforced by the retrieval gate holding the overlay record.

use eliot_context_contracts::{
    LEARNING_TICKET_SCHEMA_VERSION, LearningAdmissionTicket, learning_ticket_digest,
};
use eliot_contracts::{StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Governor, GovernorState};

/// Stable identity of this admission contract.
pub const LEARNING_ADMISSION_CONTRACT: &str = "eliot.governor.learning-admission";
/// Wire revision of the claim shape accepted by issuance.
pub const LEARNING_ADMISSION_SCHEMA_VERSION: u32 = LEARNING_TICKET_SCHEMA_VERSION;

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
    /// Shape validation only; owner checks happen at issuance.
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
    #[error("admission digest does not match live owner state: tampered or stale epoch")]
    DigestMismatch,
    #[error("presented fence does not exactly match the admitted fence")]
    StaleStateFence,
}

/// Owner-issued learning admission permit (opaque in-process handle).
///
/// Wraps the wire [`LearningAdmissionTicket`] in a private field with no
/// `Serialize` impl: a permit is in-process owner evidence, not
/// caller-owned data. All getters delegate to the bound ticket, so the
/// permit digest and any ticket minted for the same claim are identical by
/// construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearningAdmissionPermit {
    ticket: LearningAdmissionTicket,
}

impl LearningAdmissionPermit {
    pub fn source_campaign_id(&self) -> &str {
        &self.ticket.source_campaign_id
    }
    pub fn target_task_id(&self) -> &str {
        &self.ticket.target_task_id
    }
    pub fn fence(&self) -> &StateFence {
        &self.ticket.fence
    }
    pub fn overlay_id(&self) -> Option<&str> {
        self.ticket.overlay_id.as_deref()
    }
    pub fn candidate_id(&self) -> Option<&str> {
        self.ticket.candidate_id.as_deref()
    }
    pub fn scope_ref(&self) -> &str {
        &self.ticket.scope_ref
    }
    pub fn authority_ref(&self) -> &str {
        &self.ticket.authority_ref
    }
    pub fn retention_ref(&self) -> &str {
        &self.ticket.retention_ref
    }
    pub fn evaluator_ref(&self) -> &str {
        &self.ticket.evaluator_ref
    }
    pub fn rollback_ref(&self) -> &str {
        &self.ticket.rollback_ref
    }
    pub fn digest(&self) -> &str {
        &self.ticket.digest
    }
    /// The bound wire ticket. Exposed so owner-side flows can transport the
    /// exact minted artifact across process boundaries; possession of the
    /// ticket alone authorizes nothing without live verification.
    pub fn ticket(&self) -> &LearningAdmissionTicket {
        &self.ticket
    }
}

/// States in which the Governor owner admits learning influence.
fn admitting(state: GovernorState) -> bool {
    matches!(
        state,
        GovernorState::Starting | GovernorState::Ready | GovernorState::Degraded
    )
}

fn trim_owned(value: &str) -> String {
    value.trim().to_string()
}

fn trim_optional(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
}

/// Live owner checks shared by permit and ticket minting.
fn check_live_admission(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<(), LearningAdmissionError> {
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
    Ok(())
}

fn mint_ticket(claim: &LearningAdmissionClaim) -> Result<LearningAdmissionTicket, LearningAdmissionError> {
    let mut ticket = LearningAdmissionTicket {
        schema_version: LEARNING_TICKET_SCHEMA_VERSION,
        source_campaign_id: trim_owned(&claim.source_campaign_id),
        target_task_id: trim_owned(&claim.target_task_id),
        fence: claim.fence.clone(),
        overlay_id: trim_optional(&claim.overlay_id),
        candidate_id: trim_optional(&claim.candidate_id),
        scope_ref: trim_owned(&claim.scope_ref),
        authority_ref: trim_owned(&claim.authority_ref),
        retention_ref: trim_owned(&claim.retention_ref),
        evaluator_ref: trim_owned(&claim.evaluator_ref),
        rollback_ref: trim_owned(&claim.rollback_ref),
        digest: String::new(),
    };
    ticket.digest = learning_ticket_digest(&ticket)
        .map_err(|_| LearningAdmissionError::InvalidFence)?;
    Ok(ticket)
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
    check_live_admission(governor, claim)?;
    Ok(LearningAdmissionPermit {
        ticket: mint_ticket(claim)?,
    })
}

/// Mint the serializable wire twin of a permit after the same live checks.
///
/// The ticket carries the exact bound fields and digest a permit would;
/// transport it across process boundaries and verify with live state plus
/// [`eliot_context_contracts::ticket_fresh_for`] (or re-verify owner-side
/// with [`verify_learning_ticket`]). Minting is owner-only; verification is
/// recomputation any holder performs.
pub fn issue_learning_ticket(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionTicket, LearningAdmissionError> {
    check_live_admission(governor, claim)?;
    mint_ticket(claim)
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
/// Refuses with `DigestMismatch` when the digest does not recompute (tampered
/// fields) or the bound epoch/generation is not live (rotation), and with
/// `StaleStateFence` when only the presented fence drifted. Refuses when the
/// Governor is not admitting.
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
    let recomputed =
        learning_ticket_digest(&permit.ticket).map_err(|_| LearningAdmissionError::InvalidFence)?;
    if recomputed != permit.ticket.digest {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !permit
        .ticket
        .fence
        .authority_epoch
        .is_same_authority(live_epoch)
        || permit.ticket.fence.resource_generation != live_generation
    {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !fences_match_exact(current_fence, &permit.ticket.fence) {
        return Err(LearningAdmissionError::StaleStateFence);
    }
    Ok(VerifiedLearningAdmission { permit })
}

/// Rebind a presented wire ticket to the current owner state and fence.
///
/// Owner-side counterpart of the pure [`eliot_context_contracts::ticket_fresh_for`]
/// check: same verdicts, plus the admitting-state gate. Prefer this
/// wherever a live [`Governor`] is in scope.
pub fn verify_learning_ticket(
    governor: &Governor,
    ticket: &LearningAdmissionTicket,
    current_fence: &StateFence,
) -> Result<(), LearningAdmissionError> {
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    ticket
        .validate()
        .map_err(|_| LearningAdmissionError::InvalidFence)?;
    let recomputed =
        learning_ticket_digest(ticket).map_err(|_| LearningAdmissionError::InvalidFence)?;
    if recomputed != ticket.digest {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    let live_epoch = &governor.config().authority_epoch;
    let live_generation = governor.config().resource_generation;
    if !ticket.fence.authority_epoch.is_same_authority(live_epoch)
        || ticket.fence.resource_generation != live_generation
    {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !fences_match_exact(current_fence, &ticket.fence) {
        return Err(LearningAdmissionError::StaleStateFence);
    }
    Ok(())
}
