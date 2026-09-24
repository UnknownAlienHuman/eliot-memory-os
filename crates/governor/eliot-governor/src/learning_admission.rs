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
    LEARNING_RECORD_TICKET_SCHEMA_VERSION, LEARNING_TICKET_SCHEMA_VERSION, LearningAdmissionTicket,
    LearningRecordAdmissionTicket, learning_record_ticket_digest, learning_ticket_digest,
};
use eliot_contracts::{StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Governor, GovernorState};
use eliot_store_api::LearningRecordIdentity;

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

/// Exact record binding attached to a behavioral learning admission.
///
/// The older [`LearningAdmissionClaim`] remains available for context
/// admission compatibility. Behavioral learning effects must use this binding
/// and the record-bound issuance/verification functions below; a caller-owned
/// boolean or an unbound influence ticket can never make a record effective.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningRecordAdmissionBinding {
    /// Closed learning record kind.
    pub record_kind: String,
    /// Exact record handle.
    pub record_handle: String,
    /// Exact immutable record digest.
    pub record_digest: String,
    /// Exact canonical scope identity.
    pub scope_id: String,
    /// Exact State Fence under which the record may affect behavior.
    pub state_fence: StateFence,
    /// Absolute expiry deadline in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl LearningRecordAdmissionBinding {
    /// Build a binding from the canonical store identity.
    #[must_use]
    pub fn from_identity(identity: &LearningRecordIdentity) -> Self {
        Self {
            record_kind: identity.record_kind.as_str().to_owned(),
            record_handle: identity.handle.clone(),
            record_digest: identity.record_digest.clone(),
            scope_id: identity.scope_id.clone(),
            state_fence: identity.state_fence.clone(),
            expires_at_unix_ms: identity.expires_at_unix_ms,
        }
    }

    fn validate(&self) -> Result<(), LearningAdmissionError> {
        if !matches!(
            self.record_kind.as_str(),
            "delta" | "overlay" | "closure" | "activation_receipt" | "candidate" | "view_ref"
        ) {
            return Err(LearningAdmissionError::RecordIdentityMismatch);
        }
        for (field, value) in [
            ("record_handle", &self.record_handle),
            ("record_digest", &self.record_digest),
            ("scope_id", &self.scope_id),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(LearningAdmissionError::MissingField(field));
            }
        }
        if self.record_digest.len() != 64
            || !self
                .record_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(LearningAdmissionError::RecordIdentityMismatch);
        }
        self.state_fence
            .validate()
            .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
        if self.expires_at_unix_ms == 0 {
            return Err(LearningAdmissionError::MissingField("expires_at_unix_ms"));
        }
        Ok(())
    }
}

/// Claim for an exact learning-record behavioral admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningRecordAdmissionClaim {
    /// Existing campaign/task/owner admission claim.
    pub admission: LearningAdmissionClaim,
    /// Exact record binding required for behavioral effect.
    pub record: LearningRecordAdmissionBinding,
}

impl LearningRecordAdmissionClaim {
    /// Validate both the owner claim and exact record binding.
    pub fn validate(&self) -> Result<(), LearningAdmissionError> {
        self.admission.validate()?;
        self.record.validate()
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
    #[error("learning admission has no exact record binding")]
    MissingRecordBinding,
    #[error("learning admission record identity does not match the committed record")]
    RecordIdentityMismatch,
    #[error("learning admission has expired")]
    AdmissionExpired,
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
    record_binding: Option<LearningRecordAdmissionBinding>,
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

    /// Exact record binding, when this permit was issued for behavioral
    /// learning rather than the legacy context-only contour.
    pub fn record_binding(&self) -> Option<&LearningRecordAdmissionBinding> {
        self.record_binding.as_ref()
    }

    /// Mint the exact wire twin from this already owner-issued permit.
    pub fn record_ticket(&self) -> Result<LearningRecordAdmissionTicket, LearningAdmissionError> {
        let binding = self
            .record_binding()
            .ok_or(LearningAdmissionError::MissingRecordBinding)?;
        if binding.state_fence != *self.fence() {
            return Err(LearningAdmissionError::RecordIdentityMismatch);
        }
        let mut ticket = LearningRecordAdmissionTicket {
            schema_version: LEARNING_RECORD_TICKET_SCHEMA_VERSION,
            source_campaign_id: self.source_campaign_id().to_owned(),
            target_task_id: self.target_task_id().to_owned(),
            fence: self.fence().clone(),
            record_kind: binding.record_kind.clone(),
            record_handle: binding.record_handle.clone(),
            record_digest: binding.record_digest.clone(),
            scope_id: binding.scope_id.clone(),
            expires_at_unix_ms: binding.expires_at_unix_ms,
            authority_ref: self.authority_ref().to_owned(),
            retention_ref: self.retention_ref().to_owned(),
            evaluator_ref: self.evaluator_ref().to_owned(),
            rollback_ref: self.rollback_ref().to_owned(),
            digest: String::new(),
        };
        ticket.digest = learning_record_ticket_digest(&ticket)
            .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
        Ok(ticket)
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

fn trim_optional(value: Option<&String>) -> Option<String> {
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

fn mint_ticket(
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionTicket, LearningAdmissionError> {
    let mut ticket = LearningAdmissionTicket {
        schema_version: LEARNING_TICKET_SCHEMA_VERSION,
        source_campaign_id: trim_owned(&claim.source_campaign_id),
        target_task_id: trim_owned(&claim.target_task_id),
        fence: claim.fence.clone(),
        overlay_id: trim_optional(claim.overlay_id.as_ref()),
        candidate_id: trim_optional(claim.candidate_id.as_ref()),
        scope_ref: trim_owned(&claim.scope_ref),
        authority_ref: trim_owned(&claim.authority_ref),
        retention_ref: trim_owned(&claim.retention_ref),
        evaluator_ref: trim_owned(&claim.evaluator_ref),
        rollback_ref: trim_owned(&claim.rollback_ref),
        digest: String::new(),
    };
    ticket.digest =
        learning_ticket_digest(&ticket).map_err(|_| LearningAdmissionError::InvalidFence)?;
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
        record_binding: None,
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

/// Mint an owner-issued permit bound to one exact learning record identity.
///
/// This is the only issuance path accepted by behavioral learning
/// effectiveness. The opaque permit carries the binding privately; callers
/// cannot replace it after issuance.
pub fn issue_learning_record_admission(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    check_live_admission(governor, &claim.admission)?;
    claim.validate()?;
    if claim.record.state_fence != claim.admission.fence {
        return Err(LearningAdmissionError::RecordIdentityMismatch);
    }
    Ok(LearningAdmissionPermit {
        ticket: mint_ticket(&claim.admission)?,
        record_binding: Some(claim.record.clone()),
    })
}

/// Mint the serializable exact-record twin of a record-bound permit.
pub fn issue_learning_record_ticket(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
) -> Result<LearningRecordAdmissionTicket, LearningAdmissionError> {
    check_live_admission(governor, &claim.admission)?;
    claim.validate()?;
    if claim.record.state_fence != claim.admission.fence {
        return Err(LearningAdmissionError::RecordIdentityMismatch);
    }
    let mut ticket = LearningRecordAdmissionTicket {
        schema_version: LEARNING_RECORD_TICKET_SCHEMA_VERSION,
        source_campaign_id: trim_owned(&claim.admission.source_campaign_id),
        target_task_id: trim_owned(&claim.admission.target_task_id),
        fence: claim.admission.fence.clone(),
        record_kind: claim.record.record_kind.clone(),
        record_handle: claim.record.record_handle.clone(),
        record_digest: claim.record.record_digest.clone(),
        scope_id: claim.record.scope_id.clone(),
        expires_at_unix_ms: claim.record.expires_at_unix_ms,
        authority_ref: trim_owned(&claim.admission.authority_ref),
        retention_ref: trim_owned(&claim.admission.retention_ref),
        evaluator_ref: trim_owned(&claim.admission.evaluator_ref),
        rollback_ref: trim_owned(&claim.admission.rollback_ref),
        digest: String::new(),
    };
    ticket.digest = learning_record_ticket_digest(&ticket)
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    Ok(ticket)
}

/// Rebind a record-bound permit to the current owner and exact record.
///
/// This check is intentionally separate from legacy influence verification:
/// a valid owner permit without the exact record binding is not sufficient
/// for behavioral effect.
pub fn verify_learning_record_admission<'a>(
    governor: &Governor,
    permit: &'a LearningAdmissionPermit,
    current_fence: &StateFence,
    identity: &LearningRecordIdentity,
    now_unix_ms: u64,
) -> Result<VerifiedLearningAdmission<'a>, LearningAdmissionError> {
    identity
        .validate()
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    let binding = permit
        .record_binding()
        .ok_or(LearningAdmissionError::MissingRecordBinding)?;
    let expected = LearningRecordAdmissionBinding::from_identity(identity);
    if binding != &expected {
        return Err(LearningAdmissionError::RecordIdentityMismatch);
    }
    if binding.expires_at_unix_ms <= now_unix_ms {
        return Err(LearningAdmissionError::AdmissionExpired);
    }
    verify_learning_admission(governor, permit, current_fence)
}

/// Verify the exact wire record ticket against live owner state and time.
pub fn verify_learning_record_ticket(
    governor: &Governor,
    ticket: &LearningRecordAdmissionTicket,
    current_fence: &StateFence,
    identity: &LearningRecordIdentity,
    now_unix_ms: u64,
) -> Result<(), LearningAdmissionError> {
    identity
        .validate()
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    if ticket.record_kind != identity.record_kind.as_str()
        || ticket.record_handle != identity.handle
        || ticket.record_digest != identity.record_digest
        || ticket.scope_id != identity.scope_id
        || ticket.expires_at_unix_ms != identity.expires_at_unix_ms
        || ticket.fence != identity.state_fence
    {
        return Err(LearningAdmissionError::RecordIdentityMismatch);
    }
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    ticket
        .validate()
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    let recomputed = learning_record_ticket_digest(ticket)
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
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
    if ticket.expires_at_unix_ms <= now_unix_ms {
        return Err(LearningAdmissionError::AdmissionExpired);
    }
    Ok(())
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
