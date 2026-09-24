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

use eliot_config::ConfigPolicySnapshot;
use eliot_context_contracts::{
    LEARNING_TICKET_SCHEMA_VERSION, LearningAdmissionTicket, learning_ticket_digest,
};
use eliot_contracts::{StateFence, canonical_json_bytes, fences_match_exact, sha256_hex};
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

/// Request for an owner-bound learning permit. Unlike
/// [`LearningAdmissionClaim`], this request carries no authority-bearing
/// strings. The Governor composition fills scope, authority, retention,
/// evaluator, and rollback from its retained owner projections before minting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningAdmissionRequest {
    /// Source campaign subject identity; issuance derives its authority from
    /// the current owner projection rather than trusting this string.
    pub source_campaign_id: String,
    /// Target task subject identity; the Governor resolves its current owner
    /// record before issuing.
    pub target_task_id: String,
    /// Optional overlay subject identity.
    pub overlay_id: Option<String>,
    /// Optional reusable-candidate subject identity.
    pub candidate_id: Option<String>,
}

impl LearningAdmissionRequest {
    pub fn validate(&self) -> Result<(), LearningAdmissionError> {
        if self.source_campaign_id.trim().is_empty() {
            return Err(LearningAdmissionError::MissingField("source_campaign_id"));
        }
        if self.target_task_id.trim().is_empty() {
            return Err(LearningAdmissionError::MissingField("target_task_id"));
        }
        if self
            .overlay_id
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
            && self
                .candidate_id
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(LearningAdmissionError::NoInfluenceSubject);
        }
        Ok(())
    }
}

/// Policy setting key carrying the Governor-owned active-backlog bound.
pub const LEARNING_BACKLOG_MAX_ACTIVE_SETTING: &str = "meta.learning.backlog.max_active";
/// Policy setting key carrying the Governor-owned value floor.
pub const LEARNING_BACKLOG_MIN_VALUE_SETTING: &str = "meta.learning.backlog.min_value";

/// Bounds derived from the current Policy owner snapshot.
///
/// These values are not daemon defaults. The daemon may install them only
/// after the authenticated Governor has read both settings from the live
/// policy owner and rebound them to the current policy revision.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LearningBoundDecision {
    pub max_active: usize,
    pub min_value: f64,
}

impl LearningBoundDecision {
    /// Parse the two closed policy settings from an admitted policy snapshot.
    pub fn from_policy_snapshot(
        snapshot: &ConfigPolicySnapshot,
    ) -> Result<Self, LearningAdmissionError> {
        let value_for = |key: &str| {
            let setting = snapshot
                .settings
                .iter()
                .find(|setting| setting.key == key)
                .ok_or(LearningAdmissionError::OwnerEvidenceUnavailable(
                    "learning_bounds",
                ))?;
            if setting.owner_ref != snapshot.policy_owner.owner_ref {
                return Err(LearningAdmissionError::OwnerEvidenceMismatch(
                    "learning_bounds_owner",
                ));
            }
            setting
                .value_ref
                .strip_prefix("literal:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or(LearningAdmissionError::OwnerEvidenceUnavailable(
                    "learning_bounds_value",
                ))
        };
        let max_active = value_for(LEARNING_BACKLOG_MAX_ACTIVE_SETTING)
            .and_then(|value| {
                value.parse::<usize>().map_err(|_| {
                    LearningAdmissionError::OwnerEvidenceMismatch("learning_max_active")
                })
            })?;
        if max_active == 0 {
            return Err(LearningAdmissionError::OwnerEvidenceMismatch(
                "learning_max_active",
            ));
        }
        let min_value = value_for(LEARNING_BACKLOG_MIN_VALUE_SETTING)
            .and_then(|value| {
                value.parse::<f64>().map_err(|_| {
                    LearningAdmissionError::OwnerEvidenceMismatch("learning_min_value")
                })
            })?;
        if !min_value.is_finite() || min_value < 0.0 {
            return Err(LearningAdmissionError::OwnerEvidenceMismatch(
                "learning_min_value",
            ));
        }
        Ok(Self {
            max_active,
            min_value,
        })
    }
}

/// Immutable owner evidence carried by a production learning permit.
///
/// The opaque permit keeps this projection private to the owner-issued
/// handle. Every field is copied from a live Task/Canonical/Policy owner
/// record; a requester can name a subject but cannot replace these refs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningOwnerEvidence {
    pub task_ref: String,
    pub recipe_ref: String,
    pub closure_ref: String,
    pub campaign_ref: String,
    pub overlay_ref: String,
    pub cross_task_admission_ref: Option<String>,
}

impl LearningOwnerEvidence {
    fn validate(&self) -> Result<(), LearningAdmissionError> {
        for (field, value) in [
            ("task_ref", &self.task_ref),
            ("recipe_ref", &self.recipe_ref),
            ("closure_ref", &self.closure_ref),
            ("campaign_ref", &self.campaign_ref),
            ("overlay_ref", &self.overlay_ref),
        ] {
            if value.trim().is_empty() {
                return Err(LearningAdmissionError::OwnerEvidenceUnavailable(field));
            }
        }
        if self
            .cross_task_admission_ref
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(LearningAdmissionError::OwnerEvidenceUnavailable(
                "cross_task_admission_ref",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Result<String, LearningAdmissionError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|_| LearningAdmissionError::InvalidFence)?;
        Ok(sha256_hex(&bytes))
    }

    #[must_use]
    pub fn task_ref(&self) -> &str { &self.task_ref }
    #[must_use]
    pub fn recipe_ref(&self) -> &str { &self.recipe_ref }
    #[must_use]
    pub fn closure_ref(&self) -> &str { &self.closure_ref }
    #[must_use]
    pub fn campaign_ref(&self) -> &str { &self.campaign_ref }
    #[must_use]
    pub fn overlay_ref(&self) -> &str { &self.overlay_ref }
    #[must_use]
    pub fn cross_task_admission_ref(&self) -> Option<&str> {
        self.cross_task_admission_ref.as_deref()
    }
}

/// Owner-issued cross-task receipt.
///
/// This is distinct from the ordinary learning permit: it is minted only by
/// the live Governor composition after the target task, plan, policy,
/// evaluator, and rollback projections have been re-read. The receipt is
/// still candidate evidence; it grants no task, policy, or activation
/// authority by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossTaskAdmissionReceipt {
    pub admission_id: String,
    pub permit_digest: String,
    pub source_campaign_id: String,
    pub target_task_id: String,
    pub scope_ref: String,
    pub authority_ref: String,
    pub retention_ref: String,
    pub evaluator_ref: String,
    pub rollback_ref: String,
    pub owner_evidence_digest: String,
    pub digest: String,
}

impl CrossTaskAdmissionReceipt {
    pub(crate) fn issue(
        verified: &VerifiedLearningAdmission<'_>,
        owner_evidence: &LearningOwnerEvidence,
    ) -> Result<Self, LearningAdmissionError> {
        let permit = verified.permit();
        let owner_evidence_digest = owner_evidence.digest()?;
        let admission_id = format!("governor-cross-task:{}", permit.digest());
        let mut receipt = Self {
            admission_id,
            permit_digest: permit.digest().to_owned(),
            source_campaign_id: permit.source_campaign_id().to_owned(),
            target_task_id: permit.target_task_id().to_owned(),
            scope_ref: permit.scope_ref().to_owned(),
            authority_ref: permit.authority_ref().to_owned(),
            retention_ref: permit.retention_ref().to_owned(),
            evaluator_ref: permit.evaluator_ref().to_owned(),
            rollback_ref: permit.rollback_ref().to_owned(),
            owner_evidence_digest,
            digest: String::new(),
        };
        receipt.digest = receipt.compute_digest()?;
        Ok(receipt)
    }

    fn compute_digest(&self) -> Result<String, LearningAdmissionError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|_| LearningAdmissionError::InvalidFence)?;
        Ok(sha256_hex(&bytes))
    }

    #[must_use]
    pub fn validate(&self) -> bool {
        self.compute_digest().is_ok_and(|digest| digest == self.digest)
    }
}

/// Owner projection used to bind a learning permit to the current canonical
/// task, plan, policy, and evaluator records.
///
/// The fields are private so a requester cannot construct or replace them.
/// The Governor composition is the only constructor and refreshes the
/// projection from its single retained owner set on every issuance or
/// verification.
#[derive(Clone, Debug, PartialEq)]
pub struct LearningAdmissionOwnerRecord {
    state_fence: StateFence,
    scope_ref: String,
    authority_ref: String,
    retention_ref: String,
    evaluator_ref: String,
    rollback_ref: String,
    policy_revision: u64,
    bounds: LearningBoundDecision,
    owner_evidence: LearningOwnerEvidence,
}

impl LearningAdmissionOwnerRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_owner_projection(
        state_fence: StateFence,
        scope_ref: String,
        authority_ref: String,
        retention_ref: String,
        evaluator_ref: String,
        rollback_ref: String,
        policy_revision: u64,
        bounds: LearningBoundDecision,
        owner_evidence: LearningOwnerEvidence,
    ) -> Result<Self, LearningAdmissionError> {
        let record = Self {
            state_fence,
            scope_ref,
            authority_ref,
            retention_ref,
            evaluator_ref,
            rollback_ref,
            policy_revision,
            bounds,
            owner_evidence,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), LearningAdmissionError> {
        self.state_fence
            .validate()
            .map_err(|_| LearningAdmissionError::InvalidFence)?;
        for (field, value) in [
            ("scope_ref", &self.scope_ref),
            ("authority_ref", &self.authority_ref),
            ("retention_ref", &self.retention_ref),
            ("evaluator_ref", &self.evaluator_ref),
            ("rollback_ref", &self.rollback_ref),
        ] {
            if value.trim().is_empty() {
                return Err(LearningAdmissionError::OwnerEvidenceUnavailable(field));
            }
        }
        if self.policy_revision == 0 {
            return Err(LearningAdmissionError::OwnerEvidenceUnavailable(
                "policy_revision",
            ));
        }
        if self.bounds.max_active == 0
            || !self.bounds.min_value.is_finite()
            || self.bounds.min_value < 0.0
        {
            return Err(LearningAdmissionError::OwnerEvidenceMismatch(
                "learning_bounds",
            ));
        }
        self.owner_evidence.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    #[must_use]
    pub fn scope_ref(&self) -> &str {
        &self.scope_ref
    }

    #[must_use]
    pub fn authority_ref(&self) -> &str {
        &self.authority_ref
    }

    #[must_use]
    pub fn retention_ref(&self) -> &str {
        &self.retention_ref
    }

    #[must_use]
    pub fn evaluator_ref(&self) -> &str {
        &self.evaluator_ref
    }

    #[must_use]
    pub fn rollback_ref(&self) -> &str {
        &self.rollback_ref
    }

    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    #[must_use]
    pub const fn bounds(&self) -> LearningBoundDecision {
        self.bounds
    }

    #[must_use]
    pub const fn owner_evidence(&self) -> &LearningOwnerEvidence {
        &self.owner_evidence
    }

    pub(crate) fn claim_for(
        &self,
        request: &LearningAdmissionRequest,
        fence: &StateFence,
    ) -> Result<LearningAdmissionClaim, LearningAdmissionError> {
        request.validate()?;
        if !fences_match_exact(fence, &self.state_fence) {
            return Err(LearningAdmissionError::StaleStateFence);
        }
        Ok(LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: request.source_campaign_id.clone(),
            target_task_id: request.target_task_id.clone(),
            fence: self.state_fence.clone(),
            overlay_id: request.overlay_id.clone(),
            candidate_id: request.candidate_id.clone(),
            scope_ref: self.scope_ref.clone(),
            authority_ref: self.authority_ref.clone(),
            retention_ref: self.retention_ref.clone(),
            evaluator_ref: self.evaluator_ref.clone(),
            rollback_ref: self.rollback_ref.clone(),
        })
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
    #[error("owner evidence required for learning admission is unavailable: {0}")]
    OwnerEvidenceUnavailable(&'static str),
    #[error("owner evidence does not match the learning admission binding: {0}")]
    OwnerEvidenceMismatch(&'static str),
    #[error("learning admission target task identity is invalid")]
    InvalidTargetTask,
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
    owner_evidence: Option<LearningOwnerEvidence>,
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

    /// Owner evidence attached by the live composition path.
    ///
    /// Generic claim issuance remains available for low-level contract
    /// proofs, but production daemon admission must carry this projection.
    #[must_use]
    pub fn owner_evidence(&self) -> Option<&LearningOwnerEvidence> {
        self.owner_evidence.as_ref()
    }

    /// Deterministic identity a Governor-issued cross-task receipt must use.
    #[must_use]
    pub fn cross_task_admission_id(&self) -> String {
        format!("governor-cross-task:{}", self.digest())
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
        owner_evidence: None,
    })
}

/// Mint a production permit with the live owner evidence projection attached.
///
/// This is crate-visible so only [`crate::GovernorComposition`] can attach the
/// task/plan/policy/recipe/closure/campaign projection. The public generic
/// issuer above remains a shape/epoch contract primitive, not a daemon root.
pub(crate) fn issue_learning_admission_with_owner_evidence(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
    owner_evidence: &LearningOwnerEvidence,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    owner_evidence.validate()?;
    check_live_admission(governor, claim)?;
    Ok(LearningAdmissionPermit {
        ticket: mint_ticket(claim)?,
        owner_evidence: Some(owner_evidence.clone()),
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
