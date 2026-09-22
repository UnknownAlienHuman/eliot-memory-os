//! Learning-derived candidate screen for Context Compiler retrieval (#1869).
//!
//! I12.24 requires that retrieval verify campaign identity, local-admission
//! status, expiry, closure status, State Fence, and cross-task admission
//! before exposing any overlay/candidate-derived behavior. This module is the
//! retrieval-side enforcement point, driven by the existing
//! [`admit_context`](crate::admit_context) entrypoint:
//!
//! - Learning provenance is *requester-declared* via an explicit sidecar map
//!   (`atom_id -> LearningAtomClaim`). Atoms absent from the map pass through
//!   exactly as before — historical behavior is preserved bit-for-bit, and no
//!   contract vocabulary is invented or reinterpreted.
//! - Every claimed atom must match an owner-verified Governor permit
//!   ([`VerifiedLearningAdmission`], constructible only by the Governor
//!   owner): origin campaign, target task, exact State Fence, overlay and/or
//!   reusable-candidate subject, liveness, non-draft state, and closed+owned
//!   reusable status. Any failure refuses the whole retrieval
//!   ([`ContextError`]) before any value surfaces.
//! - Cross-task rule: the compilation task must equal the permit's admitted
//!   target task. A different task needs its own owner-issued permit —
//!   permits do not stretch, and bare strings never authorize.

use std::collections::BTreeMap;

use eliot_context_contracts::{AdmissionInput, AdmissionResult, ContextError};
use eliot_contracts::{ArtifactId, StateFence, fences_match_exact};
use eliot_governor::VerifiedLearningAdmission;

use crate::admit_context;

/// Requester-declared learning provenance for one atom: the claim, never proof.
///
/// Authentication comes exclusively from matching an owner-verified permit in
/// [`screen_learning_subjects`]. Presence in the claims map is what marks an
/// atom learning-derived; nothing in the atom's own contract fields is
/// reinterpreted as learning authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearningAtomClaim {
    /// Origin campaign the influence was admitted from (must equal the
    /// permit's bound source campaign).
    pub campaign_id: String,
    /// Local overlay subject (must equal the permit-bound overlay when the
    /// permit binds one).
    pub overlay_id: Option<String>,
    /// Reusable candidate subject (must equal the permit-bound candidate
    /// when the permit binds one).
    pub candidate_id: Option<String>,
    /// Closure disposition that closed the reusable candidate (`None` =
    /// unclosed, ineligible).
    pub closure_ref: Option<String>,
    /// Owning decision authority (`None` = ownerless, ineligible).
    pub owner: Option<String>,
    /// Draft deltas are ineligible for retrieval.
    pub draft: bool,
    /// Wall-clock expiry of the local admission as unix seconds (`None` =
    /// no wall-clock bound; epoch/fence/overlay expiry still apply).
    pub expires_at_unix_secs: Option<u64>,
}

impl LearningAtomClaim {
    /// Shape validation only; owner binding happens in the screen.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.campaign_id.trim().is_empty() {
            return Err(ContextError::MissingField("learning.campaign_id"));
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
            return Err(ContextError::MissingField("learning.subject"));
        }
        Ok(())
    }
}

/// One claimed atom with its compilation identity, for screening.
pub struct LearningSubject<'a> {
    pub atom_id: &'a ArtifactId,
    pub binding_task_id: &'a str,
    pub binding_fence: &'a StateFence,
    pub claim: &'a LearningAtomClaim,
}

/// Screen claimed learning atoms against an owner-verified permit.
///
/// Fail-closed: the first violation refuses the whole retrieval. Order:
/// origin campaign, target task, exact fence, overlay subject, candidate
/// subject, expiry, draft state, reusable closure/owner status.
pub fn screen_learning_subjects(
    subjects: &[LearningSubject<'_>],
    verified: &VerifiedLearningAdmission<'_>,
    now_unix_secs: u64,
) -> Result<(), ContextError> {
    if subjects.len() > 4096 {
        return Err(ContextError::Bounds {
            field: "learning.subjects",
        });
    }
    let permit = verified.permit();
    for subject in subjects {
        subject.claim.validate()?;
        if subject.claim.campaign_id != permit.source_campaign_id() {
            return Err(ContextError::IdentityConflict);
        }
        if subject.binding_task_id != permit.target_task_id() {
            return Err(ContextError::IdentityConflict);
        }
        if !fences_match_exact(subject.binding_fence, permit.fence()) {
            return Err(ContextError::InvalidFence);
        }
        match (&subject.claim.overlay_id, permit.overlay_id()) {
            (Some(claimed), Some(bound)) if claimed == bound => {}
            (None, None) => {}
            _ => return Err(ContextError::IdentityConflict),
        }
        match (&subject.claim.candidate_id, permit.candidate_id()) {
            (Some(claimed), Some(bound)) if claimed == bound => {}
            (None, None) => {}
            _ => return Err(ContextError::IdentityConflict),
        }
        if let Some(expires) = subject.claim.expires_at_unix_secs
            && now_unix_secs >= expires
        {
            return Err(ContextError::InvalidField("learning.expires_at"));
        }
        if subject.claim.draft {
            return Err(ContextError::InvalidField("learning.draft"));
        }
        if subject.claim.candidate_id.is_some() {
            if subject
                .claim
                .closure_ref
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ContextError::InvalidField("learning.closure_ref"));
            }
            if subject
                .claim
                .owner
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ContextError::InvalidField("learning.owner"));
            }
        }
    }
    Ok(())
}

/// Governed retrieval entrypoint: screen declared learning atoms against an
/// owner-verified permit, then run the unchanged [`admit_context`] decision.
///
/// Every `claims` entry must name an atom present in the input denominator;
/// atoms absent from `claims` are decided exactly as before. Any screen
/// failure returns `Err` and admits nothing.
pub fn admit_context_with_learning(
    input: &AdmissionInput,
    claims: &BTreeMap<ArtifactId, LearningAtomClaim>,
    verified: &VerifiedLearningAdmission<'_>,
    now_unix_secs: u64,
) -> Result<AdmissionResult, ContextError> {
    if claims.len() > 4096 {
        return Err(ContextError::Bounds {
            field: "learning.claims",
        });
    }
    let candidates: BTreeMap<_, _> = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| (candidate.atom_id.clone(), candidate))
        .collect();
    let mut subjects = Vec::with_capacity(claims.len());
    for (atom_id, claim) in claims {
        let candidate = candidates
            .get(atom_id)
            .ok_or(ContextError::DenominatorMismatch)?;
        subjects.push(LearningSubject {
            atom_id,
            binding_task_id: candidate.binding.task_id.as_str(),
            binding_fence: &candidate.binding.state_fence,
            claim,
        });
    }
    screen_learning_subjects(&subjects, verified, now_unix_secs)?;
    admit_context(input)
}
