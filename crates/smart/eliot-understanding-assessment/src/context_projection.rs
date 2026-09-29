//! Self-model Context projection for the Common Ground and scoped
//! understanding cells (#238).
//!
//! The self-model that these cells assess is delivered to them as Context
//! material: the already-compiled `ActiveUnderstandingView` plus the
//! accepted-source projection, the optional admitted epistemic contribution
//! and the optional experience envelopes, every one of them read by handle
//! from its own owner. This module owns that projection: the owner envelope
//! the assessment reads, the view-atom role resolution taken from the
//! projected view, and the fence gating of every carried envelope against
//! the assessment scope.
//!
//! Ownership, not interpretation. Nothing here re-authors, re-derives or
//! re-grades Context material: the view stays the owner's, the cites stay
//! the caller's, and the assessment decides. `context_projection` exists as
//! its own module so this crate's two cells no longer share one `lib.rs` as
//! the implementation owner of the self-model Context projection.
//!
//! Contract sources: `docs/architecture/A06-07-eliot-self-knowledge.md`
//! (self-model authority boundary) and
//! `docs/architecture/I06-16-scoped-understanding-assessment.md`.

#![forbid(unsafe_code)]

use eliot_context_contracts::{ActiveUnderstandingView, SemanticRole};
use eliot_dreamer_contracts::self_query::AcceptedSourceProjection;
use eliot_epistemic_contracts::ProviderContribution;

use crate::{
    AssessmentError, AssessmentScope, EvidenceCite, ExperienceEvidence, MAX_EVIDENCE_CITES,
    gate_compatible,
};

/// Shared owner-envelope intake for assessment and recheck: the compiled
/// view, the accepted-source projection, the optional admitted
/// contribution, and the optional experience envelopes — all by handle,
/// all sourced ONLY from their owners.
#[derive(Clone, Copy, Debug)]
pub struct OwnerContext<'a> {
    /// Already-compiled understanding view, by handle.
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks.
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Optional experience envelopes for outcome-side evidence.
    pub experience: &'a [ExperienceEvidence<'a>],
}

/// Match an outcome/verifier cite to a compiled view atom: exact atom
/// handle plus source revision plus source digest. Returns the owner
/// semantic role assigned at admission.
pub(crate) fn view_atom_role(
    cite: &EvidenceCite,
    view: &ActiveUnderstandingView,
) -> Option<SemanticRole> {
    view.rendered
        .iter()
        .find(|atom| {
            atom.atom_id == cite.handle
                && atom.source_revision == cite.revision
                && atom.source_digest == cite.digest
        })
        .map(|atom| atom.role)
}

/// Gate every carried fence against the assessment fence.
pub(crate) fn gate_owner(
    owner: &OwnerContext<'_>,
    scope: &AssessmentScope,
) -> Result<(), AssessmentError> {
    owner.view.validate()?;
    owner.sources.validate()?;
    if owner.view.binding.scope_id.as_str() != scope.scope_id {
        return Err(AssessmentError::InvalidField {
            field: "assessment.scope_id",
            reason: "compiled view is bound to a different work scope",
        });
    }
    gate_compatible(
        &owner.view.binding.state_fence,
        &scope.state_fence,
        "assessment.view_fence",
    )?;
    gate_compatible(
        &owner.sources.fence,
        &scope.state_fence,
        "assessment.sources_fence",
    )?;
    if let Some(contribution) = owner.contribution {
        contribution.validate()?;
        gate_compatible(
            &contribution.fence,
            &scope.state_fence,
            "assessment.contribution_fence",
        )?;
    }
    for (index, evidence) in owner.experience.iter().enumerate() {
        evidence.validate()?;
        if index >= MAX_EVIDENCE_CITES {
            return Err(AssessmentError::InvalidField {
                field: "assessment.experience",
                reason: "exceeds bounded length",
            });
        }
        gate_compatible(
            evidence.fence(),
            &scope.state_fence,
            "assessment.experience_fence",
        )?;
    }
    Ok(())
}
