//! Inert closure and external-promotion handoff contracts.

use eliot_contracts::{ArtifactId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    assessment::AssessmentDimension,
    error::LearningContractError,
    identity::{
        ContractBinding, OverlayId, OwnerId, ProofCeiling, TargetId, WorkScopeId,
        digest_without_field, validate_digest,
    },
};

/// Decision class requested from an external canonical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalDecisionClass {
    /// Request external promotion review.
    PromotionReview,
    /// Request external closure review.
    ClosureReview,
    /// Request rollback/disable review.
    RollbackReview,
    /// Request reopen/reconciliation review.
    ReopenReview,
}

/// One owner proof required by the external decision owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerProof {
    /// Semantic owner identity.
    pub owner: OwnerId,
    /// Owner-issued receipt identity.
    pub receipt: ArtifactId,
    /// Scope retained on the proof itself.
    pub scope: WorkScopeId,
    /// Fence retained on the proof itself.
    pub state_fence: StateFence,
    /// Evidence handles supporting the proof.
    pub evidence: Vec<ArtifactId>,
    /// Proof cannot exceed a candidate artifact.
    pub proof_ceiling: ProofCeiling,
}

impl OwnerProof {
    /// Validate owner evidence and exact scope/fence compatibility.
    pub fn validate_against(&self, binding: &ContractBinding) -> Result<(), LearningContractError> {
        self.owner.validate()?;
        if self.receipt.as_str().trim().is_empty() || self.scope.as_str() != binding.scope.as_str()
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "owner_proof.scope",
            });
        }
        if self.state_fence != binding.state_fence {
            return Err(LearningContractError::ScopeMismatch {
                field: "owner_proof.state_fence",
            });
        }
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(LearningContractError::CandidateCeiling);
        }
        if self.evidence.is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "owner_proof.evidence",
            });
        }
        ensure_unique(
            self.evidence.iter().map(ArtifactId::as_str),
            "owner_proof.evidence",
        )
    }
}

/// Candidate-only handoff; it cannot accept, promote, activate or close itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClosureHandoff {
    /// Shared target/task/scope/fence binding.
    pub binding: ContractBinding,
    /// Target whose candidate is under review.
    pub target: TargetId,
    /// Delta lineage.
    pub delta_id: ArtifactId,
    /// Overlay lineage.
    pub overlay_id: OverlayId,
    /// Assessment lineage.
    pub assessment_id: ArtifactId,
    /// Assessment digest used by the handoff.
    pub assessment_digest: String,
    /// Required owner-proof denominator.
    pub required_owner_proofs: Vec<OwnerProof>,
    /// Unresolved debts, failures, harms, unknowns and conflicts.
    pub debts: Vec<AssessmentDimension>,
    /// Rollback/disable/reopen references.
    pub rollback_refs: Vec<ArtifactId>,
    /// External promotion/closure references.
    pub external_promotion_refs: Vec<ArtifactId>,
    /// Requested decision class, without recording its result.
    pub requested_decision: ExternalDecisionClass,
    /// Canonical handoff digest, excluding this field.
    pub canonical_digest: String,
}

impl ClosureHandoff {
    /// Validate required owner proofs and keep the handoff inert.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        crate::identity::validate_external_id(self.target.as_str(), "closure.target")?;
        for id in [&self.delta_id, &self.assessment_id] {
            if id.as_str().trim().is_empty() {
                return Err(LearningContractError::Missing {
                    field: "closure.lineage",
                });
            }
        }
        self.overlay_id.validate()?;
        validate_digest(&self.assessment_digest, "closure.assessment_digest")?;
        if self.required_owner_proofs.is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "closure.required_owner_proofs",
            });
        }
        for proof in &self.required_owner_proofs {
            proof.validate_against(&self.binding)?;
        }
        ensure_unique(
            self.required_owner_proofs.iter().map(|p| p.owner.as_str()),
            "closure.required_owner_proofs",
        )?;
        ensure_unique(
            self.rollback_refs.iter().map(ArtifactId::as_str),
            "closure.rollback_refs",
        )?;
        if self.external_promotion_refs.is_empty()
            && self.requested_decision == ExternalDecisionClass::PromotionReview
        {
            return Err(LearningContractError::Missing {
                field: "closure.external_promotion_refs",
            });
        }
        ensure_unique(
            self.external_promotion_refs.iter().map(ArtifactId::as_str),
            "closure.external_promotion_refs",
        )?;
        ensure_unique(self.debts.iter().map(|d| d.as_str()), "closure.debts")?;
        validate_digest(&self.canonical_digest, "closure.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "closure.canonical_digest",
            });
        }
        Ok(())
    }

    /// Populate the canonical handoff digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }

    /// Validate exact assessment and overlay lineage before external review.
    pub fn validate_against_assessment(
        &self,
        assessment: &crate::assessment::LearningAssessmentCandidate,
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        assessment.validate()?;
        if self.binding != assessment.binding
            || self.target.as_str() != assessment.target.as_str()
            || self.overlay_id != assessment.overlay_id
            || self.assessment_id != assessment.assessment_receipt
            || self.assessment_digest != assessment.canonical_digest
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "closure.assessment_lineage",
            });
        }
        Ok(())
    }

    /// Validate exact assessment and delta lineage together before handoff.
    pub fn validate_against_assessment_and_delta(
        &self,
        assessment: &crate::assessment::LearningAssessmentCandidate,
        delta: &crate::delta::AttemptLearningDeltaCandidate,
    ) -> Result<(), LearningContractError> {
        self.validate_against_assessment(assessment)?;
        delta.validate()?;
        if self.delta_id != delta.delta_id
            || self.binding != delta.binding
            || self.target.as_str() != delta.target.as_str()
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "closure.delta_lineage",
            });
        }
        Ok(())
    }
}

fn ensure_unique<'a, I>(values: I, field: &'static str) -> Result<(), LearningContractError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(LearningContractError::Duplicate { field });
        }
    }
    Ok(())
}
