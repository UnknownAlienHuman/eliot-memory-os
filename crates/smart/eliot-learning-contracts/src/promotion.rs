//! Candidate-only promotion-boundary contracts (CC-007).

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    assessment::{AssessmentDimension, CausalCeiling, DimensionAssessment},
    error::LearningContractError,
    identity::{ContractBinding, TargetId, digest_without_field, validate_digest},
};

/// Closed mutation target; only candidate output is representable as valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PromotionMutationTarget {
    /// Candidate-only output reviewed by an external owner.
    CandidateOnly,
    /// Direct mutation of active prompts, policies or skills.
    ActiveGeneration,
}

/// Closed history retention; deletion is representable only to be rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HistoryRetention {
    /// Evidence and history are always retained.
    RetainAlways,
    /// Evidence or history would be deleted on rollback.
    DeleteOnRollback,
}

/// Reversible rollout boundary with mandatory canary and invalidation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RolloutBoundary {
    /// Rollout must be reversible.
    pub reversible: bool,
    /// A canary is required before wider rollout.
    pub canary_required: bool,
    /// Conditions that invalidate the promotion.
    pub invalidation_conditions: Vec<String>,
}

impl RolloutBoundary {
    /// Validate reversibility, canary and invalidation conditions.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if !self.reversible {
            return Err(LearningContractError::ScopeMismatch {
                field: "promotion.rollout.reversible",
            });
        }
        if !self.canary_required {
            return Err(LearningContractError::ScopeMismatch {
                field: "promotion.rollout.canary_required",
            });
        }
        if self.invalidation_conditions.is_empty() {
            return Err(LearningContractError::Missing {
                field: "promotion.rollout.invalidation_conditions",
            });
        }
        for condition in &self.invalidation_conditions {
            if condition.trim().is_empty() {
                return Err(LearningContractError::Missing {
                    field: "promotion.rollout.invalidation_conditions",
                });
            }
            if condition.chars().any(char::is_control) {
                return Err(LearningContractError::ScopeMismatch {
                    field: "promotion.rollout.invalidation_conditions",
                });
            }
            if condition.chars().count() > 512 {
                return Err(LearningContractError::Bound {
                    field: "promotion.rollout.invalidation_conditions",
                });
            }
        }
        ensure_unique(
            self.invalidation_conditions.iter().map(String::as_str),
            "promotion.rollout.invalidation_conditions",
        )
    }
}

/// Candidate-only promotion boundary; issuance stays with the Governor owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromotionBoundaryCandidate {
    /// Shared task-local scope/fence/source binding.
    pub binding: ContractBinding,
    /// Stable promotion-boundary identity.
    pub promotion_id: ArtifactId,
    /// Target whose candidate awaits an external decision.
    pub target: TargetId,
    /// Attributed use lineage.
    pub attribution_id: ArtifactId,
    /// Canonical attribution digest consumed here.
    pub attribution_digest: String,
    /// Experiment lineage.
    pub experiment_id: ArtifactId,
    /// Canonical experiment digest consumed here.
    pub experiment_digest: String,
    /// External Governor receipt reference; never issued in Smart.
    pub governor_receipt_ref: Option<ArtifactId>,
    /// Reversible rollout boundary.
    pub rollout: RolloutBoundary,
    /// Mutation target; only candidate output validates.
    pub mutation_target: PromotionMutationTarget,
    /// Superseded promotion identities retained in history.
    pub supersedes: Vec<ArtifactId>,
    /// Invalidation identities appended on rollback.
    pub invalidates: Vec<ArtifactId>,
    /// History retention; only retention validates.
    pub history_retention: HistoryRetention,
    /// Dimensioned evaluation including delayed harm; no scalar score exists.
    pub evaluation_dimensions: Vec<DimensionAssessment>,
    /// Weakest causal interpretation claimed here.
    pub claim_ceiling: CausalCeiling,
    /// Canonical promotion digest, excluding this field.
    pub canonical_digest: String,
}

impl PromotionBoundaryCandidate {
    /// Validate the full candidate without issuing any promotion.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        if self.promotion_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "promotion.promotion_id",
            });
        }
        crate::identity::validate_external_id(self.target.as_str(), "promotion.target")?;
        if self.attribution_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "promotion.attribution_id",
            });
        }
        validate_digest(&self.attribution_digest, "promotion.attribution_digest")?;
        if self.experiment_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "promotion.experiment_id",
            });
        }
        validate_digest(&self.experiment_digest, "promotion.experiment_digest")?;
        self.validate_receipt_ref()?;
        self.rollout.validate()?;
        if matches!(
            self.mutation_target,
            PromotionMutationTarget::ActiveGeneration
        ) {
            return Err(LearningContractError::CandidateCeiling);
        }
        if matches!(self.history_retention, HistoryRetention::DeleteOnRollback) {
            return Err(LearningContractError::ScopeMismatch {
                field: "promotion.history_retention",
            });
        }
        ensure_unique(
            self.supersedes.iter().map(ArtifactId::as_str),
            "promotion.supersedes",
        )?;
        ensure_unique(
            self.invalidates.iter().map(ArtifactId::as_str),
            "promotion.invalidates",
        )?;
        self.validate_dimensions()?;
        validate_digest(&self.canonical_digest, "promotion.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "promotion.canonical_digest",
            });
        }
        Ok(())
    }

    /// Require an external receipt reference, never a self-issued receipt.
    fn validate_receipt_ref(&self) -> Result<(), LearningContractError> {
        if let Some(receipt) = &self.governor_receipt_ref {
            if receipt.as_str().trim().is_empty() {
                return Err(LearningContractError::Missing {
                    field: "promotion.governor_receipt_ref",
                });
            }
            if receipt == &self.promotion_id
                || receipt == &self.attribution_id
                || receipt == &self.experiment_id
            {
                return Err(LearningContractError::CandidateCeiling);
            }
        }
        Ok(())
    }

    /// Require a dimensioned evaluation with delayed harm retained.
    fn validate_dimensions(&self) -> Result<(), LearningContractError> {
        if self.evaluation_dimensions.len() < 2 {
            return Err(LearningContractError::IncompleteCoverage);
        }
        for dimension in &self.evaluation_dimensions {
            dimension.validate()?;
        }
        ensure_unique(
            self.evaluation_dimensions
                .iter()
                .map(|item| item.dimension.as_str()),
            "promotion.evaluation_dimensions",
        )?;
        let has_harm = self
            .evaluation_dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::Harm);
        if !has_harm {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let weakest = self
            .evaluation_dimensions
            .iter()
            .map(|item| ceiling_rank(item.causal_ceiling))
            .min()
            .ok_or(LearningContractError::Missing {
                field: "promotion.evaluation_dimensions",
            })?;
        if ceiling_rank(self.claim_ceiling) > weakest {
            return Err(LearningContractError::NonIndependentAssessment);
        }
        Ok(())
    }

    /// Validate exact attribution and experiment lineage in one fence.
    pub fn validate_against_attribution_and_experiment(
        &self,
        attribution: &crate::attribution::UseAttributionCandidate,
        experiment: &crate::experiment::ImprovementExperimentCandidate,
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        attribution.validate()?;
        experiment.validate()?;
        experiment.validate_against_attribution(attribution)?;
        if self.binding != attribution.binding
            || self.binding != experiment.binding
            || self.target != attribution.target
            || self.target != experiment.target
            || self.attribution_id != attribution.attribution_id
            || self.attribution_digest != attribution.canonical_digest
            || self.experiment_id != experiment.experiment_id
            || self.experiment_digest != experiment.canonical_digest
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "promotion.lineage",
            });
        }
        Ok(())
    }

    /// Append a superseding invalidation without deleting evidence or history.
    pub fn invalidate(
        &mut self,
        invalidation_id: &ArtifactId,
    ) -> Result<(), LearningContractError> {
        if invalidation_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "promotion.invalidates",
            });
        }
        if self
            .invalidates
            .iter()
            .any(|entry| entry == invalidation_id)
        {
            return Err(LearningContractError::Duplicate {
                field: "promotion.invalidates",
            });
        }
        self.invalidates.push(invalidation_id.clone());
        self.seal()
    }

    /// Populate the canonical promotion digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }
}

const fn ceiling_rank(ceiling: CausalCeiling) -> u8 {
    match ceiling {
        CausalCeiling::Observational => 0,
        CausalCeiling::ControlledComparison => 1,
        CausalCeiling::CausalAttribution => 2,
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
