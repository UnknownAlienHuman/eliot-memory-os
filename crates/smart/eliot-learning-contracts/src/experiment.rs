//! Candidate-only improvement-experiment contracts (CC-007).

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    assessment::{AssessmentDimension, CausalCeiling, DimensionAssessment},
    error::LearningContractError,
    identity::{ContractBinding, TargetId, digest_without_field, validate_digest},
};

/// Closed assignment vocabulary for a governed experiment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssignmentKind {
    /// Randomized assignment with a recorded seed digest.
    Randomized,
    /// Matched control assignment.
    MatchedControl,
    /// Sequential before/after assignment inside one fence.
    Sequential,
}

/// Candidate-only improvement experiment with immutable control.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExperimentCandidate {
    /// Shared task-local scope/fence/source binding.
    pub binding: ContractBinding,
    /// Stable experiment identity.
    pub experiment_id: ArtifactId,
    /// Target under experiment.
    pub target: TargetId,
    /// Attributed use lineage.
    pub attribution_id: ArtifactId,
    /// Canonical attribution digest consumed here.
    pub attribution_digest: String,
    /// Falsifiable hypothesis under test.
    pub hypothesis: String,
    /// Eligibility rule for intervention and control.
    pub eligibility: String,
    /// Assignment mechanism.
    pub assignment: AssignmentKind,
    /// Digest of the assignment seed or matching rule.
    pub assignment_seed_digest: String,
    /// Immutable intervention identity.
    pub intervention_id: ArtifactId,
    /// Immutable control identity, distinct from the intervention.
    pub control_id: ArtifactId,
    /// Discriminator fixed before observation.
    pub pre_observation_discriminator: ArtifactId,
    /// Safeguard handles that bound the experiment.
    pub safeguards: Vec<ArtifactId>,
    /// Stop conditions that end the experiment.
    pub stop_conditions: Vec<String>,
    /// Rollback handles retained for the experiment.
    pub rollback_refs: Vec<ArtifactId>,
    /// Contamination handling policy; silence is not permitted.
    pub contamination_policy: String,
    /// Prior-exposure handles accounted by the policy.
    pub prior_exposure_refs: Vec<ArtifactId>,
    /// Digest of the frozen evidence inputs.
    pub evidence_freeze_digest: String,
    /// Frozen evidence inputs for reproducible evaluation.
    pub evidence_freeze_refs: Vec<ArtifactId>,
    /// Dimensioned outcome; there is deliberately no scalar score.
    pub outcome_dimensions: Vec<DimensionAssessment>,
    /// Weakest causal interpretation claimed here.
    pub claim_ceiling: CausalCeiling,
    /// Canonical experiment digest, excluding this field.
    pub canonical_digest: String,
}

impl ImprovementExperimentCandidate {
    /// Validate the full candidate without executing any evaluation.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        if self.experiment_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.experiment_id",
            });
        }
        crate::identity::validate_external_id(self.target.as_str(), "experiment.target")?;
        if self.attribution_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.attribution_id",
            });
        }
        validate_digest(&self.attribution_digest, "experiment.attribution_digest")?;
        validate_text(&self.hypothesis, "experiment.hypothesis", 1024)?;
        validate_text(&self.eligibility, "experiment.eligibility", 1024)?;
        validate_digest(
            &self.assignment_seed_digest,
            "experiment.assignment_seed_digest",
        )?;
        self.validate_control()?;
        self.validate_safeguards()?;
        self.validate_contamination()?;
        self.validate_freeze()?;
        self.validate_outcome()?;
        validate_digest(&self.canonical_digest, "experiment.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "experiment.canonical_digest",
            });
        }
        Ok(())
    }

    /// Require distinct immutable intervention and control identities.
    fn validate_control(&self) -> Result<(), LearningContractError> {
        if self.intervention_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.intervention_id",
            });
        }
        if self.control_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.control_id",
            });
        }
        if self.intervention_id == self.control_id {
            return Err(LearningContractError::ScopeMismatch {
                field: "experiment.control",
            });
        }
        if self
            .pre_observation_discriminator
            .as_str()
            .trim()
            .is_empty()
        {
            return Err(LearningContractError::Missing {
                field: "experiment.pre_observation_discriminator",
            });
        }
        Ok(())
    }

    /// Require safeguards, stop conditions and rollback handles.
    fn validate_safeguards(&self) -> Result<(), LearningContractError> {
        if self.safeguards.is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.safeguards",
            });
        }
        ensure_unique(
            self.safeguards.iter().map(ArtifactId::as_str),
            "experiment.safeguards",
        )?;
        if self.stop_conditions.is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.stop_conditions",
            });
        }
        for condition in &self.stop_conditions {
            validate_text(condition, "experiment.stop_conditions", 256)?;
        }
        ensure_unique(
            self.stop_conditions.iter().map(String::as_str),
            "experiment.stop_conditions",
        )?;
        if self.rollback_refs.is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.rollback_refs",
            });
        }
        ensure_unique(
            self.rollback_refs.iter().map(ArtifactId::as_str),
            "experiment.rollback_refs",
        )
    }

    /// Reject silent contamination handling.
    fn validate_contamination(&self) -> Result<(), LearningContractError> {
        validate_text(
            &self.contamination_policy,
            "experiment.contamination_policy",
            1024,
        )?;
        ensure_unique(
            self.prior_exposure_refs.iter().map(ArtifactId::as_str),
            "experiment.prior_exposure_refs",
        )
    }

    /// Require an exact evidence freeze for reproducible evaluation.
    fn validate_freeze(&self) -> Result<(), LearningContractError> {
        validate_digest(
            &self.evidence_freeze_digest,
            "experiment.evidence_freeze_digest",
        )?;
        if self.evidence_freeze_refs.is_empty() {
            return Err(LearningContractError::Missing {
                field: "experiment.evidence_freeze_refs",
            });
        }
        ensure_unique(
            self.evidence_freeze_refs.iter().map(ArtifactId::as_str),
            "experiment.evidence_freeze_refs",
        )
    }

    /// Require a dimensioned outcome with harm retained independently.
    fn validate_outcome(&self) -> Result<(), LearningContractError> {
        if self.outcome_dimensions.len() < 2 {
            return Err(LearningContractError::IncompleteCoverage);
        }
        for dimension in &self.outcome_dimensions {
            dimension.validate()?;
        }
        ensure_unique(
            self.outcome_dimensions
                .iter()
                .map(|item| item.dimension.as_str()),
            "experiment.outcome_dimensions",
        )?;
        let has_harm = self
            .outcome_dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::Harm);
        let has_control = self
            .outcome_dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::BaselineControlQuality);
        if !has_harm || !has_control {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let weakest = self
            .outcome_dimensions
            .iter()
            .map(|item| ceiling_rank(item.causal_ceiling))
            .min()
            .ok_or(LearningContractError::Missing {
                field: "experiment.outcome_dimensions",
            })?;
        if ceiling_rank(self.claim_ceiling) > weakest {
            return Err(LearningContractError::NonIndependentAssessment);
        }
        Ok(())
    }

    /// Validate exact attribution lineage in the same scope and fence.
    pub fn validate_against_attribution(
        &self,
        attribution: &crate::attribution::UseAttributionCandidate,
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        attribution.validate()?;
        if self.binding != attribution.binding
            || self.target != attribution.target
            || self.attribution_id != attribution.attribution_id
            || self.attribution_digest != attribution.canonical_digest
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "experiment.attribution_lineage",
            });
        }
        Ok(())
    }

    /// Populate the canonical experiment digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), LearningContractError> {
    if value.trim().is_empty() {
        return Err(LearningContractError::Missing { field });
    }
    if value.chars().any(char::is_control) {
        return Err(LearningContractError::ScopeMismatch { field });
    }
    if value.chars().count() > max_chars {
        return Err(LearningContractError::Bound { field });
    }
    Ok(())
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
