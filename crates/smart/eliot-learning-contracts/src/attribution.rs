//! Candidate-only use-attribution contracts for self-learning (CC-007).

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    assessment::{AssessmentDimension, CausalCeiling, DimensionAssessment},
    error::LearningContractError,
    identity::{ContractBinding, TargetId, digest_without_field, validate_digest},
    state_view::SourceDenominator,
};

/// Closed kind of the attributed subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubjectKind {
    /// A learning candidate produced by a consequential attempt.
    Candidate,
    /// A memory or retrieval representation.
    Memory,
    /// A skill or procedure representation.
    Skill,
}

/// Closed use disposition; retrieval or repetition alone is never use.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UseDisposition {
    /// Subject was included in the decision opportunity.
    Included,
    /// Subject observably influenced the decision.
    Influential,
    /// Subject was actually used in the decided action.
    Used,
    /// Subject was explicitly considered and not used.
    NonUse,
}

/// Closed basis for a use claim; the last three are never use proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UseBasis {
    /// Direct observation of the decided action.
    DirectObservation,
    /// Controlled comparison against an immutable control.
    ControlledComparison,
    /// Independent evaluator receipt, distinct from the subject.
    IndependentEvaluator,
    /// Retrieval or delivery count treated as use.
    RetrievalCount,
    /// Repetition treated as usefulness.
    Repetition,
    /// Model judgment of its own correctness.
    ModelJudgment,
}

/// Exact subject identity with pinned version and record digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttributedSubject {
    /// Kind of the attributed subject.
    pub kind: SubjectKind,
    /// Subject identity.
    pub id: ArtifactId,
    /// Exact version pinned at attribution time.
    pub version: String,
    /// Digest of the versioned subject record.
    pub digest: String,
}

impl AttributedSubject {
    /// Validate identity, exact version and digest shape.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if self.id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "attribution.subject_id",
            });
        }
        validate_version(&self.version)?;
        validate_digest(&self.digest, "attribution.subject_digest")?;
        Ok(())
    }
}

/// One explicit non-use declaration with its reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NonUseDeclaration {
    /// Subject explicitly considered and not used.
    pub subject: ArtifactId,
    /// Reason the subject was not used.
    pub reason: String,
}

impl NonUseDeclaration {
    /// Validate subject identity and nonblank reason.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if self.subject.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "attribution.non_use.subject",
            });
        }
        if self.reason.trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "attribution.non_use.reason",
            });
        }
        if self.reason.chars().count() > 512 {
            return Err(LearningContractError::Bound {
                field: "attribution.non_use.reason",
            });
        }
        if self.reason.chars().any(char::is_control) {
            return Err(LearningContractError::ScopeMismatch {
                field: "attribution.non_use.reason",
            });
        }
        Ok(())
    }
}

/// Candidate-only use attribution; it never rates its own correctness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UseAttributionCandidate {
    /// Shared task-local scope/fence/source binding.
    pub binding: ContractBinding,
    /// Stable attribution identity.
    pub attribution_id: ArtifactId,
    /// Target whose decision opportunity is attributed.
    pub target: TargetId,
    /// Attributed subject with exact version.
    pub subject: AttributedSubject,
    /// Decision or action identity that consumed or rejected the subject.
    pub decision_action_id: ArtifactId,
    /// Source delta lineage.
    pub source_delta_id: ArtifactId,
    /// Canonical source delta digest.
    pub source_delta_digest: String,
    /// Inclusion, influence, actual use or explicit non-use.
    pub disposition: UseDisposition,
    /// Basis for the use claim.
    pub use_basis: UseBasis,
    /// Complete declared versus observed denominator.
    pub denominator: SourceDenominator,
    /// Eligible subjects in the denominator.
    pub eligible_refs: Vec<ArtifactId>,
    /// Explicit non-use declarations completing the denominator.
    pub non_use: Vec<NonUseDeclaration>,
    /// Competing contributors retained alongside the subject.
    pub competing_contributors: Vec<ArtifactId>,
    /// Independent evaluator receipt, never the subject itself.
    pub evaluator_receipt: ArtifactId,
    /// Evidence handles for inclusion, influence, use or non-use.
    pub evidence_refs: Vec<ArtifactId>,
    /// Dimensioned outcome; there is deliberately no scalar score.
    pub dimensions: Vec<DimensionAssessment>,
    /// Weakest causal interpretation claimed here.
    pub claim_ceiling: CausalCeiling,
    /// Canonical attribution digest, excluding this field.
    pub canonical_digest: String,
}

impl UseAttributionCandidate {
    /// Validate the full candidate without executing any evaluation.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        if self.attribution_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "attribution.attribution_id",
            });
        }
        crate::identity::validate_external_id(self.target.as_str(), "attribution.target")?;
        self.subject.validate()?;
        if self.decision_action_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "attribution.decision_action_id",
            });
        }
        if self.source_delta_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "attribution.source_delta_id",
            });
        }
        validate_digest(&self.source_delta_digest, "attribution.source_delta_digest")?;
        self.validate_basis()?;
        self.validate_denominator()?;
        self.validate_evaluator()?;
        self.validate_evidence()?;
        self.validate_dimensions()?;
        validate_digest(&self.canonical_digest, "attribution.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "attribution.canonical_digest",
            });
        }
        Ok(())
    }

    /// Reject retrieval, repetition or model judgment as use proof.
    fn validate_basis(&self) -> Result<(), LearningContractError> {
        match self.use_basis {
            UseBasis::DirectObservation
            | UseBasis::ControlledComparison
            | UseBasis::IndependentEvaluator => Ok(()),
            UseBasis::RetrievalCount | UseBasis::Repetition | UseBasis::ModelJudgment => {
                Err(LearningContractError::ScopeMismatch {
                    field: "attribution.use_basis",
                })
            }
        }
    }

    /// Require a complete denominator with explicit non-use.
    fn validate_denominator(&self) -> Result<(), LearningContractError> {
        self.denominator.validate()?;
        let eligible =
            u32::try_from(self.eligible_refs.len()).map_err(|_| LearningContractError::Bound {
                field: "attribution.eligible_refs",
            })?;
        let non_use =
            u32::try_from(self.non_use.len()).map_err(|_| LearningContractError::Bound {
                field: "attribution.non_use",
            })?;
        let declared = eligible.saturating_add(non_use);
        if self.denominator.declared != declared
            || self.denominator.observed != declared
            || self.denominator.declared == 0
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
        ensure_unique(
            self.eligible_refs.iter().map(ArtifactId::as_str),
            "attribution.eligible_refs",
        )?;
        for entry in &self.non_use {
            entry.validate()?;
        }
        ensure_unique(
            self.non_use.iter().map(|entry| entry.subject.as_str()),
            "attribution.non_use",
        )?;
        for eligible_ref in &self.eligible_refs {
            if self
                .non_use
                .iter()
                .any(|entry| entry.subject == *eligible_ref)
            {
                return Err(LearningContractError::Duplicate {
                    field: "attribution.subject_refs",
                });
            }
        }
        let subject_in_eligible = self
            .eligible_refs
            .iter()
            .any(|candidate| candidate == &self.subject.id);
        let subject_in_non_use = self
            .non_use
            .iter()
            .any(|entry| entry.subject == self.subject.id);
        match self.disposition {
            UseDisposition::Included | UseDisposition::Influential | UseDisposition::Used => {
                if !subject_in_eligible || subject_in_non_use {
                    return Err(LearningContractError::IncompleteCoverage);
                }
            }
            UseDisposition::NonUse => {
                if !subject_in_non_use || subject_in_eligible {
                    return Err(LearningContractError::IncompleteCoverage);
                }
            }
        }
        ensure_unique(
            self.competing_contributors.iter().map(ArtifactId::as_str),
            "attribution.competing_contributors",
        )?;
        if self
            .competing_contributors
            .iter()
            .any(|candidate| candidate == &self.subject.id)
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "attribution.competing_contributors",
            });
        }
        Ok(())
    }

    /// Reject model self-rating through evaluator independence.
    fn validate_evaluator(&self) -> Result<(), LearningContractError> {
        if self.evaluator_receipt.as_str().trim().is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "attribution.evaluator_receipt",
            });
        }
        if self.evaluator_receipt == self.subject.id {
            return Err(LearningContractError::ScopeMismatch {
                field: "attribution.evaluator_independence",
            });
        }
        Ok(())
    }

    /// Require affirmative evidence handles.
    fn validate_evidence(&self) -> Result<(), LearningContractError> {
        if self.evidence_refs.is_empty() {
            return Err(LearningContractError::Missing {
                field: "attribution.evidence_refs",
            });
        }
        ensure_unique(
            self.evidence_refs.iter().map(ArtifactId::as_str),
            "attribution.evidence_refs",
        )
    }

    /// Require a dimensioned result with harm retained independently.
    fn validate_dimensions(&self) -> Result<(), LearningContractError> {
        if self.dimensions.len() < 2 {
            return Err(LearningContractError::IncompleteCoverage);
        }
        for dimension in &self.dimensions {
            dimension.validate()?;
        }
        ensure_unique(
            self.dimensions.iter().map(|item| item.dimension.as_str()),
            "attribution.dimensions",
        )?;
        let has_harm = self
            .dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::Harm);
        let has_independence = self
            .dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::SourceEvaluatorIndependence);
        if !has_harm || !has_independence {
            return Err(LearningContractError::IncompleteCoverage);
        }
        if matches!(self.disposition, UseDisposition::Used)
            && !self
                .dimensions
                .iter()
                .any(|item| item.dimension == AssessmentDimension::ActionLinkedUse)
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let weakest = self
            .dimensions
            .iter()
            .map(|item| ceiling_rank(item.causal_ceiling))
            .min()
            .ok_or(LearningContractError::Missing {
                field: "attribution.dimensions",
            })?;
        if ceiling_rank(self.claim_ceiling) > weakest {
            return Err(LearningContractError::NonIndependentAssessment);
        }
        Ok(())
    }

    /// Validate exact delta lineage in the same scope and fence.
    pub fn validate_against_delta(
        &self,
        delta: &crate::delta::AttemptLearningDeltaCandidate,
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        delta.validate()?;
        if self.binding != delta.binding
            || self.target.as_str() != delta.target.as_str()
            || self.source_delta_id != delta.delta_id
            || self.source_delta_digest != delta.canonical_digest
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "attribution.delta_lineage",
            });
        }
        Ok(())
    }

    /// Populate the canonical attribution digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }
}

fn validate_version(value: &str) -> Result<(), LearningContractError> {
    if value.trim().is_empty() {
        return Err(LearningContractError::Missing {
            field: "attribution.subject_version",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(LearningContractError::ScopeMismatch {
            field: "attribution.subject_version",
        });
    }
    if value.chars().count() > 256 {
        return Err(LearningContractError::Bound {
            field: "attribution.subject_version",
        });
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
