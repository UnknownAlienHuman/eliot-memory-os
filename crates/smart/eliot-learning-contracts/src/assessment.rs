//! Orthogonal activation, adherence, use, outcome and causal dimensions.

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    error::LearningContractError,
    identity::{ContractBinding, OverlayId, TargetId, digest_without_field, validate_digest},
    state_view::SourceDenominator,
};

/// Independent dimensions of an activation assessment.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentDimension {
    /// Declared target/member coverage and attrition.
    TargetCoverageAttrition,
    /// Retrieval, delivery and visibility evidence.
    RetrievalDeliveryVisibility,
    /// Selection or activation evidence.
    Selection,
    /// Adherence evidence.
    Adherence,
    /// Action-linked use evidence.
    ActionLinkedUse,
    /// Semantic outcome validity.
    OutcomeValidity,
    /// Baseline and control quality.
    BaselineControlQuality,
    /// Harm evidence, retained independently from benefit.
    Harm,
    /// Confounder accounting.
    Confounders,
    /// Source and evaluator independence.
    SourceEvaluatorIndependence,
    /// Transfer and applicability boundary.
    TransferApplicability,
    /// Causal claim ceiling.
    CausalCeiling,
    /// Privacy, authority and proof constraints.
    PrivacyAuthorityProof,
}

impl AssessmentDimension {
    /// Stable wire spelling for dimensions.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetCoverageAttrition => "TARGET_COVERAGE_ATTRITION",
            Self::RetrievalDeliveryVisibility => "RETRIEVAL_DELIVERY_VISIBILITY",
            Self::Selection => "SELECTION",
            Self::Adherence => "ADHERENCE",
            Self::ActionLinkedUse => "ACTION_LINKED_USE",
            Self::OutcomeValidity => "OUTCOME_VALIDITY",
            Self::BaselineControlQuality => "BASELINE_CONTROL_QUALITY",
            Self::Harm => "HARM",
            Self::Confounders => "CONFOUNDERS",
            Self::SourceEvaluatorIndependence => "SOURCE_EVALUATOR_INDEPENDENCE",
            Self::TransferApplicability => "TRANSFER_APPLICABILITY",
            Self::CausalCeiling => "CAUSAL_CEILING",
            Self::PrivacyAuthorityProof => "PRIVACY_AUTHORITY_PROOF",
        }
    }
}

/// Result for one independent assessment dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DimensionStatus {
    /// Dimension met its own declared evidence requirement.
    Pass,
    /// Dimension failed its evidence requirement.
    Fail,
    /// Evidence is unavailable or cannot establish a position.
    Unknown,
    /// Evidence is insufficient for a conclusion.
    Inconclusive,
    /// Harm was observed on this dimension.
    Harm,
    /// No effect was observed on this dimension.
    NoEffect,
}

/// Maximum causal interpretation supported by the assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalCeiling {
    /// Observation only; no causal claim.
    Observational,
    /// Controlled comparison supports a bounded causal hypothesis.
    ControlledComparison,
    /// Independent causal attribution was evidenced in the declared scope.
    CausalAttribution,
}

impl CausalCeiling {
    const fn rank(self) -> u8 {
        match self {
            Self::Observational => 0,
            Self::ControlledComparison => 1,
            Self::CausalAttribution => 2,
        }
    }
}

/// One evidence-backed independent dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DimensionAssessment {
    /// Dimension being assessed.
    pub dimension: AssessmentDimension,
    /// Independent disposition.
    pub status: DimensionStatus,
    /// Evidence handles for this dimension.
    pub evidence: Vec<ArtifactId>,
    /// Owner receipt for the dimension.
    pub owner_receipt: Option<ArtifactId>,
    /// Declared/observed denominator.
    pub denominator: SourceDenominator,
    /// Metric references; each retains its own units/population/window.
    pub metric_ids: Vec<ArtifactId>,
    /// Causal ceiling supported by this dimension.
    pub causal_ceiling: CausalCeiling,
}

impl DimensionAssessment {
    /// Validate one dimension independently.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        let established = matches!(
            self.status,
            DimensionStatus::Pass
                | DimensionStatus::Fail
                | DimensionStatus::Harm
                | DimensionStatus::NoEffect
        );
        if established
            && (self.evidence.is_empty()
                || self
                    .owner_receipt
                    .as_ref()
                    .is_none_or(|receipt| receipt.as_str().trim().is_empty()))
        {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "assessment.dimension",
            });
        }
        self.denominator.validate()?;
        ensure_unique(
            self.evidence.iter().map(ArtifactId::as_str),
            "assessment.evidence",
        )?;
        ensure_unique(
            self.metric_ids.iter().map(ArtifactId::as_str),
            "assessment.metric_ids",
        )?;
        if matches!(self.status, DimensionStatus::Harm)
            && self.dimension != AssessmentDimension::Harm
        {
            return Err(LearningContractError::NonIndependentAssessment);
        }
        Ok(())
    }
}

/// Candidate assessment; no scalar benefit or promotion state is representable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningAssessmentCandidate {
    /// Shared target/task/scope/fence binding.
    pub binding: ContractBinding,
    /// Target and overlay lineage.
    pub target: TargetId,
    /// Overlay evaluated by the receipt.
    pub overlay_id: OverlayId,
    /// Exact activation receipt identity and digest assessed here.
    pub activation_id: ArtifactId,
    /// Canonical activation receipt digest.
    pub activation_digest: String,
    /// Assessment owner receipt.
    pub assessment_receipt: ArtifactId,
    /// Independent dimensions; there is deliberately no scalar score.
    pub dimensions: Vec<DimensionAssessment>,
    /// Weakest supported causal interpretation.
    pub causal_ceiling: CausalCeiling,
    /// Explicit external references required for any later decision.
    pub external_review_refs: Vec<ArtifactId>,
    /// Canonical assessment digest, excluding this field.
    pub canonical_digest: String,
}

impl LearningAssessmentCandidate {
    /// Validate dimensions independently and preserve harm/unknown semantics.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        crate::identity::validate_external_id(self.target.as_str(), "assessment.target")?;
        self.overlay_id.validate()?;
        if self.activation_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "assessment.activation_id",
            });
        }
        validate_digest(&self.activation_digest, "assessment.activation_digest")?;
        if self.assessment_receipt.as_str().trim().is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "assessment_receipt",
            });
        }
        if self.dimensions.is_empty() {
            return Err(LearningContractError::Missing {
                field: "assessment.dimensions",
            });
        }
        for dimension in &self.dimensions {
            dimension.validate()?;
        }
        ensure_unique(
            self.dimensions.iter().map(|d| d.dimension.as_str()),
            "assessment.dimensions",
        )?;
        let weakest_ceiling = self
            .dimensions
            .iter()
            .map(|dimension| dimension.causal_ceiling)
            .min_by_key(|ceiling| ceiling.rank())
            .ok_or(LearningContractError::Missing {
                field: "assessment.dimensions",
            })?;
        if self.causal_ceiling.rank() > weakest_ceiling.rank() {
            return Err(LearningContractError::NonIndependentAssessment);
        }
        if self.causal_ceiling == CausalCeiling::CausalAttribution {
            const REQUIRED: &[AssessmentDimension] = &[
                AssessmentDimension::TargetCoverageAttrition,
                AssessmentDimension::RetrievalDeliveryVisibility,
                AssessmentDimension::Selection,
                AssessmentDimension::Adherence,
                AssessmentDimension::ActionLinkedUse,
                AssessmentDimension::OutcomeValidity,
                AssessmentDimension::BaselineControlQuality,
                AssessmentDimension::Harm,
                AssessmentDimension::Confounders,
                AssessmentDimension::SourceEvaluatorIndependence,
                AssessmentDimension::PrivacyAuthorityProof,
            ];
            for required in REQUIRED {
                let Some(dimension) = self
                    .dimensions
                    .iter()
                    .find(|item| item.dimension == *required)
                else {
                    return Err(LearningContractError::IncompleteCoverage);
                };
                let acceptable_harm_result = *required == AssessmentDimension::Harm
                    && matches!(
                        dimension.status,
                        DimensionStatus::Harm | DimensionStatus::NoEffect
                    );
                if dimension.status != DimensionStatus::Pass && !acceptable_harm_result {
                    return Err(LearningContractError::IncompleteCoverage);
                }
            }
        }
        ensure_unique(
            self.external_review_refs.iter().map(ArtifactId::as_str),
            "assessment.external_review_refs",
        )?;
        validate_digest(&self.canonical_digest, "assessment.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "assessment.canonical_digest",
            });
        }
        Ok(())
    }

    /// Validate exact activation lineage before assessing dimensions.
    pub fn validate_against_activation(
        &self,
        activation: &crate::activation::HarnessActivationReceiptCandidate,
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        activation.validate()?;
        if self.binding != activation.binding
            || self.target.as_str() != activation.target.as_str()
            || self.overlay_id != activation.overlay_id
            || self.activation_id != activation.activation_id
            || self.activation_digest != activation.canonical_digest
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "assessment.activation_lineage",
            });
        }
        Ok(())
    }

    /// Populate the canonical assessment digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
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
