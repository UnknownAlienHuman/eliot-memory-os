//! Observation-only activation lifecycle and owner receipts.

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    error::LearningContractError,
    identity::{ContractBinding, OverlayId, TargetId, digest_without_field, validate_digest},
    state_view::SourceDenominator,
};

/// Closed lifecycle vocabulary. Stages are evidence labels, never inferred state.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleStage {
    /// Candidate was produced by a consequential attempt.
    CandidateProduced,
    /// Candidate was admitted by an external owner for evaluation.
    AdmittedForEvaluation,
    /// An external owner requested activation observation.
    ActivationRequested,
    /// Candidate was retrieved for the target session.
    Retrieved,
    /// A delivery attempt was made.
    DeliveryAttempted,
    /// Candidate was delivered to the target surface.
    Delivered,
    /// Target acknowledged delivery.
    Acknowledged,
    /// Candidate was visible in the target surface.
    Visible,
    /// Candidate was selected or activated by an owner-controlled surface.
    SelectedActivated,
    /// Target adhered to the candidate in the declared context.
    Adhered,
    /// Candidate was used in an action.
    UsedInAction,
    /// Action output was observed.
    ActionOutputObserved,
    /// Semantic outcome was observed.
    SemanticOutcomeObserved,
    /// Benefit was observed; it is not causal attribution.
    Benefit,
    /// Harm was observed.
    Harm,
    /// No effect was observed.
    NoEffect,
    /// Outcome was inconclusive.
    Inconclusive,
    /// A causal assessment was issued by an independent owner.
    CausalAssessment,
    /// External promotion decision may consume this handoff.
    ExternalPromotion,
    /// External closure decision may consume this handoff.
    Closure,
}

impl LifecycleStage {
    /// Stable wire spelling used for duplicate detection and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateProduced => "CANDIDATE_PRODUCED",
            Self::AdmittedForEvaluation => "ADMITTED_FOR_EVALUATION",
            Self::ActivationRequested => "ACTIVATION_REQUESTED",
            Self::Retrieved => "RETRIEVED",
            Self::DeliveryAttempted => "DELIVERY_ATTEMPTED",
            Self::Delivered => "DELIVERED",
            Self::Acknowledged => "ACKNOWLEDGED",
            Self::Visible => "VISIBLE",
            Self::SelectedActivated => "SELECTED_ACTIVATED",
            Self::Adhered => "ADHERED",
            Self::UsedInAction => "USED_IN_ACTION",
            Self::ActionOutputObserved => "ACTION_OUTPUT_OBSERVED",
            Self::SemanticOutcomeObserved => "SEMANTIC_OUTCOME_OBSERVED",
            Self::Benefit => "BENEFIT",
            Self::Harm => "HARM",
            Self::NoEffect => "NO_EFFECT",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::CausalAssessment => "CAUSAL_ASSESSMENT",
            Self::ExternalPromotion => "EXTERNAL_PROMOTION",
            Self::Closure => "CLOSURE",
        }
    }

    /// Return the only compatible predecessor for this stage.
    pub const fn required_predecessor(self) -> Option<Self> {
        match self {
            Self::CandidateProduced => None,
            Self::AdmittedForEvaluation => Some(Self::CandidateProduced),
            Self::ActivationRequested => Some(Self::AdmittedForEvaluation),
            Self::Retrieved => Some(Self::ActivationRequested),
            Self::DeliveryAttempted => Some(Self::Retrieved),
            Self::Delivered => Some(Self::DeliveryAttempted),
            Self::Acknowledged => Some(Self::Delivered),
            Self::Visible => Some(Self::Acknowledged),
            Self::SelectedActivated => Some(Self::Visible),
            Self::Adhered => Some(Self::SelectedActivated),
            Self::UsedInAction => Some(Self::Adhered),
            Self::ActionOutputObserved => Some(Self::UsedInAction),
            Self::SemanticOutcomeObserved => Some(Self::ActionOutputObserved),
            Self::Benefit | Self::Harm | Self::NoEffect | Self::Inconclusive => {
                Some(Self::SemanticOutcomeObserved)
            }
            Self::CausalAssessment => Some(Self::Benefit),
            Self::ExternalPromotion => Some(Self::CausalAssessment),
            Self::Closure => Some(Self::ExternalPromotion),
        }
    }
}

/// Observation disposition for one stage/member pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StageDisposition {
    /// No attempt was made.
    NotAttempted,
    /// Owner rejected the stage.
    Rejected,
    /// Owner evidence observed the stage.
    Observed,
    /// Some declared population was observed.
    Partial,
    /// Owner route was unavailable.
    Unavailable,
    /// Evidence is stale.
    Stale,
    /// Evidence cannot establish the stage.
    Unknown,
}

/// Owner-issued evidence for one lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StageObservation {
    /// Stage being observed.
    pub stage: LifecycleStage,
    /// Explicit observation disposition.
    pub disposition: StageDisposition,
    /// Required prior stage when applicable.
    pub predecessor: Option<LifecycleStage>,
    /// Actual owner receipt; process/model self-report is not sufficient.
    pub owner_receipt: Option<ArtifactId>,
    /// Evidence handles for the observation.
    pub evidence: Vec<ArtifactId>,
    /// Stage/member denominator.
    pub denominator: SourceDenominator,
}

impl StageObservation {
    /// Validate predecessor and owner-evidence compatibility.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        let predecessor_is_valid = if self.stage == LifecycleStage::CausalAssessment {
            matches!(
                self.predecessor,
                Some(
                    LifecycleStage::Benefit
                        | LifecycleStage::Harm
                        | LifecycleStage::NoEffect
                        | LifecycleStage::Inconclusive,
                )
            )
        } else if self.stage == LifecycleStage::Visible {
            matches!(
                self.predecessor,
                Some(LifecycleStage::Acknowledged | LifecycleStage::Delivered)
            )
        } else if self.stage == LifecycleStage::UsedInAction {
            matches!(
                self.predecessor,
                Some(LifecycleStage::Adhered | LifecycleStage::SelectedActivated)
            )
        } else {
            self.predecessor == self.stage.required_predecessor()
        };
        if !predecessor_is_valid {
            return Err(LearningContractError::IncompatiblePredecessor);
        }
        self.denominator.validate()?;
        if matches!(
            self.disposition,
            StageDisposition::Observed | StageDisposition::Partial
        ) && (self.owner_receipt.is_none() || self.evidence.is_empty())
        {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "stage_observation",
            });
        }
        if let Some(receipt) = &self.owner_receipt
            && receipt.as_str().trim().is_empty()
        {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "stage.owner_receipt",
            });
        }
        ensure_unique(
            self.evidence.iter().map(ArtifactId::as_str),
            "stage.evidence",
        )
    }
}

/// Explicit measurement retained without collapsing metric dimensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricObservation {
    /// Stable metric identity.
    pub metric_id: ArtifactId,
    /// Metric name owned by the evaluator.
    pub name: String,
    /// Unit is explicit and cannot be inferred.
    pub unit: String,
    /// Population/denominator identity.
    pub population: SourceDenominator,
    /// Observation window identity.
    pub window: ArtifactId,
    /// Optional baseline and follow-up source references.
    pub baseline: Option<ArtifactId>,
    /// Follow-up source reference.
    pub follow_up: Option<ArtifactId>,
    /// Evaluator owner receipt.
    pub evaluator_receipt: ArtifactId,
}

impl MetricObservation {
    /// Validate the measurement dimensions and explicit denominator.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if self.metric_id.as_str().trim().is_empty()
            || self.name.trim().is_empty()
            || self.unit.trim().is_empty()
            || self.window.as_str().trim().is_empty()
            || self.evaluator_receipt.as_str().trim().is_empty()
        {
            return Err(LearningContractError::Missing { field: "metric" });
        }
        self.population.validate()
    }
}

/// Observation-only activation receipt candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HarnessActivationReceiptCandidate {
    /// Shared target/task/scope/fence binding.
    pub binding: ContractBinding,
    /// Stable activation receipt identity.
    pub activation_id: ArtifactId,
    /// Target being observed.
    pub target: TargetId,
    /// Immutable pre-attempt view digest.
    pub view_digest: String,
    /// Delta candidate lineage.
    pub delta_id: ArtifactId,
    /// Overlay candidate lineage.
    pub overlay_id: OverlayId,
    /// External admission receipt, if evaluation was admitted.
    pub admission_receipt: ArtifactId,
    /// External activation request receipt.
    pub activation_request_receipt: ArtifactId,
    /// Stage observations with explicit predecessors and owner receipts.
    pub stages: Vec<StageObservation>,
    /// Member/stage denominator retained separately from observed counts.
    pub member_denominator: SourceDenominator,
    /// Measurements retain unit/population/window/baseline/control dimensions.
    pub metrics: Vec<MetricObservation>,
    /// Attrition evidence handles.
    pub attrition: Vec<ArtifactId>,
    /// Concurrent interventions/confounder references.
    pub confounders: Vec<ArtifactId>,
    /// Whether evaluator/source independence was evidenced.
    pub independent_evaluator_receipt: Option<ArtifactId>,
    /// Canonical receipt candidate digest, excluding this field.
    pub canonical_digest: String,
}

impl HarnessActivationReceiptCandidate {
    /// Validate lineage and keep all lifecycle stages orthogonal.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        if self.activation_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "activation.activation_id",
            });
        }
        crate::identity::validate_external_id(self.target.as_str(), "activation.target")?;
        validate_digest(&self.view_digest, "activation.view_digest")?;
        for id in [
            &self.delta_id,
            &self.admission_receipt,
            &self.activation_request_receipt,
        ] {
            if id.as_str().trim().is_empty() {
                return Err(LearningContractError::Missing {
                    field: "activation.lineage",
                });
            }
        }
        self.overlay_id.validate()?;
        self.member_denominator.validate()?;
        if self.stages.is_empty() {
            return Err(LearningContractError::Missing {
                field: "activation.stages",
            });
        }
        for stage in &self.stages {
            stage.validate()?;
        }
        ensure_unique(
            self.stages.iter().map(|s| s.stage.as_str()),
            "activation.stages",
        )?;
        for metric in &self.metrics {
            metric.validate()?;
        }
        ensure_unique(
            self.metrics.iter().map(|m| m.metric_id.as_str()),
            "activation.metrics",
        )?;
        if let Some(receipt) = &self.independent_evaluator_receipt
            && receipt.as_str().trim().is_empty()
        {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "activation.independent_evaluator_receipt",
            });
        }
        validate_digest(&self.canonical_digest, "activation.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "activation.canonical_digest",
            });
        }
        Ok(())
    }

    /// Populate the canonical receipt digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }

    /// Validate that the observation receipt refers to the exact candidate lineage.
    pub fn validate_against_lineage(
        &self,
        view: &crate::state_view::CampaignLearningStateView,
        delta: &crate::delta::AttemptLearningDeltaCandidate,
        overlay: &crate::overlay::CampaignHarnessOverlayCandidate,
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        for stage in &self.stages {
            if matches!(
                stage.disposition,
                StageDisposition::Observed | StageDisposition::Partial
            ) && let Some(predecessor) = stage.predecessor
            {
                let predecessor_is_positive = self.stages.iter().any(|candidate| {
                    candidate.stage == predecessor
                        && matches!(
                            candidate.disposition,
                            StageDisposition::Observed | StageDisposition::Partial
                        )
                        && candidate.owner_receipt.is_some()
                        && !candidate.evidence.is_empty()
                });
                if !predecessor_is_positive {
                    return Err(LearningContractError::IncompatiblePredecessor);
                }
            }
        }
        delta.validate_against_view(view)?;
        overlay.validate_against_view_and_deltas(view, std::slice::from_ref(delta))?;
        if self.binding != view.binding
            || self.binding != delta.binding
            || self.binding != overlay.binding
            || self.target != view.target
            || self.target.as_str() != delta.target.as_str()
            || !overlay
                .changes
                .iter()
                .any(|change| self.target.as_str() == change.target.as_str())
            || self.view_digest != view.canonical_digest
            || self.delta_id != delta.delta_id
            || self.overlay_id != overlay.overlay_id
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "activation.lineage",
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
