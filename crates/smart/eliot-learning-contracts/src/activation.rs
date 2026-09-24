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
            Self::CandidateProduced | Self::Closure => None,
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

/// Retrieval disposition for one activation attempt. Orthogonal to delivery,
/// observable activation, adherence and outcome; never a success ladder rung.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalStatus {
    /// Surface was not eligible for this attempt.
    NotEligible,
    /// Eligible but not retrieved.
    EligibleNotRetrieved,
    /// Retrieved as compiled.
    Retrieved,
    /// Retrieved with expansion or tool-query augmentation.
    Expanded,
    /// Retrieval state is missing or inconclusive; never presumed.
    Unknown,
}

impl RetrievalStatus {
    /// Stable wire spelling used for logs and duplicate detection.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotEligible => "NOT_ELIGIBLE",
            Self::EligibleNotRetrieved => "ELIGIBLE_NOT_RETRIEVED",
            Self::Retrieved => "RETRIEVED",
            Self::Expanded => "EXPANDED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Delivery disposition for one activation attempt. Orthogonal to retrieval,
/// observable activation, adherence and outcome.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryStatus {
    /// Compiled surface was not delivered.
    NotDelivered,
    /// Delivered in full.
    Full,
    /// Delivered partially.
    Partial,
    /// Delivery record is missing.
    Missing,
}

impl DeliveryStatus {
    /// Stable wire spelling used for logs and duplicate detection.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDelivered => "NOT_DELIVERED",
            Self::Full => "FULL",
            Self::Partial => "PARTIAL",
            Self::Missing => "MISSING",
        }
    }
}

/// Observable-activation disposition for one attempt. An acknowledgement is a
/// delivery/attention signal only and never substitutes for the first
/// qualifying observable use ref. Missing or inconclusive observability
/// remains `Unknown`, never presumed compliance or non-use.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationStatus {
    /// Activation was not assessed (e.g. observation out of scope).
    NotAssessed,
    /// No qualifying activation evidence was observed; does not prove non-use.
    NotObserved,
    /// Qualifying observable activation was evidenced.
    Observed,
    /// Observability is missing or inconclusive; never presumed compliance.
    Unknown,
}

impl ActivationStatus {
    /// Stable wire spelling used for logs and duplicate detection.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAssessed => "NOT_ASSESSED",
            Self::NotObserved => "NOT_OBSERVED",
            Self::Observed => "OBSERVED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Adherence disposition for one attempt. Orthogonal to retrieval, delivery
/// and observable activation. Missing or inconclusive observability remains
/// `Unknown`, never presumed compliance.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdherenceStatus {
    /// Adherence was not assessed.
    NotAssessed,
    /// Observed use followed the prescription.
    ObservedFollowed,
    /// Observed use partially followed the prescription.
    ObservedPartial,
    /// Observed use violated the prescription.
    ObservedViolated,
    /// Observability is missing or inconclusive; never presumed compliance.
    Unknown,
}

impl AdherenceStatus {
    /// Stable wire spelling used for logs and duplicate detection.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAssessed => "NOT_ASSESSED",
            Self::ObservedFollowed => "OBSERVED_FOLLOWED",
            Self::ObservedPartial => "OBSERVED_PARTIAL",
            Self::ObservedViolated => "OBSERVED_VIOLATED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Retrieval evidence for one activation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalSection {
    /// Retrieval disposition; orthogonal to delivery/activation/adherence.
    pub status: RetrievalStatus,
    /// Expansion or tool-query refs backing an `Expanded` retrieval.
    pub expansion_or_tool_query_refs: Vec<ArtifactId>,
}

/// Delivery evidence for one activation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliverySection {
    /// Delivery disposition; orthogonal to retrieval/activation/adherence.
    pub status: DeliveryStatus,
    /// Position of the delivered packet, when known.
    pub packet_position: Option<u64>,
    /// Serialized digest of the delivered packet, when known.
    pub serialized_digest: Option<String>,
    /// Serialized byte size of the delivered packet, when known.
    pub bytes: Option<u64>,
    /// Actual billed/measured tokens of the delivered packet, when known.
    pub actual_tokens: Option<u64>,
}

/// Observable-activation evidence for one attempt. Receipt existence never
/// implies delivery, use, adherence or benefit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationSection {
    /// Activation disposition; `NotObserved` does not prove non-use.
    pub status: ActivationStatus,
    /// Delivery/attention signal only; never substitutes for
    /// `first_qualifying_observable_use_ref`.
    pub acknowledgement_ref: Option<ArtifactId>,
    /// Why observation was limited, when applicable.
    pub observation_limit_reason: Option<String>,
    /// First qualifying observable use; required when `status` is `Observed`.
    pub first_qualifying_observable_use_ref: Option<ArtifactId>,
}

/// Adherence evidence for one attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdherenceSection {
    /// Adherence disposition; `Unknown` is never presumed compliance.
    pub status: AdherenceStatus,
    /// Early/mid/final checkpoint refs backing an observed disposition.
    pub early_mid_final_checkpoint_refs: Vec<ArtifactId>,
    /// Prescribed-or-avoided action and required verifier refs backing an
    /// observed disposition.
    pub prescribed_or_avoided_action_and_required_verifier_refs: Vec<ArtifactId>,
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
    /// Full compiled-from campaign learning state view ref.
    pub compiled_view_ref: ArtifactId,
    /// Revision of the context compiler that rendered this attempt.
    pub context_compiler_revision: String,
    /// Revision of the render profile used for this attempt.
    pub render_profile_revision: String,
    /// Exact stable harness refs compiled into this attempt.
    pub stable_harness_refs: Vec<ArtifactId>,
    /// Task-family harness refs compiled into this attempt.
    pub task_family_harness_refs: Vec<ArtifactId>,
    /// Skill refs compiled into this attempt.
    pub skill_refs: Vec<ArtifactId>,
    /// Memory refs compiled into this attempt.
    pub memory_refs: Vec<ArtifactId>,
    /// Procedure refs compiled into this attempt.
    pub procedure_refs: Vec<ArtifactId>,
    /// Preserved success set or constraints ref, when one applies.
    pub preserved_success_ref: Option<ArtifactId>,
    /// Eligibility and retrieval reason for this attempt.
    pub eligibility_and_retrieval_reason: Option<String>,
    /// Retrieval evidence; orthogonal to delivery/activation/adherence.
    pub retrieval: RetrievalSection,
    /// Delivery evidence; orthogonal to retrieval/activation/adherence.
    pub delivery: DeliverySection,
    /// Observable-activation evidence; orthogonal to the other sections.
    pub activation: ActivationSection,
    /// Adherence evidence; orthogonal to the other sections.
    pub adherence: AdherenceSection,
    /// Conflict, suppression or compaction-loss refs for this attempt.
    pub conflicts_suppression_or_compaction_loss: Vec<ArtifactId>,
    /// Downstream decision, action, artifact and verifier refs.
    pub downstream_decision_action_artifact_and_verifier_refs: Vec<ArtifactId>,
    /// Receipt completeness notes and missing-field names.
    pub receipt_completeness_and_missing_fields: Vec<String>,
    /// Invalidation, expiry and missingness notes.
    pub invalidation_expiry_and_missingness: Vec<String>,
    /// Canonical receipt candidate digest, excluding this field.
    pub canonical_digest: String,
}

impl HarnessActivationReceiptCandidate {
    /// Validate lineage and keep all lifecycle stages orthogonal.
    #[allow(clippy::too_many_lines)]
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
        if self.compiled_view_ref.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "activation.compiled_view_ref",
            });
        }
        if self.context_compiler_revision.trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "activation.context_compiler_revision",
            });
        }
        if self.render_profile_revision.trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "activation.render_profile_revision",
            });
        }
        for (ids, field) in [
            (
                self.stable_harness_refs.as_slice(),
                "activation.stable_harness_refs",
            ),
            (
                self.task_family_harness_refs.as_slice(),
                "activation.task_family_harness_refs",
            ),
            (self.skill_refs.as_slice(), "activation.skill_refs"),
            (self.memory_refs.as_slice(), "activation.memory_refs"),
            (self.procedure_refs.as_slice(), "activation.procedure_refs"),
            (
                self.conflicts_suppression_or_compaction_loss.as_slice(),
                "activation.conflicts_suppression_or_compaction_loss",
            ),
            (
                self.downstream_decision_action_artifact_and_verifier_refs
                    .as_slice(),
                "activation.downstream_decision_action_artifact_and_verifier_refs",
            ),
            (
                self.retrieval.expansion_or_tool_query_refs.as_slice(),
                "activation.retrieval.expansion_or_tool_query_refs",
            ),
            (
                self.adherence.early_mid_final_checkpoint_refs.as_slice(),
                "activation.adherence.early_mid_final_checkpoint_refs",
            ),
            (
                self.adherence
                    .prescribed_or_avoided_action_and_required_verifier_refs
                    .as_slice(),
                "activation.adherence.prescribed_or_avoided_action_and_required_verifier_refs",
            ),
        ] {
            for id in ids {
                if id.as_str().trim().is_empty() {
                    return Err(LearningContractError::Missing { field });
                }
            }
        }
        if let Some(id) = &self.preserved_success_ref
            && id.as_str().trim().is_empty()
        {
            return Err(LearningContractError::Missing {
                field: "activation.preserved_success_ref",
            });
        }
        if let Some(id) = &self.activation.acknowledgement_ref
            && id.as_str().trim().is_empty()
        {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "activation.acknowledgement_ref",
            });
        }
        // An acknowledgement is a delivery/attention signal only and never
        // substitutes for the first qualifying observable use ref.
        if self.activation.status == ActivationStatus::Observed {
            let qualifies = matches!(
                &self.activation.first_qualifying_observable_use_ref,
                Some(id)
                    if !id.as_str().trim().is_empty()
                        && Some(id) != self.activation.acknowledgement_ref.as_ref()
            );
            if !qualifies {
                return Err(LearningContractError::MissingOwnerEvidence {
                    field: "activation.first_qualifying_observable_use_ref",
                });
            }
        } else if let Some(id) = &self.activation.first_qualifying_observable_use_ref
            && id.as_str().trim().is_empty()
        {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "activation.first_qualifying_observable_use_ref",
            });
        }
        // Observed adherence dispositions require checkpoint and
        // action/verifier evidence; UNKNOWN is never presumed compliance.
        if matches!(
            self.adherence.status,
            AdherenceStatus::ObservedFollowed
                | AdherenceStatus::ObservedPartial
                | AdherenceStatus::ObservedViolated
        ) {
            if self.adherence.early_mid_final_checkpoint_refs.is_empty() {
                return Err(LearningContractError::MissingOwnerEvidence {
                    field: "activation.adherence.early_mid_final_checkpoint_refs",
                });
            }
            if self
                .adherence
                .prescribed_or_avoided_action_and_required_verifier_refs
                .is_empty()
            {
                return Err(LearningContractError::MissingOwnerEvidence {
                    field: "activation.adherence.prescribed_or_avoided_action_and_required_verifier_refs",
                });
            }
        }
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
