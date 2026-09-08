//! Named phases for deterministic A-32 activation assessment composition.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate, CampaignLearningStateView,
    ContractBinding, DimensionAssessment, DimensionStatus, HarnessActivationReceiptCandidate,
    LearningAssessmentCandidate, LearningStateViewRecipe, MetricObservation, StageDisposition,
    StageObservation, TargetId, identity::validate_external_id,
};

use crate::{
    ActivationAssessmentError,
    bounds::{bounded_serialized_len, preflight},
    contracts::{
        AssessmentPolicy, AssessmentResult, IncompleteAssessment, MAX_OUTPUT_BYTES,
        MissingAssessmentField,
    },
};

/// Exact immutable evidence and lineage supplied to one assessment call.
pub struct AssessmentInput<'a> {
    /// Binding compared with every canonical record.
    pub binding: &'a ContractBinding,
    /// Target compared with the view and delta.
    pub target: &'a TargetId,
    /// Canonical pre-attempt view.
    pub view: &'a CampaignLearningStateView,
    /// Recipe that defines the view's exact member denominator.
    pub recipe: &'a LearningStateViewRecipe,
    /// Canonical attempt delta.
    pub delta: &'a AttemptLearningDeltaCandidate,
    /// Canonical task-local overlay.
    pub overlay: &'a CampaignHarnessOverlayCandidate,
    /// Stable activation candidate identity, when supplied.
    pub activation_id: Option<&'a ArtifactId>,
    /// External admission receipt identity, when supplied.
    pub admission_receipt: Option<&'a ArtifactId>,
    /// External activation request receipt identity, when supplied.
    pub activation_request_receipt: Option<&'a ArtifactId>,
    /// Assessment owner receipt identity, when supplied.
    pub assessment_receipt: Option<&'a ArtifactId>,
    /// Immutable owner-issued lifecycle observations.
    pub stages: &'a [StageObservation],
    /// Immutable owner-issued metric observations.
    pub metrics: &'a [MetricObservation],
    /// Exact attrition references.
    pub attrition: &'a [ArtifactId],
    /// Exact concurrent-intervention references.
    pub confounders: &'a [ArtifactId],
    /// Independent evaluator receipt, if one exists.
    pub independent_evaluator_receipt: Option<&'a ArtifactId>,
    /// Supplied independent dimensions.
    pub dimensions: &'a [DimensionAssessment],
    /// Explicit external review references.
    pub external_review_refs: &'a [ArtifactId],
    /// Caller-supplied finite assessment parameters.
    pub policy: &'a AssessmentPolicy,
}

/// Construct canonical activation and assessment candidates from evidence.
pub fn assess_learning_activation(
    input: &AssessmentInput<'_>,
) -> Result<AssessmentResultOrIncomplete, ActivationAssessmentError> {
    preflight(input)?;
    validate_identity(input)?;
    let missing = missing_mandatory_ids(input);
    if !missing.is_empty() {
        let snapshot = snapshot(input)?;
        let incomplete = IncompleteAssessment {
            input: snapshot,
            binding: input.binding.clone(),
            target: input.target.clone(),
            missing,
            supplied_stages: input.stages.to_vec(),
            supplied_dimensions: input.dimensions.to_vec(),
            activation_id: input.activation_id.cloned(),
        };
        let outcome = AssessmentResultOrIncomplete::Incomplete(Box::new(incomplete));
        let _ = bounded_serialized_len(
            &outcome,
            input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
            "output",
        )?;
        return Ok(outcome);
    }
    validate_owner_lineage(input)?;
    let input_snapshot = snapshot(input)?;
    let stages = expected_stages(input.stages, input.policy)?;
    let dimensions = expected_dimensions(input.dimensions, input.policy)?;
    let mut activation = HarnessActivationReceiptCandidate {
        binding: input.binding.clone(),
        activation_id: required_id(input.activation_id, "activation_id")?,
        target: input.target.clone(),
        view_digest: input.view.canonical_digest.clone(),
        delta_id: input.delta.delta_id.clone(),
        overlay_id: input.overlay.overlay_id.clone(),
        admission_receipt: required_id(input.admission_receipt, "admission_receipt")?,
        activation_request_receipt: required_id(
            input.activation_request_receipt,
            "activation_request_receipt",
        )?,
        stages,
        // The canonical view owns the observed member denominator. The local
        // policy denominator is only used for synthesized unknown rows.
        member_denominator: input.view.denominator,
        metrics: input.metrics.to_vec(),
        attrition: input.attrition.to_vec(),
        confounders: input.confounders.to_vec(),
        independent_evaluator_receipt: input.independent_evaluator_receipt.cloned(),
        canonical_digest: String::new(),
    };
    activation
        .seal()
        .map_err(|error| ActivationAssessmentError::contract("activation.seal", error))?;
    activation
        .validate_against_lineage(input.view, input.delta, input.overlay)
        .map_err(|error| ActivationAssessmentError::contract("activation.lineage", error))?;
    let mut assessment = LearningAssessmentCandidate {
        binding: input.binding.clone(),
        target: input.target.clone(),
        overlay_id: input.overlay.overlay_id.clone(),
        activation_id: activation.activation_id.clone(),
        activation_digest: activation.canonical_digest.clone(),
        assessment_receipt: required_id(input.assessment_receipt, "assessment_receipt")?,
        dimensions,
        causal_ceiling: eliot_learning_contracts::CausalCeiling::Observational,
        external_review_refs: input.external_review_refs.to_vec(),
        canonical_digest: String::new(),
    };
    assessment
        .seal()
        .map_err(|error| ActivationAssessmentError::contract("assessment.seal", error))?;
    assessment
        .validate_against_activation(&activation)
        .map_err(|error| ActivationAssessmentError::contract("assessment.lineage", error))?;
    let mut result = AssessmentResult {
        input: input_snapshot,
        activation,
        assessment,
        canonical_digest: String::new(),
    };
    let _ = bounded_serialized_len(
        &result,
        input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
        "result",
    )?;
    result.seal()?;
    result.validate()?;
    let outcome = AssessmentResultOrIncomplete::Candidate(Box::new(result));
    let _ = bounded_serialized_len(
        &outcome,
        input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
        "output",
    )?;
    Ok(outcome)
}

/// Result arm preserving a constructed candidate or explicit incomplete input.
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "disposition", content = "value", deny_unknown_fields)]
pub enum AssessmentResultOrIncomplete {
    /// Mandatory identities were supplied and validated.
    Candidate(Box<AssessmentResult>),
    /// Mandatory evidence was absent; no identity was fabricated.
    Incomplete(Box<IncompleteAssessment>),
}

fn validate_identity(input: &AssessmentInput<'_>) -> Result<(), ActivationAssessmentError> {
    if input.binding != &input.view.binding
        || input.binding != &input.delta.binding
        || input.binding != &input.overlay.binding
        || input.target != &input.view.target
        || input.target != &input.delta.target
    {
        return Err(ActivationAssessmentError::LineageMismatch { field: "binding" });
    }
    validate_external_id(input.target.as_str(), "target")
        .map_err(|error| ActivationAssessmentError::contract("target", error))
}

fn missing_mandatory_ids(input: &AssessmentInput<'_>) -> Vec<MissingAssessmentField> {
    let mut missing = Vec::new();
    if input.activation_id.is_none() {
        missing.push(MissingAssessmentField::ActivationId);
    }
    if input.admission_receipt.is_none() {
        missing.push(MissingAssessmentField::AdmissionReceipt);
    }
    if input.activation_request_receipt.is_none() {
        missing.push(MissingAssessmentField::ActivationRequestReceipt);
    }
    if input.assessment_receipt.is_none() {
        missing.push(MissingAssessmentField::AssessmentReceipt);
    }
    missing
}

fn required_id(
    value: Option<&ArtifactId>,
    field: &'static str,
) -> Result<ArtifactId, ActivationAssessmentError> {
    value
        .cloned()
        .ok_or(ActivationAssessmentError::LineageMismatch { field })
}

fn validate_owner_lineage(input: &AssessmentInput<'_>) -> Result<(), ActivationAssessmentError> {
    input
        .view
        .validate_against(input.recipe)
        .map_err(|error| ActivationAssessmentError::contract("view", error))?;
    input
        .view
        .binding
        .validate()
        .map_err(|error| ActivationAssessmentError::contract("view.binding", error))?;
    input
        .delta
        .validate_against_view(input.view)
        .map_err(|error| ActivationAssessmentError::contract("delta", error))?;
    input
        .overlay
        .validate_against_view_and_deltas(input.view, std::slice::from_ref(input.delta))
        .map_err(|error| ActivationAssessmentError::contract("overlay", error))?;
    validate_supplied_evidence(input.metrics, input.stages, input.dimensions)?;
    Ok(())
}

pub(crate) fn validate_supplied_evidence(
    metrics: &[MetricObservation],
    stages: &[StageObservation],
    dimensions: &[DimensionAssessment],
) -> Result<(), ActivationAssessmentError> {
    for metric in metrics {
        metric
            .validate()
            .map_err(|error| ActivationAssessmentError::contract("metric", error))?;
    }
    let metric_ids = metrics
        .iter()
        .map(|metric| metric.metric_id.as_str())
        .collect::<BTreeSet<_>>();
    for stage in stages {
        stage
            .validate()
            .map_err(|error| ActivationAssessmentError::contract("stage", error))?;
    }
    for dimension in dimensions {
        dimension
            .validate()
            .map_err(|error| ActivationAssessmentError::contract("dimension", error))?;
        if dimension
            .metric_ids
            .iter()
            .any(|metric_id| !metric_ids.contains(metric_id.as_str()))
        {
            return Err(ActivationAssessmentError::LineageMismatch {
                field: "dimension.metric_ids",
            });
        }
    }
    Ok(())
}

fn snapshot(
    input: &AssessmentInput<'_>,
) -> Result<crate::contracts::AssessmentInputSnapshot, ActivationAssessmentError> {
    let mut snapshot = crate::contracts::AssessmentInputSnapshot {
        recipe: input.recipe.clone(),
        view: input.view.clone(),
        delta: input.delta.clone(),
        overlay: input.overlay.clone(),
        binding: input.binding.clone(),
        target: input.target.clone(),
        policy: input.policy.clone(),
        activation_id: input.activation_id.cloned(),
        admission_receipt: input.admission_receipt.cloned(),
        activation_request_receipt: input.activation_request_receipt.cloned(),
        assessment_receipt: input.assessment_receipt.cloned(),
        stages: input.stages.to_vec(),
        metrics: input.metrics.to_vec(),
        attrition: input.attrition.to_vec(),
        confounders: input.confounders.to_vec(),
        independent_evaluator_receipt: input.independent_evaluator_receipt.cloned(),
        dimensions: input.dimensions.to_vec(),
        external_review_refs: input.external_review_refs.to_vec(),
        input_digest: String::new(),
    };
    snapshot.seal()?;
    Ok(snapshot)
}

pub(crate) fn expected_stages(
    supplied: &[StageObservation],
    policy: &AssessmentPolicy,
) -> Result<Vec<StageObservation>, ActivationAssessmentError> {
    let mut stages = Vec::with_capacity(supplied.len() + policy.required_stages.len());
    let mut seen = BTreeSet::new();
    for stage in supplied {
        if !seen.insert(stage.stage) {
            return Err(ActivationAssessmentError::Duplicate { field: "stages" });
        }
        stages.push(stage.clone());
    }
    for required in &policy.required_stages {
        if !seen.contains(required) {
            stages.push(StageObservation {
                stage: *required,
                disposition: StageDisposition::Unknown,
                predecessor: required.required_predecessor(),
                owner_receipt: None,
                evidence: Vec::new(),
                denominator: policy.stage_denominator,
            });
        }
    }
    stages.sort_by_key(|stage| stage.stage);
    Ok(stages)
}

pub(crate) fn expected_dimensions(
    supplied: &[DimensionAssessment],
    policy: &AssessmentPolicy,
) -> Result<Vec<DimensionAssessment>, ActivationAssessmentError> {
    let mut dimensions = Vec::with_capacity(supplied.len() + policy.required_dimensions.len());
    let mut seen = BTreeSet::new();
    for dimension in supplied {
        if !seen.insert(dimension.dimension) {
            return Err(ActivationAssessmentError::Duplicate {
                field: "dimensions",
            });
        }
        let mut retained = dimension.clone();
        retained.causal_ceiling = eliot_learning_contracts::CausalCeiling::Observational;
        dimensions.push(retained);
    }
    for required in &policy.required_dimensions {
        if !seen.contains(required) {
            dimensions.push(DimensionAssessment {
                dimension: *required,
                status: DimensionStatus::Unknown,
                evidence: Vec::new(),
                owner_receipt: None,
                denominator: policy.dimension_denominator,
                metric_ids: Vec::new(),
                causal_ceiling: eliot_learning_contracts::CausalCeiling::Observational,
            });
        }
    }
    dimensions.sort_by_key(|dimension| dimension.dimension);
    Ok(dimensions)
}
