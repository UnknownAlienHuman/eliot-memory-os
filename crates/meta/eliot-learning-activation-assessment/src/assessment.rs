//! Named phases for deterministic A-32 activation assessment composition.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_learning_contracts::{
    ActivationSection, ActivationStatus, AdherenceSection, AdherenceStatus,
    AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate, CampaignLearningStateView,
    ContractBinding, DeliverySection, DimensionAssessment, DimensionStatus,
    HarnessActivationReceiptCandidate, LearningAssessmentCandidate, LearningStateViewRecipe,
    MetricObservation, RetrievalSection, StageDisposition, StageObservation, TargetId,
    identity::validate_external_id,
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
    /// Full compiled-from campaign learning state view ref.
    pub compiled_view_ref: &'a ArtifactId,
    /// Revision of the context compiler that rendered this attempt.
    pub context_compiler_revision: &'a str,
    /// Revision of the render profile used for this attempt.
    pub render_profile_revision: &'a str,
    /// Exact stable harness refs compiled into this attempt.
    pub stable_harness_refs: &'a [ArtifactId],
    /// Task-family harness refs compiled into this attempt.
    pub task_family_harness_refs: &'a [ArtifactId],
    /// Skill refs compiled into this attempt.
    pub skill_refs: &'a [ArtifactId],
    /// Memory refs compiled into this attempt.
    pub memory_refs: &'a [ArtifactId],
    /// Procedure refs compiled into this attempt.
    pub procedure_refs: &'a [ArtifactId],
    /// Preserved success set or constraints ref, when one applies.
    pub preserved_success_ref: Option<&'a ArtifactId>,
    /// Eligibility and retrieval reason for this attempt.
    pub eligibility_and_retrieval_reason: Option<&'a str>,
    /// Retrieval evidence; orthogonal to delivery/activation/adherence.
    pub retrieval: &'a RetrievalSection,
    /// Delivery evidence; orthogonal to retrieval/activation/adherence.
    pub delivery: &'a DeliverySection,
    /// Observable-activation evidence; orthogonal to the other sections.
    pub activation: &'a ActivationSection,
    /// Adherence evidence; orthogonal to the other sections.
    pub adherence: &'a AdherenceSection,
    /// Conflict, suppression or compaction-loss refs for this attempt.
    pub conflicts_suppression_or_compaction_loss: &'a [ArtifactId],
    /// Downstream decision, action, artifact and verifier refs.
    pub downstream_refs: &'a [ArtifactId],
    /// Receipt completeness notes and missing-field names.
    pub receipt_completeness_and_missing_fields: &'a [String],
    /// Invalidation, expiry and missingness notes.
    pub invalidation_expiry_and_missingness: &'a [String],
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
    validate_activation_sections(input)?;
    prove_overlay_displayable(input)?;
    let input_snapshot = snapshot(input)?;
    let stages = expected_stages(input.stages, input.policy)?;
    let dimensions = expected_dimensions(input.dimensions, input.policy)?;
    let activation = build_activation_candidate(input, stages)?;
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

/// Build the immutable activation receipt candidate from caller evidence.
///
/// All harness, compiler, retrieval, delivery, activation, adherence, and
/// downstream fields are cloned from the supplied input without synthesis;
/// the guards in [`validate_activation_sections`] and the canonical
/// [`HarnessActivationReceiptCandidate::validate_against_lineage`] reject
/// ack-as-use substitution and evidence-free observed adherence.
fn build_activation_candidate(
    input: &AssessmentInput<'_>,
    stages: Vec<StageObservation>,
) -> Result<HarnessActivationReceiptCandidate, ActivationAssessmentError> {
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
        compiled_view_ref: input.compiled_view_ref.clone(),
        context_compiler_revision: input.context_compiler_revision.to_owned(),
        render_profile_revision: input.render_profile_revision.to_owned(),
        stable_harness_refs: input.stable_harness_refs.to_vec(),
        task_family_harness_refs: input.task_family_harness_refs.to_vec(),
        skill_refs: input.skill_refs.to_vec(),
        memory_refs: input.memory_refs.to_vec(),
        procedure_refs: input.procedure_refs.to_vec(),
        preserved_success_ref: input.preserved_success_ref.cloned(),
        eligibility_and_retrieval_reason: input.eligibility_and_retrieval_reason.map(str::to_owned),
        retrieval: input.retrieval.clone(),
        delivery: input.delivery.clone(),
        activation: input.activation.clone(),
        adherence: input.adherence.clone(),
        conflicts_suppression_or_compaction_loss: input
            .conflicts_suppression_or_compaction_loss
            .to_vec(),
        downstream_decision_action_artifact_and_verifier_refs: input.downstream_refs.to_vec(),
        receipt_completeness_and_missing_fields: input
            .receipt_completeness_and_missing_fields
            .to_vec(),
        invalidation_expiry_and_missingness: input.invalidation_expiry_and_missingness.to_vec(),
        canonical_digest: String::new(),
    };
    activation
        .seal()
        .map_err(|error| ActivationAssessmentError::contract("activation.seal", error))?;
    activation
        .validate_against_lineage(input.view, input.delta, input.overlay)
        .map_err(|error| ActivationAssessmentError::contract("activation.lineage", error))?;
    Ok(activation)
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

/// Prove the admitted nontrivial overlay is displayable from sealed sources.
///
/// An attempt with an admitted overlay must be able to display the immutable
/// revision, parent, source delta, pre-evaluation prediction, expected
/// observable, regressions/confounders, preserved-success constraint, next
/// discriminator, and rollback condition (acceptance A1). Assessment refuses
/// to certify an activation whose overlay cannot render that bundle: every
/// text comes from the sealed [`CampaignHarnessOverlayCandidate`] carried in
/// the input, which [`validate`] already proved digest-covered.
///
/// [`validate`]: eliot_learning_contracts::CampaignHarnessOverlayCandidate::validate
fn prove_overlay_displayable(input: &AssessmentInput<'_>) -> Result<(), ActivationAssessmentError> {
    use crate::overlay_display_1864::{OverlayDisplayInput, display_admitted_overlay};
    let overlay = input.overlay;
    let admitted_ids: Vec<String> = overlay
        .admitted_delta_ids
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let parent = format!("task-revision:{}", overlay.parent_revision.value());
    let display_input = OverlayDisplayInput {
        overlay_id: overlay.overlay_id.as_str(),
        revision: overlay.revision,
        parent_revision: &parent,
        admitted_delta_ids: &admitted_ids,
        prediction: &overlay.prediction,
        expected_observable: &overlay.expected_observable,
        regressions: &overlay.possible_regressions,
        confounders: &overlay.confounders,
        preserved_success: &overlay.preserved_success_constraint,
        next_discriminator: &overlay.next_discriminator_text,
        rollback_condition: &overlay.rollback_condition,
    };
    display_admitted_overlay(&display_input).map_err(|_| {
        ActivationAssessmentError::LineageMismatch {
            field: "overlay.display",
        }
    })?;
    Ok(())
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

/// Crate-local guard for the new receipt sections plus uniqueness of the new
/// reference slices. The canonical contracts crate re-enforces these;
/// this guard fails fast before any candidate is sealed.
pub(crate) fn validate_activation_sections(
    input: &AssessmentInput<'_>,
) -> Result<(), ActivationAssessmentError> {
    // Honest bounded accounting for the new borrowed evidence. `bounds::preflight`
    // (not owned by this work unit) serializes only the original fields, so the
    // new fields are counted here under the same caller-supplied byte limit.
    #[derive(serde::Serialize)]
    struct NewFieldPreflight<'a> {
        compiled_view_ref: &'a ArtifactId,
        context_compiler_revision: &'a str,
        render_profile_revision: &'a str,
        stable_harness_refs: &'a [ArtifactId],
        task_family_harness_refs: &'a [ArtifactId],
        skill_refs: &'a [ArtifactId],
        memory_refs: &'a [ArtifactId],
        procedure_refs: &'a [ArtifactId],
        preserved_success_ref: Option<&'a ArtifactId>,
        eligibility_and_retrieval_reason: Option<&'a str>,
        retrieval: &'a RetrievalSection,
        delivery: &'a DeliverySection,
        activation: &'a ActivationSection,
        adherence: &'a AdherenceSection,
        conflicts_suppression_or_compaction_loss: &'a [ArtifactId],
        downstream_refs: &'a [ArtifactId],
        receipt_completeness_and_missing_fields: &'a [String],
        invalidation_expiry_and_missingness: &'a [String],
    }
    let bounded = NewFieldPreflight {
        compiled_view_ref: input.compiled_view_ref,
        context_compiler_revision: input.context_compiler_revision,
        render_profile_revision: input.render_profile_revision,
        stable_harness_refs: input.stable_harness_refs,
        task_family_harness_refs: input.task_family_harness_refs,
        skill_refs: input.skill_refs,
        memory_refs: input.memory_refs,
        procedure_refs: input.procedure_refs,
        preserved_success_ref: input.preserved_success_ref,
        eligibility_and_retrieval_reason: input.eligibility_and_retrieval_reason,
        retrieval: input.retrieval,
        delivery: input.delivery,
        activation: input.activation,
        adherence: input.adherence,
        conflicts_suppression_or_compaction_loss: input.conflicts_suppression_or_compaction_loss,
        downstream_refs: input.downstream_refs,
        receipt_completeness_and_missing_fields: input.receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness: input.invalidation_expiry_and_missingness,
    };
    let _ = bounded_serialized_len(
        &bounded,
        input
            .policy
            .max_input_bytes
            .min(crate::contracts::MAX_INPUT_BYTES),
        "input",
    )?;
    ensure_unique_local(input.stable_harness_refs, "stable_harness_refs")?;
    ensure_unique_local(input.task_family_harness_refs, "task_family_harness_refs")?;
    ensure_unique_local(input.skill_refs, "skill_refs")?;
    ensure_unique_local(input.memory_refs, "memory_refs")?;
    ensure_unique_local(input.procedure_refs, "procedure_refs")?;
    ensure_unique_local(
        input.conflicts_suppression_or_compaction_loss,
        "conflicts_suppression_or_compaction_loss",
    )?;
    ensure_unique_local(input.downstream_refs, "downstream_refs")?;
    ensure_unique_local(
        &input.retrieval.expansion_or_tool_query_refs,
        "retrieval.expansion_or_tool_query_refs",
    )?;
    ensure_unique_local(
        &input.adherence.early_mid_final_checkpoint_refs,
        "adherence.early_mid_final_checkpoint_refs",
    )?;
    ensure_unique_local(
        &input
            .adherence
            .prescribed_or_avoided_action_and_required_verifier_refs,
        "adherence.prescribed_or_avoided_action_and_required_verifier_refs",
    )?;
    // An acknowledgement never substitutes for the first qualifying observable
    // use ref: Observed activation requires a distinct, non-blank use ref.
    if input.activation.status == ActivationStatus::Observed {
        let qualifies = matches!(
            &input.activation.first_qualifying_observable_use_ref,
            Some(id)
                if !id.as_str().trim().is_empty()
                    && Some(id) != input.activation.acknowledgement_ref.as_ref()
        );
        if !qualifies {
            return Err(ActivationAssessmentError::LineageMismatch {
                field: "activation.first_qualifying_observable_use_ref",
            });
        }
    }
    // Observed adherence requires checkpoint and action/verifier evidence.
    validate_observation_guards(input)?;
    Ok(())
}

fn validate_observation_guards(
    input: &AssessmentInput<'_>,
) -> Result<(), ActivationAssessmentError> {
    // Observed adherence requires checkpoint and action/verifier evidence;
    // missing or inconclusive observability stays UNKNOWN upstream.
    if matches!(
        input.adherence.status,
        AdherenceStatus::ObservedFollowed
            | AdherenceStatus::ObservedPartial
            | AdherenceStatus::ObservedViolated
    ) && (input.adherence.early_mid_final_checkpoint_refs.is_empty()
        || input
            .adherence
            .prescribed_or_avoided_action_and_required_verifier_refs
            .is_empty())
    {
        return Err(ActivationAssessmentError::LineageMismatch {
            field: "adherence.evidence",
        });
    }
    Ok(())
}

fn ensure_unique_local(
    ids: &[ArtifactId],
    field: &'static str,
) -> Result<(), ActivationAssessmentError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            return Err(ActivationAssessmentError::Duplicate { field });
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
        compiled_view_ref: input.compiled_view_ref.clone(),
        context_compiler_revision: input.context_compiler_revision.to_owned(),
        render_profile_revision: input.render_profile_revision.to_owned(),
        stable_harness_refs: input.stable_harness_refs.to_vec(),
        task_family_harness_refs: input.task_family_harness_refs.to_vec(),
        skill_refs: input.skill_refs.to_vec(),
        memory_refs: input.memory_refs.to_vec(),
        procedure_refs: input.procedure_refs.to_vec(),
        preserved_success_ref: input.preserved_success_ref.cloned(),
        eligibility_and_retrieval_reason: input.eligibility_and_retrieval_reason.map(str::to_owned),
        retrieval: input.retrieval.clone(),
        delivery: input.delivery.clone(),
        activation: input.activation.clone(),
        adherence: input.adherence.clone(),
        conflicts_suppression_or_compaction_loss: input
            .conflicts_suppression_or_compaction_loss
            .to_vec(),
        downstream_refs: input.downstream_refs.to_vec(),
        receipt_completeness_and_missing_fields: input
            .receipt_completeness_and_missing_fields
            .to_vec(),
        invalidation_expiry_and_missingness: input.invalidation_expiry_and_missingness.to_vec(),
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
