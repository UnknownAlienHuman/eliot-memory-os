//! Immutable stage-owner view and retained result set for one production call.

use eliot_context_assembly::ActiveUnderstandingViewResult;
use eliot_context_candidates::ContextCandidateSetResult;
use eliot_context_contracts::{
    CanonicalProjectionSet, ContextError, SerializedContextMeasurement,
};
use eliot_cue_activation::CueActivationEvaluation;
use eliot_dreamer_classification::ClassificationResult;
use eliot_dreamer_conflict_analysis::ConflictAnalysisCandidate;
use eliot_dreamer_contracts::grounding::GroundedDreamDraft as StructuredGroundedDreamDraft;
use eliot_dreamer_contracts::{
    canonical_bytes, DreamInputBundle, ModelDraft, ModelRouteOutcome,
    ValidatedGroundingCandidate,
};
use eliot_dreamer_orientation::{
    InertProbe, OrientationInterpretation, OrientationResidue, OrientationSemanticView,
    OrientationStageOutput,
};
use eliot_dreamer_probe_plan::{ProbePlan, ProbePlanParams};
use eliot_dreamer_rival_model::RivalModelSet;
use eliot_dreamer_contracts::rival::RivalModelSet as ProbeRivalModelSet;
use eliot_epistemic::PositionRequest;
use eliot_epistemic_contracts::CurrentEpistemicPosition;
use serde::Serialize;

use crate::pulse::{
    CandidateStage, ClassificationStage, ConflictStage, CueActivationStage, PulseError,
    PulseStage, PulseStageId, RivalStage, StageOwnerOutput, UnderstandingStage,
    check_model_boundary, check_projection_boundary,
    run_candidate_stage, run_classification_stage, run_conflict_stage, run_cue_stage,
    run_epistemic_stage, run_grounding_stage, run_probe_stage, run_rival_stage,
    run_understanding_stage,
};

pub(crate) type MeasureFn = fn(&[u8]) -> Result<SerializedContextMeasurement, ContextError>;

/// Borrowed typed owner records assembled from the admitted Kernel payload.
/// This type holds no defaults and creates no owner input itself.
pub(crate) struct OrientationOwnerInputs<'a> {
    pub classification: ClassificationStage<'a>,
    pub cue_activation: CueActivationStage<'a>,
    pub epistemic: &'a PositionRequest,
    pub understanding: UnderstandingStage<'a, MeasureFn>,
    pub grounding: &'a GroundingRequest,
    pub rivals: RivalStage<'a>,
    pub conflict: ConflictStage<'a>,
    pub probes: ProbePlanParams<'a>,
    pub candidates: CandidateStage<'a>,
}

/// Typed native outputs retained from the exact mandatory owner calls.
pub(crate) struct StageOutputSet {
    pub classification: Option<ClassificationResult>,
    pub cue_activation: Option<CueActivationEvaluation>,
    pub epistemic_position: Option<CurrentEpistemicPosition>,
    pub understanding: Option<ActiveUnderstandingViewResult>,
    pub grounding: Option<StructuredGroundedDreamDraft>,
    pub rivals: Option<RivalModelSet>,
    pub probe_rival_projection: Option<ProbeRivalModelSet>,
    pub conflict: Option<ConflictAnalysisCandidate>,
    pub probes: Option<ProbePlan>,
    pub candidates: Option<ContextCandidateSetResult>,
    pub interpretations: Vec<OrientationInterpretation>,
    pub rival_items: Vec<OrientationResidue>,
    pub gaps: Vec<OrientationResidue>,
    pub inert_probes: Vec<InertProbe>,
    pub stage_outputs: Vec<OrientationStageOutput>,
}

impl StageOutputSet {
    fn new(model_draft: &ModelDraft) -> Self {
        Self {
            classification: None,
            cue_activation: None,
            epistemic_position: None,
            understanding: None,
            grounding: None,
            rivals: None,
            probe_rival_projection: None,
            conflict: None,
            probes: None,
            candidates: None,
            interpretations: vec![OrientationInterpretation {
                statement: model_draft.statement.clone(),
                uncertainty: model_draft.uncertainty.clone(),
                expected_benefit: model_draft.expected_benefit.clone(),
                source_handles: model_draft.source_handles.clone(),
                counterevidence: model_draft.counterevidence.clone(),
                invalidation_conditions: model_draft.invalidation_conditions.clone(),
            }],
            rival_items: Vec::new(),
            gaps: Vec::new(),
            inert_probes: Vec::new(),
            stage_outputs: Vec::with_capacity(9),
        }
    }

    /// Borrows packet semantics only after every mandatory owner has returned.
    pub(crate) fn projection_view(&self) -> Option<OrientationSemanticView<'_>> {
        (self.classification.is_some()
            && self.cue_activation.is_some()
            && self.epistemic_position.is_some()
            && self.understanding.is_some()
            && self.grounding.is_some()
            && self.rivals.is_some()
            && self.conflict.is_some()
            && self.probes.is_some()
            && self.candidates.is_some()
            && self.stage_outputs.len() == 9)
            .then_some(OrientationSemanticView {
                interpretations: &self.interpretations,
                rivals: &self.rival_items,
                gaps: &self.gaps,
                probes: &self.inert_probes,
                stage_outputs: &self.stage_outputs,
            })
    }

    fn retain_stage(&mut self, stage: &mut PulseStage) -> bool {
        let (Some(owner_output), Some(input_digest), Some(output_digest)) = (
            stage.owner_output.take(),
            stage.input_commitment.as_ref(),
            stage.output_commitment.as_ref(),
        ) else {
            return false;
        };
        self.stage_outputs.push(OrientationStageOutput {
            stage: stage.id.as_str().to_owned(),
            input_digest: input_digest.clone(),
            output_digest: output_digest.clone(),
            canonical_output: stage.canonical_output.take(),
        });
        match owner_output {
            StageOwnerOutput::Classification(output) => self.classification = Some(output),
            StageOwnerOutput::CueActivation(output) => self.cue_activation = Some(output),
            StageOwnerOutput::EpistemicPosition(output) => {
                self.gaps.extend(output.unknowns.iter().map(|text| {
                    residue("epistemic_unknown", text, "epistemic_position")
                }));
                self.gaps.extend(output.required_inquiry.iter().map(|text| {
                    residue("required_inquiry", text, "epistemic_position")
                }));
                self.epistemic_position = Some(output);
            }
            StageOwnerOutput::Understanding(output) => self.understanding = Some(output),
            StageOwnerOutput::Grounding(output) => {
                let Some(ledger) = canonical_residue("claim_grounding_ledger", &output.ledger, &output.job_id) else {
                    return false;
                };
                self.gaps.push(ledger);
                self.grounding = Some(output);
            }
            StageOwnerOutput::Rivals(output) => {
                let source = output.source_set.set_id.as_str().to_owned();
                for assessment in &output.assessments {
                    let Some(entry) = canonical_residue(
                        "rival_assessment",
                        assessment,
                        &source,
                    ) else {
                        return false;
                    };
                    self.rival_items.push(entry);
                }
                for unknown in &output.unknown_slots {
                    let Some(entry) = canonical_residue(
                        "rival_unknown_facet",
                        unknown,
                        &source,
                    ) else {
                        return false;
                    };
                    self.gaps.push(entry);
                }
                if output.unknown_omitted_count != 0 {
                    self.gaps.push(residue(
                        "rival_unknown_frontier",
                        &output.unknown_omitted_count.to_string(),
                        &source,
                    ));
                }
                self.gaps.extend(output.omission_frontier.model_ids.iter().map(|model| {
                    residue(
                        "rival_omission_frontier",
                        model.model_id.as_str(),
                        &source,
                    )
                }));
                self.rivals = Some(output);
            }
            StageOwnerOutput::Conflict(output) => {
                let source = output.conflict_id.as_str();
                self.gaps.push(residue("conflict_outcome", output.outcome.as_str(), source));
                self.gaps.push(residue("conflict_scope", &output.scope, source));
                for position in &output.positions {
                    self.rival_items.push(residue(
                        "conflict_position",
                        &format!(
                            "index={} minority={} {}: {}",
                            position.position_index,
                            position.minority,
                            position.disposition.as_str(),
                            position.stance
                        ),
                        &position.source_handle,
                    ));
                    for conflict_class in &position.conflict_classes {
                        let Some(entry) = canonical_residue(
                            "conflict_class",
                            conflict_class,
                            &position.source_handle,
                        ) else {
                            return false;
                        };
                        self.gaps.push(entry);
                    }
                    self.gaps.push(residue(
                        "conflict_position_compatibility_note",
                        &position.compatibility_note,
                        &position.source_handle,
                    ));
                    self.gaps.extend(position.assumptions.iter().map(|text| {
                        residue("conflict_position_assumption", text, &position.source_handle)
                    }));
                    self.gaps.extend(position.counters.iter().map(|text| {
                        residue("conflict_position_counter", text, &position.source_handle)
                    }));
                    for compatibility in &position.compatibility {
                        self.gaps.push(residue(
                            "conflict_position_compatibility",
                            &format!(
                                "relation={} supplement={} note={} differs={} unnormalizable={} unsupported={}",
                                compatibility.relation.as_str(),
                                compatibility.supplement_version.as_str(),
                                compatibility.derivation_note,
                                dimension_names(&compatibility.differing_dimensions),
                                dimension_names(&compatibility.unnormalizable_dimensions),
                                dimension_names(&compatibility.unsupported_dimensions),
                            ),
                            &compatibility.other_source,
                        ));
                        let Some(coverage) = canonical_residue(
                            "conflict_position_compatibility_coverage",
                            &compatibility.coverage,
                            &compatibility.other_source,
                        ) else {
                            return false;
                        };
                        self.gaps.push(coverage);
                        for comparison in &compatibility.outcomes {
                            let text = match &comparison.outcome {
                                eliot_dreamer_conflict_analysis::DimensionOutcome::Equal { value } => {
                                    format!("{} equal {}", comparison.dimension.as_str(), value)
                                }
                                eliot_dreamer_conflict_analysis::DimensionOutcome::Differing {
                                    left,
                                    right,
                                } => format!(
                                    "{} differing left={} right={}",
                                    comparison.dimension.as_str(),
                                    left,
                                    right
                                ),
                                eliot_dreamer_conflict_analysis::DimensionOutcome::Unnormalizable {
                                    reason,
                                } => format!("{} unnormalizable {}", comparison.dimension.as_str(), reason),
                            };
                            self.gaps.push(residue(
                                "conflict_position_dimension",
                                &text,
                                &compatibility.other_source,
                            ));
                        }
                    }
                }
                for group in &output.lineage_groups {
                    self.gaps.push(residue(
                        "conflict_lineage_group",
                        &format!("known={} members={}", group.known, group.member_sources.join(",")),
                        &group.lineage_root,
                    ));
                }
                for risk in &output.common_mode_risks {
                    self.gaps.push(residue(
                        "conflict_common_mode_risk",
                        &format!(
                            "{}: {} sources={}",
                            risk.kind,
                            risk.description,
                            risk.affected_sources.join(",")
                        ),
                        source,
                    ));
                }
                self.gaps.extend(output.objections.iter().map(|objection| {
                    residue(
                        "conflict_objection",
                        &format!("grounded={} {}", objection.grounded, objection.statement),
                        &format!("{}:{}", objection.objection_id, objection.target_source),
                    )
                }));
                for probe in &output.recommended_probes {
                    self.inert_probes.push(InertProbe {
                        text: format!(
                            "{} objective={} result={} separates={} owner={} verifier={} cost={} risk={} privacy={} effect={}",
                            probe.probe_id,
                            probe.objective_digest,
                            probe.result_digest,
                            probe.discriminates_positions.join(","),
                            probe.owner,
                            probe.verifier,
                            probe.cost_note,
                            probe.risk_note,
                            probe.privacy_note,
                            probe.effect_note,
                        ),
                        status: "candidate_only".to_owned(),
                        result_space: probe.resolves_unknown.clone(),
                    });
                }
                self.gaps.push(residue(
                    "conflict_owner_recommendation",
                    &format!(
                        "{}: {} ({})",
                        output.recommended_owner.kind.as_str(),
                        output.recommended_owner.rationale,
                        output.recommended_owner.contract_needed
                    ),
                    &output.recommended_owner.owner_handle,
                ));
                for verdict in &output.preservation.verdicts {
                    self.gaps.push(residue(
                        "conflict_preservation",
                        &format!(
                            "{} passed={} known={} {}",
                            verdict.dimension.as_str(), verdict.passed, verdict.known, verdict.note
                        ),
                        source,
                    ));
                }
                self.gaps.push(residue(
                    "conflict_candidate_commitment",
                    &output.candidate_digest,
                    source,
                ));
                self.gaps.push(residue(
                    "conflict_analysis_note",
                    &output.note,
                    source,
                ));
                self.gaps.push(residue(
                    "conflict_independent_root_count",
                    &output.independent_root_count.to_string(),
                    source,
                ));
                if let Some(resolution) = &output.resolution_status {
                    self.gaps.push(residue(
                        "conflict_external_resolution",
                        &format!("{}: {}", resolution.decision_digest, resolution.note),
                        &resolution.decided_by,
                    ));
                }
                for causal in &output.causal_states {
                    self.gaps.push(residue(
                        "conflict_causal_state",
                        &format!(
                            "declared={} effective={} revision={} supplement={} reduction={} mechanism={}",
                            causal.declared_state.as_str(),
                            causal.effective_state.as_str(),
                            causal.declaration_revision.as_deref().unwrap_or("unavailable"),
                            causal.supplement_version.as_str(),
                            causal.reduction_reason,
                            causal.mechanism_claim_id.as_deref().unwrap_or("unavailable"),
                        ),
                        &causal.source_handle,
                    ));
                    for (name, coverage) in [
                        ("overall", &causal.coverage),
                        ("evidence", &causal.evidence_coverage),
                        ("rivals", &causal.rival_coverage),
                    ] {
                        let Some(entry) = canonical_residue(
                            "conflict_causal_coverage",
                            coverage,
                            &format!("{}:{name}", causal.source_handle),
                        ) else {
                            return false;
                        };
                        self.gaps.push(entry);
                    }
                }
                self.gaps.extend(output.unknowns.iter().map(|text| {
                    residue("conflict_unknown", text, source)
                }));
                self.gaps.extend(output.assumptions.iter().map(|text| {
                    residue("conflict_assumption", text, source)
                }));
                self.gaps.extend(output.counterevidence.iter().map(|text| {
                    residue("conflict_counterevidence", text, source)
                }));
                self.gaps.extend(output.invalidation_conditions.iter().map(|text| {
                    residue("conflict_invalidation", text, source)
                }));
                self.conflict = Some(output);
            }
            StageOwnerOutput::Probes(output) => {
                self.inert_probes.extend(output.probes.iter().map(|probe| InertProbe {
                    text: probe.expected_discrimination.clone(),
                    status: "candidate_only".to_owned(),
                    result_space: None,
                }));
                for omission in &output.omissions {
                    let Some(entry) = canonical_residue(
                        "probe_plan_omission",
                        omission,
                        output.plan_id.as_str(),
                    ) else {
                        return false;
                    };
                    self.gaps.push(entry);
                }
                self.probes = Some(output);
            }
            StageOwnerOutput::Candidates(output) => {
                for candidate in &output.set.candidates {
                    let Some(entry) = canonical_residue(
                        "context_candidate",
                        candidate,
                        candidate.atom_id.as_str(),
                    ) else {
                        return false;
                    };
                    self.rival_items.push(entry);
                }
                for omission in &output.omissions {
                    let Some(entry) = canonical_residue(
                        "context_candidate_omission",
                        omission,
                        omission.atom_id.as_str(),
                    ) else {
                        return false;
                    };
                    self.gaps.push(entry);
                }
                for frontier in &output.frontier {
                    let Some(entry) = canonical_residue(
                        "context_candidate_frontier",
                        frontier,
                        "context_candidate_set",
                    ) else {
                        return false;
                    };
                    self.gaps.push(entry);
                }
                self.candidates = Some(output);
            }
        }
        true
    }
}

/// Ordered result of the mandatory run, preserving the executed prefix and
/// the exact refusal stage for the production ledger.
pub(crate) struct MandatoryStageRun {
    pub stages: Vec<PulseStage>,
    pub outputs: StageOutputSet,
    pub failure: Option<PulseError>,
}

const MANDATORY_STAGES: [PulseStageId; 9] = [
    PulseStageId::Classification,
    PulseStageId::CueActivation,
    PulseStageId::EpistemicPosition,
    PulseStageId::Understanding,
    PulseStageId::Grounding,
    PulseStageId::Rivals,
    PulseStageId::Conflict,
    PulseStageId::Probes,
    PulseStageId::Candidates,
];

/// Runs each named owner once in denominator order after checking the exact
/// route and canonical-projection boundaries.
pub(crate) fn run_mandatory_stages(
    inputs: &OrientationOwnerInputs<'_>,
    model_draft: &ModelDraft,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
    projections: &CanonicalProjectionSet,
) -> MandatoryStageRun {
    let mut stages = Vec::with_capacity(MANDATORY_STAGES.len());
    let mut outputs = StageOutputSet::new(model_draft);
    if let Err(error) = check_model_boundary(model_outcome, bundle)
        .and_then(|()| check_projection_boundary(projections, bundle))
        .and_then(|()| {
            if model_outcome.draft.as_ref() == Some(model_draft) {
                Ok(())
            } else {
                Err(PulseError::Boundary("model route draft binding"))
            }
        })
    {
        stages.extend(MANDATORY_STAGES.map(|id| {
            PulseStage::blocked(id, "mandatory route or projection binding refused")
        }));
        return MandatoryStageRun {
            stages,
            outputs,
            failure: Some(error),
        };
    }

macro_rules! run_and_retain {
        ($binding_check:expr, $owner_call:expr, $id:expr) => {{
            if let Err(error) = $binding_check {
                return failed_run(stages, outputs, $id, error);
            }
            let mut stage = match $owner_call {
                Ok(stage) => stage,
                Err(error) => {
                    return failed_run(stages, outputs, $id, error);
                }
            };
            if !outputs.retain_stage(&mut stage) {
                return failed_run(
                    stages,
                    outputs,
                    $id,
                    PulseError::Boundary("mandatory stage output commitment"),
                );
            }
            stages.push(stage);
        }};
    }

    run_and_retain!(
        check_classification_binding(&inputs.classification, bundle, model_outcome),
        run_classification_stage(Some(&inputs.classification)),
        PulseStageId::Classification
    );
    run_and_retain!(
        check_cue_binding(&inputs.cue_activation, bundle),
        run_cue_stage(Some(&inputs.cue_activation)),
        PulseStageId::CueActivation
    );
    run_and_retain!(
        check_epistemic_binding(inputs.epistemic, bundle),
        run_epistemic_stage(Some(inputs.epistemic)),
        PulseStageId::EpistemicPosition
    );
    run_and_retain!(
        check_understanding_binding(&inputs.understanding, bundle, projections),
        run_understanding_stage(Some(UnderstandingStage {
            admitted: inputs.understanding.admitted,
            recipe: inputs.understanding.recipe,
            quality: inputs.understanding.quality,
            policy: inputs.understanding.policy,
            measure: inputs.understanding.measure,
        })),
        PulseStageId::Understanding
    );
    run_and_retain!(
        check_grounding_binding(inputs.grounding, bundle, model_outcome),
        run_grounding_stage(Some(inputs.grounding)),
        PulseStageId::Grounding
    );
    if outputs.grounding.as_ref()
        != inputs.rivals.validated_draft.input.grounded.as_deref()
    {
        return failed_run(
            stages,
            outputs,
            PulseStageId::Rivals,
            PulseError::Boundary("rival validated candidate grounding predecessor"),
        );
    }
    run_and_retain!(
        check_rival_binding(&inputs.rivals, bundle, model_outcome),
        run_rival_stage(Some(&inputs.rivals)),
        PulseStageId::Rivals
    );

    let structured_candidate: &ValidatedGroundingCandidate = inputs.rivals.validated_draft;
    let grounding_route = model_outcome
        .execution
        .as_ref()
        .and_then(|execution| execution.grounding_route.as_ref());
    if grounding_route.is_none_or(|route| route != &structured_candidate.input.grounded.input.route) {
        return failed_run(
            stages,
            outputs,
            PulseStageId::Conflict,
            PulseError::Boundary("structured grounding route lacks exact physical-route lineage"),
        );
    }
    run_and_retain!(
        check_conflict_binding(&inputs.conflict, structured_candidate, bundle),
        run_conflict_stage(Some(&inputs.conflict), Some(structured_candidate)),
        PulseStageId::Conflict
    );

    let Some(native_rivals) = outputs.rivals.as_ref() else {
        return failed_run(
            stages,
            outputs,
            PulseStageId::Probes,
            PulseError::Boundary("native rival predecessor missing"),
        );
    };
    let probe_projection = match native_rivals.to_probe_projection() {
        Ok(projection) => projection,
        Err(_) => {
            return failed_run(stages, outputs, PulseStageId::Probes, PulseError::Probes);
        }
    };
    outputs.probe_rival_projection = Some(probe_projection.clone());
    let probe_rivals = &probe_projection;
    if inputs.probes.bundle != bundle
        || inputs.probes.draft != &structured_candidate.validated
        || inputs.probes.affordances.task_id.as_str() != bundle.task_id
        || inputs.probes.affordances.scope != bundle.scope_id
        || inputs.probes.affordances.state_fence != bundle.state_fence
        || probe_rivals.bundle_digest != model_outcome.bundle_digest
        || probe_rivals.validated_input_digest != structured_candidate.validated.receipt.input_digest
        || probe_rivals.task_id.as_str() != bundle.task_id
        || probe_rivals.scope != bundle.scope_id
        || probe_rivals.state_fence != bundle.state_fence
    {
        return failed_run(
            stages,
            outputs,
            PulseStageId::Probes,
            PulseError::Boundary("probe candidate and rival predecessor bindings"),
        );
    }
    let probe_params = ProbePlanParams {
        plan_id: inputs.probes.plan_id.clone(),
        bundle,
        draft: &structured_candidate.validated,
        rivals: probe_rivals,
        affordances: inputs.probes.affordances,
        limits: inputs.probes.limits,
        policy: inputs.probes.policy,
    };
    run_and_retain!(
        Ok(()),
        run_probe_stage(Some(probe_params)),
        PulseStageId::Probes
    );

    let conflict_set = inputs.conflict.conflict_set;
    if inputs.candidates.request.binding.task_id.as_str() != bundle.task_id
        || inputs.candidates.request.binding.scope_id.as_str() != bundle.scope_id
        || inputs.candidates.request.binding.state_fence != bundle.state_fence
        || inputs.candidates.epistemic_position.is_some_and(|view| {
            view.position.admission.scope != bundle.scope_id
                || view.position.admission.fence != bundle.state_fence
        })
    {
        return failed_run(
            stages,
            outputs,
            PulseStageId::Candidates,
            PulseError::Boundary("candidate context owner bindings"),
        );
    }
    run_and_retain!(
        Ok(()),
        run_candidate_stage(
            Some(projections),
            Some(&inputs.candidates),
            outputs.cue_activation.as_ref(),
            Some(conflict_set),
        ),
        PulseStageId::Candidates
    );
    MandatoryStageRun {
        stages,
        outputs,
        failure: None,
    }
}

fn check_conflict_binding(
    stage: &ConflictStage<'_>,
    candidate: &ValidatedGroundingCandidate,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    let grounded = candidate.input.grounded.as_ref();
    if grounded.input.bundle != *bundle
        || grounded.input.bundle_digest != candidate.validated.receipt.bundle_digest
        || grounded.input.job.job_id != candidate.validated.receipt.job_id
        || grounded.input.task_id.as_str() != bundle.task_id
        || grounded.input.scope_id != bundle.scope_id
        || grounded.input.state_fence != bundle.state_fence
        || stage.item.task_id != bundle.task_id
        || stage.item.scope_id != bundle.scope_id
        || stage.item.state_fence != bundle.state_fence
        || stage.item.receipt != candidate.validated.receipt
        || stage.supplements.expected_receipt != candidate.validated.receipt
        || stage.supplements.frozen_bundle_digest != candidate.validated.receipt.bundle_digest
        || stage.supplements.frozen_manifest_digest != grounded.manifest_digest
    {
        return Err(PulseError::Boundary("conflict structured grounding predecessor"));
    }
    Ok(())
}

fn check_classification_binding(
    stage: &ClassificationStage<'_>,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
) -> Result<(), PulseError> {
    let context = stage.context;
    if context.bundle != bundle
        || context.job.job_id != model_outcome.job_id
        || context.receipt.job_id != model_outcome.job_id
        || context.receipt.bundle_digest != model_outcome.bundle_digest
        || context.grounded.job_id != model_outcome.job_id
        || context.grounded.draft_digest != context.receipt.draft_digest
        || stage.input.item.task_id != bundle.task_id
        || stage.input.item.scope_id != bundle.scope_id
        || stage.input.item.state_fence != bundle.state_fence
        || stage.input.item.receipt.bundle_digest != model_outcome.bundle_digest
    {
        return Err(PulseError::Boundary("classification admitted binding"));
    }
    Ok(())
}

fn check_cue_binding(
    stage: &CueActivationStage<'_>,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    if stage.candidate.scope_id.as_str() != bundle.scope_id
        || stage.candidate.snapshot.state_fence != bundle.state_fence
        || stage.request.state_fence != bundle.state_fence
    {
        return Err(PulseError::Boundary("cue snapshot scope or fence"));
    }
    Ok(())
}

fn check_epistemic_binding(
    request: &PositionRequest,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    if request.scope != bundle.scope_id || request.state_fence != bundle.state_fence {
        return Err(PulseError::Boundary("epistemic scope or fence"));
    }
    Ok(())
}

fn check_understanding_binding(
    stage: &UnderstandingStage<'_, MeasureFn>,
    bundle: &DreamInputBundle,
    projections: &CanonicalProjectionSet,
) -> Result<(), PulseError> {
    let binding = &stage.admitted.binding;
    if binding.task_id.as_str() != bundle.task_id
        || binding.scope_id.as_str() != bundle.scope_id
        || binding.state_fence != bundle.state_fence
        || binding != &stage.recipe.binding
        || binding != &stage.quality.binding
        || binding != &projections.binding
    {
        return Err(PulseError::Boundary("understanding and projection identity"));
    }
    Ok(())
}

fn check_grounding_binding(
    request: &GroundingRequest,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
) -> Result<(), PulseError> {
    let draft = &request.draft;
    let Some(actual_route) = model_outcome
        .execution
        .as_ref()
        .and_then(|execution| execution.grounding_route.as_ref())
    else {
        return Err(PulseError::Boundary("model owner has no physical grounding route"));
    };
    if &request.bundle != bundle
        || &draft.bundle != bundle
        || request.job.job_id != model_outcome.job_id
        || draft.job_id != model_outcome.job_id
        || draft.bundle_digest != model_outcome.bundle_digest
        || draft.task_id.as_str() != bundle.task_id
        || draft.scope_id != bundle.scope_id
        || draft.state_fence != bundle.state_fence
        || &draft.route != actual_route
    {
        return Err(PulseError::Boundary("grounding model or bundle binding"));
    }
    Ok(())
}

fn check_rival_binding(
    stage: &RivalStage<'_>,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
) -> Result<(), PulseError> {
    let candidate = stage.validated_draft;
    let grounded = candidate.input.grounded.as_ref();
    if stage.bundle != bundle
        || grounded.job_id != model_outcome.job_id
        || grounded.input.bundle != *bundle
        || grounded.input.bundle_digest != model_outcome.bundle_digest
        || grounded.input.task_id.as_str() != bundle.task_id
        || grounded.input.scope_id != bundle.scope_id
        || grounded.input.state_fence != bundle.state_fence
        || candidate.validated.receipt.job_id != model_outcome.job_id
        || candidate.validated.receipt.bundle_digest != model_outcome.bundle_digest
        || candidate.validated.receipt.task_id != bundle.task_id
        || candidate.validated.receipt.scope_id != bundle.scope_id
        || candidate.validated.receipt.state_fence != bundle.state_fence
        || stage.current_position.scope != bundle.scope_id
        || stage.current_position.state_fence != bundle.state_fence
    {
        return Err(PulseError::Boundary("rival model route or bundle binding"));
    }
    Ok(())
}

fn failed_run(
    mut stages: Vec<PulseStage>,
    outputs: StageOutputSet,
    failed_stage: PulseStageId,
    failure: PulseError,
) -> MandatoryStageRun {
    stages.push(PulseStage::blocked(failed_stage, "mandatory owner refused"));
    let mut failed_at = false;
    for id in MANDATORY_STAGES {
        if id == failed_stage {
            failed_at = true;
            continue;
        }
        if failed_at && !stages.iter().any(|stage| stage.id == id) {
            stages.push(PulseStage::blocked(id, "mandatory predecessor refused"));
        }
    }
    MandatoryStageRun {
        stages,
        outputs,
        failure: Some(failure),
    }
}

fn residue(kind: &str, text: &str, source: &str) -> OrientationResidue {
    OrientationResidue {
        kind: kind.to_owned(),
        text: text.to_owned(),
        source: source.to_owned(),
    }
}

fn canonical_residue<T: Serialize>(kind: &str, value: &T, source: &str) -> Option<OrientationResidue> {
    let text = String::from_utf8(canonical_bytes(value).ok()?).ok()?;
    Some(residue(kind, &text, source))
}

fn dimension_names(dimensions: &[eliot_dreamer_conflict_analysis::ComparisonDimension]) -> String {
    dimensions
        .iter()
        .map(|dimension| dimension.as_str())
        .collect::<Vec<_>>()
        .join(",")
}
