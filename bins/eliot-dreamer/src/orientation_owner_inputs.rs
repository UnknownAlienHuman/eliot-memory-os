//! Immutable stage-owner view and retained result set for one production call.

use eliot_context_assembly::ActiveUnderstandingViewResult;
use eliot_context_candidates::ContextCandidateSetResult;
use eliot_context_contracts::{CanonicalProjectionSet, ContextError, SerializedContextMeasurement};
use eliot_cue_activation::CueActivationEvaluation;
use eliot_dreamer_claim_grounding::GroundingRequest;
use eliot_dreamer_classification::ClassificationResult;
use eliot_dreamer_conflict_analysis::ConflictAnalysisCandidate;
use eliot_dreamer_contracts::grounding::GroundedDreamDraft as StructuredGroundedDreamDraft;
use eliot_dreamer_contracts::rival::RivalModelSet as ProbeRivalModelSet;
use eliot_dreamer_contracts::{
    DreamInputBundle, ModelDraft, ModelRouteOutcome, ValidatedGroundingCandidate, canonical_bytes,
};
use eliot_dreamer_orientation::{
    InertProbe, OrientationInterpretation, OrientationResidue, OrientationSemanticView,
    OrientationStageOutput,
};
use eliot_dreamer_probe_plan::{ProbePlan, ProbePlanParams, ProbeProposal};
use eliot_dreamer_rival_model::RivalModelSet;
use eliot_epistemic::{CurrentEpistemicPosition, ObservationRecord, PositionRequest};
use eliot_epistemic_contracts::EpistemicPositionCandidate;
use serde::Serialize;

use crate::pulse::{
    CandidateStage, ClassificationStage, ConflictStage, CueActivationStage, EpistemicStage,
    PulseError, PulseStage, PulseStageId, RivalStage, StageOwnerOutput, UnderstandingStage,
    canonical_input_commitment, check_model_boundary, check_projection_boundary,
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
    /// Original candidate retained by the Governor readback owner.
    pub admitted_candidate: &'a EpistemicPositionCandidate,
    /// Original source observation retained by the Governor readback owner.
    pub source_observation: &'a ObservationRecord,
    pub understanding: UnderstandingStage<'a, MeasureFn>,
    pub grounding: &'a GroundingRequest,
    pub rivals: RivalStage<'a>,
    pub conflict: ConflictStage<'a>,
    pub probes: ProbePlanParams<'a>,
    pub candidates: CandidateStage<'a>,
}

/// Typed native outputs retained from the exact mandatory owner calls.
pub(crate) struct StageOutputSet {
    boundary_predecessors: Vec<String>,
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
            boundary_predecessors: Vec::with_capacity(2),
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
            inert_probes: model_draft
                .recommended_probes
                .iter()
                .map(|text| InertProbe {
                    text: text.clone(),
                    status: "model_recommendation_inert".to_owned(),
                    result_space: None,
                })
                .collect(),
            stage_outputs: Vec::with_capacity(9),
        }
    }

    fn bind_boundary_predecessors(
        &mut self,
        model_outcome: &ModelRouteOutcome,
        projections: &CanonicalProjectionSet,
    ) -> bool {
        let (Some(model), Some(projection)) = (
            canonical_input_commitment(model_outcome),
            canonical_input_commitment(projections),
        ) else {
            return false;
        };
        self.boundary_predecessors = vec![model, projection];
        true
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
            && self.boundary_predecessors.len() == 2
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
        if stage.id != PulseStageId::Conflict && stage.canonical_output.is_none() {
            return false;
        }
        let (Some(owner_output), Some(input_digest), Some(output_digest)) = (
            stage.owner_output.take(),
            stage.input_commitment.as_ref(),
            stage.output_commitment.as_ref(),
        ) else {
            return false;
        };
        if self.boundary_predecessors.len() != 2 {
            return false;
        }
        let mut predecessor_commitments = self.boundary_predecessors.clone();
        predecessor_commitments.extend(
            self.stage_outputs
                .iter()
                .map(|prior| prior.output_digest.clone()),
        );
        let semantic_lengths = (
            self.interpretations.len(),
            self.rival_items.len(),
            self.gaps.len(),
            self.inert_probes.len(),
        );
        if !self.retain_owner_output(owner_output) {
            self.interpretations.truncate(semantic_lengths.0);
            self.rival_items.truncate(semantic_lengths.1);
            self.gaps.truncate(semantic_lengths.2);
            self.inert_probes.truncate(semantic_lengths.3);
            return false;
        }
        self.stage_outputs.push(OrientationStageOutput {
            stage: stage.id.as_str().to_owned(),
            input_digest: input_digest.clone(),
            output_digest: output_digest.clone(),
            predecessor_commitments,
            canonical_output: stage.canonical_output.take(),
        });
        true
    }

    fn retain_owner_output(&mut self, output: StageOwnerOutput) -> bool {
        match output {
            StageOwnerOutput::Classification(output) => self.classification = Some(*output),
            StageOwnerOutput::CueActivation(output) => self.cue_activation = Some(output),
            StageOwnerOutput::EpistemicPosition(output) => {
                if !retain_epistemic_semantics(self, &output) {
                    return false;
                }
                self.epistemic_position = Some(output);
            }
            StageOwnerOutput::Understanding(output) => self.understanding = Some(*output),
            StageOwnerOutput::Grounding(output) => {
                if !retain_grounding_semantics(self, &output) {
                    return false;
                }
                self.grounding = Some(*output);
            }
            StageOwnerOutput::Rivals(output) => {
                if !retain_rival_semantics(self, &output) {
                    return false;
                }
                self.rivals = Some(output);
            }
            StageOwnerOutput::Conflict(output) => {
                if !retain_conflict_semantics(self, &output) {
                    return false;
                }
                self.conflict = Some(output);
            }
            StageOwnerOutput::Probes(output) => {
                if !retain_probe_semantics(self, &output) {
                    return false;
                }
                self.probes = Some(output);
            }
            StageOwnerOutput::Candidates(output) => {
                if !retain_candidate_semantics(self, &output) {
                    return false;
                }
                self.candidates = Some(output);
            }
        }
        true
    }
}

fn retain_epistemic_semantics(
    target: &mut StageOutputSet,
    output: &CurrentEpistemicPosition,
) -> bool {
    let Some(position) = canonical_residue("epistemic_position", output, "epistemic_position")
    else {
        return false;
    };
    target.rival_items.push(position);
    if !push_count_residue(
        &mut target.gaps,
        "epistemic_unknown_count",
        output.unknowns.len(),
        "epistemic_position",
    ) || !push_count_residue(
        &mut target.gaps,
        "epistemic_required_inquiry_count",
        output.required_inquiry.len(),
        "epistemic_position",
    ) {
        return false;
    }
    target.gaps.extend(
        output
            .unknowns
            .iter()
            .map(|text| residue("epistemic_unknown", text, "epistemic_position")),
    );
    target.gaps.extend(
        output
            .required_inquiry
            .iter()
            .map(|text| residue("required_inquiry", text, "epistemic_position")),
    );
    true
}

fn retain_grounding_semantics(
    target: &mut StageOutputSet,
    output: &StructuredGroundedDreamDraft,
) -> bool {
    let Some(ledger) = canonical_residue("claim_grounding_ledger", &output.ledger, &output.job_id)
    else {
        return false;
    };
    target.gaps.push(ledger);
    true
}

fn retain_rival_semantics(target: &mut StageOutputSet, output: &RivalModelSet) -> bool {
    let source = output.source_set.set_id.as_str();
    for assessment in &output.assessments {
        let Some(entry) = canonical_residue("rival_assessment", assessment, source) else {
            return false;
        };
        target.rival_items.push(entry);
    }
    for unknown in &output.unknown_slots {
        let Some(entry) = canonical_residue("rival_unknown_facet", unknown, source) else {
            return false;
        };
        target.gaps.push(entry);
    }
    if output.unknown_omitted_count != 0 {
        target.gaps.push(residue(
            "rival_unknown_frontier",
            &output.unknown_omitted_count.to_string(),
            source,
        ));
    }
    retain_rival_frontier(target, output, source)
}

fn retain_rival_frontier(
    target: &mut StageOutputSet,
    output: &RivalModelSet,
    source: &str,
) -> bool {
    for (index, model) in output.omission_frontier.model_ids.iter().enumerate() {
        let frontier_source = format!("{source}:omission_frontier:{index}");
        let Some(entry) = canonical_residue("rival_omission_frontier", model, &frontier_source)
        else {
            return false;
        };
        target.gaps.push(entry);
    }
    true
}

fn retain_probe_semantics(target: &mut StageOutputSet, output: &ProbePlan) -> bool {
    let source = output.plan_id.as_str();
    if !push_count_residue(
        &mut target.gaps,
        "probe_plan_count",
        output.probes.len(),
        source,
    ) || !push_count_residue(
        &mut target.gaps,
        "probe_plan_omissions_count",
        output.omissions.len(),
        source,
    ) {
        return false;
    }
    for (index, probe) in output.probes.iter().enumerate() {
        if !retain_one_probe(target, probe, source, index) {
            return false;
        }
    }
    retain_probe_omissions(target, output)
}

fn retain_one_probe(
    target: &mut StageOutputSet,
    probe: &ProbeProposal,
    source: &str,
    index: usize,
) -> bool {
    let (Some(text), Some(result_space)) =
        (canonical_text(probe), canonical_text(&probe.result_schema))
    else {
        return false;
    };
    target.inert_probes.push(InertProbe {
        text,
        status: "candidate_only".to_owned(),
        result_space: Some(result_space),
    });
    let probe_source = format!("{source}:probe:{index}");
    let Some(rank) = canonical_residue("probe_plan_rank", &probe.rank, &probe_source) else {
        return false;
    };
    target.gaps.push(rank);
    true
}

fn retain_probe_omissions(target: &mut StageOutputSet, output: &ProbePlan) -> bool {
    for omission in &output.omissions {
        let Some(entry) =
            canonical_residue("probe_plan_omission", omission, output.plan_id.as_str())
        else {
            return false;
        };
        target.gaps.push(entry);
    }
    true
}

fn retain_candidate_semantics(
    target: &mut StageOutputSet,
    output: &ContextCandidateSetResult,
) -> bool {
    for candidate in &output.set.candidates {
        let Some(entry) =
            canonical_residue("context_candidate", candidate, candidate.atom_id.as_str())
        else {
            return false;
        };
        target.rival_items.push(entry);
    }
    if !retain_candidate_omissions(target, output) {
        return false;
    }
    for frontier in &output.frontier {
        let Some(entry) = canonical_residue(
            "context_candidate_frontier",
            frontier,
            "context_candidate_set",
        ) else {
            return false;
        };
        target.gaps.push(entry);
    }
    true
}

fn retain_candidate_omissions(
    target: &mut StageOutputSet,
    output: &ContextCandidateSetResult,
) -> bool {
    for omission in &output.omissions {
        let Some(entry) = canonical_residue(
            "context_candidate_omission",
            omission,
            omission.atom_id.as_str(),
        ) else {
            return false;
        };
        target.gaps.push(entry);
    }
    true
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

type StageFailure = (PulseStageId, PulseError);

struct StageAccumulator {
    stages: Vec<PulseStage>,
    outputs: StageOutputSet,
}

impl StageAccumulator {
    fn new(model_draft: &ModelDraft) -> Self {
        Self {
            stages: Vec::with_capacity(MANDATORY_STAGES.len()),
            outputs: StageOutputSet::new(model_draft),
        }
    }

    fn block_all(self, failure: PulseError) -> MandatoryStageRun {
        MandatoryStageRun {
            stages: MANDATORY_STAGES
                .map(|id| PulseStage::blocked(id, "mandatory boundary binding refused"))
                .into(),
            outputs: self.outputs,
            failure: Some(failure),
        }
    }

    fn execute<F>(
        &mut self,
        id: PulseStageId,
        binding: Result<(), PulseError>,
        owner_call: F,
    ) -> Result<(), StageFailure>
    where
        F: FnOnce() -> Result<PulseStage, PulseError>,
    {
        binding.map_err(|error| (id, error))?;
        let mut stage = owner_call().map_err(|error| (id, error))?;
        if !self.outputs.retain_stage(&mut stage) {
            return Err((
                id,
                PulseError::Boundary("mandatory stage output commitment"),
            ));
        }
        self.stages.push(stage);
        Ok(())
    }

    fn retain_result(
        &mut self,
        id: PulseStageId,
        owner_result: Result<PulseStage, PulseError>,
    ) -> Result<(), StageFailure> {
        let mut stage = owner_result.map_err(|error| (id, error))?;
        if !self.outputs.retain_stage(&mut stage) {
            return Err((
                id,
                PulseError::Boundary("mandatory stage output commitment"),
            ));
        }
        self.stages.push(stage);
        Ok(())
    }

    fn failed(self, id: PulseStageId, failure: PulseError) -> MandatoryStageRun {
        failed_run(self.stages, self.outputs, id, failure)
    }

    fn completed(self) -> MandatoryStageRun {
        MandatoryStageRun {
            stages: self.stages,
            outputs: self.outputs,
            failure: None,
        }
    }
}

/// Runs each named owner once in denominator order after checking the exact
/// route and canonical-projection boundaries.
pub(crate) fn run_mandatory_stages(
    inputs: &OrientationOwnerInputs<'_>,
    model_draft: &ModelDraft,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
    projections: &CanonicalProjectionSet,
) -> MandatoryStageRun {
    let mut run = StageAccumulator::new(model_draft);
    let preflight = check_model_boundary(model_outcome, bundle)
        .and_then(|()| check_projection_boundary(projections, bundle))
        .and_then(|()| {
            if model_outcome.draft.as_ref() == Some(model_draft) {
                Ok(())
            } else {
                Err(PulseError::Boundary("model route draft binding"))
            }
        });
    if let Err(error) = preflight {
        return run.block_all(error);
    }
    if !run
        .outputs
        .bind_boundary_predecessors(model_outcome, projections)
    {
        return run.block_all(PulseError::Boundary("mandatory boundary commitment"));
    }

    let initial = run_initial_stages(&mut run, inputs, bundle, model_outcome, projections);
    if let Err((id, error)) = initial {
        return run.failed(id, error);
    }
    let grounded = run_grounding_rival_conflict(&mut run, inputs, bundle, model_outcome);
    if let Err((id, error)) = grounded {
        return run.failed(id, error);
    }
    let probes = run_probe_stage_from_predecessors(&mut run, inputs, bundle, model_outcome);
    if let Err((id, error)) = probes {
        return run.failed(id, error);
    }
    let candidates = run_candidate_stage_from_predecessors(&mut run, inputs, bundle, projections);
    if let Err((id, error)) = candidates {
        return run.failed(id, error);
    }
    run.completed()
}

fn run_initial_stages(
    run: &mut StageAccumulator,
    inputs: &OrientationOwnerInputs<'_>,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
    projections: &CanonicalProjectionSet,
) -> Result<(), StageFailure> {
    run.execute(
        PulseStageId::Classification,
        check_classification_binding(&inputs.classification, bundle, model_outcome),
        || run_classification_stage(Some(&inputs.classification)),
    )?;
    run.execute(
        PulseStageId::CueActivation,
        check_cue_binding(&inputs.cue_activation, bundle),
        || run_cue_stage(Some(&inputs.cue_activation)),
    )?;
    run.execute(
        PulseStageId::EpistemicPosition,
        check_epistemic_binding(
            inputs.epistemic,
            inputs.admitted_candidate,
            inputs.rivals.current_position,
            bundle,
        ),
        || {
            run_epistemic_stage(Some(&EpistemicStage {
                candidate: inputs.admitted_candidate,
                admitted_position: inputs.rivals.current_position,
                observation: inputs.source_observation,
                request: inputs.epistemic,
            }))
        },
    )?;
    run.execute(
        PulseStageId::Understanding,
        check_understanding_binding(&inputs.understanding, bundle, projections),
        || {
            run_understanding_stage(Some(UnderstandingStage {
                admitted: inputs.understanding.admitted,
                recipe: inputs.understanding.recipe,
                quality: inputs.understanding.quality,
                policy: inputs.understanding.policy,
                measure: inputs.understanding.measure,
            }))
        },
    )
}

fn run_grounding_rival_conflict(
    run: &mut StageAccumulator,
    inputs: &OrientationOwnerInputs<'_>,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
) -> Result<(), StageFailure> {
    run.execute(
        PulseStageId::Grounding,
        check_grounding_binding(inputs.grounding, bundle, model_outcome),
        || run_grounding_stage(Some(inputs.grounding)),
    )?;
    if run.outputs.grounding.as_ref() != Some(inputs.rivals.validated_draft.input.grounded.as_ref())
    {
        return Err((
            PulseStageId::Rivals,
            PulseError::Boundary("rival validated candidate grounding predecessor"),
        ));
    }
    run.execute(
        PulseStageId::Rivals,
        check_rival_binding(&inputs.rivals, bundle, model_outcome),
        || run_rival_stage(Some(&inputs.rivals)),
    )?;

    let candidate = inputs.rivals.validated_draft;
    let grounding_route = model_outcome
        .execution
        .as_ref()
        .and_then(|execution| execution.grounding_route.as_ref());
    if grounding_route.is_none_or(|route| route != &candidate.input.grounded.input.route) {
        return Err((
            PulseStageId::Conflict,
            PulseError::Boundary("structured grounding route lacks exact physical-route lineage"),
        ));
    }
    run.execute(
        PulseStageId::Conflict,
        check_conflict_binding(&inputs.conflict, candidate, bundle),
        || run_conflict_stage(Some(&inputs.conflict), Some(candidate)),
    )
}

fn run_probe_stage_from_predecessors(
    run: &mut StageAccumulator,
    inputs: &OrientationOwnerInputs<'_>,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
) -> Result<(), StageFailure> {
    let Some(native_rivals) = run.outputs.rivals.as_ref() else {
        return Err((
            PulseStageId::Probes,
            PulseError::Boundary("native rival predecessor missing"),
        ));
    };
    let Ok(probe_projection) = native_rivals.to_probe_projection() else {
        return Err((PulseStageId::Probes, PulseError::Probes));
    };
    run.outputs.probe_rival_projection = Some(probe_projection.clone());
    let candidate = inputs.rivals.validated_draft;
    if !probe_inputs_match(inputs, bundle, model_outcome, candidate, &probe_projection) {
        return Err((
            PulseStageId::Probes,
            PulseError::Boundary("probe candidate and rival predecessor bindings"),
        ));
    }
    let probe_params = ProbePlanParams {
        plan_id: inputs.probes.plan_id.clone(),
        bundle,
        draft: &candidate.validated,
        rivals: &probe_projection,
        affordances: inputs.probes.affordances,
        limits: inputs.probes.limits,
        policy: inputs.probes.policy,
    };
    run.execute(PulseStageId::Probes, Ok(()), || {
        run_probe_stage(Some(probe_params))
    })
}

fn probe_inputs_match(
    inputs: &OrientationOwnerInputs<'_>,
    bundle: &DreamInputBundle,
    model_outcome: &ModelRouteOutcome,
    candidate: &ValidatedGroundingCandidate,
    probe_rivals: &ProbeRivalModelSet,
) -> bool {
    inputs.probes.bundle == bundle
        && inputs.probes.draft == &candidate.validated
        && inputs.probes.affordances.task_id.as_str() == bundle.task_id
        && inputs.probes.affordances.scope == bundle.scope_id
        && inputs.probes.affordances.state_fence == bundle.state_fence
        && probe_rivals.bundle_digest == model_outcome.bundle_digest
        && probe_rivals.validated_input_digest == candidate.validated.receipt.input_digest
        && probe_rivals.task_id.as_str() == bundle.task_id
        && probe_rivals.scope == bundle.scope_id
        && probe_rivals.state_fence == bundle.state_fence
}

fn run_candidate_stage_from_predecessors(
    run: &mut StageAccumulator,
    inputs: &OrientationOwnerInputs<'_>,
    bundle: &DreamInputBundle,
    projections: &CanonicalProjectionSet,
) -> Result<(), StageFailure> {
    let conflict_set = inputs.conflict.conflict_set;
    let binding_ok = inputs.candidates.request.binding.task_id.as_str() == bundle.task_id
        && inputs.candidates.request.binding.scope_id.as_str() == bundle.scope_id
        && inputs.candidates.request.binding.state_fence == bundle.state_fence
        && inputs.candidates.epistemic_position.is_some_and(|view| {
            &view.position == inputs.rivals.current_position
                && view.position.admission.scope == bundle.scope_id
                && view.position.admission.fence == bundle.state_fence
        });
    if !binding_ok {
        return Err((
            PulseStageId::Candidates,
            PulseError::Boundary("candidate context owner bindings"),
        ));
    }
    let owner_result = run_candidate_stage(
        Some(projections),
        Some(&inputs.candidates),
        run.outputs.cue_activation.as_ref(),
        Some(conflict_set),
    );
    run.retain_result(PulseStageId::Candidates, owner_result)
}

fn check_conflict_binding(
    stage: &ConflictStage<'_>,
    candidate: &ValidatedGroundingCandidate,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    let grounded = candidate.input.grounded.as_ref();
    if grounded.input.bundle != *bundle
        || grounded.input.bundle_digest != candidate.validated.receipt.bundle_digest
        || grounded.input.job.canonical_id() != candidate.validated.receipt.job_id
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
        return Err(PulseError::Boundary(
            "conflict structured grounding predecessor",
        ));
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
        || context.job.canonical_id() != model_outcome.job_id
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
    candidate: &EpistemicPositionCandidate,
    admitted_position: &eliot_epistemic_contracts::CurrentEpistemicPosition,
    bundle: &DreamInputBundle,
) -> Result<(), PulseError> {
    if request.scope != bundle.scope_id
        || request.state_fence != bundle.state_fence
        || candidate.scope != bundle.scope_id
        || candidate.fence != bundle.state_fence
        || admitted_position.admission.scope != bundle.scope_id
        || admitted_position.admission.fence != bundle.state_fence
    {
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
        return Err(PulseError::Boundary(
            "understanding and projection identity",
        ));
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
        return Err(PulseError::Boundary(
            "model owner has no physical grounding route",
        ));
    };
    if &request.bundle != bundle
        || &draft.bundle != bundle
        || request.job.canonical_id() != model_outcome.job_id
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
        || stage.current_position.admission.scope != bundle.scope_id
        || stage.current_position.admission.fence != bundle.state_fence
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
    let reason = match &failure {
        PulseError::EpistemicBinding(error) => error.stage_disposition(),
        _ => "mandatory owner refused",
    };
    stages.push(PulseStage::blocked(failed_stage, reason));
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

fn canonical_residue<T: Serialize>(
    kind: &str,
    value: &T,
    source: &str,
) -> Option<OrientationResidue> {
    Some(residue(kind, &canonical_text(value)?, source))
}

fn canonical_text<T: Serialize>(value: &T) -> Option<String> {
    String::from_utf8(canonical_bytes(value).ok()?).ok()
}

fn push_count_residue(
    target: &mut Vec<OrientationResidue>,
    kind: &str,
    count: usize,
    source: &str,
) -> bool {
    let Some(entry) = canonical_residue(kind, &count, source) else {
        return false;
    };
    target.push(entry);
    true
}

fn push_string_sequence(
    target: &mut Vec<OrientationResidue>,
    kind: &str,
    values: &[String],
    source: &str,
) -> bool {
    if !push_count_residue(target, &format!("{kind}_count"), values.len(), source) {
        return false;
    }
    for (index, value) in values.iter().enumerate() {
        let Some(entry) = canonical_residue(kind, value, &format!("{source}:{kind}:{index}"))
        else {
            return false;
        };
        target.push(entry);
    }
    true
}

#[derive(Serialize)]
struct ConflictProbe<'a> {
    probe_id: &'a str,
    objective_digest: &'a str,
    result_digest: &'a str,
    discriminates_positions: &'a [String],
    resolves_unknown: Option<&'a str>,
    owner: &'a str,
    verifier: &'a str,
    cost_note: &'a str,
    risk_note: &'a str,
    privacy_note: &'a str,
    effect_note: &'a str,
}

macro_rules! push_canonical {
    ($target:expr, $kind:expr, $value:expr, $source:expr) => {{
        let Some(entry) = canonical_residue($kind, $value, $source) else {
            return false;
        };
        ($target).push(entry);
    }};
}

fn retain_conflict_semantics(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
) -> bool {
    let source = output.conflict_id.as_str();
    retain_conflict_header(target, output, source)
        && retain_conflict_positions(target, output, source)
        && retain_conflict_lineage(target, output, source)
        && retain_conflict_risks(target, output, source)
        && retain_conflict_objections(target, output, source)
        && retain_conflict_sequences(target, output, source)
        && retain_conflict_recommended_probes(target, output, source)
        && retain_conflict_preservation(target, output, source)
        && retain_conflict_causal_states(target, output, source)
}

fn retain_conflict_header(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    push_canonical!(
        &mut target.gaps,
        "conflict_outcome",
        &output.outcome.as_str(),
        source
    );
    push_canonical!(&mut target.gaps, "conflict_scope", &output.scope, source);
    push_canonical!(
        &mut target.gaps,
        "conflict_candidate_digest",
        &output.candidate_digest,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_analysis_note",
        &output.note,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_independent_root_count",
        &output.independent_root_count,
        source
    );
    push_count_residue(
        &mut target.rival_items,
        "conflict_positions_count",
        output.positions.len(),
        source,
    ) && push_count_residue(
        &mut target.gaps,
        "conflict_lineage_groups_count",
        output.lineage_groups.len(),
        source,
    ) && push_count_residue(
        &mut target.gaps,
        "conflict_common_mode_risks_count",
        output.common_mode_risks.len(),
        source,
    ) && push_count_residue(
        &mut target.gaps,
        "conflict_objections_count",
        output.objections.len(),
        source,
    ) && push_count_residue(
        &mut target.gaps,
        "conflict_recommended_probes_count",
        output.recommended_probes.len(),
        source,
    ) && push_count_residue(
        &mut target.gaps,
        "conflict_preservation_verdicts_count",
        output.preservation.verdicts.len(),
        source,
    ) && push_count_residue(
        &mut target.gaps,
        "conflict_causal_states_count",
        output.causal_states.len(),
        source,
    )
}

fn retain_conflict_positions(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    for (index, position) in output.positions.iter().enumerate() {
        let position_source = format!("{source}:position:{index}");
        if !retain_conflict_position(target, position, &position_source) {
            return false;
        }
    }
    true
}

fn retain_conflict_position(
    target: &mut StageOutputSet,
    position: &eliot_dreamer_conflict_analysis::PositionAnalysis,
    source: &str,
) -> bool {
    push_canonical!(
        &mut target.rival_items,
        "conflict_position_index",
        &position.position_index,
        source
    );
    push_canonical!(
        &mut target.rival_items,
        "conflict_position_source",
        &position.source_handle,
        source
    );
    push_canonical!(
        &mut target.rival_items,
        "conflict_position_stance",
        &position.stance,
        source
    );
    push_canonical!(
        &mut target.rival_items,
        "conflict_position_minority",
        &position.minority,
        source
    );
    push_canonical!(
        &mut target.rival_items,
        "conflict_position_disposition",
        &position.disposition.as_str(),
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_position_compatibility_note",
        &position.compatibility_note,
        source
    );
    if !push_count_residue(
        &mut target.gaps,
        "conflict_position_classes_count",
        position.conflict_classes.len(),
        source,
    ) {
        return false;
    }
    for (index, conflict_class) in position.conflict_classes.iter().enumerate() {
        let class_source = format!("{source}:class:{index}");
        push_canonical!(
            &mut target.gaps,
            "conflict_position_class",
            conflict_class,
            &class_source
        );
    }
    if !push_string_sequence(
        &mut target.gaps,
        "conflict_position_assumption",
        &position.assumptions,
        source,
    ) || !push_string_sequence(
        &mut target.gaps,
        "conflict_position_counter",
        &position.counters,
        source,
    ) || !push_count_residue(
        &mut target.gaps,
        "conflict_position_compatibilities_count",
        position.compatibility.len(),
        source,
    ) {
        return false;
    }
    retain_conflict_compatibilities(target, position, source)
}

fn retain_conflict_compatibilities(
    target: &mut StageOutputSet,
    position: &eliot_dreamer_conflict_analysis::PositionAnalysis,
    source: &str,
) -> bool {
    for (index, compatibility) in position.compatibility.iter().enumerate() {
        let compatibility_source = format!("{source}:compatibility:{index}");
        if !retain_conflict_compatibility(target, compatibility, &compatibility_source) {
            return false;
        }
    }
    true
}

fn retain_conflict_compatibility(
    target: &mut StageOutputSet,
    compatibility: &eliot_dreamer_conflict_analysis::PositionCompatibility,
    source: &str,
) -> bool {
    push_canonical!(
        &mut target.gaps,
        "conflict_compatibility_other_source",
        &compatibility.other_source,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_compatibility_relation",
        &compatibility.relation.as_str(),
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_compatibility_supplement_version",
        &compatibility.supplement_version.as_str(),
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_compatibility_derivation_note",
        &compatibility.derivation_note,
        source
    );
    if !push_count_residue(
        &mut target.gaps,
        "conflict_compatibility_outcomes_count",
        compatibility.outcomes.len(),
        source,
    ) || !push_count_residue(
        &mut target.gaps,
        "conflict_compatibility_differing_dimensions_count",
        compatibility.differing_dimensions.len(),
        source,
    ) || !push_count_residue(
        &mut target.gaps,
        "conflict_compatibility_unnormalizable_dimensions_count",
        compatibility.unnormalizable_dimensions.len(),
        source,
    ) || !push_count_residue(
        &mut target.gaps,
        "conflict_compatibility_unsupported_dimensions_count",
        compatibility.unsupported_dimensions.len(),
        source,
    ) {
        return false;
    }
    if !retain_conflict_comparisons(target, compatibility, source)
        || !retain_conflict_dimensions(target, compatibility, source)
    {
        return false;
    }
    push_canonical!(
        &mut target.gaps,
        "conflict_compatibility_coverage",
        &compatibility.coverage,
        source
    );
    true
}

fn retain_conflict_comparisons(
    target: &mut StageOutputSet,
    compatibility: &eliot_dreamer_conflict_analysis::PositionCompatibility,
    source: &str,
) -> bool {
    for (index, comparison) in compatibility.outcomes.iter().enumerate() {
        let outcome_source = format!("{source}:outcome:{index}");
        push_canonical!(
            &mut target.gaps,
            "conflict_compatibility_dimension",
            &comparison.dimension.as_str(),
            &outcome_source
        );
        if !retain_conflict_comparison_outcome(target, comparison, &outcome_source) {
            return false;
        }
    }
    true
}

fn retain_conflict_comparison_outcome(
    target: &mut StageOutputSet,
    comparison: &eliot_dreamer_conflict_analysis::DimensionComparison,
    source: &str,
) -> bool {
    match &comparison.outcome {
        eliot_dreamer_conflict_analysis::DimensionOutcome::Equal { value } => {
            push_canonical!(
                &mut target.gaps,
                "conflict_compatibility_outcome_kind",
                &"equal",
                source
            );
            push_canonical!(
                &mut target.gaps,
                "conflict_compatibility_equal_value",
                value,
                source
            );
        }
        eliot_dreamer_conflict_analysis::DimensionOutcome::Differing { left, right } => {
            push_canonical!(
                &mut target.gaps,
                "conflict_compatibility_outcome_kind",
                &"differing",
                source
            );
            push_canonical!(
                &mut target.gaps,
                "conflict_compatibility_left",
                left,
                source
            );
            push_canonical!(
                &mut target.gaps,
                "conflict_compatibility_right",
                right,
                source
            );
        }
        eliot_dreamer_conflict_analysis::DimensionOutcome::Unnormalizable { reason } => {
            push_canonical!(
                &mut target.gaps,
                "conflict_compatibility_outcome_kind",
                &"unnormalizable",
                source
            );
            push_canonical!(
                &mut target.gaps,
                "conflict_compatibility_unnormalizable_reason",
                reason,
                source
            );
        }
    }
    true
}

fn retain_conflict_dimensions(
    target: &mut StageOutputSet,
    compatibility: &eliot_dreamer_conflict_analysis::PositionCompatibility,
    source: &str,
) -> bool {
    for (field, dimensions) in [
        ("differing", &compatibility.differing_dimensions),
        ("unnormalizable", &compatibility.unnormalizable_dimensions),
        ("unsupported", &compatibility.unsupported_dimensions),
    ] {
        for (index, dimension) in dimensions.iter().enumerate() {
            let kind = format!("conflict_compatibility_{field}_dimension");
            let dimension_source = format!("{source}:{field}:{index}");
            push_canonical!(
                &mut target.gaps,
                &kind,
                &dimension.as_str(),
                &dimension_source
            );
        }
    }
    true
}

fn retain_conflict_lineage(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    for (index, group) in output.lineage_groups.iter().enumerate() {
        let group_source = format!("{source}:lineage:{index}");
        push_canonical!(
            &mut target.gaps,
            "conflict_lineage_root",
            &group.lineage_root,
            &group_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_lineage_known",
            &group.known,
            &group_source
        );
        if !push_string_sequence(
            &mut target.gaps,
            "conflict_lineage_member",
            &group.member_sources,
            &group_source,
        ) {
            return false;
        }
    }
    true
}

fn retain_conflict_risks(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    for (index, risk) in output.common_mode_risks.iter().enumerate() {
        let risk_source = format!("{source}:common_mode_risk:{index}");
        push_canonical!(
            &mut target.gaps,
            "conflict_risk_kind",
            &risk.kind,
            &risk_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_risk_description",
            &risk.description,
            &risk_source
        );
        if !push_string_sequence(
            &mut target.gaps,
            "conflict_risk_affected_source",
            &risk.affected_sources,
            &risk_source,
        ) {
            return false;
        }
    }
    true
}

fn retain_conflict_objections(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    for (index, objection) in output.objections.iter().enumerate() {
        let objection_source = format!("{source}:objection:{index}");
        push_canonical!(
            &mut target.gaps,
            "conflict_objection_id",
            &objection.objection_id,
            &objection_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_objection_target_source",
            &objection.target_source,
            &objection_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_objection_statement",
            &objection.statement,
            &objection_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_objection_grounded",
            &objection.grounded,
            &objection_source
        );
    }
    true
}

fn retain_conflict_sequences(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    push_string_sequence(
        &mut target.gaps,
        "conflict_counterevidence",
        &output.counterevidence,
        source,
    ) && push_string_sequence(
        &mut target.gaps,
        "conflict_unknown",
        &output.unknowns,
        source,
    ) && push_string_sequence(
        &mut target.gaps,
        "conflict_assumption",
        &output.assumptions,
        source,
    ) && push_string_sequence(
        &mut target.gaps,
        "conflict_invalidation_condition",
        &output.invalidation_conditions,
        source,
    )
}

fn retain_conflict_recommended_probes(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    for probe in &output.recommended_probes {
        let semantic = ConflictProbe {
            probe_id: &probe.probe_id,
            objective_digest: &probe.objective_digest,
            result_digest: &probe.result_digest,
            discriminates_positions: &probe.discriminates_positions,
            resolves_unknown: probe.resolves_unknown.as_deref(),
            owner: &probe.owner,
            verifier: &probe.verifier,
            cost_note: &probe.cost_note,
            risk_note: &probe.risk_note,
            privacy_note: &probe.privacy_note,
            effect_note: &probe.effect_note,
        };
        let (Some(text), Some(result_space)) = (
            canonical_text(&semantic),
            canonical_text(&probe.resolves_unknown),
        ) else {
            return false;
        };
        target.inert_probes.push(InertProbe {
            text,
            status: "candidate_only".to_owned(),
            result_space: Some(result_space),
        });
    }
    retain_recommended_owner(target, output, source)
}

fn retain_recommended_owner(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    push_canonical!(
        &mut target.gaps,
        "conflict_owner_kind",
        &output.recommended_owner.kind.as_str(),
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_owner_handle",
        &output.recommended_owner.owner_handle,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_owner_rationale",
        &output.recommended_owner.rationale,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_owner_contract_needed",
        &output.recommended_owner.contract_needed,
        source
    );
    true
}

fn retain_conflict_preservation(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    for (index, verdict) in output.preservation.verdicts.iter().enumerate() {
        let verdict_source = format!("{source}:preservation:{index}");
        push_canonical!(
            &mut target.gaps,
            "conflict_preservation_dimension",
            &verdict.dimension.as_str(),
            &verdict_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_preservation_passed",
            &verdict.passed,
            &verdict_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_preservation_known",
            &verdict.known,
            &verdict_source
        );
        push_canonical!(
            &mut target.gaps,
            "conflict_preservation_note",
            &verdict.note,
            &verdict_source
        );
    }
    let resolution = output.resolution_status.as_ref().map(|resolution| {
        (
            resolution.decision_digest.as_str(),
            resolution.decided_by.as_str(),
            resolution.note.as_str(),
        )
    });
    push_canonical!(
        &mut target.gaps,
        "conflict_external_resolution",
        &resolution,
        source
    );
    true
}

fn retain_conflict_causal_states(
    target: &mut StageOutputSet,
    output: &ConflictAnalysisCandidate,
    source: &str,
) -> bool {
    for (index, causal) in output.causal_states.iter().enumerate() {
        let causal_source = format!("{source}:causal:{index}");
        if !retain_one_causal_state(target, causal, &causal_source) {
            return false;
        }
    }
    true
}

fn retain_one_causal_state(
    target: &mut StageOutputSet,
    causal: &eliot_dreamer_conflict_analysis::CausalClaimRecord,
    source: &str,
) -> bool {
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_source",
        &causal.source_handle,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_declared_state",
        &causal.declared_state.as_str(),
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_effective_state",
        &causal.effective_state.as_str(),
        source
    );
    let declaration_revision = causal.declaration_revision.as_deref();
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_declaration_revision",
        &declaration_revision,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_supplement_version",
        &causal.supplement_version.as_str(),
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_reduction_reason",
        &causal.reduction_reason,
        source
    );
    let mechanism_claim_id = causal.mechanism_claim_id.as_deref();
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_mechanism_claim_id",
        &mechanism_claim_id,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_overall_coverage",
        &causal.coverage,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_evidence_coverage",
        &causal.evidence_coverage,
        source
    );
    push_canonical!(
        &mut target.gaps,
        "conflict_causal_rival_coverage",
        &causal.rival_coverage,
        source
    );
    true
}
