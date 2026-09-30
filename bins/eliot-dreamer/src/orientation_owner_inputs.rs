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
use eliot_dreamer_contracts::{DreamInputBundle, ModelDraft, ModelRouteOutcome};
use eliot_dreamer_orientation::{
    InertProbe, OrientationInterpretation, OrientationResidue, OrientationSemanticView,
    OrientationStageOutput,
};
use eliot_dreamer_probe_plan::{ProbePlan, ProbePlanParams};
use eliot_dreamer_rival_model::{RivalModelError, RivalModelSet};
use eliot_dreamer_contracts::rival::RivalModelSet as ProbeRivalModelSet;
use eliot_epistemic::PositionRequest;
use eliot_epistemic_contracts::CurrentEpistemicPosition;

use crate::pulse::{
    CandidateStage, ClassificationStage, ConflictStage, CueActivationStage, PulseError,
    PulseStage, PulseStageId, RivalStage, StageOwnerOutput, UnderstandingStage,
    check_model_boundary, check_projection_boundary,
    run_classification_stage, run_cue_stage, run_epistemic_stage, run_grounding_stage,
    run_rival_stage, run_understanding_stage,
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
    pub probe_rival_projection: Option<Result<ProbeRivalModelSet, RivalModelError>>,
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
                self.gaps.push(residue(
                    "claim_grounding_ledger",
                    &format!("{:?}", output.ledger),
                    &output.job_id,
                ));
                self.grounding = Some(output);
            }
            StageOwnerOutput::Rivals(output) => {
                let source = output.source_set.set_id.as_str().to_owned();
                self.rival_items.extend(output.assessments.iter().map(|assessment| {
                    residue(
                        "rival_assessment",
                        &format!("{}: {:?}", assessment.model_id.as_str(), assessment.disposition),
                        &source,
                    )
                }));
                self.gaps.extend(output.unknown_slots.iter().map(|unknown| {
                    residue(
                        "rival_unknown_facet",
                        &format!(
                            "{:?}/{:?} row={:?} entry={:?} member={:?}",
                            unknown.table, unknown.field, unknown.row, unknown.entry, unknown.member
                        ),
                        &source,
                    )
                }));
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
                self.gaps.extend(output.omissions.iter().map(|omission| {
                    residue(
                        "probe_plan_omission",
                        &format!("{omission:?}"),
                        output.plan_id.as_str(),
                    )
                }));
                self.probes = Some(output);
            }
            StageOwnerOutput::Candidates(output) => {
                self.rival_items.extend(output.set.candidates.iter().map(|candidate| {
                    residue(
                        "context_candidate",
                        &format!("{candidate:?}"),
                        "context_candidate_set",
                    )
                }));
                self.gaps.extend(output.omissions.iter().map(|omission| {
                    residue(
                        "context_candidate_omission",
                        &format!("{omission:?}"),
                        "context_candidate_set",
                    )
                }));
                self.gaps.extend(output.frontier.iter().map(|frontier| {
                    residue(
                        "context_candidate_frontier",
                        &format!("{frontier:?}"),
                        "context_candidate_set",
                    )
                }));
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
        ($owner_call:expr, $id:expr, $input_digest:expr) => {{
            let mut stage = match $owner_call {
                Ok(stage) => stage,
                Err(error) => {
                    return failed_run(stages, outputs, $id, error);
                }
            };
            stage.input_commitment = Some($input_digest.to_owned());
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

    let bundle_commitment = model_outcome.bundle_digest.as_str();
    run_and_retain!(
        run_classification_stage(Some(&inputs.classification)),
        PulseStageId::Classification,
        bundle_commitment
    );
    run_and_retain!(
        run_cue_stage(Some(&inputs.cue_activation)),
        PulseStageId::CueActivation,
        bundle_commitment
    );
    run_and_retain!(
        run_epistemic_stage(Some(inputs.epistemic)),
        PulseStageId::EpistemicPosition,
        bundle_commitment
    );
    run_and_retain!(
        run_understanding_stage(Some(UnderstandingStage {
            admitted: inputs.understanding.admitted,
            recipe: inputs.understanding.recipe,
            quality: inputs.understanding.quality,
            policy: inputs.understanding.policy,
            measure: inputs.understanding.measure,
        })),
        PulseStageId::Understanding,
        bundle_commitment
    );
    run_and_retain!(
        run_grounding_stage(Some(inputs.grounding)),
        PulseStageId::Grounding,
        bundle_commitment
    );
    run_and_retain!(
        run_rival_stage(Some(&inputs.rivals)),
        PulseStageId::Rivals,
        bundle_commitment
    );

    let probe_projection = outputs
        .rivals
        .as_ref()
        .map(RivalModelSet::to_probe_projection);
    if let Some(projection) = probe_projection {
        outputs.probe_rival_projection = Some(projection);
    }

    // The grounding owner returns the structured A03 v2 result. Conflict
    // analysis currently accepts the distinct legacy root result type, so
    // the stage cannot consume a caller-side lookalike as a substitute.
    failed_run(stages, outputs, PulseStageId::Conflict, PulseError::Conflict)
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
