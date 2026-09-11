//! Deterministic, inert rival accounting and exact declaration projections.

use crate::dependencies;
use crate::equivalence;
use crate::error::RivalModelError;
use crate::meter::{MeterCharge, OperationMeter, WorkAddress};
use crate::policy::RivalPolicy;
use crate::states::{
    ModelOmissionReason, ModelUnavailableReason, ModelUnknownReason, OutputSection, WorkStage,
};
use eliot_dreamer_contracts::rival::{
    ConditionAssumptionRef, DeclarationAvailability, MaterialClaimRef, PredictionAvailability,
    RivalDeclarationSet, RivalModelDeclaration, RivalModelRef, RivalModelSlot, RivalPrediction,
    RivalPredictionRef, RivalPredictionSlot,
};
use eliot_epistemic_contracts::ValidityBounds;
use eliot_evaluation_contracts::ExpectedObservableSpec;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

/// Per-declaration accounting outcome. It does not assert truth or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ModelDisposition {
    /// This retained model is included in the bounded analysis frontier.
    Retained,
    /// This retained model remains in source declarations outside the frontier.
    Omitted { reason: ModelOmissionReason },
    /// The model identity is known while its body is unavailable.
    Unavailable { reason: ModelUnavailableReason },
    /// The body is retained but a required material input is unavailable.
    Unknown { reason: ModelUnknownReason },
}

/// Bounded accounting record for one source declaration slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalModelAssessment {
    /// Stable declaration artifact identity from either slot form.
    pub model_id: eliot_dreamer_contracts::grounding::ArtifactId,
    /// Optional model-owned revision; absent remains unavailable.
    pub model_revision: Option<u64>,
    /// Optional declaration digest; absent remains unavailable.
    pub declaration_digest: Option<String>,
    /// Explicit accounting outcome.
    pub disposition: ModelDisposition,
    /// Exact material projection digest, when all material inputs are retained.
    pub material_projection_digest: Option<String>,
    /// Equivalence class assigned by exact projection, if any.
    pub equivalence_class: Option<u32>,
}

/// Exact material-equivalence class; all source declarations remain addressable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalEquivalenceClass {
    /// Stable deterministic class number in canonical member order.
    pub class_id: u32,
    /// Exact retained declaration references in this class.
    pub members: Vec<RivalModelRef>,
}

/// An inert cross-match between one expected and one falsifying observable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InertDiscriminator {
    /// Model whose prediction declares the observable as expected.
    pub expected_model: RivalModelRef,
    /// Prediction declaring the expected observable.
    pub expected_prediction: RivalPredictionRef,
    /// Model whose prediction declares the same observable as a falsifier.
    pub falsifying_model: RivalModelRef,
    /// Prediction declaring the falsifying observable.
    pub falsifying_prediction: RivalPredictionRef,
    /// Exact material target shared by both declarations.
    pub target: MaterialClaimRef,
    /// Exact applicability shared by both declarations.
    pub applicability: ValidityBounds,
    /// Exact assumption references shared by both declarations.
    pub condition_assumptions: std::collections::BTreeSet<ConditionAssumptionRef>,
    /// Exact opaque owner observable; no matcher is executed here.
    pub observable: ExpectedObservableSpec,
}

/// Whether discriminator search reached all addressable comparisons.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SearchCompletion {
    NotStarted,
    Complete,
    Bounded,
}

/// Why an exact discriminator requirement could not be emitted as a match.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DiscriminatorRequirementReason {
    Unknown,
    Unavailable,
    InternallyIdentical,
    NotApplicable,
    OutsideAnalysisFrontier,
}

/// The declaration facet that made a discriminator comparison incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DiscriminatorRequirementFacet {
    PredictionReferences,
    Expected,
    Falsifier,
    ModelFrontier,
}

/// Compact address of a peer prediction, without copying its declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscriminatorPeerAddress {
    pub model_row: u32,
    pub prediction_ref_entry: Option<u32>,
}

/// A source-addressable discriminator requirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscriminatorRequirement {
    pub model_row: u32,
    pub prediction_ref_entry: Option<u32>,
    pub facet: DiscriminatorRequirementFacet,
    pub peer: Option<DiscriminatorPeerAddress>,
    pub reason: DiscriminatorRequirementReason,
}

/// Result of the inert, exact-only discriminator search.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscriminatorSearch {
    pub completion: SearchCompletion,
    pub outcome: DiscriminatorOutcome,
    pub requirements: Vec<DiscriminatorRequirement>,
}

/// Outcome of discriminator search; none of these variants is a verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DiscriminatorOutcome {
    Matches,
    NoExact,
    Unprobeable,
    InsufficientRivals,
}

impl DiscriminatorSearch {
    pub(crate) fn not_started() -> Self {
        Self {
            completion: SearchCompletion::NotStarted,
            outcome: DiscriminatorOutcome::InsufficientRivals,
            requirements: Vec::new(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), RivalModelError> {
        if self.requirements.len() > 256 {
            return Err(RivalModelError::Bound {
                field: "discriminators.requirements",
                maximum: 256,
                actual: self.requirements.len(),
            });
        }
        for requirement in &self.requirements {
            if matches!(
                requirement.reason,
                DiscriminatorRequirementReason::OutsideAnalysisFrontier
            ) && requirement.facet != DiscriminatorRequirementFacet::ModelFrontier
            {
                return Err(RivalModelError::InvalidContract(
                    "discriminators.frontier_facet",
                ));
            }
            if matches!(
                requirement.facet,
                DiscriminatorRequirementFacet::Expected | DiscriminatorRequirementFacet::Falsifier
            ) && requirement.prediction_ref_entry.is_none()
            {
                return Err(RivalModelError::InvalidContract(
                    "discriminators.requirement_entry",
                ));
            }
            if matches!(
                requirement.facet,
                DiscriminatorRequirementFacet::ModelFrontier
            ) && requirement.prediction_ref_entry.is_some()
            {
                return Err(RivalModelError::InvalidContract(
                    "discriminators.model_frontier_entry",
                ));
            }
            if requirement.peer.is_some_and(|peer| {
                peer.model_row == requirement.model_row
                    && peer.prediction_ref_entry == requirement.prediction_ref_entry
            }) {
                return Err(RivalModelError::InvalidContract(
                    "discriminators.requirement_peer",
                ));
            }
        }
        Ok(())
    }
}

/// Deterministic accounting of declarations outside the bounded frontier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmissionFrontier {
    /// Omitted retained model identities in canonical order.
    pub model_ids: Vec<RivalModelRef>,
    /// Stable section names for bounded output overflow.
    pub sections: Vec<OutputSection>,
    /// Analysis stage at which optional work exhausted the shared meter.
    pub exhausted_stage: Option<WorkStage>,
    /// Model identity at the exhaustion frontier, when one was addressable.
    pub exhausted_model_id: Option<eliot_dreamer_contracts::grounding::ArtifactId>,
    /// Prediction identity at a lookup frontier before a pair was available.
    pub exhausted_prediction_id: Option<eliot_dreamer_contracts::grounding::ArtifactId>,
    /// Model pair at a discriminator frontier, when one was addressable.
    pub exhausted_pair: Option<(
        eliot_dreamer_contracts::grounding::ArtifactId,
        eliot_dreamer_contracts::grounding::ArtifactId,
    )>,
    /// Prediction identities at a discriminator capacity frontier.
    pub exhausted_prediction_pair: Option<(
        eliot_dreamer_contracts::grounding::ArtifactId,
        eliot_dreamer_contracts::grounding::ArtifactId,
    )>,
}

pub(crate) struct AnalysisOutput {
    pub assessments: Vec<RivalModelAssessment>,
    pub equivalence_classes: Vec<RivalEquivalenceClass>,
    pub discriminators: Vec<InertDiscriminator>,
    pub discriminator_search: DiscriminatorSearch,
    pub omission_frontier: OmissionFrontier,
}

struct PredictionAddress<'a> {
    model: &'a RivalModelRef,
    model_row: u32,
    prediction_ref_entry: u32,
    reference: &'a RivalPredictionRef,
}

#[derive(Clone, Copy)]
enum AnalysisArray {
    Discriminators,
    Requirements,
}

struct AnalysisArrayBudget {
    ceiling: usize,
    bytes: usize,
    discriminator_items: usize,
    requirement_items: usize,
}

impl AnalysisArrayBudget {
    fn new(ceiling: usize) -> Self {
        Self {
            ceiling,
            bytes: 4,
            discriminator_items: 0,
            requirement_items: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.ceiling.saturating_sub(self.bytes)
    }

    fn admit(&mut self, array: AnalysisArray, item_bytes: usize) -> bool {
        let items = match array {
            AnalysisArray::Discriminators => self.discriminator_items,
            AnalysisArray::Requirements => self.requirement_items,
        };
        let Some(added) = item_bytes.checked_add(usize::from(items != 0)) else {
            return false;
        };
        let Some(next) = self.bytes.checked_add(added) else {
            return false;
        };
        if next > self.ceiling {
            return false;
        }
        self.bytes = next;
        match array {
            AnalysisArray::Discriminators => {
                self.discriminator_items = self.discriminator_items.saturating_add(1);
            }
            AnalysisArray::Requirements => {
                self.requirement_items = self.requirement_items.saturating_add(1);
            }
        }
        true
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered analysis stages share meter accounting and exact frontiers"
)]
pub(crate) fn analyze(
    declarations: &RivalDeclarationSet,
    policy: &RivalPolicy,
    meter: &mut OperationMeter,
    output_ceiling: usize,
) -> Result<AnalysisOutput, RivalModelError> {
    meter.observation();
    dependencies::validate(declarations, meter)?;
    if meter.is_exhausted() {
        return exhausted_output(declarations, meter);
    }
    let mut assessments = Vec::with_capacity(declarations.models.len());
    let mut retained = Vec::new();
    let max_models = usize::try_from(policy.max_models).unwrap_or(usize::MAX);
    for slot in &declarations.models {
        match slot {
            RivalModelSlot::Retained { declaration } => {
                let model = model_ref(declaration)?;
                if matches!(
                    meter.charge(1, WorkStage::ModelAssessment, Some(&model.model_id), None,)?,
                    MeterCharge::Exhausted
                ) {
                    assessments.push(assessment_for(
                        &model,
                        ModelDisposition::Omitted {
                            reason: ModelOmissionReason::AnalysisWorkFrontier,
                        },
                    ));
                    break;
                }
                if retained.len() < max_models {
                    retained.push((model, declaration.as_ref()));
                } else {
                    assessments.push(assessment_for(
                        &model,
                        ModelDisposition::Omitted {
                            reason: ModelOmissionReason::ModelFrontierCapacity,
                        },
                    ));
                }
            }
            RivalModelSlot::Unavailable {
                model_id,
                model_revision,
                declaration_digest,
                ..
            } => assessments.push(RivalModelAssessment {
                model_id: model_id.clone(),
                model_revision: *model_revision,
                declaration_digest: declaration_digest.clone(),
                disposition: ModelDisposition::Unavailable {
                    reason: ModelUnavailableReason::BodyUnavailable,
                },
                material_projection_digest: None,
                equivalence_class: None,
            }),
        }
    }
    if meter.is_exhausted() {
        return exhausted_output(declarations, meter);
    }

    let mut class_by_digest = std::collections::BTreeMap::<String, u32>::new();
    let mut classes = Vec::<RivalEquivalenceClass>::new();
    for (model, declaration) in &retained {
        let projection = equivalence::material_digest(declaration, declarations, meter)?;
        if meter.is_exhausted() {
            return exhausted_output(declarations, meter);
        }
        let Some(projection) = projection else {
            assessments.push(assessment_for(
                model,
                ModelDisposition::Unknown {
                    reason: ModelUnknownReason::MaterialInputsUnavailable,
                },
            ));
            continue;
        };
        let class_id = if let Some(class_id) = class_by_digest.get(&projection) {
            *class_id
        } else {
            let class_id = u32::try_from(classes.len()).map_err(|_| RivalModelError::Bound {
                field: "equivalence_classes",
                maximum: 256,
                actual: classes.len(),
            })?;
            class_by_digest.insert(projection.clone(), class_id);
            classes.push(RivalEquivalenceClass {
                class_id,
                members: Vec::new(),
            });
            class_id
        };
        classes[usize::try_from(class_id)
            .map_err(|_| RivalModelError::InvalidContract("equivalence_class"))?]
        .members
        .push(model.clone());
        let mut assessment = assessment_for(model, ModelDisposition::Retained);
        assessment.material_projection_digest = Some(projection);
        assessment.equivalence_class = Some(class_id);
        assessments.push(assessment);
    }
    assessments.sort_by(|left, right| left.model_id.cmp(&right.model_id));
    for class in &mut classes {
        class.members.sort();
    }
    let omission_frontier = OmissionFrontier {
        model_ids: assessments
            .iter()
            .filter(|assessment| matches!(assessment.disposition, ModelDisposition::Omitted { .. }))
            .filter_map(|assessment| {
                Some(RivalModelRef {
                    model_id: assessment.model_id.clone(),
                    model_revision: assessment.model_revision?,
                    declaration_digest: assessment.declaration_digest.clone()?,
                })
            })
            .collect(),
        sections: if assessments
            .iter()
            .any(|assessment| matches!(assessment.disposition, ModelDisposition::Omitted { .. }))
        {
            vec![OutputSection::Models]
        } else {
            Vec::new()
        },
        exhausted_stage: None,
        exhausted_model_id: None,
        exhausted_prediction_id: None,
        exhausted_pair: None,
        exhausted_prediction_pair: None,
    };
    let class_by_model = assessments
        .iter()
        .filter_map(|assessment| {
            assessment
                .equivalence_class
                .map(|class| (assessment.model_id.clone(), class))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let (discriminators, discriminator_search) = inert_discriminators(
        declarations,
        &retained,
        &class_by_model,
        classes.len(),
        policy.max_discriminators,
        output_ceiling,
        meter,
    )?;
    let mut output = AnalysisOutput {
        assessments,
        equivalence_classes: classes,
        discriminators,
        discriminator_search,
        omission_frontier,
    };
    if let Some(frontier) = meter.frontier() {
        output.omission_frontier.exhausted_stage = Some(frontier.stage);
        output
            .omission_frontier
            .exhausted_model_id
            .clone_from(&frontier.model_id);
        output
            .omission_frontier
            .exhausted_prediction_id
            .clone_from(&frontier.prediction_id);
        output
            .omission_frontier
            .exhausted_pair
            .clone_from(&frontier.pair);
        output
            .omission_frontier
            .exhausted_prediction_pair
            .clone_from(&frontier.prediction_pair);
        output
            .omission_frontier
            .sections
            .push(OutputSection::AnalysisWork);
    }
    Ok(output)
}

fn exhausted_output(
    declarations: &RivalDeclarationSet,
    meter: &OperationMeter,
) -> Result<AnalysisOutput, RivalModelError> {
    let mut assessments = Vec::with_capacity(declarations.models.len());
    for slot in &declarations.models {
        match slot {
            RivalModelSlot::Retained { declaration } => {
                let model = model_ref(declaration)?;
                assessments.push(assessment_for(
                    &model,
                    ModelDisposition::Omitted {
                        reason: ModelOmissionReason::AnalysisWorkFrontier,
                    },
                ));
            }
            RivalModelSlot::Unavailable {
                model_id,
                model_revision,
                declaration_digest,
                ..
            } => assessments.push(RivalModelAssessment {
                model_id: model_id.clone(),
                model_revision: *model_revision,
                declaration_digest: declaration_digest.clone(),
                disposition: ModelDisposition::Unavailable {
                    reason: ModelUnavailableReason::BodyUnavailable,
                },
                material_projection_digest: None,
                equivalence_class: None,
            }),
        }
    }
    Ok(AnalysisOutput {
        omission_frontier: frontier_for(&assessments, meter),
        assessments,
        equivalence_classes: Vec::new(),
        discriminators: Vec::new(),
        discriminator_search: DiscriminatorSearch {
            completion: SearchCompletion::Bounded,
            outcome: DiscriminatorOutcome::InsufficientRivals,
            requirements: Vec::new(),
        },
    })
}

fn frontier_for(assessments: &[RivalModelAssessment], meter: &OperationMeter) -> OmissionFrontier {
    let model_ids = assessments
        .iter()
        .filter(|assessment| matches!(assessment.disposition, ModelDisposition::Omitted { .. }))
        .filter_map(|assessment| {
            Some(RivalModelRef {
                model_id: assessment.model_id.clone(),
                model_revision: assessment.model_revision?,
                declaration_digest: assessment.declaration_digest.clone()?,
            })
        })
        .collect();
    OmissionFrontier {
        model_ids,
        sections: vec![OutputSection::AnalysisWork],
        exhausted_stage: meter.frontier().map(|frontier| frontier.stage),
        exhausted_model_id: meter
            .frontier()
            .and_then(|frontier| frontier.model_id.clone()),
        exhausted_prediction_id: meter
            .frontier()
            .and_then(|frontier| frontier.prediction_id.clone()),
        exhausted_pair: meter.frontier().and_then(|frontier| frontier.pair.clone()),
        exhausted_prediction_pair: meter
            .frontier()
            .and_then(|frontier| frontier.prediction_pair.clone()),
    }
}

fn assessment_for(model: &RivalModelRef, disposition: ModelDisposition) -> RivalModelAssessment {
    RivalModelAssessment {
        model_id: model.model_id.clone(),
        model_revision: Some(model.model_revision),
        declaration_digest: Some(model.declaration_digest.clone()),
        disposition,
        material_projection_digest: None,
        equivalence_class: None,
    }
}

fn model_ref(declaration: &RivalModelDeclaration) -> Result<RivalModelRef, RivalModelError> {
    let reference = RivalModelRef {
        model_id: declaration.model_id.clone(),
        model_revision: declaration.model_revision,
        declaration_digest: declaration.digest.clone(),
    };
    reference
        .validate()
        .map_err(|_| RivalModelError::InvalidContract("model_ref"))?;
    Ok(reference)
}

#[allow(
    clippy::too_many_lines,
    reason = "bounded discriminator pairing retains typed requirements and frontiers"
)]
fn inert_discriminators(
    declarations: &RivalDeclarationSet,
    retained: &[(RivalModelRef, &RivalModelDeclaration)],
    classes: &std::collections::BTreeMap<eliot_dreamer_contracts::grounding::ArtifactId, u32>,
    known_class_count: usize,
    maximum: u32,
    output_ceiling: usize,
    meter: &mut OperationMeter,
) -> Result<(Vec<InertDiscriminator>, DiscriminatorSearch), RivalModelError> {
    let model_rows = declarations
        .models
        .iter()
        .enumerate()
        .filter_map(|(row, slot)| match slot {
            RivalModelSlot::Retained { declaration } => {
                Some((declaration.model_id.clone(), u32::try_from(row).ok()?))
            }
            RivalModelSlot::Unavailable { .. } => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut array_budget = AnalysisArrayBudget::new(output_ceiling);
    let mut predictions_by_id = Vec::new();
    for slot in &declarations.predictions {
        if matches!(
            meter.charge(1, WorkStage::PredictionIndexScan, None, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(discriminator_search(
                Vec::new(),
                Vec::new(),
                known_class_count,
                meter,
            ));
        }
        let RivalPredictionSlot::Retained { prediction } = slot else {
            continue;
        };
        if matches!(
            meter.charge(1, WorkStage::PredictionIndexEntry, None, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(discriminator_search(
                Vec::new(),
                Vec::new(),
                known_class_count,
                meter,
            ));
        }
        predictions_by_id.push(prediction.as_ref());
    }
    let mut requirements = Vec::new();
    for (row, slot) in declarations.models.iter().enumerate() {
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        let model_row = u32::try_from(row).map_err(|_| RivalModelError::Bound {
            field: "discriminators.model_row",
            maximum: 255,
            actual: row,
        })?;
        if !retained
            .iter()
            .any(|(model, _)| model.model_id == declaration.model_id)
        {
            push_requirement(
                &mut requirements,
                &mut array_budget,
                meter,
                WorkAddress::model(&declaration.model_id),
                model_row,
                None,
                DiscriminatorRequirementFacet::ModelFrontier,
                None,
                DiscriminatorRequirementReason::OutsideAnalysisFrontier,
            )?;
        } else if !classes.contains_key(&declaration.model_id) {
            push_requirement(
                &mut requirements,
                &mut array_budget,
                meter,
                WorkAddress::model(&declaration.model_id),
                model_row,
                None,
                DiscriminatorRequirementFacet::ModelFrontier,
                None,
                DiscriminatorRequirementReason::Unknown,
            )?;
        }
        match &declaration.prediction_refs {
            DeclarationAvailability::Unknown { .. } => push_requirement(
                &mut requirements,
                &mut array_budget,
                meter,
                WorkAddress::model(&declaration.model_id),
                model_row,
                None,
                DiscriminatorRequirementFacet::PredictionReferences,
                None,
                DiscriminatorRequirementReason::Unknown,
            )?,
            DeclarationAvailability::NotApplicable { .. } => push_requirement(
                &mut requirements,
                &mut array_budget,
                meter,
                WorkAddress::model(&declaration.model_id),
                model_row,
                None,
                DiscriminatorRequirementFacet::PredictionReferences,
                None,
                DiscriminatorRequirementReason::NotApplicable,
            )?,
            DeclarationAvailability::Supplied { .. } => {}
        }
    }
    let mut predictions = Vec::new();
    for (model, declaration) in retained {
        let Some(model_row) = model_rows.get(&model.model_id).copied() else {
            continue;
        };
        let DeclarationAvailability::Supplied { entries } = &declaration.prediction_refs else {
            continue;
        };
        for (prediction_ref_entry, reference) in entries.iter().enumerate() {
            if matches!(
                meter.charge(
                    1,
                    WorkStage::PredictionReference,
                    Some(&model.model_id),
                    None
                )?,
                MeterCharge::Exhausted
            ) {
                return Ok(discriminator_search(
                    Vec::new(),
                    Vec::new(),
                    known_class_count,
                    meter,
                ));
            }
            predictions.push(PredictionAddress {
                model,
                model_row,
                prediction_ref_entry: u32::try_from(prediction_ref_entry).map_err(|_| {
                    RivalModelError::Bound {
                        field: "discriminators.prediction_ref_entry",
                        maximum: 255,
                        actual: prediction_ref_entry,
                    }
                })?,
                reference,
            });
        }
    }
    let mut output = Vec::new();
    for address_a in &predictions {
        let model_a = address_a.model;
        let reference_a = address_a.reference;
        let Some(class_a) = classes.get(&model_a.model_id) else {
            continue;
        };
        let prediction_a = match find_prediction(
            reference_a,
            &predictions_by_id,
            meter,
            &model_a.model_id,
            &reference_a.prediction_id,
            None,
        )? {
            Some(prediction) => prediction,
            None if meter.is_exhausted() => {
                return Ok(discriminator_search(
                    output,
                    requirements,
                    known_class_count,
                    meter,
                ));
            }
            None => {
                push_requirement(
                    &mut requirements,
                    &mut array_budget,
                    meter,
                    WorkAddress::prediction(&model_a.model_id, &reference_a.prediction_id),
                    address_a.model_row,
                    Some(address_a.prediction_ref_entry),
                    DiscriminatorRequirementFacet::Expected,
                    None,
                    DiscriminatorRequirementReason::Unavailable,
                )?;
                continue;
            }
        };
        let PredictionAvailability::Declared { observable } = &prediction_a.expected else {
            push_requirement(
                &mut requirements,
                &mut array_budget,
                meter,
                WorkAddress::prediction(&model_a.model_id, &reference_a.prediction_id),
                address_a.model_row,
                Some(address_a.prediction_ref_entry),
                DiscriminatorRequirementFacet::Expected,
                None,
                DiscriminatorRequirementReason::Unknown,
            )?;
            continue;
        };
        if matches!(
            prediction_a.falsifier,
            PredictionAvailability::Unknown { .. }
        ) {
            push_requirement(
                &mut requirements,
                &mut array_budget,
                meter,
                WorkAddress::prediction(&model_a.model_id, &reference_a.prediction_id),
                address_a.model_row,
                Some(address_a.prediction_ref_entry),
                DiscriminatorRequirementFacet::Falsifier,
                None,
                DiscriminatorRequirementReason::Unknown,
            )?;
            continue;
        }
        if matches!(
            (&prediction_a.expected, &prediction_a.falsifier),
            (
                PredictionAvailability::Declared { observable: expected },
                PredictionAvailability::Declared { observable: falsifier }
            ) if expected == falsifier
        ) {
            push_requirement(
                &mut requirements,
                &mut array_budget,
                meter,
                WorkAddress::prediction(&model_a.model_id, &reference_a.prediction_id),
                address_a.model_row,
                Some(address_a.prediction_ref_entry),
                DiscriminatorRequirementFacet::Falsifier,
                None,
                DiscriminatorRequirementReason::InternallyIdentical,
            )?;
            continue;
        }
        for address_b in &predictions {
            let model_b = address_b.model;
            let reference_b = address_b.reference;
            let Some(class_b) = classes.get(&model_b.model_id) else {
                continue;
            };
            if class_a == class_b {
                continue;
            }
            if output.len() >= usize::try_from(maximum).unwrap_or(usize::MAX) {
                meter.mark_discriminator_frontier(
                    &model_a.model_id,
                    &reference_a.prediction_id,
                    &model_b.model_id,
                    &reference_b.prediction_id,
                );
                return Ok(discriminator_search(
                    output,
                    requirements,
                    known_class_count,
                    meter,
                ));
            }
            if matches!(
                meter.charge_discriminator(
                    1,
                    WorkStage::DiscriminatorPair,
                    &model_a.model_id,
                    &reference_a.prediction_id,
                    Some((&model_b.model_id, &reference_b.prediction_id)),
                )?,
                MeterCharge::Exhausted
            ) {
                return Ok(discriminator_search(
                    output,
                    requirements,
                    known_class_count,
                    meter,
                ));
            }
            if model_a == model_b {
                continue;
            }
            let prediction_b = match find_prediction(
                reference_b,
                &predictions_by_id,
                meter,
                &model_a.model_id,
                &reference_a.prediction_id,
                Some((&model_b.model_id, &reference_b.prediction_id)),
            )? {
                Some(prediction) => prediction,
                None if meter.is_exhausted() => {
                    return Ok(discriminator_search(
                        output,
                        requirements,
                        known_class_count,
                        meter,
                    ));
                }
                None => {
                    push_requirement(
                        &mut requirements,
                        &mut array_budget,
                        meter,
                        WorkAddress::pair(
                            &model_a.model_id,
                            &reference_a.prediction_id,
                            &model_b.model_id,
                            &reference_b.prediction_id,
                        ),
                        address_a.model_row,
                        Some(address_a.prediction_ref_entry),
                        DiscriminatorRequirementFacet::Falsifier,
                        Some(DiscriminatorPeerAddress {
                            model_row: address_b.model_row,
                            prediction_ref_entry: Some(address_b.prediction_ref_entry),
                        }),
                        DiscriminatorRequirementReason::Unavailable,
                    )?;
                    continue;
                }
            };
            let PredictionAvailability::Declared {
                observable: falsifier,
            } = &prediction_b.falsifier
            else {
                push_requirement(
                    &mut requirements,
                    &mut array_budget,
                    meter,
                    WorkAddress::pair(
                        &model_a.model_id,
                        &reference_a.prediction_id,
                        &model_b.model_id,
                        &reference_b.prediction_id,
                    ),
                    address_a.model_row,
                    Some(address_a.prediction_ref_entry),
                    DiscriminatorRequirementFacet::Falsifier,
                    Some(DiscriminatorPeerAddress {
                        model_row: address_b.model_row,
                        prediction_ref_entry: Some(address_b.prediction_ref_entry),
                    }),
                    DiscriminatorRequirementReason::Unknown,
                )?;
                continue;
            };
            if observable != falsifier
                || prediction_a.target != prediction_b.target
                || prediction_a.applicability != prediction_b.applicability
                || prediction_a.condition_assumptions != prediction_b.condition_assumptions
            {
                continue;
            }
            if !push_discriminator(
                &mut output,
                &mut array_budget,
                meter,
                model_a,
                reference_a,
                model_b,
                reference_b,
                prediction_a,
                observable,
            )? {
                return Ok(discriminator_search(
                    output,
                    requirements,
                    known_class_count,
                    meter,
                ));
            }
        }
    }
    Ok(discriminator_search(
        output,
        requirements,
        known_class_count,
        meter,
    ))
}

fn discriminator_search(
    discriminators: Vec<InertDiscriminator>,
    requirements: Vec<DiscriminatorRequirement>,
    known_classes: usize,
    meter: &OperationMeter,
) -> (Vec<InertDiscriminator>, DiscriminatorSearch) {
    let has_frontier_requirement = requirements.iter().any(|requirement| {
        matches!(
            requirement.reason,
            DiscriminatorRequirementReason::OutsideAnalysisFrontier
        )
    });
    let completion = if meter.is_exhausted() || has_frontier_requirement {
        SearchCompletion::Bounded
    } else if known_classes < 2 {
        SearchCompletion::NotStarted
    } else {
        SearchCompletion::Complete
    };
    let outcome = if known_classes < 2 {
        DiscriminatorOutcome::InsufficientRivals
    } else if !discriminators.is_empty() {
        DiscriminatorOutcome::Matches
    } else if completion != SearchCompletion::Complete || !requirements.is_empty() {
        DiscriminatorOutcome::Unprobeable
    } else {
        DiscriminatorOutcome::NoExact
    };
    (
        discriminators,
        DiscriminatorSearch {
            completion,
            outcome,
            requirements,
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one bounded emission carries independent typed coordinates and owners"
)]
fn push_requirement(
    requirements: &mut Vec<DiscriminatorRequirement>,
    budget: &mut AnalysisArrayBudget,
    meter: &mut OperationMeter,
    address: WorkAddress<'_>,
    model_row: u32,
    prediction_ref_entry: Option<u32>,
    facet: DiscriminatorRequirementFacet,
    peer: Option<DiscriminatorPeerAddress>,
    reason: DiscriminatorRequirementReason,
) -> Result<(), RivalModelError> {
    if requirements.len() >= 256 {
        meter.mark_addressed_frontier(WorkStage::DiscriminatorLimit, address);
        return Ok(());
    }
    let item = DiscriminatorRequirement {
        model_row,
        prediction_ref_entry,
        facet,
        peer,
        reason,
    };
    let Some(wire_bytes) = preflight_item(&item, budget.remaining(), meter, address)? else {
        return Ok(());
    };
    if !budget.admit(AnalysisArray::Requirements, wire_bytes) {
        meter.mark_addressed_frontier(WorkStage::DiscriminatorLimit, address);
        return Ok(());
    }
    let blocks = wire_blocks(wire_bytes)?;
    if matches!(
        meter.charge_addressed(blocks, WorkStage::DiscriminatorPair, address)?,
        MeterCharge::Exhausted
    ) {
        return Ok(());
    }
    requirements.push(item);
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "one metered emission carries both typed prediction sides and observable"
)]
fn push_discriminator(
    output: &mut Vec<InertDiscriminator>,
    budget: &mut AnalysisArrayBudget,
    meter: &mut OperationMeter,
    expected_model: &RivalModelRef,
    expected_prediction: &RivalPredictionRef,
    falsifying_model: &RivalModelRef,
    falsifying_prediction: &RivalPredictionRef,
    expected: &RivalPrediction,
    observable: &ExpectedObservableSpec,
) -> Result<bool, RivalModelError> {
    #[derive(Serialize)]
    struct Borrowed<'a> {
        expected_model: &'a RivalModelRef,
        expected_prediction: &'a RivalPredictionRef,
        falsifying_model: &'a RivalModelRef,
        falsifying_prediction: &'a RivalPredictionRef,
        target: &'a MaterialClaimRef,
        applicability: &'a ValidityBounds,
        condition_assumptions: &'a std::collections::BTreeSet<ConditionAssumptionRef>,
        observable: &'a ExpectedObservableSpec,
    }
    let borrowed = Borrowed {
        expected_model,
        expected_prediction,
        falsifying_model,
        falsifying_prediction,
        target: &expected.target,
        applicability: &expected.applicability,
        condition_assumptions: &expected.condition_assumptions,
        observable,
    };
    let address = WorkAddress::pair(
        &expected_model.model_id,
        &expected_prediction.prediction_id,
        &falsifying_model.model_id,
        &falsifying_prediction.prediction_id,
    );
    let Some(wire_bytes) = preflight_item(&borrowed, budget.remaining(), meter, address)? else {
        return Ok(false);
    };
    if !budget.admit(AnalysisArray::Discriminators, wire_bytes) {
        meter.mark_discriminator_frontier(
            &expected_model.model_id,
            &expected_prediction.prediction_id,
            &falsifying_model.model_id,
            &falsifying_prediction.prediction_id,
        );
        return Ok(false);
    }
    let blocks = wire_blocks(wire_bytes)?;
    if matches!(
        meter.charge_addressed(blocks, WorkStage::DiscriminatorPair, address)?,
        MeterCharge::Exhausted
    ) {
        return Ok(false);
    }
    output.push(InertDiscriminator {
        expected_model: expected_model.clone(),
        expected_prediction: expected_prediction.clone(),
        falsifying_model: falsifying_model.clone(),
        falsifying_prediction: falsifying_prediction.clone(),
        target: expected.target.clone(),
        applicability: expected.applicability.clone(),
        condition_assumptions: expected.condition_assumptions.clone(),
        observable: observable.clone(),
    });
    Ok(true)
}

fn wire_blocks(bytes: usize) -> Result<usize, RivalModelError> {
    bytes
        .checked_add(1023)
        .and_then(|value| value.checked_div(1024))
        .map(|blocks| blocks.max(1))
        .ok_or(RivalModelError::Bound {
            field: "discriminators.serialization_work",
            maximum: usize::MAX,
            actual: bytes,
        })
}

#[derive(Clone, Copy)]
enum WriterFailure {
    Wire,
    Meter,
}

struct MeteredWriter<'meter, 'address> {
    meter: &'meter mut OperationMeter,
    address: WorkAddress<'address>,
    count: usize,
    ceiling: usize,
    charged_blocks: usize,
    failure: Option<WriterFailure>,
}

impl MeteredWriter<'_, '_> {
    fn count(&self) -> usize {
        self.count
    }

    fn failure(&self) -> Option<WriterFailure> {
        self.failure
    }
}

impl Write for MeteredWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.count.checked_add(bytes.len()) else {
            self.failure = Some(WriterFailure::Wire);
            return Err(io::Error::other("discriminator output overflow"));
        };
        if next > self.ceiling {
            self.failure = Some(WriterFailure::Wire);
            return Err(io::Error::other("discriminator output ceiling"));
        }
        let Some(blocks) = next
            .checked_add(1023)
            .map(|value| value / 1024)
            .map(|blocks| blocks.max(1))
        else {
            self.failure = Some(WriterFailure::Wire);
            return Err(io::Error::other("discriminator output overflow"));
        };
        let additional = blocks.saturating_sub(self.charged_blocks);
        if additional != 0 {
            match self.meter.charge_addressed(
                additional,
                WorkStage::DiscriminatorPair,
                self.address,
            ) {
                Ok(MeterCharge::Charged) => self.charged_blocks = blocks,
                Ok(MeterCharge::Exhausted) | Err(_) => {
                    self.failure = Some(WriterFailure::Meter);
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "analysis work"));
                }
            }
        }
        self.count = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn preflight_item<T: Serialize>(
    item: &T,
    ceiling: usize,
    meter: &mut OperationMeter,
    address: WorkAddress<'_>,
) -> Result<Option<usize>, RivalModelError> {
    let (result, count, failure) = {
        let mut writer = MeteredWriter {
            meter,
            address,
            count: 0,
            ceiling,
            charged_blocks: 0,
            failure: None,
        };
        let result = serde_json::to_writer(&mut writer, item);
        (result, writer.count(), writer.failure())
    };
    match (result, failure) {
        (Ok(()), None) => Ok(Some(count)),
        (_, Some(WriterFailure::Wire)) => {
            meter.mark_addressed_frontier(WorkStage::DiscriminatorLimit, address);
            Ok(None)
        }
        (_, Some(WriterFailure::Meter)) => Ok(None),
        (Err(_), None) => Err(RivalModelError::InvalidContract("discriminator.preimage")),
    }
}

fn find_prediction<'a>(
    reference: &RivalPredictionRef,
    retained: &'a [&'a RivalPrediction],
    meter: &mut OperationMeter,
    expected_model: &eliot_dreamer_contracts::grounding::ArtifactId,
    expected_prediction: &eliot_dreamer_contracts::grounding::ArtifactId,
    falsifying: Option<(
        &eliot_dreamer_contracts::grounding::ArtifactId,
        &eliot_dreamer_contracts::grounding::ArtifactId,
    )>,
) -> Result<Option<&'a RivalPrediction>, RivalModelError> {
    for prediction in retained {
        if matches!(
            meter.charge_discriminator(
                1,
                WorkStage::PredictionLookupCompare,
                expected_model,
                expected_prediction,
                falsifying,
            )?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        if prediction.prediction_id == reference.prediction_id
            && prediction.digest == reference.prediction_digest
        {
            return Ok(Some(*prediction));
        }
    }
    Ok(None)
}
