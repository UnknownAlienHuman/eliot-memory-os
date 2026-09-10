//! Bounded result-packing helpers.

use crate::analysis::{
    DiscriminatorSearch, InertDiscriminator, OmissionFrontier, RivalEquivalenceClass,
    RivalModelAssessment,
};
use crate::bounds::MAX_RIVAL_WIRE_BYTES;
use crate::comparison::{
    ComparisonCompletion, ComparisonField, ComparisonMap, ComparisonPhase, SharedInputGroup,
    SharedInputKind, SourceAddress,
};
use crate::error::RivalModelError;
use crate::meter::{MeterCharge, OperationMeter};
use crate::model_detail::{ModelBodyOmissionReason, RivalModelDetail};
use crate::policy::RivalPolicy;
use crate::result::{CoverageStatus, RivalModelDisposition, RivalModelSet, SourceSetRef};
use crate::states::{OutputSection, WorkStage};
use crate::unknown::UnknownSlotRef;
use eliot_dreamer_contracts::ValidatedGroundingCandidate;
use eliot_dreamer_contracts::grounding::{ArtifactId, StateFence, TaskId};
use eliot_dreamer_contracts::rival::{
    CurrentPositionBinding, RivalDeclarationSet, RivalModelDeclaration, RivalPredictionSlot,
};
use serde::Serialize;
use std::io::{self, Write};

#[derive(Clone, Copy)]
enum MeteredWriteFailure {
    Wire,
    Meter,
    Serializer,
}

struct MeteredWriter<'a> {
    meter: &'a mut OperationMeter,
    model_id: Option<ArtifactId>,
    count: usize,
    charged_blocks: usize,
    ceiling: usize,
    failure: Option<MeteredWriteFailure>,
}

impl Write for MeteredWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let next = self.count.checked_add(bytes.len()).ok_or_else(|| {
            self.failure = Some(MeteredWriteFailure::Wire);
            io::Error::new(io::ErrorKind::WriteZero, "serialized size overflow")
        })?;
        if next > self.ceiling {
            self.failure = Some(MeteredWriteFailure::Wire);
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "serialized size bound",
            ));
        }
        let blocks = hash_blocks(next);
        let additional = blocks.saturating_sub(self.charged_blocks);
        if additional != 0 {
            match self.meter.charge(
                additional,
                WorkStage::ResultPacking,
                self.model_id.as_ref(),
                None,
            ) {
                Ok(MeterCharge::Charged) => {}
                Ok(MeterCharge::Exhausted) | Err(_) => {
                    self.failure = Some(MeteredWriteFailure::Meter);
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "packing work bound",
                    ));
                }
            }
            self.charged_blocks = blocks;
        }
        self.count = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn preflight_with_meter<T: Serialize>(
    value: &T,
    ceiling: usize,
    meter: &mut OperationMeter,
) -> Result<usize, RivalModelError> {
    preflight_with_context(value, ceiling, meter, None)
}

fn preflight_with_context<T: Serialize>(
    value: &T,
    ceiling: usize,
    meter: &mut OperationMeter,
    model_id: Option<&ArtifactId>,
) -> Result<usize, RivalModelError> {
    let mut writer = MeteredWriter {
        meter,
        model_id: model_id.cloned(),
        count: 0,
        charged_blocks: 0,
        ceiling,
        failure: Some(MeteredWriteFailure::Serializer),
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        let (field, maximum) = match writer.failure {
            Some(MeteredWriteFailure::Meter) => ("result.packing_work", usize::MAX),
            Some(MeteredWriteFailure::Wire) => ("serialized_wire", ceiling),
            Some(MeteredWriteFailure::Serializer) | None => {
                return Err(RivalModelError::InvalidContract(
                    "result.packing.serialization",
                ));
            }
        };
        return Err(RivalModelError::Bound {
            field,
            maximum,
            actual: writer.count.saturating_add(1),
        });
    }
    Ok(writer.count)
}

/// Returns the number of 1 KiB work blocks needed for a canonical hash pass.
pub(crate) fn hash_blocks(bytes: usize) -> usize {
    bytes
        .saturating_add(1023)
        .checked_div(1024)
        .unwrap_or(usize::MAX)
        .max(1)
}

pub(crate) struct PackingLedger {
    funded_bytes: usize,
    final_pass_blocks: usize,
}

impl PackingLedger {
    pub(crate) fn fund(
        mandatory_capacity: usize,
        meter: &mut OperationMeter,
    ) -> Result<Self, RivalModelError> {
        let blocks = hash_blocks(mandatory_capacity);
        let final_pass_blocks = blocks.checked_mul(2).ok_or(RivalModelError::Bound {
            field: "result.final_passes",
            maximum: MAX_RIVAL_WIRE_BYTES,
            actual: usize::MAX,
        })?;
        meter.reserve(final_pass_blocks, "result.final_passes")?;
        Ok(Self {
            funded_bytes: mandatory_capacity,
            final_pass_blocks,
        })
    }

    pub(crate) fn admit(
        &mut self,
        wire_bytes: usize,
        meter: &mut OperationMeter,
    ) -> Result<bool, RivalModelError> {
        let blocks = hash_blocks(wire_bytes);
        let required = blocks.checked_mul(2).ok_or(RivalModelError::Bound {
            field: "result.final_passes",
            maximum: MAX_RIVAL_WIRE_BYTES,
            actual: usize::MAX,
        })?;
        if required > self.final_pass_blocks {
            let additional = required - self.final_pass_blocks;
            if !meter.can_reserve(additional) {
                return Ok(false);
            }
            meter.reserve(additional, "result.final_passes")?;
            self.final_pass_blocks = required;
        }
        self.funded_bytes = self.funded_bytes.max(wire_bytes);
        Ok(true)
    }

    pub(crate) fn covers(&self, wire_bytes: usize) -> bool {
        wire_bytes <= self.funded_bytes
    }

    pub(crate) fn funded_bytes(&self) -> usize {
        self.funded_bytes
    }
}

/// Computes the output ceiling from the global, local, and remaining job
/// output/report budgets. Prior usage is subtracted once; the current result
/// is checked separately after packing.
pub(crate) fn output_ceiling(
    candidate: &ValidatedGroundingCandidate,
    policy: &RivalPolicy,
) -> Result<usize, RivalModelError> {
    let budget = &candidate.input.grounded.input.job.budget;
    budget
        .require_exact()
        .map_err(|_| RivalModelError::InvalidContract("job.budget"))?;
    let policy_limit = policy.max_output_bytes_as_usize()?;
    let output_remaining = remaining(
        budget.output_bytes,
        candidate.input.usage.output_bytes,
        "job.budget.output_bytes",
    )?;
    let report_remaining = remaining(
        budget.report_bytes,
        candidate.input.usage.report_bytes,
        "job.budget.report_bytes",
    )?;
    Ok(MAX_RIVAL_WIRE_BYTES
        .min(policy_limit)
        .min(output_remaining)
        .min(report_remaining))
}

/// Measures a result envelope with declarations borrowed, before the retained
/// declaration body is cloned into the optional result field.
pub(crate) fn preflight_with_declarations(
    result: &RivalModelSet,
    declarations: &RivalDeclarationSet,
    ceiling: usize,
    meter: &mut OperationMeter,
) -> Result<usize, RivalModelError> {
    #[derive(Serialize)]
    struct BorrowedResult<'a> {
        schema_version: u32,
        set_id: &'a ArtifactId,
        task_id: &'a TaskId,
        scope: &'a str,
        state_fence: &'a StateFence,
        bundle_digest: &'a str,
        validated_input_digest: &'a str,
        current_position: &'a CurrentPositionBinding,
        source_set: &'a SourceSetRef,
        policy_id: &'a str,
        policy_digest: &'a str,
        declarations: Option<&'a RivalDeclarationSet>,
        assessments: &'a [RivalModelAssessment],
        model_details: &'a [RivalModelDetail],
        equivalence_classes: &'a [RivalEquivalenceClass],
        discriminators: &'a [InertDiscriminator],
        discriminator_search: &'a DiscriminatorSearch,
        comparison: &'a ComparisonMap,
        omission_frontier: &'a OmissionFrontier,
        unknown_slots: &'a [UnknownSlotRef],
        unknown_total: usize,
        unknown_omitted_count: usize,
        omitted_count: usize,
        distinct_material_classes: usize,
        required_min_classes: usize,
        model_coverage: CoverageStatus,
        source_coverage: CoverageStatus,
        disposition: RivalModelDisposition,
        digest: &'a str,
    }
    let borrowed = BorrowedResult {
        schema_version: result.schema_version,
        set_id: &result.set_id,
        task_id: &result.task_id,
        scope: &result.scope,
        state_fence: &result.state_fence,
        bundle_digest: &result.bundle_digest,
        validated_input_digest: &result.validated_input_digest,
        current_position: &result.current_position,
        source_set: &result.source_set,
        policy_id: &result.policy_id,
        policy_digest: &result.policy_digest,
        declarations: Some(declarations),
        assessments: &result.assessments,
        model_details: &result.model_details,
        equivalence_classes: &result.equivalence_classes,
        discriminators: &result.discriminators,
        discriminator_search: &result.discriminator_search,
        comparison: &result.comparison,
        omission_frontier: &result.omission_frontier,
        unknown_slots: &result.unknown_slots,
        unknown_total: result.unknown_total,
        unknown_omitted_count: result.unknown_omitted_count,
        omitted_count: result.omitted_count,
        distinct_material_classes: result.distinct_material_classes,
        required_min_classes: result.required_min_classes,
        model_coverage: result.model_coverage,
        source_coverage: result.source_coverage,
        disposition: result.disposition,
        digest: &result.digest,
    };
    preflight_with_meter(&borrowed, ceiling, meter)
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BorrowedModelDetail<'a> {
    Retained {
        source_row: u32,
        declaration: &'a RivalModelDeclaration,
    },
    Omitted {
        source_row: u32,
        reason: ModelBodyOmissionReason,
    },
    Unavailable {
        source_row: u32,
    },
}

pub(crate) fn preflight_with_model_details(
    result: &RivalModelSet,
    details: &[BorrowedModelDetail<'_>],
    ceiling: usize,
    meter: &mut OperationMeter,
    model_id: Option<&ArtifactId>,
) -> Result<usize, RivalModelError> {
    #[derive(Serialize)]
    struct BorrowedResult<'a, 'b, 'c> {
        schema_version: u32,
        set_id: &'a ArtifactId,
        task_id: &'a TaskId,
        scope: &'a str,
        state_fence: &'a StateFence,
        bundle_digest: &'a str,
        validated_input_digest: &'a str,
        current_position: &'a CurrentPositionBinding,
        source_set: &'a SourceSetRef,
        policy_id: &'a str,
        policy_digest: &'a str,
        declarations: &'a Option<Box<RivalDeclarationSet>>,
        assessments: &'a [RivalModelAssessment],
        model_details: &'b [BorrowedModelDetail<'c>],
        equivalence_classes: &'a [RivalEquivalenceClass],
        discriminators: &'a [InertDiscriminator],
        discriminator_search: &'a DiscriminatorSearch,
        comparison: &'a ComparisonMap,
        omission_frontier: &'a OmissionFrontier,
        unknown_slots: &'a [UnknownSlotRef],
        unknown_total: usize,
        unknown_omitted_count: usize,
        omitted_count: usize,
        distinct_material_classes: usize,
        required_min_classes: usize,
        model_coverage: CoverageStatus,
        source_coverage: CoverageStatus,
        disposition: RivalModelDisposition,
        digest: &'a str,
    }
    let borrowed = BorrowedResult {
        schema_version: result.schema_version,
        set_id: &result.set_id,
        task_id: &result.task_id,
        scope: &result.scope,
        state_fence: &result.state_fence,
        bundle_digest: &result.bundle_digest,
        validated_input_digest: &result.validated_input_digest,
        current_position: &result.current_position,
        source_set: &result.source_set,
        policy_id: &result.policy_id,
        policy_digest: &result.policy_digest,
        declarations: &result.declarations,
        assessments: &result.assessments,
        model_details: details,
        equivalence_classes: &result.equivalence_classes,
        discriminators: &result.discriminators,
        discriminator_search: &result.discriminator_search,
        comparison: &result.comparison,
        omission_frontier: &result.omission_frontier,
        unknown_slots: &result.unknown_slots,
        unknown_total: result.unknown_total,
        unknown_omitted_count: result.unknown_omitted_count,
        omitted_count: result.omitted_count,
        distinct_material_classes: result.distinct_material_classes,
        required_min_classes: result.required_min_classes,
        model_coverage: result.model_coverage,
        source_coverage: result.source_coverage,
        disposition: result.disposition,
        digest: &result.digest,
    };
    preflight_with_context(&borrowed, ceiling, meter, model_id)
}

pub(crate) fn preflight_result(
    result: &RivalModelSet,
    ceiling: usize,
    meter: &mut OperationMeter,
) -> Result<usize, RivalModelError> {
    preflight_with_meter(result, ceiling, meter)
}

pub(crate) fn preflight_model_body(
    declaration: &RivalModelDeclaration,
    ceiling: usize,
    meter: &mut OperationMeter,
) -> Result<usize, RivalModelError> {
    preflight_with_context(declaration, ceiling, meter, Some(&declaration.model_id))
}

pub(crate) fn preflight_declarations_materialization(
    declarations: &RivalDeclarationSet,
    meter: &mut OperationMeter,
) -> Result<usize, RivalModelError> {
    preflight_with_meter(declarations, MAX_RIVAL_WIRE_BYTES, meter)
}

/// Reserves a conservative, input-derived envelope for the mandatory result
/// skeleton and every possible typed frontier. The extra capacity is only a
/// funding bound; synthetic values are never emitted as frontier data.
#[allow(
    clippy::too_many_lines,
    reason = "capacity planning keeps ordered section reserves and final passes atomic"
)]
pub(crate) fn mandatory_capacity_bytes(
    result: &RivalModelSet,
    declarations: &RivalDeclarationSet,
    meter: &mut OperationMeter,
) -> Result<usize, RivalModelError> {
    #[derive(Serialize)]
    struct BorrowedModelRef<'a> {
        model_id: &'a ArtifactId,
        model_revision: u64,
        declaration_digest: &'a str,
    }
    #[derive(Serialize)]
    struct BorrowedFrontier<'a, 'b> {
        model_ids: &'b [BorrowedModelRef<'a>],
        sections: &'b [OutputSection],
        exhausted_stage: Option<WorkStage>,
        exhausted_model_id: Option<&'a ArtifactId>,
        exhausted_prediction_id: Option<&'a ArtifactId>,
        exhausted_pair: Option<(&'a ArtifactId, &'a ArtifactId)>,
        exhausted_prediction_pair: Option<(&'a ArtifactId, &'a ArtifactId)>,
    }
    let scan_units = declarations
        .models
        .len()
        .checked_add(declarations.predictions.len())
        .and_then(|count| count.checked_add(3))
        .ok_or(RivalModelError::Bound {
            field: "result.frontier_capacity_scan",
            maximum: MAX_RIVAL_WIRE_BYTES,
            actual: usize::MAX,
        })?;
    match meter.charge(scan_units, WorkStage::ResultPacking, None, None)? {
        MeterCharge::Charged => {}
        MeterCharge::Exhausted => {
            return Err(RivalModelError::Bound {
                field: "result.frontier_capacity_scan",
                maximum: MAX_RIVAL_WIRE_BYTES,
                actual: scan_units,
            });
        }
    }
    let skeleton = preflight_with_meter(result, MAX_RIVAL_WIRE_BYTES, meter)?;
    let comparison_skeleton =
        preflight_with_meter(&result.comparison, MAX_RIVAL_WIRE_BYTES, meter)?;
    let comparison_fallback = comparison_fallback_capacity(declarations, meter)?;
    let model_ids = declarations
        .models
        .iter()
        .map(eliot_dreamer_contracts::rival::RivalModelSlot::stable_id)
        .collect::<Vec<_>>();
    let prediction_ids = declarations
        .predictions
        .iter()
        .map(|slot| match slot {
            RivalPredictionSlot::Retained { prediction } => &prediction.prediction_id,
            RivalPredictionSlot::Unavailable { prediction_id, .. } => prediction_id,
        })
        .collect::<Vec<_>>();
    let max_model_id = max_wire_id(model_ids.iter().copied(), meter)?;
    let max_prediction_id = max_wire_id(prediction_ids.iter().copied(), meter)?;
    let model_refs = declarations
        .models
        .iter()
        .filter_map(|slot| match slot {
            eliot_dreamer_contracts::rival::RivalModelSlot::Retained { declaration } => {
                Some(BorrowedModelRef {
                    model_id: &declaration.model_id,
                    model_revision: declaration.model_revision,
                    declaration_digest: &declaration.digest,
                })
            }
            eliot_dreamer_contracts::rival::RivalModelSlot::Unavailable { .. } => None,
        })
        .collect::<Vec<_>>();
    let sections = [
        OutputSection::Models,
        OutputSection::AnalysisWork,
        OutputSection::Comparisons,
        OutputSection::SourceDeclarations,
    ];
    let mut largest_stage = WorkStage::ModelAssessment;
    let mut largest_stage_bytes = 0;
    for stage in all_work_stages() {
        let stage_bytes = preflight_with_meter(&stage, MAX_RIVAL_WIRE_BYTES, meter)?;
        if stage_bytes > largest_stage_bytes {
            largest_stage = stage;
            largest_stage_bytes = stage_bytes;
        }
    }
    let frontier = BorrowedFrontier {
        model_ids: &model_refs,
        sections: &sections,
        exhausted_stage: Some(largest_stage),
        exhausted_model_id: max_model_id,
        exhausted_prediction_id: max_prediction_id,
        exhausted_pair: max_model_id.map(|id| (id, id)),
        exhausted_prediction_pair: max_prediction_id.map(|id| (id, id)),
    };
    let frontier_bytes = preflight_with_meter(&frontier, MAX_RIVAL_WIRE_BYTES, meter)?;
    let base_frontier =
        preflight_with_meter(&result.omission_frontier, MAX_RIVAL_WIRE_BYTES, meter)?;
    skeleton
        .checked_sub(base_frontier)
        .and_then(|bytes| bytes.checked_sub(comparison_skeleton))
        .and_then(|bytes| bytes.checked_add(comparison_fallback))
        .and_then(|bytes| bytes.checked_add(frontier_bytes))
        .ok_or(RivalModelError::Bound {
            field: "result.frontier_capacity",
            maximum: MAX_RIVAL_WIRE_BYTES,
            actual: usize::MAX,
        })
}

fn comparison_fallback_capacity(
    declarations: &RivalDeclarationSet,
    meter: &mut OperationMeter,
) -> Result<usize, RivalModelError> {
    let count = 4096usize;
    let address = SourceAddress {
        model_row: u32::try_from(declarations.models.len().saturating_sub(1)).unwrap_or(u32::MAX),
        field: ComparisonField::Explanations,
        entry: Some(u32::MAX),
        member: None,
    };
    let addresses = vec![address; count];
    let fallback = ComparisonMap {
        completion: ComparisonCompletion::Bounded,
        phase: ComparisonPhase::Output,
        frontier: Some(address),
        model_context: addresses.clone(),
        groups: vec![SharedInputGroup {
            kind: SharedInputKind::Claim,
            occurrences: addresses,
        }],
    };
    preflight_with_meter(&fallback, MAX_RIVAL_WIRE_BYTES, meter)
}

fn all_work_stages() -> [WorkStage; 36] {
    [
        WorkStage::ModelAssessment,
        WorkStage::MaterialEquivalence,
        WorkStage::MaterialProjectionHash,
        WorkStage::ClaimReference,
        WorkStage::ClaimLookup,
        WorkStage::ClaimOwnerCheck,
        WorkStage::AssumptionReference,
        WorkStage::AssumptionLookup,
        WorkStage::AssumptionOwnerCheck,
        WorkStage::DependencyRetainedCollection,
        WorkStage::DependencyIndexEntry,
        WorkStage::DependencyIndexInsert,
        WorkStage::DependencyEdgeTable,
        WorkStage::DependencyNode,
        WorkStage::DependencyReference,
        WorkStage::DependencyEdge,
        WorkStage::RelatedDependencyScan,
        WorkStage::UnavailableDependencyScan,
        WorkStage::DependencyDfsNode,
        WorkStage::DependencyDfsEdge,
        WorkStage::DependencyLookup,
        WorkStage::RelatedModelLookup,
        WorkStage::RecordDependencyLookup,
        WorkStage::CausalReference,
        WorkStage::CausalLookup,
        WorkStage::PredictionReference,
        WorkStage::PredictionLookup,
        WorkStage::PredictionOwnerCheck,
        WorkStage::PredictionAssumptionLookup,
        WorkStage::PredictionAssumptionOwnerCheck,
        WorkStage::PredictionIndexScan,
        WorkStage::PredictionIndexEntry,
        WorkStage::DiscriminatorPair,
        WorkStage::PredictionLookupCompare,
        WorkStage::DiscriminatorLimit,
        WorkStage::ResultPacking,
    ]
}

fn max_wire_id<'a, I>(
    ids: I,
    meter: &mut OperationMeter,
) -> Result<Option<&'a ArtifactId>, RivalModelError>
where
    I: Iterator<Item = &'a ArtifactId>,
{
    let mut maximum = 0;
    let mut selected = None;
    for id in ids {
        let bytes = preflight_with_meter(id, MAX_RIVAL_WIRE_BYTES, meter)?;
        if bytes > maximum {
            maximum = bytes;
            selected = Some(id);
        }
    }
    Ok(selected)
}

fn remaining(
    limit: Option<u64>,
    prior: u64,
    field: &'static str,
) -> Result<usize, RivalModelError> {
    let limit = limit.ok_or(RivalModelError::InvalidContract("job.budget"))?;
    let remaining = limit.checked_sub(prior).ok_or(RivalModelError::Bound {
        field,
        maximum: usize::try_from(limit).unwrap_or(usize::MAX),
        actual: usize::try_from(prior).unwrap_or(usize::MAX),
    })?;
    usize::try_from(remaining).map_err(|_| RivalModelError::Bound {
        field,
        maximum: usize::MAX,
        actual: usize::MAX,
    })
}
