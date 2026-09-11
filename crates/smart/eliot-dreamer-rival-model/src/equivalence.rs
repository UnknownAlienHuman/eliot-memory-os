//! Conservative material projections for retained rival declarations.

use crate::bounds::{self, MAX_RIVAL_WIRE_BYTES};
use crate::error::RivalModelError;
use crate::meter::{MeterCharge, OperationMeter};
use crate::states::WorkStage;
use eliot_dreamer_contracts::rival::{
    ClaimDeclarations, ConditionAssumptionRef, DeclarationAvailability, MaterialClaimRef,
    PredictionAvailability, RivalDependency, RivalModelDeclaration, RivalPredictionRef,
    RivalPredictionSlot, VerifierAvailability,
};
use eliot_dreamer_contracts::{canonical_bytes, digest_hex};
use eliot_epistemic_contracts::{CausalClaim, CausalStatus, EvidenceGrade, ValidityBounds};
use serde::Serialize;

const HASH_BLOCK_BYTES: usize = 1024;

/// Computes an equivalence key while retaining explicit uncertainty as `None`.
/// Structural mismatches and malformed supplied records remain errors.
pub(crate) fn material_digest(
    declaration: &RivalModelDeclaration,
    set: &eliot_dreamer_contracts::rival::RivalDeclarationSet,
    meter: &mut OperationMeter,
) -> Result<Option<String>, RivalModelError> {
    if matches!(
        meter.charge(
            1,
            WorkStage::MaterialEquivalence,
            Some(&declaration.model_id),
            None,
        )?,
        MeterCharge::Exhausted
    ) {
        return Ok(None);
    }
    let model_id = Some(&declaration.model_id);
    let Some(explanations) = resolve_claim_refs(&declaration.explanations, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(assumptions) = resolve_assumptions(&declaration.assumptions, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(predictions) =
        resolve_predictions(&declaration.prediction_refs, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(supporting_claims) =
        resolve_claim_declarations(&declaration.supporting_claims, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(counterevidence_claims) =
        resolve_claim_declarations(&declaration.counterevidence_claims, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(revision_conditions) =
        resolve_claim_declarations(&declaration.revision_conditions, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(invalidation_conditions) =
        resolve_claim_declarations(&declaration.invalidation_conditions, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(successful_transfers) =
        resolve_claim_declarations(&declaration.successful_transfers, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(failed_transfers) =
        resolve_claim_declarations(&declaration.failed_transfers, set, meter, model_id)?
    else {
        return Ok(None);
    };
    let Some(downstream_effects) =
        resolve_claim_declarations(&declaration.downstream_effects, set, meter, model_id)?
    else {
        return Ok(None);
    };
    if !resolve_dependencies(&declaration.dependency_refs, set, meter, model_id)? {
        return Ok(None);
    }
    let Some(causal_readings) =
        resolve_causal_readings(&declaration.causal_readings, meter, model_id)?
    else {
        return Ok(None);
    };
    let projection = MaterialProjection {
        applicability: &declaration.applicability,
        question: &declaration.question,
        explanations: &explanations,
        assumptions: &assumptions,
        predictions: &predictions,
        dependency_refs: &declaration.dependency_refs,
        causal_readings: &causal_readings,
        supporting_claims: &supporting_claims,
        counterevidence_claims: &counterevidence_claims,
        revision_conditions: &revision_conditions,
        invalidation_conditions: &invalidation_conditions,
        successful_transfers: &successful_transfers,
        failed_transfers: &failed_transfers,
        downstream_effects: &downstream_effects,
    };
    let projection_bytes = bounds::preflight(&projection, MAX_RIVAL_WIRE_BYTES)?;
    let hash_blocks = projection_bytes.div_ceil(HASH_BLOCK_BYTES).max(1);
    if matches!(
        meter.charge(
            hash_blocks,
            WorkStage::MaterialProjectionHash,
            model_id,
            None
        )?,
        MeterCharge::Exhausted
    ) {
        return Ok(None);
    }
    let bytes = canonical_bytes(&projection)
        .map_err(|_| RivalModelError::InvalidContract("model_projection"))?;
    Ok(Some(digest_hex(&bytes)))
}

#[derive(Serialize)]
struct ClaimMaterial<'a> {
    claim_id: &'a str,
    proposition: &'a eliot_dreamer_contracts::grounding::PropositionId,
    digest: &'a str,
}

#[derive(Serialize)]
struct PredictionMaterial<'a> {
    target: ClaimMaterial<'a>,
    applicability: &'a ValidityBounds,
    condition_assumptions: &'a std::collections::BTreeSet<ConditionAssumptionRef>,
    expected: &'a PredictionAvailability,
    falsifier: &'a PredictionAvailability,
    forecast: &'a eliot_dreamer_contracts::rival::RivalForecast,
    verifier: &'a VerifierAvailability,
}

#[derive(Serialize)]
struct CausalMaterial<'a> {
    subject: &'a eliot_epistemic_contracts::PropositionId,
    status: CausalStatus,
    mechanism: &'a str,
    rivals: &'a std::collections::BTreeSet<String>,
    confounders: &'a std::collections::BTreeSet<String>,
    outcome: &'a str,
    control: &'a str,
    scope: &'a str,
    ceiling: EvidenceGrade,
}

#[derive(Serialize)]
enum MaterialAvailability<T> {
    Supplied { entries: Vec<T> },
    NotApplicable { reason: String },
}

#[derive(Serialize)]
struct MaterialProjection<'a> {
    applicability: &'a ValidityBounds,
    question: &'a str,
    explanations: &'a [ClaimMaterial<'a>],
    assumptions: &'a MaterialAvailability<ConditionAssumptionRef>,
    predictions: &'a MaterialAvailability<PredictionMaterial<'a>>,
    dependency_refs: &'a DeclarationAvailability<RivalDependency>,
    causal_readings: &'a MaterialAvailability<CausalMaterial<'a>>,
    supporting_claims: &'a MaterialAvailability<ClaimMaterial<'a>>,
    counterevidence_claims: &'a MaterialAvailability<ClaimMaterial<'a>>,
    revision_conditions: &'a MaterialAvailability<ClaimMaterial<'a>>,
    invalidation_conditions: &'a MaterialAvailability<ClaimMaterial<'a>>,
    successful_transfers: &'a MaterialAvailability<ClaimMaterial<'a>>,
    failed_transfers: &'a MaterialAvailability<ClaimMaterial<'a>>,
    downstream_effects: &'a MaterialAvailability<ClaimMaterial<'a>>,
}

fn resolve_claim_refs<'a>(
    refs: &[MaterialClaimRef],
    set: &'a eliot_dreamer_contracts::rival::RivalDeclarationSet,
    meter: &mut OperationMeter,
    model_id: Option<&eliot_dreamer_contracts::grounding::ArtifactId>,
) -> Result<Option<Vec<ClaimMaterial<'a>>>, RivalModelError> {
    let mut resolved = Vec::with_capacity(refs.len());
    for reference in refs {
        if matches!(
            meter.charge(1, WorkStage::ClaimReference, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        let mut slot = None;
        for candidate in &set.claims {
            if matches!(
                meter.charge(1, WorkStage::ClaimLookup, model_id, None)?,
                MeterCharge::Exhausted
            ) {
                return Ok(None);
            }
            if candidate.stable_id() == reference.claim_id {
                slot = Some(candidate);
                break;
            }
        }
        let Some(slot) = slot else {
            return Err(RivalModelError::InvalidContract("missing_claim_material"));
        };
        let eliot_dreamer_contracts::rival::RivalClaimSlot::Retained { claim } = slot else {
            return Ok(None);
        };
        if matches!(
            meter.charge(1, WorkStage::ClaimOwnerCheck, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        reference
            .validate_against(claim)
            .map_err(|_| RivalModelError::InvalidContract("claim_material"))?;
        resolved.push(ClaimMaterial {
            claim_id: &claim.claim_id,
            proposition: &claim.proposition,
            digest: &claim.source_preimage_digest,
        });
    }
    Ok(Some(resolved))
}

fn resolve_claim_declarations<'a>(
    declarations: &ClaimDeclarations,
    set: &'a eliot_dreamer_contracts::rival::RivalDeclarationSet,
    meter: &mut OperationMeter,
    model_id: Option<&eliot_dreamer_contracts::grounding::ArtifactId>,
) -> Result<Option<MaterialAvailability<ClaimMaterial<'a>>>, RivalModelError> {
    match declarations {
        ClaimDeclarations::Supplied { claims } => {
            Ok(resolve_claim_refs(claims, set, meter, model_id)?
                .map(|entries| MaterialAvailability::Supplied { entries }))
        }
        ClaimDeclarations::Unknown { .. } => Ok(None),
        ClaimDeclarations::NotApplicable { reason } => {
            Ok(Some(MaterialAvailability::NotApplicable {
                reason: reason.clone(),
            }))
        }
    }
}

fn resolve_assumptions(
    availability: &DeclarationAvailability<ConditionAssumptionRef>,
    set: &eliot_dreamer_contracts::rival::RivalDeclarationSet,
    meter: &mut OperationMeter,
    model_id: Option<&eliot_dreamer_contracts::grounding::ArtifactId>,
) -> Result<Option<MaterialAvailability<ConditionAssumptionRef>>, RivalModelError> {
    let entries = match availability {
        DeclarationAvailability::Supplied { entries } => entries,
        DeclarationAvailability::Unknown { .. } => return Ok(None),
        DeclarationAvailability::NotApplicable { reason } => {
            return Ok(Some(MaterialAvailability::NotApplicable {
                reason: reason.clone(),
            }));
        }
    };
    for reference in entries {
        if matches!(
            meter.charge(1, WorkStage::AssumptionReference, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        let mut slot = None;
        for candidate in &set.assumptions {
            if matches!(
                meter.charge(1, WorkStage::AssumptionLookup, model_id, None)?,
                MeterCharge::Exhausted
            ) {
                return Ok(None);
            }
            if candidate.stable_id() == reference.assumption_id {
                slot = Some(candidate);
                break;
            }
        }
        let Some(slot) = slot else {
            return Err(RivalModelError::InvalidContract(
                "missing_assumption_material",
            ));
        };
        let eliot_dreamer_contracts::rival::RivalAssumptionSlot::Retained { assumption } = slot
        else {
            return Ok(None);
        };
        if matches!(
            meter.charge(1, WorkStage::AssumptionOwnerCheck, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        if assumption.digest != reference.assumption_digest {
            return Err(RivalModelError::InvalidContract("assumption_material"));
        }
    }
    Ok(Some(MaterialAvailability::Supplied {
        entries: entries.clone(),
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "dependency resolution preserves typed owner joins and unresolved states"
)]
fn resolve_dependencies(
    availability: &DeclarationAvailability<RivalDependency>,
    set: &eliot_dreamer_contracts::rival::RivalDeclarationSet,
    meter: &mut OperationMeter,
    model_id: Option<&eliot_dreamer_contracts::grounding::ArtifactId>,
) -> Result<bool, RivalModelError> {
    let entries = match availability {
        DeclarationAvailability::Supplied { entries } => entries,
        DeclarationAvailability::Unknown { .. } => return Ok(false),
        DeclarationAvailability::NotApplicable { .. } => return Ok(true),
    };
    for dependency in entries {
        if matches!(
            meter.charge(1, WorkStage::DependencyReference, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(false);
        }
        match dependency {
            RivalDependency::Model { reference } => {
                let mut slot = None;
                for candidate in &set.models {
                    if matches!(
                        meter.charge(1, WorkStage::DependencyLookup, model_id, None)?,
                        MeterCharge::Exhausted
                    ) {
                        return Ok(false);
                    }
                    if candidate.stable_id() == &reference.model_id {
                        slot = Some(candidate);
                        break;
                    }
                }
                let Some(slot) = slot else {
                    for related in &set.related_models {
                        if matches!(
                            meter.charge(1, WorkStage::RelatedModelLookup, model_id, None)?,
                            MeterCharge::Exhausted
                        ) {
                            return Ok(false);
                        }
                        if related.reference == *reference {
                            return Ok(false);
                        }
                    }
                    return Err(RivalModelError::InvalidContract(
                        "missing_model_dependency_material",
                    ));
                };
                match slot {
                    eliot_dreamer_contracts::rival::RivalModelSlot::Retained { declaration } => {
                        if declaration.model_revision != reference.model_revision
                            || declaration.digest != reference.declaration_digest
                        {
                            return Err(RivalModelError::InvalidContract(
                                "model_dependency_identity",
                            ));
                        }
                    }
                    eliot_dreamer_contracts::rival::RivalModelSlot::Unavailable {
                        model_revision,
                        declaration_digest,
                        ..
                    } => {
                        if model_revision
                            .is_some_and(|revision| revision != reference.model_revision)
                            || declaration_digest
                                .as_ref()
                                .is_some_and(|digest| digest != &reference.declaration_digest)
                        {
                            return Err(RivalModelError::InvalidContract(
                                "model_dependency_identity",
                            ));
                        }
                        return Ok(false);
                    }
                }
            }
            RivalDependency::Record {
                record_id,
                content_digest,
                source_revision,
            } => {
                let mut slot = None;
                for candidate in &set.sources {
                    if matches!(
                        meter.charge(1, WorkStage::RecordDependencyLookup, model_id, None)?,
                        MeterCharge::Exhausted
                    ) {
                        return Ok(false);
                    }
                    if candidate.stable_id() == record_id {
                        slot = Some(candidate);
                        break;
                    }
                }
                let Some(slot) = slot else {
                    return Err(RivalModelError::InvalidContract(
                        "missing_record_dependency_material",
                    ));
                };
                match slot {
                    eliot_dreamer_contracts::rival::RivalSourceSlot::Retained { reference } => {
                        if reference.content_digest != *content_digest
                            || reference.source_revision != *source_revision
                        {
                            return Err(RivalModelError::InvalidContract(
                                "record_dependency_identity",
                            ));
                        }
                    }
                    eliot_dreamer_contracts::rival::RivalSourceSlot::Unavailable {
                        content_digest: known_digest,
                        source_revision: known_revision,
                        ..
                    } => {
                        if known_digest
                            .as_ref()
                            .is_some_and(|digest| digest != content_digest)
                            || known_revision
                                .as_ref()
                                .is_some_and(|revision| revision != source_revision)
                        {
                            return Err(RivalModelError::InvalidContract(
                                "record_dependency_identity",
                            ));
                        }
                        return Ok(false);
                    }
                }
            }
        }
    }
    Ok(true)
}

fn resolve_causal_readings<'a>(
    availability: &'a DeclarationAvailability<CausalClaim>,
    meter: &mut OperationMeter,
    model_id: Option<&eliot_dreamer_contracts::grounding::ArtifactId>,
) -> Result<Option<MaterialAvailability<CausalMaterial<'a>>>, RivalModelError> {
    let entries = match availability {
        DeclarationAvailability::Supplied { entries } => entries,
        DeclarationAvailability::Unknown { .. } => return Ok(None),
        DeclarationAvailability::NotApplicable { reason } => {
            return Ok(Some(MaterialAvailability::NotApplicable {
                reason: reason.clone(),
            }));
        }
    };
    let mut resolved = Vec::with_capacity(entries.len());
    for causal in entries {
        if matches!(
            meter.charge(1, WorkStage::CausalReference, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        if matches!(
            meter.charge(1, WorkStage::CausalLookup, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        causal
            .validate()
            .map_err(|_| RivalModelError::InvalidContract("causal_material"))?;
        if causal.status == CausalStatus::Unknown {
            return Ok(None);
        }
        resolved.push(CausalMaterial {
            subject: &causal.subject,
            status: causal.status,
            mechanism: &causal.mechanism,
            rivals: &causal.rivals,
            confounders: &causal.confounders,
            outcome: &causal.outcome,
            control: &causal.control,
            scope: &causal.scope,
            ceiling: causal.ceiling,
        });
    }
    Ok(Some(MaterialAvailability::Supplied { entries: resolved }))
}

#[allow(
    clippy::too_many_lines,
    reason = "prediction resolution retains ordered references and bounded availability"
)]
fn resolve_predictions<'a>(
    availability: &DeclarationAvailability<RivalPredictionRef>,
    set: &'a eliot_dreamer_contracts::rival::RivalDeclarationSet,
    meter: &mut OperationMeter,
    model_id: Option<&eliot_dreamer_contracts::grounding::ArtifactId>,
) -> Result<Option<MaterialAvailability<PredictionMaterial<'a>>>, RivalModelError> {
    let entries = match availability {
        DeclarationAvailability::Supplied { entries } => entries,
        DeclarationAvailability::Unknown { .. } => return Ok(None),
        DeclarationAvailability::NotApplicable { reason } => {
            return Ok(Some(MaterialAvailability::NotApplicable {
                reason: reason.clone(),
            }));
        }
    };
    let mut resolved = Vec::with_capacity(entries.len());
    for reference in entries {
        if matches!(
            meter.charge(1, WorkStage::PredictionReference, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        let mut slot = None;
        for candidate in &set.predictions {
            if matches!(
                meter.charge(1, WorkStage::PredictionLookup, model_id, None)?,
                MeterCharge::Exhausted
            ) {
                return Ok(None);
            }
            if candidate.stable_id() == &reference.prediction_id {
                slot = Some(candidate);
                break;
            }
        }
        let Some(slot) = slot else {
            return Err(RivalModelError::InvalidContract(
                "missing_prediction_material",
            ));
        };
        let RivalPredictionSlot::Retained { prediction } = slot else {
            return Ok(None);
        };
        if matches!(
            meter.charge(1, WorkStage::PredictionOwnerCheck, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(None);
        }
        if prediction.digest != reference.prediction_digest {
            return Err(RivalModelError::InvalidContract("prediction_material"));
        }
        let Some(mut target_material) = resolve_claim_refs(
            std::slice::from_ref(&prediction.target),
            set,
            meter,
            model_id,
        )?
        else {
            return Ok(None);
        };
        let target = target_material
            .pop()
            .ok_or(RivalModelError::InvalidContract("prediction_target"))?;
        for assumption in &prediction.condition_assumptions {
            let mut assumption_slot = None;
            for candidate in &set.assumptions {
                if matches!(
                    meter.charge(1, WorkStage::PredictionAssumptionLookup, model_id, None)?,
                    MeterCharge::Exhausted
                ) {
                    return Ok(None);
                }
                if candidate.stable_id() == assumption.assumption_id {
                    assumption_slot = Some(candidate);
                    break;
                }
            }
            let Some(assumption_slot) = assumption_slot else {
                return Err(RivalModelError::InvalidContract(
                    "missing_prediction_assumption",
                ));
            };
            let eliot_dreamer_contracts::rival::RivalAssumptionSlot::Retained {
                assumption: record,
            } = assumption_slot
            else {
                return Ok(None);
            };
            if matches!(
                meter.charge(1, WorkStage::PredictionAssumptionOwnerCheck, model_id, None)?,
                MeterCharge::Exhausted
            ) {
                return Ok(None);
            }
            if record.digest != assumption.assumption_digest {
                return Err(RivalModelError::InvalidContract(
                    "prediction_assumption_digest",
                ));
            }
        }
        for forecast in [
            &prediction.forecast.verifier_verdict,
            &prediction.forecast.diagnostic_change,
            &prediction.forecast.effect_blast_radius,
            &prediction.forecast.expected_value_or_range,
        ] {
            if let eliot_dreamer_contracts::rival::ForecastAvailability::Claim { reference } =
                forecast
                && resolve_claim_refs(std::slice::from_ref(reference), set, meter, model_id)?
                    .is_none()
            {
                return Ok(None);
            }
        }
        if matches!(
            &prediction.expected,
            eliot_dreamer_contracts::rival::PredictionAvailability::Unknown { .. }
        ) || matches!(
            &prediction.falsifier,
            eliot_dreamer_contracts::rival::PredictionAvailability::Unknown { .. }
        ) || matches!(
            &prediction.forecast.verifier_verdict,
            eliot_dreamer_contracts::rival::ForecastAvailability::Unknown { .. }
        ) || matches!(
            &prediction.forecast.diagnostic_change,
            eliot_dreamer_contracts::rival::ForecastAvailability::Unknown { .. }
        ) || matches!(
            &prediction.forecast.effect_blast_radius,
            eliot_dreamer_contracts::rival::ForecastAvailability::Unknown { .. }
        ) || matches!(
            &prediction.forecast.expected_value_or_range,
            eliot_dreamer_contracts::rival::ForecastAvailability::Unknown { .. }
        ) || matches!(
            &prediction.verifier,
            VerifierAvailability::Unavailable { .. }
        ) {
            return Ok(None);
        }
        resolved.push(PredictionMaterial {
            target,
            applicability: &prediction.applicability,
            condition_assumptions: &prediction.condition_assumptions,
            expected: &prediction.expected,
            falsifier: &prediction.falsifier,
            forecast: &prediction.forecast,
            verifier: &prediction.verifier,
        });
    }
    Ok(Some(MaterialAvailability::Supplied { entries: resolved }))
}
