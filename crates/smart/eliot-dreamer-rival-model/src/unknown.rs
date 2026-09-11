//! Compact, source-bound addresses for explicitly unknown rival inputs.

use crate::error::RivalModelError;
use eliot_dreamer_contracts::grounding::ArtifactId;
use eliot_dreamer_contracts::grounding::PrecisionPayload;
use eliot_dreamer_contracts::rival::{
    ClaimDeclarations, CommonModeDisclosure, CurrentPositionAvailability, DeclarationAvailability,
    ForecastAvailability, RelatedRivalModelReference, RivalAssumptionSlot, RivalClaimSlot,
    RivalCoverageDeclaration, RivalCoverageReceipt, RivalDeclarationSet, RivalModelDeclaration,
    RivalModelSlot, RivalPredictionSlot, RivalSourceSlot, SuppliedLineage, TemporalAvailability,
    VerifierAvailability,
};
use eliot_epistemic_contracts::{CausalClaim, CausalStatus, ConflictSet, MemberDisposition};
use eliot_epistemic_contracts::{SupportRecord, SupportResult};
use serde::{Deserialize, Serialize};

/// Maximum number of addressable unknown facets retained for one set.
pub(crate) const MAX_UNKNOWN_SLOTS: usize = 4096;

/// Semantic table containing the unknown facet.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum UnknownTable {
    Set,
    Models,
    RelatedModels,
    Claims,
    Assumptions,
    Predictions,
    Sources,
    /// Unknown source-owner basis from the validated input's width observation.
    ConsultedSources,
    ModelCoverage,
    SourceCoverage,
}

/// Closed field identity; no free-form reason or path is copied into output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum UnknownField {
    Unresolved,
    UnavailableBody,
    SourceOwner,
    RelatedModelBody,
    Assumptions,
    Predictions,
    Dependencies,
    Support,
    Causal,
    Conflicts,
    SupportingClaims,
    CounterevidenceClaims,
    RevisionConditions,
    InvalidationConditions,
    SuccessfulTransfers,
    FailedTransfers,
    DownstreamEffects,
    CurrentPosition,
    Lineage,
    Temporal,
    CommonMode,
    Expected,
    Falsifier,
    ForecastVerifierVerdict,
    ForecastDiagnosticChange,
    ForecastEffectBlastRadius,
    ForecastExpectedValueOrRange,
    Verifier,
    CoverageDenominator,
    CoverageReceipt,
    SupportResult,
    SupportGrade,
    CausalStatus,
    ConflictUnresolved,
    ConflictUnresolvedOwner,
    CoverageMemberDisposition,
    PrecisionCoverageMember,
    AbsenceProofCoverageMember,
}

/// A compact pointer into an exact supplied declaration set.
///
/// `row`, `entry`, and `member` are source ordinals. For declaration tables,
/// the containing result binds the inventory to its exact set identity and
/// digest. `ConsultedSources` is a distinct input-owned source basis: its row
/// indexes the canonical sorted unknown-owner handles from the validated
/// source-width observation. These ordinals are compact expansion addresses,
/// not claims of source independence or authentication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownSlotRef {
    pub table: UnknownTable,
    pub row: Option<u16>,
    pub field: UnknownField,
    pub entry: Option<u16>,
    pub member: Option<u16>,
}

/// Collects only explicit unknown/unavailable facets. `NotApplicable`, empty
/// supplied collections, unsupported declarations, and contradictions remain
/// their own supplied states and do not create synthetic unknown entries.
#[allow(
    clippy::too_many_lines,
    reason = "ordered unknown-facet traversal shares one bounded frontier"
)]
pub(crate) fn collect_unknown_slots(
    set: &RivalDeclarationSet,
    unknown_owner_handles: &std::collections::BTreeSet<ArtifactId>,
) -> Result<Vec<UnknownSlotRef>, RivalModelError> {
    let mut slots = Vec::new();
    for (entry, _) in set.unresolved.iter().enumerate() {
        push(
            &mut slots,
            UnknownTable::Set,
            None,
            UnknownField::Unresolved,
            Some(entry),
            None,
        )?;
    }

    for (row, slot) in set.models.iter().enumerate() {
        match slot {
            RivalModelSlot::Unavailable { .. } => push(
                &mut slots,
                UnknownTable::Models,
                Some(row),
                UnknownField::UnavailableBody,
                None,
                None,
            )?,
            RivalModelSlot::Retained { declaration } => {
                collect_model(&mut slots, row, declaration)?;
            }
        }
    }
    for (row, related) in set.related_models.iter().enumerate() {
        collect_related(&mut slots, row, related)?;
    }
    for (row, slot) in set.claims.iter().enumerate() {
        match slot {
            RivalClaimSlot::Unavailable { .. } => push(
                &mut slots,
                UnknownTable::Claims,
                Some(row),
                UnknownField::UnavailableBody,
                None,
                None,
            )?,
            RivalClaimSlot::Retained { claim } => {
                collect_precision_payload(
                    &mut slots,
                    UnknownTable::Claims,
                    row,
                    None,
                    &claim.payload,
                )?;
            }
        }
    }
    for (row, slot) in set.assumptions.iter().enumerate() {
        if matches!(slot, RivalAssumptionSlot::Unavailable { .. }) {
            push(
                &mut slots,
                UnknownTable::Assumptions,
                Some(row),
                UnknownField::UnavailableBody,
                None,
                None,
            )?;
        }
    }
    for (row, slot) in set.predictions.iter().enumerate() {
        match slot {
            RivalPredictionSlot::Unavailable { .. } => push(
                &mut slots,
                UnknownTable::Predictions,
                Some(row),
                UnknownField::UnavailableBody,
                None,
                None,
            )?,
            RivalPredictionSlot::Retained { prediction } => {
                collect_prediction(&mut slots, row, prediction)?;
            }
        }
    }
    for (row, slot) in set.sources.iter().enumerate() {
        match slot {
            RivalSourceSlot::Unavailable { .. } => push(
                &mut slots,
                UnknownTable::Sources,
                Some(row),
                UnknownField::UnavailableBody,
                None,
                None,
            )?,
            RivalSourceSlot::Retained { reference } => {
                collect_source(&mut slots, row, reference)?;
            }
        }
    }
    collect_coverage(&mut slots, UnknownTable::ModelCoverage, &set.model_coverage)?;
    collect_coverage(
        &mut slots,
        UnknownTable::SourceCoverage,
        &set.source_coverage,
    )?;
    for (row, _) in unknown_owner_handles.iter().enumerate() {
        push(
            &mut slots,
            UnknownTable::ConsultedSources,
            Some(row),
            UnknownField::SourceOwner,
            None,
            None,
        )?;
    }
    Ok(slots)
}

#[allow(
    clippy::too_many_lines,
    reason = "atomic model-facet collection preserves owner ordering and bounds"
)]
fn collect_model(
    slots: &mut Vec<UnknownSlotRef>,
    row: usize,
    declaration: &RivalModelDeclaration,
) -> Result<(), RivalModelError> {
    for (entry, _) in declaration.unresolved.iter().enumerate() {
        push(
            slots,
            UnknownTable::Models,
            Some(row),
            UnknownField::Unresolved,
            Some(entry),
            None,
        )?;
    }
    collect_declaration_availability(
        slots,
        row,
        &declaration.assumptions,
        UnknownField::Assumptions,
    )?;
    collect_declaration_availability(
        slots,
        row,
        &declaration.prediction_refs,
        UnknownField::Predictions,
    )?;
    collect_declaration_availability(
        slots,
        row,
        &declaration.dependency_refs,
        UnknownField::Dependencies,
    )?;
    collect_declaration_availability(
        slots,
        row,
        &declaration.support_observations,
        UnknownField::Support,
    )?;
    collect_declaration_availability(
        slots,
        row,
        &declaration.causal_readings,
        UnknownField::Causal,
    )?;
    collect_declaration_availability(slots, row, &declaration.conflicts, UnknownField::Conflicts)?;
    if let DeclarationAvailability::Supplied { entries } = &declaration.support_observations {
        for (entry, support) in entries.iter().enumerate() {
            collect_support(slots, UnknownTable::Models, row, Some(entry), support)?;
        }
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.causal_readings {
        for (entry, causal) in entries.iter().enumerate() {
            collect_causal(slots, UnknownTable::Models, row, Some(entry), causal)?;
        }
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.conflicts {
        for (entry, conflict) in entries.iter().enumerate() {
            collect_conflict(slots, UnknownTable::Models, row, entry, conflict)?;
        }
    }
    for (claims, field) in [
        (
            &declaration.supporting_claims,
            UnknownField::SupportingClaims,
        ),
        (
            &declaration.counterevidence_claims,
            UnknownField::CounterevidenceClaims,
        ),
        (
            &declaration.revision_conditions,
            UnknownField::RevisionConditions,
        ),
        (
            &declaration.invalidation_conditions,
            UnknownField::InvalidationConditions,
        ),
        (
            &declaration.successful_transfers,
            UnknownField::SuccessfulTransfers,
        ),
        (&declaration.failed_transfers, UnknownField::FailedTransfers),
        (
            &declaration.downstream_effects,
            UnknownField::DownstreamEffects,
        ),
    ] {
        collect_claim_declarations(slots, row, claims, field)?;
    }
    if matches!(
        &declaration.current_position,
        CurrentPositionAvailability::Unknown { .. }
    ) {
        push(
            slots,
            UnknownTable::Models,
            Some(row),
            UnknownField::CurrentPosition,
            None,
            None,
        )?;
    }
    if matches!(&declaration.lineage, SuppliedLineage::Unknown { .. }) {
        push(
            slots,
            UnknownTable::Models,
            Some(row),
            UnknownField::Lineage,
            None,
            None,
        )?;
    }
    if matches!(&declaration.temporal, TemporalAvailability::Unknown { .. }) {
        push(
            slots,
            UnknownTable::Models,
            Some(row),
            UnknownField::Temporal,
            None,
            None,
        )?;
    }
    if matches!(
        &declaration.common_mode,
        CommonModeDisclosure::Unknown { .. }
    ) {
        push(
            slots,
            UnknownTable::Models,
            Some(row),
            UnknownField::CommonMode,
            None,
            None,
        )?;
    }
    Ok(())
}

fn collect_related(
    slots: &mut Vec<UnknownSlotRef>,
    row: usize,
    _related: &RelatedRivalModelReference,
) -> Result<(), RivalModelError> {
    push(
        slots,
        UnknownTable::RelatedModels,
        Some(row),
        UnknownField::RelatedModelBody,
        None,
        None,
    )
}

fn collect_prediction(
    slots: &mut Vec<UnknownSlotRef>,
    row: usize,
    prediction: &eliot_dreamer_contracts::rival::RivalPrediction,
) -> Result<(), RivalModelError> {
    if matches!(
        &prediction.expected,
        eliot_dreamer_contracts::rival::PredictionAvailability::Unknown { .. }
    ) {
        push(
            slots,
            UnknownTable::Predictions,
            Some(row),
            UnknownField::Expected,
            None,
            None,
        )?;
    }
    if matches!(
        &prediction.falsifier,
        eliot_dreamer_contracts::rival::PredictionAvailability::Unknown { .. }
    ) {
        push(
            slots,
            UnknownTable::Predictions,
            Some(row),
            UnknownField::Falsifier,
            None,
            None,
        )?;
    }
    for (forecast, field) in [
        (
            &prediction.forecast.verifier_verdict,
            UnknownField::ForecastVerifierVerdict,
        ),
        (
            &prediction.forecast.diagnostic_change,
            UnknownField::ForecastDiagnosticChange,
        ),
        (
            &prediction.forecast.effect_blast_radius,
            UnknownField::ForecastEffectBlastRadius,
        ),
        (
            &prediction.forecast.expected_value_or_range,
            UnknownField::ForecastExpectedValueOrRange,
        ),
    ] {
        if matches!(forecast, ForecastAvailability::Unknown { .. }) {
            push(
                slots,
                UnknownTable::Predictions,
                Some(row),
                field,
                None,
                None,
            )?;
        }
    }
    if matches!(
        &prediction.verifier,
        VerifierAvailability::Unavailable { .. }
    ) {
        push(
            slots,
            UnknownTable::Predictions,
            Some(row),
            UnknownField::Verifier,
            None,
            None,
        )?;
    }
    Ok(())
}

fn collect_source(
    slots: &mut Vec<UnknownSlotRef>,
    row: usize,
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
) -> Result<(), RivalModelError> {
    if let Some(support) = &reference.support {
        collect_support(slots, UnknownTable::Sources, row, None, support)?;
    }
    for (entry, assertion) in reference.assertions.iter().enumerate() {
        if let Some(support) = &assertion.support {
            collect_support(slots, UnknownTable::Sources, row, Some(entry), support)?;
        }
        collect_precision_payload(
            slots,
            UnknownTable::Sources,
            row,
            Some(entry),
            &assertion.precision,
        )?;
    }
    Ok(())
}

fn collect_precision_payload(
    slots: &mut Vec<UnknownSlotRef>,
    table: UnknownTable,
    row: usize,
    entry: Option<usize>,
    payload: &PrecisionPayload,
) -> Result<(), RivalModelError> {
    match payload {
        PrecisionPayload::Causal { causal } => {
            collect_causal(slots, table, row, entry, causal)?;
        }
        PrecisionPayload::AbsenceExhaustiveNegative {
            receipt,
            absence_proof,
            ..
        } => {
            if let Some(receipt) = receipt {
                collect_receipt_members(
                    slots,
                    table,
                    Some(row),
                    receipt,
                    UnknownField::PrecisionCoverageMember,
                    entry,
                )?;
            }
            if let Some(proof) = absence_proof {
                collect_receipt_members(
                    slots,
                    table,
                    Some(row),
                    &proof.receipt,
                    UnknownField::AbsenceProofCoverageMember,
                    entry,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_support(
    slots: &mut Vec<UnknownSlotRef>,
    table: UnknownTable,
    row: usize,
    entry: Option<usize>,
    support: &SupportRecord,
) -> Result<(), RivalModelError> {
    if support.result == SupportResult::Unknown {
        push(
            slots,
            table,
            Some(row),
            UnknownField::SupportResult,
            entry,
            None,
        )?;
    }
    if support.grade.grade.is_none() {
        push(
            slots,
            table,
            Some(row),
            UnknownField::SupportGrade,
            entry,
            None,
        )?;
    }
    Ok(())
}

fn collect_causal(
    slots: &mut Vec<UnknownSlotRef>,
    table: UnknownTable,
    row: usize,
    entry: Option<usize>,
    causal: &CausalClaim,
) -> Result<(), RivalModelError> {
    if causal.status == CausalStatus::Unknown {
        push(
            slots,
            table,
            Some(row),
            UnknownField::CausalStatus,
            entry,
            None,
        )?;
    }
    Ok(())
}

fn collect_conflict(
    slots: &mut Vec<UnknownSlotRef>,
    table: UnknownTable,
    row: usize,
    entry: usize,
    conflict: &ConflictSet,
) -> Result<(), RivalModelError> {
    for (member, _) in conflict.unresolved.iter().enumerate() {
        push(
            slots,
            table,
            Some(row),
            UnknownField::ConflictUnresolved,
            Some(entry),
            Some(member),
        )?;
    }
    for (member, _) in conflict.unresolved_owners.iter().enumerate() {
        push(
            slots,
            table,
            Some(row),
            UnknownField::ConflictUnresolvedOwner,
            Some(entry),
            Some(member),
        )?;
    }
    Ok(())
}

fn collect_receipt_members(
    slots: &mut Vec<UnknownSlotRef>,
    table: UnknownTable,
    row: Option<usize>,
    receipt: &eliot_epistemic_contracts::CoverageReceipt,
    field: UnknownField,
    entry: Option<usize>,
) -> Result<(), RivalModelError> {
    for (member, outcome) in receipt.members.iter().enumerate() {
        if matches!(
            outcome.disposition,
            MemberDisposition::Unknown | MemberDisposition::Unavailable
        ) {
            push(slots, table, row, field, entry, Some(member))?;
        }
    }
    Ok(())
}

fn collect_declaration_availability<T>(
    slots: &mut Vec<UnknownSlotRef>,
    row: usize,
    availability: &DeclarationAvailability<T>,
    field: UnknownField,
) -> Result<(), RivalModelError> {
    if matches!(availability, DeclarationAvailability::Unknown { .. }) {
        push(slots, UnknownTable::Models, Some(row), field, None, None)?;
    }
    Ok(())
}

fn collect_claim_declarations(
    slots: &mut Vec<UnknownSlotRef>,
    row: usize,
    declarations: &ClaimDeclarations,
    field: UnknownField,
) -> Result<(), RivalModelError> {
    if matches!(declarations, ClaimDeclarations::Unknown { .. }) {
        push(slots, UnknownTable::Models, Some(row), field, None, None)?;
    }
    Ok(())
}

fn collect_coverage(
    slots: &mut Vec<UnknownSlotRef>,
    table: UnknownTable,
    coverage: &RivalCoverageDeclaration,
) -> Result<(), RivalModelError> {
    if matches!(coverage, RivalCoverageDeclaration::Unknown { .. }) {
        push(
            slots,
            table,
            None,
            UnknownField::CoverageDenominator,
            None,
            None,
        )?;
    }
    let receipt = match coverage {
        RivalCoverageDeclaration::Supplied { receipt, .. }
        | RivalCoverageDeclaration::Unknown { receipt, .. } => receipt,
    };
    match receipt {
        RivalCoverageReceipt::Unavailable { .. } => push(
            slots,
            table,
            None,
            UnknownField::CoverageReceipt,
            None,
            None,
        )?,
        RivalCoverageReceipt::Supplied { receipt } => {
            collect_receipt_members(
                slots,
                table,
                None,
                receipt,
                UnknownField::CoverageMemberDisposition,
                None,
            )?;
        }
    }
    Ok(())
}

fn push(
    slots: &mut Vec<UnknownSlotRef>,
    table: UnknownTable,
    row: Option<usize>,
    field: UnknownField,
    entry: Option<usize>,
    member: Option<usize>,
) -> Result<(), RivalModelError> {
    if slots.len() >= MAX_UNKNOWN_SLOTS {
        return Err(RivalModelError::Bound {
            field: "unknown_slots",
            maximum: MAX_UNKNOWN_SLOTS,
            actual: slots.len().saturating_add(1),
        });
    }
    slots.push(UnknownSlotRef {
        table,
        row: ordinal(row)?,
        field,
        entry: ordinal(entry)?,
        member: ordinal(member)?,
    });
    Ok(())
}

fn ordinal(value: Option<usize>) -> Result<Option<u16>, RivalModelError> {
    value
        .map(u16::try_from)
        .transpose()
        .map_err(|_| RivalModelError::Bound {
            field: "unknown_slot.ordinal",
            maximum: u16::MAX as usize,
            actual: usize::MAX,
        })
}
