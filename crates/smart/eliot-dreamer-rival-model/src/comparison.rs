//! Bounded source-addressable comparison groups.
//!
//! This module records typed, repeated inputs without copying their payloads;
//! it does not establish source independence, equivalence, causality, truth,
//! or an experimental recommendation.

use crate::error::RivalModelError;
use crate::meter::{MeterCharge, OperationMeter, WorkAddress};
use crate::states::WorkStage;
use eliot_dreamer_contracts::grounding::canonical::SourceId;
use eliot_dreamer_contracts::rival::{
    ClaimDeclarations, CommonModeDisclosure, ConditionAssumptionRef, DeclarationAvailability,
    MaterialClaimRef, RivalDeclarationSet,
};
use eliot_epistemic_contracts::{CausalClaim, ConflictSet, LineageRootId, SupportRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Write};

/// The closed field location of a shared input occurrence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ComparisonField {
    Explanations,
    SupportingClaims,
    CounterevidenceClaims,
    RevisionConditions,
    InvalidationConditions,
    SuccessfulTransfers,
    FailedTransfers,
    DownstreamEffects,
    Assumptions,
    SupportObservations,
    CausalReadings,
    Conflicts,
    ConflictPosition,
    ConflictCommonLineage,
    SourceLineage,
    CausalLineage,
    CommonModeRoot,
    CommonModeClaims,
    Applicability,
    Question,
    AssumptionsAvailability,
    PredictionRefsAvailability,
    DependencyRefsAvailability,
    CurrentPosition,
    Temporal,
    Lineage,
    CommonMode,
}

/// Typed shared-input domain. Repeated owner IDs are retained as data only.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SharedInputKind {
    Claim,
    Assumption,
    SupportRecord,
    CausalRecord,
    SourceOwner,
    CommonModeRoot,
}

/// Compact location in the validated declaration source set.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAddress {
    pub model_row: u32,
    pub field: ComparisonField,
    pub entry: Option<u32>,
    pub member: Option<u32>,
}

/// One repeated typed input and all of its source-bound occurrences.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedInputGroup {
    pub kind: SharedInputKind,
    pub occurrences: Vec<SourceAddress>,
}

/// Whether the bounded comparison walk completed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ComparisonCompletion {
    NotStarted,
    Complete,
    Bounded,
}

/// Closed phase and exact address at which comparison work stopped.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ComparisonPhase {
    Walk,
    Compare,
    Hash,
    Output,
}

/// Immutable comparison carrier. Groups contain at least two distinct model
/// rows and retain every meaningful occurrence address.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonMap {
    pub completion: ComparisonCompletion,
    pub phase: ComparisonPhase,
    pub frontier: Option<SourceAddress>,
    /// Whole-field addresses preserving supplied availability and context.
    pub model_context: Vec<SourceAddress>,
    pub groups: Vec<SharedInputGroup>,
}

const MAX_COMPARISON_ITEMS: usize = 4096;

struct KeyGroup<'a> {
    kind: SharedInputKind,
    key: SharedKey<'a>,
    occurrences: Vec<SourceAddress>,
    models: BTreeSet<u32>,
    key_wire_bytes: usize,
}

#[derive(Clone, Copy)]
enum SharedKey<'a> {
    Claim(&'a MaterialClaimRef),
    Assumption(&'a ConditionAssumptionRef),
    Support(&'a SupportRecord),
    Causal(&'a CausalClaim),
    SourceOwner(&'a SourceId),
    CommonModeRoot(&'a LineageRootId),
}

impl SharedKey<'_> {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Claim(left), Self::Claim(right)) => *left == *right,
            (Self::Assumption(left), Self::Assumption(right)) => *left == *right,
            (Self::Support(left), Self::Support(right)) => *left == *right,
            (Self::Causal(left), Self::Causal(right)) => *left == *right,
            (Self::SourceOwner(left), Self::SourceOwner(right)) => *left == *right,
            (Self::CommonModeRoot(left), Self::CommonModeRoot(right)) => *left == *right,
            _ => false,
        }
    }
}

/// Builds a bounded comparison map from an already validated declaration set.
/// The walk is linear per occurrence and uses the shared operation meter; no
/// hash projection or source-independence claim is inferred.
#[allow(
    clippy::too_many_lines,
    reason = "ordered comparison walk preserves shared meter and exact aggregate frontiers"
)]
pub(crate) fn build_comparison_map(
    declarations: &RivalDeclarationSet,
    meter: &mut OperationMeter,
    output_ceiling: usize,
) -> Result<ComparisonMap, RivalModelError> {
    let mut state = ComparisonMap {
        completion: ComparisonCompletion::NotStarted,
        phase: ComparisonPhase::Walk,
        frontier: None,
        model_context: Vec::new(),
        groups: Vec::new(),
    };
    let Some(base_bytes) = bounded_wire_size(&state, output_ceiling)? else {
        state.completion = ComparisonCompletion::Bounded;
        state.phase = ComparisonPhase::Output;
        return Ok(state);
    };
    let mut output_budget = ComparisonBudget::new(base_bytes, output_ceiling);
    let mut occurrences = Vec::new();
    for (model_row, slot) in declarations.models.iter().enumerate() {
        let model_row = u32::try_from(model_row).map_err(|_| RivalModelError::Bound {
            field: "comparison.model_row",
            maximum: u32::MAX as usize,
            actual: model_row,
        })?;
        let declaration = match slot {
            eliot_dreamer_contracts::rival::RivalModelSlot::Retained { declaration } => {
                declaration.as_ref()
            }
            eliot_dreamer_contracts::rival::RivalModelSlot::Unavailable { .. } => continue,
        };
        let model_items = model_item_count(declaration)?;
        let current_items = state
            .model_context
            .len()
            .checked_add(occurrences.len())
            .ok_or(RivalModelError::Bound {
                field: "comparison.items",
                maximum: MAX_COMPARISON_ITEMS,
                actual: usize::MAX,
            })?;
        let next_items = current_items
            .checked_add(model_items)
            .ok_or(RivalModelError::Bound {
                field: "comparison.items",
                maximum: MAX_COMPARISON_ITEMS,
                actual: usize::MAX,
            })?;
        if next_items > MAX_COMPARISON_ITEMS {
            let frontier = SourceAddress {
                model_row,
                field: ComparisonField::Applicability,
                entry: None,
                member: None,
            };
            return finish_bounded(state, meter, ComparisonPhase::Walk, Some(frontier));
        }
        if matches!(
            meter.charge(model_items, WorkStage::ResultPacking, None, None)?,
            MeterCharge::Exhausted
        ) {
            let frontier = SourceAddress {
                model_row,
                field: ComparisonField::Applicability,
                entry: None,
                member: None,
            };
            return finish_bounded(state, meter, ComparisonPhase::Walk, Some(frontier));
        }
        for field in [
            ComparisonField::Applicability,
            ComparisonField::Question,
            ComparisonField::AssumptionsAvailability,
            ComparisonField::PredictionRefsAvailability,
            ComparisonField::DependencyRefsAvailability,
            ComparisonField::CurrentPosition,
            ComparisonField::Temporal,
            ComparisonField::Lineage,
            ComparisonField::CommonMode,
            ComparisonField::SupportObservations,
            ComparisonField::CausalReadings,
            ComparisonField::Conflicts,
            ComparisonField::SupportingClaims,
            ComparisonField::CounterevidenceClaims,
            ComparisonField::RevisionConditions,
            ComparisonField::InvalidationConditions,
            ComparisonField::SuccessfulTransfers,
            ComparisonField::FailedTransfers,
            ComparisonField::DownstreamEffects,
        ] {
            let address = SourceAddress {
                model_row,
                field,
                entry: None,
                member: None,
            };
            if !output_budget.admit(&address)? {
                return finish_bounded(state, meter, ComparisonPhase::Walk, Some(address));
            }
            state.model_context.push(address);
        }
        for (entry, claim) in declaration.explanations.iter().enumerate() {
            let entry = checked_ordinal(entry, "comparison.entry")?;
            occurrences.push(KeyOccurrence {
                kind: SharedInputKind::Claim,
                key: SharedKey::Claim(claim),
                address: SourceAddress {
                    model_row,
                    field: ComparisonField::Explanations,
                    entry: Some(entry),
                    member: None,
                },
            });
        }
        collect_claim_declaration(
            &mut occurrences,
            model_row,
            ComparisonField::SupportingClaims,
            &declaration.supporting_claims,
        )?;
        collect_claim_declaration(
            &mut occurrences,
            model_row,
            ComparisonField::CounterevidenceClaims,
            &declaration.counterevidence_claims,
        )?;
        collect_claim_declaration(
            &mut occurrences,
            model_row,
            ComparisonField::RevisionConditions,
            &declaration.revision_conditions,
        )?;
        collect_claim_declaration(
            &mut occurrences,
            model_row,
            ComparisonField::InvalidationConditions,
            &declaration.invalidation_conditions,
        )?;
        collect_claim_declaration(
            &mut occurrences,
            model_row,
            ComparisonField::SuccessfulTransfers,
            &declaration.successful_transfers,
        )?;
        collect_claim_declaration(
            &mut occurrences,
            model_row,
            ComparisonField::FailedTransfers,
            &declaration.failed_transfers,
        )?;
        collect_claim_declaration(
            &mut occurrences,
            model_row,
            ComparisonField::DownstreamEffects,
            &declaration.downstream_effects,
        )?;
        collect_assumptions(&mut occurrences, model_row, &declaration.assumptions)?;
        collect_support(
            &mut occurrences,
            model_row,
            &declaration.support_observations,
        )?;
        collect_causal(&mut occurrences, model_row, &declaration.causal_readings)?;
        if let Some(frontier) = collect_conflicts(
            &mut occurrences,
            &mut state.model_context,
            &mut output_budget,
            model_row,
            &declaration.conflicts,
        )? {
            return finish_bounded(state, meter, ComparisonPhase::Walk, Some(frontier));
        }
        collect_lineage(&mut occurrences, model_row, &declaration.lineage)?;
        collect_common_mode(&mut occurrences, model_row, &declaration.common_mode)?;
    }
    let mut key_sizes = Vec::with_capacity(occurrences.len());
    for item in &occurrences {
        let Some(size) = borrowed_key_size(&item.key, meter, item.address)? else {
            return finish_bounded(state, meter, ComparisonPhase::Compare, Some(item.address));
        };
        key_sizes.push(size);
    }
    state.completion = ComparisonCompletion::Complete;
    state.phase = ComparisonPhase::Compare;
    let mut groups: Vec<KeyGroup<'_>> = Vec::new();
    for (item, key_bytes) in occurrences.iter().zip(&key_sizes) {
        if matches!(
            meter.charge(1, WorkStage::MaterialEquivalence, None, None)?,
            MeterCharge::Exhausted
        ) {
            state.completion = ComparisonCompletion::Bounded;
            state.frontier = Some(item.address);
            state.phase = ComparisonPhase::Compare;
            break;
        }
        let mut matched = None;
        for (group_index, group) in groups.iter().enumerate() {
            let compare_work = wire_blocks(*key_bytes)?
                .checked_add(wire_blocks(group.key_wire_bytes)?)
                .ok_or(RivalModelError::Bound {
                    field: "comparison.key_work",
                    maximum: usize::MAX,
                    actual: usize::MAX,
                })?;
            if matches!(
                meter.charge_addressed(
                    compare_work.max(1),
                    WorkStage::MaterialEquivalence,
                    neutral_address(),
                )?,
                MeterCharge::Exhausted
            ) {
                state.completion = ComparisonCompletion::Bounded;
                state.frontier = Some(item.address);
                state.phase = ComparisonPhase::Compare;
                break;
            }
            if group.kind == item.kind && group.key.same(&item.key) {
                matched = Some(group_index);
                break;
            }
        }
        if state.completion == ComparisonCompletion::Bounded {
            break;
        }
        if let Some(group_index) = matched {
            if !output_budget.admit(&item.address)?
                || groups[group_index].occurrences.len() >= MAX_COMPARISON_ITEMS
            {
                state.completion = ComparisonCompletion::Bounded;
                state.frontier = Some(item.address);
                break;
            }
            groups[group_index].occurrences.push(item.address);
            groups[group_index].models.insert(item.address.model_row);
        } else {
            if groups.len() >= MAX_COMPARISON_ITEMS
                || !output_budget.reserve_group_prefix(item.kind)?
                || !output_budget.admit(&item.address)?
            {
                state.completion = ComparisonCompletion::Bounded;
                state.frontier = Some(item.address);
                break;
            }
            groups.push(KeyGroup {
                kind: item.kind,
                key: item.key,
                occurrences: vec![item.address],
                models: [item.address.model_row].into_iter().collect(),
                key_wire_bytes: *key_bytes,
            });
        }
    }
    let was_bounded = state.completion == ComparisonCompletion::Bounded;
    if !canonicalize(&mut state.model_context, &mut groups, meter)? {
        state.completion = ComparisonCompletion::Bounded;
        if !was_bounded {
            state.phase = ComparisonPhase::Compare;
            state.frontier = None;
        }
        state.model_context.clear();
        state.groups.clear();
        return Ok(state);
    }
    state.groups = groups
        .into_iter()
        .filter_map(|group| {
            (group.models.len() >= 2).then_some(SharedInputGroup {
                kind: group.kind,
                occurrences: group.occurrences,
            })
        })
        .collect();
    if state.completion == ComparisonCompletion::Complete {
        state.phase = ComparisonPhase::Output;
        if !metered_output_fits(&state, output_ceiling, meter)? {
            state.completion = ComparisonCompletion::Bounded;
            state.frontier = None;
        }
    } else {
        state.phase = ComparisonPhase::Compare;
    }
    Ok(state)
}

fn finish_bounded(
    mut state: ComparisonMap,
    meter: &mut OperationMeter,
    phase: ComparisonPhase,
    frontier: Option<SourceAddress>,
) -> Result<ComparisonMap, RivalModelError> {
    state.completion = ComparisonCompletion::Bounded;
    state.phase = phase;
    state.frontier = frontier;
    let mut groups: Vec<KeyGroup<'_>> = Vec::new();
    if !canonicalize(&mut state.model_context, &mut groups, meter)? {
        state.model_context.clear();
        state.groups.clear();
    }
    Ok(state)
}

fn canonicalize(
    context: &mut [SourceAddress],
    groups: &mut [KeyGroup<'_>],
    meter: &mut OperationMeter,
) -> Result<bool, RivalModelError> {
    let mut sort_work = context
        .len()
        .checked_mul(context.len())
        .ok_or(RivalModelError::Bound {
            field: "comparison.sort_work",
            maximum: usize::MAX,
            actual: usize::MAX,
        })?
        .checked_add(
            groups
                .len()
                .checked_mul(groups.len())
                .ok_or(RivalModelError::Bound {
                    field: "comparison.sort_work",
                    maximum: usize::MAX,
                    actual: usize::MAX,
                })?,
        )
        .ok_or(RivalModelError::Bound {
            field: "comparison.sort_work",
            maximum: usize::MAX,
            actual: usize::MAX,
        })?;
    for group in groups.iter() {
        sort_work = sort_work
            .checked_add(
                group
                    .occurrences
                    .len()
                    .checked_mul(group.occurrences.len())
                    .ok_or(RivalModelError::Bound {
                        field: "comparison.sort_work",
                        maximum: usize::MAX,
                        actual: usize::MAX,
                    })?,
            )
            .ok_or(RivalModelError::Bound {
                field: "comparison.sort_work",
                maximum: usize::MAX,
                actual: usize::MAX,
            })?;
    }
    if matches!(
        meter.charge_addressed(
            sort_work.max(1),
            WorkStage::ResultPacking,
            neutral_address(),
        )?,
        MeterCharge::Exhausted
    ) {
        return Ok(false);
    }
    context.sort_unstable();
    for group in groups.iter_mut() {
        group.occurrences.sort_unstable();
    }
    groups.sort_unstable_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.occurrences.first().cmp(&right.occurrences.first()))
    });
    Ok(true)
}

fn model_item_count(
    declaration: &eliot_dreamer_contracts::rival::RivalModelDeclaration,
) -> Result<usize, RivalModelError> {
    let mut total = 19usize;
    add_count(&mut total, declaration.explanations.len())?;
    for claims in [
        &declaration.supporting_claims,
        &declaration.counterevidence_claims,
        &declaration.revision_conditions,
        &declaration.invalidation_conditions,
        &declaration.successful_transfers,
        &declaration.failed_transfers,
        &declaration.downstream_effects,
    ] {
        if let ClaimDeclarations::Supplied { claims } = claims {
            add_count(&mut total, claims.len())?;
        }
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.assumptions {
        add_count(&mut total, entries.len())?;
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.support_observations {
        add_count(&mut total, entries.len())?;
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.causal_readings {
        add_count(
            &mut total,
            entries.len().checked_mul(2).ok_or(RivalModelError::Bound {
                field: "comparison.items",
                maximum: MAX_COMPARISON_ITEMS,
                actual: usize::MAX,
            })?,
        )?;
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.conflicts {
        for conflict in entries {
            add_count(
                &mut total,
                1usize
                    .checked_add(conflict.positions.len())
                    .ok_or(RivalModelError::Bound {
                        field: "comparison.items",
                        maximum: MAX_COMPARISON_ITEMS,
                        actual: usize::MAX,
                    })?,
            )?;
            add_count(&mut total, conflict.common_lineage.len())?;
        }
    }
    if let eliot_dreamer_contracts::rival::SuppliedLineage::Retained { closure } =
        &declaration.lineage
    {
        add_count(&mut total, closure.lineage.len())?;
    }
    if let CommonModeDisclosure::Supplied {
        lineage_roots,
        basis,
    } = &declaration.common_mode
    {
        add_count(&mut total, lineage_roots.len())?;
        if let ClaimDeclarations::Supplied { claims } = basis {
            add_count(&mut total, claims.len())?;
        }
    }
    Ok(total)
}

fn add_count(total: &mut usize, amount: usize) -> Result<(), RivalModelError> {
    *total = total.checked_add(amount).ok_or(RivalModelError::Bound {
        field: "comparison.items",
        maximum: MAX_COMPARISON_ITEMS,
        actual: usize::MAX,
    })?;
    Ok(())
}

struct KeyOccurrence<'a> {
    kind: SharedInputKind,
    key: SharedKey<'a>,
    address: SourceAddress,
}

struct ComparisonBudget {
    ceiling: usize,
    bytes: usize,
}

impl ComparisonBudget {
    fn new(base: usize, ceiling: usize) -> Self {
        Self {
            ceiling,
            bytes: base,
        }
    }

    fn admit<T: Serialize>(&mut self, item: &T) -> Result<bool, RivalModelError> {
        let Some(remaining) = self.ceiling.checked_sub(self.bytes) else {
            return Ok(false);
        };
        let Some(payload) = bounded_wire_size(item, remaining)? else {
            return Ok(false);
        };
        let added = payload.checked_add(1).ok_or(RivalModelError::Bound {
            field: "comparison.output_bytes",
            maximum: self.ceiling,
            actual: usize::MAX,
        })?;
        let Some(next) = self.bytes.checked_add(added) else {
            return Ok(false);
        };
        if next > self.ceiling {
            return Ok(false);
        }
        self.bytes = next;
        Ok(true)
    }

    fn reserve_group_prefix(&mut self, kind: SharedInputKind) -> Result<bool, RivalModelError> {
        let empty = SharedInputGroup {
            kind,
            occurrences: Vec::new(),
        };
        self.admit(&empty)
    }
}

fn checked_ordinal(value: usize, field: &'static str) -> Result<u32, RivalModelError> {
    u32::try_from(value).map_err(|_| RivalModelError::Bound {
        field,
        maximum: u32::MAX as usize,
        actual: value,
    })
}

fn collect_claims<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    model_row: u32,
    field: ComparisonField,
    declarations: &'a ClaimDeclarations,
) -> Result<(), RivalModelError> {
    if let ClaimDeclarations::Supplied { claims } = declarations {
        for (entry, claim) in claims.iter().enumerate() {
            let entry = checked_ordinal(entry, "comparison.entry")?;
            keys.push(KeyOccurrence {
                kind: SharedInputKind::Claim,
                key: SharedKey::Claim(claim),
                address: SourceAddress {
                    model_row,
                    field,
                    entry: Some(entry),
                    member: None,
                },
            });
        }
    }
    Ok(())
}

fn collect_claim_declaration<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    model_row: u32,
    field: ComparisonField,
    declarations: &'a ClaimDeclarations,
) -> Result<(), RivalModelError> {
    collect_claims(keys, model_row, field, declarations)
}

fn collect_assumptions<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    model_row: u32,
    availability: &'a DeclarationAvailability<ConditionAssumptionRef>,
) -> Result<(), RivalModelError> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        for (entry, assumption) in entries.iter().enumerate() {
            let entry = checked_ordinal(entry, "comparison.entry")?;
            keys.push(KeyOccurrence {
                kind: SharedInputKind::Assumption,
                key: SharedKey::Assumption(assumption),
                address: SourceAddress {
                    model_row,
                    field: ComparisonField::Assumptions,
                    entry: Some(entry),
                    member: None,
                },
            });
        }
    }
    Ok(())
}

fn collect_support<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    model_row: u32,
    availability: &'a DeclarationAvailability<SupportRecord>,
) -> Result<(), RivalModelError> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        for (entry, support) in entries.iter().enumerate() {
            let entry = checked_ordinal(entry, "comparison.entry")?;
            keys.push(KeyOccurrence {
                kind: SharedInputKind::SupportRecord,
                key: SharedKey::Support(support),
                address: SourceAddress {
                    model_row,
                    field: ComparisonField::SupportObservations,
                    entry: Some(entry),
                    member: None,
                },
            });
        }
    }
    Ok(())
}

fn collect_causal<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    model_row: u32,
    availability: &'a DeclarationAvailability<CausalClaim>,
) -> Result<(), RivalModelError> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        for (entry, causal) in entries.iter().enumerate() {
            let entry = checked_ordinal(entry, "comparison.entry")?;
            keys.push(KeyOccurrence {
                kind: SharedInputKind::CausalRecord,
                key: SharedKey::Causal(causal),
                address: SourceAddress {
                    model_row,
                    field: ComparisonField::CausalReadings,
                    entry: Some(entry),
                    member: None,
                },
            });
            keys.push(KeyOccurrence {
                kind: SharedInputKind::CommonModeRoot,
                key: SharedKey::CommonModeRoot(&causal.lineage),
                address: SourceAddress {
                    model_row,
                    field: ComparisonField::CausalLineage,
                    entry: Some(entry),
                    member: None,
                },
            });
        }
    }
    Ok(())
}

fn collect_conflicts<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    context: &mut Vec<SourceAddress>,
    budget: &mut ComparisonBudget,
    model_row: u32,
    availability: &'a DeclarationAvailability<ConflictSet>,
) -> Result<Option<SourceAddress>, RivalModelError> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        for (entry, conflict) in entries.iter().enumerate() {
            let entry = checked_ordinal(entry, "comparison.entry")?;
            let conflict_address = SourceAddress {
                model_row,
                field: ComparisonField::Conflicts,
                entry: Some(entry),
                member: None,
            };
            if !budget.admit(&conflict_address)? {
                return Ok(Some(conflict_address));
            }
            context.push(conflict_address);
            for (member, _) in conflict.positions.iter().enumerate() {
                let member = checked_ordinal(member, "comparison.member")?;
                let position_address = SourceAddress {
                    model_row,
                    field: ComparisonField::ConflictPosition,
                    entry: Some(entry),
                    member: Some(member),
                };
                if !budget.admit(&position_address)? {
                    return Ok(Some(position_address));
                }
                context.push(position_address);
            }
            for (member, root) in conflict.common_lineage.iter().enumerate() {
                let member = checked_ordinal(member, "comparison.member")?;
                keys.push(KeyOccurrence {
                    kind: SharedInputKind::CommonModeRoot,
                    key: SharedKey::CommonModeRoot(root),
                    address: SourceAddress {
                        model_row,
                        field: ComparisonField::ConflictCommonLineage,
                        entry: Some(entry),
                        member: Some(member),
                    },
                });
            }
        }
    }
    Ok(None)
}

fn collect_lineage<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    model_row: u32,
    lineage: &'a eliot_dreamer_contracts::rival::SuppliedLineage,
) -> Result<(), RivalModelError> {
    if let eliot_dreamer_contracts::rival::SuppliedLineage::Retained { closure } = lineage {
        for (entry, source) in closure.lineage.iter().enumerate() {
            let entry = checked_ordinal(entry, "comparison.entry")?;
            keys.push(KeyOccurrence {
                kind: SharedInputKind::SourceOwner,
                key: SharedKey::SourceOwner(&source.owner),
                address: SourceAddress {
                    model_row,
                    field: ComparisonField::SourceLineage,
                    entry: Some(entry),
                    member: None,
                },
            });
        }
    }
    Ok(())
}

fn collect_common_mode<'a>(
    keys: &mut Vec<KeyOccurrence<'a>>,
    model_row: u32,
    common_mode: &'a CommonModeDisclosure,
) -> Result<(), RivalModelError> {
    if let CommonModeDisclosure::Supplied {
        lineage_roots,
        basis,
    } = common_mode
    {
        for (member, root) in lineage_roots.iter().enumerate() {
            let member = checked_ordinal(member, "comparison.member")?;
            keys.push(KeyOccurrence {
                kind: SharedInputKind::CommonModeRoot,
                key: SharedKey::CommonModeRoot(root),
                address: SourceAddress {
                    model_row,
                    field: ComparisonField::CommonModeRoot,
                    entry: None,
                    member: Some(member),
                },
            });
        }
        collect_claims(keys, model_row, ComparisonField::CommonModeClaims, basis)?;
    }
    Ok(())
}

struct CountingWriter {
    count: usize,
    ceiling: usize,
}

impl CountingWriter {
    fn exceeded(&self) -> bool {
        self.count > self.ceiling
    }
}

fn bounded_wire_size<T: Serialize>(
    value: &T,
    ceiling: usize,
) -> Result<Option<usize>, RivalModelError> {
    let mut writer = CountingWriter { count: 0, ceiling };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(Some(writer.count)),
        Err(_) if writer.exceeded() => Ok(None),
        Err(_) => Err(RivalModelError::InvalidContract("comparison.preimage")),
    }
}

fn neutral_address() -> WorkAddress<'static> {
    WorkAddress {
        model_id: None,
        prediction_id: None,
        pair: None,
        prediction_pair: None,
    }
}

fn wire_blocks(bytes: usize) -> Result<usize, RivalModelError> {
    bytes
        .checked_add(1023)
        .and_then(|value| value.checked_div(1024))
        .map(|blocks| blocks.max(1))
        .ok_or(RivalModelError::Bound {
            field: "comparison.serialization_work",
            maximum: usize::MAX,
            actual: bytes,
        })
}

#[derive(Clone, Copy)]
enum MeteredFailure {
    Ceiling,
    Meter,
}

struct MeteredWriter<'meter> {
    meter: &'meter mut OperationMeter,
    stage: WorkStage,
    count: usize,
    ceiling: usize,
    charged_blocks: usize,
    failure: Option<MeteredFailure>,
}

impl Write for MeteredWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.count.checked_add(bytes.len()) else {
            self.failure = Some(MeteredFailure::Ceiling);
            return Err(io::Error::other("comparison wire overflow"));
        };
        if next > self.ceiling {
            self.failure = Some(MeteredFailure::Ceiling);
            return Err(io::Error::other("comparison wire ceiling"));
        }
        let Some(blocks) = next.checked_add(1023).map(|value| (value / 1024).max(1)) else {
            self.failure = Some(MeteredFailure::Ceiling);
            return Err(io::Error::other("comparison wire overflow"));
        };
        let additional = blocks.saturating_sub(self.charged_blocks);
        if additional != 0 {
            match self
                .meter
                .charge_addressed(additional, self.stage, neutral_address())
            {
                Ok(MeterCharge::Charged) => self.charged_blocks = blocks,
                Ok(MeterCharge::Exhausted) | Err(_) => {
                    self.failure = Some(MeteredFailure::Meter);
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "comparison work"));
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

fn borrowed_key_size(
    key: &SharedKey<'_>,
    meter: &mut OperationMeter,
    _address: SourceAddress,
) -> Result<Option<usize>, RivalModelError> {
    let (result, count, failure) = {
        let mut writer = MeteredWriter {
            meter,
            stage: WorkStage::MaterialEquivalence,
            count: 0,
            ceiling: crate::bounds::MAX_RIVAL_WIRE_BYTES,
            charged_blocks: 0,
            failure: None,
        };
        let result = match key {
            SharedKey::Claim(value) => serde_json::to_writer(&mut writer, value),
            SharedKey::Assumption(value) => serde_json::to_writer(&mut writer, value),
            SharedKey::Support(value) => serde_json::to_writer(&mut writer, value),
            SharedKey::Causal(value) => serde_json::to_writer(&mut writer, value),
            SharedKey::SourceOwner(value) => serde_json::to_writer(&mut writer, value),
            SharedKey::CommonModeRoot(value) => serde_json::to_writer(&mut writer, value),
        };
        (result, writer.count, writer.failure)
    };
    match (result, failure) {
        (Ok(()), None) => Ok(Some(count)),
        (_, Some(MeteredFailure::Ceiling | MeteredFailure::Meter)) => Ok(None),
        (Err(_), None) => Err(RivalModelError::InvalidContract("comparison.key")),
    }
}

fn metered_output_fits(
    state: &ComparisonMap,
    ceiling: usize,
    meter: &mut OperationMeter,
) -> Result<bool, RivalModelError> {
    let (result, failure) = {
        let mut writer = MeteredWriter {
            meter,
            stage: WorkStage::ResultPacking,
            count: 0,
            ceiling,
            charged_blocks: 0,
            failure: None,
        };
        let result = serde_json::to_writer(&mut writer, state);
        (result, writer.failure)
    };
    match (result, failure) {
        (Ok(()), None) => Ok(true),
        (_, Some(MeteredFailure::Ceiling | MeteredFailure::Meter)) => Ok(false),
        (Err(_), None) => Err(RivalModelError::InvalidContract("comparison.output")),
    }
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self.count.saturating_add(bytes.len());
        if self.count > self.ceiling {
            return Err(io::Error::other("comparison output ceiling"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
