//! Deterministic recipe demand and witness planning for A04.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::assembly::{
    ConditionalEvaluation, ConditionalEvaluationState, ConditionalPredicate, ConflictAtomIdentity,
    DreamInputRole, DreamJobRecipe, RoleDisposition, RoleOmissionPolicy, SuppliedItemIdentity,
};
use eliot_dreamer_contracts::grounding::{AllowedReferenceManifest, AuthorizedReference};

use crate::input::{NormalizedAssemblyInput, SuppliedItemState};

/// Demand and conservation facts for one role after the bounded planning pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoleDemand {
    pub(crate) role: DreamInputRole,
    pub(crate) requested: u32,
    pub(crate) selected: Vec<SuppliedItemIdentity>,
    pub(crate) unmet: u32,
}

/// Owner-authorized omission retained after a failed optional trial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlannedOmission {
    pub(crate) identity: SuppliedItemIdentity,
    pub(crate) reason: eliot_dreamer_contracts::MaterialOutcomeReason,
    pub(crate) accounting: eliot_dreamer_contracts::assembly::AssemblyOmissionAccounting,
}

/// Failed optional trial retained as a blocked ledger outcome when the owner
/// did not authorize a reversible or non-recoverable omission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeferredSelection {
    pub(crate) identity: SuppliedItemIdentity,
    pub(crate) reason: eliot_dreamer_contracts::MaterialOutcomeReason,
}

/// Provisional core plan. Packing, model bytes, measurements and final output
/// remain separate phases and consume this immutable selection decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreAssemblyPlan {
    /// Identities admitted by the mandatory/core pass before optional trials.
    pub(crate) core_selected: Vec<SuppliedItemIdentity>,
    pub(crate) selected: Vec<SuppliedItemIdentity>,
    pub(crate) demands: Vec<RoleDemand>,
    pub(crate) conditional_evaluations: Vec<ConditionalEvaluation>,
    pub(crate) blocked_or_unavailable: Vec<SuppliedItemIdentity>,
    pub(crate) omissions: Vec<PlannedOmission>,
    pub(crate) deferred: Vec<DeferredSelection>,
}

/// Plan finite role demand, conditional witnesses and interpretation closure.
pub(crate) fn plan_core(
    input: &NormalizedAssemblyInput,
) -> Result<CoreAssemblyPlan, ContractViolation> {
    let mut plan = plan_with_forced(input, &BTreeSet::new())?;
    plan.core_selected = plan.selected.clone();
    Ok(plan)
}

/// Recompute the complete actual closure with additional identities forced by
/// one atomic optional trial.
pub(crate) fn plan_with_forced(
    input: &NormalizedAssemblyInput,
    extra_forced: &BTreeSet<SuppliedItemIdentity>,
) -> Result<CoreAssemblyPlan, ContractViolation> {
    let mut demands = seed_demands(input)?;
    let mut forced = BTreeSet::new();
    promote_source_free(input, &mut forced);
    promote_protected(input, &mut forced)?;
    forced.extend(extra_forced.iter().cloned());
    for role in &input.recipe.roles {
        let forced_count = selected_count(&forced, role.role)?;
        raise_demand(&mut demands, role.role, forced_count);
    }

    let _planned_conditionals = evaluate_conditionals(input, &mut demands, &mut forced)?;
    propagate_dependencies(&input.recipe, &mut demands);
    let selected = select_actual_candidates(input, &demands, &forced)?;
    let conditional_evaluations = evaluate_actual_conditionals(input, &selected)?;

    let demand_records = role_demand_records(input, &demands, &selected)?;
    let selected = selected.into_iter().collect();
    let blocked_or_unavailable = input
        .supplied_items
        .iter()
        .filter(|item| {
            matches!(
                item.state,
                SuppliedItemState::Blocked(_) | SuppliedItemState::Unavailable(_)
            )
        })
        .map(|item| item.identity.clone())
        .collect();
    Ok(CoreAssemblyPlan {
        core_selected: Vec::new(),
        selected,
        demands: demand_records,
        conditional_evaluations,
        blocked_or_unavailable,
        omissions: Vec::new(),
        deferred: Vec::new(),
    })
}

fn seed_demands(
    input: &NormalizedAssemblyInput,
) -> Result<BTreeMap<DreamInputRole, u32>, ContractViolation> {
    let mut demands = BTreeMap::new();
    let mut protected_counts = BTreeMap::new();
    let mut source_free_counts = BTreeMap::new();
    for identity in &input.supplied_identities {
        if identity.handle.is_none() {
            increment_count(&mut source_free_counts, identity.role)?;
        }
    }
    for item in &input.supplied_items {
        let role = role_for(&input.recipe, item.identity.role)?;
        if role.protected || matches!(role.omission_policy, RoleOmissionPolicy::NonDroppable) {
            increment_count(&mut protected_counts, item.identity.role)?;
        }
    }
    for role in &input.recipe.roles {
        let required = if matches!(role.disposition, RoleDisposition::Required) {
            role.minimum
        } else {
            0
        };
        let protected = protected_counts
            .get(&role.role)
            .copied()
            .unwrap_or_default();
        let source_free = source_free_counts
            .get(&role.role)
            .copied()
            .unwrap_or_default();
        demands.insert(role.role, required.max(protected).max(source_free));
    }
    Ok(demands)
}

fn increment_count(
    counts: &mut BTreeMap<DreamInputRole, u32>,
    role: DreamInputRole,
) -> Result<(), ContractViolation> {
    let current = counts.get(&role).copied().unwrap_or_default();
    let next = current.checked_add(1).ok_or(ContractViolation::Budget {
        dimension: "source_width",
        reason: "role demand count overflows the bounded planner".to_owned(),
    })?;
    counts.insert(role, next);
    Ok(())
}

fn promote_source_free(
    input: &NormalizedAssemblyInput,
    selected: &mut BTreeSet<SuppliedItemIdentity>,
) {
    for identity in &input.supplied_identities {
        if identity.handle.is_none() {
            selected.insert(identity.clone());
        }
    }
}

fn promote_protected(
    input: &NormalizedAssemblyInput,
    selected: &mut BTreeSet<SuppliedItemIdentity>,
) -> Result<(), ContractViolation> {
    for item in &input.supplied_items {
        let role = role_for(&input.recipe, item.identity.role)?;
        if !(role.protected || matches!(role.omission_policy, RoleOmissionPolicy::NonDroppable)) {
            continue;
        }
        selected.insert(item.identity.clone());
    }
    Ok(())
}

fn evaluate_conditionals(
    input: &NormalizedAssemblyInput,
    demands: &mut BTreeMap<DreamInputRole, u32>,
    selected: &mut BTreeSet<SuppliedItemIdentity>,
) -> Result<Vec<ConditionalEvaluation>, ContractViolation> {
    let mut evaluations = Vec::new();
    let mut planned_states = BTreeMap::new();
    for role in &input.recipe.roles {
        let Some(condition) = role.condition.clone() else {
            continue;
        };
        let (state, evidence_items, conflict_atom) = match condition.predicate {
            ConditionalPredicate::EvidenceAvailable | ConditionalPredicate::RolePresent => {
                let witness_allowed = planned_witness_allowed(
                    input,
                    role.role,
                    condition.evidence_role,
                    &planned_states,
                )?;
                let witness = if witness_allowed {
                    first_witness(input, condition.evidence_role, selected)?
                } else {
                    None
                };
                if let Some(identity) = witness {
                    selected.insert(identity.clone());
                    raise_demand(demands, role.role, role.minimum);
                    raise_demand(
                        demands,
                        condition.evidence_role,
                        selected_count(selected, condition.evidence_role)?,
                    );
                    (ConditionalEvaluationState::True, vec![identity], None)
                } else if coverage_proves_empty(
                    &input.manifest,
                    condition.coverage.as_ref(),
                    condition.evidence_role,
                ) {
                    (ConditionalEvaluationState::KnownFalse, Vec::new(), None)
                } else {
                    (ConditionalEvaluationState::Unresolved, Vec::new(), None)
                }
            }
            ConditionalPredicate::ConflictPresent => {
                let witness_allowed = planned_witness_allowed(
                    input,
                    role.role,
                    condition.evidence_role,
                    &planned_states,
                )?;
                let witness = if witness_allowed
                    && condition.evidence_role == DreamInputRole::ConflictsAndUnknowns
                {
                    conflict_witness(input)
                } else {
                    None
                };
                if let Some((identity, atom)) = witness {
                    selected.insert(identity.clone());
                    raise_demand(demands, role.role, role.minimum);
                    raise_demand(
                        demands,
                        condition.evidence_role,
                        selected_count(selected, condition.evidence_role)?,
                    );
                    (ConditionalEvaluationState::True, vec![identity], Some(atom))
                } else if coverage_proves_empty(
                    &input.manifest,
                    condition.coverage.as_ref(),
                    condition.evidence_role,
                ) {
                    (ConditionalEvaluationState::KnownFalse, Vec::new(), None)
                } else {
                    (ConditionalEvaluationState::Unresolved, Vec::new(), None)
                }
            }
        };
        evaluations.push(ConditionalEvaluation {
            role: role.role,
            condition,
            state,
            evidence_items,
            conflict_atom,
        });
        planned_states.insert(role.role, state);
    }
    Ok(evaluations)
}

fn planned_witness_allowed(
    input: &NormalizedAssemblyInput,
    conditional_role: DreamInputRole,
    evidence_role: DreamInputRole,
    planned_states: &BTreeMap<DreamInputRole, ConditionalEvaluationState>,
) -> Result<bool, ContractViolation> {
    let conditional_index = input
        .recipe
        .roles
        .iter()
        .position(|role| role.role == conditional_role)
        .ok_or(ContractViolation::BindingMismatch {
            field: "role.condition",
            reason: "conditional role is absent from the recipe declaration".to_owned(),
        })?;
    let evidence = role_for(&input.recipe, evidence_role)?;
    let evidence_index = input
        .recipe
        .roles
        .iter()
        .position(|role| role.role == evidence_role)
        .ok_or(ContractViolation::BindingMismatch {
            field: "role.condition.evidence_role",
            reason: "condition evidence role is absent from the recipe declaration".to_owned(),
        })?;
    if evidence_index >= conditional_index {
        return Ok(false);
    }
    if evidence.disposition == RoleDisposition::Conditional {
        return Ok(matches!(
            planned_states.get(&evidence_role),
            Some(ConditionalEvaluationState::True)
        ));
    }
    Ok(true)
}

fn evaluate_actual_conditionals(
    input: &NormalizedAssemblyInput,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<Vec<ConditionalEvaluation>, ContractViolation> {
    input
        .recipe
        .roles
        .iter()
        .filter(|role| role.disposition == RoleDisposition::Conditional)
        .map(|role| evaluate_actual_conditional(input, role, selected))
        .collect()
}

fn evaluate_actual_conditional(
    input: &NormalizedAssemblyInput,
    role: &eliot_dreamer_contracts::RecipeRole,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<ConditionalEvaluation, ContractViolation> {
    let condition = role
        .condition
        .clone()
        .ok_or(ContractViolation::MissingField("role.condition"))?;
    let (state, evidence_items, conflict_atom) = match condition.predicate {
        ConditionalPredicate::EvidenceAvailable | ConditionalPredicate::RolePresent => {
            let witness = first_actual_witness(input, condition.evidence_role, selected)?;
            if let Some(identity) = witness {
                (ConditionalEvaluationState::True, vec![identity], None)
            } else if coverage_proves_empty(
                &input.manifest,
                condition.coverage.as_ref(),
                condition.evidence_role,
            ) {
                (ConditionalEvaluationState::KnownFalse, Vec::new(), None)
            } else {
                (ConditionalEvaluationState::Unresolved, Vec::new(), None)
            }
        }
        ConditionalPredicate::ConflictPresent => {
            let witness = if condition.evidence_role == DreamInputRole::ConflictsAndUnknowns {
                conflict_witness_included(input, selected)
            } else {
                None
            };
            if let Some((identity, atom)) = witness {
                (ConditionalEvaluationState::True, vec![identity], Some(atom))
            } else if coverage_proves_empty(
                &input.manifest,
                condition.coverage.as_ref(),
                condition.evidence_role,
            ) {
                (ConditionalEvaluationState::KnownFalse, Vec::new(), None)
            } else {
                (ConditionalEvaluationState::Unresolved, Vec::new(), None)
            }
        }
    };
    Ok(ConditionalEvaluation {
        role: role.role,
        condition,
        state,
        evidence_items,
        conflict_atom,
    })
}

fn first_actual_witness(
    input: &NormalizedAssemblyInput,
    role: DreamInputRole,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<Option<SuppliedItemIdentity>, ContractViolation> {
    role_for(&input.recipe, role)?;
    let mut candidates = selected
        .iter()
        .filter(|identity| identity.role == role && eligible_identity(input, identity))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| candidate_order(input, left, right));
    Ok(candidates.into_iter().next())
}

fn first_witness(
    input: &NormalizedAssemblyInput,
    role: DreamInputRole,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<Option<SuppliedItemIdentity>, ContractViolation> {
    let recipe_role = role_for(&input.recipe, role)?;
    if recipe_role.maximum == 0 {
        return Ok(None);
    }
    if let Some(existing) = selected
        .iter()
        .find(|identity| identity.role == role && eligible_identity(input, identity))
    {
        return Ok(Some(existing.clone()));
    }
    if selected_count(selected, role)? >= recipe_role.maximum {
        return Ok(None);
    }
    let mut candidates = input
        .supplied_identities
        .iter()
        .filter(|identity| identity.role == role)
        .filter(|identity| !selected.contains(*identity))
        .filter(|identity| eligible_identity(input, identity))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| candidate_order(input, left, right));
    Ok(candidates.into_iter().next())
}

fn conflict_witness(
    input: &NormalizedAssemblyInput,
) -> Option<(SuppliedItemIdentity, ConflictAtomIdentity)> {
    let mut candidates = input
        .supplied_identities
        .iter()
        .filter(|identity| {
            identity.role == DreamInputRole::ConflictsAndUnknowns
                && identity.handle.is_some()
                && eligible_identity(input, identity)
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| candidate_order(input, left, right));
    candidates
        .into_iter()
        .find_map(|identity| conflict_atom_for(input, &identity).map(|atom| (identity, atom)))
}

fn conflict_witness_included(
    input: &NormalizedAssemblyInput,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Option<(SuppliedItemIdentity, ConflictAtomIdentity)> {
    let mut candidates = selected
        .iter()
        .filter(|identity| {
            identity.role == DreamInputRole::ConflictsAndUnknowns
                && identity.handle.is_some()
                && eligible_identity(input, identity)
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| candidate_order(input, left, right));
    candidates
        .into_iter()
        .find_map(|identity| conflict_atom_for(input, &identity).map(|atom| (identity, atom)))
}

fn conflict_atom_for(
    input: &NormalizedAssemblyInput,
    identity: &SuppliedItemIdentity,
) -> Option<ConflictAtomIdentity> {
    let handle = identity.handle.as_ref()?;
    let reference = input.manifest.references.get(handle)?;
    let context = input.context.as_ref()?;
    context
        .view
        .rendered
        .iter()
        .filter(|atom| atom.role == eliot_context_contracts::SemanticRole::Conflict)
        .filter(|atom| {
            atom.source_revision == reference.source_revision
                && atom.source_digest == reference.content_digest
        })
        .find(|atom| source_owner_matches(atom, reference))
        .map(|atom| ConflictAtomIdentity {
            atom_id: atom.atom_id.clone(),
            source_revision: atom.source_revision.clone(),
            source_digest: atom.source_digest.clone(),
        })
}

fn source_owner_matches(
    atom: &eliot_context_contracts::RenderedAtom,
    reference: &AuthorizedReference,
) -> bool {
    reference
        .source_lineage
        .as_ref()
        .map(|lineage| lineage.owner == atom.source_identity)
        .or_else(|| {
            reference.provenance.as_ref().and_then(|provenance| {
                provenance
                    .lineage
                    .iter()
                    .find(|lineage| {
                        lineage.content_digest == reference.content_digest
                            && lineage.revision == reference.source_revision
                    })
                    .map(|lineage| lineage.owner == atom.source_identity)
            })
        })
        .unwrap_or(false)
}

fn coverage_proves_empty(
    manifest: &AllowedReferenceManifest,
    binding: Option<&eliot_dreamer_contracts::ConditionalCoverageBinding>,
    evidence_role: DreamInputRole,
) -> bool {
    let Some(binding) = binding else { return false };
    let Some(denominator) = manifest.coverage_denominators.get(&binding.denominator) else {
        return false;
    };
    let Some(receipt) = manifest.coverage_receipts.get(&binding.denominator) else {
        return false;
    };
    matches!(
        denominator.kind,
        eliot_dreamer_contracts::grounding::canonical::DenominatorKind::CompleteScope
    ) && denominator.roles.len() == 1
        && denominator.roles.iter().next().map(String::as_str) == Some(evidence_role.as_str())
        && denominator.members.is_empty()
        && denominator.bounds.total == 0
        && !denominator.bounds.truncated
        && denominator.query.is_some()
        && denominator.frontier.is_some()
        && receipt.digest == binding.receipt
        && receipt.denominator == binding.denominator
        && receipt.denominator_size == 0
        && receipt.members.is_empty()
        && receipt.omissions.is_empty()
        && receipt.fence == denominator.fence
        && denominator.fence == manifest.state_fence
}

fn propagate_dependencies(recipe: &DreamJobRecipe, demands: &mut BTreeMap<DreamInputRole, u32>) {
    for role in recipe.roles.iter().rev() {
        if demands.get(&role.role).copied().unwrap_or_default() == 0 {
            continue;
        }
        for dependency in &role.interpretation_dependencies {
            if let Some(dependency_role) = recipe
                .roles
                .iter()
                .find(|candidate| candidate.role == *dependency)
            {
                let required = dependency_role.minimum.max(1);
                let current = demands.get(dependency).copied().unwrap_or_default();
                demands.insert(*dependency, current.max(required));
            }
        }
    }
}

fn select_actual_candidates(
    input: &NormalizedAssemblyInput,
    demands: &BTreeMap<DreamInputRole, u32>,
    forced: &BTreeSet<SuppliedItemIdentity>,
) -> Result<BTreeSet<SuppliedItemIdentity>, ContractViolation> {
    let mut selected = BTreeSet::new();
    let mut conditional_states = BTreeMap::new();
    for role in &input.recipe.roles {
        let requested = demands.get(&role.role).copied().unwrap_or_default();
        if requested == 0 || role.disposition == RoleDisposition::NotApplicable {
            if role.disposition == RoleDisposition::Conditional {
                let evaluation = evaluate_actual_conditional(input, role, &selected)?;
                conditional_states.insert(role.role, evaluation.state);
            }
            continue;
        }
        let conditional_ready = if role.disposition == RoleDisposition::Conditional {
            let evaluation = evaluate_actual_conditional(input, role, &selected)?;
            let ready = evaluation.state == ConditionalEvaluationState::True;
            conditional_states.insert(role.role, evaluation.state);
            ready
        } else {
            true
        };
        if !conditional_ready
            || !dependencies_included(input, role, &selected, &conditional_states)?
        {
            continue;
        }
        let target = requested.min(role.maximum);
        let mut candidates = forced
            .iter()
            .filter(|identity| identity.role == role.role)
            .cloned()
            .collect::<Vec<_>>();
        let mut remaining = input
            .supplied_identities
            .iter()
            .filter(|identity| identity.role == role.role)
            .filter(|identity| eligible_identity(input, identity))
            .cloned()
            .collect::<Vec<_>>();
        candidates.retain(|identity| eligible_identity(input, identity));
        remaining.retain(|identity| !forced.contains(identity));
        candidates.sort_by(|left, right| candidate_order(input, left, right));
        remaining.sort_by(|left, right| candidate_order(input, left, right));
        candidates.extend(remaining);
        for identity in candidates {
            if selected_count(&selected, role.role)? >= target {
                break;
            }
            selected.insert(identity);
        }
    }
    Ok(selected)
}

fn dependencies_included(
    input: &NormalizedAssemblyInput,
    role: &eliot_dreamer_contracts::RecipeRole,
    selected: &BTreeSet<SuppliedItemIdentity>,
    conditional_states: &BTreeMap<DreamInputRole, ConditionalEvaluationState>,
) -> Result<bool, ContractViolation> {
    for dependency in &role.interpretation_dependencies {
        let dependency_role = role_for(&input.recipe, *dependency)?;
        if dependency_role.disposition == RoleDisposition::NotApplicable
            || conditional_states.get(dependency) == Some(&ConditionalEvaluationState::KnownFalse)
            || conditional_states.get(dependency) == Some(&ConditionalEvaluationState::Unresolved)
            || selected_count(selected, *dependency)? < dependency_role.minimum.max(1)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn role_demand_records(
    input: &NormalizedAssemblyInput,
    demands: &BTreeMap<DreamInputRole, u32>,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<Vec<RoleDemand>, ContractViolation> {
    input
        .recipe
        .roles
        .iter()
        .map(|role| {
            let selected = selected
                .iter()
                .filter(|identity| identity.role == role.role)
                .cloned()
                .collect::<Vec<_>>();
            let selected_count = count_u32(selected.len())?;
            let requested = demands.get(&role.role).copied().unwrap_or_default();
            let unmet = requested.checked_sub(selected_count).ok_or(
                ContractViolation::BindingMismatch {
                    field: "planner.role_demand",
                    reason: "selected role count exceeds its exact planned demand".to_owned(),
                },
            )?;
            Ok(RoleDemand {
                role: role.role,
                requested,
                selected,
                unmet,
            })
        })
        .collect()
}

fn eligible_identity(input: &NormalizedAssemblyInput, identity: &SuppliedItemIdentity) -> bool {
    if identity.handle.is_none() {
        return true;
    }
    input
        .supplied_items
        .iter()
        .find(|item| item.identity == *identity)
        .is_some_and(eligible_item)
}

fn eligible_item(item: &crate::input::SuppliedAssemblyItem) -> bool {
    matches!(item.state, SuppliedItemState::Available)
        && item.material.is_some()
        && item.measurement.is_some()
}

fn selected_count(
    selected: &BTreeSet<SuppliedItemIdentity>,
    role: DreamInputRole,
) -> Result<u32, ContractViolation> {
    count_u32(
        selected
            .iter()
            .filter(|identity| identity.role == role)
            .count(),
    )
}

fn raise_demand(demands: &mut BTreeMap<DreamInputRole, u32>, role: DreamInputRole, value: u32) {
    let current = demands.get(&role).copied().unwrap_or_default();
    let next = current.max(value);
    demands.insert(role, next);
}

fn role_for(
    recipe: &DreamJobRecipe,
    role: DreamInputRole,
) -> Result<&eliot_dreamer_contracts::RecipeRole, ContractViolation> {
    recipe
        .roles
        .iter()
        .find(|candidate| candidate.role == role)
        .ok_or(ContractViolation::BindingMismatch {
            field: "recipe.roles",
            reason: "planner role is absent from the validated denominator".to_owned(),
        })
}

fn candidate_order(
    input: &NormalizedAssemblyInput,
    left: &SuppliedItemIdentity,
    right: &SuppliedItemIdentity,
) -> std::cmp::Ordering {
    let role_key = |identity: &SuppliedItemIdentity| {
        let role = input
            .recipe
            .roles
            .iter()
            .find(|role| role.role == identity.role);
        (
            role.map_or(0, |role| role.source_priority),
            input
                .recipe
                .roles
                .iter()
                .position(|role| role.role == identity.role)
                .unwrap_or(usize::MAX),
        )
    };
    role_key(left)
        .cmp(&role_key(right))
        .then_with(|| source_owner(input, left).cmp(&source_owner(input, right)))
        .then_with(|| left.cmp(right))
}

fn source_owner(input: &NormalizedAssemblyInput, identity: &SuppliedItemIdentity) -> String {
    identity
        .handle
        .as_ref()
        .and_then(|handle| input.manifest.references.get(handle))
        .and_then(|reference| {
            reference
                .source_lineage
                .as_ref()
                .map(|lineage| lineage.owner.as_str().to_owned())
                .or_else(|| {
                    reference.provenance.as_ref().and_then(|provenance| {
                        provenance
                            .lineage
                            .iter()
                            .find(|lineage| {
                                lineage.revision == reference.source_revision
                                    && lineage.content_digest == reference.content_digest
                            })
                            .map(|lineage| lineage.owner.as_str().to_owned())
                    })
                })
        })
        .unwrap_or_default()
}

fn count_u32(value: usize) -> Result<u32, ContractViolation> {
    u32::try_from(value).map_err(|_| ContractViolation::Budget {
        dimension: "source_width",
        reason: "planner count exceeds the finite role ledger bound".to_owned(),
    })
}
