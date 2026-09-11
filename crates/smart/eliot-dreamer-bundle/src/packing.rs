//! Atomic optional-source packing for a frozen A04 core plan.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_dreamer_contracts::assembly::{
    AssemblyOmissionAccounting, AssemblyOmissionConstraint, ConditionalEvaluationState,
    DreamInputRole, RoleDisposition, RoleOmissionPolicy, SuppliedItemIdentity,
};
use eliot_dreamer_contracts::bundle::OmissionHandle;
use eliot_dreamer_contracts::{ContractViolation, MaterialOutcomeReason};

use crate::assembly::build_material_set;
use crate::budget::{
    CoreBudgetAccounting, compute_core_budget, core_budget_fits, failed_budget_constraints,
};
use crate::input::{NormalizedAssemblyInput, SuppliedAssemblyItem, SuppliedItemState};
use crate::recipe::{CoreAssemblyPlan, DeferredSelection, PlannedOmission, plan_with_forced};

/// Pack optional sources in deterministic ingress order. Every trial starts
/// from the complete committed selection and commits only a fully rebuilt
/// closure that still satisfies the core readiness rules.
pub(crate) fn pack_optionals(
    input: &NormalizedAssemblyInput,
    core: &CoreAssemblyPlan,
) -> Result<CoreAssemblyPlan, ContractViolation> {
    if input.policy.cancelled || input.policy.deadline_reached {
        return Ok(core.clone());
    }
    let mut current = core.clone();
    let carrier = build_material_set(input, &current)?;
    let (output_bytes, report_bytes) =
        crate::finalization::provisional_artifact_sizes(input, &carrier)?;
    if !crate::finalization::provisional_budget_constraints(input, output_bytes, report_bytes)
        .is_empty()
    {
        return Ok(current);
    }
    let budget = compute_core_budget(input, &carrier, &carrier.model_input_bytes()?)?;
    if !core_ready(input, &current, &carrier, &budget) {
        return Ok(current);
    }

    let mut committed: BTreeSet<_> = current.selected.iter().cloned().collect();
    for item in &input.supplied_items {
        if !is_optional_candidate(input, &current, item) || committed.contains(&item.identity) {
            continue;
        }
        if conditional_is_known_false(&current, item.identity.role) {
            reject_candidate(
                input,
                &mut current,
                item,
                MaterialOutcomeReason::Unprocessed,
                Vec::new(),
            );
            continue;
        }
        let maximum = role_maximum(input, item.identity.role)?;
        let committed_count = committed
            .iter()
            .filter(|identity| identity.role == item.identity.role)
            .count();
        if u32::try_from(committed_count).unwrap_or(u32::MAX) >= maximum {
            let supplied = supplied_count(input, item.identity.role)?;
            let reason = if supplied > maximum {
                MaterialOutcomeReason::BudgetExceeded
            } else {
                MaterialOutcomeReason::Unprocessed
            };
            reject_candidate(
                input,
                &mut current,
                item,
                reason,
                if supplied > maximum {
                    vec![AssemblyOmissionConstraint::RoleMaximum {
                        maximum,
                        supplied_count: supplied,
                    }]
                } else {
                    Vec::new()
                },
            );
            continue;
        }
        match try_optional_candidate(input, core, &current, &committed, item)? {
            TrialOutcome::Accepted(trial) => {
                committed = trial.selected.iter().cloned().collect();
                current = trial;
            }
            TrialOutcome::Rejected {
                reason,
                constraints,
            } => {
                reject_candidate(input, &mut current, item, reason, constraints);
            }
        }
    }
    Ok(current)
}

enum TrialOutcome {
    Accepted(CoreAssemblyPlan),
    Rejected {
        reason: MaterialOutcomeReason,
        constraints: Vec<AssemblyOmissionConstraint>,
    },
}

fn try_optional_candidate(
    input: &NormalizedAssemblyInput,
    core: &CoreAssemblyPlan,
    current: &CoreAssemblyPlan,
    committed: &BTreeSet<SuppliedItemIdentity>,
    item: &SuppliedAssemblyItem,
) -> Result<TrialOutcome, ContractViolation> {
    let mut forced = committed.clone();
    forced.insert(item.identity.clone());
    let mut trial = plan_with_forced(input, &forced)?;
    trial.core_selected.clone_from(&core.core_selected);
    if !contains_all(&trial.selected, committed)
        || !contains_all_slice(&trial.selected, &core.core_selected)
    {
        return Ok(TrialOutcome::Rejected {
            reason: MaterialOutcomeReason::Unprocessed,
            constraints: Vec::new(),
        });
    }
    if !trial
        .selected
        .iter()
        .any(|identity| identity == &item.identity)
        || !demands_closed(&trial)
    {
        return Ok(TrialOutcome::Rejected {
            reason: trial_failure_reason(&trial),
            constraints: Vec::new(),
        });
    }
    trial.omissions = current
        .omissions
        .iter()
        .filter(|omission| !trial.selected.iter().any(|id| id == &omission.identity))
        .cloned()
        .collect();
    let trial_carrier = build_material_set(input, &trial)?;
    let trial_bytes = trial_carrier.model_input_bytes()?;
    let trial_budget = compute_core_budget(input, &trial_carrier, &trial_bytes)?;
    if let Err(constraint) = core_budget_fits(input, &trial_budget) {
        let constraints = failed_budget_constraints(&trial_budget);
        if constraints.is_empty() {
            return Err(constraint);
        }
        return Ok(TrialOutcome::Rejected {
            reason: MaterialOutcomeReason::BudgetExceeded,
            constraints,
        });
    }
    let (output_bytes, report_bytes) =
        crate::finalization::provisional_artifact_sizes(input, &trial_carrier)?;
    let constraints =
        crate::finalization::provisional_budget_constraints(input, output_bytes, report_bytes);
    if !constraints.is_empty() {
        return Ok(TrialOutcome::Rejected {
            reason: MaterialOutcomeReason::BudgetExceeded,
            constraints,
        });
    }
    if !core_ready(input, &trial, &trial_carrier, &trial_budget) {
        return Ok(TrialOutcome::Rejected {
            reason: trial_failure_reason(&trial),
            constraints: Vec::new(),
        });
    }
    trial.deferred = current
        .deferred
        .iter()
        .filter(|deferred| !trial.selected.iter().any(|id| id == &deferred.identity))
        .cloned()
        .collect();
    Ok(TrialOutcome::Accepted(trial))
}

fn reject_candidate(
    input: &NormalizedAssemblyInput,
    current: &mut CoreAssemblyPlan,
    item: &SuppliedAssemblyItem,
    reason: MaterialOutcomeReason,
    constraints: Vec<AssemblyOmissionConstraint>,
) {
    if permitted_omission(input, item).is_some() {
        current.omissions =
            append_omission(input, current.omissions.clone(), item, reason, constraints);
        current
            .deferred
            .retain(|deferred| deferred.identity != item.identity);
    } else {
        current.deferred = append_deferred(current.deferred.clone(), item, reason);
        current
            .omissions
            .retain(|omission| omission.identity != item.identity);
    }
}

pub(crate) fn core_ready(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
    carrier: &eliot_dreamer_contracts::AssemblyMaterialSet,
    budget: &CoreBudgetAccounting,
) -> bool {
    if !demands_closed(plan)
        || plan
            .conditional_evaluations
            .iter()
            .any(|evaluation| evaluation.state == ConditionalEvaluationState::Unresolved)
        || (input.recipe.context_required && carrier.context.is_none())
        || ((input.curation.is_some()
            || input.recipe.job.job_class == eliot_dreamer_contracts::JobClass::Curation)
            && !carrier.has_complete_curation_material())
        || core_budget_fits(input, budget).is_err()
    {
        return false;
    }
    for role in &input.recipe.roles {
        if role.disposition == RoleDisposition::Conditional
            && plan
                .selected
                .iter()
                .any(|identity| identity.role == role.role)
            && plan
                .conditional_evaluations
                .iter()
                .find(|evaluation| evaluation.role == role.role)
                .is_none_or(|evaluation| evaluation.state != ConditionalEvaluationState::True)
        {
            return false;
        }
        for _identity in plan
            .selected
            .iter()
            .filter(|identity| identity.role == role.role)
        {
            for dependency in &role.interpretation_dependencies {
                let dependency_role = input
                    .recipe
                    .roles
                    .iter()
                    .find(|candidate| candidate.role == *dependency);
                let Some(dependency_role) = dependency_role else {
                    return false;
                };
                if plan
                    .selected
                    .iter()
                    .filter(|candidate| candidate.role == *dependency)
                    .count()
                    < usize::try_from(dependency_role.minimum.max(1)).unwrap_or(usize::MAX)
                    || (dependency_role.disposition == RoleDisposition::Conditional
                        && plan
                            .conditional_evaluations
                            .iter()
                            .find(|evaluation| evaluation.role == *dependency)
                            .is_none_or(|evaluation| {
                                evaluation.state != ConditionalEvaluationState::True
                            }))
                {
                    return false;
                }
            }
        }
    }
    input.supplied_items.iter().all(|item| {
        let Some(role) = input
            .recipe
            .roles
            .iter()
            .find(|role| role.role == item.identity.role)
        else {
            return false;
        };
        !(role.protected || role.omission_policy == RoleOmissionPolicy::NonDroppable)
            || plan.selected.iter().any(|id| id == &item.identity)
    })
}

fn demands_closed(plan: &CoreAssemblyPlan) -> bool {
    plan.demands.iter().all(|demand| demand.unmet == 0)
}

fn is_optional_candidate(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
    item: &SuppliedAssemblyItem,
) -> bool {
    input
        .recipe
        .roles
        .iter()
        .find(|role| role.role == item.identity.role)
        .is_some_and(|role| {
            role.disposition != RoleDisposition::NotApplicable
                && !role.protected
                && role.omission_policy != RoleOmissionPolicy::NonDroppable
                && !role.source_rule.is_none()
                && matches!(item.state, SuppliedItemState::Available)
                && item.material.is_some()
                && item.measurement.is_some()
                && (role.disposition != RoleDisposition::Conditional
                    || plan.conditional_evaluations.iter().any(|evaluation| {
                        evaluation.role == role.role
                            && matches!(
                                evaluation.state,
                                ConditionalEvaluationState::True
                                    | ConditionalEvaluationState::KnownFalse
                            )
                    }))
        })
}

fn conditional_is_known_false(plan: &CoreAssemblyPlan, role: DreamInputRole) -> bool {
    plan.conditional_evaluations.iter().any(|evaluation| {
        evaluation.role == role && evaluation.state == ConditionalEvaluationState::KnownFalse
    })
}

fn contains_all(
    selected: &[SuppliedItemIdentity],
    required: &BTreeSet<SuppliedItemIdentity>,
) -> bool {
    required
        .iter()
        .all(|identity| selected.iter().any(|candidate| candidate == identity))
}

fn contains_all_slice(
    selected: &[SuppliedItemIdentity],
    required: &[SuppliedItemIdentity],
) -> bool {
    required
        .iter()
        .all(|identity| selected.iter().any(|candidate| candidate == identity))
}

fn supplied_count(
    input: &NormalizedAssemblyInput,
    role: DreamInputRole,
) -> Result<u32, ContractViolation> {
    u32::try_from(
        input
            .supplied_identities
            .iter()
            .filter(|identity| identity.role == role)
            .count(),
    )
    .map_err(|_| ContractViolation::Budget {
        dimension: "source_width",
        reason: "optional role denominator exceeds the finite ledger bound".to_owned(),
    })
}

fn role_maximum(
    input: &NormalizedAssemblyInput,
    role: DreamInputRole,
) -> Result<u32, ContractViolation> {
    input
        .recipe
        .roles
        .iter()
        .find(|candidate| candidate.role == role)
        .map(|role| role.maximum)
        .ok_or(ContractViolation::BindingMismatch {
            field: "recipe.roles",
            reason: "optional candidate names no recipe role".to_owned(),
        })
}

fn trial_failure_reason(plan: &CoreAssemblyPlan) -> MaterialOutcomeReason {
    if plan.demands.iter().any(|demand| demand.unmet > 0) {
        MaterialOutcomeReason::Missing
    } else {
        MaterialOutcomeReason::Unprocessed
    }
}

fn append_omission(
    input: &NormalizedAssemblyInput,
    mut omissions: Vec<PlannedOmission>,
    item: &SuppliedAssemblyItem,
    reason: MaterialOutcomeReason,
    constraints: Vec<AssemblyOmissionConstraint>,
) -> Vec<PlannedOmission> {
    if !matches!(item.state, SuppliedItemState::Available) {
        return omissions;
    }
    if omissions
        .iter()
        .any(|omission| omission.identity == item.identity)
    {
        return omissions;
    }
    if permitted_omission(input, item).is_none() {
        return omissions;
    }
    omissions.push(PlannedOmission {
        identity: item.identity.clone(),
        reason,
        accounting: AssemblyOmissionAccounting {
            measured: item.measurement.clone(),
            constraints,
            coverage: item.omission_coverage.clone(),
        },
    });
    omissions
}

fn append_deferred(
    mut deferred: Vec<DeferredSelection>,
    item: &SuppliedAssemblyItem,
    reason: MaterialOutcomeReason,
) -> Vec<DeferredSelection> {
    if deferred.iter().any(|entry| entry.identity == item.identity) {
        return deferred;
    }
    deferred.push(DeferredSelection {
        identity: item.identity.clone(),
        reason,
    });
    deferred
}

fn permitted_omission<'a>(
    input: &NormalizedAssemblyInput,
    item: &'a SuppliedAssemblyItem,
) -> Option<&'a OmissionHandle> {
    let role = input
        .recipe
        .roles
        .iter()
        .find(|role| role.role == item.identity.role)?;
    let omission = item.omission.as_ref()?;
    match role.omission_policy {
        RoleOmissionPolicy::ReversibleHandle if omission.reversible => Some(omission),
        RoleOmissionPolicy::NonRecoverableReason
            if !omission.reversible && omission.nonrecoverable_reason.is_some() =>
        {
            Some(omission)
        }
        _ => None,
    }
}
