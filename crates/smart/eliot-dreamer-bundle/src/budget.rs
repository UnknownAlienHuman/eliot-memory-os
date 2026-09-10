//! Pure core budget accounting for A04 planning.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_context_contracts::{MeasurementCompositionProfile, MeasurementUnit};
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::assembly::AssemblyOmissionConstraint;
use eliot_dreamer_contracts::budget::{BudgetDimension, BudgetLimits};
use eliot_dreamer_contracts::grounding::AuthorizedReference;

use crate::input::NormalizedAssemblyInput;

/// Exact measurements available before model execution/finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreBudgetAccounting {
    pub(crate) input_bytes: u64,
    pub(crate) reference_width: u64,
    pub(crate) source_width: u64,
    pub(crate) attempts: u64,
    pub(crate) elapsed_ms: u64,
    pub(crate) reserve_total: u64,
    pub(crate) route_input_plus_reserves: u64,
    pub(crate) profile: MeasurementCompositionProfile,
    pub(crate) effective_limits: BudgetLimits,
}

/// Compute independent byte/count observations from the frozen carrier.
pub(crate) fn compute_core_budget(
    input: &NormalizedAssemblyInput,
    carrier: &eliot_dreamer_contracts::AssemblyMaterialSet,
    model_input: &[u8],
) -> Result<CoreBudgetAccounting, ContractViolation> {
    let input_bytes = u64::try_from(model_input.len()).map_err(|_| ContractViolation::Budget {
        dimension: "input_bytes",
        reason: "canonical model input length overflows budget accounting".to_owned(),
    })?;
    let reference_width = u64::try_from(carrier.selected_references.len()).map_err(|_| {
        ContractViolation::Budget {
            dimension: "reference_width",
            reason: "selected reference count overflows budget accounting".to_owned(),
        }
    })?;
    let source_width = distinct_source_owners(&carrier.selected_references)?;
    if input.measurement_profile.unit != MeasurementUnit::Utf8Bytes {
        return Err(ContractViolation::BindingMismatch {
            field: "request.measurement_profile.unit",
            reason: "core byte accounting requires an explicit UTF-8 byte profile".to_owned(),
        });
    }
    let reserve_total = input.recipe.reserves.total_for(
        &input.measurement_profile.profile_id,
        input.measurement_profile.unit,
    )?;
    let route_input_plus_reserves =
        input_bytes
            .checked_add(reserve_total)
            .ok_or(ContractViolation::Budget {
                dimension: "input_bytes",
                reason: "route input plus declared reserves overflow budget accounting".to_owned(),
            })?;
    Ok(CoreBudgetAccounting {
        input_bytes,
        reference_width,
        source_width,
        attempts: input.policy.attempts,
        elapsed_ms: input.policy.elapsed_ms,
        reserve_total,
        route_input_plus_reserves,
        profile: input.measurement_profile.clone(),
        effective_limits: effective_limits(&input.recipe.limits, &input.recipe.job.budget),
    })
}

/// Return whether all pre-execution observations have exact admitted bounds.
/// The execution-only dimensions remain outside this phase; no zero usage is
/// invented for them.
pub(crate) fn core_budget_fits(
    input: &NormalizedAssemblyInput,
    budget: &CoreBudgetAccounting,
) -> Result<(), ContractViolation> {
    let limits = &budget.effective_limits;
    check_limit(budget.input_bytes, limits.input_bytes, "input_bytes")?;
    check_limit(
        budget.reference_width,
        limits.reference_width,
        "reference_width",
    )?;
    check_limit(budget.source_width, limits.source_width, "source_width")?;
    check_limit(budget.attempts, limits.attempts, "attempts")?;
    check_limit(budget.elapsed_ms, limits.wall_ms, "wall_ms")?;
    check_reserve_capacity(input, budget)
}

fn check_limit(
    used: u64,
    limit: Option<u64>,
    dimension: &'static str,
) -> Result<(), ContractViolation> {
    let limit = limit.ok_or(ContractViolation::Budget {
        dimension,
        reason: "optional packing requires an exact admitted core limit".to_owned(),
    })?;
    if used > limit {
        return Err(ContractViolation::Budget {
            dimension,
            reason: format!("measured core usage {used} exceeds admitted limit {limit}"),
        });
    }
    Ok(())
}

fn check_reserve_capacity(
    input: &NormalizedAssemblyInput,
    budget: &CoreBudgetAccounting,
) -> Result<(), ContractViolation> {
    let reserves = &input.recipe.reserves;
    let capacity = &budget.profile.capacity;
    if reserves.fixed.value < capacity.fixed_overhead
        || reserves.model_output.value < capacity.output_reserve
        || reserves.review.value < capacity.review_reserve
    {
        return Err(ContractViolation::Budget {
            dimension: "assembly_reserve",
            reason: "declared reserve under-covers the exact route profile capacity".to_owned(),
        });
    }
    if budget.route_input_plus_reserves > capacity.route_capacity {
        return Err(ContractViolation::Budget {
            dimension: "assembly_reserve",
            reason: "model input plus all declared reserves exceeds route capacity".to_owned(),
        });
    }
    Ok(())
}

/// Build exact accounting constraints for a failed optional trial.
pub(crate) fn failed_budget_constraints(
    budget: &CoreBudgetAccounting,
) -> Vec<AssemblyOmissionConstraint> {
    let mut constraints = Vec::new();
    let limits = &budget.effective_limits;
    push_budget_constraint(
        &mut constraints,
        BudgetDimension::InputBytes,
        budget.input_bytes,
        limits.input_bytes,
    );
    push_budget_constraint(
        &mut constraints,
        BudgetDimension::ReferenceWidth,
        budget.reference_width,
        limits.reference_width,
    );
    push_budget_constraint(
        &mut constraints,
        BudgetDimension::SourceWidth,
        budget.source_width,
        limits.source_width,
    );
    push_budget_constraint(
        &mut constraints,
        BudgetDimension::Attempts,
        budget.attempts,
        limits.attempts,
    );
    push_budget_constraint(
        &mut constraints,
        BudgetDimension::WallMs,
        budget.elapsed_ms,
        limits.wall_ms,
    );
    let capacity = &budget.profile.capacity;
    if budget.route_input_plus_reserves > capacity.route_capacity {
        constraints.push(AssemblyOmissionConstraint::RouteCapacity {
            profile: budget.profile.profile_id.clone(),
            unit: budget.profile.unit,
            limit: capacity.route_capacity,
            required: budget.route_input_plus_reserves,
        });
    }
    constraints
}

fn push_budget_constraint(
    constraints: &mut Vec<AssemblyOmissionConstraint>,
    dimension: BudgetDimension,
    required: u64,
    limit: Option<u64>,
) {
    if let Some(limit) = limit
        && required > limit
    {
        constraints.push(AssemblyOmissionConstraint::Budget {
            dimension,
            limit,
            required,
        });
    }
}

fn distinct_source_owners(
    references: &std::collections::BTreeMap<eliot_contracts::ArtifactId, AuthorizedReference>,
) -> Result<u64, ContractViolation> {
    let mut owners = BTreeSet::new();
    for reference in references.values() {
        let owner = source_owner(reference).ok_or(ContractViolation::BindingMismatch {
            field: "result.budget_usage.source_width",
            reason: "selected source lacks an exact owner lineage binding".to_owned(),
        })?;
        owners.insert(owner);
    }
    u64::try_from(owners.len()).map_err(|_| ContractViolation::Budget {
        dimension: "source_width",
        reason: "distinct source owner count overflows budget accounting".to_owned(),
    })
}

fn source_owner(reference: &AuthorizedReference) -> Option<String> {
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
                        lineage.content_digest == reference.content_digest
                            && lineage.revision == reference.source_revision
                    })
                    .map(|lineage| lineage.owner.as_str().to_owned())
            })
        })
}

fn effective_limits(recipe: &BudgetLimits, job: &BudgetLimits) -> BudgetLimits {
    BudgetLimits {
        input_bytes: minimum(recipe.input_bytes, job.input_bytes),
        output_bytes: minimum(recipe.output_bytes, job.output_bytes),
        source_width: minimum(recipe.source_width, job.source_width),
        reference_width: minimum(recipe.reference_width, job.reference_width),
        model_calls: minimum(recipe.model_calls, job.model_calls),
        attempts: minimum(recipe.attempts, job.attempts),
        candidates: minimum(recipe.candidates, job.candidates),
        wall_ms: minimum(recipe.wall_ms, job.wall_ms),
        work_fan_out: minimum(recipe.work_fan_out, job.work_fan_out),
        report_bytes: minimum(recipe.report_bytes, job.report_bytes),
        max_stu: minimum(recipe.max_stu, job.max_stu),
    }
}

fn minimum(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        _ => None,
    }
}
