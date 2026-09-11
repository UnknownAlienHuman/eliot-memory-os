//! Public A-04 planning and observation-bound finalization.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_context_contracts::{
    MeasurementStatus, MeasurementUnit, StuEstimate, TokenizerObservation,
};
use eliot_dreamer_contracts::assembly::AssemblyOmissionConstraint;
use eliot_dreamer_contracts::assembly::{
    AssemblyFrontier, AssemblyMaterialSet, AssemblyResult, AssemblyStop, AssemblyStopReason,
    BundleMeasurement, ConditionalEvaluationState, MaterialDisposition, MaterialOutcomeReason,
    ReserveUsage, RoleDisposition, RoleOutcomeState,
};
use eliot_dreamer_contracts::budget::{BudgetLimits, BudgetUsage};
use eliot_dreamer_contracts::bundle::{BundleCompleteness, BundleStatus, DreamInputBundle};
use eliot_dreamer_contracts::{ContractViolation, DisclosureAuthorization};
use eliot_security_contracts::{ClosureCompleteness, DisclosureDecisionKind};

use crate::assembly::{self, AssemblyPlan};
use crate::budget::compute_core_budget;
use crate::input::{AssemblyPolicy, AssemblyRequest, validate_and_normalize};

/// Final observations supplied by the execution owner. A-04 never reads a
/// clock, invokes a provider, or estimates a tokenizer result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssemblyFinalObservations {
    pub input_digest: String,
    pub measurement_profile: eliot_context_contracts::MeasurementCompositionProfile,
    pub stu_estimate: Option<StuEstimate>,
    pub tokenizer: Option<TokenizerObservation>,
    pub disclosure: Option<DisclosureAuthorization>,
}

/// Plan and freeze the complete normalized carrier before execution.
pub fn plan_bundle(request: AssemblyRequest) -> Result<AssemblyPlan, ContractViolation> {
    let input = validate_and_normalize(request)?;
    let core = crate::recipe::plan_core(&input)?;
    assembly::build_plan(&input, &core)
}

/// Finalize a frozen plan using only caller-supplied execution observations.
pub fn finalize_bundle(
    plan: AssemblyPlan,
    observations: AssemblyFinalObservations,
    final_policy: AssemblyPolicy,
) -> Result<AssemblyResult, ContractViolation> {
    let final_policy = AssemblyPolicy {
        cancelled: final_policy.cancelled || plan.input().policy.cancelled,
        deadline_reached: final_policy.deadline_reached || plan.input().policy.deadline_reached,
        elapsed_ms: final_policy.elapsed_ms,
        attempts: final_policy.attempts,
    };
    validate_observations(&plan, &observations, final_policy)?;
    let (frozen_input, carrier, model_input, model_input_digest, core, _initial_budget) =
        plan.into_parts();
    let AssemblyFinalObservations {
        input_digest: _,
        measurement_profile,
        stu_estimate,
        tokenizer,
        disclosure,
    } = observations;
    let mut input = frozen_input;
    input.policy = final_policy;
    let budget = compute_core_budget(&input, &carrier, &model_input)?;
    let measurement = BundleMeasurement {
        input_digest: model_input_digest,
        profile: measurement_profile,
        status: MeasurementStatus::ExactUtf8,
        input_utf8_bytes: Some(exact_len(model_input.len(), "input_bytes")?),
        stu_estimate,
        tokenizer,
    };
    let reserve_usage = zero_reserve_usage_for_profile(&measurement.profile);
    let mut result = provisional_result(
        &input,
        carrier,
        measurement,
        reserve_usage,
        disclosure,
        final_policy,
    );
    let ready = crate::packing::core_ready(&input, &core, &result.materials, &budget);
    let semantic_complete = ready
        && result.frontier.roles.is_empty()
        && result.frontier.supplied_items.is_empty()
        && stu_estimate.is_some()
        && plain_allow_complete(result.disclosure.as_ref())
        && reserve_coverage(&result);
    let (tentative_status, tentative_stop, tentative_detail) =
        if final_policy.cancelled || final_policy.deadline_reached {
            (
                BundleStatus::Blocked,
                AssemblyStopReason::Cancelled,
                "assembly cancelled by injected policy".to_owned(),
            )
        } else if semantic_complete {
            (
                BundleStatus::Complete,
                AssemblyStopReason::Completed,
                "assembly met the frozen readiness conditions".to_owned(),
            )
        } else {
            (
                BundleStatus::Blocked,
                AssemblyStopReason::Incomplete,
                "assembly remains incomplete at the retained frontier".to_owned(),
            )
        };
    result.status = tentative_status;
    result.stop = AssemblyStop {
        reason: tentative_stop,
        detail: (tentative_stop != AssemblyStopReason::Completed).then(|| tentative_detail.clone()),
    };
    let output = result.canonical_output_bytes()?;
    let output_bytes = exact_len(output.len(), "output_bytes")?;
    let mut usage = budget_usage(&model_input, &result, output_bytes, 0, final_policy)?;
    result.budget_usage = usage;
    let initial_audit = result.canonical_audit_bytes()?;
    usage.report_bytes = exact_len(initial_audit.len(), "report_bytes")?;
    result.budget_usage = usage;
    let overage = budget_overage(&result.budget_usage, &result.materials.recipe.limits)
        || budget_overage(&result.budget_usage, &result.materials.recipe.job.budget)
        || route_overage(&result)
        || frontier_budget_overage(&result);
    if overage {
        result.status = BundleStatus::BudgetExhausted;
        result.stop = AssemblyStop {
            reason: AssemblyStopReason::BudgetExhausted,
            detail: Some(format!("budget exceeded; {tentative_detail}")),
        };
    }
    let audit = result.canonical_audit_bytes()?;
    result.budget_usage.report_bytes = exact_len(audit.len(), "report_bytes")?;
    result.result_digest = result.computed_digest()?;
    result.validate()?;
    Ok(result)
}

fn validate_observations(
    plan: &AssemblyPlan,
    observations: &AssemblyFinalObservations,
    final_policy: AssemblyPolicy,
) -> Result<(), ContractViolation> {
    observations
        .measurement_profile
        .validate()
        .map_err(|error| ContractViolation::BindingMismatch {
            field: "final.measurement_profile",
            reason: error.to_string(),
        })?;
    if observations.input_digest != plan.model_input_digest()
        || observations.measurement_profile != plan.input().measurement_profile
    {
        return Err(ContractViolation::BindingMismatch {
            field: "final.measurement_profile",
            reason: "final observations differ from the frozen input identity".to_owned(),
        });
    }
    if final_policy.elapsed_ms < plan.budget().elapsed_ms
        || final_policy.attempts < plan.budget().attempts
    {
        return Err(ContractViolation::BindingMismatch {
            field: "final.policy",
            reason: "final observations cannot reduce the initial elapsed or attempt count"
                .to_owned(),
        });
    }
    if let Some(disclosure) = &observations.disclosure {
        disclosure
            .closure
            .validate()
            .map_err(|error| disclosure_error(error.to_string()))?;
        disclosure
            .decision
            .validate()
            .map_err(|error| disclosure_error(error.to_string()))?;
        for receipt in disclosure.declassification_receipts.values() {
            receipt
                .validate()
                .map_err(|error| disclosure_error(error.to_string()))?;
        }
    }
    Ok(())
}

fn disclosure_error(reason: String) -> ContractViolation {
    ContractViolation::BindingMismatch {
        field: "result.disclosure",
        reason,
    }
}

pub(crate) fn provisional_artifact_sizes(
    input: &crate::input::NormalizedAssemblyInput,
    materials: &AssemblyMaterialSet,
) -> Result<(u64, u64), ContractViolation> {
    let model_input = materials.model_input_bytes()?;
    let measurement = BundleMeasurement {
        input_digest: materials.model_input_digest()?,
        profile: input.measurement_profile.clone(),
        status: MeasurementStatus::ExactUtf8,
        input_utf8_bytes: Some(exact_len(model_input.len(), "input_bytes")?),
        stu_estimate: None,
        tokenizer: None,
    };
    let result = provisional_result(
        input,
        materials.clone(),
        measurement,
        zero_reserve_usage_for_profile(&input.measurement_profile),
        None,
        input.policy,
    );
    let output = result.canonical_output_bytes()?;
    let audit = result.canonical_audit_bytes()?;
    Ok((
        exact_len(output.len(), "output_bytes")?,
        exact_len(audit.len(), "report_bytes")?,
    ))
}

pub(crate) fn provisional_budget_constraints(
    input: &crate::input::NormalizedAssemblyInput,
    output_bytes: u64,
    report_bytes: u64,
) -> Vec<AssemblyOmissionConstraint> {
    let output_limit = input
        .recipe
        .limits
        .output_bytes
        .zip(input.recipe.job.budget.output_bytes)
        .map(|(recipe, job)| recipe.min(job));
    let report_limit = input
        .recipe
        .limits
        .report_bytes
        .zip(input.recipe.job.budget.report_bytes)
        .map(|(recipe, job)| recipe.min(job));
    let mut constraints = Vec::new();
    if let Some(limit) = output_limit
        && output_bytes > limit
    {
        constraints.push(AssemblyOmissionConstraint::Budget {
            dimension: eliot_dreamer_contracts::BudgetDimension::OutputBytes,
            limit,
            required: output_bytes,
        });
    }
    if let Some(limit) = report_limit
        && report_bytes > limit
    {
        constraints.push(AssemblyOmissionConstraint::Budget {
            dimension: eliot_dreamer_contracts::BudgetDimension::ReportBytes,
            limit,
            required: report_bytes,
        });
    }
    constraints
}

fn zero_reserve_usage_for_profile(
    profile: &eliot_context_contracts::MeasurementCompositionProfile,
) -> ReserveUsage {
    ReserveUsage {
        profile: profile.profile_id.clone(),
        unit: profile.unit,
        fixed: 0,
        protocol: 0,
        model_output: 0,
        grounding: 0,
        review: 0,
        headroom: 0,
    }
}

fn provisional_result(
    input: &crate::input::NormalizedAssemblyInput,
    materials: AssemblyMaterialSet,
    measurement: BundleMeasurement,
    reserve_usage: ReserveUsage,
    disclosure: Option<DisclosureAuthorization>,
    policy: AssemblyPolicy,
) -> AssemblyResult {
    let bundle = DreamInputBundle {
        schema_version: 1,
        job_id: input.recipe.job.canonical_id(),
        scope_id: input.recipe.job.scope_id.clone(),
        task_id: input.recipe.job.task_id.clone(),
        state_fence: input.recipe.job.state_fence.clone(),
        manifest_digest: materials.manifest.digest.clone(),
        materials: materials
            .materials
            .iter()
            .map(|material| material.material.clone())
            .collect(),
        omissions: materials
            .ledger
            .iter()
            .filter_map(|entry| entry.omission.clone())
            .collect(),
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    };
    let frontier = frontier_for(&materials);
    AssemblyResult {
        schema_version: eliot_dreamer_contracts::result_schema_version(),
        bundle,
        materials,
        status: BundleStatus::Blocked,
        stop: AssemblyStop {
            reason: AssemblyStopReason::Incomplete,
            detail: Some("assembly remains incomplete at the retained frontier".to_owned()),
        },
        frontier,
        reserve_usage,
        budget_usage: BudgetUsage {
            input_bytes: 0,
            output_bytes: 0,
            source_width: 0,
            reference_width: 0,
            model_calls: 0,
            attempts: policy.attempts,
            candidates: 0,
            wall_ms: policy.elapsed_ms,
            work_fan_out: 0,
            report_bytes: 0,
            stu_used: measurement
                .stu_estimate
                .map_or(0, |estimate| estimate.value),
        },
        bundle_measurement: measurement,
        disclosure,
        result_digest: "0".repeat(64),
    }
}

fn frontier_for(materials: &AssemblyMaterialSet) -> AssemblyFrontier {
    let roles = materials
        .recipe
        .roles
        .iter()
        .filter_map(|role| {
            let outcome = materials
                .role_outcomes
                .iter()
                .find(|item| item.role == role.role)?;
            let conditional_low = role.disposition == RoleDisposition::Conditional
                && materials
                    .conditional_evaluations
                    .iter()
                    .find(|evaluation| evaluation.role == role.role)
                    .is_some_and(|evaluation| {
                        evaluation.state == ConditionalEvaluationState::Unresolved
                            || (evaluation.state == ConditionalEvaluationState::True
                                && outcome.retained_count < role.minimum)
                    });
            (matches!(
                outcome.state,
                RoleOutcomeState::Missing | RoleOutcomeState::Unresolved
            ) || (role.disposition == RoleDisposition::Required
                && outcome.retained_count < role.minimum)
                || conditional_low)
                .then_some(role.role)
        })
        .collect();
    let supplied_items = materials
        .ledger
        .iter()
        .filter(|entry| {
            matches!(
                entry.disposition,
                MaterialDisposition::Blocked | MaterialDisposition::Unavailable
            )
        })
        .filter_map(|entry| {
            materials.supplied_items.iter().find(|identity| {
                identity.role == entry.role
                    && identity.ordinal == entry.ordinal
                    && identity.handle == entry.handle
                    && identity.content_digest == entry.content_digest
                    && identity.source_revision == entry.source_revision
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let references = supplied_items
        .iter()
        .filter_map(|identity| identity.handle.clone())
        .filter(|handle| materials.manifest.references.contains_key(handle))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    AssemblyFrontier {
        roles,
        references,
        supplied_items,
    }
}

fn budget_usage(
    model_input: &[u8],
    result: &AssemblyResult,
    output_bytes: u64,
    report_bytes: u64,
    policy: AssemblyPolicy,
) -> Result<BudgetUsage, ContractViolation> {
    Ok(BudgetUsage {
        input_bytes: model_input.len() as u64,
        output_bytes,
        source_width: selected_source_owner_count(&result.materials)?,
        reference_width: result.materials.selected_references.len() as u64,
        model_calls: 0,
        attempts: policy.attempts,
        candidates: 0,
        wall_ms: policy.elapsed_ms,
        work_fan_out: 0,
        report_bytes,
        stu_used: result
            .bundle_measurement
            .stu_estimate
            .map_or(0, |estimate| estimate.value),
    })
}

fn selected_source_owner_count(materials: &AssemblyMaterialSet) -> Result<u64, ContractViolation> {
    let mut owners = BTreeSet::new();
    for reference in materials.selected_references.values() {
        let owner = reference
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
            .ok_or(ContractViolation::BindingMismatch {
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

fn budget_overage(usage: &BudgetUsage, limits: &BudgetLimits) -> bool {
    [
        (usage.input_bytes, limits.input_bytes),
        (usage.output_bytes, limits.output_bytes),
        (usage.source_width, limits.source_width),
        (usage.reference_width, limits.reference_width),
        (usage.model_calls, limits.model_calls),
        (usage.attempts, limits.attempts),
        (usage.candidates, limits.candidates),
        (usage.wall_ms, limits.wall_ms),
        (usage.work_fan_out, limits.work_fan_out),
        (usage.report_bytes, limits.report_bytes),
        (usage.stu_used, limits.max_stu),
    ]
    .into_iter()
    .any(|(used, limit)| limit.is_some_and(|limit| used > limit))
}

fn route_overage(result: &AssemblyResult) -> bool {
    if result.bundle_measurement.profile.unit != MeasurementUnit::Utf8Bytes {
        return false;
    }
    result
        .materials
        .recipe
        .reserves
        .total_for(
            &result.bundle_measurement.profile.profile_id,
            MeasurementUnit::Utf8Bytes,
        )
        .ok()
        .and_then(|total| result.budget_usage.input_bytes.checked_add(total))
        .is_some_and(|required| {
            required > result.bundle_measurement.profile.capacity.route_capacity
        })
}

fn frontier_budget_overage(result: &AssemblyResult) -> bool {
    result.frontier.supplied_items.iter().any(|identity| {
        result.materials.ledger.iter().any(|entry| {
            entry.role == identity.role
                && entry.ordinal == identity.ordinal
                && entry.handle == identity.handle
                && entry.content_digest == identity.content_digest
                && entry.source_revision == identity.source_revision
                && matches!(
                    entry.disposition,
                    MaterialDisposition::Blocked | MaterialDisposition::Unavailable
                )
                && entry.reason == Some(MaterialOutcomeReason::BudgetExceeded)
        })
    })
}

fn reserve_coverage(result: &AssemblyResult) -> bool {
    let profile = &result.bundle_measurement.profile;
    let reserves = &result.materials.recipe.reserves;
    reserves.fixed.value >= profile.capacity.fixed_overhead
        && reserves.model_output.value >= profile.capacity.output_reserve
        && reserves.review.value >= profile.capacity.review_reserve
}

fn plain_allow_complete(disclosure: Option<&DisclosureAuthorization>) -> bool {
    disclosure.is_some_and(|disclosure| {
        disclosure.decision.decision == DisclosureDecisionKind::Allow
            && disclosure.closure.completeness == ClosureCompleteness::Complete
            && disclosure.decision.closure_completeness == ClosureCompleteness::Complete
            && disclosure.decision.uncovered_domains.is_empty()
    })
}

fn exact_len(value: usize, dimension: &'static str) -> Result<u64, ContractViolation> {
    u64::try_from(value).map_err(|_| ContractViolation::Budget {
        dimension,
        reason: "canonical artifact length overflows budget accounting".to_owned(),
    })
}
