//! Bounded discriminative probe-planning algorithm.
//!
//! The planner is a pure function of its bound inputs: it validates every
//! input, requires exact task, scope, and fence agreement, classifies each
//! inquiry-affordance descriptor, collapses duplicate probes, ranks survivors
//! with the vector-preserving order, admits them against the candidate bound,
//! and records every remainder as an explicit gap. Classification policy:
//!
//! * feasibility other than `FEASIBLE` — including unknown — is unprobeable;
//!   unknown feasibility never reads as feasible;
//! * information with no expected gain (`NO_GAIN`, `UNAVAILABLE`) is
//!   unprobeable; unknown gain stays plannable but ranks after known gain;
//! * authority other than `PERMITTED` — including unknown — and denied
//!   consent are authority-blocked; permission is described, never granted;
//! * a descriptor whose applicability scope differs from the plan scope is
//!   unprobeable for this plan;
//! * consent, privacy, effect, reversibility, cost, latency, resource,
//!   context, and attention stay visible in the preserved vector and never
//!   block: this planner decides no policy.
//!
//! Budget admission counts ranked proposals against the exact `candidates`
//! limit. An unknown (`None`) candidate limit admits nothing: every ranked
//! proposal becomes an over-budget gap, because unknown-as-unlimited cannot
//! authorize proposals.

use std::collections::BTreeMap;

use eliot_dreamer_contracts::{
    AuthorityDimension, BudgetLimits, ConsentDimension, ContractViolation, DreamInputBundle,
    FeasibilityDimension, InformationDimension, InquiryAffordanceDescriptor, InquiryAffordanceSet,
    ProbeAffordanceRef, ResultUpdateDiscriminability, RivalModelSet, ValidatedDreamDraft,
    error::len_i64,
    grounding::canonical::{ArtifactId, TaskId},
};

use crate::bounds::{self, MAX_PROBE_PLAN_MERGED};
use crate::model::{
    OmissionKind, ProbeDimensions, ProbeOmission, ProbePlan, ProbePlanParams, ProbeProposal,
    ProbeTarget, omission_order_key,
};

/// Classification of one descriptor before ranking.
enum DescriptorClass {
    /// Admitted to vector ranking and the candidate bound.
    Plannable,
    /// Recorded as an explicit gap with the closed reason.
    Gap(OmissionKind, String),
}

/// Validates inputs, checks cross-bindings, and assembles the frozen plan.
pub(crate) fn build_plan(params: ProbePlanParams<'_>) -> Result<ProbePlan, ContractViolation> {
    let ProbePlanParams {
        plan_id,
        bundle,
        draft,
        rivals,
        affordances,
        limits,
    } = params;
    bundle.validate()?;
    draft.validate()?;
    rivals.validate()?;
    affordances.validate()?;
    limits.validate()?;
    let scope = bound_context(bundle, draft, rivals, affordances)?;
    let mut groups = classify_descriptors(affordances, &scope)?;
    let mut probes = rank_plannables(&mut groups)?;
    let mut omissions = Vec::new();
    drain_gaps(&mut groups, &mut omissions)?;
    admit_against_budget(&mut probes, &mut omissions, limits)?;
    sort_omissions(&mut omissions);
    assemble(
        plan_id,
        bundle,
        draft,
        rivals,
        affordances,
        &scope,
        probes,
        omissions,
    )
}

/// Task, scope, and fence agreement across all bound inputs; fails closed.
fn bound_context(
    bundle: &DreamInputBundle,
    draft: &ValidatedDreamDraft,
    rivals: &RivalModelSet,
    affordances: &InquiryAffordanceSet,
) -> Result<BoundContext, ContractViolation> {
    let receipt = &draft.receipt;
    for (got, want, field) in [
        (
            bundle.task_id.as_str(),
            receipt.task_id.as_str(),
            "probe_plan.task_id",
        ),
        (
            rivals.task_id.as_str(),
            receipt.task_id.as_str(),
            "probe_plan.task_id",
        ),
        (
            affordances.task_id.as_str(),
            receipt.task_id.as_str(),
            "probe_plan.task_id",
        ),
        (
            bundle.scope_id.as_str(),
            receipt.scope_id.as_str(),
            "probe_plan.scope",
        ),
        (
            rivals.scope.as_str(),
            receipt.scope_id.as_str(),
            "probe_plan.scope",
        ),
        (
            affordances.scope.as_str(),
            receipt.scope_id.as_str(),
            "probe_plan.scope",
        ),
    ] {
        if got != want {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "bound inputs disagree on plan identity".to_owned(),
            });
        }
    }
    for (fence, field) in [
        (&bundle.state_fence, "probe_plan.bundle.state_fence"),
        (&draft.state_fence, "probe_plan.draft.state_fence"),
        (&receipt.state_fence, "probe_plan.receipt.state_fence"),
        (&rivals.state_fence, "probe_plan.rivals.state_fence"),
        (
            &affordances.state_fence,
            "probe_plan.affordances.state_fence",
        ),
    ] {
        if *fence != bundle.state_fence {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "bound inputs disagree on plan fence".to_owned(),
            });
        }
    }
    Ok(BoundContext {
        task: affordances.task_id.clone(),
        scope: receipt.scope_id.clone(),
    })
}

struct BoundContext {
    task: TaskId,
    scope: String,
}

/// One classified descriptor group; duplicates collapse onto the lowest
/// affordance identity within the same class and collapse key. The preserved
/// owner follows the primary identity verbatim; merged lineage stays in
/// `merged_affordances` so no owner is ever substituted.
struct DescriptorGroup {
    order: u8,
    kind: eliot_dreamer_contracts::AffordanceKind,
    target: ProbeTarget,
    primary: ArtifactId,
    primary_digest: String,
    owner: eliot_dreamer_contracts::ProbeOwnerRef,
    merged: Vec<ArtifactId>,
    result_schema: eliot_dreamer_contracts::PossibleResultSchema,
    dimensions: ProbeDimensions,
    class: DescriptorClass,
    collapse: String,
}

/// Classifies every descriptor and collapses duplicates deterministically.
///
/// Duplicate collapse consumes only the A-03 predeclared update-set
/// classification (issue 610/11): two descriptors collapse onto one group
/// only when they share the planner-owned `(kind, target)` collapse key,
/// the planner-owned admission class, and the A-03 predeclared
/// [`ResultUpdateDiscriminability`] of their result schemas. Descriptors
/// whose schemas the A-03 vocabulary classifies differently stay split, so
/// the planner never merges across a declared discriminability boundary and
/// performs zero update, meaning, or materiality inference of its own.
fn classify_descriptors(
    affordances: &InquiryAffordanceSet,
    scope: &BoundContext,
) -> Result<Vec<DescriptorGroup>, ContractViolation> {
    let mut groups: BTreeMap<(u8, String, ResultUpdateDiscriminability), DescriptorGroup> =
        BTreeMap::new();
    for descriptor in &affordances.descriptors {
        let group = classify_one(descriptor, &scope.scope)?;
        // The A-03 classification is predeclared on the validated descriptor
        // schema; comparing it verbatim is admission gating, not a judgment.
        let discriminability = group.result_schema.update_discriminability();
        match groups.get_mut(&(group.order, group.collapse.clone(), discriminability)) {
            Some(existing) => merge_group(existing, group)?,
            None => {
                groups.insert(
                    (group.order, group.collapse.clone(), discriminability),
                    group,
                );
            }
        }
    }
    Ok(groups.into_values().collect())
}

fn classify_one(
    descriptor: &InquiryAffordanceDescriptor,
    scope: &str,
) -> Result<DescriptorGroup, ContractViolation> {
    let target = ProbeTarget::from_affordance(&descriptor.target);
    let dimensions = ProbeDimensions {
        information: descriptor.information.clone(),
        cost: descriptor.cost.clone(),
        latency: descriptor.latency.clone(),
        context: descriptor.context.clone(),
        resource: descriptor.resource.clone(),
        privacy: descriptor.privacy.clone(),
        consent: descriptor.consent.clone(),
        authority: descriptor.authority.clone(),
        effect: descriptor.effect.clone(),
        reversibility: descriptor.reversibility.clone(),
        feasibility: descriptor.feasibility.clone(),
        attention: descriptor.attention.clone(),
    };
    let class = classify_dimensions(&dimensions, &descriptor.applicability.scope, scope);
    let order = match &class {
        DescriptorClass::Plannable => 0,
        DescriptorClass::Gap(OmissionKind::Unprobeable, _) => 1,
        DescriptorClass::Gap(OmissionKind::OverBudget, _) => 2,
        DescriptorClass::Gap(OmissionKind::AuthorityBlocked, _) => 3,
    };
    let collapse = bounds::canonical_digest(&(&descriptor.kind, &target))?;
    Ok(DescriptorGroup {
        order,
        kind: descriptor.kind,
        target,
        primary: descriptor.affordance_id.clone(),
        primary_digest: descriptor.digest.clone(),
        owner: descriptor.owner.clone(),
        merged: Vec::new(),
        result_schema: descriptor.result_schema.clone(),
        dimensions,
        class,
        collapse,
    })
}

/// Merges a duplicate onto the lowest affordance identity; fails closed when
/// the merged table would exceed its bound. The caller admits only groups
/// whose A-03 predeclared discriminability already agrees, so this merge
/// never crosses a declared update-set boundary.
fn merge_group(
    existing: &mut DescriptorGroup,
    incoming: DescriptorGroup,
) -> Result<(), ContractViolation> {
    if incoming.primary < existing.primary {
        existing.merged.push(existing.primary.clone());
        existing.primary = incoming.primary;
        existing.primary_digest = incoming.primary_digest;
        existing.owner = incoming.owner;
    } else {
        existing.merged.push(incoming.primary);
    }
    for extra in incoming.merged {
        existing.merged.push(extra);
    }
    existing.merged.sort();
    existing.merged.dedup();
    if existing.merged.len() > MAX_PROBE_PLAN_MERGED {
        return Err(ContractViolation::OutOfBounds {
            field: "probe_plan.merged_affordances",
            min: 0,
            max: len_i64(MAX_PROBE_PLAN_MERGED),
            got: len_i64(existing.merged.len()),
        });
    }
    Ok(())
}

/// Closed gating policy over feasibility, information, authority, consent,
/// and applicability scope. Every other dimension stays advisory.
fn classify_dimensions(
    dimensions: &ProbeDimensions,
    applicability_scope: &str,
    scope: &str,
) -> DescriptorClass {
    if applicability_scope != scope {
        return DescriptorClass::Gap(
            OmissionKind::Unprobeable,
            format!("applicability scope {applicability_scope} differs from plan scope {scope}"),
        );
    }
    match &dimensions.feasibility {
        FeasibilityDimension::Feasible { .. } => {}
        FeasibilityDimension::Infeasible { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::Unprobeable,
                format!("feasibility declares INFEASIBLE: {reason}"),
            );
        }
        FeasibilityDimension::Unknown { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::Unprobeable,
                format!("feasibility declares UNKNOWN: {reason}"),
            );
        }
        FeasibilityDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::Unprobeable,
                format!("feasibility declares UNAVAILABLE: {reason}"),
            );
        }
    }
    match &dimensions.information {
        InformationDimension::High { .. }
        | InformationDimension::Moderate { .. }
        | InformationDimension::Low { .. }
        | InformationDimension::Unknown { .. } => {}
        InformationDimension::NoGain { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::Unprobeable,
                format!("information declares NO_GAIN: {reason}"),
            );
        }
        InformationDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::Unprobeable,
                format!("information declares UNAVAILABLE: {reason}"),
            );
        }
    }
    match &dimensions.authority {
        AuthorityDimension::Permitted { .. } => {}
        AuthorityDimension::RequiresApproval { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("authority declares REQUIRES_APPROVAL: {reason}"),
            );
        }
        AuthorityDimension::Denied { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("authority declares DENIED: {reason}"),
            );
        }
        AuthorityDimension::Unknown { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("authority declares UNKNOWN: {reason}"),
            );
        }
        AuthorityDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("authority declares UNAVAILABLE: {reason}"),
            );
        }
    }
    match &dimensions.consent {
        ConsentDimension::Denied { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("consent declares DENIED: {reason}"),
            );
        }
        ConsentDimension::Granted { .. }
        | ConsentDimension::RequiresGrant { .. }
        | ConsentDimension::Unknown { .. }
        | ConsentDimension::Unavailable { .. } => {}
    }
    DescriptorClass::Plannable
}

/// Sorts plannable groups by the vector-preserving order and assigns ranks.
fn rank_plannables(
    groups: &mut [DescriptorGroup],
) -> Result<Vec<ProbeProposal>, ContractViolation> {
    let mut plannable: Vec<&mut DescriptorGroup> = groups
        .iter_mut()
        .filter(|group| matches!(group.class, DescriptorClass::Plannable))
        .collect();
    plannable.sort_by(|left, right| {
        left.dimensions
            .order_key()
            .cmp(&right.dimensions.order_key())
            .then_with(|| left.primary.cmp(&right.primary))
    });
    let mut probes = Vec::with_capacity(plannable.len());
    for (index, group) in plannable.into_iter().enumerate() {
        let rank = u32::try_from(index).map_err(|_| ContractViolation::OutOfBounds {
            field: "probe_plan.probes",
            min: 0,
            max: i64::from(u32::MAX),
            got: len_i64(index),
        })?;
        probes.push(proposal_for(group, rank)?);
    }
    Ok(probes)
}

fn proposal_for(group: &DescriptorGroup, rank: u32) -> Result<ProbeProposal, ContractViolation> {
    let discrimination = group.target.discrimination();
    bounds::text(&discrimination, "probe_plan.probe.expected_discrimination")?;
    Ok(ProbeProposal {
        probe_id: group.primary.clone(),
        rank,
        kind: group.kind,
        target: group.target.clone(),
        affordance: ProbeAffordanceRef {
            affordance_id: group.primary.clone(),
            affordance_digest: group.primary_digest.clone(),
        },
        owner: group.owner.clone(),
        merged_affordances: group.merged.iter().cloned().collect(),
        expected_discrimination: discrimination,
        result_schema: group.result_schema.clone(),
        dimensions: group.dimensions.clone(),
    })
}

/// Moves every classified gap group into an explicit omission entry; reason
/// bound failures fail closed so no gap is ever silently dropped.
fn drain_gaps(
    groups: &mut [DescriptorGroup],
    omissions: &mut Vec<ProbeOmission>,
) -> Result<(), ContractViolation> {
    for group in groups.iter() {
        if let DescriptorClass::Gap(kind, reason) = &group.class {
            omissions.push(omission_for(group, *kind, reason)?);
        }
    }
    Ok(())
}

fn omission_for(
    group: &DescriptorGroup,
    kind: OmissionKind,
    reason: &str,
) -> Result<ProbeOmission, ContractViolation> {
    bounds::text(reason, "probe_plan.omission.reason")?;
    Ok(ProbeOmission {
        kind,
        target: group.target.clone(),
        affordance: ProbeAffordanceRef {
            affordance_id: group.primary.clone(),
            affordance_digest: group.primary_digest.clone(),
        },
        owner: group.owner.clone(),
        merged_affordances: group.merged.iter().cloned().collect(),
        reason: reason.to_owned(),
        dimensions: group.dimensions.clone(),
    })
}

/// Admits ranked proposals against the exact candidate bound; the remainder,
/// or every proposal when the bound is unknown, becomes over-budget gaps.
fn admit_against_budget(
    probes: &mut Vec<ProbeProposal>,
    omissions: &mut Vec<ProbeOmission>,
    limits: &BudgetLimits,
) -> Result<(), ContractViolation> {
    let admitted = match limits.candidates {
        Some(bound) => usize::try_from(bound).map_err(|_| ContractViolation::OutOfBounds {
            field: "probe_plan.candidates",
            min: 0,
            max: len_i64(usize::MAX),
            got: i64::MAX,
        })?,
        None => 0,
    };
    let overflow: Vec<ProbeProposal> = if limits.candidates.is_some() {
        probes.split_off(admitted.min(probes.len()))
    } else {
        probes.split_off(0)
    };
    for probe in overflow {
        let reason = match limits.candidates {
            Some(bound) => format!(
                "candidate bound admits {bound}: rank {} exceeds the admitted count",
                probe.rank
            ),
            None => format!(
                "candidate bound unknown: rank {} cannot be admitted without an exact limit",
                probe.rank
            ),
        };
        bounds::text(&reason, "probe_plan.omission.reason")?;
        omissions.push(ProbeOmission {
            kind: OmissionKind::OverBudget,
            target: probe.target.clone(),
            affordance: probe.affordance.clone(),
            owner: probe.owner.clone(),
            merged_affordances: probe.merged_affordances.clone(),
            reason,
            dimensions: probe.dimensions.clone(),
        });
    }
    for (index, probe) in probes.iter_mut().enumerate() {
        let rank = u32::try_from(index).map_err(|_| ContractViolation::OutOfBounds {
            field: "probe_plan.probes",
            min: 0,
            max: i64::from(u32::MAX),
            got: len_i64(index),
        })?;
        probe.rank = rank;
    }
    Ok(())
}

/// Sorts omissions into canonical gap order.
fn sort_omissions(omissions: &mut [ProbeOmission]) {
    omissions.sort_by(|left, right| {
        omission_order_key(left)
            .cmp(&omission_order_key(right))
            .then_with(|| {
                left.affordance
                    .affordance_id
                    .cmp(&right.affordance.affordance_id)
            })
    });
}

#[allow(
    clippy::too_many_arguments,
    reason = "assembly threads the complete validated plan envelope once"
)]
fn assemble(
    plan_id: ArtifactId,
    bundle: &DreamInputBundle,
    draft: &ValidatedDreamDraft,
    rivals: &RivalModelSet,
    affordances: &InquiryAffordanceSet,
    scope: &BoundContext,
    probes: Vec<ProbeProposal>,
    omissions: Vec<ProbeOmission>,
) -> Result<ProbePlan, ContractViolation> {
    let mut plan = ProbePlan {
        schema_version: crate::bounds::PROBE_PLAN_SCHEMA_VERSION,
        plan_id,
        task_id: scope.task.clone(),
        scope: scope.scope.clone(),
        state_fence: bundle.state_fence.clone(),
        draft_digest: draft.draft_digest.clone(),
        rival_digest: rivals.digest.clone(),
        affordance_digest: affordances.digest.clone(),
        manifest_digest: bundle.manifest_digest.clone(),
        probes,
        omissions,
        digest: String::new(),
    };
    bounds::preflight(&plan)?;
    plan.digest = plan.compute_digest()?;
    plan.validate()?;
    Ok(plan)
}
