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
//! * authority other than `PERMITTED` — including unknown — and consent other
//!   than `GRANTED` are authority-blocked; permission is described, never
//!   granted;
//! * privacy other than contained/not-applicable, effect other than
//!   side-effect-free/observable-only, reversibility other than reversible,
//!   and unknown Human-attention requirements are authority-blocked;
//! * a descriptor whose applicability scope differs from the plan scope is
//!   unprobeable for this plan;
//! * cost, latency, context, and resource remain visible advisory vectors;
//!   they do not cross-subsidize one another or scalarize the order.
//!
//! Budget admission counts ranked proposals against the exact `candidates`
//! limit. An unknown (`None`) candidate limit admits nothing: every ranked
//! proposal becomes an over-budget gap, because unknown-as-unlimited cannot
//! authorize proposals.

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_contracts::{
    AuthorityDimension, BudgetDemand, BudgetLimits, ConsentDimension, ContractViolation,
    DreamInputBundle, EffectDimension, FeasibilityDimension, GapUpdateMeaning,
    HumanAttentionDimension, InformationDimension, InquiryAffordanceDescriptor,
    InquiryAffordanceSet, PossibleResultSchema, PrivacyDimension, ProbeAffordanceRef,
    ProbeCapabilityAvailability, ProbeExternalOwners, ProbeLifecycle, ProbeObjectiveBinding,
    ProbeOrderingDimension, ProbeOrderingPolicy, ProbeOwnerRef, ResultTarget, ResultUpdate,
    ResultUpdateDiscriminability, ReversibilityDimension, RivalModelSet, RivalUpdateMeaning,
    ValidatedDreamDraft,
    error::len_i64,
    grounding::canonical::{ArtifactId, TaskId},
};

use crate::bounds::{self, MAX_PROBE_PLAN_MERGED};
use crate::model::{
    OmissionKind, ProbeDimensions, ProbeObjectiveDisposition, ProbeObjectiveDispositionKind,
    ProbeOmission, ProbePlan, ProbePlanParams, ProbeProposal, ProbeRelation, ProbeRelationKind,
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
        policy,
    } = params;
    bundle.validate()?;
    draft.validate()?;
    rivals.validate()?;
    affordances.validate()?;
    limits.validate()?;
    policy.validate()?;
    let scope = bound_context(bundle, draft, rivals, affordances)?;
    let mut groups = classify_descriptors(affordances, &scope, limits)?;
    let mut probes = rank_plannables(&mut groups, policy)?;
    let mut omissions = Vec::new();
    drain_gaps(&mut groups, &mut omissions)?;
    admit_against_budget(&mut probes, &mut omissions, limits)?;
    sort_omissions(&mut omissions);
    let objective_dispositions = objective_dispositions(&groups, &probes, &omissions)?;
    let relations = build_relations(&probes, policy);
    assemble(
        plan_id,
        bundle,
        draft,
        rivals,
        affordances,
        &scope,
        policy,
        probes,
        omissions,
        objective_dispositions,
        relations,
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
    for (got, want, field) in [
        (
            receipt.job_id.as_str(),
            bundle.job_id.as_str(),
            "probe_plan.job_id",
        ),
        (
            receipt.manifest_digest.as_str(),
            bundle.manifest_digest.as_str(),
            "probe_plan.manifest_digest",
        ),
        (
            rivals.bundle_digest.as_str(),
            receipt.bundle_digest.as_str(),
            "probe_plan.rivals.bundle_digest",
        ),
        (
            rivals.validated_input_digest.as_str(),
            receipt.input_digest.as_str(),
            "probe_plan.rivals.validated_input_digest",
        ),
    ] {
        if got != want {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "bound source identity does not match the validated draft".to_owned(),
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
    objective: Option<ProbeObjectiveBinding>,
    budget_demand: Option<BudgetDemand>,
    lifecycle: Option<ProbeLifecycle>,
    external_owners: Option<ProbeExternalOwners>,
    capability: Option<ProbeCapabilityAvailability>,
    merged: Vec<ArtifactId>,
    result_schema: eliot_dreamer_contracts::PossibleResultSchema,
    dimensions: ProbeDimensions,
    class: DescriptorClass,
    collapse: String,
}

/// Classifies every descriptor and collapses duplicates deterministically.
///
/// Duplicate collapse consumes the A-03 predeclared update-set
/// classification (issue 610/11) and a complete semantic equivalence key:
/// kind, target, applicability, owner, result schema, and every planning
/// dimension must agree. Descriptor identities and their digest-pinned
/// lineage are the only fields allowed to differ. The planner performs no
/// update, meaning, or materiality inference of its own.
fn classify_descriptors(
    affordances: &InquiryAffordanceSet,
    scope: &BoundContext,
    limits: &BudgetLimits,
) -> Result<Vec<DescriptorGroup>, ContractViolation> {
    let mut groups: BTreeMap<(u8, String, ResultUpdateDiscriminability), DescriptorGroup> =
        BTreeMap::new();
    for descriptor in &affordances.descriptors {
        let group = classify_one(descriptor, &scope.scope, limits)?;
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
    limits: &BudgetLimits,
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
    let mut class = classify_dimensions(
        &dimensions,
        &descriptor.applicability.scope,
        scope,
        &target,
        &descriptor.result_schema,
        descriptor.objective_binding.as_ref(),
    );
    if matches!(class, DescriptorClass::Plannable)
        && let Some((kind, reason)) = semantic_block_reason(
            &target,
            descriptor.objective_binding.as_ref(),
            descriptor.budget_demand,
            descriptor.lifecycle.as_ref(),
            descriptor.external_owners.as_ref(),
            descriptor.capability.as_ref(),
            &descriptor.result_schema,
            limits,
            scope,
        )
    {
        class = DescriptorClass::Gap(kind, reason);
    }
    let order = match &class {
        DescriptorClass::Plannable => 0,
        DescriptorClass::Gap(OmissionKind::Unprobeable, _) => 1,
        DescriptorClass::Gap(OmissionKind::OverBudget, _) => 2,
        DescriptorClass::Gap(OmissionKind::AuthorityBlocked, _) => 3,
    };
    // The collapse key excludes only the descriptor's own identity and digest.
    // Every semantic field remains part of equivalence, so a cheaper/riskier
    // or differently declared result is never erased by a coarse label.
    let collapse = bounds::canonical_digest(&(
        &descriptor.kind,
        &target,
        &descriptor.applicability,
        &descriptor.owner,
        &descriptor.result_schema,
        &dimensions,
    ))?;
    Ok(DescriptorGroup {
        order,
        kind: descriptor.kind,
        target,
        primary: descriptor.affordance_id.clone(),
        primary_digest: descriptor.digest.clone(),
        owner: descriptor.owner.clone(),
        objective: descriptor.objective_binding.clone(),
        budget_demand: descriptor.budget_demand,
        lifecycle: descriptor.lifecycle.clone(),
        external_owners: descriptor.external_owners.clone(),
        capability: descriptor.capability.clone(),
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
        existing.objective = incoming.objective;
        existing.budget_demand = incoming.budget_demand;
        existing.lifecycle = incoming.lifecycle;
        existing.external_owners = incoming.external_owners;
        existing.capability = incoming.capability;
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

/// Closed gating policy over applicability, feasibility, information,
/// authority, consent, privacy, effect, reversibility, Human attention, and
/// result-matrix discrimination. Cost, latency, context, and resource remain
/// advisory vectors because this package has no per-candidate usage contract.
#[allow(
    clippy::too_many_lines,
    reason = "the closed readiness gates must preserve each independent dimension"
)]
fn classify_dimensions(
    dimensions: &ProbeDimensions,
    applicability_scope: &str,
    scope: &str,
    target: &ProbeTarget,
    result_schema: &PossibleResultSchema,
    objective: Option<&ProbeObjectiveBinding>,
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
    if let Some(reason) = result_matrix_block_reason(target, result_schema, objective) {
        return DescriptorClass::Gap(OmissionKind::Unprobeable, reason);
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
        ConsentDimension::Granted { .. } => {}
        ConsentDimension::RequiresGrant { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("consent declares REQUIRES_GRANT: {reason}"),
            );
        }
        ConsentDimension::Denied { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("consent declares DENIED: {reason}"),
            );
        }
        ConsentDimension::Unknown { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("consent declares UNKNOWN: {reason}"),
            );
        }
        ConsentDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("consent declares UNAVAILABLE: {reason}"),
            );
        }
    }
    match &dimensions.privacy {
        PrivacyDimension::Contained { .. } | PrivacyDimension::NotApplicable { .. } => {}
        PrivacyDimension::Elevated { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("privacy declares ELEVATED: {reason}"),
            );
        }
        PrivacyDimension::Unknown { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("privacy declares UNKNOWN: {reason}"),
            );
        }
        PrivacyDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("privacy declares UNAVAILABLE: {reason}"),
            );
        }
    }
    match &dimensions.effect {
        EffectDimension::SideEffectFree { .. } | EffectDimension::ObservableOnly { .. } => {}
        EffectDimension::StateChanging { detail } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("effect declares STATE_CHANGING and requires external admission: {detail}"),
            );
        }
        EffectDimension::Unknown { reason } | EffectDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!(
                    "effect declares UNKNOWN_OR_UNAVAILABLE and needs reconciliation: {reason}"
                ),
            );
        }
    }
    match &dimensions.reversibility {
        ReversibilityDimension::Reversible { .. } => {}
        ReversibilityDimension::Irreversible { reason }
        | ReversibilityDimension::Unknown { reason }
        | ReversibilityDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!(
                    "reversibility is not admitted and needs external rollback authority: {reason}"
                ),
            );
        }
    }
    match &dimensions.attention {
        HumanAttentionDimension::Unknown { reason }
        | HumanAttentionDimension::Unavailable { reason } => {
            return DescriptorClass::Gap(
                OmissionKind::AuthorityBlocked,
                format!("Human-attention requirement is unknown: {reason}"),
            );
        }
        HumanAttentionDimension::Unneeded { .. }
        | HumanAttentionDimension::Brief { .. }
        | HumanAttentionDimension::Sustained { .. }
        | HumanAttentionDimension::NotApplicable { .. } => {}
    }
    DescriptorClass::Plannable
}

/// Requires the owner-supplied semantics that cannot be inferred by the
/// planner. Missing or uncertain declarations stay explicit gaps; the planner
/// never promotes a legacy omission to a ready candidate by default.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "each independent readiness gate remains explicit and maps to a separate contract requirement"
)]
fn semantic_block_reason(
    target: &ProbeTarget,
    objective: Option<&ProbeObjectiveBinding>,
    demand: Option<BudgetDemand>,
    lifecycle: Option<&ProbeLifecycle>,
    external_owners: Option<&ProbeExternalOwners>,
    capability: Option<&ProbeCapabilityAvailability>,
    result_schema: &PossibleResultSchema,
    limits: &BudgetLimits,
    scope: &str,
) -> Option<(OmissionKind, String)> {
    if let Some(reason) = objective_binding_block_reason(target, objective) {
        return Some((OmissionKind::Unprobeable, reason));
    }
    let Some(objective) = objective else {
        return Some((
            OmissionKind::Unprobeable,
            "objective binding is missing; exact material objective linkage is required".to_owned(),
        ));
    };
    if !objective.ready_for_planning() {
        let reason = match (&objective.materiality, &objective.resolution) {
            (eliot_dreamer_contracts::ProbeObjectiveMateriality::NonMaterial { reason }, _) => {
                format!("objective is non-material: {reason}")
            }
            (eliot_dreamer_contracts::ProbeObjectiveMateriality::Unknown { reason }, _) => {
                format!("objective materiality is unknown: {reason}")
            }
            (_, eliot_dreamer_contracts::ProbeObjectiveResolution::Resolved { basis }) => {
                format!("objective is already resolved: {basis}")
            }
            (_, eliot_dreamer_contracts::ProbeObjectiveResolution::Invalidated { reason }) => {
                format!("objective is invalidated: {reason}")
            }
            (_, eliot_dreamer_contracts::ProbeObjectiveResolution::Unknown { reason }) => {
                format!("objective resolution is unknown: {reason}")
            }
            _ => "objective is not ready for planning".to_owned(),
        };
        return Some((OmissionKind::Unprobeable, reason));
    }

    let Some(demand) = demand else {
        return Some((
            OmissionKind::OverBudget,
            "candidate budget demand is unknown; every independent dimension must be declared"
                .to_owned(),
        ));
    };
    if let Err(error) = demand.fits(limits) {
        return Some((
            OmissionKind::OverBudget,
            format!("candidate budget demand is not independently admitted: {error}"),
        ));
    }

    if lifecycle.is_none() {
        return Some((
            OmissionKind::AuthorityBlocked,
            "cancellation, cleanup/rollback, and unknown-outcome reconciliation requirements are missing"
                .to_owned(),
        ));
    }

    let Some(external_owners) = external_owners else {
        return Some((
            OmissionKind::AuthorityBlocked,
            "external admission, execution, evidence, and verifier owners are missing".to_owned(),
        ));
    };
    if [
        &external_owners.admission,
        &external_owners.execution,
        &external_owners.evidence,
        &external_owners.verifier,
    ]
    .iter()
    .any(|owner| matches!(owner, ProbeOwnerRef::Unavailable { .. }))
    {
        return Some((
            OmissionKind::AuthorityBlocked,
            "an external admission/execution/evidence/verifier owner is unavailable".to_owned(),
        ));
    }

    match capability {
        Some(ProbeCapabilityAvailability::Available { .. }) => {}
        Some(ProbeCapabilityAvailability::Unavailable { reason }) => {
            return Some((
                OmissionKind::Unprobeable,
                format!("capability is unavailable: {reason}"),
            ));
        }
        Some(ProbeCapabilityAvailability::Unknown { reason }) => {
            return Some((
                OmissionKind::Unprobeable,
                format!("capability is unknown: {reason}"),
            ));
        }
        Some(ProbeCapabilityAvailability::NotApplicable { reason }) => {
            return Some((
                OmissionKind::Unprobeable,
                format!("capability is not applicable: {reason}"),
            ));
        }
        None => {
            return Some((
                OmissionKind::Unprobeable,
                "capability availability is missing".to_owned(),
            ));
        }
    }

    let schema = result_schema;
    if schema.branch_acceptance.len() != schema.branches.len() {
        return Some((
            OmissionKind::Unprobeable,
            "result branch evidence acceptance is missing for one or more outcomes".to_owned(),
        ));
    }
    for branch in &schema.branches {
        let Some(acceptance) = schema
            .branch_acceptance
            .iter()
            .find(|acceptance| acceptance.result_id == branch.result_id)
        else {
            return Some((
                OmissionKind::Unprobeable,
                format!(
                    "result branch {} has no evidence acceptance row",
                    branch.result_id
                ),
            ));
        };
        if !acceptance.evidence.is_ready() {
            return Some((
                OmissionKind::Unprobeable,
                format!(
                    "result branch {} has non-accepted evidence",
                    branch.result_id
                ),
            ));
        }
        if objective.causal_requirements.as_ref() != acceptance.causal.as_ref() {
            return Some((
                OmissionKind::Unprobeable,
                format!(
                    "result branch {} does not preserve the objective causal controls/confounders/rivals",
                    branch.result_id
                ),
            ));
        }
        if let eliot_dreamer_contracts::BranchEvidenceAcceptance::Accepted {
            owner, verifier, ..
        } = &acceptance.evidence
        {
            if matches!(owner, ProbeOwnerRef::Unavailable { .. }) {
                return Some((
                    OmissionKind::AuthorityBlocked,
                    format!(
                        "result branch {} has no available evidence owner",
                        branch.result_id
                    ),
                ));
            }
            if verifier.scope != scope {
                return Some((
                    OmissionKind::Unprobeable,
                    format!(
                        "result branch {} verifier scope does not match plan scope",
                        branch.result_id
                    ),
                ));
            }
        }
    }

    None
}

fn objective_binding_block_reason(
    target: &ProbeTarget,
    objective: Option<&ProbeObjectiveBinding>,
) -> Option<String> {
    let Some(binding) = objective else {
        return Some(match target {
            ProbeTarget::EvidenceUnknown { .. } | ProbeTarget::AssumptionUnknown { .. } => {
                "evidence or assumption target has no exact canonical objective linkage".to_owned()
            }
            _ => "objective binding is missing; exact material objective linkage is required"
                .to_owned(),
        });
    };
    let mismatch = match target {
        ProbeTarget::RivalDisagreement { .. } => {
            binding.claim.is_some() || binding.assumption.is_some()
        }
        ProbeTarget::EvidenceUnknown { claim } => {
            binding.claim.as_ref() != Some(claim)
                || binding.assumption.is_some()
                || binding.denominator.is_none()
        }
        ProbeTarget::AssumptionUnknown { assumption, claim } => {
            binding.assumption.as_ref() != Some(assumption)
                || binding.claim.as_ref() != claim.as_ref()
        }
        ProbeTarget::ObjectiveUnknown { objective } => {
            binding.objective != *objective
                || binding.claim.is_some()
                || binding.assumption.is_some()
        }
    };
    mismatch
        .then(|| "objective binding does not match the exact planner target identity".to_owned())
}

/// Returns a bounded reason when the supplied result matrix cannot establish
/// a discriminative candidate for the declared target. The A-03 contract owns
/// update-set equality; this layer only checks that the predeclared difference
/// is relevant to the target and contains a meaningful falsifying branch.
#[allow(
    clippy::too_many_lines,
    reason = "the bounded matrix proof keeps every rejection reason explicit"
)]
fn result_matrix_block_reason(
    target: &ProbeTarget,
    schema: &PossibleResultSchema,
    objective: Option<&ProbeObjectiveBinding>,
) -> Option<String> {
    if objective.is_none()
        && matches!(
            target,
            ProbeTarget::EvidenceUnknown { .. } | ProbeTarget::AssumptionUnknown { .. }
        )
    {
        return Some(
            "evidence or assumption target has no exact canonical objective linkage".to_owned(),
        );
    }
    if schema.branches.len() < 2 {
        return Some("result matrix needs at least two possible outcomes".to_owned());
    }
    if schema.update_discriminability() != ResultUpdateDiscriminability::Discriminating {
        return Some("result matrix updates are identical for every outcome".to_owned());
    }
    let relevant_targets = schema
        .targets
        .iter()
        .filter(|result_target| result_target_is_relevant(target, objective, result_target))
        .count();
    if matches!(target, ProbeTarget::RivalDisagreement { .. }) && relevant_targets < 2 {
        return Some(
            "result matrix must name both rival endpoints or a rival and an unknown frontier"
                .to_owned(),
        );
    }
    if relevant_targets == 0 {
        return Some("result matrix does not update the declared target".to_owned());
    }

    let branch_updates: Vec<Vec<&ResultUpdate>> = schema
        .branches
        .iter()
        .map(|branch| {
            branch
                .updates
                .iter()
                .filter(|update| {
                    result_update_is_relevant(target, objective, update)
                        && meaningful_update(update)
                })
                .collect()
        })
        .collect();
    if branch_updates.iter().all(Vec::is_empty) {
        return Some("result matrix has no meaningful rival or gap update".to_owned());
    }
    let differs = branch_updates.iter().enumerate().any(|(index, left)| {
        branch_updates[index + 1..]
            .iter()
            .any(|right| left != right)
    });
    if !differs {
        return Some("result matrix has no relevant outcome difference".to_owned());
    }

    match target {
        ProbeTarget::RivalDisagreement { .. } => {
            let has_strengthened = branch_updates.iter().flatten().any(|update| {
                matches!(
                    update,
                    ResultUpdate::Rival {
                        meaning: RivalUpdateMeaning::Strengthened,
                        ..
                    }
                )
            });
            let has_weakened = branch_updates.iter().flatten().any(|update| {
                matches!(
                    update,
                    ResultUpdate::Rival {
                        meaning: RivalUpdateMeaning::Weakened,
                        ..
                    }
                )
            });
            if !has_strengthened || !has_weakened {
                return Some(
                    "rival result matrix is confirmation-only; it needs a falsifying branch"
                        .to_owned(),
                );
            }
        }
        ProbeTarget::EvidenceUnknown { .. }
        | ProbeTarget::AssumptionUnknown { .. }
        | ProbeTarget::ObjectiveUnknown { .. } => {
            let has_open = branch_updates.iter().flatten().any(|update| {
                matches!(
                    update,
                    ResultUpdate::Gap {
                        meaning: GapUpdateMeaning::RemainsOpen,
                        ..
                    }
                )
            });
            let has_progress = branch_updates.iter().flatten().any(|update| {
                matches!(
                    update,
                    ResultUpdate::Gap {
                        meaning: GapUpdateMeaning::Addressed | GapUpdateMeaning::PartiallyAddressed,
                        ..
                    }
                )
            });
            if !has_open || !has_progress {
                return Some(
                    "gap result matrix is confirmation-only; it needs an open and a progress branch"
                        .to_owned(),
                );
            }
        }
    }
    None
}

fn result_target_is_relevant(
    target: &ProbeTarget,
    objective: Option<&ProbeObjectiveBinding>,
    result_target: &ResultTarget,
) -> bool {
    match (target, result_target) {
        (
            ProbeTarget::RivalDisagreement { left, right },
            ResultTarget::Rival { prediction, .. },
        ) => prediction
            .as_ref()
            .is_none_or(|prediction| prediction == left || prediction == right),
        (
            ProbeTarget::ObjectiveUnknown {
                objective: target_objective,
            },
            ResultTarget::Gap { objective: result },
        ) => target_objective == result,
        (
            ProbeTarget::EvidenceUnknown { .. } | ProbeTarget::AssumptionUnknown { .. },
            ResultTarget::Gap { objective: result },
        ) => objective.is_some_and(|binding| &binding.objective == result),
        _ => false,
    }
}

fn result_update_is_relevant(
    target: &ProbeTarget,
    objective: Option<&ProbeObjectiveBinding>,
    update: &ResultUpdate,
) -> bool {
    match update {
        ResultUpdate::Rival {
            model,
            prediction,
            meaning: _,
        } => result_target_is_relevant(
            target,
            objective,
            &ResultTarget::Rival {
                model: model.clone(),
                prediction: prediction.clone(),
            },
        ),
        ResultUpdate::Gap {
            objective: update_objective,
            ..
        } => result_target_is_relevant(
            target,
            objective,
            &ResultTarget::Gap {
                objective: update_objective.clone(),
            },
        ),
        ResultUpdate::Unknown {
            target: update_target,
            ..
        } => result_target_is_relevant(target, objective, update_target),
    }
}

fn meaningful_update(update: &ResultUpdate) -> bool {
    match update {
        // `Unchanged` and `RemainsOpen` are meaningful negative outcomes:
        // they are the falsifying side of a confirmation/progress split.
        ResultUpdate::Rival { .. } | ResultUpdate::Gap { .. } => true,
        ResultUpdate::Unknown { .. } => false,
    }
}

/// Reapplies the ready-candidate gates when a plan is validated after
/// deserialization or caller-side construction. The source applicability
/// scope is not carried by a proposal, so shape validation uses an equal
/// synthetic scope and checks the remaining closed gates here.
pub(crate) fn validate_ready_probe(
    probe: &ProbeProposal,
    plan_scope: &str,
) -> Result<(), ContractViolation> {
    if let DescriptorClass::Gap(kind, reason) = classify_dimensions(
        &probe.dimensions,
        "",
        "",
        &probe.target,
        &probe.result_schema,
        Some(&probe.objective),
    ) {
        return Err(ContractViolation::BindingMismatch {
            field: "probe_plan.probe",
            reason: format!("candidate is not ready ({kind:?}): {reason}"),
        });
    }
    let limits = limits_for_demand(probe.budget_demand);
    if let Some((kind, reason)) = semantic_block_reason(
        &probe.target,
        Some(&probe.objective),
        Some(probe.budget_demand),
        Some(&probe.lifecycle),
        Some(&probe.external_owners),
        Some(&probe.capability),
        &probe.result_schema,
        &limits,
        plan_scope,
    ) {
        return Err(ContractViolation::BindingMismatch {
            field: "probe_plan.probe",
            reason: format!("candidate is not ready ({kind:?}): {reason}"),
        });
    }
    Ok(())
}

fn limits_for_demand(demand: BudgetDemand) -> BudgetLimits {
    BudgetLimits {
        input_bytes: demand.input_bytes,
        output_bytes: demand.output_bytes,
        source_width: demand.source_width,
        reference_width: demand.reference_width,
        model_calls: demand.model_calls,
        attempts: demand.attempts,
        candidates: demand.candidates,
        wall_ms: demand.wall_ms,
        work_fan_out: demand.work_fan_out,
        report_bytes: demand.report_bytes,
        max_stu: demand.max_stu,
    }
}

/// Sorts plannable groups by the vector-preserving order and assigns ranks.
fn rank_plannables(
    groups: &mut [DescriptorGroup],
    policy: &ProbeOrderingPolicy,
) -> Result<Vec<ProbeProposal>, ContractViolation> {
    let mut plannable: Vec<&mut DescriptorGroup> = groups
        .iter_mut()
        .filter(|group| matches!(group.class, DescriptorClass::Plannable))
        .collect();
    plannable.sort_by(|left, right| {
        left.dimensions
            .order_key_with(policy)
            .cmp(&right.dimensions.order_key_with(policy))
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
        objective: group
            .objective
            .clone()
            .ok_or(ContractViolation::MissingField(
                "probe_plan.probe.objective",
            ))?,
        budget_demand: group.budget_demand.ok_or(ContractViolation::MissingField(
            "probe_plan.probe.budget_demand",
        ))?,
        lifecycle: group
            .lifecycle
            .clone()
            .ok_or(ContractViolation::MissingField(
                "probe_plan.probe.lifecycle",
            ))?,
        external_owners: group
            .external_owners
            .clone()
            .ok_or(ContractViolation::MissingField(
                "probe_plan.probe.external_owners",
            ))?,
        capability: group
            .capability
            .clone()
            .ok_or(ContractViolation::MissingField(
                "probe_plan.probe.capability",
            ))?,
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
        objective: group.objective.clone(),
        budget_demand: group.budget_demand,
        lifecycle: group.lifecycle.clone(),
        external_owners: group.external_owners.clone(),
        capability: group.capability.clone(),
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
            objective: Some(probe.objective.clone()),
            budget_demand: Some(probe.budget_demand),
            lifecycle: Some(probe.lifecycle.clone()),
            external_owners: Some(probe.external_owners.clone()),
            capability: Some(probe.capability.clone()),
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

fn objective_dispositions(
    groups: &[DescriptorGroup],
    probes: &[ProbeProposal],
    omissions: &[ProbeOmission],
) -> Result<Vec<ProbeObjectiveDisposition>, ContractViolation> {
    let mut dispositions = Vec::with_capacity(groups.len());
    for group in groups {
        let (disposition, reason) = match &group.class {
            DescriptorClass::Gap(kind, reason) => (
                match kind {
                    OmissionKind::Unprobeable => ProbeObjectiveDispositionKind::Unprobeable,
                    OmissionKind::OverBudget => ProbeObjectiveDispositionKind::Omitted,
                    OmissionKind::AuthorityBlocked => ProbeObjectiveDispositionKind::Blocked,
                },
                reason.clone(),
            ),
            DescriptorClass::Plannable => {
                if probes.iter().any(|probe| probe.probe_id == group.primary) {
                    (
                        ProbeObjectiveDispositionKind::Ready,
                        "objective retained as a ready candidate".to_owned(),
                    )
                } else if let Some(omission) = omissions
                    .iter()
                    .find(|omission| omission.affordance.affordance_id == group.primary)
                {
                    (
                        match omission.kind {
                            OmissionKind::Unprobeable => ProbeObjectiveDispositionKind::Unprobeable,
                            OmissionKind::OverBudget => ProbeObjectiveDispositionKind::Omitted,
                            OmissionKind::AuthorityBlocked => {
                                ProbeObjectiveDispositionKind::Blocked
                            }
                        },
                        omission.reason.clone(),
                    )
                } else {
                    return Err(ContractViolation::BindingMismatch {
                        field: "probe_plan.objective_dispositions",
                        reason: "source group has no candidate or explicit omission".to_owned(),
                    });
                }
            }
        };
        let mut affordances = BTreeSet::new();
        affordances.insert(group.primary.clone());
        affordances.extend(group.merged.iter().cloned());
        let row = ProbeObjectiveDisposition {
            objective: group.objective.clone(),
            target: group.target.clone(),
            disposition,
            affordances,
            reason,
        };
        row.validate()?;
        dispositions.push(row);
    }
    Ok(dispositions)
}

fn build_relations(probes: &[ProbeProposal], policy: &ProbeOrderingPolicy) -> Vec<ProbeRelation> {
    let mut relations = Vec::new();
    for (index, left) in probes.iter().enumerate() {
        for right in probes.iter().skip(index + 1) {
            let mut left_better = false;
            let mut right_better = false;
            let mut unknown = false;
            let mut basis = Vec::new();
            for dimension in &policy.dimensions {
                if let (Some(left_rank), Some(right_rank)) = (
                    known_dimension_rank(&left.dimensions, *dimension),
                    known_dimension_rank(&right.dimensions, *dimension),
                ) {
                    match left_rank.cmp(&right_rank) {
                        std::cmp::Ordering::Less => {
                            left_better = true;
                            basis.push(*dimension);
                        }
                        std::cmp::Ordering::Greater => {
                            right_better = true;
                            basis.push(*dimension);
                        }
                        std::cmp::Ordering::Equal => {}
                    }
                } else {
                    unknown = true;
                    basis.push(*dimension);
                }
            }
            if basis.is_empty() {
                basis.extend(policy.dimensions.iter().copied());
            }
            let (relation_left, relation_right, kind) = if !unknown && left_better && !right_better
            {
                (
                    left.probe_id.clone(),
                    right.probe_id.clone(),
                    ProbeRelationKind::Dominates,
                )
            } else if !unknown && right_better && !left_better {
                (
                    right.probe_id.clone(),
                    left.probe_id.clone(),
                    ProbeRelationKind::Dominates,
                )
            } else if !unknown && left_better && right_better {
                (
                    left.probe_id.clone(),
                    right.probe_id.clone(),
                    ProbeRelationKind::Tradeoff,
                )
            } else {
                (
                    left.probe_id.clone(),
                    right.probe_id.clone(),
                    ProbeRelationKind::Incomparable,
                )
            };
            relations.push(ProbeRelation {
                left: relation_left,
                right: relation_right,
                kind,
                basis,
            });
        }
    }
    relations
}

fn known_dimension_rank(
    dimensions: &ProbeDimensions,
    dimension: ProbeOrderingDimension,
) -> Option<u8> {
    match dimension {
        ProbeOrderingDimension::Information => match dimensions.information {
            InformationDimension::High { .. } => Some(0),
            InformationDimension::Moderate { .. } => Some(1),
            InformationDimension::Low { .. } => Some(2),
            InformationDimension::NoGain { .. }
            | InformationDimension::Unknown { .. }
            | InformationDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Cost => match dimensions.cost {
            eliot_dreamer_contracts::CostDimension::Negligible { .. } => Some(0),
            eliot_dreamer_contracts::CostDimension::Low { .. } => Some(1),
            eliot_dreamer_contracts::CostDimension::Moderate { .. } => Some(2),
            eliot_dreamer_contracts::CostDimension::High { .. } => Some(3),
            eliot_dreamer_contracts::CostDimension::Unknown { .. }
            | eliot_dreamer_contracts::CostDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Latency => match dimensions.latency {
            eliot_dreamer_contracts::LatencyDimension::Immediate { .. } => Some(0),
            eliot_dreamer_contracts::LatencyDimension::Interactive { .. } => Some(1),
            eliot_dreamer_contracts::LatencyDimension::Deferred { .. } => Some(2),
            eliot_dreamer_contracts::LatencyDimension::Unknown { .. }
            | eliot_dreamer_contracts::LatencyDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Context => match dimensions.context {
            eliot_dreamer_contracts::ContextDimension::SelfContained { .. } => Some(0),
            eliot_dreamer_contracts::ContextDimension::Narrow { .. } => Some(1),
            eliot_dreamer_contracts::ContextDimension::Broad { .. } => Some(2),
            eliot_dreamer_contracts::ContextDimension::NotApplicable { .. } => Some(3),
            eliot_dreamer_contracts::ContextDimension::Unknown { .. }
            | eliot_dreamer_contracts::ContextDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Resource => match dimensions.resource {
            eliot_dreamer_contracts::ResourceDimension::Trivial { .. } => Some(0),
            eliot_dreamer_contracts::ResourceDimension::NotApplicable { .. } => Some(1),
            eliot_dreamer_contracts::ResourceDimension::Bounded { .. } => Some(2),
            eliot_dreamer_contracts::ResourceDimension::Heavy { .. } => Some(3),
            eliot_dreamer_contracts::ResourceDimension::Unknown { .. }
            | eliot_dreamer_contracts::ResourceDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Privacy => match dimensions.privacy {
            eliot_dreamer_contracts::PrivacyDimension::Contained { .. } => Some(0),
            eliot_dreamer_contracts::PrivacyDimension::NotApplicable { .. } => Some(1),
            eliot_dreamer_contracts::PrivacyDimension::Elevated { .. }
            | eliot_dreamer_contracts::PrivacyDimension::Unknown { .. }
            | eliot_dreamer_contracts::PrivacyDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Consent => match dimensions.consent {
            eliot_dreamer_contracts::ConsentDimension::Granted { .. } => Some(0),
            eliot_dreamer_contracts::ConsentDimension::RequiresGrant { .. } => Some(1),
            eliot_dreamer_contracts::ConsentDimension::Denied { .. }
            | eliot_dreamer_contracts::ConsentDimension::Unknown { .. }
            | eliot_dreamer_contracts::ConsentDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Authority => match dimensions.authority {
            AuthorityDimension::Permitted { .. } => Some(0),
            AuthorityDimension::RequiresApproval { .. } => Some(1),
            AuthorityDimension::Denied { .. }
            | AuthorityDimension::Unknown { .. }
            | AuthorityDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Effect => match dimensions.effect {
            EffectDimension::SideEffectFree { .. } => Some(0),
            EffectDimension::ObservableOnly { .. } => Some(1),
            EffectDimension::StateChanging { .. }
            | EffectDimension::Unknown { .. }
            | EffectDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Reversibility => match dimensions.reversibility {
            ReversibilityDimension::Reversible { .. } => Some(0),
            ReversibilityDimension::Irreversible { .. }
            | ReversibilityDimension::Unknown { .. }
            | ReversibilityDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::Feasibility => match dimensions.feasibility {
            FeasibilityDimension::Feasible { .. } => Some(0),
            FeasibilityDimension::Infeasible { .. }
            | FeasibilityDimension::Unknown { .. }
            | FeasibilityDimension::Unavailable { .. } => None,
        },
        ProbeOrderingDimension::HumanAttention => match dimensions.attention {
            HumanAttentionDimension::Unneeded { .. } => Some(0),
            HumanAttentionDimension::NotApplicable { .. } => Some(1),
            HumanAttentionDimension::Brief { .. } => Some(2),
            HumanAttentionDimension::Sustained { .. } => Some(3),
            HumanAttentionDimension::Unknown { .. }
            | HumanAttentionDimension::Unavailable { .. } => None,
        },
    }
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
    policy: &ProbeOrderingPolicy,
    probes: Vec<ProbeProposal>,
    omissions: Vec<ProbeOmission>,
    objective_dispositions: Vec<ProbeObjectiveDisposition>,
    relations: Vec<ProbeRelation>,
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
        ordering_policy: policy.clone(),
        probes,
        omissions,
        objective_dispositions,
        relations,
        digest: String::new(),
    };
    bounds::preflight(&plan)?;
    plan.digest = plan.compute_digest()?;
    plan.validate()?;
    Ok(plan)
}
