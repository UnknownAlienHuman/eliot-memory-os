//! Deterministic, candidate-only typed relation proposal.
//!
//! The handler consumes an already assembled A03 relation closure, qualifies
//! semantic evidence against an explicit policy, and emits one reversible
//! candidate. It never creates endpoints, traverses storage, or mutates a
//! canonical graph.

#![forbid(unsafe_code)]

mod evidence;
mod policy;
mod result;
mod selection;

pub use evidence::{
    material_evidence_grounded, qualify_alternatives, qualify_causal_claim, qualify_disclosure,
    qualify_endpoints, qualify_evidence, qualify_temporal,
};
pub use policy::{
    CausalMaterialBinding, CausalPredicateBinding, EvidenceBinding, EvidenceBindingKind,
    EvidenceGradeBinding, PathRef, RelationPolicy, grade_binding_digest,
};
pub use result::{RelationResult, assemble_candidate};
pub use selection::{Selection, select, validate_alternative_coverage, validate_path};

use eliot_dreamer_contracts::{
    CurationAcceptanceCtx, RelationDisposition, RelationInput, seal_relation,
};

type SemanticEvaluation = Result<
    (Vec<String>, Vec<String>, Vec<String>, Selection),
    eliot_dreamer_contracts::ContractViolation,
>;

pub(crate) fn computed_work_bound(
    input: &RelationInput,
    policy: &RelationPolicy,
) -> Result<u64, eliot_dreamer_contracts::ContractViolation> {
    let count = |value: usize| {
        u64::try_from(value).map_err(|_| eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.work",
            reason: "cardinality conversion overflow".to_owned(),
        })
    };
    let add = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.work",
                reason: "semantic bound overflow".to_owned(),
            })
    };
    let evidence = add(
        count(input.evidence.len())?,
        count(input.counterevidence.len())?,
    )?;
    let alternatives = add(
        add(
            count(input.rivals.len())?,
            u64::from(input.no_relation_alternative.is_some()),
        )?,
        add(
            count(policy.expected_alternative_refs.len())?,
            count(policy.omitted_alternative_refs.len())?,
        )?,
    )?;
    let alternative_refs = input
        .rivals
        .iter()
        .chain(input.no_relation_alternative.iter())
        .try_fold(0_u64, |total, alternative| {
            add(total, count(alternative.evidence_refs.len())?)
        })?;
    let bindings = add(
        count(policy.grade_bindings.len())?,
        count(policy.causal_bindings.len())?,
    )?;
    let neighborhood = count(input.neighborhood.relations.len())?;
    let path = count(policy.transitive_path.len())?;
    let claim_refs = if let Some(claim) = &policy.causal_claim {
        let width = claim
            .evidence_refs
            .len()
            .checked_add(claim.rivals.len())
            .and_then(|value| value.checked_add(claim.confounders.len()))
            .ok_or(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.work",
                reason: "causal reference count overflow".to_owned(),
            })?;
        count(width)?
    } else {
        0
    };
    let total = add(
        add(
            add(add(evidence, bindings)?, alternatives)?,
            alternative_refs,
        )?,
        add(add(add(neighborhood, path)?, claim_refs)?, 2)?,
    )?;
    // This is a checked semantic record-comparison reservation, not a CPU-time
    // estimate; it covers bounded nested alternative, role and path scans.
    let cubic = total
        .checked_mul(total)
        .and_then(|square| square.checked_mul(total))
        .ok_or(eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.work",
            reason: "semantic cubic bound overflow".to_owned(),
        })?;
    let material_scan = if policy.causal_claim.is_some() || !policy.transitive_path.is_empty() {
        7_u64
            .checked_mul(1024)
            .ok_or(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.work",
                reason: "accepted material bound overflow".to_owned(),
            })?
    } else {
        0
    };
    let work = add(cubic, material_scan)?;
    if work > policy.max_work {
        return Err(eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.work",
            reason: "semantic work bound exceeded".to_owned(),
        });
    }
    Ok(work)
}

fn causal_complete(input: &RelationInput, policy: &RelationPolicy) -> bool {
    if !policy.is_causal(input.family, &input.registry) {
        return true;
    }
    if policy.causal_claim.is_none() {
        return false;
    }
    let kinds = [
        EvidenceBindingKind::Mechanism,
        EvidenceBindingKind::Intervention,
        EvidenceBindingKind::Outcome,
        EvidenceBindingKind::Control,
        EvidenceBindingKind::Rival,
        EvidenceBindingKind::Confounder,
        EvidenceBindingKind::Discriminator,
    ];
    kinds.iter().all(|kind| {
        policy
            .causal_bindings
            .iter()
            .any(|binding| binding.kind == *kind)
    })
}

fn execution_window(
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    if policy.cancellation_requested {
        return Err(eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.cancellation",
            reason: "relation cancelled before semantic evaluation".to_owned(),
        });
    }
    if let (Some(now), Some(deadline)) = (policy.now_ms, policy.deadline_ms)
        && now >= deadline
    {
        return Err(eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.deadline",
            reason: "relation deadline elapsed".to_owned(),
        });
    }
    Ok(())
}

/// Proposes one typed directed relation from the supplied immutable closure.
///
/// All clock observations, bounds, cancellation and policy identity are
/// supplied by the caller. The accepted-item seam is crossed only by
/// [`seal_relation`] after the candidate has been assembled.
fn evaluate_semantics(
    input: &RelationInput,
    ctx: &CurationAcceptanceCtx<'_>,
    policy: &RelationPolicy,
) -> SemanticEvaluation {
    validate_alternative_coverage(input, policy)?;
    validate_path(input, policy)?;
    qualify_endpoints(input)?;
    qualify_temporal(input, policy)?;
    let (support, counter, mut unknown) = qualify_evidence(input, policy)?;
    let (alternative_unknown, alternative_support, unknown_alternative) =
        qualify_alternatives(input, policy)?;
    unknown.extend(alternative_unknown);
    unknown.sort();
    unknown.dedup();
    let causal_qualified = if policy.is_causal(input.family, &input.registry) {
        match &policy.causal_claim {
            None => false,
            Some(claim)
                if !matches!(
                    claim.status,
                    eliot_epistemic_contracts::CausalStatus::InterventionSupported
                        | eliot_epistemic_contracts::CausalStatus::AblationSupported
                ) =>
            {
                false
            }
            Some(_) => {
                qualify_causal_claim(input, ctx, policy)?;
                true
            }
        }
    } else {
        true
    };
    let positive = (!support.is_empty() || !policy.transitive_path.is_empty())
        && (support.is_empty() || material_evidence_grounded(input, policy, &support))
        && counter.is_empty()
        && unknown.is_empty()
        && causal_complete(input, policy)
        && causal_qualified;
    let mut selected = select(
        input,
        policy,
        &support,
        &counter,
        &unknown,
        alternative_support,
        unknown_alternative,
    )?;
    if (selected.disposition == RelationDisposition::Positive
        || selected.disposition == RelationDisposition::Partial)
        && !positive
    {
        selected.disposition = RelationDisposition::Unsupported;
    }
    Ok((support, counter, unknown, selected))
}

pub fn propose_relation(
    input: RelationInput,
    ctx: &CurationAcceptanceCtx<'_>,
    policy: &RelationPolicy,
) -> Result<RelationResult, eliot_dreamer_contracts::ContractViolation> {
    execution_window(policy)?;
    policy.validate()?;
    if ctx.usage.stu_used > policy.max_stu {
        return Err(eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.stu",
            reason: "independent STU bound exceeded".to_owned(),
        });
    }
    if policy.digest != input.policy_digest {
        return Err(
            eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                field: "relation.policy_digest",
                reason: "input is bound to a different policy".to_owned(),
            },
        );
    }
    policy.check_input(&input)?;
    input.validate_acceptance(ctx)?;
    // Reserve the full checked semantic scan before any A22 loops begin.
    let work_units = computed_work_bound(&input, policy)?;
    let (support, counter, unknown, selected) = evaluate_semantics(&input, ctx, policy)?;
    let association = matches!(
        selected.disposition,
        RelationDisposition::Positive
            | RelationDisposition::Partial
            | RelationDisposition::Duplicate
            | RelationDisposition::Inverse
    );
    qualify_disclosure(&input, association)?;
    let unknown_evidence_refs = unknown;
    let candidate = assemble_candidate(&input, policy, &selected, support, counter)?;
    let closure = seal_relation(input, candidate, ctx)?;
    let expiry = policy.deadline_ms.map(|v| v.to_string());
    let reopen_frontier = Some("reopen-on-endpoint-registry-evidence-digest-change".to_owned());
    let degradation = (selected.disposition != RelationDisposition::Positive)
        .then(|| "candidate retained without positive semantic selection".to_owned());
    result::RelationResult::preflight_components(&result::ResultParts {
        closure: &closure,
        policy,
        disposition: selected.disposition,
        unknown_evidence_refs: &unknown_evidence_refs,
        work_units,
        stu_used: ctx.usage.stu_used,
        expiry: expiry.as_ref(),
        reopen_frontier: reopen_frontier.as_ref(),
        degradation: degradation.as_ref(),
    })?;
    RelationResult {
        closure,
        policy: policy.clone(),
        disposition: selected.disposition,
        unknown_evidence_refs,
        work_units,
        stu_used: ctx.usage.stu_used,
        expiry,
        reopen_frontier,
        degradation,
        result_digest: String::new(),
    }
    .seal()
}
