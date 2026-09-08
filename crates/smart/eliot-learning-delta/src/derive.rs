//! Named derivation phases for the A34 semantic edge.

use std::{
    collections::BTreeSet,
    io::{self, Write},
};

use eliot_contracts::ArtifactId;
use eliot_instrument_api::{ExecutionStatus, VerificationOutcome};
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, AttemptLearningOutcome, CampaignLearningStateView,
    NoChangeDisposition, SlotDisposition, ValueState, identity::digest_without_field,
};

use crate::{
    AttemptEvidence, AttemptStatus, BeforeSelector, ChangeRequest, DependencyRole,
    DerivationContext, DerivationPolicy, EvidenceKind, EvidenceReceipt, LearningDeltaError,
    NoChangeProof, RefinerDraft, SemanticOutcome,
    input::{operation_from_values, validate_unique_ids},
    retry::{RetryAssessment, assess_retry},
};

/// Derive exactly one successful A32 outcome from immutable supplied records.
pub fn derive_attempt_learning_outcome(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    optional_refiner_draft: Option<&RefinerDraft>,
    policy: &DerivationPolicy,
) -> Result<AttemptLearningOutcome, LearningDeltaError> {
    policy.validate()?;
    phase_preflight(state_view, input, context, optional_refiner_draft, policy)?;
    input.validate_shape(policy)?;
    state_view.validate_against(&input.recipe)?;
    phase_validate_view(state_view, input)?;
    phase_validate_status(input)?;
    phase_validate_records(input, context, policy, optional_refiner_draft)?;
    phase_validate_dependencies(input)?;
    if !input.changes.is_empty() && input.no_change.is_some() {
        return Err(LearningDeltaError::InvalidInput {
            field: "result.arms",
        });
    }

    let mut operations = Vec::new();
    for request in &input.changes {
        let before = phase_resolve_before(state_view, input, &request.before, &request.target)?;
        operations.push(operation_from_request(
            state_view, request, input, before, policy,
        )?);
    }
    let mut paired: Vec<_> = operations
        .into_iter()
        .zip(input.changes.iter().map(|request| request.rollback.clone()))
        .collect();
    paired.sort_by(|left, right| {
        left.0
            .target()
            .as_str()
            .cmp(right.0.target().as_str())
            .then_with(|| surface_key(&left.0).cmp(surface_key(&right.0)))
    });
    if paired.windows(2).any(|window| {
        window[0].0.target() == window[1].0.target()
            && surface_key(&window[0].0) == surface_key(&window[1].0)
    }) {
        return Err(LearningDeltaError::InvalidInput {
            field: "changes.target_conflict",
        });
    }
    let inverses: Vec<_> = paired.iter().map(|pair| pair.1.clone()).collect();
    let operations: Vec<_> = paired.into_iter().map(|pair| pair.0).collect();
    if input.changes.is_empty() && input.no_change.is_none() {
        return Err(LearningDeltaError::InsufficientEvidence { field: "result" });
    }
    let retry = assess_retry(input, context)?;
    if matches!(retry, RetryAssessment::EquivalentAllowed(_)) && !operations.is_empty() {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.delta",
        });
    }

    if let Some(no_change) = &input.no_change {
        phase_resolve_before(state_view, input, &input.before, &input.target)?;
        return phase_build_no_change(state_view, input, no_change, retry, policy);
    }
    if matches!(retry, RetryAssessment::EquivalentAllowed(_)) {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.result",
        });
    }
    phase_build_delta(state_view, input, &operations, &inverses, policy)
}

fn phase_preflight(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    optional_refiner_draft: Option<&RefinerDraft>,
    policy: &DerivationPolicy,
) -> Result<(), LearningDeltaError> {
    let (mut input_bytes, source_units, view_items, dependency_edges) =
        preflight_counts(state_view, input, context, policy)?;
    preflight_serialization(
        state_view,
        input,
        context,
        optional_refiner_draft,
        policy,
        &mut input_bytes,
    )?;
    let Some(input_bytes) = input_bytes else {
        return Err(LearningDeltaError::Bound {
            field: "input_bytes",
        });
    };
    if input_bytes
        > usize::try_from(policy.max_input_bytes).map_err(|_| LearningDeltaError::Bound {
            field: "input_bytes",
        })?
        || source_units > policy.max_source_units
    {
        return Err(LearningDeltaError::Bound { field: "input" });
    }
    let operations = input.changes.len();
    let work = operations
        .checked_mul(
            input
                .observations
                .len()
                .checked_add(1)
                .ok_or(LearningDeltaError::Bound { field: "work" })?,
        )
        .and_then(|value| value.checked_add(input.recipe.slots.len()))
        .and_then(|value| value.checked_add(view_items))
        .and_then(|value| value.checked_add(dependency_edges))
        .and_then(|value| value.checked_add(input.dependency_evidence.len()))
        .ok_or(LearningDeltaError::Bound { field: "work" })?;
    if u32::try_from(work).map_err(|_| LearningDeltaError::Bound { field: "work" })?
        > policy.max_work_units
    {
        return Err(LearningDeltaError::Bound { field: "work" });
    }
    Ok(())
}

fn preflight_serialization(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    optional_refiner_draft: Option<&RefinerDraft>,
    policy: &DerivationPolicy,
    input_bytes: &mut Option<usize>,
) -> Result<(), LearningDeltaError> {
    count_serialized(
        input,
        input_bytes,
        policy.max_input_bytes,
        "input.serialization",
    )?;
    count_serialized(
        state_view,
        input_bytes,
        policy.max_input_bytes,
        "view.serialization",
    )?;
    count_serialized(
        policy,
        input_bytes,
        policy.max_input_bytes,
        "policy.serialization",
    )?;
    if let Some(draft) = optional_refiner_draft {
        count_serialized(
            draft,
            input_bytes,
            policy.max_input_bytes,
            "refiner.serialization",
        )?;
    }
    count_serialized(
        context.current.run,
        input_bytes,
        policy.max_input_bytes,
        "verification.serialization",
    )?;
    count_serialized(
        context.current.binding,
        input_bytes,
        policy.max_input_bytes,
        "frozen_property.serialization",
    )?;
    count_serialized(
        context.current.invocation,
        input_bytes,
        policy.max_input_bytes,
        "attempt_invocation.serialization",
    )?;
    count_serialized(
        context.current.raw_evidence,
        input_bytes,
        policy.max_input_bytes,
        "raw_evidence.serialization",
    )?;
    if let Some(prior) = context.prior {
        count_serialized(
            prior.run,
            input_bytes,
            policy.max_input_bytes,
            "prior.serialization",
        )?;
        count_serialized(
            prior.binding,
            input_bytes,
            policy.max_input_bytes,
            "prior.frozen_property.serialization",
        )?;
        count_serialized(
            prior.invocation,
            input_bytes,
            policy.max_input_bytes,
            "prior.attempt_invocation.serialization",
        )?;
        count_serialized(
            prior.raw_evidence,
            input_bytes,
            policy.max_input_bytes,
            "prior.raw_evidence.serialization",
        )?;
    }
    Ok(())
}

fn validate_normalized_values(
    run: &eliot_instrument_api::VerificationRun,
    policy: &DerivationPolicy,
    field: &'static str,
) -> Result<(), LearningDeltaError> {
    let max_nodes = usize::try_from(policy.max_references)
        .map_err(|_| LearningDeltaError::Bound { field })?
        .checked_mul(16)
        .ok_or(LearningDeltaError::Bound { field })?;
    let mut nodes = 0usize;
    let mut stack = run
        .evidence
        .iter()
        .map(|record| (&record.value, 0u8))
        .collect::<Vec<_>>();
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or(LearningDeltaError::Bound { field })?;
        if nodes > max_nodes || depth > 64 {
            return Err(LearningDeltaError::Bound { field });
        }
        if let Some(items) = value.as_array() {
            if u32::try_from(items.len()).map_err(|_| LearningDeltaError::Bound { field })?
                > policy.max_references
            {
                return Err(LearningDeltaError::Bound { field });
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(LearningDeltaError::Bound { field })?;
            for item in items {
                stack.push((item, child_depth));
            }
        } else if let Some(fields) = value.as_object() {
            if u32::try_from(fields.len()).map_err(|_| LearningDeltaError::Bound { field })?
                > policy.max_references
            {
                return Err(LearningDeltaError::Bound { field });
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(LearningDeltaError::Bound { field })?;
            for item in fields.values() {
                stack.push((item, child_depth));
            }
        }
    }
    Ok(())
}

fn preflight_counts(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    policy: &DerivationPolicy,
) -> Result<(Option<usize>, u32, usize, usize), LearningDeltaError> {
    let mut input_bytes = Some(0usize);
    let mut source_units = 0u32;
    let mut add = |size: usize| {
        input_bytes = input_bytes.and_then(|total| total.checked_add(size));
    };
    add(input.binding.source.digest.len());
    add(input.retry.environment_fingerprint.len());
    add(input.intended_strategy_digest.len());
    add(input.attempted_strategy_digest.len());
    add(input.mechanism_fingerprint.len());
    add(input.probe_fingerprint.len());
    add(input.action_plan_fingerprint.len());
    validate_preflight_collections(state_view, input, context, policy)?;
    let view_items = count_view_items(state_view)?;
    let dependency_edges = count_dependency_edges(input)?;
    for (count, field) in [
        (view_items, "view.items"),
        (dependency_edges, "dependency.edges"),
    ] {
        if u32::try_from(count).map_err(|_| LearningDeltaError::Bound { field })?
            > policy.max_references
        {
            return Err(LearningDeltaError::Bound { field });
        }
    }
    count_preflight_receipts(input, context, &mut add, &mut source_units)?;
    validate_normalized_values(context.current.run, policy, "verification.values")?;
    if let Some(prior) = context.prior {
        validate_normalized_values(prior.run, policy, "prior.verification.values")?;
    }
    Ok((input_bytes, source_units, view_items, dependency_edges))
}

fn validate_preflight_collections(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    policy: &DerivationPolicy,
) -> Result<(), LearningDeltaError> {
    let bounded = [
        (input.observations.len(), "observations"),
        (state_view.slots.len(), "view.slots"),
        (
            input.owner_empty_declarations.len(),
            "owner_empty_declarations",
        ),
        (input.changes.len(), "changes"),
        (input.dependency_evidence.len(), "dependency_evidence"),
        (input.recipe.slots.len(), "recipe.slots"),
        (input.baseline.len(), "baseline"),
        (input.control.len(), "control"),
        (input.confounders.len(), "confounders"),
        (
            input.retry.prior_material_evidence.len(),
            "retry.material_references",
        ),
        (input.retry.prior_evidence.len(), "retry.evidence"),
        (
            input
                .no_change
                .as_ref()
                .map_or(0, |request| request.affirmative_evidence.len()),
            "no_change.evidence",
        ),
        (context.current.run.evidence.len(), "verification.evidence"),
        (
            context.current.run.raw_evidence.len(),
            "verification.raw_evidence",
        ),
        (context.current.raw_evidence.len(), "raw_evidence"),
    ];
    for (count, field) in bounded {
        if u32::try_from(count).map_err(|_| LearningDeltaError::Bound { field })?
            > policy.max_references
        {
            return Err(LearningDeltaError::Bound { field });
        }
    }
    for slot in &state_view.slots {
        for (count, field) in [
            (slot.members.len(), "view.slot.members"),
            (slot.evidence.len(), "view.slot.evidence"),
        ] {
            if u32::try_from(count).map_err(|_| LearningDeltaError::Bound { field })?
                > policy.max_references
            {
                return Err(LearningDeltaError::Bound { field });
            }
        }
    }
    for slot in &input.recipe.slots {
        if u32::try_from(slot.declared_members.len()).map_err(|_| LearningDeltaError::Bound {
            field: "recipe.members",
        })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "recipe.members",
            });
        }
    }
    for change in &input.changes {
        if u32::try_from(change.dependencies.len()).map_err(|_| LearningDeltaError::Bound {
            field: "change.dependencies",
        })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "change.dependencies",
            });
        }
    }
    for dependency in &input.dependency_evidence {
        if u32::try_from(dependency.depends_on.len()).map_err(|_| LearningDeltaError::Bound {
            field: "dependency.edges",
        })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "dependency.edges",
            });
        }
    }
    if let Some(prior) = context.prior {
        for (count, field) in [
            (prior.run.evidence.len(), "prior.verification.evidence"),
            (
                prior.run.raw_evidence.len(),
                "prior.verification.raw_evidence",
            ),
            (prior.raw_evidence.len(), "prior.raw_evidence"),
        ] {
            if u32::try_from(count).map_err(|_| LearningDeltaError::Bound { field })?
                > policy.max_references
            {
                return Err(LearningDeltaError::Bound { field });
            }
        }
    }
    Ok(())
}

fn count_view_items(state_view: &CampaignLearningStateView) -> Result<usize, LearningDeltaError> {
    state_view
        .slots
        .iter()
        .try_fold(0usize, |total, slot| {
            total
                .checked_add(slot.members.len())?
                .checked_add(slot.evidence.len())
        })
        .ok_or(LearningDeltaError::Bound {
            field: "view.items",
        })?
        .checked_add(state_view.slots.len())
        .and_then(|total| total.checked_add(state_view.omissions.len()))
        .and_then(|total| total.checked_add(state_view.frontier.len()))
        .and_then(|total| total.checked_add(state_view.owner_disagreements.len()))
        .and_then(|total| total.checked_add(state_view.required_references.len()))
        .ok_or(LearningDeltaError::Bound {
            field: "view.items",
        })
}

fn count_dependency_edges(input: &AttemptEvidence) -> Result<usize, LearningDeltaError> {
    input
        .dependency_evidence
        .iter()
        .try_fold(0usize, |total, dependency| {
            total.checked_add(dependency.depends_on.len())
        })
        .ok_or(LearningDeltaError::Bound {
            field: "dependency.edges",
        })
}

fn count_preflight_receipts(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    add: &mut impl FnMut(usize),
    source_units: &mut u32,
) -> Result<(), LearningDeltaError> {
    for receipt in input.observations.iter().chain(input.evaluator.iter()) {
        add(receipt.id.as_str().len());
        add(receipt.source_revision.len());
        add(receipt.source_digest.len());
        *source_units =
            (*source_units)
                .checked_add(receipt.source_units)
                .ok_or(LearningDeltaError::Bound {
                    field: "source_units",
                })?;
    }
    for raw in context.current.raw_evidence {
        add(raw.bytes.len());
    }
    if let Some(prior) = context.prior {
        for raw in prior.raw_evidence {
            add(raw.bytes.len());
        }
    }
    Ok(())
}
fn count_serialized<T: serde::Serialize + ?Sized>(
    value: &T,
    total: &mut Option<usize>,
    limit: u32,
    field: &'static str,
) -> Result<(), LearningDeltaError> {
    let mut writer = CountingWriter {
        total,
        limit: usize::try_from(limit).map_err(|_| LearningDeltaError::Bound { field })?,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| LearningDeltaError::Bound { field })
}

struct CountingWriter<'a> {
    total: &'a mut Option<usize>,
    limit: usize,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(total) = self.total else {
            return Err(io::Error::other("serialization bound"));
        };
        let next = total
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialization bound"))?;
        if next > self.limit {
            *self.total = None;
            return Err(io::Error::other("serialization bound"));
        }
        *total = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn phase_validate_view(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
) -> Result<(), LearningDeltaError> {
    state_view.binding.validate()?;
    if state_view.binding != input.binding
        || state_view.target != input.target
        || state_view.recipe_id != input.recipe.recipe_id
        || state_view.recipe_digest != input.recipe.canonical_digest
    {
        return Err(LearningDeltaError::EvidenceBinding { field: "view" });
    }
    if input.recipe.binding != input.binding || input.recipe.target != input.target {
        return Err(LearningDeltaError::EvidenceBinding { field: "recipe" });
    }
    if state_view.invalidated {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "view.invalidated",
        });
    }
    if !state_view.owner_disagreements.is_empty() {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "view.owner_disagreements",
        });
    }
    if digest_without_field(state_view, "canonical_digest")? != state_view.canonical_digest {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "view.digest",
        });
    }
    Ok(())
}

fn phase_validate_status(input: &AttemptEvidence) -> Result<(), LearningDeltaError> {
    match input.status {
        AttemptStatus::Consequential => Ok(()),
        AttemptStatus::NonConsequential => Err(LearningDeltaError::NonConsequential),
        AttemptStatus::Cancelled => Err(LearningDeltaError::Cancelled),
        AttemptStatus::BoundedOut => Err(LearningDeltaError::BoundedOut),
    }
}

fn phase_validate_records(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    policy: &DerivationPolicy,
    optional_refiner_draft: Option<&RefinerDraft>,
) -> Result<(), LearningDeltaError> {
    if input.observations.is_empty() {
        return Err(LearningDeltaError::InsufficientEvidence {
            field: "observations",
        });
    }
    let mut receipt_ids = input
        .observations
        .iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    if let Some(evaluator) = &input.evaluator {
        receipt_ids.push(evaluator.id.clone());
    }
    validate_unique_ids(&receipt_ids, "evidence.receipts")?;
    for observation in &input.observations {
        observation.validate_for(input, policy)?;
        if observation.kind != EvidenceKind::Observation {
            return Err(LearningDeltaError::NonSemanticEvidence);
        }
    }
    validate_current_evaluator(input, context, policy)?;
    validate_auxiliary_references(input, context)?;
    if let Some(draft) = optional_refiner_draft.or(input.refiner.as_ref()) {
        if draft.artifact.as_str().trim().is_empty()
            || draft.receipt.as_str().trim().is_empty()
            || draft.route.trim().is_empty()
        {
            return Err(LearningDeltaError::InvalidInput { field: "refiner" });
        }
        if let Some(input_draft) = input.refiner.as_ref()
            && Some(draft) != Some(input_draft)
        {
            return Err(LearningDeltaError::InvalidInput {
                field: "refiner.binding",
            });
        }
    }
    let record_count = input
        .observations
        .len()
        .checked_add(1)
        .ok_or(LearningDeltaError::Bound { field: "evidence" })?;
    if u32::try_from(record_count).map_err(|_| LearningDeltaError::Bound { field: "evidence" })?
        > policy.max_evidence
    {
        return Err(LearningDeltaError::Bound { field: "evidence" });
    }
    Ok(())
}

fn validate_auxiliary_references(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
) -> Result<(), LearningDeltaError> {
    let raw_ids: BTreeSet<&str> = context
        .current
        .raw_evidence
        .iter()
        .map(|raw| raw.artifact_id.as_str())
        .collect();
    let mut categories = BTreeSet::new();
    for (ids, field) in [
        (&input.baseline, "baseline"),
        (&input.control, "control"),
        (&input.confounders, "confounders"),
    ] {
        for id in ids {
            if !raw_ids.contains(id.as_str()) || !categories.insert(id.as_str()) {
                return Err(LearningDeltaError::EvidenceBinding { field });
            }
        }
    }
    Ok(())
}

fn validate_current_evaluator(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    policy: &DerivationPolicy,
) -> Result<(), LearningDeltaError> {
    let evaluator = input
        .evaluator
        .as_ref()
        .ok_or(LearningDeltaError::MissingEvaluator)?;
    evaluator.validate_for(input, policy)?;
    if evaluator.kind != EvidenceKind::Evaluator {
        return Err(LearningDeltaError::MissingEvaluator);
    }
    let run = context.current.run;
    run.validate()
        .map_err(|_| LearningDeltaError::EvidenceBinding {
            field: "verification_run",
        })?;
    if !matches!(
        run.freshness,
        eliot_instrument_api::EvidenceFreshness::ExactCandidate
            | eliot_instrument_api::EvidenceFreshness::ExactCommit
            | eliot_instrument_api::EvidenceFreshness::ExactQuiescedWorktree
    ) || run.coverage != eliot_instrument_api::EvidenceCoverage::CompleteForScope
    {
        return Err(LearningDeltaError::InsufficientEvidence {
            field: "verification_run.coverage",
        });
    }
    let expected = input
        .evaluator_binding
        .as_ref()
        .ok_or(LearningDeltaError::MissingEvaluator)?;
    let frozen = context.current.binding;
    validate_frozen_property(expected, frozen, policy)?;
    if run.run_id != frozen.run_id
        || run.verifier != frozen.verifier
        || run.invocation_id != frozen.invocation_id
        || run.property != frozen.property
        || run.scope != frozen.scope
        || run.scope != input.binding.scope.as_str()
        || frozen.scope != input.binding.scope.as_str()
        || run.state_fence != input.binding.state_fence
    {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "verification_run.lineage",
        });
    }
    let invocation = context.current.invocation;
    if invocation.attempt_id != input.attempt_id
        || invocation.target != input.target
        || invocation.task_id != input.binding.task_id
        || invocation.scope != input.binding.scope
        || invocation.state_fence != input.binding.state_fence
        || invocation.invocation_id != run.invocation_id
        || invocation.pre_observation_invocation_id != input.pre_observation_invocation_id
        || invocation
            .pre_observation_invocation_id
            .as_str()
            .trim()
            .is_empty()
        || invocation.pre_observation_invocation_id == invocation.invocation_id
        || invocation.environment_fingerprint != input.retry.environment_fingerprint
        || invocation.relation_receipt.as_str().trim().is_empty()
    {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "attempt_invocation",
        });
    }
    let raw_ids = validate_raw_set(
        context.current.raw_evidence,
        run,
        invocation.relation_receipt.as_str(),
    )?;
    validate_current_raw_and_outcome(input, context, evaluator, expected, run, &raw_ids)
}

fn validate_current_raw_and_outcome(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    evaluator: &EvidenceReceipt,
    expected: &crate::EvaluatorBinding,
    run: &eliot_instrument_api::VerificationRun,
    raw_ids: &BTreeSet<&str>,
) -> Result<(), LearningDeltaError> {
    for record in input.observations.iter().chain(input.evaluator.iter()) {
        let raw = context
            .current
            .raw_evidence
            .iter()
            .find(|raw| raw.artifact_id == record.id)
            .ok_or(LearningDeltaError::EvidenceBinding {
                field: "raw_evidence.receipt",
            })?;
        if record.source_digest != raw.sha256 || raw.invocation_id != expected.invocation_id {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "raw_evidence.digest",
            });
        }
    }
    if !input
        .observations
        .iter()
        .chain(input.evaluator.iter())
        .all(|record| raw_ids.contains(record.id.as_str()))
    {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "raw_evidence.membership",
        });
    }
    validate_pre_observation_materials(input, context, raw_ids)?;
    let mapped =
        map_verification_outcome(run.outcome, expected.pass_outcome, expected.fail_outcome)?;
    if evaluator.outcome != mapped || !matches!(run.execution, ExecutionStatus::Succeeded) {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "verification_run.outcome",
        });
    }
    Ok(())
}

fn validate_frozen_property(
    expected: &crate::EvaluatorBinding,
    frozen: &crate::FrozenPropertyBinding,
    policy: &DerivationPolicy,
) -> Result<(), LearningDeltaError> {
    if policy.evaluator_contract.as_ref() != Some(&expected.contract_id)
        || policy.evaluator_verifier.as_ref() != Some(&expected.verifier)
        || expected.property != policy.evaluator_property
        || expected.revision != policy.evaluator_revision
        || expected.pass_outcome != policy.evaluator_pass_outcome
        || expected.fail_outcome != policy.evaluator_fail_outcome
    {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "policy.evaluator",
        });
    }
    if frozen.run_id != expected.run_id
        || frozen.invocation_id != expected.invocation_id
        || frozen.verifier != expected.verifier
        || frozen.property != expected.property
        || frozen.scope != expected.scope
        || frozen.revision != expected.revision
        || frozen.pass_outcome != expected.pass_outcome
        || frozen.fail_outcome != expected.fail_outcome
    {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "frozen_property",
        });
    }
    Ok(())
}

fn validate_raw_set<'a>(
    raw_evidence: &'a [eliot_instrument_api::RawEvidence],
    run: &eliot_instrument_api::VerificationRun,
    relation_receipt: &str,
) -> Result<BTreeSet<&'a str>, LearningDeltaError> {
    let mut raw_ids = BTreeSet::new();
    for raw in raw_evidence {
        raw.validate()
            .map_err(|_| LearningDeltaError::EvidenceBinding {
                field: "raw_evidence",
            })?;
        if !raw_ids.insert(raw.artifact_id.as_str()) {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "raw_evidence.lineage",
            });
        }
    }
    let run_ids: BTreeSet<&str> = run
        .raw_evidence
        .iter()
        .map(eliot_contracts::ArtifactId::as_str)
        .collect();
    if relation_receipt.trim().is_empty()
        || raw_ids.is_empty()
        || run_ids.len() != run.raw_evidence.len()
        || run_ids != raw_ids
        || run
            .evidence
            .iter()
            .any(|record| !run_ids.contains(record.raw_artifact_id.as_str()))
    {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "raw_evidence.membership",
        });
    }
    Ok(raw_ids)
}

fn validate_pre_observation_materials(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    raw_ids: &BTreeSet<&str>,
) -> Result<(), LearningDeltaError> {
    let materials = [
        (&input.discriminator_evidence, &input.discriminator_digest),
        (
            &input.intended_strategy_evidence,
            &input.intended_strategy_digest,
        ),
        (
            &input.attempted_strategy_evidence,
            &input.attempted_strategy_digest,
        ),
        (&input.mechanism_evidence, &input.mechanism_fingerprint),
        (&input.probe_evidence, &input.probe_fingerprint),
        (&input.action_plan_evidence, &input.action_plan_fingerprint),
    ];
    let mut seen = BTreeSet::new();
    for (artifact, digest) in materials {
        if !seen.insert(artifact.as_str()) || !raw_ids.contains(artifact.as_str()) {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "pre_observation.material",
            });
        }
        let raw = context
            .current
            .raw_evidence
            .iter()
            .find(|raw| raw.artifact_id == *artifact)
            .ok_or(LearningDeltaError::EvidenceBinding {
                field: "pre_observation.material",
            })?;
        if raw.invocation_id != input.pre_observation_invocation_id || raw.sha256 != *digest {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "pre_observation.digest",
            });
        }
    }
    Ok(())
}

fn map_verification_outcome(
    outcome: VerificationOutcome,
    pass: SemanticOutcome,
    fail: SemanticOutcome,
) -> Result<SemanticOutcome, LearningDeltaError> {
    match outcome {
        VerificationOutcome::Pass => Ok(pass),
        VerificationOutcome::Fail => Ok(fail),
        VerificationOutcome::Partial
        | VerificationOutcome::Unknown
        | VerificationOutcome::Blocked
        | VerificationOutcome::Cancelled => Err(LearningDeltaError::InsufficientEvidence {
            field: "verification_run.outcome",
        }),
    }
}

fn phase_validate_dependencies(input: &AttemptEvidence) -> Result<(), LearningDeltaError> {
    let ids: BTreeSet<&str> = input
        .dependency_evidence
        .iter()
        .map(|dependency| dependency.id.as_str())
        .collect();
    if ids.len() != input.dependency_evidence.len() {
        return Err(LearningDeltaError::InvalidInput {
            field: "dependencies.duplicate",
        });
    }
    for dependency in &input.dependency_evidence {
        if dependency.binding.validate().is_err()
            || dependency.binding.schema_version != input.binding.schema_version
            || dependency.binding.policy_revision != input.binding.policy_revision
            || dependency.binding.request_id != input.binding.request_id
            || dependency.binding.operation_id != input.binding.operation_id
            || dependency.binding.product_id != input.binding.product_id
            || dependency.binding.task_id != input.binding.task_id
            || dependency.binding.scope != input.binding.scope
            || dependency.binding.state_fence != input.binding.state_fence
            || dependency.binding.proof_ceiling != input.binding.proof_ceiling
            || dependency.source_digest != dependency.binding.source.digest
            || dependency.status != crate::DependencyStatus::Current
            || dependency
                .depends_on
                .iter()
                .any(|id| !ids.contains(id.as_str()))
        {
            return Err(LearningDeltaError::InsufficientEvidence {
                field: "dependencies",
            });
        }
    }
    let required: BTreeSet<&str> = input
        .changes
        .iter()
        .flat_map(|change| {
            change
                .dependencies
                .iter()
                .map(ArtifactId::as_str)
                .chain(std::iter::once(change.invalidation.as_str()))
        })
        .collect();
    if required.iter().any(|id| !ids.contains(id)) {
        return Err(LearningDeltaError::InsufficientEvidence {
            field: "dependencies.missing",
        });
    }
    for change in &input.changes {
        let invalidation = input
            .dependency_evidence
            .iter()
            .find(|dependency| dependency.id == change.invalidation)
            .ok_or(LearningDeltaError::InsufficientEvidence {
                field: "invalidation.missing",
            })?;
        if !matches!(&invalidation.role, DependencyRole::Invalidation { target, surface, owner, member_id }
            if target == &change.target && surface == &change.surface && owner == &change.owner && member_id == &change.member_id)
        {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "invalidation.role",
            });
        }
        for dependency_id in &change.dependencies {
            let supporting = input
                .dependency_evidence
                .iter()
                .find(|dependency| dependency.id == *dependency_id)
                .ok_or(LearningDeltaError::InsufficientEvidence {
                    field: "dependencies.missing",
                })?;
            if !matches!(supporting.role, DependencyRole::Supporting) {
                return Err(LearningDeltaError::EvidenceBinding {
                    field: "dependency.role",
                });
            }
        }
    }
    if dependency_cycle(&input.dependency_evidence) {
        return Err(LearningDeltaError::InvalidInput {
            field: "dependencies.cycle",
        });
    }
    Ok(())
}

fn dependency_cycle(dependencies: &[crate::DependencyEvidence]) -> bool {
    let mut colors = std::collections::BTreeMap::new();
    for dependency in dependencies {
        let id = dependency.id.as_str();
        if colors.get(id) == Some(&2) {
            continue;
        }
        let mut stack = vec![(id, false)];
        while let Some((current, exiting)) = stack.pop() {
            if exiting {
                colors.insert(current, 2);
                continue;
            }
            match colors.get(current).copied() {
                Some(1) => return true,
                Some(2) => continue,
                _ => {}
            }
            colors.insert(current, 1);
            stack.push((current, true));
            if let Some(record) = dependencies
                .iter()
                .find(|record| record.id.as_str() == current)
            {
                for next in record.depends_on.iter().rev() {
                    stack.push((next.as_str(), false));
                }
            }
        }
    }
    false
}

fn phase_resolve_before(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    selector: &BeforeSelector,
    expected_target: &eliot_learning_contracts::TargetId,
) -> Result<ValueState, LearningDeltaError> {
    match selector {
        BeforeSelector::CurrentMember { .. } => {
            resolve_current_before(state_view, input, expected_target, selector)
        }
        BeforeSelector::KnownEmpty { .. } => {
            resolve_known_empty_before(state_view, input, expected_target, selector)
        }
    }
}

fn resolve_current_before(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    expected_target: &eliot_learning_contracts::TargetId,
    selector: &BeforeSelector,
) -> Result<ValueState, LearningDeltaError> {
    let BeforeSelector::CurrentMember {
        slot_id,
        member_id,
        owner,
        source_owner,
        source_revision,
        source_snapshot,
        source_digest,
        projection_revision,
    } = selector
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable { field: "selector" });
    };
    let Some(spec) = input
        .recipe
        .slots
        .iter()
        .find(|slot| slot.slot_id == *slot_id)
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable { field: "slot" });
    };
    if spec.target != *expected_target
        || spec.owner != *owner
        || !spec.declared_members.contains(member_id)
    {
        return Err(LearningDeltaError::BeforeValueUnavailable { field: "selector" });
    }
    let Some(projection) = state_view
        .slots
        .iter()
        .find(|slot| slot.slot_id == *slot_id)
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "slot.projection",
        });
    };
    if projection.disposition != SlotDisposition::Current {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "slot.disposition",
        });
    }
    let Some(member) = projection
        .members
        .iter()
        .find(|member| member.member_id == *member_id)
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable { field: "member" });
    };
    if member.owner != *owner
        || member.source.owner != *source_owner
        || member.source.revision != *source_revision
        || member.source.snapshot != *source_snapshot
        || member.source.digest != *source_digest
        || member.projection_revision != *projection_revision
        || member.disposition != SlotDisposition::Current
    {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "member.lineage",
        });
    }
    let Some(digest) = member.value_digest.clone() else {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "member.value",
        });
    };
    Ok(ValueState {
        present: true,
        digest: Some(digest),
    })
}

fn resolve_known_empty_before(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    expected_target: &eliot_learning_contracts::TargetId,
    selector: &BeforeSelector,
) -> Result<ValueState, LearningDeltaError> {
    let BeforeSelector::KnownEmpty {
        slot_id,
        owner,
        source_owner,
        source_snapshot,
        source_revision,
        source_digest,
        evidence,
    } = selector
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable { field: "selector" });
    };
    let Some(spec) = input
        .recipe
        .slots
        .iter()
        .find(|slot| slot.slot_id == *slot_id)
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "empty.slot",
        });
    };
    let Some(projection) = state_view
        .slots
        .iter()
        .find(|slot| slot.slot_id == *slot_id)
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "empty.projection",
        });
    };
    let Some(declaration) = input
        .owner_empty_declarations
        .iter()
        .find(|declaration| declaration.receipt_id == *evidence)
    else {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "empty.declaration",
        });
    };
    if spec.target != *expected_target
        || declaration.binding.validate().is_err()
        || declaration.source.validate().is_err()
        || spec.owner != *owner
        || source_owner.as_str().trim().is_empty()
        || source_snapshot.as_str().trim().is_empty()
        || source_revision.value() == 0
        || source_digest.len() != 64
        || !source_digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || declaration.slot_id != *slot_id
        || declaration.target != *expected_target
        || declaration.owner != *owner
        || declaration.source.owner != *source_owner
        || declaration.source.snapshot != *source_snapshot
        || declaration.source.revision != *source_revision
        || declaration.source.digest != *source_digest
        || declaration.binding.source != declaration.source
        || declaration.binding.schema_version != input.binding.schema_version
        || declaration.binding.policy_revision != input.binding.policy_revision
        || declaration.binding.product_id != input.binding.product_id
        || declaration.binding.task_id != input.binding.task_id
        || declaration.binding.scope != input.binding.scope
        || declaration.binding.state_fence != input.binding.state_fence
        || declaration.binding.proof_ceiling != input.binding.proof_ceiling
        || !spec.declared_members.is_empty()
        || projection.disposition != SlotDisposition::KnownEmpty
        || !projection.members.is_empty()
        || !projection.evidence.contains(evidence)
    {
        return Err(LearningDeltaError::BeforeValueUnavailable {
            field: "empty.proof",
        });
    }
    Ok(ValueState {
        present: false,
        digest: None,
    })
}

fn operation_from_request(
    state_view: &CampaignLearningStateView,
    request: &ChangeRequest,
    input: &AttemptEvidence,
    before: ValueState,
    policy: &DerivationPolicy,
) -> Result<eliot_learning_contracts::ChangeOperation, LearningDeltaError> {
    if request.slot_id.as_str().trim().is_empty()
        || request.owner.as_str().trim().is_empty()
        || request.accepted_type.trim().is_empty()
    {
        return Err(LearningDeltaError::ProtectedSurface);
    }
    let selector_member = match &request.before {
        BeforeSelector::CurrentMember { member_id, .. } => Some(member_id),
        BeforeSelector::KnownEmpty { .. } => None,
    };
    if request.member_id.as_ref() != selector_member {
        return Err(LearningDeltaError::ProtectedSurface);
    }
    let spec = input
        .recipe
        .slots
        .iter()
        .find(|slot| slot.slot_id == request.slot_id)
        .ok_or(LearningDeltaError::ProtectedSurface)?;
    if spec.target != request.target
        || spec.owner != request.owner
        || spec.accepted_type != request.accepted_type
        || spec.schema_digest != request.schema_digest
        || request.invalidation.as_str().trim().is_empty()
    {
        return Err(LearningDeltaError::ProtectedSurface);
    }
    if !policy.allows_surface(request) {
        return Err(LearningDeltaError::ProtectedSurface);
    }
    if state_view
        .required_references
        .contains(&request.invalidation)
    {
        return Err(LearningDeltaError::ProtectedSurface);
    }
    validate_unique_ids(&request.dependencies, "change.dependencies")?;
    operation_from_values(request, before)
}

fn phase_build_delta(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    operations: &[eliot_learning_contracts::ChangeOperation],
    inverses: &[eliot_learning_contracts::InverseChange],
    policy: &DerivationPolicy,
) -> Result<AttemptLearningOutcome, LearningDeltaError> {
    let evaluator = input
        .evaluator
        .as_ref()
        .ok_or(LearningDeltaError::MissingEvaluator)?;
    if !matches!(
        evaluator.outcome,
        SemanticOutcome::Benefit | SemanticOutcome::Harm
    ) {
        return Err(LearningDeltaError::InsufficientEvidence {
            field: "delta.evaluator",
        });
    }
    let mut evidence: Vec<ArtifactId> = input
        .observations
        .iter()
        .map(|record| record.id.clone())
        .collect();
    evidence.push(evaluator.id.clone());
    evidence.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut evaluator_receipts = vec![evaluator.id.clone()];
    evaluator_receipts.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut closure: BTreeSet<&str> = input
        .changes
        .iter()
        .flat_map(|request| {
            request
                .dependencies
                .iter()
                .map(ArtifactId::as_str)
                .chain(std::iter::once(request.invalidation.as_str()))
        })
        .collect();
    let mut pending: Vec<&str> = closure.iter().copied().collect();
    while let Some(id) = pending.pop() {
        let dependency = input
            .dependency_evidence
            .iter()
            .find(|candidate| candidate.id.as_str() == id)
            .ok_or(LearningDeltaError::InsufficientEvidence {
                field: "dependencies.missing",
            })?;
        for next in &dependency.depends_on {
            if closure.insert(next.as_str()) {
                pending.push(next.as_str());
            }
        }
    }
    let dependencies: Vec<ArtifactId> = input
        .dependency_evidence
        .iter()
        .filter(|dependency| closure.contains(dependency.id.as_str()))
        .map(|dependency| dependency.id.clone())
        .collect();
    let mut dependencies = dependencies;
    dependencies.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut candidate = AttemptLearningDeltaCandidate {
        binding: input.binding.clone(),
        attempt_id: input.attempt_id.clone(),
        delta_id: input.delta_id.clone(),
        target: input.target.clone(),
        base_view_digest: state_view.canonical_digest.clone(),
        pre_observation_discriminator: input.pre_observation_discriminator.clone(),
        intended_strategy: input.intended_strategy.clone(),
        attempted_strategy: input.attempted_strategy.clone(),
        changes: operations.to_vec(),
        inverses: inverses.to_vec(),
        evidence,
        evaluator_receipts,
        baseline: sorted_ids(&input.baseline),
        control: sorted_ids(&input.control),
        confounders: sorted_ids(&input.confounders),
        dependencies,
        equivalent_retry: None,
        proof_ceiling: eliot_learning_contracts::ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    candidate.validate_against_view(state_view)?;
    check_output_size(&AttemptLearningOutcome::Delta(candidate.clone()), policy)?;
    Ok(AttemptLearningOutcome::Delta(candidate))
}

fn phase_build_no_change(
    state_view: &CampaignLearningStateView,
    input: &AttemptEvidence,
    request: &crate::NoChangeRequest,
    retry: RetryAssessment,
    policy: &DerivationPolicy,
) -> Result<AttemptLearningOutcome, LearningDeltaError> {
    let observed =
        usize::try_from(request.denominator.observed).map_err(|_| LearningDeltaError::Bound {
            field: "no_change.evidence",
        })?;
    if request.denominator.declared == 0
        || request.denominator.declared != request.denominator.observed
        || observed != request.affirmative_evidence.len()
    {
        return Err(LearningDeltaError::InvalidNoChangePredicate);
    }
    validate_unique_ids(&request.affirmative_evidence, "no_change.evidence")?;
    let mut available: BTreeSet<&str> = input
        .observations
        .iter()
        .map(|record| record.id.as_str())
        .collect();
    if let Some(evaluator) = &input.evaluator {
        available.insert(evaluator.id.as_str());
    }
    available.extend(
        input
            .retry
            .prior_evidence
            .iter()
            .map(eliot_contracts::ArtifactId::as_str),
    );
    if request
        .affirmative_evidence
        .iter()
        .any(|id| !available.contains(id.as_str()))
        || !request
            .affirmative_evidence
            .iter()
            .any(|id| id == request.proof.evidence_id())
    {
        return Err(LearningDeltaError::InvalidNoChangePredicate);
    }
    let Some(evaluator) = input.evaluator.as_ref() else {
        return Err(LearningDeltaError::MissingEvaluator);
    };
    match &request.proof {
        NoChangeProof::ConfirmedFixedPrediction { evaluator: id } => {
            if id != &evaluator.id || evaluator.outcome != input.predicted_outcome {
                return Err(LearningDeltaError::InvalidNoChangePredicate);
            }
        }
        NoChangeProof::ControlledReplicationNeeded { reason, .. } => {
            if !matches!(retry, RetryAssessment::EquivalentAllowed(actual) if actual == *reason)
                || evaluator.outcome != SemanticOutcome::MeasuredUnchanged
            {
                return Err(LearningDeltaError::InvalidNoChangePredicate);
            }
        }
        NoChangeProof::ProtectedConstraint { .. }
        | NoChangeProof::ProvenNonApplicability { .. }
        | NoChangeProof::Contradicted { .. }
        | NoChangeProof::UnsafeCandidate { .. }
        | NoChangeProof::OwnerBlocked { .. }
        | NoChangeProof::ExternalReviewRequired { .. } => {}
    }
    let reason = request.proof.reason();
    let expected = input
        .evaluator_binding
        .as_ref()
        .ok_or(LearningDeltaError::MissingEvaluator)?;
    if !policy.allows_no_change(
        reason,
        &expected.verifier,
        &expected.property,
        &expected.revision,
        evaluator.outcome,
    ) {
        return Err(LearningDeltaError::InvalidNoChangePredicate);
    }
    let mut affirmative = request.affirmative_evidence.clone();
    affirmative.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut disposition = NoChangeDisposition {
        binding: input.binding.clone(),
        attempt_id: input.attempt_id.clone(),
        target: input.target.clone(),
        reason: request.proof.reason(),
        affirmative_evidence: affirmative,
        denominator: request.denominator,
        canonical_digest: String::new(),
    };
    disposition.seal()?;
    disposition.validate()?;
    if digest_without_field(state_view, "canonical_digest")? != state_view.canonical_digest {
        return Err(LearningDeltaError::EvidenceBinding {
            field: "view.digest",
        });
    }
    check_output_size(
        &AttemptLearningOutcome::NoChange(disposition.clone()),
        policy,
    )?;
    Ok(AttemptLearningOutcome::NoChange(disposition))
}

fn check_output_size(
    output: &AttemptLearningOutcome,
    policy: &DerivationPolicy,
) -> Result<(), LearningDeltaError> {
    let mut total = Some(0usize);
    count_serialized(output, &mut total, policy.max_output_bytes, "output")?;
    if total.is_none() {
        return Err(LearningDeltaError::Bound { field: "output" });
    }
    Ok(())
}

fn sorted_ids(ids: &[ArtifactId]) -> Vec<ArtifactId> {
    let mut result = ids.to_vec();
    result.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    result
}

fn surface_key(operation: &eliot_learning_contracts::ChangeOperation) -> &'static str {
    use eliot_learning_contracts::ChangeSurface;
    let surface = match operation {
        eliot_learning_contracts::ChangeOperation::Replace { surface, .. }
        | eliot_learning_contracts::ChangeOperation::Add { surface, .. }
        | eliot_learning_contracts::ChangeOperation::Remove { surface, .. } => surface,
    };
    match surface {
        ChangeSurface::TaskLocalContext => "task_local_context",
        ChangeSurface::Memory => "memory",
        ChangeSurface::Skill => "skill",
        ChangeSurface::Tool => "tool",
        ChangeSurface::Route => "route",
        ChangeSurface::Hypothesis => "hypothesis",
        ChangeSurface::Strategy => "strategy",
        ChangeSurface::Abstraction => "abstraction",
        ChangeSurface::CandidateParent => "candidate_parent",
        ChangeSurface::VerificationOrder => "verification_order",
        ChangeSurface::SearchProbeStopping => "search_probe_stopping",
    }
}
