use eliot_learning_contracts::delta::EquivalentRetry;
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, ChangeOperation, MemberProjection, OwnerDisagreement,
    SlotProjection,
};

use crate::{
    MAX_CHANGES, MAX_DELTAS, MAX_INPUT_TEXT_BYTES, MAX_OUTPUT_BYTES, MAX_REFERENCES,
    MAX_WORK_UNITS, OverlayComposeInput, OverlayError,
};

const JSON_ESCAPE_FACTOR: usize = 6;
const RECORD_OVERHEAD: usize = 1024;

#[derive(Default)]
struct Budget {
    text: usize,
    references: usize,
    work: usize,
}

impl Budget {
    fn text(&mut self, value: &str, field: &'static str) -> Result<(), OverlayError> {
        if value.len() > 8192 {
            return Err(OverlayError::Bound { field });
        }
        self.text = self
            .text
            .checked_add(value.len())
            .ok_or(OverlayError::Bound {
                field: "input.text",
            })?;
        if self.text > MAX_INPUT_TEXT_BYTES {
            return Err(OverlayError::Bound {
                field: "input.text",
            });
        }
        Ok(())
    }

    fn refs(&mut self, count: usize, field: &'static str) -> Result<(), OverlayError> {
        self.references = self
            .references
            .checked_add(count)
            .ok_or(OverlayError::Bound { field })?;
        if self.references > MAX_REFERENCES {
            return Err(OverlayError::Bound { field });
        }
        Ok(())
    }

    fn work(&mut self, count: usize) -> Result<(), OverlayError> {
        self.work = self.work.checked_add(count).ok_or(OverlayError::Bound {
            field: "input.work",
        })?;
        if self.work > MAX_WORK_UNITS {
            return Err(OverlayError::Bound {
                field: "input.work",
            });
        }
        Ok(())
    }
}

pub(crate) fn preflight(input: &OverlayComposeInput<'_>) -> Result<(), OverlayError> {
    let mut budget = Budget::default();
    if input.deltas.is_empty() || input.deltas.len() > MAX_DELTAS {
        return Err(OverlayError::Bound { field: "deltas" });
    }
    if input.admitted.len() != input.deltas.len() {
        return Err(OverlayError::Conflict { field: "admitted" });
    }
    let change_count = input.deltas.iter().try_fold(0usize, |total, delta| {
        total
            .checked_add(delta.changes.len())
            .ok_or(OverlayError::Bound {
                field: "deltas.changes",
            })
    })?;
    if change_count > MAX_CHANGES {
        return Err(OverlayError::Bound {
            field: "deltas.changes",
        });
    }
    budget.text(
        input.protected_surface_base_digest,
        "protected_surface_base_digest",
    )?;
    budget.text(
        input.protected_surface_proposed_digest,
        "protected_surface_proposed_digest",
    )?;
    budget.text(
        input.fixed_before_observation_discriminator.as_str(),
        "discriminator",
    )?;
    budget.text(input.overlay_id.as_str(), "overlay_id")?;
    bound_recipe(input.recipe, &mut budget)?;
    bound_view(input.view, &mut budget)?;
    for delta in input.deltas {
        bound_delta(delta, &mut budget)?;
    }
    for pair in input.admitted {
        budget.text(pair.delta_id.as_str(), "admitted.delta_id")?;
        budget.text(&pair.canonical_digest, "admitted.canonical_digest")?;
    }
    budget.work(
        input
            .deltas
            .len()
            .checked_mul(change_count.checked_add(1).ok_or(OverlayError::Bound {
                field: "input.work",
            })?)
            .ok_or(OverlayError::Bound {
                field: "input.work",
            })?,
    )?;
    // JSON may escape one UTF-8 byte into six output bytes. Emitted changes
    // repeat target/value material and structural fields, so reserve a
    // checked worst-case record envelope before cloning/sealing.
    let escaped_text = budget
        .text
        .checked_mul(JSON_ESCAPE_FACTOR)
        .ok_or(OverlayError::Bound {
            field: "output.bytes",
        })?;
    let records = change_count
        .checked_mul(4)
        .and_then(|count| count.checked_add(input.deltas.len().checked_mul(3)?))
        .and_then(|count| count.checked_add(input.admitted.len().checked_mul(2)?))
        .ok_or(OverlayError::Bound {
            field: "output.bytes",
        })?;
    let structural = records
        .checked_mul(RECORD_OVERHEAD)
        .ok_or(OverlayError::Bound {
            field: "output.bytes",
        })?;
    let output_estimate = escaped_text
        .checked_add(structural)
        .ok_or(OverlayError::Bound {
            field: "output.bytes",
        })?;
    if output_estimate > MAX_OUTPUT_BYTES {
        return Err(OverlayError::Bound {
            field: "output.bytes",
        });
    }
    Ok(())
}

fn bound_recipe(
    recipe: &eliot_learning_contracts::LearningStateViewRecipe,
    b: &mut Budget,
) -> Result<(), OverlayError> {
    b.text(recipe.recipe_id.as_str(), "recipe.recipe_id")?;
    b.text(recipe.campaign_id.as_str(), "recipe.campaign_id")?;
    b.text(recipe.target.as_str(), "recipe.target")?;
    b.text(&recipe.canonical_digest, "recipe.canonical_digest")?;
    b.text(&recipe.privacy_class, "recipe.privacy_class")?;
    if recipe.slots.len() > 256 {
        return Err(OverlayError::Bound {
            field: "recipe.slots",
        });
    }
    b.refs(recipe.slots.len(), "recipe.slots")?;
    for slot in &recipe.slots {
        b.text(slot.slot_id.as_str(), "slot.slot_id")?;
        b.text(slot.owner.as_str(), "slot.owner")?;
        b.text(slot.target.as_str(), "slot.target")?;
        b.text(&slot.accepted_type, "slot.accepted_type")?;
        b.text(&slot.schema_digest, "slot.schema_digest")?;
        b.refs(slot.declared_members.len(), "slot.members")?;
        for member in &slot.declared_members {
            b.text(member.as_str(), "slot.member")?;
        }
        if let eliot_learning_contracts::SlotRequirement::Conditional { depends_on } =
            &slot.requirement
        {
            b.text(depends_on.as_str(), "slot.depends_on")?;
        }
    }
    bound_binding(&recipe.binding, b)
}

fn bound_view(
    view: &eliot_learning_contracts::CampaignLearningStateView,
    b: &mut Budget,
) -> Result<(), OverlayError> {
    b.text(view.view_id.as_str(), "view.view_id")?;
    b.text(view.recipe_id.as_str(), "view.recipe_id")?;
    b.text(view.campaign_id.as_str(), "view.campaign_id")?;
    b.text(view.target.as_str(), "view.target")?;
    b.text(&view.recipe_digest, "view.recipe_digest")?;
    b.text(&view.canonical_digest, "view.canonical_digest")?;
    if let Some(reason) = &view.invalidation_reason {
        b.text(reason, "view.invalidation_reason")?;
    }
    b.refs(view.slots.len(), "view.slots")?;
    b.refs(
        view.omissions
            .len()
            .checked_add(view.frontier.len())
            .and_then(|n| n.checked_add(view.required_references.len()))
            .ok_or(OverlayError::Bound {
                field: "view.references",
            })?,
        "view.references",
    )?;
    b.refs(view.owner_disagreements.len(), "view.owner_disagreements")?;
    for slot in &view.slots {
        bound_slot(slot, b)?;
    }
    for id in &view.omissions {
        b.text(id.as_str(), "view.omission")?;
    }
    for id in &view.frontier {
        b.text(id.as_str(), "view.frontier")?;
    }
    for id in &view.required_references {
        b.text(id.as_str(), "view.reference")?;
    }
    for disagreement in &view.owner_disagreements {
        bound_disagreement(disagreement, b)?;
    }
    bound_binding(&view.binding, b)
}

fn bound_slot(slot: &SlotProjection, b: &mut Budget) -> Result<(), OverlayError> {
    b.text(slot.slot_id.as_str(), "projection.slot_id")?;
    b.refs(
        slot.members
            .len()
            .checked_add(slot.evidence.len())
            .ok_or(OverlayError::Bound {
                field: "projection.members",
            })?,
        "projection.members",
    )?;
    for id in &slot.evidence {
        b.text(id.as_str(), "projection.evidence")?;
    }
    for member in &slot.members {
        bound_member(member, b)?;
    }
    Ok(())
}

fn bound_member(member: &MemberProjection, b: &mut Budget) -> Result<(), OverlayError> {
    b.text(member.member_id.as_str(), "member.id")?;
    b.text(member.owner.as_str(), "member.owner")?;
    b.text(member.source.owner.as_str(), "member.source.owner")?;
    b.text(member.source.snapshot.as_str(), "member.source.snapshot")?;
    b.text(&member.source.digest, "member.source.digest")?;
    if let Some(value) = &member.value_digest {
        b.text(value, "member.value_digest")?;
    }
    b.refs(member.evidence.len(), "member.evidence")?;
    for id in &member.evidence {
        b.text(id.as_str(), "member.evidence")?;
    }
    Ok(())
}

fn bound_disagreement(value: &OwnerDisagreement, b: &mut Budget) -> Result<(), OverlayError> {
    b.text(value.slot_id.as_str(), "disagreement.slot_id")?;
    b.refs(
        value
            .owners
            .len()
            .checked_add(value.evidence.len())
            .ok_or(OverlayError::Bound {
                field: "disagreement",
            })?,
        "disagreement",
    )?;
    for owner in &value.owners {
        b.text(owner.as_str(), "disagreement.owner")?;
    }
    for id in &value.evidence {
        b.text(id.as_str(), "disagreement.evidence")?;
    }
    Ok(())
}

fn bound_delta(delta: &AttemptLearningDeltaCandidate, b: &mut Budget) -> Result<(), OverlayError> {
    bound_binding(&delta.binding, b)?;
    b.text(delta.attempt_id.as_str(), "delta.attempt_id")?;
    b.text(delta.delta_id.as_str(), "delta.delta_id")?;
    b.text(delta.target.as_str(), "delta.target")?;
    b.text(&delta.base_view_digest, "delta.base_view_digest")?;
    b.text(
        delta.pre_observation_discriminator.as_str(),
        "delta.discriminator",
    )?;
    b.text(delta.intended_strategy.as_str(), "delta.intended_strategy")?;
    b.text(
        delta.attempted_strategy.as_str(),
        "delta.attempted_strategy",
    )?;
    if delta.changes.is_empty() || delta.changes.len() > MAX_CHANGES {
        return Err(OverlayError::Bound {
            field: "delta.changes",
        });
    }
    let reference_count = delta
        .changes
        .len()
        .checked_add(delta.inverses.len())
        .and_then(|n| n.checked_add(delta.evidence.len()))
        .and_then(|n| n.checked_add(delta.evaluator_receipts.len()))
        .and_then(|n| n.checked_add(delta.baseline.len()))
        .and_then(|n| n.checked_add(delta.control.len()))
        .and_then(|n| n.checked_add(delta.confounders.len()))
        .and_then(|n| n.checked_add(delta.dependencies.len()))
        .ok_or(OverlayError::Bound {
            field: "delta.references",
        })?;
    b.refs(reference_count, "delta.references")?;
    for change in &delta.changes {
        bound_change(change, b)?;
    }
    for inverse in &delta.inverses {
        b.text(inverse.forward_target.as_str(), "inverse.target")?;
        bound_change(&inverse.inverse, b)?;
    }
    for ids in [
        &delta.evidence,
        &delta.evaluator_receipts,
        &delta.baseline,
        &delta.control,
        &delta.confounders,
        &delta.dependencies,
    ] {
        for id in ids {
            b.text(id.as_str(), "delta.reference")?;
        }
    }
    if let Some(retry) = &delta.equivalent_retry {
        bound_retry(retry, b)?;
    }
    b.text(&delta.canonical_digest, "delta.canonical_digest")
}

fn bound_change(change: &ChangeOperation, b: &mut Budget) -> Result<(), OverlayError> {
    b.text(change.target().as_str(), "change.target")?;
    match change {
        ChangeOperation::Replace { before, after, .. } => {
            bound_state(before, b)?;
            bound_state(after, b)?;
        }
        ChangeOperation::Add { after, .. } | ChangeOperation::Remove { before: after, .. } => {
            bound_state(after, b)?;
        }
    }
    Ok(())
}

fn bound_state(
    state: &eliot_learning_contracts::ValueState,
    b: &mut Budget,
) -> Result<(), OverlayError> {
    if let Some(digest) = &state.digest {
        b.text(digest, "change.value")?;
    }
    Ok(())
}

fn bound_retry(retry: &EquivalentRetry, b: &mut Budget) -> Result<(), OverlayError> {
    b.text(retry.prior_attempt.as_str(), "retry.attempt")?;
    b.text(&retry.strategy_fingerprint, "retry.strategy")?;
    b.text(&retry.reason, "retry.reason")?;
    b.refs(retry.evidence.len(), "retry.evidence")?;
    for id in &retry.evidence {
        b.text(id.as_str(), "retry.evidence")?;
    }
    Ok(())
}

fn bound_binding(
    binding: &eliot_learning_contracts::ContractBinding,
    b: &mut Budget,
) -> Result<(), OverlayError> {
    b.text(binding.request_id.as_str(), "binding.request_id")?;
    b.text(binding.operation_id.as_str(), "binding.operation_id")?;
    b.text(binding.product_id.as_str(), "binding.product_id")?;
    b.text(binding.task_id.as_str(), "binding.task_id")?;
    b.text(binding.scope.as_str(), "binding.scope")?;
    b.text(binding.source.owner.as_str(), "binding.source.owner")?;
    b.text(binding.source.snapshot.as_str(), "binding.source.snapshot")?;
    b.text(&binding.source.digest, "binding.source.digest")
}
