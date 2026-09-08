//! Deterministic compilation of an immutable recipe-bound learning state view.
//!
//! This package is a pure structural compiler. It consumes exact A-32
//! projections and caller-owned references; it does not read storage, inspect
//! the current system, infer lessons, resolve disagreement, or issue authority.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_contracts::identity::SourceLineage;
use eliot_learning_contracts::{
    CampaignLearningStateView, Completeness, LearningContractError, LearningStateViewRecipe,
    MemberProjection, OmissionPolicy, OwnerDisagreement, SlotDisposition, SlotProjection,
    SlotRequirement, SlotSpec, SourceDenominator,
};

/// Maximum declared slots accepted by this pure compiler.
pub const MAX_SLOTS: usize = 256;
/// Maximum members retained across supplied projections.
pub const MAX_MEMBERS: usize = 4096;
/// Maximum explicit references supplied to one compilation.
pub const MAX_REFERENCES: usize = 256;
/// Maximum evidence handles supplied across one compilation.
pub const MAX_EVIDENCE: usize = 16384;
/// Maximum evidence handles on one slot, member or disagreement.
pub const MAX_RECORD_EVIDENCE: usize = 256;
/// Maximum owners represented by one supplied disagreement.
pub const MAX_DISAGREEMENT_OWNERS: usize = 256;
/// Maximum bytes in a free-form recipe/projection label handled here.
pub const MAX_LABEL_BYTES: usize = 8192;
/// Maximum aggregate input text inspected by this bounded compiler.
pub const MAX_INPUT_TEXT_BYTES: usize = 1_048_576;

/// Compile exact A-32 owner projections into one immutable candidate view.
///
/// Recipe order and each slot's declared member order remain semantic. The
/// caller supplies view identity, required references and disagreements exactly;
/// this function does not derive or replace them. The richer invalidation
/// metadata described by later architecture sections is deferred because the
/// current A-32 view has no typed input for it.
pub fn compile_campaign_learning_state_view(
    recipe: &LearningStateViewRecipe,
    projections: &[SlotProjection],
    state_fence: &StateFence,
    required_references: &[ArtifactId],
    view_id: &ArtifactId,
    supplied_disagreements: &[OwnerDisagreement],
) -> Result<CampaignLearningStateView, LearningContractError> {
    bound_input_sizes(
        recipe,
        projections,
        required_references,
        supplied_disagreements,
        view_id,
    )?;
    recipe.validate()?;
    validate_dependency_graph(recipe)?;
    state_fence
        .validate()
        .map_err(|_| LearningContractError::Foundation)?;
    if state_fence != &recipe.binding.state_fence {
        return Err(LearningContractError::ScopeMismatch {
            field: "compile.state_fence",
        });
    }
    if view_id.as_str().trim().is_empty() {
        return Err(LearningContractError::Missing { field: "view_id" });
    }
    validate_references(required_references)?;
    validate_disagreements(recipe, supplied_disagreements)?;
    validate_shared_lineage(projections)?;

    let recipe_by_id: BTreeMap<_, _> = recipe
        .slots
        .iter()
        .map(|slot| (slot.slot_id.as_str(), slot))
        .collect();
    let mut by_slot = BTreeMap::new();
    for projection in projections {
        projection.validate()?;
        let spec = recipe_by_id.get(projection.slot_id.as_str()).ok_or(
            LearningContractError::ScopeMismatch {
                field: "projection.slot_id",
            },
        )?;
        if by_slot
            .insert(projection.slot_id.as_str(), projection)
            .is_some()
        {
            return Err(LearningContractError::Duplicate {
                field: "projections.slot_id",
            });
        }
        validate_projection_against_spec(projection, spec)?;
    }

    let mut slots = Vec::with_capacity(recipe.slots.len());
    let mut omissions = Vec::new();
    let mut frontier = Vec::new();
    for spec in &recipe.slots {
        if let Some(projection) = by_slot.get(spec.slot_id.as_str()) {
            slots.push(canonical_slot_projection(projection, spec)?);
        } else {
            match (&spec.requirement, recipe.omission_policy) {
                (SlotRequirement::Optional, OmissionPolicy::RequiredSlots) => {
                    omissions.push(spec.slot_id.clone());
                }
                (_, OmissionPolicy::ExplicitFrontier) => frontier.push(spec.slot_id.clone()),
                (SlotRequirement::Required | SlotRequirement::Conditional { .. }, _) => {
                    return Err(LearningContractError::IncompleteCoverage);
                }
            }
        }
    }

    let completeness = classify_completeness(recipe, &slots, &frontier);
    let mut references = required_references.to_vec();
    references.sort_by(|left, right| left.as_str().cmp(right.as_str()));

    let mut view = CampaignLearningStateView {
        view_id: view_id.clone(),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target: recipe.target.clone(),
        binding: recipe.binding.clone(),
        recipe_digest: recipe.canonical_digest.clone(),
        slots,
        denominator: SourceDenominator {
            declared: u32::try_from(recipe.slots.len()).map_err(|_| {
                LearningContractError::Bound {
                    field: "recipe.slots",
                }
            })?,
            observed: 0,
        },
        completeness,
        omissions,
        frontier,
        owner_disagreements: canonical_disagreements(supplied_disagreements),
        required_references: references,
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    view.denominator.observed =
        u32::try_from(view.slots.len()).map_err(|_| LearningContractError::Bound {
            field: "view.slots",
        })?;
    view.seal()?;
    view.validate_against(recipe)?;
    Ok(view)
}

#[allow(clippy::too_many_lines)]
fn bound_input_sizes(
    recipe: &LearningStateViewRecipe,
    projections: &[SlotProjection],
    required_references: &[ArtifactId],
    disagreements: &[OwnerDisagreement],
    view_id: &ArtifactId,
) -> Result<(), LearningContractError> {
    let mut text_bytes = 0usize;
    let mut add_text = |value: &str, field: &'static str| {
        check_label(value, field)?;
        text_bytes = text_bytes
            .checked_add(value.len())
            .ok_or(LearningContractError::Bound {
                field: "input.text",
            })?;
        if text_bytes > MAX_INPUT_TEXT_BYTES {
            return Err(LearningContractError::Bound {
                field: "input.text",
            });
        }
        Ok(())
    };
    if recipe.slots.len() > MAX_SLOTS {
        return Err(LearningContractError::Bound {
            field: "recipe.slots",
        });
    }
    if projections.len() > MAX_SLOTS {
        return Err(LearningContractError::Bound {
            field: "projections",
        });
    }
    if required_references.len() > MAX_REFERENCES {
        return Err(LearningContractError::Bound {
            field: "required_references",
        });
    }
    if disagreements.len() > MAX_SLOTS {
        return Err(LearningContractError::Bound {
            field: "owner_disagreements",
        });
    }
    add_text(recipe.recipe_id.as_str(), "recipe.recipe_id")?;
    add_text(recipe.campaign_id.as_str(), "recipe.campaign_id")?;
    add_text(recipe.target.as_str(), "recipe.target")?;
    add_text(recipe.binding.request_id.as_str(), "binding.request_id")?;
    add_text(recipe.binding.operation_id.as_str(), "binding.operation_id")?;
    add_text(recipe.binding.product_id.as_str(), "binding.product_id")?;
    add_text(recipe.binding.task_id.as_str(), "binding.task_id")?;
    add_text(recipe.binding.scope.as_str(), "binding.scope")?;
    add_text(recipe.binding.source.owner.as_str(), "binding.source.owner")?;
    add_text(
        recipe.binding.source.snapshot.as_str(),
        "binding.source.snapshot",
    )?;
    add_text(
        recipe.binding.source.digest.as_str(),
        "binding.source.digest",
    )?;
    add_text(recipe.privacy_class.as_str(), "recipe.privacy_class")?;
    add_text(recipe.canonical_digest.as_str(), "recipe.canonical_digest")?;
    add_text(view_id.as_str(), "view_id")?;
    let mut member_count = 0usize;
    let mut evidence_count = 0usize;
    for slot in &recipe.slots {
        if slot.declared_members.len() > 256 {
            return Err(LearningContractError::Bound {
                field: "slot.declared_members",
            });
        }
        check_label(slot.accepted_type.as_str(), "slot.accepted_type")?;
        add_text(slot.slot_id.as_str(), "slot.slot_id")?;
        add_text(slot.owner.as_str(), "slot.owner")?;
        add_text(slot.target.as_str(), "slot.target")?;
        add_text(slot.accepted_type.as_str(), "slot.accepted_type")?;
        add_text(slot.schema_digest.as_str(), "slot.schema_digest")?;
        member_count = member_count
            .checked_add(slot.declared_members.len())
            .ok_or(LearningContractError::Bound {
                field: "recipe.declared_members",
            })?;
        if member_count > MAX_MEMBERS {
            return Err(LearningContractError::Bound {
                field: "recipe.declared_members",
            });
        }
        for member in &slot.declared_members {
            add_text(member.as_str(), "slot.declared_members")?;
        }
    }
    for projection in projections {
        if projection.members.len() > 256 || projection.evidence.len() > MAX_RECORD_EVIDENCE {
            return Err(LearningContractError::Bound {
                field: "projection.record",
            });
        }
        add_text(projection.slot_id.as_str(), "projection.slot_id")?;
        member_count = member_count.checked_add(projection.members.len()).ok_or(
            LearningContractError::Bound {
                field: "projections.members",
            },
        )?;
        if member_count > MAX_MEMBERS {
            return Err(LearningContractError::Bound {
                field: "projections.members",
            });
        }
        evidence_count = evidence_count
            .checked_add(projection.evidence.len())
            .ok_or(LearningContractError::Bound {
                field: "projections.evidence",
            })?;
        if evidence_count > MAX_EVIDENCE {
            return Err(LearningContractError::Bound {
                field: "projections.evidence",
            });
        }
        for evidence in &projection.evidence {
            add_text(evidence.as_str(), "projection.evidence")?;
        }
        for member in &projection.members {
            if member.evidence.len() > MAX_RECORD_EVIDENCE {
                return Err(LearningContractError::Bound {
                    field: "member.evidence",
                });
            }
            add_text(member.member_id.as_str(), "member.member_id")?;
            add_text(member.owner.as_str(), "member.owner")?;
            add_text(member.source.owner.as_str(), "member.source.owner")?;
            add_text(member.source.snapshot.as_str(), "member.source.snapshot")?;
            add_text(member.source.digest.as_str(), "member.source.digest")?;
            if let Some(value) = &member.value_digest {
                add_text(value.as_str(), "member.value_digest")?;
            }
            evidence_count = evidence_count.checked_add(member.evidence.len()).ok_or(
                LearningContractError::Bound {
                    field: "projections.member_evidence",
                },
            )?;
            if evidence_count > MAX_EVIDENCE {
                return Err(LearningContractError::Bound {
                    field: "projections.member_evidence",
                });
            }
            for evidence in &member.evidence {
                add_text(evidence.as_str(), "member.evidence")?;
            }
        }
    }
    for reference in required_references {
        add_text(reference.as_str(), "required_references")?;
    }
    for disagreement in disagreements {
        add_text(disagreement.slot_id.as_str(), "disagreement.slot_id")?;
        if disagreement.owners.len() > MAX_DISAGREEMENT_OWNERS
            || disagreement.evidence.len() > MAX_RECORD_EVIDENCE
        {
            return Err(LearningContractError::Bound {
                field: "owner_disagreement.record",
            });
        }
        for owner in &disagreement.owners {
            add_text(owner.as_str(), "disagreement.owners")?;
        }
        for evidence in &disagreement.evidence {
            add_text(evidence.as_str(), "disagreement.evidence")?;
        }
    }
    if member_count > MAX_MEMBERS {
        return Err(LearningContractError::Bound {
            field: "projections.members",
        });
    }
    if evidence_count > MAX_EVIDENCE {
        return Err(LearningContractError::Bound {
            field: "projections.evidence",
        });
    }
    Ok(())
}

fn check_label(value: &str, field: &'static str) -> Result<(), LearningContractError> {
    if value.len() > MAX_LABEL_BYTES {
        Err(LearningContractError::Bound { field })
    } else {
        Ok(())
    }
}

fn validate_references(references: &[ArtifactId]) -> Result<(), LearningContractError> {
    let mut seen = BTreeSet::new();
    for reference in references {
        if reference.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "required_references",
            });
        }
        if !seen.insert(reference.as_str()) {
            return Err(LearningContractError::Duplicate {
                field: "required_references",
            });
        }
    }
    Ok(())
}

fn validate_dependency_graph(
    recipe: &LearningStateViewRecipe,
) -> Result<(), LearningContractError> {
    let by_id: BTreeMap<_, _> = recipe
        .slots
        .iter()
        .map(|slot| (slot.slot_id.as_str(), slot))
        .collect();
    for start in &recipe.slots {
        let mut visited = BTreeSet::new();
        let mut current = start;
        loop {
            if !visited.insert(current.slot_id.as_str()) {
                return Err(LearningContractError::ScopeMismatch {
                    field: "recipe.dependencies",
                });
            }
            let SlotRequirement::Conditional { depends_on } = &current.requirement else {
                break;
            };
            current =
                by_id
                    .get(depends_on.as_str())
                    .ok_or(LearningContractError::ScopeMismatch {
                        field: "recipe.dependencies",
                    })?;
        }
    }
    Ok(())
}

fn validate_disagreements(
    recipe: &LearningStateViewRecipe,
    disagreements: &[OwnerDisagreement],
) -> Result<(), LearningContractError> {
    let mut seen = BTreeSet::new();
    for disagreement in disagreements {
        disagreement.validate()?;
        if !seen.insert(disagreement.slot_id.as_str()) {
            return Err(LearningContractError::Duplicate {
                field: "owner_disagreements.slot_id",
            });
        }
        if recipe_slot(recipe, &disagreement.slot_id).is_err() {
            return Err(LearningContractError::ScopeMismatch {
                field: "owner_disagreements.slot_id",
            });
        }
    }
    Ok(())
}

fn validate_projection_against_spec(
    projection: &SlotProjection,
    spec: &SlotSpec,
) -> Result<(), LearningContractError> {
    let declared: BTreeSet<_> = spec
        .declared_members
        .iter()
        .map(eliot_learning_contracts::MemberId::as_str)
        .collect();
    let observed: BTreeSet<_> = projection
        .members
        .iter()
        .map(|member| member.member_id.as_str())
        .collect();
    if declared != observed {
        return Err(LearningContractError::IncompleteCoverage);
    }
    if projection.disposition == SlotDisposition::KnownEmpty && !projection.members.is_empty() {
        return Err(LearningContractError::IncompleteCoverage);
    }
    for member in &projection.members {
        if member.owner != spec.owner {
            return Err(LearningContractError::ScopeMismatch {
                field: "member.owner",
            });
        }
    }
    if projection.disposition == SlotDisposition::Current
        && projection
            .members
            .iter()
            .any(|member| member.disposition != SlotDisposition::Current)
    {
        return Err(LearningContractError::IncompleteCoverage);
    }
    if projection.disposition == SlotDisposition::KnownEmpty && projection.evidence.is_empty() {
        return Err(LearningContractError::MissingOwnerEvidence {
            field: "projection.known_empty",
        });
    }
    Ok(())
}

fn validate_shared_lineage(projections: &[SlotProjection]) -> Result<(), LearningContractError> {
    let mut source_lineage: BTreeMap<(&str, &str), &SourceLineage> = BTreeMap::new();
    for projection in projections {
        for member in &projection.members {
            let key = (
                member.source.owner.as_str(),
                member.source.snapshot.as_str(),
            );
            if let Some(previous) = source_lineage.insert(key, &member.source)
                && previous != &member.source
            {
                return Err(LearningContractError::ScopeMismatch {
                    field: "member.source",
                });
            }
        }
    }
    Ok(())
}

fn canonical_slot_projection(
    projection: &SlotProjection,
    spec: &SlotSpec,
) -> Result<SlotProjection, LearningContractError> {
    let mut members_by_id: BTreeMap<&str, &MemberProjection> = BTreeMap::new();
    for member in &projection.members {
        if members_by_id
            .insert(member.member_id.as_str(), member)
            .is_some()
        {
            return Err(LearningContractError::Duplicate {
                field: "projection.members",
            });
        }
    }
    let mut members = Vec::with_capacity(spec.declared_members.len());
    for member_id in &spec.declared_members {
        let member = members_by_id
            .remove(member_id.as_str())
            .ok_or(LearningContractError::IncompleteCoverage)?;
        let mut member = (*member).clone();
        member
            .evidence
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        members.push(member);
    }
    if !members_by_id.is_empty() {
        return Err(LearningContractError::IncompleteCoverage);
    }
    let mut evidence = projection.evidence.clone();
    evidence.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    Ok(SlotProjection {
        slot_id: projection.slot_id.clone(),
        disposition: projection.disposition,
        members,
        evidence,
    })
}

fn canonical_disagreements(disagreements: &[OwnerDisagreement]) -> Vec<OwnerDisagreement> {
    let mut result = disagreements.to_vec();
    result.sort_by(|left, right| left.slot_id.as_str().cmp(right.slot_id.as_str()));
    for disagreement in &mut result {
        disagreement
            .owners
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        disagreement
            .evidence
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
    }
    result
}

fn recipe_slot<'a>(
    recipe: &'a LearningStateViewRecipe,
    id: &eliot_learning_contracts::SlotId,
) -> Result<&'a SlotSpec, LearningContractError> {
    recipe
        .slots
        .iter()
        .find(|slot| slot.slot_id == *id)
        .ok_or(LearningContractError::ScopeMismatch { field: "slot_id" })
}

fn classify_completeness(
    recipe: &LearningStateViewRecipe,
    slots: &[SlotProjection],
    frontier: &[eliot_learning_contracts::SlotId],
) -> Completeness {
    let mut blocked = false;
    let mut stale = false;
    let mut partial = !frontier.is_empty();
    let mut required_ids = BTreeSet::new();
    for spec in &recipe.slots {
        if !matches!(spec.requirement, SlotRequirement::Optional) {
            required_ids.insert(spec.slot_id.as_str());
        }
        if let SlotRequirement::Conditional { depends_on } = &spec.requirement {
            required_ids.insert(depends_on.as_str());
        }
    }
    for spec in &recipe.slots {
        if !required_ids.contains(spec.slot_id.as_str()) {
            continue;
        }
        let Some(slot) = slots
            .iter()
            .find(|candidate| candidate.slot_id == spec.slot_id)
        else {
            partial = true;
            continue;
        };
        match slot.disposition {
            SlotDisposition::Blocked | SlotDisposition::Unavailable => blocked = true,
            SlotDisposition::Stale => stale = true,
            SlotDisposition::Current => {}
            SlotDisposition::KnownEmpty => {
                if !slot.evidence.is_empty() && spec.declared_members.is_empty() {
                    // An explicitly evidenced empty owner projection is ready.
                } else {
                    partial = true;
                }
            }
            SlotDisposition::Historical
            | SlotDisposition::Superseded
            | SlotDisposition::Unknown
            | SlotDisposition::Conflicted => partial = true,
        }
        for member in &slot.members {
            match member.disposition {
                SlotDisposition::Blocked | SlotDisposition::Unavailable => blocked = true,
                SlotDisposition::Stale => stale = true,
                SlotDisposition::Current => {}
                SlotDisposition::Historical
                | SlotDisposition::Superseded
                | SlotDisposition::Unknown
                | SlotDisposition::Conflicted
                | SlotDisposition::KnownEmpty => partial = true,
            }
        }
    }
    if blocked {
        Completeness::Blocked
    } else if stale {
        Completeness::Stale
    } else if partial {
        Completeness::Partial
    } else {
        Completeness::CompleteForDeclaredRecipe
    }
}
