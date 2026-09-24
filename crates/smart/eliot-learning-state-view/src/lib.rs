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
    CampaignHistoryPlanReference, CampaignLearningStateView, CampaignPositionKind,
    CampaignPositionRef, CampaignSourceResolution, CampaignSourceResolutionStatus,
    CampaignSourceRevisionRef, CampaignViewRebuildReason, Completeness, LearningContractError,
    LearningStateViewRecipe, MemberProjection, OmissionPolicy, OwnerDisagreement, SlotDisposition,
    SlotProjection, SlotRequirement, SlotSpec, SourceDenominator,
};
use eliot_reactive_context_plan::{CampaignIntent, RetrievalPlan};

/// Maximum declared slots accepted by this pure compiler.
pub const MAX_SLOTS: usize = 256;
/// Maximum members retained across supplied projections.
pub const MAX_MEMBERS: usize = 4096;
/// Maximum explicit references supplied to one compilation.
pub const MAX_REFERENCES: usize = 256;
/// Maximum existing campaign retrieval plans retained by one view.
pub const MAX_HISTORY_PLANS: usize = 64;
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

/// One existing compiled campaign-scoped retrieval plan and only the bounded
/// handles/digests selected through it.
pub struct CampaignHistoryPlanInput<'a> {
    /// Validated existing campaign-scoped plan; never caller-authored labels.
    pub plan: &'a RetrievalPlan,
    /// Bounded result handles selected under the plan.
    pub selected_handles: Vec<ArtifactId>,
    /// Digest of a bounded summary, when returned.
    pub summary_digest: Option<String>,
    /// Digests of bounded diffs, when returned.
    pub diff_digests: Vec<String>,
    /// Handles of policy-permitted bounded slices.
    pub policy_slice_handles: Vec<ArtifactId>,
}

/// Complete pure-compiler input. Owner reads and the runtime clock are
/// supplied by the authenticated caller; this API performs no I/O.
#[derive(Clone, Copy)]
pub struct CampaignLearningStateCompilationInput<'a> {
    /// Frozen recipe and persisted source-reference manifest.
    pub recipe: &'a LearningStateViewRecipe,
    /// Exact A-32 projections for declared recipe slots.
    pub projections: &'a [SlotProjection],
    /// Authenticated current task fence used for all named owner reads.
    pub current_state_fence: &'a StateFence,
    /// One exact resolution outcome per closed source role.
    pub source_resolutions: &'a [CampaignSourceResolution],
    /// Objective, acceptance, evaluator and context artifact handles.
    pub required_references: &'a [ArtifactId],
    /// Owner disagreements retained without resolution.
    pub disagreements: &'a [OwnerDisagreement],
    /// Progress positions tied to resolved source revisions.
    pub positions: &'a [CampaignPositionRef],
    /// Full-content digest of the current frozen anchor owner record.
    pub frozen_anchor_digest: &'a str,
    /// Actual existing `RetrievalPlans` and their bounded results.
    pub history_plans: &'a [CampaignHistoryPlanInput<'a>],
    /// Runtime clock's generation time in milliseconds.
    pub generated_at_ms: i64,
    /// Runtime clock's expiration boundary in milliseconds, if configured.
    pub expires_at_ms: Option<i64>,
    /// Typed reason a prior immutable view was rebuilt.
    pub rebuild_reason: Option<CampaignViewRebuildReason>,
}

/// Compile exact owner projections and provenance into an immutable view.
///
/// Recipe order and each slot's declared member order remain semantic. The
/// owner reads, exact task fence, and runtime timestamp come from the
/// authenticated caller; this pure function validates but never reads or
/// fabricates an owner record. Its id is derived from the complete content.
pub fn compile_campaign_learning_state_view(
    input: CampaignLearningStateCompilationInput<'_>,
) -> Result<CampaignLearningStateView, LearningContractError> {
    validate_compilation_input(&input)?;
    let compiled = compile_slots(input.recipe, input.projections, input.source_resolutions)?;
    build_compiled_view(&input, compiled)
}

struct CompiledSlots {
    slots: Vec<SlotProjection>,
    omissions: Vec<eliot_learning_contracts::SlotId>,
    frontier: Vec<eliot_learning_contracts::SlotId>,
}

fn validate_compilation_input(
    input: &CampaignLearningStateCompilationInput<'_>,
) -> Result<(), LearningContractError> {
    bound_input_sizes(input)?;
    input.recipe.validate()?;
    validate_dependency_graph(input.recipe)?;
    input
        .current_state_fence
        .validate()
        .map_err(|_| LearningContractError::Foundation)?;
    if input.current_state_fence != &input.recipe.binding.state_fence {
        return Err(LearningContractError::ScopeMismatch {
            field: "compile.state_fence",
        });
    }
    validate_references(input.required_references)?;
    validate_disagreements(input.recipe, input.disagreements)?;
    validate_shared_lineage(input.projections)?;
    validate_history_plan_inputs(input.recipe, input.current_state_fence, input.history_plans)
}

fn compile_slots(
    recipe: &LearningStateViewRecipe,
    projections: &[SlotProjection],
    source_resolutions: &[eliot_learning_contracts::CampaignSourceResolution],
) -> Result<CompiledSlots, LearningContractError> {
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
    partition_compiled_slots(recipe, &by_slot, source_resolutions)
}

fn partition_compiled_slots<'projection>(
    recipe: &LearningStateViewRecipe,
    by_slot: &BTreeMap<&'projection str, &'projection SlotProjection>,
    source_resolutions: &[eliot_learning_contracts::CampaignSourceResolution],
) -> Result<CompiledSlots, LearningContractError> {
    let mut compiled = CompiledSlots {
        slots: Vec::with_capacity(recipe.slots.len()),
        omissions: Vec::new(),
        frontier: Vec::new(),
    };
    for spec in &recipe.slots {
        if let Some(projection) = by_slot.get(spec.slot_id.as_str()) {
            compiled
                .slots
                .push(canonical_slot_projection(projection, spec)?);
        } else {
            match (&spec.requirement, recipe.omission_policy) {
                (SlotRequirement::Optional, OmissionPolicy::RequiredSlots) => {
                    compiled.omissions.push(spec.slot_id.clone());
                }
                (_, OmissionPolicy::ExplicitFrontier) => {
                    compiled.frontier.push(spec.slot_id.clone());
                }
                (
                    SlotRequirement::Required | SlotRequirement::Conditional { .. },
                    OmissionPolicy::RequiredSlots,
                ) => {
                    let source_resolution = source_resolutions
                        .iter()
                        .find(|resolution| resolution.role == spec.source_role)
                        .ok_or(LearningContractError::IncompleteCoverage)?;
                    if source_resolution.status
                        == eliot_learning_contracts::CampaignSourceResolutionStatus::Current
                    {
                        return Err(LearningContractError::IncompleteCoverage);
                    }
                    compiled.frontier.push(spec.slot_id.clone());
                }
            }
        }
    }
    Ok(compiled)
}

fn build_compiled_view(
    input: &CampaignLearningStateCompilationInput<'_>,
    compiled: CompiledSlots,
) -> Result<CampaignLearningStateView, LearningContractError> {
    let recipe = input.recipe;
    let mut resolutions = input.source_resolutions.to_vec();
    resolutions.sort_by_key(|resolution| resolution.role);
    let mut positions = input.positions.to_vec();
    positions.sort_by_key(|position| position_kind_key(position.kind));
    let history_plans = canonical_history_references(input.history_plans)?;
    let mut required_references = input.required_references.to_vec();
    required_references.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let declared = u32::try_from(recipe.slots.len()).map_err(|_| LearningContractError::Bound {
        field: "recipe.slots",
    })?;
    let observed =
        u32::try_from(compiled.slots.len()).map_err(|_| LearningContractError::Bound {
            field: "view.slots",
        })?;
    let mut view = CampaignLearningStateView {
        view_id: ArtifactId::new("pending-campaign-learning-state-view")
            .map_err(|_| LearningContractError::Foundation)?,
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target: recipe.target.clone(),
        binding: recipe.binding.clone(),
        recipe_digest: recipe.canonical_digest.clone(),
        provenance: eliot_learning_contracts::CampaignLearningStateProvenance {
            source_resolutions: resolutions,
            frozen_anchor_digest: input.frozen_anchor_digest.to_owned(),
            positions,
            history_plans,
            generated_at_ms: input.generated_at_ms,
            expires_at_ms: input.expires_at_ms,
            rebuild_reason: input.rebuild_reason,
        },
        slots: compiled.slots,
        denominator: SourceDenominator { declared, observed },
        completeness: Completeness::Blocked,
        omissions: compiled.omissions,
        frontier: compiled.frontier,
        owner_disagreements: canonical_disagreements(input.disagreements),
        required_references,
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    view.completeness = view.derived_completeness(recipe);
    view.seal_content_addressed()?;
    view.validate_against(recipe)?;
    Ok(view)
}

/// Verify a persisted view against the exact current task fence, named owner
/// resolutions, compiled history plans, and runtime observation time.
///
/// Source-resolution digests are compared to the view's frozen references;
/// the resolver must compute each digest from the complete current owner
/// record during its authenticated named read.
pub fn validate_campaign_learning_state_view_current(
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
    current_state_fence: &StateFence,
    current_source_resolutions: &[CampaignSourceResolution],
    current_history_plans: &[CampaignHistoryPlanInput<'_>],
    observed_at_ms: i64,
) -> Result<(), LearningContractError> {
    view.validate_against(recipe)?;
    validate_context_partial_eligibility(view, recipe)?;
    if observed_at_ms < 0
        || view.provenance.generated_at_ms > observed_at_ms
        || view
            .provenance
            .expires_at_ms
            .is_some_and(|expires_at| observed_at_ms >= expires_at)
    {
        return Err(LearningContractError::ScopeMismatch {
            field: "view.runtime_time",
        });
    }
    current_state_fence
        .validate()
        .map_err(|_| LearningContractError::Foundation)?;
    if current_state_fence != &recipe.binding.state_fence
        || current_state_fence != &view.binding.state_fence
    {
        return Err(LearningContractError::ScopeMismatch {
            field: "view.current_state_fence",
        });
    }
    if view.invalidated
        || matches!(
            view.completeness,
            Completeness::Blocked | Completeness::Stale
        )
    {
        return Err(LearningContractError::IncompleteCoverage);
    }
    validate_history_plan_inputs(recipe, current_state_fence, current_history_plans)?;
    let mut current_resolutions = current_source_resolutions.to_vec();
    current_resolutions.sort_by_key(|resolution| resolution.role);
    if current_resolutions != view.provenance.source_resolutions {
        return Err(LearningContractError::ScopeMismatch {
            field: "view.current_source_revisions",
        });
    }
    let current_history_references = canonical_history_references(current_history_plans)?;
    if current_history_references != view.provenance.history_plans
        || current_history_references.is_empty()
    {
        return Err(LearningContractError::ScopeMismatch {
            field: "view.current_history_plans",
        });
    }
    Ok(())
}

fn validate_context_partial_eligibility(
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Result<(), LearningContractError> {
    if view.completeness != Completeness::Partial {
        return Ok(());
    }
    for slot_id in view.omissions.iter().chain(view.frontier.iter()) {
        let spec = recipe
            .slots
            .iter()
            .find(|slot| slot.slot_id == *slot_id)
            .ok_or(LearningContractError::IncompleteCoverage)?;
        let non_load_bearing = match &spec.requirement {
            SlotRequirement::Optional => true,
            SlotRequirement::Conditional { depends_on } => {
                !view.slots.iter().any(|slot| slot.slot_id == *depends_on)
            }
            SlotRequirement::Required => false,
        };
        if !non_load_bearing {
            return Err(LearningContractError::IncompleteCoverage);
        }
    }
    for requirement in &recipe.source_requirements {
        let resolution = view
            .provenance
            .source_resolutions
            .iter()
            .find(|resolution| resolution.role == requirement.role)
            .ok_or(LearningContractError::IncompleteCoverage)?;
        if resolution.status != CampaignSourceResolutionStatus::Current && requirement.load_bearing
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
    }
    for spec in &recipe.slots {
        let active = match &spec.requirement {
            SlotRequirement::Required => true,
            SlotRequirement::Optional => false,
            SlotRequirement::Conditional { depends_on } => {
                view.slots.iter().any(|slot| slot.slot_id == *depends_on)
            }
        };
        if !active {
            continue;
        }
        let slot = view
            .slots
            .iter()
            .find(|slot| slot.slot_id == spec.slot_id)
            .ok_or(LearningContractError::IncompleteCoverage)?;
        let evidenced_empty = slot.disposition == SlotDisposition::KnownEmpty
            && spec.declared_members.is_empty()
            && !slot.evidence.is_empty();
        if slot.disposition != SlotDisposition::Current && !evidenced_empty {
            return Err(LearningContractError::IncompleteCoverage);
        }
        if slot
            .members
            .iter()
            .any(|member| member.disposition != SlotDisposition::Current)
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
    }
    Ok(())
}

fn bound_input_sizes(
    input: &CampaignLearningStateCompilationInput<'_>,
) -> Result<(), LearningContractError> {
    let mut budget = InputBudget::default();
    bound_recipe_input(input.recipe, &mut budget)?;
    bound_projection_input(input.projections, &mut budget)?;
    bound_reference_input(input.required_references, &mut budget)?;
    bound_disagreement_input(input.disagreements, &mut budget)?;
    bound_provenance_input(
        input.source_resolutions,
        input.positions,
        input.history_plans,
        input.frozen_anchor_digest,
        &mut budget,
    )
}

#[derive(Default)]
struct InputBudget {
    declared_members: usize,
    supplied_members: usize,
    evidence: usize,
    text_bytes: usize,
}

impl InputBudget {
    fn add_text(&mut self, value: &str, field: &'static str) -> Result<(), LearningContractError> {
        check_label(value, field)?;
        self.text_bytes =
            self.text_bytes
                .checked_add(value.len())
                .ok_or(LearningContractError::Bound {
                    field: "input.text",
                })?;
        if self.text_bytes > MAX_INPUT_TEXT_BYTES {
            return Err(LearningContractError::Bound {
                field: "input.text",
            });
        }
        Ok(())
    }

    fn add_declared_members(&mut self, count: usize) -> Result<(), LearningContractError> {
        self.declared_members =
            self.declared_members
                .checked_add(count)
                .ok_or(LearningContractError::Bound {
                    field: "recipe.declared_members",
                })?;
        if self.declared_members > MAX_MEMBERS {
            return Err(LearningContractError::Bound {
                field: "recipe.declared_members",
            });
        }
        Ok(())
    }

    fn add_supplied_members(&mut self, count: usize) -> Result<(), LearningContractError> {
        self.supplied_members =
            self.supplied_members
                .checked_add(count)
                .ok_or(LearningContractError::Bound {
                    field: "projections.members",
                })?;
        if self.supplied_members > MAX_MEMBERS {
            return Err(LearningContractError::Bound {
                field: "projections.members",
            });
        }
        Ok(())
    }

    fn add_evidence(
        &mut self,
        count: usize,
        field: &'static str,
    ) -> Result<(), LearningContractError> {
        self.evidence = self
            .evidence
            .checked_add(count)
            .ok_or(LearningContractError::Bound { field })?;
        if self.evidence > MAX_EVIDENCE {
            return Err(LearningContractError::Bound { field });
        }
        Ok(())
    }
}

fn bound_recipe_input(
    recipe: &LearningStateViewRecipe,
    budget: &mut InputBudget,
) -> Result<(), LearningContractError> {
    if recipe.slots.len() > MAX_SLOTS {
        return Err(LearningContractError::Bound {
            field: "recipe.slots",
        });
    }
    budget.add_text(recipe.recipe_id.as_str(), "recipe.recipe_id")?;
    budget.add_text(recipe.campaign_id.as_str(), "recipe.campaign_id")?;
    budget.add_text(recipe.target.as_str(), "recipe.target")?;
    budget.add_text(recipe.binding.request_id.as_str(), "binding.request_id")?;
    budget.add_text(recipe.binding.operation_id.as_str(), "binding.operation_id")?;
    budget.add_text(recipe.binding.product_id.as_str(), "binding.product_id")?;
    budget.add_text(recipe.binding.task_id.as_str(), "binding.task_id")?;
    budget.add_text(recipe.binding.scope.as_str(), "binding.scope")?;
    budget.add_text(recipe.binding.source.owner.as_str(), "binding.source.owner")?;
    budget.add_text(
        recipe.binding.source.snapshot.as_str(),
        "binding.source.snapshot",
    )?;
    budget.add_text(
        recipe.binding.source.digest.as_str(),
        "binding.source.digest",
    )?;
    budget.add_text(recipe.privacy_class.as_str(), "recipe.privacy_class")?;
    budget.add_text(recipe.canonical_digest.as_str(), "recipe.canonical_digest")?;
    for slot in &recipe.slots {
        if slot.declared_members.len() > 256 {
            return Err(LearningContractError::Bound {
                field: "slot.declared_members",
            });
        }
        budget.add_declared_members(slot.declared_members.len())?;
        check_label(slot.accepted_type.as_str(), "slot.accepted_type")?;
        budget.add_text(slot.slot_id.as_str(), "slot.slot_id")?;
        budget.add_text(slot.owner.as_str(), "slot.owner")?;
        budget.add_text(slot.target.as_str(), "slot.target")?;
        budget.add_text(slot.accepted_type.as_str(), "slot.accepted_type")?;
        budget.add_text(slot.schema_digest.as_str(), "slot.schema_digest")?;
        if let SlotRequirement::Conditional { depends_on } = &slot.requirement {
            budget.add_text(depends_on.as_str(), "slot.depends_on")?;
        }
        for member in &slot.declared_members {
            budget.add_text(member.as_str(), "slot.declared_members")?;
        }
    }
    for requirement in &recipe.source_requirements {
        budget.add_text(requirement.owner.as_str(), "source_requirement.owner")?;
        if let Some(reference) = &requirement.expected_reference {
            bound_source_reference(reference, budget)?;
        }
    }
    Ok(())
}

fn bound_projection_input(
    projections: &[SlotProjection],
    budget: &mut InputBudget,
) -> Result<(), LearningContractError> {
    if projections.len() > MAX_SLOTS {
        return Err(LearningContractError::Bound {
            field: "projections",
        });
    }
    for projection in projections {
        if projection.members.len() > 256 {
            return Err(LearningContractError::Bound {
                field: "projection.members",
            });
        }
        if projection.evidence.len() > MAX_RECORD_EVIDENCE {
            return Err(LearningContractError::Bound {
                field: "projection.evidence",
            });
        }
        budget.add_supplied_members(projection.members.len())?;
        budget.add_evidence(projection.evidence.len(), "projections.evidence")?;
    }
    for projection in projections {
        budget.add_text(projection.slot_id.as_str(), "projection.slot_id")?;
        for evidence in &projection.evidence {
            budget.add_text(evidence.as_str(), "projection.evidence")?;
        }
        for member in &projection.members {
            if member.evidence.len() > MAX_RECORD_EVIDENCE {
                return Err(LearningContractError::Bound {
                    field: "member.evidence",
                });
            }
            budget.add_evidence(member.evidence.len(), "projections.member_evidence")?;
            budget.add_text(member.member_id.as_str(), "member.member_id")?;
            budget.add_text(member.owner.as_str(), "member.owner")?;
            budget.add_text(member.source.owner.as_str(), "member.source.owner")?;
            budget.add_text(member.source.snapshot.as_str(), "member.source.snapshot")?;
            budget.add_text(member.source.digest.as_str(), "member.source.digest")?;
            if let Some(value) = &member.value_digest {
                budget.add_text(value.as_str(), "member.value_digest")?;
            }
            for evidence in &member.evidence {
                budget.add_text(evidence.as_str(), "member.evidence")?;
            }
        }
    }
    Ok(())
}

fn bound_reference_input(
    required_references: &[ArtifactId],
    budget: &mut InputBudget,
) -> Result<(), LearningContractError> {
    if required_references.len() > MAX_REFERENCES {
        return Err(LearningContractError::Bound {
            field: "required_references",
        });
    }
    for reference in required_references {
        budget.add_text(reference.as_str(), "required_references")?;
    }
    Ok(())
}

fn bound_source_reference(
    reference: &CampaignSourceRevisionRef,
    budget: &mut InputBudget,
) -> Result<(), LearningContractError> {
    budget.add_text(reference.owner.as_str(), "source.owner")?;
    budget.add_text(source_record_id(reference).as_str(), "source.record_id")?;
    budget.add_text(reference.content_digest.as_str(), "source.content_digest")?;
    for projection in &reference.slot_projection_digests {
        budget.add_text(
            projection.slot_id.as_str(),
            "source.slot_projection.slot_id",
        )?;
        budget.add_text(projection.digest.as_str(), "source.slot_projection.digest")?;
    }
    if let eliot_learning_contracts::CampaignOwnerRevision::ResourceSnapshot(value) =
        &reference.revision
    {
        budget.add_text(value, "source.revision")?;
    }
    Ok(())
}

fn bound_provenance_input(
    resolutions: &[CampaignSourceResolution],
    positions: &[CampaignPositionRef],
    history_plans: &[CampaignHistoryPlanInput<'_>],
    frozen_anchor_digest: &str,
    budget: &mut InputBudget,
) -> Result<(), LearningContractError> {
    if resolutions.len() > eliot_learning_contracts::CampaignSourceRole::all().len()
        || positions.len() > 5
        || history_plans.len() > MAX_HISTORY_PLANS
    {
        return Err(LearningContractError::Bound {
            field: "view.provenance",
        });
    }
    budget.add_text(frozen_anchor_digest, "provenance.frozen_anchor_digest")?;
    for resolution in resolutions {
        if let Some(reference) = &resolution.reference {
            bound_source_reference(reference, budget)?;
        }
    }
    for position in positions {
        budget.add_text(
            position.source_content_digest.as_str(),
            "position.source_digest",
        )?;
        budget.add_text(position.position_digest.as_str(), "position.digest")?;
        if let eliot_learning_contracts::CampaignOwnerRevision::ResourceSnapshot(value) =
            &position.revision
        {
            budget.add_text(value, "position.revision")?;
        }
    }
    for history in history_plans {
        if history.selected_handles.len() > MAX_RECORD_EVIDENCE
            || history.diff_digests.len() > MAX_RECORD_EVIDENCE
            || history.policy_slice_handles.len() > MAX_RECORD_EVIDENCE
        {
            return Err(LearningContractError::Bound {
                field: "history_plan.references",
            });
        }
        if let Some(summary_digest) = &history.summary_digest {
            budget.add_text(summary_digest, "history_plan.summary_digest")?;
        }
        for digest in &history.diff_digests {
            budget.add_text(digest, "history_plan.diff_digest")?;
        }
        for handle in history
            .selected_handles
            .iter()
            .chain(&history.policy_slice_handles)
        {
            budget.add_text(handle.as_str(), "history_plan.handle")?;
        }
    }
    Ok(())
}

fn validate_history_plan_inputs(
    recipe: &LearningStateViewRecipe,
    current_state_fence: &StateFence,
    history_plans: &[CampaignHistoryPlanInput<'_>],
) -> Result<(), LearningContractError> {
    let mut plan_digests = BTreeSet::new();
    for history in history_plans {
        history
            .plan
            .validate()
            .map_err(|_| LearningContractError::Foundation)?;
        let query = history
            .plan
            .campaign_experience_query
            .as_ref()
            .ok_or(LearningContractError::IncompleteCoverage)?;
        if query.scope != recipe.campaign_id.as_str()
            || query.intent == CampaignIntent::None
            || &query.fence != current_state_fence
            || history
                .plan
                .source_projection_fences
                .iter()
                .any(|source| source.fence != *current_state_fence)
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "history_plan.campaign_scope_or_fence",
            });
        }
        if !query.handles.is_empty()
            && history
                .selected_handles
                .iter()
                .any(|handle| !query.handles.contains(handle))
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "history_plan.selected_handles",
            });
        }
        let selected: BTreeSet<_> = history.selected_handles.iter().cloned().collect();
        if selected.len() != history.selected_handles.len()
            || history
                .policy_slice_handles
                .iter()
                .any(|handle| !selected.contains(handle))
        {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let mut diff_digests = BTreeSet::new();
        for digest in &history.diff_digests {
            eliot_learning_contracts::identity::validate_digest(
                digest,
                "history_plan.diff_digest",
            )?;
            if !diff_digests.insert(digest) {
                return Err(LearningContractError::Duplicate {
                    field: "history_plan.diff_digests",
                });
            }
        }
        if let Some(digest) = &history.summary_digest {
            eliot_learning_contracts::identity::validate_digest(
                digest,
                "history_plan.summary_digest",
            )?;
        }
        let digest = history
            .plan
            .canonical_digest()
            .map_err(|_| LearningContractError::Foundation)?;
        if !plan_digests.insert(digest) {
            return Err(LearningContractError::Duplicate {
                field: "history_plans",
            });
        }
    }
    Ok(())
}

fn canonical_history_references(
    history_plans: &[CampaignHistoryPlanInput<'_>],
) -> Result<Vec<CampaignHistoryPlanReference>, LearningContractError> {
    let mut references = Vec::with_capacity(history_plans.len());
    for history in history_plans {
        let mut selected_handles = history.selected_handles.clone();
        selected_handles.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let mut diff_digests = history.diff_digests.clone();
        diff_digests.sort();
        let mut policy_slice_handles = history.policy_slice_handles.clone();
        policy_slice_handles.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        references.push(CampaignHistoryPlanReference {
            retrieval_plan_digest: history
                .plan
                .canonical_digest()
                .map_err(|_| LearningContractError::Foundation)?,
            selected_handles,
            summary_digest: history.summary_digest.clone(),
            diff_digests,
            policy_slice_handles,
        });
    }
    references.sort_by(|left, right| left.retrieval_plan_digest.cmp(&right.retrieval_plan_digest));
    Ok(references)
}

fn position_kind_key(kind: CampaignPositionKind) -> u8 {
    match kind {
        CampaignPositionKind::Current => 0,
        CampaignPositionKind::Experience => 1,
        CampaignPositionKind::Adaptation => 2,
        CampaignPositionKind::Evaluation => 3,
        CampaignPositionKind::EconomicsProgress => 4,
    }
}

fn source_record_id(reference: &CampaignSourceRevisionRef) -> String {
    use eliot_learning_contracts::CampaignOwnerRecordId;

    match &reference.record_id {
        CampaignOwnerRecordId::Artifact(id) => id.as_str().to_owned(),
        CampaignOwnerRecordId::Contract(id) => id.as_str().to_owned(),
        CampaignOwnerRecordId::Decision(id) => id.as_str().to_owned(),
        CampaignOwnerRecordId::Task(id) => id.as_str().to_owned(),
        CampaignOwnerRecordId::Resource(id) => id.clone(),
    }
}

fn bound_disagreement_input(
    disagreements: &[OwnerDisagreement],
    budget: &mut InputBudget,
) -> Result<(), LearningContractError> {
    if disagreements.len() > MAX_SLOTS {
        return Err(LearningContractError::Bound {
            field: "owner_disagreements",
        });
    }
    for disagreement in disagreements {
        if disagreement.owners.len() > MAX_DISAGREEMENT_OWNERS {
            return Err(LearningContractError::Bound {
                field: "owner_disagreement.owners",
            });
        }
        if disagreement.evidence.len() > MAX_RECORD_EVIDENCE {
            return Err(LearningContractError::Bound {
                field: "owner_disagreement.evidence",
            });
        }
        budget.add_evidence(disagreement.evidence.len(), "owner_disagreement.evidence")?;
    }
    for disagreement in disagreements {
        budget.add_text(disagreement.slot_id.as_str(), "disagreement.slot_id")?;
        for owner in &disagreement.owners {
            budget.add_text(owner.as_str(), "disagreement.owners")?;
        }
        for evidence in &disagreement.evidence {
            budget.add_text(evidence.as_str(), "disagreement.evidence")?;
        }
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
