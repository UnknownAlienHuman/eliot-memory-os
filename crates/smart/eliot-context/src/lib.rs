//! Store-neutral Smart contracts and pure compilation for ELIOT context.
//!
//! This crate owns the derived understanding view and its admission rules.  It
//! does not own canonical memory, a graph index, a model route, or a write
//! authority.  Inputs are already admitted records; outputs retain handles,
//! fences, omissions and explicit uncertainty so a caller can rebuild or
//! inspect every decision made by the compiler.

#![forbid(unsafe_code)]

pub mod campaign_publication;

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use eliot_contracts::{ArtifactId, ContractVersion, DecisionId, StateFence, TaskRevision, fences_match_exact};
use eliot_cue_contracts::CueKind;
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};
use eliot_learning_contracts::{
    CampaignLearningStateView, CampaignOwnerRecordId, CampaignSourceResolution,
    CampaignSourceResolutionStatus, CampaignSourceRevisionRef, CampaignSourceRole,
    LearningContractError, LearningStateViewRecipe,
};
use eliot_learning_state_view::{
    CampaignHistoryPlanInput, validate_campaign_learning_state_view_current,
};
use eliot_context_contracts::{
    CapacityLimits as CampaignCapacityLimits, ContextRecipe as CampaignContextRecipe,
    LossPolicy as CampaignLossPolicy, RepresentationKind as CampaignRepresentationKind,
    SemanticRole, SessionDeliverySnapshot,
};
use crate::campaign_publication::{
    ContextCampaignRecipeBody, ContextSourceDocument, context_delivery_publication,
    context_recipe_publication,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this capability contract.
pub const CONTRACT_NAME: &str = "eliot.smart.context";
/// Wire revision of this capability contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Failures which prevent a safe derived view from being emitted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextError {
    /// A required field is empty or contains control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A source or atom has no lineage.
    #[error("{field} must contain at least one handle")]
    MissingLineage { field: &'static str },
    /// Inputs refer to different causal snapshots.
    #[error("context inputs are not compatible with the requested state fence")]
    FenceMismatch,
    /// The recipe was compiled for a different task revision.
    #[error(
        "context recipe revision {recipe_revision:?} does not match task revision {task_revision:?}"
    )]
    RecipeRevisionMismatch {
        /// Revision carried by the recipe.
        recipe_revision: TaskRevision,
        /// Current task revision carried by the input.
        task_revision: TaskRevision,
    },
    /// Context inputs are not bound to the exact task, scope, task revision,
    /// and fence of the campaign learning view being consumed.
    #[error("campaign learning view does not bind context input field {field}")]
    CampaignBindingMismatch { field: &'static str },
    /// A context input or budget recipe is not the exact content of its
    /// current owner revision in the campaign view.
    #[error("campaign source binding is missing, stale, or digest-mismatched for {role:?}")]
    CampaignSourceMismatch { role: CampaignSourceRole },
    /// A context atom cites a handle that is not retained by the validated
    /// campaign view's required references or owner projection evidence.
    #[error("context atom support is not retained by the campaign learning view")]
    CampaignSupportMismatch,
    /// The durable campaign recipe cannot be represented by this bounded
    /// compiler without weakening its role or loss policy.
    #[error("campaign context policy is unsupported for semantic role {0:?}")]
    UnsupportedCampaignPolicy(SemanticRole),
    /// A non-droppable policy could not be met by the exact route capacity.
    #[error("campaign context capacity cannot preserve non-droppable material")]
    NonDroppableCapacity,
    /// The exact rich campaign context recipe failed its own contract checks.
    #[error("campaign context recipe is invalid")]
    InvalidCampaignRecipe,
    /// A mandatory owner semantic role has no represented candidate.
    #[error("campaign context delivery has no candidate for required role {0:?}")]
    MissingCampaignRole(ContextRole),
    /// The route's exact available capacity cannot be represented by this
    /// compiler's bounded integer cost unit.
    #[error("campaign context capacity is outside the supported cost range")]
    CampaignCapacityOutOfRange,
    /// A semantic identity appears more than once in one admitted set.
    #[error("duplicate semantic identity in {field}")]
    DuplicateIdentity {
        /// Stable field path containing the duplicate.
        field: &'static str,
    },
    /// A recipe would remove a required safety section.
    #[error("recipe does not preserve required context role {0:?}")]
    MissingRequiredRole(ContextRole),
    /// A bounded unit cannot be represented without losing its meaning.
    #[error("context unit {atom_id} has no usable representation")]
    Unrepresentable { atom_id: ArtifactId },
    /// A revision cannot be advanced.
    #[error("context revision overflow")]
    RevisionOverflow,
}

/// Failure to compile active context against a recipe-bound campaign learning
/// view. The learning-view validation error is kept separate from ordinary
/// context admission failures so callers can distinguish stale owner state
/// from an invalid context atom or budget recipe.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CampaignContextCompileError {
    /// The learning view no longer matches its recipe, fence, owner revisions,
    /// or retained `RetrievalPlan` set.
    #[error("campaign learning state is not current: {0}")]
    LearningState(#[from] LearningContractError),
    /// The ordinary bounded context compiler rejected its inputs.
    #[error("context compilation failed: {0}")]
    Context(#[from] ContextError),
}

/// Exact owner inputs required to compile context against a campaign view.
#[derive(Clone, Copy)]
pub struct CampaignLearningStateCompileInput<'a> {
    /// Current rich `ContextRecipe` and its exact admitted compiler input.
    pub recipe_body: &'a ContextCampaignRecipeBody,
    /// Actual prior owner-issued delivery snapshot.
    pub prior_delivery: &'a SessionDeliverySnapshot,
    /// Immutable learning-state view selected or compiled for this attempt.
    pub learning_view: &'a CampaignLearningStateView,
    /// Exact Task Controller recipe governing the learning-state view.
    pub learning_recipe: &'a LearningStateViewRecipe,
    /// Current authenticated owner-read fence.
    pub current_state_fence: &'a StateFence,
    /// Fresh exact source resolutions from named owner reads.
    pub current_source_resolutions: &'a [CampaignSourceResolution],
    /// Fresh validated retrieval plans from owner records.
    pub current_history_plans: &'a [CampaignHistoryPlanInput<'a>],
    /// Current bounded runtime time in Unix milliseconds.
    pub observed_at_ms: i64,
}

/// Result of compiling decision-local context against one exact immutable
/// campaign view. The source view identity and digest remain attached to the
/// result so a consumer cannot accidentally detach compiled context from the
/// owner revisions that were validated first.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignCompiledContext {
    /// Exact validated learning-view identity.
    pub learning_state_view_id: ArtifactId,
    /// Canonical digest of that immutable view.
    pub learning_state_view_digest: String,
    /// Exact rich owner `ContextRecipe` whose capacity and role policy governed this
    /// compilation.
    pub context_recipe_digest: String,
    /// Exact independent route capacity components retained with the result.
    pub capacity: CampaignCapacityLimits,
    /// Lossless semantic-to-compiler role policy projection used at compile.
    pub role_policy_projection: Vec<CampaignContextRolePolicy>,
    /// Exact artifact handles retained from the validated learning view.
    /// These let the downstream Context consumer retrieve the source-backed
    /// campaign state used to admit this compilation.
    pub learning_state_handles: Vec<ArtifactId>,
    /// Bounded decision-local context compiled from already admitted atoms.
    pub context: CompiledContext,
}

/// Visible projection from one rich semantic-role loss rule to the narrower
/// decision-local compiler role. Multiple source roles may share a compiler
/// role only when their loss policies agree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignContextRolePolicy {
    /// Role declared by the canonical Context owner recipe.
    pub semantic_role: SemanticRole,
    /// Role consumed by this pure Context Compiler.
    pub context_role: ContextRole,
    /// Exact permitted loss policy.
    pub loss_policy: CampaignLossPolicy,
    /// Whether the canonical recipe marks the source role as mandatory.
    pub required: bool,
    /// Exact allowed representations retained from the owner recipe.
    pub allowed_representations: Vec<CampaignRepresentationKind>,
}

fn text(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ContextError::InvalidText { field })
    } else {
        Ok(())
    }
}

/// Semantic role of one whole, addressable context unit.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextRole {
    /// Goal, acceptance and current commitments.
    Goal,
    /// Blocking attention, conflicts and hard constraints.
    Attention,
    /// Current observations and epistemic position.
    Evidence,
    /// Supported or competing interpretations.
    Model,
    /// Active plan and continuity state.
    Continuity,
    /// Invariants and exact negative-memory triggers.
    Safety,
    /// Unknowns and discriminative probes.
    Unknown,
    /// Authorized tools and available affordances.
    Affordance,
    /// Next action, observable and verifier.
    DecisionTail,
}

impl ContextRole {
    const fn priority(self) -> u8 {
        match self {
            Self::Goal => 0,
            Self::Attention => 1,
            Self::Evidence => 2,
            Self::Model => 3,
            Self::Continuity => 4,
            Self::Safety => 5,
            Self::Unknown => 6,
            Self::Affordance => 7,
            Self::DecisionTail => 8,
        }
    }
}

/// Admission disposition for one candidate unit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionDisposition {
    /// Include the complete unit in the compiled view.
    Included,
    /// Include only its exact handle; expansion remains possible.
    HandleOnly,
    /// Keep it out of the active view for this decision.
    Suppressed,
    /// Keep it isolated because its influence is not safe.
    Quarantined,
    /// Require a fresh fence or source check before admission.
    Revalidate,
}

/// A reasoned admission record, retained for reconstruction and diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecision {
    /// Candidate identity.
    pub atom_id: ArtifactId,
    /// Selected disposition.
    pub disposition: AdmissionDisposition,
    /// Stable reason code.
    pub reason: String,
    /// Whether this candidate was safety-protected.
    pub protected: bool,
}

/// One whole unit offered to the compiler by a canonical projection owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextAtom {
    /// Stable source/projection identity.
    pub atom_id: ArtifactId,
    /// Semantic role in the view.
    pub role: ContextRole,
    /// Renderable bounded representation; never treated as authority by itself.
    pub payload: String,
    /// Exact source handles supporting this unit.
    pub source_handles: Vec<ArtifactId>,
    /// Epistemic status of its supporting material.
    pub status: EpistemicStatus,
    /// Safe rendering ceiling.
    pub assertability: Assertability,
    /// Source freshness.
    pub freshness: EvidenceFreshness,
    /// Fence under which the unit was read.
    pub state_fence: StateFence,
    /// Candidate is required by the decision safety floor.
    pub required: bool,
    /// Candidate is protected from ordinary budget shedding.
    pub protected: bool,
    /// Estimated complete-unit cost in route-specific positions/tokens.
    pub cost: u32,
    /// Expected change to the current decision if admitted.
    pub expected_decision_delta: u16,
    /// Risk value of retaining this unit near the decision boundary.
    pub risk: u8,
    /// Exact activation cue keys which led to this candidate.
    pub cues: Vec<String>,
}

impl ContextAtom {
    /// Validate lineage, representation, fence and epistemic safety.
    pub fn validate(&self) -> Result<(), ContextError> {
        text(self.payload.as_str(), "atom.payload")?;
        if self.source_handles.is_empty() {
            return Err(ContextError::MissingLineage {
                field: "atom.source_handles",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ContextError::FenceMismatch)?;
        if matches!(
            self.status,
            EpistemicStatus::Stale | EpistemicStatus::Contested | EpistemicStatus::Rejected
        ) && self.assertability == Assertability::Assertable
        {
            return Err(ContextError::Unrepresentable {
                atom_id: self.atom_id.clone(),
            });
        }
        Ok(())
    }
}

/// Whole-unit budget selected for one route and decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextRecipe {
    /// Revision of this recipe.
    pub recipe_revision: TaskRevision,
    /// Maximum complete-unit cost for the view.
    pub total_cost: u32,
    /// Per-role maxima. Missing roles have no optional allocation.
    pub role_budgets: Vec<RoleBudget>,
    /// Roles that must remain represented, at least by an exact handle.
    pub required_roles: Vec<ContextRole>,
}

/// Budget for one semantic role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleBudget {
    /// Role being budgeted.
    pub role: ContextRole,
    /// Maximum cost of complete units for that role.
    pub maximum_cost: u32,
}

impl ContextRecipe {
    /// Validate that the recipe has a usable decision-local safety floor.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.total_cost == 0 {
            return Err(ContextError::InvalidText {
                field: "recipe.total_cost",
            });
        }
        let mut budget_roles = BTreeSet::new();
        for budget in &self.role_budgets {
            if !budget_roles.insert(budget.role) {
                return Err(ContextError::DuplicateIdentity {
                    field: "recipe.role_budgets.role",
                });
            }
        }
        let mut required_roles = BTreeSet::new();
        for role in &self.required_roles {
            if !required_roles.insert(*role) {
                return Err(ContextError::DuplicateIdentity {
                    field: "recipe.required_roles",
                });
            }
            if !budget_roles.contains(role) {
                return Err(ContextError::MissingRequiredRole(*role));
            }
        }
        Ok(())
    }

    fn budget_for(&self, role: ContextRole) -> u32 {
        self.role_budgets
            .iter()
            .find(|budget| budget.role == role)
            .map_or(0, |budget| budget.maximum_cost)
    }
}

/// Input projection for one compilation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextInput {
    /// `WorkScope` identity, kept separate from project claims.
    pub scope: String,
    /// Task identity represented by the view.
    pub task_id: Option<DecisionId>,
    /// Current task-plan revision.
    pub task_revision: TaskRevision,
    /// Fence shared by the read set.
    pub state_fence: StateFence,
    /// Already admitted candidates from canonical projections.
    pub atoms: Vec<ContextAtom>,
    /// Explicit unknowns that cannot be reduced to an atom.
    pub unknowns: Vec<String>,
}

impl ContextInput {
    /// Validate the complete read set before compilation.
    pub fn validate(&self) -> Result<(), ContextError> {
        text(self.scope.as_str(), "input.scope")?;
        self.state_fence
            .validate()
            .map_err(|_| ContextError::FenceMismatch)?;
        let mut atom_ids = BTreeSet::new();
        for atom in &self.atoms {
            if !atom_ids.insert(atom.atom_id.clone()) {
                return Err(ContextError::DuplicateIdentity {
                    field: "input.atoms.atom_id",
                });
            }
            atom.validate()?;
            if !fences_match_exact(&self.state_fence, &atom.state_fence) {
                return Err(ContextError::FenceMismatch);
            }
        }
        for unknown in &self.unknowns {
            text(unknown.as_str(), "input.unknowns")?;
        }
        Ok(())
    }
}

/// Dimensioned quality result; no scalar can hide a failed load-bearing axis.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each named dimension is independently observable on the wire"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PacketQualityScorecard {
    /// Goal/acceptance represented.
    pub goal_coverage: bool,
    /// Current evidence and operating model represented.
    pub epistemic_coverage: bool,
    /// Exact source handles retained.
    pub provenance_coverage: bool,
    /// All selected material shares the requested fence.
    pub fence_coherent: bool,
    /// Conflicts and unknowns are visible.
    pub uncertainty_visible: bool,
    /// Safety and negative-memory role represented.
    pub safety_coverage: bool,
    /// Next action and verifier represented.
    pub decision_readiness: bool,
    /// Some complete units were omitted for boundedness.
    pub bounded_omission: bool,
}

/// Compiled, inspectable active view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompiledContext {
    /// Scope of the view.
    pub scope: String,
    /// Task revision used to compile it.
    pub revision: TaskRevision,
    /// Fence shared by all admitted material.
    pub state_fence: StateFence,
    /// Complete units in decision order.
    pub units: Vec<ContextAtom>,
    /// Exact handles retained when full units did not fit.
    pub handle_only: Vec<ArtifactId>,
    /// Explicit candidates and their admission decisions.
    pub admissions: Vec<AdmissionDecision>,
    /// Unknowns and coverage gaps.
    pub unknowns: Vec<String>,
    /// Quality dimensions for this exact compilation.
    pub quality: PacketQualityScorecard,
}

/// Pure compiler for decision-local context.
#[derive(Clone, Copy, Debug, Default)]
pub struct ContextCompiler;

impl ContextCompiler {
    /// Compile a bounded view without model calls, storage access or mutation.
    pub fn compile(
        input: &ContextInput,
        recipe: &ContextRecipe,
    ) -> Result<CompiledContext, ContextError> {
        Self::compile_with_revocation(input, recipe, &BTreeSet::new())
    }

    /// Validate the exact campaign learning view and current owner-read set
    /// before compiling any context from its bound task and scope.
    ///
    /// `current_source_resolutions` and `current_history_plans` must be the
    /// result of authenticated owner reads for `current_state_fence`. The
    /// learning-state validator checks those records against the recipe and
    /// prior view. The current `ContextRecipe` row contains the current exact
    /// compiler input; the separate `ContextDelivery` row contains only the
    /// prior owner-issued snapshot. Both are checked independently
    /// before the pure context compiler runs.
    pub fn compile_with_campaign_learning_state(
        input: CampaignLearningStateCompileInput<'_>,
    ) -> Result<CampaignCompiledContext, CampaignContextCompileError> {
        let context_recipe = &input.recipe_body.recipe;
        let context_input = &input.recipe_body.compiler_input;
        validate_campaign_context_binding(
            context_recipe,
            context_input,
            input.learning_view,
            input.current_state_fence,
        )?;

        context_recipe
            .validate()
            .map_err(|_| ContextError::InvalidCampaignRecipe)?;
        input.learning_view.validate_against(input.learning_recipe)?;
        let context_recipe_source = current_campaign_source(
            input.current_source_resolutions,
            CampaignSourceRole::ContextRecipe,
        )?;
        let context_delivery_source = current_campaign_source(
            input.current_source_resolutions,
            CampaignSourceRole::ContextDelivery,
        )?;
        let recipe_publication = context_recipe_publication(context_recipe, context_input)
            .map_err(|_| ContextError::InvalidCampaignRecipe)?;
        let delivery_publication =
            context_delivery_publication(context_recipe, input.prior_delivery).map_err(|_| {
                ContextError::CampaignSourceMismatch {
                    role: CampaignSourceRole::ContextDelivery,
                }
            })?;
        if !matches!(
            recipe_publication.document(),
            ContextSourceDocument::Recipe(source_recipe)
                if source_recipe.as_ref() == input.recipe_body
        ) {
            return Err(ContextError::CampaignSourceMismatch {
                role: CampaignSourceRole::ContextRecipe,
            }
            .into());
        }
        if !matches!(
            delivery_publication.document(),
            ContextSourceDocument::Delivery(source_delivery)
                if source_delivery.as_ref() == input.prior_delivery
        ) {
            return Err(ContextError::CampaignSourceMismatch {
                role: CampaignSourceRole::ContextDelivery,
            }
            .into());
        }
        // The current rich `ContextRecipe`/input and prior-delivery snapshot
        // were decoded from the exact typed bodies returned by these current
        // owner reads. Confirm their native identities and original fences
        // agree with the exact references before compiling.
        if !campaign_source_matches_publication(
            context_recipe_source,
            &recipe_publication,
        ) || !campaign_source_matches_publication(
            context_delivery_source,
            &delivery_publication,
        ) {
            return Err(ContextError::CampaignSourceMismatch {
                role: CampaignSourceRole::ContextDelivery,
            }
            .into());
        }
        validate_context_support_handles(
            context_input,
            input.learning_view,
            input.current_source_resolutions,
        )?;
        validate_campaign_learning_state_view_current(
            input.learning_view,
            input.learning_recipe,
            input.current_state_fence,
            input.current_source_resolutions,
            input.current_history_plans,
            input.observed_at_ms,
        )?;

        let (compiler_input, compiler_recipe, role_policy_projection) =
            project_campaign_context_recipe(context_recipe, context_input)?;
        let context = Self::compile(&compiler_input, &compiler_recipe)?;
        enforce_campaign_loss_policies(&compiler_input, &context, &role_policy_projection)?;
        let learning_state_handles = campaign_learning_state_handles(input.learning_view)?;
        Ok(CampaignCompiledContext {
            learning_state_view_id: input.learning_view.view_id.clone(),
            learning_state_view_digest: input.learning_view.canonical_digest.clone(),
            context_recipe_digest: context_recipe.recipe_sha256.clone(),
            capacity: context_recipe.capacity,
            role_policy_projection,
            learning_state_handles,
            context,
        })
    }

    /// Compile a bounded view while treating `revoked_handles` as removed support.
    ///
    /// Behaves exactly like [`compile`](Self::compile) with an empty set.
    /// With a non-empty set, three pure I12.20 revocation-closure projections
    /// apply on top of the identical budget admission:
    ///
    /// * any candidate atom with at least one source handle in
    ///   `revoked_handles` is quarantined with reason
    ///   `revoked_source_support_removed`, regardless of budget, required, or
    ///   protected status. Quarantined atoms stay in `admissions` history and
    ///   contribute a rebuild unknown;
    /// * atoms with incomplete lineage (empty source handles, or blank handle
    ///   text where lineage is required) are quarantined as a bounded scope
    ///   covering only the affected atoms — the clean remainder still
    ///   compiles — with an explicit rebuild-from-clean-inputs unknown (see
    ///   [`bounded_quarantine_scope_for_incomplete_lineage`]);
    /// * mixed-lineage atoms (more than one distinct source handle) inherit
    ///   the minimum assertability across their material sources, downgraded
    ///   and never upgraded (see [`minimum_assertability_for_lineage`]);
    /// * the invalidated-derivative key set for the revoked roots (see
    ///   [`revoked_derivative_invalidation_set`]) is threaded into `unknowns`
    ///   as one stable marker; external cache/context-profile owners recover
    ///   the exact keys through that function.
    ///
    /// All three projections are deterministic, bounded, stateless and
    /// side-effect free: no retrieval, no canonical writes, no Problem State
    /// or store/effects wiring. Opening Problem State, purging stores, and
    /// scheduling rebuild effects belong to other owners; this function only
    /// emits the typed quarantine dispositions and rebuild unknowns they
    /// must consume.
    pub fn compile_with_revocation(
        input: &ContextInput,
        recipe: &ContextRecipe,
        revoked_handles: &BTreeSet<ArtifactId>,
    ) -> Result<CompiledContext, ContextError> {
        // Bounded incomplete-lineage scope (I12.20). Empty for the empty-set
        // path, so `compile` keeps its fail-closed whole-input validation.
        let incomplete_scope = if revoked_handles.is_empty() {
            BTreeSet::new()
        } else {
            bounded_quarantine_scope_for_incomplete_lineage(&input.atoms)
        };
        // Compile the clean remainder; the quarantined scope is seeded into
        // `admissions` below and never silently dropped.
        let scoped = scoped_input_without_quarantined_scope(input, &incomplete_scope);
        scoped.validate()?;
        recipe.validate()?;
        if recipe.recipe_revision != scoped.task_revision {
            return Err(ContextError::RecipeRevisionMismatch {
                recipe_revision: recipe.recipe_revision,
                task_revision: scoped.task_revision,
            });
        }
        // Per-source assertability floors for the minimum-inheritance cap.
        // Built only for revocation passes so the empty-set `compile` path
        // is untouched.
        let source_floor = if revoked_handles.is_empty() {
            None
        } else {
            Some(source_assertability_floors(&scoped.atoms))
        };
        let mut candidates = scoped.atoms.clone();
        candidates.sort_by(Self::candidate_order);
        let mut units = Vec::new();
        let mut handles = Vec::new();
        let mut ledger = BudgetLedger::default();
        // Seed the bounded quarantine first, in deterministic atom-id order:
        // only the affected atoms, never a broad suppression of the read set.
        let mut admissions = seed_incomplete_lineage_quarantines(&input.atoms, &incomplete_scope);
        admissions.reserve(candidates.len());
        let mut revoked_seen = false;
        let mut revoked_quarantined: BTreeSet<ArtifactId> = BTreeSet::new();

        for atom in candidates {
            if !atom.source_handles.is_empty()
                && atom
                    .source_handles
                    .iter()
                    .any(|h| revoked_handles.contains(h))
            {
                revoked_seen = true;
                revoked_quarantined.insert(atom.atom_id.clone());
                admissions.push(AdmissionDecision {
                    atom_id: atom.atom_id,
                    protected: atom.protected,
                    reason: "revoked_source_support_removed".to_owned(),
                    disposition: AdmissionDisposition::Quarantined,
                });
                continue;
            }
            // Minimum-inheritance cap (I12.20): a mixed-lineage atom inherits
            // the minimum ceiling across its material sources. `None` on the
            // empty-set path, so `compile` output is untouched.
            let (effective, capped) = capped_assertability_for_atom(&atom, source_floor.as_ref());
            admissions.push(admit_with_budget(
                &atom,
                recipe,
                &mut ledger,
                effective,
                capped,
                &mut units,
                &mut handles,
            ));
        }

        let mut unknowns = scoped.unknowns.clone();
        if !incomplete_scope.is_empty() {
            unknowns.push(INCOMPLETE_LINEAGE_REBUILD_UNKNOWN.to_owned());
        }
        if revoked_seen {
            unknowns.push("revoked_support_removed_rebuild_from_clean_inputs_required".to_owned());
        }
        // Thread the invalidated-derivative key set into the output as one
        // stable marker; the exact keys stay available to external
        // cache/context-profile owners via
        // `revoked_derivative_invalidation_set`. Empty on the empty-set path.
        unknowns.extend(derivative_invalidation_unknown(
            revoked_handles,
            &revoked_quarantined,
        ));
        if admissions
            .iter()
            .any(|item| item.disposition != AdmissionDisposition::Included)
        {
            unknowns.push("some candidate context was omitted or requires revalidation".to_owned());
        }
        unknowns.sort();
        unknowns.dedup();
        let quality = scorecard(&units, &handles, &unknowns, &input.state_fence);
        Ok(CompiledContext {
            scope: input.scope.clone(),
            revision: input.task_revision,
            state_fence: input.state_fence.clone(),
            units,
            handle_only: handles,
            admissions,
            unknowns,
            quality,
        })
    }

    fn candidate_order(left: &ContextAtom, right: &ContextAtom) -> Ordering {
        left.required
            .cmp(&right.required)
            .reverse()
            .then_with(|| left.protected.cmp(&right.protected).reverse())
            .then_with(|| left.role.priority().cmp(&right.role.priority()))
            .then_with(|| {
                left.expected_decision_delta
                    .cmp(&right.expected_decision_delta)
                    .reverse()
            })
            .then_with(|| left.risk.cmp(&right.risk).reverse())
            .then_with(|| left.atom_id.cmp(&right.atom_id))
    }
}

fn project_campaign_context_recipe(
    recipe: &CampaignContextRecipe,
    input: &ContextInput,
) -> Result<(ContextInput, ContextRecipe, Vec<CampaignContextRolePolicy>), ContextError> {
    recipe
        .validate()
        .map_err(|_| ContextError::InvalidCampaignRecipe)?;
    let available = recipe
        .capacity
        .route_capacity
        .checked_sub(recipe.capacity.fixed_overhead)
        .and_then(|remaining| remaining.checked_sub(recipe.capacity.output_reserve))
        .and_then(|remaining| remaining.checked_sub(recipe.capacity.review_reserve))
        .ok_or(ContextError::InvalidCampaignRecipe)?;
    let total_cost = u32::try_from(available).map_err(|_| ContextError::CampaignCapacityOutOfRange)?;
    if total_cost == 0 {
        return Err(ContextError::CampaignCapacityOutOfRange);
    }

    let mut role_rules: BTreeMap<ContextRole, (CampaignLossPolicy, bool)> = BTreeMap::new();
    let mut role_policy_projection = Vec::with_capacity(recipe.role_policies.len());
    for rule in &recipe.role_policies {
        let context_role = map_campaign_semantic_role(rule.role);
        let retained_representation = match rule.loss_policy {
            CampaignLossPolicy::HandleOnly => CampaignRepresentationKind::Handle,
            CampaignLossPolicy::NonDroppable
            | CampaignLossPolicy::Extractive
            | CampaignLossPolicy::Summarizable => CampaignRepresentationKind::Whole,
        };
        if !rule.allowed_representations.contains(&retained_representation) {
            return Err(ContextError::UnsupportedCampaignPolicy(rule.role));
        }
        if let Some((existing_policy, existing_required)) = role_rules.get_mut(&context_role) {
            if *existing_policy != rule.loss_policy {
                return Err(ContextError::UnsupportedCampaignPolicy(rule.role));
            }
            *existing_required |= rule.required;
        } else {
            role_rules.insert(context_role, (rule.loss_policy, rule.required));
        }
        role_policy_projection.push(CampaignContextRolePolicy {
            semantic_role: rule.role,
            context_role,
            loss_policy: rule.loss_policy,
            required: rule.required,
            allowed_representations: rule.allowed_representations.clone(),
        });
    }

    for atom in &input.atoms {
        if !role_rules.contains_key(&atom.role) {
            return Err(ContextError::MissingCampaignRole(atom.role));
        }
    }
    let mut compiler_recipe = ContextRecipe {
        recipe_revision: recipe.decision.recipe_revision,
        total_cost,
        role_budgets: Vec::with_capacity(role_rules.len()),
        required_roles: Vec::new(),
    };
    for (role, (loss_policy, required)) in &role_rules {
        compiler_recipe.role_budgets.push(RoleBudget {
            role: *role,
            maximum_cost: if *loss_policy == CampaignLossPolicy::HandleOnly {
                0
            } else {
                total_cost
            },
        });
        if *required {
            compiler_recipe.required_roles.push(*role);
            if !input.atoms.iter().any(|atom| atom.role == *role) {
                return Err(ContextError::MissingCampaignRole(*role));
            }
        }
    }
    compiler_recipe.validate()?;

    let mut compiler_input = input.clone();
    for atom in &mut compiler_input.atoms {
        if role_rules
            .get(&atom.role)
            .is_some_and(|(_, required)| *required)
        {
            atom.required = true;
        }
    }
    Ok((compiler_input, compiler_recipe, role_policy_projection))
}

const fn map_campaign_semantic_role(role: SemanticRole) -> ContextRole {
    match role {
        SemanticRole::Authority | SemanticRole::Negative | SemanticRole::Security => {
            ContextRole::Safety
        }
        SemanticRole::Goal => ContextRole::Goal,
        SemanticRole::Scope | SemanticRole::Instruction => ContextRole::Continuity,
        SemanticRole::Acceptance | SemanticRole::Verifier => ContextRole::DecisionTail,
        SemanticRole::Source | SemanticRole::Evidence => ContextRole::Evidence,
        SemanticRole::MaterialUnknown => ContextRole::Unknown,
        SemanticRole::Optional => ContextRole::Model,
        SemanticRole::Conflict | SemanticRole::Constraint => ContextRole::Attention,
    }
}

fn enforce_campaign_loss_policies(
    input: &ContextInput,
    compiled: &CompiledContext,
    policies: &[CampaignContextRolePolicy],
) -> Result<(), ContextError> {
    for policy in policies {
        let atoms: Vec<_> = input
            .atoms
            .iter()
            .filter(|atom| atom.role == policy.context_role)
            .collect();
        for atom in atoms {
            let decision = compiled
                .admissions
                .iter()
                .find(|decision| decision.atom_id == atom.atom_id)
                .ok_or(ContextError::CampaignSupportMismatch)?;
            if policy.loss_policy == CampaignLossPolicy::HandleOnly
                && decision.disposition == AdmissionDisposition::Included
            {
                return Err(ContextError::UnsupportedCampaignPolicy(policy.semantic_role));
            }
            match (policy.loss_policy, decision.disposition) {
                (CampaignLossPolicy::NonDroppable, AdmissionDisposition::Included) => {}
                (CampaignLossPolicy::NonDroppable, _) => {
                    return Err(ContextError::NonDroppableCapacity);
                }
                (
                    CampaignLossPolicy::Extractive | CampaignLossPolicy::Summarizable,
                    AdmissionDisposition::HandleOnly,
                ) if !policy
                    .allowed_representations
                    .contains(&CampaignRepresentationKind::Handle) =>
                {
                    return Err(ContextError::UnsupportedCampaignPolicy(policy.semantic_role));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_campaign_context_binding(
    recipe: &CampaignContextRecipe,
    input: &ContextInput,
    learning_view: &CampaignLearningStateView,
    current_state_fence: &StateFence,
) -> Result<(), ContextError> {
    if &input.state_fence != current_state_fence
        || learning_view.binding.state_fence != *current_state_fence
    {
        return Err(ContextError::CampaignBindingMismatch {
            field: "state_fence",
        });
    }
    if input.scope != learning_view.binding.scope.as_str() {
        return Err(ContextError::CampaignBindingMismatch { field: "scope" });
    }
    if recipe.binding.task_id.as_str() != learning_view.binding.task_id.as_str() {
        return Err(ContextError::CampaignBindingMismatch { field: "task_id" });
    }
    if recipe.binding.scope_id.as_str() != input.scope
        || recipe.binding.state_fence != *current_state_fence
    {
        return Err(ContextError::CampaignBindingMismatch {
            field: "recipe_binding",
        });
    }
    if input.task_id.as_ref() != Some(&recipe.binding.decision_id) {
        return Err(ContextError::CampaignBindingMismatch { field: "decision_id" });
    }
    if recipe.decision.recipe_revision != input.task_revision {
        return Err(ContextError::RecipeRevisionMismatch {
            recipe_revision: recipe.decision.recipe_revision,
            task_revision: input.task_revision,
        });
    }
    if current_state_fence.task_revision != Some(input.task_revision) {
        return Err(ContextError::CampaignBindingMismatch {
            field: "task_revision",
        });
    }
    Ok(())
}

fn current_campaign_source(
    resolutions: &[CampaignSourceResolution],
    role: CampaignSourceRole,
) -> Result<&CampaignSourceRevisionRef, CampaignContextCompileError> {
    let mut matches = resolutions.iter().filter(|resolution| resolution.role == role);
    let resolution = matches
        .next()
        .ok_or(ContextError::CampaignSourceMismatch { role })?;
    if matches.next().is_some()
        || resolution.status != CampaignSourceResolutionStatus::Current
        || resolution
            .reference
            .as_ref()
            .is_none_or(|reference| reference.role != role)
    {
        return Err(ContextError::CampaignSourceMismatch { role }.into());
    }
    resolution
        .reference
        .as_ref()
        .ok_or(ContextError::CampaignSourceMismatch { role }.into())
}

fn campaign_source_matches_publication(
    reference: &CampaignSourceRevisionRef,
    publication: &crate::campaign_publication::ContextSourcePublication,
) -> bool {
    reference.owner.as_str() == publication.owner_id()
        && reference.record_id == *publication.record_id()
        && reference.revision == *publication.revision()
        && reference.recorded_state_fence == *publication.recorded_state_fence()
}

fn campaign_learning_state_handles(
    view: &CampaignLearningStateView,
) -> Result<Vec<ArtifactId>, ContextError> {
    const MAX_HANDLES: usize = 16_384;
    let mut handles = BTreeSet::new();
    handles.extend(view.required_references.iter().cloned());
    for slot in &view.slots {
        handles.extend(slot.evidence.iter().cloned());
        for member in &slot.members {
            handles.extend(member.evidence.iter().cloned());
        }
    }
    for history in &view.provenance.history_plans {
        handles.extend(history.selected_handles.iter().cloned());
        handles.extend(history.policy_slice_handles.iter().cloned());
    }
    for position in &view.provenance.positions {
        if let CampaignOwnerRecordId::Artifact(handle) = &position.record_id {
            handles.insert(handle.clone());
        }
    }
    if handles.len() > MAX_HANDLES {
        return Err(ContextError::CampaignSupportMismatch);
    }
    Ok(handles.into_iter().collect())
}

fn validate_context_support_handles(
    input: &ContextInput,
    view: &CampaignLearningStateView,
    resolutions: &[CampaignSourceResolution],
) -> Result<(), ContextError> {
    let mut retained = BTreeSet::new();
    retained.extend(
        view.required_references
            .iter()
            .map(ArtifactId::as_str),
    );
    for slot in &view.slots {
        retained.extend(slot.evidence.iter().map(ArtifactId::as_str));
        for member in &slot.members {
            retained.extend(member.evidence.iter().map(ArtifactId::as_str));
        }
    }
    for resolution in resolutions {
        if resolution.status != CampaignSourceResolutionStatus::Current {
            continue;
        }
        if let Some(reference) = &resolution.reference {
            retained.insert(match &reference.record_id {
                CampaignOwnerRecordId::Artifact(value) => value.as_str(),
                CampaignOwnerRecordId::Contract(value) => value.as_str(),
                CampaignOwnerRecordId::Decision(value) => value.as_str(),
                CampaignOwnerRecordId::Task(value) => value.as_str(),
                CampaignOwnerRecordId::Resource(value) => value.as_str(),
            });
        }
    }
    if input
        .atoms
        .iter()
        .flat_map(|atom| atom.source_handles.iter())
        .any(|handle| !retained.contains(handle.as_str()))
    {
        return Err(ContextError::CampaignSupportMismatch);
    }
    Ok(())
}

/// Admission reason for bounded incomplete-lineage quarantine (I12.20).
const INCOMPLETE_LINEAGE_QUARANTINE_REASON: &str = "incomplete_lineage_bounded_quarantine";
/// Admission reason for mixed-lineage atoms capped to the minimum source ceiling.
const LINEAGE_ASSERTABILITY_CAP_REASON: &str =
    "admitted_within_fence_and_budget_minimum_lineage_assertability_applied";
/// Unknown marking invalidated derivative caches/profiles after revocation.
const REVOKED_DERIVATIVE_INVALIDATION_UNKNOWN: &str =
    "revoked_derivative_cache_invalidation_required_rebuild_from_clean_inputs";
/// Unknown marking bounded incomplete-lineage quarantine.
const INCOMPLETE_LINEAGE_REBUILD_UNKNOWN: &str =
    "incomplete_lineage_bounded_quarantine_rebuild_from_clean_inputs_required";

/// Rank of one assertability ceiling: lower is more restrictive.
///
/// Ordering is `AbstainOrFence < NonAssertableUnverified < Assertable`, so a
/// minimum over ranks is always the weakest (most restrictive) ceiling.
const fn assertability_rank(level: Assertability) -> u8 {
    match level {
        Assertability::AbstainOrFence => 0,
        Assertability::NonAssertableUnverified => 1,
        Assertability::Assertable => 2,
    }
}

/// Ceiling for one rank, inverse to [`assertability_rank`].
const fn assertability_for_rank(rank: u8) -> Assertability {
    match rank {
        0 => Assertability::AbstainOrFence,
        1 => Assertability::NonAssertableUnverified,
        _ => Assertability::Assertable,
    }
}

/// Minimum allowed assertability across a set of material source ceilings.
///
/// I12.20 requires that any mixed-lineage derived item inherits the minimum
/// allowed influence/assertability of its material supporting sources. This
/// is the pure projection of that rule: the result is the most restrictive
/// input ceiling, so a derived item is downgraded but never upgraded. An
/// empty set carries no support and fails closed to
/// [`Assertability::AbstainOrFence`].
///
/// Performs no retrieval and changes no epistemic status or authority; it
/// only projects the minimum over caller-supplied ceilings. Deterministic,
/// bounded, stateless and side-effect free.
pub fn minimum_assertability_for_lineage(levels: &[Assertability]) -> Assertability {
    let mut rank = u8::MAX;
    for level in levels {
        rank = rank.min(assertability_rank(*level));
    }
    if rank == u8::MAX {
        Assertability::AbstainOrFence
    } else {
        assertability_for_rank(rank)
    }
}

/// Invalidated derivative key set for revoked roots.
///
/// I12.20 requires removing revoked support from derived artifacts, including
/// Context Compiler outputs and caches. This is the pure projection of that
/// rule for external cache/context-profile owners: one
/// `revoked_source_support:{handle}` key per revoked root handle plus one
/// `quarantined_derivative:{atom}` key per revocation-quarantined atom, in
/// deterministic order. Owners match their derivative keys against this set,
/// invalidate without resurrecting revoked influence, and rebuild from clean
/// inputs.
///
/// Performs no I/O and owns no cache; deterministic, bounded, stateless and
/// side-effect free.
pub fn revoked_derivative_invalidation_set(
    revoked_handles: &BTreeSet<ArtifactId>,
    quarantined_atom_ids: &BTreeSet<ArtifactId>,
) -> BTreeSet<String> {
    let mut invalidated = BTreeSet::new();
    for handle in revoked_handles {
        invalidated.insert(format!("revoked_source_support:{handle}"));
    }
    for atom_id in quarantined_atom_ids {
        invalidated.insert(format!("quarantined_derivative:{atom_id}"));
    }
    invalidated
}

/// Bounded quarantine scope for incomplete lineage.
///
/// I12.20 requires that when lineage is incomplete, only the bounded affected
/// scope is quarantined: Problem State is opened and a rebuild from clean
/// inputs is scheduled instead of purging memory by similarity. This is the
/// pure compiler slice of that rule: it returns exactly the atom ids whose
/// lineage is incomplete — an empty source-handle vector, or any blank
/// handle text where lineage is required — in deterministic order. Clean
/// atoms are never included, so callers quarantine the bounded scope instead
/// of failing or suppressing the whole read set, and emit no similarity
/// purge.
///
/// Opening Problem State and scheduling rebuild effects belong to other
/// owners; deterministic, bounded, stateless and side-effect free.
pub fn bounded_quarantine_scope_for_incomplete_lineage(
    atoms: &[ContextAtom],
) -> BTreeSet<ArtifactId> {
    let mut scope = BTreeSet::new();
    for atom in atoms {
        let incomplete = atom.source_handles.is_empty()
            || atom
                .source_handles
                .iter()
                .any(|handle| handle.as_str().trim().is_empty());
        if incomplete {
            scope.insert(atom.atom_id.clone());
        }
    }
    scope
}

/// Read set with a quarantine scope removed, preserving all other fields.
///
/// Pure projection used to compile the clean remainder while the quarantined
/// scope is seeded into `admissions` separately; never silently drops atoms.
fn scoped_input_without_quarantined_scope(
    input: &ContextInput,
    scope: &BTreeSet<ArtifactId>,
) -> ContextInput {
    ContextInput {
        scope: input.scope.clone(),
        task_id: input.task_id.clone(),
        task_revision: input.task_revision,
        state_fence: input.state_fence.clone(),
        atoms: input
            .atoms
            .iter()
            .filter(|atom| !scope.contains(&atom.atom_id))
            .cloned()
            .collect(),
        unknowns: input.unknowns.clone(),
    }
}

/// Per-source assertability floors observed across one read set.
///
/// This stateless package can only observe the read set itself, so each
/// handle's floor is the minimum declared ceiling across the atoms projecting
/// it (see [`minimum_assertability_for_lineage`]). Deterministic and bounded.
fn source_assertability_floors(atoms: &[ContextAtom]) -> BTreeMap<&ArtifactId, Assertability> {
    let mut floors: BTreeMap<&ArtifactId, Assertability> = BTreeMap::new();
    for atom in atoms {
        for handle in &atom.source_handles {
            floors
                .entry(handle)
                .and_modify(|floor| {
                    *floor = minimum_assertability_for_lineage(&[*floor, atom.assertability]);
                })
                .or_insert(atom.assertability);
        }
    }
    floors
}

/// Effective assertability for one atom under the minimum-inheritance cap.
///
/// With `None` floors (the empty-set `compile` path) the declared ceiling
/// passes through untouched. Otherwise a mixed-lineage atom — more than one
/// distinct source handle — is downgraded to the minimum ceiling across its
/// material sources, never upgraded; single-lineage atoms keep their declared
/// ceiling. Returns the effective ceiling and whether a downgrade applied.
fn capped_assertability_for_atom(
    atom: &ContextAtom,
    source_floors: Option<&BTreeMap<&ArtifactId, Assertability>>,
) -> (Assertability, bool) {
    let Some(floors) = source_floors else {
        return (atom.assertability, false);
    };
    let distinct: BTreeSet<&ArtifactId> = atom.source_handles.iter().collect();
    if distinct.len() < 2 {
        return (atom.assertability, false);
    }
    let mut ceilings = Vec::with_capacity(distinct.len() + 1);
    ceilings.push(atom.assertability);
    for handle in distinct {
        if let Some(floor) = floors.get(handle) {
            ceilings.push(*floor);
        }
    }
    let minimum = minimum_assertability_for_lineage(&ceilings);
    if assertability_rank(minimum) < assertability_rank(atom.assertability) {
        (minimum, true)
    } else {
        (atom.assertability, false)
    }
}

/// Whole-unit budget ledger threaded through candidate admission.
#[derive(Clone, Debug, Default)]
struct BudgetLedger {
    spent_total: u32,
    spent_roles: Vec<(ContextRole, u32)>,
}

/// Whole-unit budget admission for one candidate.
///
/// Identical admission semantics to the historical compiler loop: unsafe
/// material is quarantined, stale material revalidates, fitting units are
/// included whole (emitted with their effective assertability ceiling),
/// required/protected overflow degrades to exact handles, and optional
/// overflow is suppressed. Emitted reasons name the minimum-inheritance cap
/// whenever it downgraded an included unit.
fn admit_with_budget(
    atom: &ContextAtom,
    recipe: &ContextRecipe,
    ledger: &mut BudgetLedger,
    effective: Assertability,
    capped: bool,
    units: &mut Vec<ContextAtom>,
    handles: &mut Vec<ArtifactId>,
) -> AdmissionDecision {
    let role_spent = ledger
        .spent_roles
        .iter()
        .find(|(role, _)| *role == atom.role)
        .map_or(0, |(_, spent)| *spent);
    let role_limit = recipe.budget_for(atom.role);
    let fits = ledger.spent_total.saturating_add(atom.cost) <= recipe.total_cost
        && role_spent.saturating_add(atom.cost) <= role_limit;
    let freshness_ok = matches!(
        atom.freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    );
    let safe = effective != Assertability::AbstainOrFence
        && !matches!(atom.status, EpistemicStatus::Rejected);
    let disposition = if !safe {
        AdmissionDisposition::Quarantined
    } else if !freshness_ok {
        AdmissionDisposition::Revalidate
    } else if fits {
        let mut emitted = atom.clone();
        emitted.assertability = effective;
        units.push(emitted);
        ledger.spent_total = ledger.spent_total.saturating_add(atom.cost);
        if let Some((_, spent)) = ledger
            .spent_roles
            .iter_mut()
            .find(|(role, _)| *role == atom.role)
        {
            *spent = spent.saturating_add(atom.cost);
        } else {
            ledger.spent_roles.push((atom.role, atom.cost));
        }
        AdmissionDisposition::Included
    } else if atom.required || atom.protected {
        handles.push(atom.atom_id.clone());
        AdmissionDisposition::HandleOnly
    } else {
        AdmissionDisposition::Suppressed
    };
    let reason = if capped && disposition == AdmissionDisposition::Included {
        LINEAGE_ASSERTABILITY_CAP_REASON.to_owned()
    } else {
        reason_for(disposition)
    };
    AdmissionDecision {
        atom_id: atom.atom_id.clone(),
        protected: atom.protected,
        reason,
        disposition,
    }
}

/// Bounded quarantine admissions for an incomplete-lineage scope.
///
/// Returns one `Quarantined` decision per affected atom in deterministic
/// atom-id order; clean atoms never appear, so the scope stays bounded.
/// Rebuild-from-clean-inputs signalling is emitted by the caller as an
/// unknown alongside these decisions.
fn seed_incomplete_lineage_quarantines(
    atoms: &[ContextAtom],
    scope: &BTreeSet<ArtifactId>,
) -> Vec<AdmissionDecision> {
    let mut seeded = Vec::with_capacity(scope.len());
    for atom_id in scope {
        let protected = match atoms.iter().find(|atom| &atom.atom_id == atom_id) {
            Some(atom) => atom.protected,
            None => false,
        };
        seeded.push(AdmissionDecision {
            atom_id: atom_id.clone(),
            disposition: AdmissionDisposition::Quarantined,
            reason: INCOMPLETE_LINEAGE_QUARANTINE_REASON.to_owned(),
            protected,
        });
    }
    seeded
}

/// Rebuild unknown threading the invalidated-derivative key set into output.
///
/// Returns one stable marker when [`revoked_derivative_invalidation_set`]
/// is non-empty for the revoked roots, and nothing otherwise — in particular
/// nothing on the empty-set `compile` path.
fn derivative_invalidation_unknown(
    revoked_handles: &BTreeSet<ArtifactId>,
    revoked_quarantined: &BTreeSet<ArtifactId>,
) -> Option<String> {
    if revoked_derivative_invalidation_set(revoked_handles, revoked_quarantined).is_empty() {
        None
    } else {
        Some(REVOKED_DERIVATIVE_INVALIDATION_UNKNOWN.to_owned())
    }
}

fn reason_for(disposition: AdmissionDisposition) -> String {
    match disposition {
        AdmissionDisposition::Included => "admitted_within_fence_and_budget".to_owned(),
        AdmissionDisposition::HandleOnly => {
            "whole_unit_budget_exhausted_handle_retained".to_owned()
        }
        AdmissionDisposition::Suppressed => "optional_unit_exceeds_bounded_budget".to_owned(),
        AdmissionDisposition::Quarantined => {
            "assertability_or_source_status_forbids_influence".to_owned()
        }
        AdmissionDisposition::Revalidate => {
            "freshness_or_generation_requires_revalidation".to_owned()
        }
    }
}

fn scorecard(
    units: &[ContextAtom],
    handles: &[ArtifactId],
    unknowns: &[String],
    fence: &StateFence,
) -> PacketQualityScorecard {
    let has = |role| {
        units.iter().any(|unit| unit.role == role)
            || units
                .iter()
                .any(|unit| unit.role == role && handles.iter().any(|id| id == &unit.atom_id))
    };
    PacketQualityScorecard {
        goal_coverage: has(ContextRole::Goal),
        epistemic_coverage: has(ContextRole::Evidence) || has(ContextRole::Model),
        provenance_coverage: units.iter().all(|unit| !unit.source_handles.is_empty()),
        fence_coherent: fence.validate().is_ok(),
        uncertainty_visible: !unknowns.is_empty() || has(ContextRole::Unknown),
        safety_coverage: has(ContextRole::Safety),
        decision_readiness: has(ContextRole::DecisionTail),
        bounded_omission: !handles.is_empty() || units.is_empty(),
    }
}

/// A durable blocking obligation, not a transient notification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionResolution {
    /// Still blocks dependent work.
    Open,
    /// Received but not resolved.
    Acknowledged,
    /// Closed by evidence-backed resolution.
    Resolved,
    /// Closed by an authorized waiver.
    Waived,
    /// Replaced by a later governed item.
    Superseded,
}

/// Explicit attention state included by the caller as a `ContextAtom`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalAttention {
    /// Stable attention identity.
    pub attention_id: ArtifactId,
    /// Why attention is required.
    pub problem: String,
    /// Source/evidence handles.
    pub evidence: Vec<ArtifactId>,
    /// Owner identity.
    pub owner: String,
    /// Affected action classes.
    pub affected_actions: Vec<String>,
    /// Current resolution state.
    pub resolution: AttentionResolution,
    /// State fence of the obligation.
    pub state_fence: StateFence,
}

impl CriticalAttention {
    /// Validate that an attention item cannot silently disappear.
    pub fn validate(&self) -> Result<(), ContextError> {
        text(self.problem.as_str(), "attention.problem")?;
        text(self.owner.as_str(), "attention.owner")?;
        if self.evidence.is_empty() {
            return Err(ContextError::MissingLineage {
                field: "attention.evidence",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ContextError::FenceMismatch)
    }
}

/// Historical cue-kind spellings retained only for explicit legacy decoding.
///
/// The local current `CueKind` duplicate (issue #832 reservation) is removed:
/// the single current owner is A-10 `eliot_cue_contracts::CueKind`. These
/// eight spellings preserve the exact historical wire identities
/// (`SCREAMING_SNAKE_CASE`) so frozen external records stay readable. They
/// never masquerade as current types: only [`decode_legacy_cue_kind`]
/// interprets them, and it converts exactly the three evidence-backed
/// one-to-one kinds.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum LegacyContextCueKind {
    Path,
    Symbol,
    Error,
    Command,
    Service,
    TaskClass,
    Concept,
    Problem,
}

/// Bounded failure of historical cue-kind decoding.
///
/// Every rejection names its exact disposition: unknown text outside the
/// eight historical spellings, the ambiguous `Path` split (file versus
/// directory needs path context this decoder does not have), or an
/// unsupported legacy kind with no evidence-backed current counterpart.
/// No caller text is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyCueKindError {
    /// Input is outside the eight historical spellings, missing, or empty.
    UnknownSpelling,
    /// `Path` cannot split into `FilePath`/`DirPath` without path context.
    AmbiguousSplit { kind: LegacyContextCueKind },
    /// Historical kind with no exact current counterpart.
    UnsupportedLegacy { kind: LegacyContextCueKind },
}

impl std::fmt::Display for LegacyCueKindError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSpelling => write!(formatter, "unknown historical cue-kind spelling"),
            Self::AmbiguousSplit { kind } => write!(
                formatter,
                "historical cue kind {kind:?} is ambiguous without path context"
            ),
            Self::UnsupportedLegacy { kind } => write!(
                formatter,
                "historical cue kind {kind:?} has no exact current counterpart"
            ),
        }
    }
}

impl std::error::Error for LegacyCueKindError {}

/// Decode one historical cue-kind spelling to the current A-10 kind.
///
/// Converts exactly `SYMBOL`, `TASK_CLASS`, and `CONCEPT` one-to-one.
/// `PATH` fails as [`LegacyCueKindError::AmbiguousSplit`];
/// `ERROR`, `COMMAND`, `SERVICE`, and `PROBLEM` fail as
/// [`LegacyCueKindError::UnsupportedLegacy`]; anything else (including
/// empty or differently-cased text) fails as
/// [`LegacyCueKindError::UnknownSpelling`]. Ambiguous input stays
/// rejected rather than guessing context.
pub fn decode_legacy_cue_kind(value: &str) -> Result<CueKind, LegacyCueKindError> {
    match value {
        "SYMBOL" => Ok(CueKind::Symbol),
        "TASK_CLASS" => Ok(CueKind::TaskClass),
        "CONCEPT" => Ok(CueKind::Concept),
        "PATH" => Err(LegacyCueKindError::AmbiguousSplit {
            kind: LegacyContextCueKind::Path,
        }),
        "ERROR" => Err(LegacyCueKindError::UnsupportedLegacy {
            kind: LegacyContextCueKind::Error,
        }),
        "COMMAND" => Err(LegacyCueKindError::UnsupportedLegacy {
            kind: LegacyContextCueKind::Command,
        }),
        "SERVICE" => Err(LegacyCueKindError::UnsupportedLegacy {
            kind: LegacyContextCueKind::Service,
        }),
        "PROBLEM" => Err(LegacyCueKindError::UnsupportedLegacy {
            kind: LegacyContextCueKind::Problem,
        }),
        _ => Err(LegacyCueKindError::UnknownSpelling),
    }
}

/// Observable event that can activate exact memory handles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationCue {
    /// Scope in which this cue is meaningful.
    pub scope: String,
    /// Cue category.
    pub kind: CueKind,
    /// Raw observed cue value.
    pub value: String,
    /// Exact record handles bound to this cue.
    pub handles: Vec<ArtifactId>,
}

impl ActivationCue {
    /// Normalize without changing canonical path spelling.
    ///
    /// Trim-only applies to path-like and symbol kinds
    /// (`FilePath`, `DirPath`, `Symbol`), preserving the historical
    /// `Path`/`Symbol` behavior; every other current kind collapses
    /// whitespace exactly as before.
    pub fn normalized_value(&self) -> Result<String, ContextError> {
        text(self.scope.as_str(), "cue.scope")?;
        text(self.value.as_str(), "cue.value")?;
        let normalized = match self.kind {
            CueKind::FilePath | CueKind::DirPath | CueKind::Symbol => self.value.trim().to_owned(),
            _ => self
                .value
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase(),
        };
        if self.handles.is_empty() {
            return Err(ContextError::MissingLineage {
                field: "cue.handles",
            });
        }
        Ok(normalized)
    }
}

/// Result of exact-first cue firing, before context admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CueActivation {
    /// Exact scope and normalized cue key.
    pub scope: String,
    /// Matched handles in deterministic order.
    pub handles: Vec<ArtifactId>,
}

/// Deterministic, model-free cue index projection.
///
/// Declaration order follows the single A-10 owner
/// (`eliot_cue_contracts::CueKind`); this crate defines no kind ordering
/// of its own.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CueIndex {
    entries: Vec<(String, CueKind, String, Vec<ArtifactId>)>,
}

impl CueIndex {
    /// Build an immutable index from admitted bindings.
    pub fn build(cues: impl IntoIterator<Item = ActivationCue>) -> Result<Self, ContextError> {
        let mut entries = Vec::new();
        for cue in cues {
            entries.push((
                cue.scope.clone(),
                cue.kind,
                cue.normalized_value()?,
                cue.handles,
            ));
        }
        entries.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        Ok(Self { entries })
    }

    /// Fire exact matches only; broad semantic spreading belongs to a later route.
    pub fn fire_exact(
        &self,
        scope: &str,
        kind: CueKind,
        value: &str,
    ) -> Result<CueActivation, ContextError> {
        text(scope, "cue.scope")?;
        text(value, "cue.value")?;
        let normalized = match kind {
            CueKind::FilePath | CueKind::DirPath | CueKind::Symbol => value.trim().to_owned(),
            _ => value
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase(),
        };
        let mut handles = self
            .entries
            .iter()
            .filter(|entry| entry.0 == scope && entry.1 == kind && entry.2 == normalized)
            .flat_map(|entry| entry.3.iter().cloned())
            .collect::<Vec<_>>();
        handles.sort();
        handles.dedup();
        Ok(CueActivation {
            scope: scope.to_owned(),
            handles,
        })
    }
}

/// Request for a bounded, read-only orientation packet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationRequest {
    /// Question to orient.
    pub question: String,
    /// Scope for every selected handle.
    pub scope: String,
    /// Exact task fence.
    pub state_fence: StateFence,
    /// Maximum number of source handles to expose.
    pub maximum_handles: u32,
}

/// Deterministic orientation bundle handed to Dreamer or an agent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationPacket {
    /// Original bounded question.
    pub question: String,
    /// Scope and fence used for selection.
    pub scope: String,
    /// Exact handles selected by the cue route.
    pub handles: Vec<ArtifactId>,
    /// Explicit gap when no complete orientation was possible.
    pub gaps: Vec<String>,
    /// Fence for downstream revalidation.
    pub state_fence: StateFence,
}

impl OrientationRequest {
    /// Construct an exact-first packet from cue activations.
    pub fn orient(&self, activations: &[CueActivation]) -> Result<OrientationPacket, ContextError> {
        text(self.question.as_str(), "orientation.question")?;
        text(self.scope.as_str(), "orientation.scope")?;
        self.state_fence
            .validate()
            .map_err(|_| ContextError::FenceMismatch)?;
        if self.maximum_handles == 0 {
            return Err(ContextError::InvalidText {
                field: "orientation.maximum_handles",
            });
        }
        let mut handles = activations
            .iter()
            .flat_map(|activation| activation.handles.iter().cloned())
            .collect::<Vec<_>>();
        handles.sort();
        handles.dedup();
        handles.truncate(self.maximum_handles as usize);
        let gaps = if handles.is_empty() {
            vec!["no_exact_activation_for_question".to_owned()]
        } else if activations
            .iter()
            .flat_map(|activation| activation.handles.iter())
            .count()
            > handles.len()
        {
            vec!["orientation_handle_budget_exhausted".to_owned()]
        } else {
            Vec::new()
        };
        Ok(OrientationPacket {
            question: self.question.clone(),
            scope: self.scope.clone(),
            handles,
            gaps,
            state_fence: self.state_fence.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{LegacyContextCueKind, LegacyCueKindError, decode_legacy_cue_kind};
    use eliot_cue_contracts::CueKind;

    #[test]
    fn legacy_decoder_covers_all_historical_spellings_explicitly() {
        assert_eq!(decode_legacy_cue_kind("SYMBOL"), Ok(CueKind::Symbol));
        assert_eq!(decode_legacy_cue_kind("TASK_CLASS"), Ok(CueKind::TaskClass));
        assert_eq!(decode_legacy_cue_kind("CONCEPT"), Ok(CueKind::Concept));
        assert_eq!(
            decode_legacy_cue_kind("PATH"),
            Err(LegacyCueKindError::AmbiguousSplit {
                kind: LegacyContextCueKind::Path
            })
        );
        for (spelling, kind) in [
            ("ERROR", LegacyContextCueKind::Error),
            ("COMMAND", LegacyContextCueKind::Command),
            ("SERVICE", LegacyContextCueKind::Service),
            ("PROBLEM", LegacyContextCueKind::Problem),
        ] {
            assert_eq!(
                decode_legacy_cue_kind(spelling),
                Err(LegacyCueKindError::UnsupportedLegacy { kind }),
                "{spelling} must carry its explicit legacy disposition"
            );
        }
        for unknown in ["", "PATHS", "symbol", "Symbol", "TASK-CLASS", "CONCEPT "] {
            assert_eq!(
                decode_legacy_cue_kind(unknown),
                Err(LegacyCueKindError::UnknownSpelling),
                "{unknown:?} must stay rejected, never guessed"
            );
        }
    }
}
