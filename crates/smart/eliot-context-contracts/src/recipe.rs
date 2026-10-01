//! Stable reusable `ContextRecipe` policy definition (I12.13).
//!
//! [`ContextRecipe`](crate::ContextRecipe) in `atom.rs` is the
//! compilation-bound instance: it carries the [`ContextBinding`](crate::ContextBinding),
//! a [`DecisionRevision`](crate::DecisionRevision) whose `recipe_revision` is a
//! `TaskRevision`, the provider/role denominator, the per-role loss rules, the
//! capacity envelope, the predecessor, the invalidation, and a
//! `recipe_sha256` digest that covers all of that — the compilation binding
//! included. I12.13 asks for a *versioned, reusable* recipe that is approved
//! once and applied to many compilations, and W1 of #1724 requires that this
//! policy definition be separated from that instance and from the task/input
//! revision. This module is that definition.
//!
//! It is a sibling of [`ContextRecipe`](crate::ContextRecipe), not a second
//! copy of it and not a replacement. Nothing here re-declares the denominator,
//! the per-role loss rules, the capacity envelope or the compilation binding;
//! those stay where the instance already keeps them. The two halves are joined
//! by [`ContextRecipePolicy::binds_recipe`], which compares the ORIGINAL
//! recorded values of both records.
//!
//! Field-by-field mapping of the I12.13 `ContextRecipe` block
//! (`docs/architecture/I12-13-context-compiler.md`, lines 35-50):
//!
//! ```text
//! recipe_id_revision_and_digest              -> policy_id, policy_revision, policy_sha256
//! applicable_task_route_impact_and_governance
//!   _profiles                                -> applicability
//! stage_graph_and_order                      -> stages (declared order is the graph order)
//! candidate_feature_configuration            -> candidate_features
//! admission_and_suppression_policy           -> admission
//! instruction_directive_evidence_tool_and
//!   result_budgets                           -> section_budgets
//! protected_reasoning_review_and_margin
//!   _reserve                                 -> protected_reserve
//! layout_position_and_repetition_policy      -> layout
//! omission_and_expansion_policy              -> omission
//! scorecard_blocking_dimensions              -> blocking_dimensions
//! execution_contour_and_generation           -> execution
//! empirical_qualification_and_counter_metrics-> qualification
//! parent_supersession_kill_and_rollback      -> supersession
//! ```
//!
//! Already covered by the existing instance and therefore deliberately absent
//! here: the provider/role denominator, the per-role loss rules
//! ([`RoleLossRule`](crate::RoleLossRule)), the route/output/review reserves
//! ([`CapacityLimits`](crate::CapacityLimits)), and the parent policy reference
//! (`ContextRecipe::predecessor`).
//!
//! I12.13 also states that a recipe cannot weaken the `Decision Safety Floor`,
//! `ContextAtomPolicy` classes, authority/privacy, active `Recovery`/`Conflict`
//! Directives, reversible omission or proof ceilings. The two rules that
//! belong to the policy record itself are enforced here: a mandatory role of
//! the instance may never be a role this policy declares suppressible, and a
//! privacy/authority omission may never be declared reversible. Everything
//! else in that sentence needs the independent owners and belongs to W3, not
//! to this schema.
//!
//! # W2 — resolving exactly one applicable approved recipe
//!
//! A [`ContextRecipePolicy`] is a versioned definition, not a selection. The
//! selection itself is [`ApprovedRecipeCatalogue`]: the owner-published
//! configuration that carries the compilation's own applicability dimensions
//! and compiler-generation profile, the independent
//! [`GoverningContextRequirements`] every candidate is measured against, and
//! every approved candidate revision the owner currently holds.
//! [`ApprovedRecipeCatalogue::resolve`] returns exactly one
//! [`ResolvedContextRecipe`] or a typed [`RecipeResolutionRefusal`]. There is
//! no first-match, no latest-by-name and no default. Precedence used to be the
//! owner-minted [`PolicyRevision`]; #1724 W6 replaced it with the owner's
//! explicit current-recipe pointer, because a revision number is not an
//! activation authority. An unresolved governing input still refuses before any
//! candidate is examined.
//!
//! # W3 — validating against independent governing requirements
//!
//! [`GoverningContextRequirements`] composes records owned elsewhere in this
//! crate: the owner-issued [`DecisionSafetyFloor`](crate::DecisionSafetyFloor),
//! the six applicability inputs of
//! [`QualityApplicability`](crate::QualityApplicability) over the independent
//! [`QUALITY_APPLICABILITY_INPUTS`](crate::QUALITY_APPLICABILITY_INPUTS)
//! denominator, scorecard dimensions drawn from the independent
//! [`QUALITY_DIMENSIONS`] denominator, omission reasons owned by
//! [`OmissionRecord`](crate::OmissionRecord), and
//! [`ProofCeiling`](eliot_receipts::ProofCeiling). No field is derived from a
//! candidate recipe, so the comparisons in
//! [`GoverningContextRequirements::authorize`] are never a candidate checked
//! against a copy of its own content.
//!
//! Two named owners are deliberately NOT read here and are recorded as
//! boundaries instead of being replaced by a stand-in:
//!
//! * I7.11 `ContextAtomPolicy` class comparison is owned by
//!   `eliot-context-admission` (`FloorAtomPolicy`). That crate depends on this
//!   one, so this contract cannot read its record content; the only binding
//!   available here is the Decision Safety Floor evidence identity compared in
//!   `authorize`. `RecipeAdmissionPolicy::admission_rule` has no owner record to
//!   be compared against anywhere in the workspace, which is why it is outside
//!   the certified digest domain rather than inside it.
//! * I12.13's active `Recovery`/`Conflict` Directives have no record type
//!   anywhere in the workspace. The only owner spelling is
//!   [`QualityApplicabilityInput::ActiveDirective`], so that is what is
//!   resolved: an unresolved directive input refuses the whole resolution.
//!
//! # W7 — supersession and rollback as new owner decisions
//!
//! [`RecipeActivationRecord`] is the decision that made an approved revision
//! current; it names the exact predecessor it supersedes and the applicability
//! and compiler-generation scope it is confined to.
//! [`RecipeRevocationRecord`] is the decision that killed or rolled a revision
//! back, naming the previous compatible revision a rollback returns to.
//!
//! Neither is stored ON the approved content. That is the whole point: a kill or
//! a rollback used to be a mutable field of [`RecipeSupersession`], so revoking
//! a revision meant editing the bytes that revision's `policy_sha256` covers.
//! Every View and `ContextEconomyReceipt` produced under it still names that
//! digest, so the edit silently relabelled historical evidence instead of
//! superseding it. With the decision held beside the content, the approved
//! revision is immutable forever: a View that names `policy_sha256` P keeps
//! naming P whether or not P was later revoked, and a re-resolution under a
//! newer catalogue produces a different `resolution_sha256` rather than
//! restamping the old one.
//!
//! # W3k9 — the completed section budget contract
//!
//! #1725 implementation step 1 completes [`ContextSectionBudget`] rather than
//! adding a second budget type. The record now states, for each semantic role,
//! the whole-unit boundary kind, the minimum whole-unit count AND the exact
//! identities that count is about, the planning maximum with the route profile
//! it is expressed in, the permitted loss/handle representation, the
//! whole-unit degradation disposition and the feature-disable rule.
//!
//! Three refusals carry that completion:
//!
//! 1. two budgets for one semantic role are refused on the role alone, so an
//!    identical repeat is not silently merged either, and a disagreement with
//!    the compilation-bound instance's own
//!    [`RoleLossRule`](crate::RoleLossRule) for that role is refused in
//!    [`ContextRecipePolicy::binds_recipe`] rather than resolved by preferring
//!    one record;
//! 2. [`ContextSectionBudget::validate_admitted_section`] checks membership of
//!    the exact required references AND the independent whole-unit floor against
//!    the observed admitted set, so a count can never stand in for membership
//!    and neither is derived from the other;
//! 3. that same check admits a required reference only in a representation the
//!    role's `omission_or_handle_policy` permits, reusing the crate's single
//!    [`LossPolicy::allows`] rule — `NON_DROPPABLE` admits `WHOLE` only, so a
//!    handle never becomes the whole unit.
//!
//! The policy is inside the existing digest: [`ContextRecipePolicy`] serializes
//! its whole approved content into
//! [`CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN`](crate::CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN),
//! so changing any of these fields changes `policy_sha256`, and
//! `DecisionRevision::policy_sha256` binds the compilation to it. No second
//! digest and no change to an existing domain or to the compilation-bound
//! instance's own `canonical_policy_digest`. The shape change is the explicit
//! versioned migration recorded on
//! [`CONTEXT_RECIPE_POLICY_SCHEMA_VERSION`].
//!
//! # W6 — recipes change only through the existing improvement gate
//!
//! I12.13: "It may be changed only as an Improvement Candidate through replay,
//! shadow/canary and rollback." The restated invariant is that a candidate, a
//! valid hash, a smaller packet or a positive token saving is NOT permission to
//! activate. Three mechanisms carry it, and none of them is a new gate: the
//! existing [`RecipeActivationRecord`] is the owner promotion decision, and this
//! slice adds only what it did not state.
//!
//! 1. [`ApprovedRecipeCatalogue::current`] is the current recipe pointer, an
//!    explicit required owner-published field. [`ApprovedRecipeCatalogue::resolve`]
//!    reads it and nothing else. It previously took the applicable candidate
//!    with the greatest [`PolicyRevision`], which made a revision NUMBER the
//!    authority: publishing a newer approved candidate silently promoted it
//!    with no promotion decision at all. Revision ordering no longer appears in
//!    selection. A held, unrevoked, applicable candidate the pointer does not
//!    name is refused as
//!    [`RecipeResolutionRefusal::ApplicableCandidateNotCurrent`] rather than
//!    selected or ignored.
//! 2. [`RecipePromotionBasis`] is the basis the promotion decision was made
//!    under, held on that decision. `InitialBuiltInBaseline` preserves an
//!    explicitly approved initial/built-in baseline with no fabricated prior
//!    experimental evidence — it is the only basis with no predecessor, and it
//!    is the only one that may carry
//!    [`RecipeQualificationState::Unqualified`].
//!    `ImprovementCandidate` carries a [`RecipeImprovementCandidate`] naming the
//!    exact predecessor, the exact proposed content, the applicability it was
//!    triaged against, the exact baseline, the replay/holdout evidence, the
//!    shadow-or-isolated-canary evidence and the counter-metrics measured
//!    against that baseline.
//! 3. An unqualified metric stays labelled unqualified. `RecipeQualificationState`
//!    is inside `policy_sha256`, so relabelling a revision produces a different
//!    identity and the pointer stops naming it; the gate adds the other half —
//!    a revision promoted as an Improvement Candidate whose own recorded metrics
//!    are still `Unqualified` is refused, because the replay/holdout and
//!    shadow/isolated-canary evidence the decision cites is then evidence about
//!    different metrics than the revision it promotes.
//!
//! The improvement candidate itself is an OWNER record and is referenced, not
//! copied: `eliot-improvement` (C1) depends on this crate, so `ImprovementSurface`
//! cannot be named from here and the surface identity is not restated as a
//! second vocabulary. This is the same owner-reference convention already used
//! for [`RecipeAdmissionPolicy::admission_rule`],
//! [`RecipeAdmissionPolicy::safety_floor`] and
//! [`RecipeQualification::qualification`].
//!
//! Run-time qualification experiments are later product-phase work. Nothing here
//! runs one, records an outcome, or defaults a missing one: the gate refuses
//! when the evidence reference is absent.
//!
//! # A2 — a certified member is one this path reads
//!
//! Acceptance A2: "A policy change alters the recipe revision/digest and
//! effective compiler behavior together; ignored settings cannot be certified."
//! `policy_sha256` is the approved revision's identity, so every member inside it
//! is a claim that this path runs what that member declares. Eight members were
//! inside the digest with no reader outside their own same-struct validator, which
//! made a certified behavioural no-op expressible: publish a revision that changes
//! one of them, recompute the digest, issue the matching activation, and every
//! identity that embeds the published document moves while the delivered content
//! does not. NONE of the eight is excluded from the digest — I12.13 names every one
//! of them as content of the versioned `ContextRecipe` (lines 33-49), so dropping
//! any of them would be the weakening A2 forbids. Each is now READ:
//!
//! ```text
//! section_budgets[].unit_boundary_kind
//!     require_executable compares it with EXECUTED_SECTION_UNIT_BOUNDARY, the
//!     whole-unit boundary kind the assembly projection actually emits per record
//! section_budgets[].omission_or_handle_policy
//!     binds_recipe compares it with the instance's own per-role
//!     RoleLossRule::loss_policy for the same role
//! section_budgets[].minimum_required_whole_units
//! section_budgets[].planning_maximum_whole_units
//!     authorize compares both with the governing Decision Safety Floor's own
//!     mandatory member count for that role
//! layout.role_positions[].position
//!     RecipeLayoutPolicy::validate requires the declared positions to be the
//!     contiguous zero-based sequence 0..n in declaration order (a total order,
//!     not a set of keys), and the renderer APPLIES it:
//!     eliot-context-assembly's render::render sorts by this position, so a
//!     re-hashed revision that reverses the order changes the delivered bytes
//!     and their output_digest instead of being certified and ignored
//! qualification.qualification
//!     validate_promotion_basis requires it to be owner evidence the activating
//!     decision itself cites
//! admission.admission_rule
//!     authorize compares it with GoverningContextRequirements'
//!     own required_admission_rule, the admission rule this decision boundary
//!     must admit under
//! qualification.counter_metrics[].forbidden_movement
//!     covers_declared_counter_metrics compares the (metric, direction) pair, so a
//!     candidate measured against a guardrail forbidding one direction cannot
//!     promote a revision whose guardrail forbids the other
//! protected_reserve.reserves.{reasoning,review,evidence}_reserve
//! protected_reserve.margin_reserve
//!     authorises_protected_reserves requires the declared protected reserves and
//!     margin to fit inside the governing Decision Safety Floor's own route
//!     capacity; ProtectedReservePolicy::validate refuses a zero margin outright
//! ```
//!
//! Stated without minimising it: ALL EIGHT readers are REFUSALS, not passes.
//! None confirms a declaration and lets the compilation proceed on it — each
//! comparison fails the dependent compilation when the declaration disagrees with
//! an independent value. Six compare against content another record owns
//! (`omission_or_handle_policy` against the instance's own per-role loss rule,
//! `qualification.qualification` and `admission.admission_rule` against the
//! independent governing requirements and the owner evidence the promotion
//! decision itself cites, `position` against the order the execution path renders
//! under, `forbidden_movement` against the candidate's own measured guardrail set,
//! and the protected reserves against the governing floor's route capacity). One
//! compares against a compiled-in executed fact stated in this contract
//! (`unit_boundary_kind` against [`EXECUTED_SECTION_UNIT_BOUNDARY`]), and one
//! refuses an incoherent value outright (`margin_reserve == 0`). A policy cannot
//! reach a delivered View by declaring one of these settings unless something
//! outside the policy agrees with it.
//!
//! Four residuals stay named rather than papered over.
//!
//! 1. The two whole-unit amounts are read only as a FLOOR. Raising
//!    `minimum_required_whole_units` or `planning_maximum_whole_units` above what
//!    the independent Decision Safety Floor requires still moves `policy_sha256`
//!    and moves no delivered byte, because the whole-unit allocation algorithm is
//!    #1725's and is deliberately not reimplemented here. The direction that was
//!    not enforced at all is now enforced — LOWERING either below the floor's
//!    mandatory member count refuses with `MissingFloor` — so neither can weaken
//!    a floor while moving the identity.
//! 2. [`EXECUTED_ORDERING_REVISION`] and [`EXECUTED_SECTION_UNIT_BOUNDARY`] are
//!    stated by this contract rather than published by the execution owner in
//!    [`RecipeExecutionSupport`]. Both comparisons fail CLOSED when the two
//!    disagree, so the coupling cannot be silently wrong, but promoting both
//!    facts into [`RecipeExecutionSupport`] is the change that would let the
//!    execution owner state them, and it is owed there.
//! 3. `admission.admission_rule` and the protected reserves are bound by IDENTITY
//!    and by CAPACITY CEILING respectively. I7.11 places the admission rule's own
//!    class comparison in `eliot-context-admission`, which depends on this crate,
//!    so the rule's content stays there; and no execution path in this workspace
//!    measures a reserve figure, so the reserve bound is "this fits in the
//!    owner's route capacity", not "this was spent".
//! 4. `counter_metrics[].forbidden_movement` is read on the improvement-candidate
//!    promotion arm only, because a built-in baseline activation carries no
//!    measured metric set to read it against. It stays certified: I12.13 names the
//!    guardrail direction as recipe content, and excluding it would let two
//!    revisions differing only in direction collide on one `policy_sha256`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::{ArtifactId, PolicyRevision};
use eliot_receipts::{ProofCeiling, ProtectedReserves};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdmittedContextSet, BoundaryDisposition, BoundaryTransformerRevision, BoundaryUnitKind,
    ContextError, ContextRecipe, DecisionSafetyFloor, LossPolicy, NonRecoverableReason,
    OmissionReason, QUALITY_DIMENSIONS, QualityApplicability, QualityApplicabilityInput,
    QualityDimension, RepresentationKind, SemanticRole, validate_digest, validate_text,
};

/// Wire revision of the reusable recipe policy definition.
///
/// The field is required, the struct denies unknown fields, and an unknown
/// revision is refused by name. It is deliberately not
/// [`CONTEXT_CONTRACT_VERSION`](crate::CONTEXT_CONTRACT_VERSION): the
/// compilation-bound instance keeps the crate contract version, and a policy
/// revision is a different versioned thing. A payload that predates this
/// definition therefore cannot decode into it, which is the versioned
/// migration — the old accepted bytes stay with the old instance shape rather
/// than being read as a policy that declares nothing.
///
/// #1725 W3k9 raised this from `1` to `2`. Revision `2` adds the required
/// [`ContextSectionBudget`] members `required_exact_references` and
/// `planning_route_profile`; revision `1` carried only a whole-unit count and a
/// bare planning figure. Nothing is defaulted and nothing is reinterpreted:
/// `required_exact_references` has no `#[serde(default)]`, so a revision-`1`
/// payload cannot decode into a revision-`2` policy, and `validate()` refuses a
/// `policy_schema_version` that is not this exact constant. An approved
/// revision-`1` policy stays readable as revision-`1` bytes under its own
/// recorded `policy_sha256`; re-issuing it as revision `2` is a new owner
/// decision naming the exact required identities and the route profile its
/// planning maximum is expressed in, because revision `1` never said which
/// whole units were required or in which profile.
pub const CONTEXT_RECIPE_POLICY_SCHEMA_VERSION: u32 = 2;

/// Digest domain separator for the reusable recipe policy.
///
/// A separate domain from `ContextRecipe::canonical_policy_digest`, which
/// covers the compilation binding. One digest cannot be both a reusable policy
/// identity and a per-compilation instance identity, and the existing domain is
/// left exactly as it was.
///
/// #1724 A2 leaves this domain and the covered byte stream untouched. Every
/// member of a policy is inside it and every member is now read by the
/// validating or executing path, so there is nothing to exclude and no accepted
/// digest moves. Excluding a member I12.13 names as recipe content would be the
/// weakening A2 forbids, and moving the domain would invalidate every published
/// `policy_sha256` to fix nothing.
pub const CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN: &str = "eliot.smart.context.recipe-policy.v1";

/// The one stage the current consolidated Context execution path runs.
///
/// I12.13 lets a policy declare a stage graph. The current path is a single
/// whole-unit compile-and-render stage with no predecessor edge, so a policy
/// that declares anything else is declaring a graph this path does not execute.
/// #1724 W4 requires such a policy to refuse at the point it would otherwise be
/// certified into a digest, instead of contributing a stage graph nothing reads.
pub const EXECUTED_CONTEXT_STAGE: &str = "context.stage.compile-and-render.v1";

/// The whole-unit disposition the current path applies when a section floor
/// cannot be preserved.
///
/// `BlockDependentDecisionOrEffect` is the boundary owner's own vocabulary for
/// "this operation applied no permitted degradation": the current admission and
/// assembly path never narrows, extracts or summarizes a section behind a
/// declared degradation, it refuses the dependent operation instead
/// (`ContextError::MissingFloor` / `AssemblyError::Incomplete`). A policy that
/// declares any other degradation would be describing behaviour this path does
/// not have, so it refuses rather than being digested.
pub const EXECUTED_SECTION_DEGRADATION: BoundaryDisposition =
    BoundaryDisposition::BlockDependentDecisionOrEffect;

/// The whole-unit boundary kind the current path emits for one budgeted section.
///
/// I12.13 `ContextSectionBudget.unit_boundary_kind` names what one whole unit of
/// a section is, and the current assembly projection emits exactly one
/// independently addressable `BoundaryMetadataEnvelope` of kind
/// [`BoundaryUnitKind::Unit`] per admitted record
/// (`eliot-context-assembly/src/boundary.rs::unit_envelope`); the `Batch`
/// envelope it also emits is the source-less parent of the whole admitted set,
/// not a section unit. `ContiguousExtract`, `CallResultPair` and `EvidenceEdge`
/// describe composite units this path never builds per section, so a policy
/// declaring one would be certifying a boundary the delivered packet does not
/// have. [`ContextRecipePolicy::require_executable`] refuses that by name.
///
/// This is the contract's own statement of an executed fact, in the same
/// standing as [`EXECUTED_CONTEXT_STAGE`], [`EXECUTED_SECTION_DEGRADATION`],
/// [`EXECUTED_REPETITION_POLICY`] and [`EXECUTED_ORDERING_REVISION`]. It is not
/// a member of [`RecipeExecutionSupport`] because that record is the execution
/// owner's, and adding a member to it is a change to a struct the owner builds;
/// naming the fact here keeps this change inside one file. Promoting it into
/// `RecipeExecutionSupport` is the change that would let the execution owner
/// state the kind it emits instead of this contract asserting it. Until then the
/// coupling fails CLOSED: a policy declaring another kind refuses.
const EXECUTED_SECTION_UNIT_BOUNDARY: BoundaryUnitKind = BoundaryUnitKind::Unit;

/// The repetition treatment the current renderer actually applies.
///
/// `render` projects every admitted record exactly once, and
/// `AdmittedContextSet::validate` already refuses a repeated atom identity, so
/// the implemented treatment is "an identical unit is represented once". A
/// policy declaring a bounded repeat allowance or a repeat suppression would be
/// describing behaviour the renderer does not have.
pub const EXECUTED_REPETITION_POLICY: RecipeRepetitionPolicy =
    RecipeRepetitionPolicy::DeduplicateIdentical;

/// The rendered-ordering SCHEME this contract authorises the executing path to
/// run.
///
/// #1724 W4. [`RecipeExecutionSupport::ordering_revision`] is the executing path's
/// own statement of the scheme it renders under, and until now nothing read it: it
/// was validated as non-empty text and then compared with nothing, so the revision
/// a delivered View's execution identity carried was never checked against the one
/// this contract would authorise. [`ContextRecipePolicy::require_executable`] now
/// compares the two and refuses when they differ, which closes that half of the gap;
/// the other half — the role order the recipe declares — is closed by the renderer
/// itself, which now sorts by the approved revision's `layout.role_positions`
/// (`eliot-context-assembly` `render::render`) instead of the `SemanticRole` enum's
/// own ordinal. A policy declaring `Negative` before `Goal` therefore renders
/// `Negative` first, and a policy declaring a different order changes the delivered
/// bytes and their `output_digest`.
///
/// The SCHEME is "declared role position, then provider, then atom identity", and
/// it is the same string the assembly crate's `ASSEMBLY_ORDERING_REVISION` names.
/// This crate must not depend on the assembly crate that depends on it, so the two
/// spellings are separate constants kept in step by hand and the coupling is
/// deliberately fail-closed: if the execution owner changes the scheme revision
/// without changing this constant, every publication refuses with
/// [`RecipeResolutionRefusal::UnsupportedSetting`] naming
/// `recipe_support.ordering_revision` instead of quietly rendering under an order
/// this contract has not checked. The execution owner further qualifies this scheme
/// with the approved revision's own `policy_sha256` when it stamps a view, so two
/// revisions with different declared orders carry different executed ordering
/// revisions on their Views.
///
/// The same pattern, and the same owed promotion, applies to
/// [`EXECUTED_SECTION_UNIT_BOUNDARY`]: both facts are stated here because this file
/// is the only one in scope, and both belong in [`RecipeExecutionSupport`] once the
/// execution owner can restate them.
pub const EXECUTED_ORDERING_REVISION: &str = "a18.declared-role-position.v1";

/// I12.13 `applicable_task_route_impact_and_governance_profiles`.
///
/// A profile is a named, owner-declared profile, not a caller-supplied value
/// and not a default. Each list is a genuine set: order inside one list carries
/// no meaning and is canonicalized by sorting for the policy digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeApplicability {
    /// Task profiles this policy revision applies to.
    pub task_profiles: Vec<String>,
    /// Route profiles this policy revision applies to.
    pub route_profiles: Vec<String>,
    /// Impact profiles this policy revision applies to.
    pub impact_profiles: Vec<String>,
    /// Governance profiles this policy revision applies to.
    pub governance_profiles: Vec<String>,
}

impl RecipeApplicability {
    fn validate(&self) -> Result<(), ContextError> {
        for (profiles, field) in [
            (
                &self.task_profiles,
                "recipe_policy.applicability.task_profiles",
            ),
            (
                &self.route_profiles,
                "recipe_policy.applicability.route_profiles",
            ),
            (
                &self.impact_profiles,
                "recipe_policy.applicability.impact_profiles",
            ),
            (
                &self.governance_profiles,
                "recipe_policy.applicability.governance_profiles",
            ),
        ] {
            if profiles.is_empty() || profiles.len() > 64 {
                return Err(ContextError::Bounds { field });
            }
            let mut seen = BTreeSet::new();
            for profile in profiles {
                validate_text(profile, field)?;
                if !seen.insert(profile.as_str()) {
                    return Err(ContextError::Duplicate(field));
                }
            }
        }
        Ok(())
    }

    /// Whether `declared` names every profile `required` names, in all four
    /// dimensions.
    ///
    /// This is the applicability rule I12.13 states and it is a subset test,
    /// not an equality test: a policy may apply more broadly than one
    /// compilation needs, but it cannot apply to a compilation whose declared
    /// profile it never names. A candidate therefore cannot widen its own
    /// applicability by editing the compilation side of the comparison.
    fn declared_covers(declared: &Self, required: &Self) -> bool {
        [
            (&declared.task_profiles, &required.task_profiles),
            (&declared.route_profiles, &required.route_profiles),
            (&declared.impact_profiles, &required.impact_profiles),
            (&declared.governance_profiles, &required.governance_profiles),
        ]
        .into_iter()
        .all(|(declared, required)| required.iter().all(|profile| declared.contains(profile)))
    }
}

/// One stage of the policy's stage graph.
///
/// The graph is expressed by `predecessors`; the position in
/// [`ContextRecipePolicy::stages`] is the execution order. A predecessor must
/// already have been declared, so the declared order is a topological order of
/// the graph instead of an arbitrary permutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeStage {
    /// Stable identity of this stage inside the policy.
    pub stage_id: ArtifactId,
    /// Semantic role this stage contributes.
    pub semantic_role: SemanticRole,
    /// Stages that must precede this one.
    pub predecessors: Vec<ArtifactId>,
}

/// I12.13 `admission_and_suppression_policy`.
///
/// The rule and floor are owner references, not copies: the admission rule and
/// the Decision Safety Floor keep their own owners and their own records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeAdmissionPolicy {
    /// Owner admission rule applied under this policy revision.
    ///
    /// #1724 A2: validated as bounded non-empty identity text here, and READ by
    /// [`GoverningContextRequirements::authorize`], which requires it to equal the
    /// admission rule the independent owner requirements name as mandatory for
    /// this decision boundary. The rule's own content stays at its owner
    /// (`eliot-context-admission`, which depends on this crate); what is bound
    /// here is the revision's identity claim about which rule it admits under.
    pub admission_rule: ArtifactId,
    /// Owner Decision Safety Floor this policy revision admits against.
    pub safety_floor: ArtifactId,
    /// Roles this policy revision may suppress at admission.
    ///
    /// A role listed here may never also be a mandatory role of the
    /// compilation-bound instance; `binds_recipe` refuses that combination
    /// with the crate's own floor vocabulary.
    pub suppressible_roles: Vec<SemanticRole>,
}

impl RecipeAdmissionPolicy {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.admission_rule.as_str(),
            "recipe_policy.admission.admission_rule",
        )?;
        validate_text(
            self.safety_floor.as_str(),
            "recipe_policy.admission.safety_floor",
        )?;
        if self.suppressible_roles.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.admission.suppressible_roles",
            });
        }
        let mut seen = BTreeSet::new();
        for role in &self.suppressible_roles {
            if !seen.insert(*role) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.admission.suppressible_roles",
                ));
            }
        }
        Ok(())
    }
}

/// I12.13 `ContextSectionBudget`, expressed in whole addressable units.
///
/// The unit count is a count of whole units, never a token slice: a JSON
/// object, URL, source identity, tool call/result pair or evidence edge is
/// never divided to make a budget fit. The budget algorithm itself is not here
/// and is not reimplemented here.
///
/// #1725 W3k9 completed the record. It already carried the semantic role, the
/// unit boundary kind, a minimum whole-unit count, a planning maximum, a
/// loss/handle policy, a degradation disposition and the feature-disable rule;
/// what it could not state was WHICH units the count refers to and in which
/// route profile the planning maximum is expressed. A count is not membership:
/// N admitted units of the right role say nothing about which N they are, so
/// `required_exact_references` is a separate required member and
/// [`ContextSectionBudget::validate_admitted_section`] checks the two
/// independently rather than deriving one from the other.
///
/// #1724 A2 — who reads each member, and where:
///
/// * `unit_boundary_kind` — [`ContextRecipePolicy::require_executable`], against
///   the kind the assembly projection actually emits. A kind this path does not
///   emit refuses the dependent compilation by name.
/// * `omission_or_handle_policy` — [`ContextRecipePolicy::binds_recipe`], against
///   the compilation-bound instance's own per-role
///   [`RoleLossRule`](crate::RoleLossRule). A policy that declares a different
///   representation contract for a role than the instance the renderer actually
///   applies refuses.
/// * `minimum_required_whole_units` and `planning_maximum_whole_units` —
///   [`GoverningContextRequirements::authorize`], against the governing
///   [`DecisionSafetyFloor`](crate::DecisionSafetyFloor)'s own mandatory member
///   count for this role. Each mandatory floor member is one non-droppable whole
///   unit of that role, so a budget that may retain fewer of them than the floor
///   requires is a floor weakening and refuses with
///   [`ContextError::MissingFloor`]. This validation reads the amounts; the
///   amount ceiling above the floor is a planning bound owned by #1725's
///   whole-unit algorithm, which is deliberately not reimplemented here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextSectionBudget {
    /// Semantic role this budget governs.
    pub semantic_role: SemanticRole,
    /// Whole-unit boundary kind of this section.
    ///
    /// Read by [`ContextRecipePolicy::require_executable`]; see the type
    /// documentation.
    pub unit_boundary_kind: BoundaryUnitKind,
    /// Minimum complete units retained for this role.
    ///
    /// The independent whole-unit floor. It is never satisfied by
    /// `required_exact_references`: that list is the set of exact identities,
    /// and this figure is the count that must be reached in the admitted set.
    ///
    /// Read against the governing floor's mandatory member count in
    /// [`GoverningContextRequirements::authorize`].
    pub minimum_required_whole_units: u64,
    /// Exact identities this section must contain, by role.
    ///
    /// Required and non-empty: a section that names no exact required identity
    /// could only ever be checked by count, which is exactly the gap #1725
    /// closes. These are unit identities — an `EvidenceAtom`, `ClaimCard`,
    /// `ToolDefinition`, source-catalog entry, `WorkItem`, completed causal stage
    /// or normative anchor — and a JSON object, URL, source identity, call/result
    /// pair or evidence edge is never a member of this set, because none of
    /// them is one whole unit. A genuine set: order carries no meaning and it
    /// is sorted for the policy digest.
    pub required_exact_references: Vec<ArtifactId>,
    /// Owner proof references for this section's protected floor.
    pub protected_floor_refs: Vec<ArtifactId>,
    /// Planning maximum, in the same whole units as
    /// `minimum_required_whole_units`, that is, in the whole units of
    /// `unit_boundary_kind`.
    ///
    /// Read against the governing floor's mandatory member count in
    /// [`GoverningContextRequirements::authorize`].
    pub planning_maximum_whole_units: u64,
    /// Route profile the planning maximum is expressed in.
    ///
    /// The maximum is a planning figure for one named profile, not a universal
    /// one, so it names the profile it is valid for. It must be a profile this
    /// revision's own `applicability.route_profiles` declares; a maximum
    /// measured for a profile the revision does not apply to describes nothing
    /// this revision runs.
    pub planning_route_profile: String,
    /// Permitted omission/handle policy for this section.
    ///
    /// This is also the handle rule: a handle may satisfy one of
    /// `required_exact_references` only where this policy permits
    /// [`RepresentationKind::Handle`], so a `NON_DROPPABLE` section can never be
    /// satisfied by a handle standing in for the complete unit.
    ///
    /// Read against the instance's own per-role loss rule in
    /// [`ContextRecipePolicy::binds_recipe`].
    pub omission_or_handle_policy: LossPolicy,
    /// Whole-unit degradation applied when the section cannot be preserved.
    pub degradation_behavior: BoundaryDisposition,
    /// Whether the optional feature is disabled when the floor cannot be kept.
    pub disable_feature_when_floor_cannot_be_preserved: bool,
}

impl ContextSectionBudget {
    fn validate(&self) -> Result<(), ContextError> {
        // The two amounts are the only members of this struct with an internal
        // incoherence to refuse: a section that must retain no complete unit, or
        // that may plan for fewer units than it must retain, does not describe a
        // budget at all. Their binding to the independent governing floor is
        // `GoverningContextRequirements::authorize`, which is the only place that
        // holds the floor record; see the type documentation.
        if self.minimum_required_whole_units == 0 {
            return Err(ContextError::MissingField(
                "section_budget.minimum_required_whole_units",
            ));
        }
        self.validate_required_references()?;
        if self.planning_maximum_whole_units < self.minimum_required_whole_units {
            return Err(ContextError::CapacityExceeded);
        }
        validate_text(
            &self.planning_route_profile,
            "section_budget.planning_route_profile",
        )?;
        if self.protected_floor_refs.len() > 64 {
            return Err(ContextError::Bounds {
                field: "section_budget.protected_floor_refs",
            });
        }
        let mut seen = BTreeSet::new();
        for reference in &self.protected_floor_refs {
            validate_text(reference.as_str(), "section_budget.protected_floor_refs")?;
            if !seen.insert(reference.clone()) {
                return Err(ContextError::Duplicate(
                    "section_budget.protected_floor_refs",
                ));
            }
        }
        Ok(())
    }

    /// The exact required identities of this section, distinct and bounded.
    ///
    /// Absent or empty is refused: the required member is what makes membership
    /// checkable at all, and a budget that carries only a whole-unit count
    /// cannot be checked against the identities the floor names.
    fn validate_required_references(&self) -> Result<(), ContextError> {
        if self.required_exact_references.is_empty() {
            return Err(ContextError::MissingField(
                "section_budget.required_exact_references",
            ));
        }
        if self.required_exact_references.len() > 64 {
            return Err(ContextError::Bounds {
                field: "section_budget.required_exact_references",
            });
        }
        let mut seen = BTreeSet::new();
        for reference in &self.required_exact_references {
            validate_text(
                reference.as_str(),
                "section_budget.required_exact_references",
            )?;
            if !seen.insert(reference.clone()) {
                return Err(ContextError::Duplicate(
                    "section_budget.required_exact_references",
                ));
            }
        }
        Ok(())
    }

    /// Validate one compiled section against this budget on the OBSERVED
    /// admitted set.
    ///
    /// Two independent checks, and neither can stand in for the other:
    ///
    /// * membership — every identity in `required_exact_references` is present
    ///   among the admitted records of this section's semantic role. The
    ///   comparison is against the admitted records themselves, so a section
    ///   that admits the wrong units while meeting the count is refused by name
    ///   instead of being counted as satisfied.
    /// * the independent floor — the number of distinct admitted whole units of
    ///   this role reaches `minimum_required_whole_units`. The count is taken
    ///   from the admitted records and never from `required_exact_references`,
    ///   so a policy cannot meet its own floor by naming its membership list.
    ///
    /// Each required reference must additionally be carried in a representation
    /// this role's `omission_or_handle_policy` permits. That is the handle rule
    /// and it is not derived from the floor or from the count: under
    /// [`LossPolicy::NonDroppable`] only [`RepresentationKind::Whole`] is
    /// permitted, so a handle can never satisfy a required reference of a
    /// non-droppable section.
    ///
    /// The observed set is an input, never derived here: this function reads the
    /// admitted records and this budget's own declarations and compares them to
    /// each other, so it does not certify an admission decision of its own.
    pub fn validate_admitted_section(
        &self,
        admitted: &AdmittedContextSet,
    ) -> Result<(), ContextError> {
        let mut admitted_units: BTreeMap<&ArtifactId, RepresentationKind> = BTreeMap::new();
        for record in &admitted.records {
            if record.candidate.provider_role.role != self.semantic_role {
                continue;
            }
            let atom_id = &record.candidate.atom_id;
            if admitted_units
                .insert(atom_id, record.candidate.representation.kind())
                .is_some()
            {
                // One identity counted once: a repeated identity cannot stand in
                // for a second whole unit in the floor below.
                return Err(ContextError::Duplicate("admitted.atom_id"));
            }
        }
        for reference in &self.required_exact_references {
            let representation = admitted_units
                .get(reference)
                .ok_or(ContextError::MissingFloor)?;
            if !self.omission_or_handle_policy.allows(*representation) {
                return Err(ContextError::WholeUnitRequired);
            }
        }
        let admitted_whole_units =
            u64::try_from(admitted_units.len()).map_err(|_| ContextError::Overflow)?;
        if admitted_whole_units < self.minimum_required_whole_units {
            return Err(ContextError::MissingFloor);
        }
        Ok(())
    }
}

/// I12.13 `protected_reasoning_review_and_margin_reserve`.
///
/// The protected reasoning and review figures are the Context-budget owner's
/// existing [`ProtectedReserves`] record, reused verbatim rather than
/// re-declared, and the instance's [`CapacityLimits`](crate::CapacityLimits)
/// keeps the route, output and review capacity envelope. Only the protected
/// margin, which has no such owner record, is declared here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectedReservePolicy {
    /// Context-budget owner record of the protected reasoning/review reserve.
    ///
    /// #1724 A2: READ by
    /// [`GoverningContextRequirements::authorises_protected_reserves`] against
    /// the governing Decision Safety Floor's own route capacity. The three
    /// figures were inside `policy_sha256` with no reader anywhere.
    pub reserves: ProtectedReserves,
    /// Protected margin reserve not covered by `reserves`.
    ///
    /// #1724 A2: READ by
    /// [`GoverningContextRequirements::authorises_protected_reserves`] against the
    /// governing Decision Safety Floor's own route capacity, and refused outright
    /// at zero here. It was inside `policy_sha256` whose only reader was this
    /// validator, so raising it from 1 to 1000 moved `policy_sha256` and moved no
    /// delivered byte — a certified behavioural no-op, which is the second half of
    /// A2. It is now bounded by an owner record this crate does not own, so a
    /// revision cannot claim a protected reserve the independent floor's route
    /// capacity does not hold. No execution path in this workspace measures a
    /// margin figure, so the ceiling is a capacity coherence bound rather than a
    /// spent-amount check; that residual is named in the module header.
    pub margin_reserve: u64,
}

impl ProtectedReservePolicy {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.reserves.owner_ref.as_str(),
            "recipe_policy.protected_reserve.reserves.owner_ref",
        )?;
        if self.margin_reserve == 0 {
            return Err(ContextError::MissingField(
                "recipe_policy.protected_reserve.margin_reserve",
            ));
        }
        Ok(())
    }
}

/// Declared layout position of one semantic role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeRolePosition {
    /// Positioned role.
    pub semantic_role: SemanticRole,
    /// Zero-based layout position.
    ///
    /// #1724 A2: read as an ordinal in two places, not as a duplicate-detection key.
    /// [`RecipeLayoutPolicy::validate`] requires the declared positions to be the
    /// contiguous zero-based sequence `0..n` in the order they are declared, so a
    /// set of unique but gapped or arbitrarily large positions is refused rather
    /// than certified. Before that, this member was only inserted into a set to
    /// detect a duplicate, so it certified an order this path could not state.
    /// The renderer now READS it: `eliot-context-assembly`'s `render::render` takes
    /// the roles in position order and sorts the rendered payload by it, refusing a
    /// role the approved revision does not position. A re-hashed revision that
    /// reverses the declared order therefore renders in the reversed order and
    /// changes the delivered `output_digest`, instead of being certified and
    /// ignored by a renderer sorting the `SemanticRole` enum's own ordinal.
    pub position: u32,
}

/// How repeated content is treated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum RecipeRepetitionPolicy {
    /// An identical unit is represented once.
    #[serde(rename = "DEDUPLICATE_IDENTICAL")]
    DeduplicateIdentical,
    /// A repeated unit is suppressed.
    #[serde(rename = "SUPPRESS_REPEATED")]
    SuppressRepeated,
    /// Repetition is permitted up to an explicit bound.
    #[serde(rename = "BOUNDED")]
    Bounded {
        /// Upper bound on repeats of one unit; never zero.
        maximum_repeats: u32,
    },
}

impl RecipeRepetitionPolicy {
    fn validate(self) -> Result<(), ContextError> {
        if matches!(self, Self::Bounded { maximum_repeats: 0 }) {
            return Err(ContextError::Bounds {
                field: "recipe_policy.layout.repetition.maximum_repeats",
            });
        }
        Ok(())
    }
}

/// I12.13 `layout_position_and_repetition_policy`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeLayoutPolicy {
    /// Declared position of each configured role.
    pub role_positions: Vec<RecipeRolePosition>,
    /// Repetition treatment applied to repeated content.
    pub repetition: RecipeRepetitionPolicy,
}

impl RecipeLayoutPolicy {
    /// Validate the declared layout as a total order, not as a set of keys.
    ///
    /// #1724 A2. The positions must be exactly `0..role_positions.len()` in the
    /// order they are declared, so the declaration is a total order rather than a
    /// set of keys. A set of unique but gapped positions is refused because it
    /// cannot be the order of anything, and the positions are read here as
    /// ordinals rather than only as duplicate-detection keys. This function only
    /// decides that the declared order IS well formed; that this execution path
    /// renders under exactly this order is not decided here but performed by
    /// `eliot-context-assembly`'s `render::render`, which reads these positions.
    fn validate(&self) -> Result<(), ContextError> {
        if self.role_positions.is_empty() || self.role_positions.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.layout.role_positions",
            });
        }
        let mut roles = BTreeSet::new();
        for (index, declared) in self.role_positions.iter().enumerate() {
            if !roles.insert(declared.semantic_role) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.layout.role_positions.semantic_role",
                ));
            }
            if usize::try_from(declared.position).ok() != Some(index) {
                return Err(ContextError::InvalidField(
                    "recipe_policy.layout.role_positions.position",
                ));
            }
        }
        self.repetition.validate()
    }
}

/// I12.13 `omission_and_expansion_policy`.
///
/// A permitted reason that is not declared non-recoverable is reversible: an
/// exact expansion handle stands in for it. A privacy or authority omission
/// has no reversible form, so I12.13's ceiling that a recipe "cannot weaken
/// ... authority/privacy, reversible omission" requires those two reasons to
/// be declared non-recoverable here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeOmissionPolicy {
    /// Omission reasons this policy revision may apply.
    pub permitted_reasons: Vec<OmissionReason>,
    /// Reasons that may stand as an explicitly non-recoverable omission.
    pub non_recoverable_reasons: Vec<NonRecoverableReason>,
}

/// The non-recoverable reason an omitted protected unit must declare.
const fn non_recoverable_for(reason: OmissionReason) -> Option<NonRecoverableReason> {
    match reason {
        OmissionReason::Privacy => Some(NonRecoverableReason::Privacy),
        OmissionReason::Authority => Some(NonRecoverableReason::Authority),
        _ => None,
    }
}

impl RecipeOmissionPolicy {
    fn validate(&self) -> Result<(), ContextError> {
        if self.permitted_reasons.is_empty() || self.permitted_reasons.len() > 16 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.omission.permitted_reasons",
            });
        }
        if self.non_recoverable_reasons.len() > 16 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.omission.non_recoverable_reasons",
            });
        }
        let mut permitted = BTreeSet::new();
        for reason in &self.permitted_reasons {
            if !permitted.insert(*reason) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.omission.permitted_reasons",
                ));
            }
        }
        let mut declared = BTreeSet::new();
        for reason in &self.non_recoverable_reasons {
            if !declared.insert(*reason) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.omission.non_recoverable_reasons",
                ));
            }
        }
        for reason in &self.permitted_reasons {
            if let Some(required) = non_recoverable_for(*reason)
                && !declared.contains(&required)
            {
                return Err(ContextError::OmissionHandleInvalid);
            }
        }
        Ok(())
    }
}

/// I12.13 `execution_contour_and_generation`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeExecutionContour {
    /// Owner execution contour this policy revision runs under.
    pub contour: ArtifactId,
    /// Contour generation; the owner's own monotone execution generation.
    pub generation: u64,
    /// Exact transform identity and configuration the compilation is bound to.
    pub transform: BoundaryTransformerRevision,
}

impl RecipeExecutionContour {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.contour.as_str(), "recipe_policy.execution.contour")?;
        if self.generation == 0 {
            return Err(ContextError::MissingField(
                "recipe_policy.execution.generation",
            ));
        }
        validate_text(
            self.transform.transformer_id.as_str(),
            "recipe_policy.execution.transform.transformer_id",
        )?;
        validate_digest(
            &self.transform.configuration_sha256,
            "recipe_policy.execution.transform.configuration_sha256",
        )
    }
}

/// Whether this revision's recorded metrics are empirically qualified.
///
/// I12.13 and the improvement gate both require an unqualified metric to stay
/// labelled unqualified, so the state is recorded rather than inferred from the
/// presence of a qualification reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeQualificationState {
    /// Recorded metrics are not empirically qualified.
    Unqualified,
    /// Recorded metrics are qualified by the cited owner evidence.
    Qualified,
}

/// Direction in which a guardrail metric may not worsen.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CounterMetricMovement {
    /// The metric must not increase.
    Increase,
    /// The metric must not decrease.
    Decrease,
}

/// One counter-metric guardrail of this policy revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeCounterMetric {
    /// Owner metric identity.
    pub metric_id: ArtifactId,
    /// Direction in which the metric may not worsen.
    ///
    /// #1724 A2: read by
    /// [`RecipeImprovementCandidate::covers_declared_counter_metrics`], which
    /// requires the guardrail a candidate actually measured against the baseline
    /// to forbid the SAME direction for the same metric. A candidate measured
    /// against `Increase` cannot promote a revision whose guardrail is
    /// `Decrease`, because its replay/holdout and canary evidence is then
    /// evidence about a different guardrail than the one the revision ships.
    /// That comparison is on the improvement-candidate promotion arm, which is
    /// the only arm on which a guardrail direction has a measured set to be
    /// compared against: a [`RecipePromotionBasis::InitialBuiltInBaseline`]
    /// activation carries no candidate and therefore no measurements, so its
    /// declared direction is a claim the owner approval itself makes rather than
    /// a claim replay/canary evidence supports. It stays inside `policy_sha256`
    /// because I12.13 names the guardrail direction as content of the versioned
    /// recipe, and it is read wherever a measured set exists to read it against.
    pub forbidden_movement: CounterMetricMovement,
}

/// I12.13 `empirical_qualification_and_counter_metrics`.
///
/// #1724 A2: `qualification` is an owner evidence reference, and an unresolved
/// owner reference inside a certified digest is a setting nothing reads. It is
/// resolved by
/// [`ApprovedRecipeCatalogue::validate_promotion_basis`], which requires it to be
/// owner evidence the activating promotion decision itself cites — the baseline
/// approval for [`RecipePromotionBasis::InitialBuiltInBaseline`], or the
/// candidate/replay-holdout/canary evidence for
/// [`RecipePromotionBasis::ImprovementCandidate`]. A revision therefore cannot
/// claim qualification by an evidence reference that no owner decision ever
/// made.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeQualification {
    /// Owner qualification evidence reference for this revision's metrics.
    ///
    /// Read by
    /// [`ApprovedRecipeCatalogue::validate_promotion_basis`]; see the type
    /// documentation.
    pub qualification: ArtifactId,
    /// Qualification state of the recorded metrics.
    pub state: RecipeQualificationState,
    /// Guardrail metrics that may not worsen under this revision.
    pub counter_metrics: Vec<RecipeCounterMetric>,
}

impl RecipeQualification {
    /// Closed guardrail-set bound, shared with the W6 improvement candidate so
    /// both records are checked by one rule instead of two that can drift. The
    /// two field names are passed separately because every refusal names the
    /// exact field it is about, and a runtime concatenation would not be a
    /// `&'static str`.
    pub(crate) fn validate_counter_metrics(
        metrics: &[RecipeCounterMetric],
        field: &'static str,
        metric_field: &'static str,
    ) -> Result<(), ContextError> {
        if metrics.len() > 64 {
            return Err(ContextError::Bounds { field });
        }
        let mut seen = BTreeSet::new();
        for metric in metrics {
            validate_text(metric.metric_id.as_str(), metric_field)?;
            if !seen.insert(metric.metric_id.clone()) {
                return Err(ContextError::Duplicate(metric_field));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.qualification.as_str(),
            "recipe_policy.qualification.qualification",
        )?;
        Self::validate_counter_metrics(
            &self.counter_metrics,
            "recipe_policy.qualification.counter_metrics",
            "recipe_policy.qualification.counter_metrics.metric_id",
        )
    }
}

/// I12.13 `parent_supersession_kill_and_rollback`.
///
/// The parent revision is the existing `ContextRecipe::predecessor` of the
/// instance, and the invalidation identity is its existing `invalidation`;
/// neither is repeated here. What the policy record keeps is the ONE owner
/// decision that made this revision current: [`RecipeActivationRecord`].
///
/// #1724 W7 removed the kill and rollback identities from this struct on
/// purpose. They were mutable fields ON the approved content, so a kill or a
/// rollback had to be expressed by editing the revision it revoked — which
/// re-hashes the approved content, destroys the immutability of the revision
/// that produced an existing View, and lets a later receipt be re-labelled
/// under a new `policy_sha256`. They are now
/// [`RecipeRevocationRecord`]s held beside the candidates: a new owner decision
/// naming the revoked identity, never a rewrite of that identity's bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeSupersession {
    /// Scoped activation record that made this revision current.
    pub activation: ArtifactId,
}

impl RecipeSupersession {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.activation.as_str(),
            "recipe_policy.supersession.activation",
        )
    }
}

/// Digest domain separator for one owner activation decision.
pub const RECIPE_ACTIVATION_DIGEST_DOMAIN: &str = "eliot.smart.context.recipe-activation.v1";

/// Digest domain separator for one owner kill/rollback decision.
pub const RECIPE_REVOCATION_DIGEST_DOMAIN: &str = "eliot.smart.context.recipe-revocation.v1";

/// One `PacketCompiler`-surface Improvement Candidate proposed against a recipe.
///
/// #1724 W6. I12.13: "It may be changed only as an Improvement Candidate through
/// replay, shadow/canary and rollback." Every element that sentence names is a
/// field here, and the two that only this crate can compare — the proposed
/// content and the guardrails — are compared against the real records by
/// [`RecipePromotionBasis`]'s check inside
/// [`ApprovedRecipeCatalogue::validate`], not merely recorded.
///
/// The candidate, the replay/holdout evidence and the canary evidence are OWNER
/// records and are referenced, not copied. `eliot-improvement` (C1) depends on
/// this crate, so its `ImprovementSurface` cannot be named here and its closed
/// vocabulary is deliberately not restated; naming a candidate by its owner
/// identity keeps the reference resolvable at the owner instead of duplicating
/// a spelling that a variant rename could desynchronize.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeImprovementCandidate {
    /// Owner Improvement Candidate record for this proposal.
    pub candidate: ArtifactId,
    /// Exact approved revision this candidate proposes to supersede.
    ///
    /// A candidate is tied to one predecessor, not to "whatever is current when
    /// it is promoted", so a decision cannot silently rebase a proposal onto a
    /// revision it was never measured against.
    pub predecessor: RecipePolicyIdentity,
    /// Exact approved revision this candidate proposes to make current.
    ///
    /// Checked against the activated identity of the promotion decision, so a
    /// candidate cannot be cited as the evidence for different content than the
    /// content it was measured on.
    pub proposed: RecipePolicyIdentity,
    /// Applicability this candidate was triaged and measured against.
    pub applicability: RecipeApplicability,
    /// Exact approved revision the replay/holdout comparison is measured
    /// against.
    ///
    /// Required, not defaulted: a comparison with no named baseline has no
    /// denominator. A built-in baseline carries no candidate record at all, so it
    /// never reaches this field.
    pub baseline: RecipePolicyIdentity,
    /// Owner replay/holdout evidence reference.
    pub replay_holdout: ArtifactId,
    /// Owner shadow or isolated canary evidence reference.
    pub canary: ArtifactId,
    /// Guardrail counter-metrics measured against `baseline`.
    ///
    /// Required and non-empty: a candidate measured against no guardrail is not
    /// a gated candidate, and a smaller packet or a positive token saving is
    /// not a guardrail.
    pub counter_metrics: Vec<RecipeCounterMetric>,
}

impl RecipeImprovementCandidate {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.candidate.as_str(), "improvement.candidate")?;
        self.predecessor.validate_identity()?;
        self.proposed.validate_identity()?;
        if self.predecessor == self.proposed {
            return Err(ContextError::IdentityConflict);
        }
        self.applicability.validate()?;
        self.baseline.validate_identity()?;
        validate_text(self.replay_holdout.as_str(), "improvement.replay_holdout")?;
        validate_text(self.canary.as_str(), "improvement.canary")?;
        RecipeQualification::validate_counter_metrics(
            &self.counter_metrics,
            "improvement.counter_metrics",
            "improvement.counter_metrics.metric_id",
        )?;
        if self.counter_metrics.is_empty() {
            return Err(ContextError::MissingField("improvement.counter_metrics"));
        }
        Ok(())
    }

    /// Whether every counter-metric the proposed policy declares was actually
    /// measured against the baseline, in the same direction.
    ///
    /// This is the content comparison a positive token saving cannot pass: a
    /// candidate that measured fewer guardrails than its proposed policy declares
    /// has not been checked against the guardrails it would ship with. It is
    /// candidate-versus-policy, NOT candidate-versus-an-independent denominator,
    /// because no owner record of the required guardrail set exists; the residual
    /// is named in the delivery report rather than papered over with a field
    /// invented here.
    ///
    /// #1724 A2: the comparison is on the (metric, direction) pair, not on the
    /// metric identity alone. A candidate measured against a guardrail that
    /// forbids `Increase` has evidence about that guardrail, and promoting a
    /// revision whose guardrail forbids `Decrease` for the same metric would ship
    /// a direction the cited evidence never measured. `forbidden_movement` had no
    /// reader anywhere in the tree before this, and it stays inside
    /// `policy_sha256`: I12.13 names the guardrail direction as content of the
    /// versioned recipe, and this is the reader that makes approving it mean
    /// something.
    fn covers_declared_counter_metrics(&self, policy: &ContextRecipePolicy) -> bool {
        policy.qualification.counter_metrics.iter().all(|declared| {
            self.counter_metrics.iter().any(|measured| {
                measured.metric_id == declared.metric_id
                    && measured.forbidden_movement == declared.forbidden_movement
            })
        })
    }
}

/// The basis an owner promotion decision was made under.
///
/// #1724 W6. Exactly two, and the choice is the whole gate: a revision is either
/// the explicitly approved initial/built-in baseline, or it is an Improvement
/// Candidate that carried replay/holdout and shadow-or-isolated-canary evidence.
/// There is no third "the owner felt like it" arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipePromotionBasis {
    /// The explicitly approved initial or built-in baseline.
    ///
    /// It has no predecessor — a revision that supersedes one is a successor, not
    /// a baseline — and it is the only basis that may record
    /// [`RecipeQualificationState::Unqualified`]. I7.11: the existing byte/token
    /// figures are unvalidated planning candidates until a route-specific profile
    /// is qualified, and this is how that is preserved rather than fabricated
    /// away: the baseline is current because it was explicitly approved, and its
    /// metrics keep saying they are unqualified.
    InitialBuiltInBaseline {
        /// Owner approval that established this revision as the initial
        /// baseline. Required, so a baseline is an approval and not a default.
        approval: ArtifactId,
    },
    /// An Improvement Candidate promoted through the existing improvement gate.
    ImprovementCandidate {
        /// The exact candidate, its predecessor, proposed content, applicability,
        /// baseline, replay/holdout, canary and counter-metrics.
        candidate: Box<RecipeImprovementCandidate>,
    },
}

impl RecipePromotionBasis {
    fn validate(&self) -> Result<(), ContextError> {
        match self {
            Self::InitialBuiltInBaseline { approval } => {
                validate_text(approval.as_str(), "promotion.initial_baseline.approval")
            }
            Self::ImprovementCandidate { candidate } => candidate.validate(),
        }
    }
}

/// The owner decision that made one approved revision current.
///
/// #1724 W7. A newly accepted recipe produces a NEW immutable revision plus this
/// record, which is what makes the change observable: it names the activated
/// identity, the exact predecessor it supersedes, the applicability and
/// compiler-generation scope the activation is confined to, and — #1724 W6 — the
/// [`RecipePromotionBasis`] the decision was made under. A decision confined
/// to a scope cannot be read as a global activation, and
/// [`ApprovedRecipeCatalogue::validate`] refuses a compilation whose own
/// applicability the activation does not cover, so a future decision revalidates
/// applicability rather than inheriting an old activation.
///
/// `basis` is inside `record_sha256`, so the gate evidence and the decision that
/// relied on it are covered by the decision's own recorded digest. Changing the
/// basis of an existing activation re-hashes that decision, which stops
/// [`ApprovedRecipeCatalogue::current`] from naming it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeActivationRecord {
    /// Owner decision identity that made `activated` current.
    pub decision: ArtifactId,
    /// The exact approved revision this decision activated.
    pub activated: RecipePolicyIdentity,
    /// The exact revision this one supersedes, when there is a predecessor.
    ///
    /// It is an identity, not content: the predecessor keeps its own bytes and
    /// its own activation, so a View produced under it still names a revision
    /// the owner actually approved.
    pub predecessor: Option<RecipePolicyIdentity>,
    /// Applicability scope this activation is confined to.
    pub applicability: RecipeApplicability,
    /// Compiler-generation scope this activation is confined to.
    pub execution: RecipeExecutionContour,
    /// The gate basis this decision was made under.
    pub basis: RecipePromotionBasis,
    /// Digest of this activation record.
    pub record_sha256: String,
}

#[derive(Serialize)]
struct RecipeActivationDigestInput<'a> {
    domain: &'static str,
    activation: &'a RecipeActivationRecord,
}

impl RecipeActivationRecord {
    /// Compute the digest expected in `record_sha256`.
    pub fn canonical_record_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.record_sha256 = "0".repeat(64);
        let input = RecipeActivationDigestInput {
            domain: RECIPE_ACTIVATION_DIGEST_DOMAIN,
            activation: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_activation.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validate the closed decision record and its own recorded digest.
    ///
    /// The basis is validated here for its own shape; the comparisons that need
    /// the activated policy's CONTENT — that the candidate's proposed content is
    /// this revision, that it covered this revision's guardrails, that a
    /// candidate's recorded metrics are qualified — belong to
    /// [`ApprovedRecipeCatalogue::validate`], which is the only place that holds
    /// the approved bytes.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.decision.as_str(), "recipe_activation.decision")?;
        self.activated.validate_identity()?;
        if let Some(predecessor) = &self.predecessor {
            if predecessor == &self.activated {
                return Err(ContextError::IdentityConflict);
            }
            predecessor.validate_identity()?;
        }
        self.applicability.validate()?;
        self.execution.validate()?;
        self.basis.validate()?;
        validate_digest(&self.record_sha256, "recipe_activation.record_sha256")?;
        if self.canonical_record_digest()? != self.record_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// The owner decision that killed or rolled back one approved revision.
///
/// #1724 W7. Rollback is a NEW decision naming the previous COMPATIBLE revision
/// the owner still holds; it never overwrites the revoked revision's content and
/// never edits the revision being returned to. `replacement` absent is a kill
/// with no replacement; present is a rollback to an identity the catalogue still
/// carries, which [`ApprovedRecipeCatalogue::validate`] requires.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeRevocationRecord {
    /// Owner decision identity that revoked the revision.
    pub decision: ArtifactId,
    /// The exact approved revision this decision revoked.
    pub revoked: RecipePolicyIdentity,
    /// The previous compatible revision this returns to, for a rollback.
    pub replacement: Option<RecipePolicyIdentity>,
    /// Digest of this revocation record.
    pub record_sha256: String,
}

#[derive(Serialize)]
struct RecipeRevocationDigestInput<'a> {
    domain: &'static str,
    revocation: &'a RecipeRevocationRecord,
}

impl RecipeRevocationRecord {
    /// Compute the digest expected in `record_sha256`.
    pub fn canonical_record_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.record_sha256 = "0".repeat(64);
        let input = RecipeRevocationDigestInput {
            domain: RECIPE_REVOCATION_DIGEST_DOMAIN,
            revocation: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_revocation.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validate the closed decision record and its own recorded digest.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.decision.as_str(), "recipe_revocation.decision")?;
        validate_text(self.revoked.policy_id.as_str(), "recipe_revocation.revoked")?;
        validate_digest(
            &self.revoked.policy_sha256,
            "recipe_revocation.revoked.policy_sha256",
        )?;
        if let Some(replacement) = &self.replacement {
            if replacement == &self.revoked {
                return Err(ContextError::IdentityConflict);
            }
            validate_text(
                replacement.policy_id.as_str(),
                "recipe_revocation.replacement",
            )?;
            validate_digest(
                &replacement.policy_sha256,
                "recipe_revocation.replacement.policy_sha256",
            )?;
        }
        validate_digest(&self.record_sha256, "recipe_revocation.record_sha256")?;
        if self.canonical_record_digest()? != self.record_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// One approved, reusable `ContextRecipe` policy revision.
///
/// The `policy_id`/`policy_revision` pair identifies the revision; the
/// `policy_sha256` binds its exact content in its own digest domain. None of
/// the three is a `TaskRevision`: the task/input revision belongs to the
/// compilation-bound instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextRecipePolicy {
    /// Wire revision of this policy definition.
    pub policy_schema_version: u32,
    /// Stable identity of this policy.
    pub policy_id: ArtifactId,
    /// Reusable policy revision, distinct from any task revision.
    pub policy_revision: PolicyRevision,
    /// Digest of this policy's content in the policy digest domain.
    pub policy_sha256: String,
    /// Task/route/impact/governance applicability.
    pub applicability: RecipeApplicability,
    /// Stage graph, in execution order.
    pub stages: Vec<RecipeStage>,
    /// Candidate features this revision configures.
    pub candidate_features: Vec<SemanticRole>,
    /// Admission and suppression policy.
    pub admission: RecipeAdmissionPolicy,
    /// Whole-unit section budgets.
    pub section_budgets: Vec<ContextSectionBudget>,
    /// Protected reasoning/review reserve and protected margin.
    pub protected_reserve: ProtectedReservePolicy,
    /// Layout, position and repetition policy.
    pub layout: RecipeLayoutPolicy,
    /// Omission and expansion policy.
    pub omission: RecipeOmissionPolicy,
    /// Scorecard dimensions that block this revision.
    pub blocking_dimensions: Vec<QualityDimension>,
    /// Execution contour and generation.
    pub execution: RecipeExecutionContour,
    /// Empirical qualification and counter-metrics.
    pub qualification: RecipeQualification,
    /// Activation, kill and rollback decisions.
    pub supersession: RecipeSupersession,
}

#[derive(Serialize)]
struct RecipePolicyDigestInput<'a> {
    domain: &'static str,
    policy: &'a ContextRecipePolicy,
}

impl ContextRecipePolicy {
    /// Compute the digest expected in `policy_sha256` for this policy.
    ///
    /// The whole policy is inside the domain. #1724 A2 did not narrow it: every
    /// member a policy declares is now read by the validating or executing path,
    /// so there is no member whose approval would move this digest and nothing
    /// else. Genuine sets are sorted; `stages` is not, because stage order is
    /// meaning and not a set. `ContextRecipe::canonical_policy_digest` is
    /// untouched: its domain still covers the compilation binding.
    pub fn canonical_policy_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.policy_sha256 = "0".repeat(64);
        canonical.applicability.task_profiles.sort();
        canonical.applicability.route_profiles.sort();
        canonical.applicability.impact_profiles.sort();
        canonical.applicability.governance_profiles.sort();
        canonical.candidate_features.sort();
        canonical.admission.suppressible_roles.sort();
        canonical
            .section_budgets
            .sort_by_key(|budget| budget.semantic_role);
        // The section policy itself is inside this digest, not beside it: every
        // `ContextSectionBudget` member — the semantic role, the unit kind, the
        // minimum whole-unit count, the exact required references, the planning
        // maximum and its route profile, the permitted loss/handle policy, the
        // degradation disposition and the feature-disable rule — is covered
        // because the whole approved content is what is serialized. Ordering
        // normalization is the only thing added: `required_exact_references` is
        // a genuine set, so two revisions that name the same units in a
        // different order are the same policy, and `semantic_role` is unique
        // per budget after `validate()` refused a duplicate role.
        for budget in &mut canonical.section_budgets {
            budget.required_exact_references.sort();
        }
        canonical
            .layout
            .role_positions
            .sort_by_key(|declared| declared.semantic_role);
        canonical.omission.permitted_reasons.sort();
        canonical.omission.non_recoverable_reasons.sort();
        canonical.blocking_dimensions.sort();
        canonical
            .qualification
            .counter_metrics
            .sort_by(|left, right| left.metric_id.cmp(&right.metric_id));
        let input = RecipePolicyDigestInput {
            domain: CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN,
            policy: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_policy.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validate the closed policy record and its own recorded digest.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.policy_schema_version != CONTEXT_RECIPE_POLICY_SCHEMA_VERSION {
            return Err(ContextError::InvalidField(
                "recipe_policy.policy_schema_version",
            ));
        }
        validate_text(self.policy_id.as_str(), "recipe_policy.policy_id")?;
        validate_digest(&self.policy_sha256, "recipe_policy.policy_sha256")?;
        self.applicability.validate()?;
        let features = self.configured_features()?;
        self.validate_stage_order(&features)?;
        self.admission.validate()?;
        for role in &self.admission.suppressible_roles {
            if !features.contains(role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        self.validate_section_budgets(&features)?;
        self.protected_reserve.validate()?;
        self.layout.validate()?;
        // #1724 A2: `role_positions` is documented as the declared position of
        // EACH configured role, and `require_executable` compares that order
        // with the order the execution path renders under. Covering only part of
        // the configured features would certify a partial order, so the converse
        // of the per-declaration check below is required too.
        let positioned: BTreeSet<SemanticRole> = self
            .layout
            .role_positions
            .iter()
            .map(|declared| declared.semantic_role)
            .collect();
        for declared in &self.layout.role_positions {
            if !features.contains(&declared.semantic_role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        if positioned != features {
            return Err(ContextError::MissingField(
                "recipe_policy.layout.role_positions",
            ));
        }
        self.omission.validate()?;
        Self::validate_blocking_dimensions(&self.blocking_dimensions)?;
        self.execution.validate()?;
        self.qualification.validate()?;
        self.supersession.validate()?;
        if self.canonical_policy_digest()? != self.policy_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }

    /// Check that this exact approved policy is the one the compilation-bound
    /// instance was issued under.
    ///
    /// The ORIGINAL recorded values of both records are used: the instance's
    /// own `validate()` runs first, and the policy's recorded digest is
    /// compared with the digest the instance recorded in
    /// [`DecisionRevision::policy_sha256`](crate::DecisionRevision). No digest
    /// is recomputed here to stand in for that owner record, and a recipe may
    /// not make itself applicable by dropping a mandatory role, adding a
    /// feature the policy does not configure, or declaring a mandatory role
    /// suppressible.
    ///
    /// One semantic role has one permitted-loss policy across the two records.
    /// A section budget's `omission_or_handle_policy` and the instance's
    /// [`RoleLossRule`](crate::RoleLossRule) `loss_policy` are two policies for
    /// the same role, and a disagreement is refused rather than resolved by
    /// preferring one: this is the check that makes `NON_DROPPABLE` unable to
    /// become `HANDLE_ONLY` by being written in the record the other validator
    /// does not read. The refusal is
    /// [`ContextError::WholeUnitRequired`], the same typed failure the role's
    /// own representation rule raises, because that is exactly what it is.
    ///
    /// #1724 A2 adds the per-role representation comparison itself: every
    /// budgeted section's `omission_or_handle_policy` must equal the instance's
    /// own per-role loss rule ([`RoleLossRule`](crate::RoleLossRule)) for that
    /// role, and a budgeted role the instance carries no loss rule for is
    /// [`ContextError::MissingField`]. Both halves matter: skipping a budgeted
    /// role the instance does not govern would leave its `omission_or_handle_policy`
    /// certified inside `policy_sha256` and read by no path, which is the
    /// certified-behavioural-no-op A2 forbids. The absence refusal reuses the
    /// crate's own vocabulary for it — `ContextRecipe::validate` already raises
    /// `MissingField("recipe.role_policies")` when a role it governs carries no
    /// rule.
    pub fn binds_recipe(&self, recipe: &ContextRecipe) -> Result<(), ContextError> {
        self.validate()?;
        recipe.validate()?;
        if recipe.decision.policy_sha256 != self.policy_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        let features = self.configured_features()?;
        for role in &recipe.mandatory_roles {
            if !features.contains(role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
            if self.admission.suppressible_roles.contains(role) {
                return Err(ContextError::MissingFloor);
            }
        }
        for rule in &recipe.role_policies {
            if !features.contains(&rule.role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        self.require_consistent_role_policies(recipe)
    }

    /// Refuse two role policies for one semantic role that disagree.
    ///
    /// #1724 A2: the policy's per-section omission/handle policy is compared
    /// with the instance's OWN per-role loss rule, which is the representation
    /// contract the admission and rendering path actually enforces
    /// (`RoleLossRule::validate` plus the representation kinds it admits). A
    /// policy that declared a different one for the same role was a certified
    /// setting that changed nothing: the instance's rule is what the renderer
    /// applied, and the policy's copy of it was read by no path at all.
    ///
    /// A budgeted role the instance governs no rule for is refused rather than
    /// skipped, for the same reason: skipping it would leave that budget's
    /// `omission_or_handle_policy` inside `policy_sha256` and read by no path at
    /// all, which is the certified behavioural no-op A2 forbids. The refusal
    /// reuses the crate's own vocabulary for a role without a rule —
    /// `ContextRecipe::validate` raises the same
    /// [`ContextError::MissingField`] for `recipe.role_policies`.
    fn require_consistent_role_policies(&self, recipe: &ContextRecipe) -> Result<(), ContextError> {
        for budget in &self.section_budgets {
            let Some(rule) = recipe
                .role_policies
                .iter()
                .find(|rule| rule.role == budget.semantic_role)
            else {
                return Err(ContextError::MissingField("recipe.role_policies"));
            };
            if rule.loss_policy != budget.omission_or_handle_policy {
                return Err(ContextError::WholeUnitRequired);
            }
        }
        Ok(())
    }

    /// Refuse a policy that declares anything this execution path does not run.
    ///
    /// This is #1724 W4's refusal clause. Every certified field of a policy is
    /// inside `policy_sha256`, so an unsupported declaration would otherwise be
    /// certified: a re-hashed policy with a different stage graph, a different
    /// repetition treatment, a whole-unit degradation the path never applies or
    /// a feature disable it cannot perform would pass every digest check while
    /// changing nothing about the output. Acceptance A2 requires the opposite:
    /// a policy change must move the revision/digest and the effective compiler
    /// behaviour together, or refuse.
    ///
    /// The comparisons are exact and one-directional — the policy must declare
    /// exactly what this path applies. Nothing here reads a value the policy did
    /// not declare, and no comparison is against a value derived from the policy
    /// itself. The refusal is a typed
    /// [`RecipeResolutionRefusal::UnsupportedSetting`] naming the exact field
    /// and the identity of the revision that declares it, so a dependent
    /// compilation is blocked with a name rather than a silent degradation.
    ///
    /// #1724 A2 adds the whole-unit boundary kind: a section may only declare
    /// the kind the assembly projection actually emits
    /// ([`EXECUTED_SECTION_UNIT_BOUNDARY`]). It was previously inside the digest
    /// with no reader anywhere, including this refusal.
    ///
    /// #1724 W4 closes the ordering half. Two changes together, and neither is
    /// sufficient alone:
    ///
    /// * [`RecipeExecutionSupport::ordering_revision`] must equal
    ///   [`EXECUTED_ORDERING_REVISION`], the scheme this contract authorises. The
    ///   revision was previously populated and validated as text and read by
    ///   nothing, so the execution identity stamped on a delivered View named a
    ///   scheme this contract never checked. It is now compared here.
    /// * `layout.role_positions` is APPLIED, not compared: the renderer
    ///   (`eliot-context-assembly` `render::render`) reads the declared positions
    ///   and sorts the rendered payload by them. A policy that declares the reverse
    ///   of the previous rendered order used to pass here and used to be certified
    ///   in `policy_sha256` while the renderer emitted its own order; it now
    ///   renders in the order it declared.
    ///
    /// The refusal names the field whose value is unsupported, so the two halves
    /// stay distinguishable in what the caller receives:
    /// `recipe_support.ordering_revision` is the executing path declaring a scheme
    /// this contract cannot cross-check, and `section_budget.unit_boundary_kind` is
    /// the policy declaring a boundary kind the projection does not emit.
    pub fn require_executable(
        &self,
        support: &RecipeExecutionSupport,
    ) -> Result<(), RecipeResolutionRefusal> {
        self.validate()
            .map_err(|error| RecipeResolutionRefusal::InvalidCatalogue {
                reason: error.to_string(),
            })?;
        support
            .validate()
            .map_err(|error| RecipeResolutionRefusal::InvalidCatalogue {
                reason: error.to_string(),
            })?;
        let identity = RecipePolicyIdentity::of(self);
        let unsupported = |field: &str| RecipeResolutionRefusal::UnsupportedSetting {
            identity: identity.clone(),
            field: field.to_owned(),
        };
        if self.stages.len() != 1
            || self.stages[0].stage_id != support.executed_stage
            || !self.stages[0].predecessors.is_empty()
        {
            return Err(unsupported("recipe_policy.stages"));
        }
        if self.layout.repetition != support.repetition {
            return Err(unsupported("recipe_policy.layout.repetition"));
        }
        // #1724 W4. `ordering_revision` was validated as non-empty text and
        // compared with nothing, so the scheme revision stamped on a delivered
        // View's execution identity named an ordering this contract never checked.
        // It is now the one member of `RecipeExecutionSupport` this function reads
        // against a value derived from the policy's OWN layout scheme, and a
        // mismatch refuses by name.
        if support.ordering_revision.as_str() != self.declared_ordering_revision() {
            return Err(unsupported("recipe_support.ordering_revision"));
        }
        // `layout.role_positions` needs no comparison here: the renderer APPLIES
        // the declared order (eliot-context-assembly `render::render` reads
        // `layout.role_positions` and sorts by `position`), so a declaration that
        // differs from what a previous execution path applied now moves the
        // delivered bytes and `output_digest` instead of being certified and
        // ignored. What is still refused here is a role the renderer cannot
        // position, which `RecipeLayoutPolicy::validate` already makes impossible
        // by requiring the positions to be the contiguous sequence `0..n`.
        for budget in &self.section_budgets {
            if budget.unit_boundary_kind != EXECUTED_SECTION_UNIT_BOUNDARY {
                return Err(unsupported("section_budget.unit_boundary_kind"));
            }
            if budget.degradation_behavior != support.section_degradation {
                return Err(unsupported("section_budget.degradation_behavior"));
            }
            if budget.disable_feature_when_floor_cannot_be_preserved
                && !support.supports_feature_disable
            {
                return Err(unsupported(
                    "section_budget.disable_feature_when_floor_cannot_be_preserved",
                ));
            }
        }
        Ok(())
    }

    /// The ordering revision this revision's declared layout requires of the
    /// executing path, derived from the policy's own content.
    ///
    /// #1724 W4. [`RecipeExecutionSupport::ordering_revision`] is the executing
    /// path's statement of the scheme it renders under, and it was validated as
    /// non-empty text and compared with nothing: the revision stamped on a
    /// delivered `ContextExecutionIdentity` named an ordering this contract never
    /// checked, so a recipe could declare any `layout.role_positions` order and be
    /// certified while the renderer emitted its own.
    ///
    /// The renderer now APPLIES the declared order (eliot-context-assembly
    /// `render::render` sorts by `position`), so the order is not a hidden default
    /// any more. What this function supplies is the SCHEME half of the binding: the
    /// order the approved revision requires is "declared role position, then
    /// provider, then atom identity", and that scheme string is compared against
    /// the one the execution owner publishes, so the two cannot name different
    /// orderings without a typed [`RecipeResolutionRefusal::UnsupportedSetting`]
    /// naming `recipe_support.ordering_revision`.
    ///
    /// The revision carries no per-revision suffix: the execution owner qualifies
    /// the SAME scheme with the approved revision's own `policy_sha256` when it
    /// stamps a view (`executed_ordering_revision` in eliot-context-assembly), so
    /// the identity of two revisions with different declared orders still differs
    /// on the view while the SCHEME this contract authorises is one string.
    fn declared_ordering_revision(&self) -> String {
        EXECUTED_ORDERING_REVISION.to_owned()
    }

    fn configured_features(&self) -> Result<BTreeSet<SemanticRole>, ContextError> {
        if self.candidate_features.is_empty() || self.candidate_features.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.candidate_features",
            });
        }
        let features: BTreeSet<SemanticRole> = self.candidate_features.iter().copied().collect();
        if features.len() != self.candidate_features.len() {
            return Err(ContextError::Duplicate("recipe_policy.candidate_features"));
        }
        Ok(features)
    }

    fn validate_stage_order(&self, features: &BTreeSet<SemanticRole>) -> Result<(), ContextError> {
        if self.stages.is_empty() || self.stages.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.stages",
            });
        }
        let mut declared = BTreeSet::new();
        for (position, stage) in self.stages.iter().enumerate() {
            validate_text(stage.stage_id.as_str(), "recipe_policy.stages.stage_id")?;
            if !declared.insert(stage.stage_id.clone()) {
                return Err(ContextError::Duplicate("recipe_policy.stages.stage_id"));
            }
            let mut edges = BTreeSet::new();
            for predecessor in &stage.predecessors {
                validate_text(predecessor.as_str(), "recipe_policy.stages.predecessors")?;
                if !edges.insert(predecessor.clone()) {
                    return Err(ContextError::Duplicate("recipe_policy.stages.predecessors"));
                }
                if !self.stages[..position]
                    .iter()
                    .any(|earlier| earlier.stage_id == *predecessor)
                {
                    return Err(ContextError::InvalidField(
                        "recipe_policy.stages.predecessors",
                    ));
                }
            }
        }
        for stage in &self.stages {
            if !features.contains(&stage.semantic_role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
        }
        Ok(())
    }

    /// Validate every section budget of this revision.
    ///
    /// Two budgets may not claim the same semantic role. The refusal is on the
    /// role alone, so an IDENTICAL repeat is refused exactly like a conflicting
    /// one: two budgets for one role are two policies for one role, and neither
    /// merging them nor keeping one of them is a decision this validator is
    /// allowed to make silently. The conflict that survives past this check —
    /// one role, one section budget but a different permitted loss policy in the
    /// compilation-bound instance's own
    /// [`RoleLossRule`](crate::RoleLossRule) — is refused where both records are
    /// read together, in
    /// [`ContextRecipePolicy::binds_recipe`].
    fn validate_section_budgets(
        &self,
        features: &BTreeSet<SemanticRole>,
    ) -> Result<(), ContextError> {
        if self.section_budgets.is_empty() || self.section_budgets.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_policy.section_budgets",
            });
        }
        let mut budgeted = BTreeSet::new();
        for budget in &self.section_budgets {
            if !budgeted.insert(budget.semantic_role) {
                return Err(ContextError::Duplicate(
                    "recipe_policy.section_budgets.semantic_role",
                ));
            }
            if !features.contains(&budget.semantic_role) {
                return Err(ContextError::MissingField(
                    "recipe_policy.candidate_features",
                ));
            }
            budget.validate()?;
            if !self
                .applicability
                .route_profiles
                .contains(&budget.planning_route_profile)
            {
                return Err(ContextError::MissingField(
                    "recipe_policy.applicability.route_profiles",
                ));
            }
        }
        Ok(())
    }

    fn validate_blocking_dimensions(dimensions: &[QualityDimension]) -> Result<(), ContextError> {
        if dimensions.is_empty() || dimensions.len() > QUALITY_DIMENSIONS.len() {
            return Err(ContextError::Bounds {
                field: "recipe_policy.blocking_dimensions",
            });
        }
        let mut seen = BTreeSet::new();
        for dimension in dimensions {
            if !QUALITY_DIMENSIONS.contains(dimension) || !seen.insert(*dimension) {
                return Err(ContextError::InvalidField(
                    "recipe_policy.blocking_dimensions",
                ));
            }
        }
        Ok(())
    }
}

/// The independent denominator of what one Context execution path actually runs.
///
/// #1724 W4: the current candidate admission, ordering, rendering and
/// scorecard/measurement must consume the pinned recipe rather than independent
/// hidden defaults, and a stage or feature that is not supported must refuse
/// instead of appearing in a certified digest while being ignored.
///
/// This record is the executing path's own statement of the concrete settings it
/// applies. It is built by the execution owner, never by a candidate recipe, so
/// [`ContextRecipePolicy::require_executable`] compares a policy against an
/// independent answer rather than against a copy of the policy's own
/// declarations. A member is only admitted here when the path that publishes
/// this record reads that value when it compiles and renders; adding a member
/// therefore means adding the execution that reads it, not widening a check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeExecutionSupport {
    /// Stage identity this path runs for every compilation.
    pub executed_stage: ArtifactId,
    /// Rendered-ordering SCHEME revision this path applies. I12.13 makes the order
    /// itself part of the recipe, so what this member states is the SCHEME the
    /// order is applied under — declared role position, then provider, then atom
    /// identity — and the specific order comes from the approved revision's own
    /// `layout.role_positions`.
    ///
    /// #1724 W4: read by [`ContextRecipePolicy::require_executable`], which
    /// refuses unless it equals [`EXECUTED_ORDERING_REVISION`]. Before that it was
    /// validated as non-empty text and compared with nothing, so the revision
    /// stamped on a delivered execution identity was never checked against the
    /// scheme this contract authorises — a token nothing read, added for the exact
    /// purpose this check now serves.
    pub ordering_revision: ArtifactId,
    /// Repetition treatment this path applies to repeated content.
    pub repetition: RecipeRepetitionPolicy,
    /// Whole-unit disposition this path applies when a section floor cannot be
    /// preserved.
    pub section_degradation: BoundaryDisposition,
    /// Whether this path can disable an optional feature when a section floor
    /// cannot be preserved.
    ///
    /// The current whole-unit admission and assembly path has no such disable:
    /// an unpreservable section blocks the dependent decision instead. The
    /// field is required rather than defaulted so an executing path that gains
    /// the capability states it explicitly, and a policy that relies on it
    /// refuses until it does.
    pub supports_feature_disable: bool,
}

impl RecipeExecutionSupport {
    /// Validate the closed support record before it is compared to a policy.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.executed_stage.as_str(),
            "recipe_support.executed_stage",
        )?;
        validate_text(
            self.ordering_revision.as_str(),
            "recipe_support.ordering_revision",
        )?;
        self.repetition.validate()?;
        Ok(())
    }
}

/// Digest domain separator for one pinned recipe resolution.
///
/// A third domain, after [`CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN`] and the
/// instance's own `canonical_policy_digest`. The resolution digest binds the
/// selected revision, its exact content, the approval decision, the
/// applicability dimensions and the compiler-generation profile, so a
/// resolution cannot be replayed against a different compilation.
pub const CONTEXT_RECIPE_RESOLUTION_DIGEST_DOMAIN: &str =
    "eliot.smart.context.recipe-resolution.v1";

/// The four applicability dimensions I12.13 declares a recipe against.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeApplicabilityDimension {
    /// `applicable_task_..._profiles`.
    Task,
    /// `..._route_..._profiles`.
    Route,
    /// `..._impact_..._profiles`.
    Impact,
    /// `..._governance_profiles`.
    Governance,
}

impl RecipeApplicabilityDimension {
    /// The declared profile list of this dimension.
    fn profiles(self, applicability: &RecipeApplicability) -> &[String] {
        match self {
            Self::Task => &applicability.task_profiles,
            Self::Route => &applicability.route_profiles,
            Self::Impact => &applicability.impact_profiles,
            Self::Governance => &applicability.governance_profiles,
        }
    }
}

/// Identity of exactly one approved policy revision.
///
/// These are the three values that recover the immutable approved content: the
/// policy identity, its owner-minted revision and the digest of its bytes in
/// the policy digest domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipePolicyIdentity {
    /// Stable identity of the selected policy.
    pub policy_id: ArtifactId,
    /// Owner-minted reusable policy revision.
    pub policy_revision: PolicyRevision,
    /// Digest of the selected policy's exact content.
    pub policy_sha256: String,
}

impl RecipePolicyIdentity {
    /// Read the identity an owner-published candidate already carries.
    fn of(policy: &ContextRecipePolicy) -> Self {
        Self {
            policy_id: policy.policy_id.clone(),
            policy_revision: policy.policy_revision,
            policy_sha256: policy.policy_sha256.clone(),
        }
    }

    /// Validate the identity's own recorded fields.
    ///
    /// An identity that names nothing, or whose digest is not a digest, cannot be
    /// a predecessor, a proposed content, a baseline or a current pointer, so it
    /// is refused before any content comparison is attempted. This checks the
    /// ORIGINAL recorded values only; it derives no digest of its own.
    fn validate_identity(&self) -> Result<(), ContextError> {
        validate_text(self.policy_id.as_str(), "recipe_policy_identity.policy_id")?;
        validate_digest(&self.policy_sha256, "recipe_policy_identity.policy_sha256")
    }

    /// Check that this identity still names exactly this content.
    ///
    /// The ORIGINAL recorded values of both records are compared. No digest is
    /// recomputed here to stand in for the owner's record; the policy's own
    /// `validate` is what re-derives its content digest.
    fn validate(&self, policy: &ContextRecipePolicy) -> Result<(), ContextError> {
        policy.validate()?;
        if self.policy_id != policy.policy_id
            || self.policy_revision != policy.policy_revision
            || self.policy_sha256 != policy.policy_sha256
        {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// Why one owner-published candidate is not the resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeRejectionReason {
    /// An owner kill or rollback decision revoked this revision.
    Revoked {
        /// The owner decision that revoked the revision.
        decision: ArtifactId,
    },
    /// The candidate does not declare one applicability profile of this
    /// compilation.
    UndeclaredApplicability {
        /// Dimension whose profile the candidate never names.
        dimension: RecipeApplicabilityDimension,
        /// The exact profile the candidate omits.
        profile: String,
    },
    /// The candidate was issued under a different compiler-generation or route
    /// profile, including a different transform configuration digest.
    StaleCompilerGeneration {
        /// The compiler-generation profile this compilation runs under.
        expected: RecipeExecutionContour,
        /// The compiler-generation profile the candidate was issued under.
        observed: RecipeExecutionContour,
    },
}

/// One rejected candidate, with the exact reason it did not apply.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeCandidateRejection {
    /// Identity of the rejected candidate.
    pub identity: RecipePolicyIdentity,
    /// Why it was not selected.
    pub reason: RecipeRejectionReason,
}

/// Typed refusal of a dependent Context compilation.
///
/// I12.13 requires a missing or ambiguous applicability to block the dependent
/// compilation rather than fall back. Every variant names what was missing or
/// which candidates were indistinguishable; none of them resolves to a default.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeResolutionRefusal {
    /// The owner configuration itself is not a closed, valid record, so no
    /// resolution may be attempted from it.
    InvalidCatalogue {
        /// Bounded field-level reason from the closed record validator.
        reason: String,
    },
    /// One or more of the six independent applicability inputs is unresolved,
    /// so the candidate set cannot be compared against a governing answer.
    UnresolvedGoverningInput {
        /// Every unresolved input, in canonical order.
        inputs: Vec<QualityApplicabilityInput>,
    },
    /// The revision the current pointer names is not an applicable candidate.
    NoApplicableCandidate {
        /// The pointed revision, with its exact rejection reason.
        rejected: Vec<RecipeCandidateRejection>,
    },
    /// The owner holds an approved, unrevoked, applicable revision that the
    /// current pointer does not name.
    ///
    /// #1724 W6. This arm is the refusal a "newest candidate wins" rule could
    /// not produce. A candidate is not permission to activate, so the resolution
    /// neither silently adopts it nor silently continues on the older revision:
    /// it blocks the dependent compilation until the owner promotion decision
    /// that names the candidate is published.
    ApplicableCandidateNotCurrent {
        /// The revision the current pointer does name.
        current: RecipePolicyIdentity,
        /// Every applicable, unrevoked revision the pointer does not name, in
        /// policy-identity order.
        unpointed: Vec<RecipePolicyIdentity>,
    },
    /// The selected revision declares a setting the executing Context path does
    /// not run, so certifying it would place that setting inside a delivered
    /// digest while ignoring it.
    UnsupportedSetting {
        /// Identity of the revision that declares the unsupported setting.
        identity: RecipePolicyIdentity,
        /// Exact policy field the execution path does not implement.
        field: String,
    },
}

fn applicability_input_label(input: QualityApplicabilityInput) -> &'static str {
    match input {
        QualityApplicabilityInput::TaskAcceptance => "task_acceptance",
        QualityApplicabilityInput::Route => "route",
        QualityApplicabilityInput::Impact => "impact",
        QualityApplicabilityInput::GovernanceProfile => "governance_profile",
        QualityApplicabilityInput::ProtectedFloor => "protected_floor",
        QualityApplicabilityInput::ActiveDirective => "active_directive",
    }
}

impl fmt::Display for RecipeResolutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCatalogue { reason } => {
                write!(formatter, "owner recipe catalogue is invalid: {reason}")
            }
            Self::UnresolvedGoverningInput { inputs } => {
                let labels: Vec<&str> = inputs
                    .iter()
                    .map(|input| applicability_input_label(*input))
                    .collect();
                write!(formatter, "governing applicability unresolved: {labels:?}")
            }
            Self::NoApplicableCandidate { rejected } => write!(
                formatter,
                "no applicable approved recipe among {} owner candidate(s)",
                rejected.len()
            ),
            Self::ApplicableCandidateNotCurrent { current, unpointed } => write!(
                formatter,
                "current pointer {} leaves {} applicable approved recipe(s) not yet promoted",
                current.policy_id.as_str(),
                unpointed.len()
            ),
            Self::UnsupportedSetting { identity, field } => write!(
                formatter,
                "approved recipe {} declares {field}, which this execution path does not run",
                identity.policy_id.as_str()
            ),
        }
    }
}

impl std::error::Error for RecipeResolutionRefusal {}

#[derive(Serialize)]
struct RecipeResolutionDigestInput<'a> {
    domain: &'static str,
    resolution: &'a ResolvedContextRecipe,
}

/// Exactly one applicable approved recipe, pinned for a whole compilation.
///
/// The pinned revision is recoverable: `identity` plus `policy` re-derive the
/// immutable approved content, `approval` names the owner decision that made
/// it current, and `execution` names the compiler-generation and route profile
/// the compilation is bound to. `resolution_sha256` binds all five, so a
/// resolution cannot be carried into another compilation, another revision or
/// another generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedContextRecipe {
    /// Identity of the selected revision.
    pub identity: RecipePolicyIdentity,
    /// The exact recoverable immutable approved content that was selected.
    pub policy: ContextRecipePolicy,
    /// Owner activation decision that made the selected revision current.
    pub approval: ArtifactId,
    /// Applicability dimensions this resolution was made against.
    pub applicability: RecipeApplicability,
    /// Compiler-generation and route profile this resolution is pinned to.
    pub execution: RecipeExecutionContour,
    /// Digest pinning identity, content, approval, applicability and execution.
    pub resolution_sha256: String,
}

impl ResolvedContextRecipe {
    /// Compute the digest expected in `resolution_sha256`.
    pub fn canonical_resolution_digest(&self) -> Result<String, ContextError> {
        let mut canonical = self.clone();
        canonical.resolution_sha256 = "0".repeat(64);
        let input = RecipeResolutionDigestInput {
            domain: CONTEXT_RECIPE_RESOLUTION_DIGEST_DOMAIN,
            resolution: &canonical,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&input)
            .map_err(|_| ContextError::InvalidField("recipe_resolution.canonical"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Re-derive every recorded value of this resolution from the selected
    /// policy it carries.
    ///
    /// A stored resolution is not evidence of its own applicability: the
    /// approval must be the policy's own activation decision, the pinned
    /// compiler-generation profile must equal the policy's, the declared
    /// applicability must cover every profile this compilation named, and the
    /// recorded digest must match.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.identity.validate(&self.policy)?;
        validate_text(self.approval.as_str(), "recipe_resolution.approval")?;
        self.applicability.validate()?;
        if self.approval != self.policy.supersession.activation
            || self.execution != self.policy.execution
            || !RecipeApplicability::declared_covers(
                &self.policy.applicability,
                &self.applicability,
            )
        {
            return Err(ContextError::IdentityConflict);
        }
        validate_digest(
            &self.resolution_sha256,
            "recipe_resolution.resolution_sha256",
        )?;
        if self.canonical_resolution_digest()? != self.resolution_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// Independent governing requirements every candidate is validated against.
///
/// Every member is an owner record or an owner constant that exists outside
/// this module: the Decision Safety Floor for this decision boundary, the
/// admission rule that boundary must admit under, the six I12.13 applicability
/// inputs with their resolved/unknown partition, the scorecard dimensions the
/// owner requires this revision to block on, the omission reasons the owner
/// requires the revision to be able to apply, the complete ceiling of reasons
/// that may be non-recoverable, and the maximum proof this decision boundary
/// may carry. None of them is read from, or derivable from, a candidate recipe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningContextRequirements {
    /// Owner-issued Decision Safety Floor for this decision boundary.
    pub floor: DecisionSafetyFloor,
    /// Owner admission rule this decision boundary must admit under.
    ///
    /// #1724 A2. Required and not defaulted: it is the independent denominator
    /// for [`RecipeAdmissionPolicy::admission_rule`], which was inside
    /// `policy_sha256` with no reader outside its own text validation, so
    /// re-pointing a revision at a different admission rule moved the certified
    /// policy identity and every identity embedding it while the admitted
    /// membership did not change. I7.11 places the admission rule's own class
    /// comparison in `eliot-context-admission`, which depends on this crate, so
    /// the rule's CONTENT is not resolvable here and is not restated; what is
    /// bound is the revision's identity claim about which rule it admits under,
    /// against the rule the owner names for this boundary. The sibling member
    /// [`RecipeAdmissionPolicy::safety_floor`] is already bound the same way
    /// against [`Self::floor`], so this is the same comparison one level across.
    pub required_admission_rule: ArtifactId,
    /// Applicability inputs resolved before grading, from the quality owner.
    pub applicability: QualityApplicability,
    /// Scorecard dimensions the owner requires this revision to block on.
    ///
    /// The set is required and may not be empty: an owner requirement set that
    /// blocked nothing would let any candidate pass this dimension.
    pub required_blocking_dimensions: Vec<QualityDimension>,
    /// Omission reasons the owner requires this revision to be able to apply.
    pub required_omission_reasons: Vec<OmissionReason>,
    /// Complete ceiling of reasons that may stand as non-recoverable.
    ///
    /// This is a ceiling, not a floor: a recipe may declare fewer
    /// non-recoverable reasons than this, and any reason outside it refuses.
    pub permitted_non_recoverable_reasons: Vec<NonRecoverableReason>,
    /// Maximum proof this decision boundary may carry.
    pub required_proof_ceiling: ProofCeiling,
}

impl GoverningContextRequirements {
    fn validate(&self) -> Result<(), ContextError> {
        self.floor.validate()?;
        validate_text(
            self.required_admission_rule.as_str(),
            "governing.required_admission_rule",
        )?;
        self.applicability.validate()?;
        Self::validate_blocking_dimensions(&self.required_blocking_dimensions)?;
        Self::distinct_omissions(
            &self.required_omission_reasons,
            "governing.required_omission_reasons",
        )?;
        Self::distinct_omissions(
            &self.permitted_non_recoverable_reasons,
            "governing.permitted_non_recoverable_reasons",
        )
    }

    fn validate_blocking_dimensions(dimensions: &[QualityDimension]) -> Result<(), ContextError> {
        if dimensions.is_empty() || dimensions.len() > QUALITY_DIMENSIONS.len() {
            return Err(ContextError::Bounds {
                field: "governing.required_blocking_dimensions",
            });
        }
        let mut seen = BTreeSet::new();
        for dimension in dimensions {
            if !QUALITY_DIMENSIONS.contains(dimension) || !seen.insert(*dimension) {
                return Err(ContextError::InvalidField(
                    "governing.required_blocking_dimensions",
                ));
            }
        }
        Ok(())
    }

    fn distinct_omissions<T: Copy + Ord>(
        reasons: &[T],
        field: &'static str,
    ) -> Result<(), ContextError> {
        if reasons.len() > 16 {
            return Err(ContextError::Bounds { field });
        }
        let mut seen = BTreeSet::new();
        for reason in reasons {
            if !seen.insert(*reason) {
                return Err(ContextError::Duplicate(field));
            }
        }
        Ok(())
    }

    /// Whether every budgeted section keeps at least the whole units the floor
    /// makes mandatory for that role.
    ///
    /// #1724 A2. This is the only place in the workspace that reads
    /// [`ContextSectionBudget::minimum_required_whole_units`] and
    /// [`ContextSectionBudget::planning_maximum_whole_units`] against anything
    /// outside the budget itself. Every mandatory
    /// [`DecisionSafetyFloor`](crate::DecisionSafetyFloor) member is one
    /// non-droppable whole unit of its role, so a section budget that may retain
    /// fewer complete units of a role than the floor requires — or that may plan
    /// for fewer — is a floor weakening dressed as a planning figure, and
    /// `authorize` refuses it. Before this the two amounts were compared only with
    /// each other inside one budget struct, so changing either moved
    /// `policy_sha256` and moved nothing else, and lowering either below the floor
    /// passed every check.
    ///
    /// The ceiling ABOVE the floor stays a planning bound: the whole-unit
    /// allocation algorithm is #1725's and is deliberately not reimplemented
    /// here, so there is no independent count of available units to bound it
    /// against.
    fn authorises_whole_unit_budgets(&self, policy: &ContextRecipePolicy) -> bool {
        let mut mandatory_units: BTreeMap<SemanticRole, u64> = BTreeMap::new();
        for member in &self.floor.members {
            let count = mandatory_units.entry(member.role).or_insert(0);
            *count = count.saturating_add(1);
        }
        policy.section_budgets.iter().all(|budget| {
            mandatory_units
                .get(&budget.semantic_role)
                .is_none_or(|required| {
                    budget.minimum_required_whole_units >= *required
                        && budget.planning_maximum_whole_units >= *required
                })
        })
    }

    /// Whether the protected reserves this revision declares fit inside the
    /// floor's own route capacity.
    ///
    /// #1724 A2. This is the only place in the workspace that reads
    /// [`ProtectedReservePolicy::margin_reserve`] or the three figures of
    /// [`ProtectedReservePolicy::reserves`] against anything this crate does not
    /// own. Every one of those four amounts was inside `policy_sha256` with no
    /// reader, so raising any of them moved the certified policy identity and
    /// every identity embedding the published document while the delivered
    /// content did not move. They are now bounded by the independent
    /// [`DecisionSafetyFloor::capacity`] the owner issued for this decision
    /// boundary: a revision that claims more protected capacity than the floor's
    /// route capacity can hold refuses with
    /// [`ContextError::CapacityExceeded`].
    ///
    /// The bound is a CAPACITY COHERENCE bound, not a spent-amount check: no
    /// execution path in this workspace measures a protected reserve figure, so
    /// there is no measured consumption to compare a declaration against. That is
    /// why this is a floor comparison rather than an equality, and it is named as
    /// a residual in the module header rather than presented as enforcement of a
    /// spend.
    fn authorises_protected_reserves(&self, policy: &ContextRecipePolicy) -> bool {
        let declared = &policy.protected_reserve;
        let reserved = declared
            .reserves
            .reasoning_reserve
            .saturating_add(declared.reserves.review_reserve)
            .saturating_add(declared.reserves.evidence_reserve)
            .saturating_add(declared.margin_reserve);
        reserved <= self.floor.capacity.route_capacity
    }

    /// Validate one resolved recipe against these requirements.
    ///
    /// The comparisons are set comparisons against owner requirements, so a
    /// candidate cannot make itself valid: it may not drop a role the floor
    /// makes mandatory, shave the floor's capacity envelope, budget fewer whole
    /// units of a role than the floor makes mandatory, admit under an admission
    /// rule other than the one this boundary requires, claim more protected
    /// reserve capacity than the floor's route capacity holds, block fewer
    /// scorecard dimensions than the owner requires, drop a required omission
    /// reason, widen the non-recoverable set beyond the owner's ceiling, or
    /// serve a decision boundary whose proof ceiling exceeds its empirical
    /// qualification.
    pub fn authorize(
        &self,
        resolved: &ResolvedContextRecipe,
        instance: &ContextRecipe,
    ) -> Result<(), ContextError> {
        self.validate()?;
        resolved.validate()?;
        let policy = &resolved.policy;
        policy.binds_recipe(instance)?;

        if self.floor.binding != instance.binding {
            return Err(ContextError::InvalidFence);
        }
        if policy.admission.safety_floor != self.floor.rule_evidence {
            return Err(ContextError::IdentityConflict);
        }
        // #1724 A2: the admission-rule IDENTITY is read here, against the rule the
        // owner requires for this boundary. It was certified with no reader.
        if policy.admission.admission_rule != self.required_admission_rule {
            return Err(ContextError::IdentityConflict);
        }
        let features = policy.configured_features()?;
        let budgeted: BTreeSet<SemanticRole> = policy
            .section_budgets
            .iter()
            .map(|budget| budget.semantic_role)
            .collect();
        let mandatory: BTreeSet<SemanticRole> = instance.mandatory_roles.iter().copied().collect();
        for role in &self.floor.mandatory_roles {
            if !features.contains(role) || !budgeted.contains(role) || !mandatory.contains(role) {
                return Err(ContextError::MissingFloor);
            }
            if policy.admission.suppressible_roles.contains(role) {
                return Err(ContextError::MissingFloor);
            }
        }

        let floor_capacity = &self.floor.capacity;
        if instance.capacity.route_capacity < floor_capacity.route_capacity
            || instance.capacity.output_reserve < floor_capacity.output_reserve
            || instance.capacity.review_reserve < floor_capacity.review_reserve
            || instance.capacity.fixed_overhead > floor_capacity.fixed_overhead
        {
            return Err(ContextError::CapacityExceeded);
        }

        // #1724 A2: the section-budget AMOUNTS are read here, against the floor.
        if !self.authorises_whole_unit_budgets(policy) {
            return Err(ContextError::MissingFloor);
        }

        // #1724 A2: the PROTECTED RESERVE amounts are read here, against the
        // floor's own route capacity.
        if !self.authorises_protected_reserves(policy) {
            return Err(ContextError::CapacityExceeded);
        }

        let blocked: BTreeSet<QualityDimension> =
            policy.blocking_dimensions.iter().copied().collect();
        if !self
            .required_blocking_dimensions
            .iter()
            .all(|dimension| blocked.contains(dimension))
        {
            return Err(ContextError::QualityIncomplete);
        }

        let permitted: BTreeSet<OmissionReason> =
            policy.omission.permitted_reasons.iter().copied().collect();
        if !self
            .required_omission_reasons
            .iter()
            .all(|reason| permitted.contains(reason))
        {
            return Err(ContextError::OmissionHandleInvalid);
        }
        let non_recoverable: BTreeSet<NonRecoverableReason> = policy
            .omission
            .non_recoverable_reasons
            .iter()
            .copied()
            .collect();
        let ceiling: BTreeSet<NonRecoverableReason> = self
            .permitted_non_recoverable_reasons
            .iter()
            .copied()
            .collect();
        if !non_recoverable.is_subset(&ceiling) {
            return Err(ContextError::OmissionHandleInvalid);
        }

        if self.required_proof_ceiling > ProofCeiling::Observation
            && policy.qualification.state != RecipeQualificationState::Qualified
        {
            return Err(ContextError::QualityIncomplete);
        }

        if self
            .applicability
            .resolved
            .contains(&QualityApplicabilityInput::ActiveDirective)
            && (!features.contains(&SemanticRole::Conflict)
                || !features.contains(&SemanticRole::Negative))
        {
            return Err(ContextError::MissingField(
                "recipe_policy.candidate_features",
            ));
        }
        Ok(())
    }
}

/// The current owner configuration from which exactly one applicable approved
/// recipe is resolved.
///
/// This is the owner catalogue, not the compiler. It carries the compilation's
/// own applicability dimensions and compiler-generation profile, the
/// independent governing requirements, every approved candidate revision the
/// owner currently holds, and — #1724 W7 — the owner decisions that made those
/// revisions current or revoked them. The pure compiler receives the result of
/// [`ApprovedRecipeCatalogue::resolve`]; it never consults this record, a
/// mutable registry, the filesystem, the network or a model.
///
/// `current` is the current recipe pointer and is a REQUIRED member with no
/// default, because it is the only thing that decides what is current. Before
/// #1724 W6 the pointer was implicit: `resolve` took the applicable candidate
/// with the greatest [`PolicyRevision`], which made a revision number an
/// activation authority and let a publisher change the current recipe by
/// publishing a newer candidate, with no promotion decision anywhere.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRecipeCatalogue {
    /// The one approved revision this catalogue holds current.
    ///
    /// Nothing else changes what is current: not a higher revision number, not a
    /// valid digest, not a smaller packet, not a favourable measurement. The
    /// pointer is resolved to the owner promotion decision that made it current
    /// by [`ApprovedRecipeCatalogue::validate`], which requires the pointed
    /// revision's own recorded activation identity to name an activation record
    /// this catalogue carries.
    pub current: RecipePolicyIdentity,
    /// Compiler-generation and route profile this compilation runs under.
    pub execution: RecipeExecutionContour,
    /// Applicability dimensions of this compilation.
    pub applicability: RecipeApplicability,
    /// Independent governing requirements every candidate is measured against.
    pub governing: GoverningContextRequirements,
    /// Owner-published approved candidate policy revisions.
    pub candidates: Vec<ContextRecipePolicy>,
    /// Owner activation decisions for the candidates, one per candidate.
    ///
    /// Order carries no meaning. #1724 W6 removed the reading in which the
    /// newest record here, or the highest revision, decided what was current.
    pub activations: Vec<RecipeActivationRecord>,
    /// Owner kill/rollback decisions for candidates this owner no longer serves.
    pub revocations: Vec<RecipeRevocationRecord>,
}

impl ApprovedRecipeCatalogue {
    /// Validate the closed owner configuration before any candidate is
    /// compared.
    ///
    /// #1724 W7 adds the decision closure. Every candidate must be named by
    /// exactly one activation decision whose `decision` identity equals the
    /// candidate's own recorded `supersession.activation`, so a revision cannot
    /// be served without the decision that made it current or be made current
    /// by a decision that belongs to another revision. Each activation names
    /// the exact predecessor it supersedes, which must be a revision this owner
    /// still holds, and each revocation names either nothing (a kill) or the
    /// previous compatible revision it returns to, which must likewise still be
    /// held. A rollback therefore cannot name a revision the owner does not
    /// have, and cannot be expressed at all by editing the revoked revision.
    ///
    /// #1724 W6 adds the pointer closure and the gate closure. `current` must
    /// name a revision this owner holds. Every activation's
    /// [`RecipePromotionBasis`] is then measured against the CONTENT of the
    /// revision it activated: an initial/built-in baseline has no predecessor, a
    /// candidate's declared predecessor is the decision's predecessor, the
    /// candidate's declared proposed content IS the activated revision, the
    /// candidate's applicability covers the scope the decision activates, the
    /// candidate measured every counter-metric the activated revision declares,
    /// and the activated revision records its metrics as qualified. A candidate,
    /// a valid hash, a smaller packet or a positive token saving satisfies none
    /// of those, so none of them can activate anything.
    ///
    /// #1724 A4 follows from the same shape: nothing in this record, and nothing
    /// in a View or a `ContextEconomyReceipt`, can rewrite an approved
    /// revision's `policy_sha256`. Evidence that names a digest keeps naming it
    /// after a later revocation, and a new compilation resolves a new
    /// `resolution_sha256` rather than restamping the old evidence.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.candidates.is_empty() || self.candidates.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_catalogue.candidates",
            });
        }
        if self.activations.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_catalogue.activations",
            });
        }
        if self.activations.len() != self.candidates.len() {
            return Err(ContextError::IdentityConflict);
        }
        if self.revocations.len() > 64 {
            return Err(ContextError::Bounds {
                field: "recipe_catalogue.revocations",
            });
        }
        self.current.validate_identity()?;
        self.execution.validate()?;
        self.applicability.validate()?;
        self.governing.validate()?;
        let mut seen = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !seen.insert((candidate.policy_id.clone(), candidate.policy_revision)) {
                return Err(ContextError::Duplicate("recipe_catalogue.candidates"));
            }
        }
        let mut held: BTreeMap<RecipePolicyIdentity, &ContextRecipePolicy> = BTreeMap::new();
        for candidate in &self.candidates {
            if held
                .insert(RecipePolicyIdentity::of(candidate), candidate)
                .is_some()
            {
                return Err(ContextError::IdentityConflict);
            }
        }

        let mut decisions = BTreeSet::new();
        let mut activated = BTreeSet::new();
        for activation in &self.activations {
            activation.validate()?;
            if !decisions.insert(activation.decision.clone())
                || !activated.insert(activation.activated.clone())
            {
                return Err(ContextError::Duplicate("recipe_catalogue.activations"));
            }
            let Some(activated_policy) = held.get(&activation.activated) else {
                return Err(ContextError::IdentityConflict);
            };
            // The activation is confined to the contour and transform
            // identity it was decided under. Its `generation` is deliberately
            // not compared here: a contour generation is the owner's monotone
            // execution counter, and freezing every historical activation on it
            // would make the catalogue unusable after one bump. Generation
            // staleness is already a per-candidate rejection
            // (`RecipeRejectionReason::StaleCompilerGeneration`), which is the
            // narrower and correct place for it.
            if activation.execution.contour != self.execution.contour
                || activation.execution.transform != self.execution.transform
            {
                return Err(ContextError::IdentityConflict);
            }
            if !RecipeApplicability::declared_covers(&activation.applicability, &self.applicability)
            {
                return Err(ContextError::IdentityConflict);
            }
            if activation
                .predecessor
                .as_ref()
                .is_some_and(|predecessor| !held.contains_key(predecessor))
            {
                return Err(ContextError::IdentityConflict);
            }
            Self::validate_promotion_basis(activation, activated_policy)?;
        }
        for candidate in &self.candidates {
            let identity = RecipePolicyIdentity::of(candidate);
            if !self.activations.iter().any(|activation| {
                activation.activated == identity
                    && activation.decision == candidate.supersession.activation
            }) {
                return Err(ContextError::IdentityConflict);
            }
        }

        self.validate_revocations(&held)?;
        if !held.contains_key(&self.current) {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }

    /// #1724 W7. Every kill or rollback names a revision this owner still holds,
    /// and a rollback names a replacement this owner still holds, so a rollback
    /// cannot return to a revision that is not there.
    fn validate_revocations(
        &self,
        held: &BTreeMap<RecipePolicyIdentity, &ContextRecipePolicy>,
    ) -> Result<(), ContextError> {
        let mut revoked = BTreeSet::new();
        let mut revocation_decisions = BTreeSet::new();
        for revocation in &self.revocations {
            revocation.validate()?;
            if !revoked.insert(revocation.revoked.clone())
                || !revocation_decisions.insert(revocation.decision.clone())
            {
                return Err(ContextError::Duplicate("recipe_catalogue.revocations"));
            }
            if !held.contains_key(&revocation.revoked) {
                return Err(ContextError::IdentityConflict);
            }
            if revocation
                .replacement
                .as_ref()
                .is_some_and(|replacement| !held.contains_key(replacement))
            {
                return Err(ContextError::IdentityConflict);
            }
        }
        Ok(())
    }

    /// #1724 W6: measure one owner promotion decision against the approved
    /// content it actually promoted.
    ///
    /// Every comparison here is against the activated revision's own recorded
    /// values or against the candidate's own recorded values, never against a
    /// value derived from the decision being checked, so a decision cannot pass
    /// by agreeing with itself.
    ///
    /// #1724 A2 adds the qualification-evidence closure: the owner evidence
    /// reference the activated revision records in
    /// [`RecipeQualification::qualification`] must be evidence THIS decision
    /// cites. A revision cannot claim to be qualified by a record no promotion
    /// decision ever made, and the reference stays inside the certified digest as
    /// a resolved comparison rather than as bare text.
    fn validate_promotion_basis(
        activation: &RecipeActivationRecord,
        activated_policy: &ContextRecipePolicy,
    ) -> Result<(), ContextError> {
        let qualification = &activated_policy.qualification.qualification;
        match &activation.basis {
            // The built-in baseline is preserved as such: it supersedes nothing
            // and it needs no fabricated prior experimental evidence, so it is
            // the one basis that may leave `qualification.state` unqualified. The
            // only owner evidence such a decision carries is its own approval,
            // so that approval is the only evidence reference its revision may
            // name as its qualification.
            RecipePromotionBasis::InitialBuiltInBaseline { approval } => {
                if activation.predecessor.is_some() {
                    return Err(ContextError::IdentityConflict);
                }
                if approval != qualification {
                    return Err(ContextError::IdentityConflict);
                }
            }
            RecipePromotionBasis::ImprovementCandidate { candidate } => {
                if activation.predecessor.as_ref() != Some(&candidate.predecessor)
                    || candidate.proposed != activation.activated
                {
                    return Err(ContextError::IdentityConflict);
                }
                // The candidate was triaged and measured in a scope at least as
                // broad as the scope this decision activates, so the evidence
                // cited is evidence about the applicability being activated.
                // `activation.applicability` is separately required to cover the
                // compilation's own applicability, so the chain reaches the
                // independent end rather than stopping at the candidate.
                if !RecipeApplicability::declared_covers(
                    &candidate.applicability,
                    &activation.applicability,
                ) {
                    return Err(ContextError::IdentityConflict);
                }
                if !candidate.covers_declared_counter_metrics(activated_policy) {
                    return Err(ContextError::QualityIncomplete);
                }
                if qualification != &candidate.candidate
                    && qualification != &candidate.replay_holdout
                    && qualification != &candidate.canary
                {
                    return Err(ContextError::IdentityConflict);
                }
                // An unqualified metric stays labelled unqualified, and a
                // revision whose own recorded metrics are unqualified cannot be
                // promoted on the strength of evidence about different metrics.
                if activated_policy.qualification.state != RecipeQualificationState::Qualified {
                    return Err(ContextError::QualityIncomplete);
                }
            }
        }
        Ok(())
    }

    /// Resolve exactly one applicable approved recipe.
    ///
    /// #1724 W6. Selection reads [`ApprovedRecipeCatalogue::current`] and
    /// nothing else. In order, with no fallback:
    ///
    /// 1. an unresolved governing applicability input refuses the compilation
    ///    before any candidate is read;
    /// 2. the pointed revision named by an owner kill or rollback decision,
    ///    issued under another compiler-generation or route profile, or not
    ///    declaring every applicability profile of this compilation refuses with
    ///    that exact reason;
    /// 3. any OTHER held, unrevoked, applicable revision refuses as
    ///    [`RecipeResolutionRefusal::ApplicableCandidateNotCurrent`]. It is
    ///    neither adopted nor ignored: a candidate that has not been pointed at
    ///    by a promotion decision is not permission to activate, so the
    ///    dependent compilation blocks until the owner publishes that decision.
    ///
    /// There is no revision comparison anywhere in this function, because a
    /// revision number is not an activation authority. The result is pinned by
    /// its own digest so the same revision cannot be reused for another
    /// compilation, task or generation.
    pub fn resolve(&self) -> Result<ResolvedContextRecipe, RecipeResolutionRefusal> {
        self.validate()
            .map_err(|error| RecipeResolutionRefusal::InvalidCatalogue {
                reason: error.to_string(),
            })?;
        let unresolved = self.governing.applicability.unresolved();
        if !unresolved.is_empty() {
            return Err(RecipeResolutionRefusal::UnresolvedGoverningInput { inputs: unresolved });
        }

        // `validate` proved `current` names a held revision, so this lookup
        // cannot miss. It is still written as a checked lookup rather than an
        // index so the pointer is never dereferenced on trust. `current` stays a
        // `&ContextRecipePolicy`: a policy is content, not a `Copy` value, and
        // every use below either borrows it or clones it deliberately.
        let current = self
            .candidates
            .iter()
            .find(|candidate| RecipePolicyIdentity::of(candidate) == self.current)
            .ok_or_else(|| RecipeResolutionRefusal::InvalidCatalogue {
                reason: ContextError::IdentityConflict.to_string(),
            })?;

        if let Some(reason) = self.applicability_rejection(current) {
            return Err(RecipeResolutionRefusal::NoApplicableCandidate {
                rejected: vec![RecipeCandidateRejection {
                    identity: RecipePolicyIdentity::of(current),
                    reason,
                }],
            });
        }

        let mut unpointed: Vec<RecipePolicyIdentity> = self
            .candidates
            .iter()
            .filter(|candidate| RecipePolicyIdentity::of(candidate) != self.current)
            .filter(|candidate| self.applicability_rejection(candidate).is_none())
            .map(RecipePolicyIdentity::of)
            .collect();
        if !unpointed.is_empty() {
            unpointed.sort();
            return Err(RecipeResolutionRefusal::ApplicableCandidateNotCurrent {
                current: self.current.clone(),
                unpointed,
            });
        }

        let mut resolution = ResolvedContextRecipe {
            identity: self.current.clone(),
            policy: current.clone(),
            approval: current.supersession.activation.clone(),
            applicability: self.applicability.clone(),
            execution: self.execution.clone(),
            resolution_sha256: "0".repeat(64),
        };
        resolution.resolution_sha256 =
            resolution.canonical_resolution_digest().map_err(|error| {
                RecipeResolutionRefusal::InvalidCatalogue {
                    reason: error.to_string(),
                }
            })?;
        Ok(resolution)
    }

    fn applicability_rejection(
        &self,
        candidate: &ContextRecipePolicy,
    ) -> Option<RecipeRejectionReason> {
        // #1724 W7: revocation is an owner decision held BESIDE the approved
        // content, read from the identity the candidate records. A kill or a
        // rollback can therefore be observed and audited without rewriting the
        // revoked revision, and a revision the owner still serves is unaffected.
        if let Some(revocation) = self
            .revocations
            .iter()
            .find(|revocation| revocation.revoked == RecipePolicyIdentity::of(candidate))
        {
            return Some(RecipeRejectionReason::Revoked {
                decision: revocation.decision.clone(),
            });
        }
        if candidate.execution != self.execution {
            return Some(RecipeRejectionReason::StaleCompilerGeneration {
                expected: self.execution.clone(),
                observed: candidate.execution.clone(),
            });
        }
        for dimension in [
            RecipeApplicabilityDimension::Task,
            RecipeApplicabilityDimension::Route,
            RecipeApplicabilityDimension::Impact,
            RecipeApplicabilityDimension::Governance,
        ] {
            let declared = dimension.profiles(&candidate.applicability);
            for profile in dimension.profiles(&self.applicability) {
                if !declared.contains(profile) {
                    return Some(RecipeRejectionReason::UndeclaredApplicability {
                        dimension,
                        profile: profile.clone(),
                    });
                }
            }
        }
        None
    }
}
