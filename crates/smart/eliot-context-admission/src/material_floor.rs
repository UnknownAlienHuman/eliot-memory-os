//! Owner-resolved applicable Decision Safety Floor, its delivery proof, and the
//! exact typed `DECISION_CONTEXT_INCOMPLETE` refusal (issue #1742).
//!
//! Grounding, quoted from the governing fragments:
//!
//! - `I7.11`: "`DecisionSafetyFloor` for a Material/Critical boundary contains
//!   all currently applicable non-droppable atoms", and "If the floor cannot be
//!   delivered and expanded before the decision, compilation returns
//!   `DECISION_CONTEXT_INCOMPLETE`". The same fragment gives the per-atom
//!   [`FloorAtomPolicy`] shape (`class`, `loss_policy`,
//!   `dependency_and_invalidation_refs`, `applicable_effect_classes`) and
//!   requires every Material/Critical action or resumed branch to carry the
//!   `I12.31` `DecisionExecutionLineageRefs` chain.
//! - `I7.8`: "before Material action, ensure current authority/action model".
//! - `I12.31`: the phase-relative completeness trichotomy
//!   (`COMPLETE | PARTIAL | STALE | UNKNOWN`) and the rule that a Material
//!   resume "fails closed when a load-bearing lineage ref is missing, stale or
//!   superseded".
//! - `I7.20`: a refusal carries the exact reason code, the applicable directive
//!   and the same operation identity; specific authentication, authority and
//!   revocation failures are preserved rather than collapsed.
//!
//! This module is a **gate**, not a second compiler:
//!
//! - [`derive_applicable_floor`] selects the owner-issued [`FloorAtomPolicy`]
//!   set applicable to the owner-resolved impact class, closes it over the
//!   owner-declared dependency edges (transitively, following every supplied
//!   owner policy for a visited identity as well as the observed candidate
//!   graph), preserves the complete required identity closure, and resolves a
//!   representation rule for every closure member. It reads no caller packet,
//!   recipe, compiled floor, tool name or `read_only` bit, so a caller cannot
//!   narrow the floor. A successfully visited dependency is never discarded.
//! - [`admit_material_decision`] first requires the prepared input's effective
//!   floor closure (the existing [`crate::floor_closure`] logic) to cover the
//!   owner-derived closure, so an owner-required edge the compiler was never
//!   given is a refusal, never a silent pass. It then invokes the existing pure
//!   compiler ([`crate::admit_context_traced`]) over the owner-resolved
//!   closure, proves that the compiled delivery actually carries every
//!   owner-required dependency in an owner-permitted representation, and
//!   validates the phase-aware `I12.31` lineage for the current decision phase.
//!
//! Nothing here re-implements `prepare_floor`/`select_required`/
//! `select_optional`, and nothing here invents a Governance Profile, directive
//! set, effect class or lineage field. An owner input that does not exist yet
//! fails closed and names the owner that must issue it.
//!
//! Host-only logic: the applicable floor is bound to the owner-issued impact
//! class (`eliot_authority::ImpactClass`), which belongs to the governed host
//! contour, so this module is gated with `#[cfg(not(target_arch = "wasm32"))]`
//! at the crate root exactly like [`crate::learning_gate`]. The pure selection
//! logic in the crate root stays shared and unchanged.

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_contracts::{PublicReference, RetainedHandoffCheckpoint};
use eliot_authority::ImpactClass;
use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmittedContextSet, AtomAvailability, ContextCandidate,
    ContextError, ContextOutcome, DecisionContextIncomplete, DecisionExecutionLineageRefs,
    DecisionLineageCompleteness, DecisionLineagePhase, DecisionLineageRef, DecisionLineageSlot,
    DecisionLineageSupersession, LossPolicy, OmissionRecord, RepresentationKind, RoleLossRule,
    SemanticRole, canonical_digest,
};
use eliot_contracts::{
    ArtifactId, DecisionId, StateFence, TaskId, TaskRevision, fences_match_exact,
};
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::EffectCeiling;
use serde::{Deserialize, Serialize};

use crate::MaterialRankTrace;

/// Maximum number of owner-issued atom policies one operation may carry.
const MAX_FLOOR_POLICIES: usize = 256;

/// Maximum number of identities one derived floor dependency closure may visit.
const MAX_FLOOR_CLOSURE: usize = 4096;

/// Maximum number of affected lineage references one refusal may name.
const MAX_AFFECTED_REFERENCES: usize = 256;

/// Owner named when no owner-issued atom policy is applicable to the resolved
/// impact class and no applicable floor can be derived at all.
const OWNER_FLOOR_POLICY: &str =
    "Context floor-policy owner together with the Governor action model";

/// One owner-issued atom policy that can place an atom in the applicable
/// Decision Safety Floor.
///
/// This is the `I7.11` `ContextAtomPolicy` in Rust form. Every field is issued
/// by the owner of that material: the Context policy owner supplies the loss and
/// representation rules, and the Governor/Task Controller supplies the impact
/// classes the policy is applicable to. The gate selects and verifies; it never
/// authors a policy, widens a loss policy, or promotes an optional atom into the
/// floor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorAtomPolicy {
    /// Exact identity of the atom this policy governs.
    pub atom_id: ArtifactId,
    /// Semantic role the atom satisfies for the decision.
    pub role: SemanticRole,
    /// Exact loss policy the owner permits for this atom.
    pub loss_policy: LossPolicy,
    /// Representations the owner permits for this atom, validated against
    /// `loss_policy` by the shared [`RoleLossRule`] contract, so a
    /// `NON_DROPPABLE` policy admits only the whole unit.
    pub allowed_representations: Vec<RepresentationKind>,
    /// References the atom's interpretation depends on. They are closed over
    /// transitively; a declared dependency the closure cannot supply is
    /// reported as an exact gap instead of being dropped.
    pub required_dependencies: Vec<ArtifactId>,
    /// Impact classes for which this policy is applicable. An empty set means
    /// the owner issued no applicability and the policy can never enter a floor.
    pub applicable_impact_classes: Vec<ImpactClass>,
}

impl FloorAtomPolicy {
    /// Validate the owner policy against the shared representation contract.
    ///
    /// [`RoleLossRule::validate`] is the single authority for the loss-policy
    /// lattice, so this never restates which representation a loss policy
    /// permits; it only binds the owner's declaration into that authority.
    fn validate(&self) -> Result<(), ContextError> {
        if self.required_dependencies.contains(&self.atom_id) {
            return Err(ContextError::Duplicate("floor_policy.dependencies"));
        }
        RoleLossRule {
            role: self.role,
            loss_policy: self.loss_policy,
            required: true,
            allowed_representations: self.allowed_representations.clone(),
        }
        .validate()
    }

    /// Whether this policy applies to the owner-resolved impact class.
    fn applies_to(&self, impact_class: ImpactClass) -> bool {
        self.applicable_impact_classes.contains(&impact_class)
    }
}

/// Owner-resolved facts about the operation the applicable floor must cover.
///
/// Every field is read from its owner, never from the caller's request: the
/// impact class from the action model ([`ImpactClass`]), the acceptance revision
/// from the Task Controller, the resources and Governance Profile from the
/// policy owner, the authority reference from the current grant, and the phase
/// from the runtime dispatch point. A caller's declared `read_only` bit or tool
/// name has no field here, so neither can narrow the floor.
pub struct OperationOwnerInputs<'a> {
    /// Decision identity the floor and refusal are bound to.
    pub decision_id: &'a DecisionId,
    /// Retained State Fence the decision is taken at.
    pub state_fence: &'a StateFence,
    /// Owner-resolved impact class of the actual operation.
    pub impact_class: ImpactClass,
    /// Owner-resolved task identity.
    pub task_id: &'a TaskId,
    /// Owner-resolved task/acceptance revision the decision is taken against.
    pub acceptance_revision: TaskRevision,
    /// Owner-resolved resources the operation may touch.
    pub requested_resources: &'a BTreeSet<String>,
    /// Owner-issued Governance Profile reference.
    pub governance_profile_ref: &'a str,
    /// Owner-issued authority reference backing the operation.
    pub authority_ref: &'a str,
    /// Decision phase the lineage is validated for.
    pub phase: DecisionLineagePhase,
    /// Identity of the floor rule that produced the owner policy set.
    pub rule_evidence: ArtifactId,
}

impl OperationOwnerInputs<'_> {
    fn validate(&self) -> Result<(), ContextError> {
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        let task_id = self.task_id.as_str();
        if task_id.trim().is_empty() || task_id.chars().any(char::is_control) {
            return Err(ContextError::InvalidField("owners.task_id"));
        }
        if self.state_fence.task_revision != Some(self.acceptance_revision) {
            return Err(ContextError::InvalidField("owners.acceptance_revision"));
        }
        if self.impact_class.is_forbidden() {
            return Err(ContextError::InvalidField("owners.impact_class"));
        }
        if !owner_text(self.governance_profile_ref) || !owner_text(self.authority_ref) {
            return Err(ContextError::InvalidField("owners.profile_and_authority"));
        }
        if self
            .requested_resources
            .iter()
            .any(|resource| !owner_text(resource))
        {
            return Err(ContextError::InvalidField("owners.requested_resources"));
        }
        Ok(())
    }
}

/// Bounded owner-text check: non-blank and free of control characters.
fn owner_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

/// One atom the derived applicable floor requires, with the exact
/// representations its owner policy permits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredFloorAtom {
    /// Exact identity of the required atom.
    pub atom_id: ArtifactId,
    /// Semantic role the atom satisfies.
    pub role: SemanticRole,
    /// Owner loss policy for the atom.
    pub loss_policy: LossPolicy,
    /// Representations the owner permits for this atom.
    pub allowed_representations: Vec<RepresentationKind>,
}

/// The applicable floor derived from the owner inputs.
///
/// This is derived independently of the caller's packet and recipe: it is the
/// set the owner policies require for the resolved impact class, closed over
/// their declared dependencies. `required` holds the directly applicable policy
/// atoms *and* every transitively required dependency, each with the
/// representation rule resolved from a supplied owner policy or, when no owner
/// policy describes the dependency, from the canonical floor-member contract
/// under the strictest (`NON_DROPPABLE`, whole-unit) delivery rule. The
/// compiled packet floor is *checked against* this set, never the other way
/// round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicableFloor {
    /// Decision identity the floor is bound to.
    pub decision_id: DecisionId,
    /// Retained fence the floor was derived at.
    pub state_fence: StateFence,
    /// Owner-resolved impact class the floor was derived for.
    pub impact_class: ImpactClass,
    /// Owner-issued Governance Profile reference.
    pub governance_profile_ref: String,
    /// Owner-issued authority reference.
    pub authority_ref: String,
    /// Owner-resolved acceptance revision.
    pub acceptance_revision: TaskRevision,
    /// Exact required atoms with their owner representation rules, ordered by
    /// atom identity.
    pub required: Vec<RequiredFloorAtom>,
    /// Identity of the floor rule that produced the owner policy set.
    pub rule_evidence: ArtifactId,
}

/// Exact lineage reference a refusal points at.
///
/// `slot` names the `I12.31` lineage slot whose requirement is unmet and
/// `reference` is verbatim the record that accounts for the gap: the policy
/// reference of a not-applicable or not-yet-produced slot, the evidence
/// reference of an explicitly unknown slot. The pair is never renamed into a
/// role the record does not itself claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedLineageReference {
    /// `I12.31` lineage slot whose requirement is unmet.
    pub slot: &'static str,
    /// The record that accounts for the gap, verbatim.
    pub reference: DecisionLineageRef,
}

/// What a refusal is about: the evidence status the caller sees.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FloorEvidenceStatus {
    /// No owner-issued atom policy is applicable to the resolved impact class,
    /// so no applicable floor can be derived at all.
    OwnerPolicyMissing,
    /// The applicable floor was derived, and required identities are absent
    /// from the owner-resolved closure or from the compiled floor.
    RequiredAtomMissing,
    /// A required atom was not delivered in a representation its owner policy
    /// permits, or without a retained, currently present, expandable source.
    RepresentationNotDeliverable,
    /// The compiled floor exceeds the route envelope and cannot be delivered
    /// whole.
    FloorOversized,
    /// The `I12.31` lineage is not complete for the current decision phase.
    LineageIncomplete,
}

/// The allowed recovery action named by a `DECISION_CONTEXT_INCOMPLETE` refusal.
///
/// `I7.11` fixes the allowed responses: decomposition, a safer partial action, a
/// different qualified route, or a human decision-not to continue. A refresh and
/// an expansion cover the first two mechanically; a narrowing is a new, explicitly
/// scoped proposal evaluated normally, never silent execution of a different
/// command.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllowedFloorAction {
    /// Re-resolve the owner inputs and recompile the closure.
    Refresh,
    /// Expand the named references before the decision, retaining the source.
    Expand,
    /// Submit a new, explicitly narrower proposal for normal evaluation.
    Narrow,
}

/// The exact typed `DECISION_CONTEXT_INCOMPLETE` refusal.
///
/// `incomplete` is the owner's existing [`DecisionContextIncomplete`] value, so
/// the wire code stays `DECISION_CONTEXT_INCOMPLETE` and its missing, stale and
/// blocked identity lists are preserved verbatim. The remaining fields carry the
/// evidence status, the exact affected lineage references, the decision phase,
/// and the allowed action, as `I7.20` requires.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionFloorRefusal {
    /// The typed incomplete result: exact code plus exact gap identities.
    pub incomplete: DecisionContextIncomplete,
    /// Decision phase the refusal was produced at.
    pub phase: DecisionLineagePhase,
    /// What the refusal is about.
    pub evidence_status: FloorEvidenceStatus,
    /// Exact lineage slots and records that account for the refusal.
    pub affected_references: Vec<AffectedLineageReference>,
    /// The one allowed recovery action.
    pub allowed_action: AllowedFloorAction,
    /// Owner that must issue a missing input, when one is missing.
    pub missing_owner: Option<&'static str>,
}

/// Refusal channel for one material decision.
///
/// A [`Self::Incomplete`] is the exact `DECISION_CONTEXT_INCOMPLETE` typed
/// limitation. A [`Self::Boundary`] preserves a more specific authentication,
/// authority, fence, revocation or capacity failure from the compiler or from an
/// owner contract: work item 5 forbids collapsing those into the incomplete
/// code, so they keep their own identity and never widen into a floor gap.
/// The incomplete arm is boxed so the refusal stays a small error value; the
/// typed fields inside it are preserved exactly and are reachable through
/// [`MaterialDecisionRefusal::incomplete`], matching how the owner contracts
/// already carry `Box<DecisionContextIncomplete>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterialDecisionRefusal {
    /// The applicable floor or the phase-aware lineage is incomplete.
    Incomplete(Box<DecisionFloorRefusal>),
    /// A more specific boundary failure, preserved uncollapsed.
    Boundary(ContextError),
}

impl MaterialDecisionRefusal {
    /// The typed incomplete refusal, or `None` for a preserved boundary failure.
    #[must_use]
    pub const fn incomplete(&self) -> Option<&DecisionFloorRefusal> {
        match self {
            Self::Incomplete(refusal) => Some(refusal),
            Self::Boundary(_) => None,
        }
    }
}

/// The admitted applicable floor and the evidence that it was delivered.
///
/// A successful packet exposes the exact floor it satisfied, the exact atoms that
/// carried it, the permitted loss and expansion manifest with the reversible
/// handles the compiler bound, the per-material selection evidence, and a
/// content-addressed handle over all of it. Swapping any of those invalidates the
/// handle exactly like any other bound fact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedDecisionFloor {
    /// The applicable floor that was satisfied.
    pub floor: ApplicableFloor,
    /// Exact required atoms, all present in the delivered set.
    pub delivered: Vec<ArtifactId>,
    /// The permitted loss and expansion manifest; each record carries its
    /// reversible handle or its explicit non-recoverable reason.
    pub omissions: Vec<OmissionRecord>,
    /// One selection-evidence record per evaluated material, each with its own
    /// content-addressed handle.
    pub traces: Vec<MaterialRankTrace>,
    /// Phase-relative completeness of the validated `I12.31` lineage.
    pub lineage_completeness: DecisionLineageCompleteness,
    /// Maximum proof this admitted floor supports.
    pub proof_ceiling: ProofCeiling,
    /// Content-addressed handle (`decision-floor:<sha256>`) resolving to exactly
    /// this admitted floor.
    pub handle: String,
}

impl AdmittedDecisionFloor {
    /// Re-resolve the content-addressed handle over the handle-cleared record.
    ///
    /// The handle is recomputed from the delivered facts, so a swapped floor,
    /// delivered set, omission manifest, trace, completeness or proof ceiling
    /// fails closed. This is a binding check over the record this admission
    /// produced; it does not replace the compiler's own receipt validation,
    /// which the compiler performs before returning.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.handle != decision_floor_handle(self)? {
            return Err(ContextError::InvalidField("decision_floor.handle"));
        }
        Ok(())
    }
}

fn decision_floor_handle(floor: &AdmittedDecisionFloor) -> Result<String, ContextError> {
    let unsigned = AdmittedDecisionFloor {
        handle: String::new(),
        ..floor.clone()
    };
    Ok(format!("decision-floor:{}", canonical_digest(&unsigned)?))
}

/// Derive the applicable floor for one operation from its owner inputs.
///
/// The derived set is the owner-issued [`FloorAtomPolicy`] slice applicable to the
/// owner-resolved impact class, closed over the declared dependency references
/// through the owner-resolved candidate identities. One atom per class is not
/// enough: every applicable identity, every transitively declared dependency
/// and every semantic role the owner bound is counted, and any identity the
/// closure cannot supply is returned as an exact `missing` gap rather than
/// dropped. The complete visited closure is preserved into the returned floor,
/// so no mandatory owner-policy edge can disappear between this derivation and
/// the final delivery check.
///
/// # Errors
///
/// Returns [`MaterialDecisionRefusal::Incomplete`] with
/// [`FloorEvidenceStatus::OwnerPolicyMissing`] when no owner-issued policy is
/// applicable to the resolved impact class, and with
/// [`FloorEvidenceStatus::RequiredAtomMissing`] naming the exact atom identities
/// the declared dependency closure cannot supply, or the exact owner-required
/// dependency no owner rule and no canonical floor member describes (no weaker
/// rule is invented for an undescribed declaration). A malformed owner input or
/// owner policy is a [`MaterialDecisionRefusal::Boundary`] refusal, so a shape
/// error is never reported as missing evidence.
pub fn derive_applicable_floor(
    owners: &OperationOwnerInputs<'_>,
    policies: &[FloorAtomPolicy],
    closure: &AdmissionInput,
) -> Result<ApplicableFloor, MaterialDecisionRefusal> {
    owners
        .validate()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if policies.is_empty() || policies.len() > MAX_FLOOR_POLICIES {
        return Err(MaterialDecisionRefusal::Boundary(ContextError::Bounds {
            field: "floor.policies",
        }));
    }
    let selected = select_applicable(owners, policies)?;
    if selected.required.is_empty() {
        return Err(deny_without_applicable_policy(owners, closure));
    }
    let dependency_closure = close_floor_dependencies(&selected, policies, closure)
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if !dependency_closure.missing.is_empty() {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Expand,
            &dependency_closure.missing,
            "the applicable floor requires an atom the owner-resolved closure does not supply",
            None,
            Vec::new(),
        ));
    }
    let required =
        resolve_floor_requirements(owners, policies, closure, &selected, &dependency_closure)?;
    Ok(ApplicableFloor {
        decision_id: owners.decision_id.clone(),
        state_fence: owners.state_fence.clone(),
        impact_class: owners.impact_class,
        governance_profile_ref: owners.governance_profile_ref.to_owned(),
        authority_ref: owners.authority_ref.to_owned(),
        acceptance_revision: owners.acceptance_revision,
        required,
        rule_evidence: owners.rule_evidence.clone(),
    })
}

/// Select the owner-issued policies applicable to the resolved impact class.
///
/// Returns the exact required set plus every reference those policies declared
/// as their interpretation dependencies, so the closure below covers the owner's
/// declared edges and not only the observed candidate graph.
fn select_applicable(
    owners: &OperationOwnerInputs<'_>,
    policies: &[FloorAtomPolicy],
) -> Result<SelectedFloorRequirements, MaterialDecisionRefusal> {
    let mut required: BTreeMap<ArtifactId, RequiredFloorAtom> = BTreeMap::new();
    let mut declared: Vec<ArtifactId> = Vec::new();
    for policy in policies {
        policy
            .validate()
            .map_err(MaterialDecisionRefusal::Boundary)?;
        if !policy.applies_to(owners.impact_class) {
            continue;
        }
        if required.contains_key(&policy.atom_id) {
            return Err(MaterialDecisionRefusal::Boundary(ContextError::Duplicate(
                "floor.policies.atom_id",
            )));
        }
        declared.extend(policy.required_dependencies.iter().cloned());
        required.insert(
            policy.atom_id.clone(),
            RequiredFloorAtom {
                atom_id: policy.atom_id.clone(),
                role: policy.role,
                loss_policy: policy.loss_policy,
                allowed_representations: policy.allowed_representations.clone(),
            },
        );
    }
    declared.sort();
    declared.dedup();
    Ok(SelectedFloorRequirements { required, declared })
}

/// The owner-selected required set and its declared dependency references.
struct SelectedFloorRequirements {
    required: BTreeMap<ArtifactId, RequiredFloorAtom>,
    declared: Vec<ArtifactId>,
}

/// The complete owner-required dependency closure: every visited identity plus
/// every visited identity the owner-resolved closure cannot supply.
///
/// Both sets are deterministic: `ids` iterates in identity order and `missing`
/// is sorted. A successfully visited dependency is preserved here, never
/// discarded, so the final delivery check sees the same mandatory edges this
/// derivation saw.
struct FloorDependencyClosure {
    /// Every identity the bounded walk visited, in deterministic order.
    ids: BTreeSet<ArtifactId>,
    /// Visited identities with no owner-resolved candidate, sorted.
    missing: Vec<ArtifactId>,
}

/// Close the selected requirements over the owner-declared and observed
/// dependency edges, preserving the complete required identity closure as well
/// as its missing identities.
///
/// The walk starts from the directly applicable policy atoms and their declared
/// dependencies. For every visited identity it follows both the observed
/// [`ContextCandidate`] dependency edges and the `required_dependencies` of
/// every supplied owner policy for that identity, transitively: the requirement
/// flows from an applicable root, so a dependency policy's own applicability no
/// longer matters once its atom is required, and `A → B → C` cannot lose `C`.
/// An identity with no candidate is recorded as missing, but its owner-policy
/// edges are still followed, so a missing middle cannot hide a deeper
/// requirement.
///
/// The bound is fail-closed: an over-large closure is a `Bounds` boundary
/// failure, never a silently truncated requirement set. Cycles terminate on the
/// visited set.
fn close_floor_dependencies(
    selected: &SelectedFloorRequirements,
    policies: &[FloorAtomPolicy],
    closure: &AdmissionInput,
) -> Result<FloorDependencyClosure, ContextError> {
    let mut queue: Vec<ArtifactId> = Vec::new();
    queue.extend(selected.required.keys().cloned());
    queue.extend(selected.declared.iter().cloned());
    let mut visited: BTreeSet<ArtifactId> = BTreeSet::new();
    let mut missing: BTreeSet<ArtifactId> = BTreeSet::new();
    while let Some(atom_id) = queue.pop() {
        if !visited.insert(atom_id.clone()) {
            continue;
        }
        if visited.len() > MAX_FLOOR_CLOSURE {
            return Err(ContextError::Bounds {
                field: "floor.closure",
            });
        }
        if let Some(candidate) = closure
            .candidates
            .candidates
            .iter()
            .find(|candidate| candidate.atom_id == atom_id)
        {
            queue.extend(candidate.dependencies.iter().cloned());
        } else {
            missing.insert(atom_id.clone());
        }
        for policy in policies.iter().filter(|policy| policy.atom_id == atom_id) {
            queue.extend(policy.required_dependencies.iter().cloned());
        }
    }
    Ok(FloorDependencyClosure {
        ids: visited,
        missing: missing.into_iter().collect(),
    })
}

/// Resolve a representation rule for every identity in the owner-derived
/// closure, ordered by atom identity.
///
/// Precedence per identity: the directly selected requirement when the identity
/// is a directly applicable policy atom; otherwise the supplied owner policy
/// for that identity; otherwise the canonical floor-member contract of the
/// prepared input, whose role is kept and whose delivery rule is the strictest
/// one (`NON_DROPPABLE`, whole-unit only) — `I7.11` admits a floor of
/// non-droppable atoms, so an owner-required atom without an explicit loss
/// declaration defaults to whole-unit delivery, never to a weaker
/// representation. An identity neither an owner policy nor a floor member
/// describes is an input/owner-policy disagreement and fails closed as
/// [`FloorEvidenceStatus::RequiredAtomMissing`]: no weaker — or invented —
/// rule may stand in for the missing declaration.
fn resolve_floor_requirements(
    owners: &OperationOwnerInputs<'_>,
    policies: &[FloorAtomPolicy],
    closure: &AdmissionInput,
    selected: &SelectedFloorRequirements,
    dependency_closure: &FloorDependencyClosure,
) -> Result<Vec<RequiredFloorAtom>, MaterialDecisionRefusal> {
    let mut required: Vec<RequiredFloorAtom> = Vec::new();
    let mut undescribed: Vec<ArtifactId> = Vec::new();
    for atom_id in &dependency_closure.ids {
        if let Some(direct) = selected.required.get(atom_id) {
            required.push(direct.clone());
            continue;
        }
        if let Some(policy) = policies.iter().find(|policy| policy.atom_id == *atom_id) {
            required.push(RequiredFloorAtom {
                atom_id: policy.atom_id.clone(),
                role: policy.role,
                loss_policy: policy.loss_policy,
                allowed_representations: policy.allowed_representations.clone(),
            });
            continue;
        }
        if let Some(member) = closure
            .floor
            .floor
            .members
            .iter()
            .find(|member| member.atom_id == *atom_id)
        {
            required.push(RequiredFloorAtom {
                atom_id: member.atom_id.clone(),
                role: member.role,
                loss_policy: LossPolicy::NonDroppable,
                allowed_representations: vec![RepresentationKind::Whole],
            });
            continue;
        }
        undescribed.push(atom_id.clone());
    }
    if !undescribed.is_empty() {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Expand,
            &undescribed,
            "the applicable floor requires an atom no owner rule and no canonical floor member describes",
            None,
            Vec::new(),
        ));
    }
    Ok(required)
}

/// Compile and prove delivery of the applicable floor, or refuse with the exact
/// typed `DECISION_CONTEXT_INCOMPLETE` limitation.
///
/// Order of operations, each step fail-closed:
///
/// 1. [`derive_applicable_floor`] from the owner inputs, never from the caller's
///    packet or recipe. The derived floor carries the complete owner-required
///    dependency closure, not just the directly applicable atoms.
/// 2. Validate the `I12.31` [`DecisionExecutionLineageRefs`] for the current
///    decision phase through the shared `validate_for_phase`, so a new effect
///    binds its proposal, authorization and required future observable without
///    demanding a not-yet-existing execution or outcome receipt, while resume,
///    verification and finish require the already-due observed or explicitly
///    unknown records.
/// 3. Require the prepared input's effective floor closure (the existing
///    [`crate::floor_closure`] logic over the same input) to cover the
///    owner-derived closure. The input is never rewritten or resealed to pass:
///    an interpretation dependency already counts toward coverage without being
///    relabelled as a top-level mandatory atom, but an owner-required edge the
///    compiler was never given is a `RequiredAtomMissing` refusal.
/// 4. Invoke the existing pure compiler ([`crate::admit_context_traced`]) over the
///    owner-resolved closure. Its `Incomplete` outcome is carried through
///    verbatim; its boundary refusals are preserved uncollapsed.
/// 5. Prove the delivery: every owner-required dependency — not only the
///    directly applicable atoms — is checked against the actual admitted
///    records, current availability and the permitted representation or
///    expansion. Presence in the closure candidates is insufficient. A handle
///    satisfies a requirement only when the exact source is currently present or
///    carries a reversible owner expansion handle, so a handle for absent or
///    non-current material is a delivery gap rather than a satisfied requirement.
///    Each gap is filed under its exact missing, stale, blocked, unavailable,
///    omitted, exhausted, unknown, known-empty or partial identity.
/// 6. Return the exact floor, the delivered identities, the permitted loss and
///    expansion manifest, and a content-addressed handle over them.
///
/// # Errors
///
/// [`MaterialDecisionRefusal::Incomplete`] for a missing or stale required atom,
/// a non-deliverable representation, an oversized floor, or an incomplete, stale
/// or unknown lineage at the current phase.
/// [`MaterialDecisionRefusal::Boundary`] for a preserved authentication,
/// authority, fence, revocation or capacity failure.
#[allow(clippy::too_many_lines)]
pub fn admit_material_decision(
    owners: &OperationOwnerInputs<'_>,
    policies: &[FloorAtomPolicy],
    closure: &AdmissionInput,
    lineage: &DecisionExecutionLineageRefs,
) -> Result<AdmittedDecisionFloor, MaterialDecisionRefusal> {
    check_closure_is_this_operation(owners, closure).map_err(MaterialDecisionRefusal::Boundary)?;
    let floor = derive_applicable_floor(owners, policies, closure)?;
    let completeness = lineage
        .validate_for_phase(owners.phase)
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if completeness != DecisionLineageCompleteness::Complete {
        let references = affected_lineage_references(lineage, owners.phase);
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::LineageIncomplete,
            allowed_lineage_action(completeness),
            std::slice::from_ref(&owners.rule_evidence),
            "the decision lineage is not complete for the current decision phase",
            None,
            references,
        ));
    }
    let effective = prepared_floor_closure(closure).map_err(MaterialDecisionRefusal::Boundary)?;
    let uncovered: Vec<ArtifactId> = floor
        .required
        .iter()
        .map(|required| required.atom_id.clone())
        .filter(|atom_id| !effective.contains(atom_id))
        .collect();
    if !uncovered.is_empty() {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Expand,
            &uncovered,
            "the owner-derived floor requires an atom the prepared input floor closure does not cover; the compiler was never given that edge",
            None,
            Vec::new(),
        ));
    }
    let (result, traces) =
        crate::admit_context_traced(closure).map_err(MaterialDecisionRefusal::Boundary)?;
    let admitted = match &result.outcome {
        ContextOutcome::Complete(set) => set,
        ContextOutcome::Incomplete(incomplete) => {
            return Err(compiler_incomplete_refusal(owners, incomplete));
        }
    };
    if !fences_match_exact(&admitted.binding.state_fence, owners.state_fence) {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidFence,
        ));
    }
    let gaps = check_floor_delivery(&floor, admitted, closure, &result.evidence.omissions);
    if !gaps.is_empty() {
        return Err(delivery_refusal(owners, &gaps));
    }
    let delivered = floor
        .required
        .iter()
        .map(|required| required.atom_id.clone())
        .collect();
    let mut omissions = result.evidence.omissions.clone();
    omissions.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    let mut admitted_floor = AdmittedDecisionFloor {
        floor,
        delivered,
        omissions,
        traces,
        lineage_completeness: completeness,
        proof_ceiling: result.evidence.proof_ceiling,
        handle: String::new(),
    };
    admitted_floor.handle =
        decision_floor_handle(&admitted_floor).map_err(MaterialDecisionRefusal::Boundary)?;
    admitted_floor
        .validate()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    Ok(admitted_floor)
}

/// The prepared input's effective floor closure over the same input.
///
/// This reuses the existing [`crate::floor_closure`] selection — mandatory
/// atoms, interpretation dependencies and member requirements, closed over the
/// candidate graph — so the coverage check trusts no second selector and the
/// caller input is never rewritten or resealed. An interpretation dependency
/// counts toward coverage as-is; nothing is relabelled as a top-level
/// mandatory atom to pass.
fn prepared_floor_closure(closure: &AdmissionInput) -> Result<BTreeSet<ArtifactId>, ContextError> {
    let candidates: BTreeMap<ArtifactId, &ContextCandidate> = closure
        .candidates
        .candidates
        .iter()
        .map(|candidate| (candidate.atom_id.clone(), candidate))
        .collect();
    crate::floor_closure(closure, &candidates)
}

/// Require that the prepared closure is the closure of THIS operation.
///
/// Every entry point that reads facts out of a caller-presented
/// [`AdmissionInput`] runs this one predicate first, so a closure compiled for
/// another decision, task or revision — even at the same fence, and even when
/// the rest of its shape validates — can never contribute a bound fact to this
/// operation. It is the same four identities the admission check requires, kept
/// as one shared helper so the dispatch binder cannot drift from it.
fn check_closure_is_this_operation(
    owners: &OperationOwnerInputs<'_>,
    closure: &AdmissionInput,
) -> Result<(), ContextError> {
    if !fences_match_exact(&closure.binding.state_fence, owners.state_fence) {
        return Err(ContextError::InvalidFence);
    }
    if closure.binding.decision_id != *owners.decision_id {
        return Err(ContextError::IdentityConflict);
    }
    // The closure must be the closure of THIS operation: a packet compiled for
    // another task, even at the same fence, is a substituted packet, not
    // evidence for this decision.
    if closure.binding.task_id.as_str() != owners.task_id.as_str() {
        return Err(ContextError::IdentityConflict);
    }
    if closure.binding.state_fence.task_revision != Some(owners.acceptance_revision) {
        return Err(ContextError::InvalidField("closure.task_revision"));
    }
    Ok(())
}

/// Owner-required atoms the compiled delivery does not actually carry.
///
/// Every requirement in the derived floor — directly applicable atoms and
/// transitively required dependencies alike — is checked against the actual
/// admitted records, current availability and the permitted representation or
/// expansion. Presence in the closure candidates is insufficient: a candidate
/// the compiler omitted, staled, or admitted in a representation the owner rule
/// forbids is a gap. Membership in the compiled mandatory list is not delivery
/// proof either; the admitted record is.
///
/// A requirement is satisfied only when an admitted record carries it in a
/// representation its owner rule permits. A handle-only delivery additionally
/// requires the exact source to be currently present or to carry a reversible
/// owner expansion handle, because possession of a handle for absent or
/// non-current material is not access.
///
/// Each gap is filed under its exact evidence identity — missing, stale,
/// blocked, unavailable, omitted, exhausted, unknown, known-empty or partial —
/// from the admission disposition, the compiler's omission manifest and the
/// current candidate availability, so the refusal names the limitation the
/// owner contracts already typed.
#[derive(Debug, Default)]
struct FloorDeliveryGaps {
    missing: Vec<ArtifactId>,
    stale: Vec<ArtifactId>,
    blocked: Vec<ArtifactId>,
    unavailable: Vec<ArtifactId>,
    omitted: Vec<ArtifactId>,
    exhausted: Vec<ArtifactId>,
    unknown: Vec<ArtifactId>,
    known_empty: Vec<ArtifactId>,
    partial: Vec<ArtifactId>,
}

impl FloorDeliveryGaps {
    fn is_empty(&self) -> bool {
        self.missing.is_empty()
            && self.stale.is_empty()
            && self.blocked.is_empty()
            && self.unavailable.is_empty()
            && self.omitted.is_empty()
            && self.exhausted.is_empty()
            && self.unknown.is_empty()
            && self.known_empty.is_empty()
            && self.partial.is_empty()
    }

    fn push(&mut self, atom_id: ArtifactId, availability: Option<AtomAvailability>, omitted: bool) {
        match availability {
            Some(AtomAvailability::Stale) => self.stale.push(atom_id),
            Some(AtomAvailability::Blocked) => self.blocked.push(atom_id),
            Some(AtomAvailability::Unavailable | AtomAvailability::Missing) => {
                self.unavailable.push(atom_id);
            }
            Some(AtomAvailability::Omitted) => self.omitted.push(atom_id),
            Some(AtomAvailability::Exhausted) => self.exhausted.push(atom_id),
            Some(AtomAvailability::Unknown) => self.unknown.push(atom_id),
            Some(AtomAvailability::KnownEmpty) => self.known_empty.push(atom_id),
            Some(AtomAvailability::Partial) => self.partial.push(atom_id),
            Some(AtomAvailability::PresentCurrent) | None => {
                if omitted {
                    self.omitted.push(atom_id);
                } else {
                    self.missing.push(atom_id);
                }
            }
        }
    }

    fn sort(&mut self) {
        self.missing.sort();
        self.stale.sort();
        self.blocked.sort();
        self.unavailable.sort();
        self.omitted.sort();
        self.exhausted.sort();
        self.unknown.sort();
        self.known_empty.sort();
        self.partial.sort();
    }
}

fn check_floor_delivery(
    floor: &ApplicableFloor,
    admitted: &AdmittedContextSet,
    closure: &AdmissionInput,
    omissions: &[OmissionRecord],
) -> FloorDeliveryGaps {
    let mut gaps = FloorDeliveryGaps::default();
    for required in &floor.required {
        let record = admitted
            .records
            .iter()
            .find(|record| record.candidate.atom_id == required.atom_id);
        let omitted = omissions
            .iter()
            .any(|omission| omission.atom_id == required.atom_id);
        let satisfied = match record {
            Some(record) => {
                let admitted_kind = matches!(
                    record.disposition,
                    AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
                );
                let permitted = required
                    .allowed_representations
                    .contains(&record.candidate.representation.kind());
                let deliverable = record.disposition != AdmissionDisposition::HandleOnly
                    || record.candidate.availability == AtomAvailability::PresentCurrent
                    || has_reversible_expansion(closure, &required.atom_id);
                admitted_kind && permitted && deliverable
            }
            None => false,
        };
        if satisfied {
            continue;
        }
        match record {
            Some(record)
                if matches!(
                    record.disposition,
                    AdmissionDisposition::Blocked | AdmissionDisposition::Quarantine
                ) =>
            {
                gaps.blocked.push(required.atom_id.clone());
            }
            Some(record) if record.disposition == AdmissionDisposition::Unavailable => {
                gaps.unavailable.push(required.atom_id.clone());
            }
            _ => {
                let availability =
                    record
                        .map(|record| record.candidate.availability)
                        .or_else(|| {
                            closure
                                .candidates
                                .candidates
                                .iter()
                                .find(|candidate| candidate.atom_id == required.atom_id)
                                .map(|candidate| candidate.availability)
                        });
                gaps.push(required.atom_id.clone(), availability, omitted);
            }
        }
    }
    gaps.sort();
    gaps
}

/// Build the typed `DECISION_CONTEXT_INCOMPLETE` refusal for a failed delivery
/// proof, carrying the exact categorized gap identities.
///
/// The evidence status follows the gaps — stale, blocked, unavailable, omitted,
/// exhausted, unknown, known-empty or partial material is a delivery failure,
/// a purely missing identity is a requirement failure — and the allowed action
/// is expansion, or refresh when the only gaps are stale. A refusal that cannot
/// name any gap degrades to a boundary failure through the shared typed-refusal
/// finish rather than becoming contentless.
fn delivery_refusal(
    owners: &OperationOwnerInputs<'_>,
    gaps: &FloorDeliveryGaps,
) -> MaterialDecisionRefusal {
    let mut incomplete = DecisionContextIncomplete::new(owners.rule_evidence.clone());
    incomplete.missing.extend(gaps.missing.iter().cloned());
    incomplete.stale.extend(gaps.stale.iter().cloned());
    incomplete.blocked.extend(gaps.blocked.iter().cloned());
    incomplete
        .unavailable
        .extend(gaps.unavailable.iter().cloned());
    incomplete.omitted.extend(gaps.omitted.iter().cloned());
    incomplete.exhausted.extend(gaps.exhausted.iter().cloned());
    incomplete.unknown.extend(gaps.unknown.iter().cloned());
    incomplete
        .known_empty
        .extend(gaps.known_empty.iter().cloned());
    incomplete.partial.extend(gaps.partial.iter().cloned());
    let allowed_action = if gaps.stale.len() == gaps_count(gaps) {
        AllowedFloorAction::Refresh
    } else {
        AllowedFloorAction::Expand
    };
    incomplete
        .reopening_requirements
        .push(action_text(allowed_action));
    incomplete.reopening_requirements.push(
        "the compiled delivery does not carry the applicable floor in an owner-permitted representation"
            .to_owned(),
    );
    let refusal = DecisionFloorRefusal {
        evidence_status: incomplete_evidence_status(&incomplete),
        incomplete,
        phase: owners.phase,
        affected_references: Vec::new(),
        allowed_action,
        missing_owner: None,
    };
    refusal.into_material()
}

/// Total number of categorized delivery gaps.
fn gaps_count(gaps: &FloorDeliveryGaps) -> usize {
    gaps.missing.len()
        + gaps.stale.len()
        + gaps.blocked.len()
        + gaps.unavailable.len()
        + gaps.omitted.len()
        + gaps.exhausted.len()
        + gaps.unknown.len()
        + gaps.known_empty.len()
        + gaps.partial.len()
}

/// Whether the owner supplied a reversible expansion handle for this atom.
///
/// The handle is the owner's own evidence that the exact source can be reopened
/// before the decision; without it a handle-only delivery of non-current
/// material proves nothing.
fn has_reversible_expansion(closure: &AdmissionInput, atom_id: &ArtifactId) -> bool {
    closure
        .supplied_omissions
        .iter()
        .find(|supplied| supplied.atom_id == *atom_id)
        .is_some_and(|supplied| supplied.expansion.is_some())
}

fn incomplete_evidence_status(incomplete: &DecisionContextIncomplete) -> FloorEvidenceStatus {
    if !incomplete.oversized.is_empty() {
        FloorEvidenceStatus::FloorOversized
    } else if !incomplete.stale.is_empty()
        || !incomplete.blocked.is_empty()
        || !incomplete.unavailable.is_empty()
        || !incomplete.omitted.is_empty()
        || !incomplete.exhausted.is_empty()
    {
        FloorEvidenceStatus::RepresentationNotDeliverable
    } else {
        FloorEvidenceStatus::RequiredAtomMissing
    }
}

const fn allowed_lineage_action(completeness: DecisionLineageCompleteness) -> AllowedFloorAction {
    match completeness {
        DecisionLineageCompleteness::Stale | DecisionLineageCompleteness::Complete => {
            AllowedFloorAction::Refresh
        }
        DecisionLineageCompleteness::Unknown | DecisionLineageCompleteness::Partial => {
            AllowedFloorAction::Expand
        }
    }
}

/// Every lineage slot that is not satisfied at this phase, with the exact record
/// that accounts for the gap.
///
/// The set is phase-relative, never blanket: before a new effect the execution and
/// outcome receipts of that effect do not exist yet and are therefore not
/// reported, while at resume, verification and finish an unresolved execution or
/// outcome record is exactly what must be named.
fn affected_lineage_references(
    lineage: &DecisionExecutionLineageRefs,
    phase: DecisionLineagePhase,
) -> Vec<AffectedLineageReference> {
    let mut affected = Vec::new();
    macro_rules! account {
        ($name:literal, $slot:expr) => {
            if let Some(reference) = slot_accounting_ref($slot) {
                affected.push(AffectedLineageReference {
                    slot: $name,
                    reference: reference.clone(),
                });
            }
        };
    }
    account!("goal", &lineage.goal);
    account!("acceptance", &lineage.acceptance);
    account!("task", &lineage.task);
    account!("observations", &lineage.observations);
    account!("evidence", &lineage.evidence);
    account!("epistemic_position", &lineage.epistemic_position);
    account!("material_unknowns", &lineage.material_unknowns);
    account!("rivals", &lineage.rivals);
    account!("selected_option", &lineage.selected_option);
    account!("rationale", &lineage.rationale);
    account!("why_now", &lineage.why_now);
    account!("revisit_conditions", &lineage.revisit_conditions);
    account!("action_contract", &lineage.action_contract);
    account!("operations", &lineage.operations);
    account!("diffs", &lineage.diffs);
    account!("change_observations", &lineage.change_observations);
    account!("anchors", &lineage.anchors);
    account!("reviews", &lineage.reviews);
    account!("artifacts", &lineage.artifacts);
    account!("verifiers", &lineage.verifiers);
    account!("outcomes", &lineage.outcomes);
    account!("memory_revisions", &lineage.memory_revisions);
    account!("omissions", &lineage.omissions);
    account!("handoff", &lineage.handoff);
    for effect in &lineage.effects {
        account!("effect.proposal", &effect.proposal);
        account!("effect.authorization", &effect.authorization);
        account!("effect.expected_observable", &effect.expected_observable);
        if phase != DecisionLineagePhase::BeforeEffect {
            account!("effect.execution", &effect.execution);
            account!("effect.outcome", &effect.outcome);
        }
    }
    if let DecisionLineageSupersession::Superseded { successor } = &lineage.epoch.supersession {
        affected.push(AffectedLineageReference {
            slot: "epoch.supersession",
            reference: successor.clone(),
        });
    }
    affected.truncate(MAX_AFFECTED_REFERENCES);
    affected
}

/// The record a non-present lineage slot names, or `None` when the slot is
/// satisfied by a present typed record.
fn slot_accounting_ref<T>(slot: &DecisionLineageSlot<T>) -> Option<&DecisionLineageRef> {
    match slot {
        DecisionLineageSlot::Present { .. } => None,
        DecisionLineageSlot::NotApplicable { policy, .. }
        | DecisionLineageSlot::NotYetProduced { policy, .. } => Some(policy),
        DecisionLineageSlot::Unknown { evidence, .. } => Some(evidence),
    }
}

/// No owner-issued policy applies to the resolved impact class.
///
/// The compiled floor's own mandatory identities are named because they are the
/// only exact identities the owner has not covered with an applicable policy, and
/// the owner that must issue one is named with the refusal.
fn deny_without_applicable_policy(
    owners: &OperationOwnerInputs<'_>,
    closure: &AdmissionInput,
) -> MaterialDecisionRefusal {
    let uncovered = closure.floor.floor.mandatory_atoms.clone();
    if uncovered.is_empty() {
        return MaterialDecisionRefusal::Boundary(ContextError::MissingFloor);
    }
    typed_refusal(
        owners,
        FloorEvidenceStatus::OwnerPolicyMissing,
        AllowedFloorAction::Refresh,
        &uncovered,
        OWNER_FLOOR_POLICY,
        Some(OWNER_FLOOR_POLICY),
        Vec::new(),
    )
}

/// Build one typed `DECISION_CONTEXT_INCOMPLETE` refusal with its exact gap
/// identities, reason, named owner and affected lineage references.
///
/// A refusal that cannot name any gap is a boundary defect rather than evidence,
/// so it degrades to a preserved [`MaterialDecisionRefusal::Boundary`] failure
/// instead of becoming a contentless incomplete result.
#[allow(clippy::too_many_arguments)]
fn typed_refusal(
    owners: &OperationOwnerInputs<'_>,
    evidence_status: FloorEvidenceStatus,
    allowed_action: AllowedFloorAction,
    identities: &[ArtifactId],
    reason: &str,
    missing_owner: Option<&'static str>,
    references: Vec<AffectedLineageReference>,
) -> MaterialDecisionRefusal {
    let mut incomplete = DecisionContextIncomplete::new(owners.rule_evidence.clone());
    incomplete.missing.extend(identities.iter().cloned());
    if incomplete.missing.is_empty() {
        incomplete.missing.push(owners.rule_evidence.clone());
    }
    incomplete
        .reopening_requirements
        .push(action_text(allowed_action));
    if owner_text(reason) {
        incomplete.reopening_requirements.push(reason.to_owned());
    }
    let refusal = DecisionFloorRefusal {
        incomplete,
        phase: owners.phase,
        evidence_status,
        affected_references: references,
        allowed_action,
        missing_owner,
    };
    refusal.into_material()
}

/// Carry the pure compiler's own `Incomplete` outcome through unchanged.
///
/// Every gap list the compiler recorded - missing, stale, blocked, unavailable,
/// omitted, exhausted, unknown, known-empty, partial, oversized, provider gaps,
/// measurements and its own reopening requirements - survives verbatim. The gate
/// adds only the evidence status, the phase and the allowed action; it never
/// renames, drops or re-sorts a gap the compiler already decided.
fn compiler_incomplete_refusal(
    owners: &OperationOwnerInputs<'_>,
    incomplete: &DecisionContextIncomplete,
) -> MaterialDecisionRefusal {
    let refusal = DecisionFloorRefusal {
        incomplete: incomplete.clone(),
        phase: owners.phase,
        evidence_status: incomplete_evidence_status(incomplete),
        affected_references: Vec::new(),
        allowed_action: AllowedFloorAction::Refresh,
        missing_owner: None,
    };
    refusal.into_material()
}

impl DecisionFloorRefusal {
    /// Finish the refusal, preserving a boundary failure when the typed
    /// incomplete result itself cannot name any gap.
    fn into_material(self) -> MaterialDecisionRefusal {
        match self.incomplete.validate() {
            Ok(()) => MaterialDecisionRefusal::Incomplete(Box::new(self)),
            Err(error) => MaterialDecisionRefusal::Boundary(error),
        }
    }
}

fn action_text(action: AllowedFloorAction) -> String {
    let text = match action {
        AllowedFloorAction::Refresh => {
            "re-resolve the owner inputs and recompile the closure at the current fence"
        }
        AllowedFloorAction::Expand => {
            "expand the named references from their retained source before the decision"
        }
        AllowedFloorAction::Narrow => {
            "submit a new, explicitly narrower proposal for normal evaluation"
        }
    };
    text.to_owned()
}

/// The material dispatch path an admitted operation is bound for (issue #1742,
/// work item 4).
///
/// `I7.8` requires the pre-action check before Material action on every route:
/// the actual action, a delegated worker, a verifier with effects, and a resume
/// dispatch all reach the one shared suitability-and-authority check
/// ([`admit_material_decision`]), never a per-route permit. The kind names which
/// dispatch path the binding below was issued for; every kind carries the same
/// bound facts and the same dispatch revalidation, so mislabelling a path
/// cannot weaken the gate — and a resume dispatch at any other phase (or any
/// other kind at resume phase) fails closed at bind time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaterialEntrypointKind {
    /// The authenticated runtime caller invoking the material action itself.
    DirectAction,
    /// A delegated worker invoked with the admitted operation's bound facts.
    DelegatedWorker,
    /// A verifier whose verification itself carries effects.
    VerifierWithEffects,
    /// A resume dispatch continuing compacted work under retained history.
    ResumeDispatch,
}

/// One source revision bound into the dispatch binding.
///
/// The admitted packet's canonical digest already covers source content; these
/// triples additionally pin the exact source revision each delivered atom was
/// compiled from, so a source substitution under an identical packet shape
/// still fails the dispatch comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundSourceRevision {
    /// Exact identity of the delivered atom.
    pub atom_id: ArtifactId,
    /// Source revision the atom was compiled from.
    pub revision: String,
    /// Content digest of the complete source snapshot.
    pub content_sha256: String,
}

/// The admitted operation bound for effect dispatch (issue #1742, work item 4).
///
/// This is the record the dispatch path presents back at effect dispatch: the
/// checked action parameters and resources, the packet and output digest, the
/// recipe, task and source revisions, the phase-aware lineage outcome, and the
/// authority owner's effect ceiling, all content-compared by
/// [`revalidate_material_dispatch`] against current owner evidence. The embedded
/// [`AdmittedDecisionFloor`] already binds the complete checked floor set with
/// its content handle; this binding extends that handle over the dispatch facts
/// so a swapped packet, a widened ceiling, a moved fence, or a saved valid
/// lease from another operation cannot pass as this one. It creates no permit
/// authority and no evaluator: admission stays in [`admit_material_decision`]
/// and authority stays with its owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialDispatchBinding {
    /// Dispatch path this binding was issued for.
    pub entrypoint: MaterialEntrypointKind,
    /// Decision identity the operation was admitted for.
    pub decision_id: DecisionId,
    /// Retained fence the operation was admitted at.
    pub state_fence: StateFence,
    /// Owner-resolved task identity.
    pub task_id: TaskId,
    /// Owner-resolved task/acceptance revision.
    pub acceptance_revision: TaskRevision,
    /// Owner-resolved resources the operation may touch.
    pub requested_resources: BTreeSet<String>,
    /// Owner-resolved impact class of the actual operation.
    pub impact_class: ImpactClass,
    /// Authority-owner effect ceiling checked at admission.
    pub effect_ceiling: EffectCeiling,
    /// Owner-issued Governance Profile reference.
    pub governance_profile_ref: String,
    /// Owner-issued authority reference backing the operation.
    pub authority_ref: String,
    /// Recipe digest the packet was compiled under.
    pub recipe_sha256: String,
    /// Exact source revisions of the delivered atoms, ordered by atom identity.
    pub sources: Vec<BoundSourceRevision>,
    /// Canonical digest of the admitted packet the effect must run under.
    pub packet_digest: String,
    /// The admitted applicable floor, with its own content handle.
    pub floor: AdmittedDecisionFloor,
    /// Decision phase the lineage was validated for.
    pub phase: DecisionLineagePhase,
    /// Phase-relative completeness of the validated lineage (always complete
    /// on a bound operation; anything else never reaches dispatch).
    pub lineage_completeness: DecisionLineageCompleteness,
    /// Content-addressed handle (`dispatch-binding:<sha256>`) resolving to
    /// exactly this bound operation.
    pub handle: String,
}

impl MaterialDispatchBinding {
    /// Re-resolve the content-addressed handle and the embedded floor handle.
    ///
    /// Any swapped entrypoint, parameter, digest, revision, ceiling, floor or
    /// lineage outcome fails closed here, before any current-owner comparison.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.handle != dispatch_binding_handle(self)? {
            return Err(ContextError::InvalidField("dispatch_binding.handle"));
        }
        self.floor.validate()
    }
}

fn dispatch_binding_handle(binding: &MaterialDispatchBinding) -> Result<String, ContextError> {
    let unsigned = MaterialDispatchBinding {
        handle: String::new(),
        ..binding.clone()
    };
    Ok(format!("dispatch-binding:{}", canonical_digest(&unsigned)?))
}

/// Current owner observations presented at effect dispatch.
///
/// Every field is read from its owner at dispatch time, never carried over
/// from admission: the fence from the Kernel, the ceiling and authority from
/// the authority owner, the packet as presented for dispatch, and the lineage
/// for revalidation. The revalidation compares these contents against the
/// binding; a missing or moved owner input fails rather than falling back to
/// the bound copy.
pub struct DispatchOwnerState<'a> {
    /// Fence the dispatch owner observes now.
    pub state_fence: &'a StateFence,
    /// Task/acceptance revision the dispatch owner observes now.
    pub acceptance_revision: TaskRevision,
    /// Effect ceiling the authority owner asserts now.
    pub effect_ceiling: EffectCeiling,
    /// Authority reference backing the dispatch now.
    pub authority_ref: &'a str,
    /// Packet presented for dispatch.
    pub packet: &'a AdmittedContextSet,
    /// Lineage presented for dispatch revalidation.
    pub lineage: &'a DecisionExecutionLineageRefs,
}

/// Bind one admitted operation for effect dispatch on one entrypoint.
///
/// The binding captures the owner-resolved parameters, the recipe digest, the
/// per-delivered-atom source revisions, the admitted packet digest, the
/// admitted floor with its handle, the phase-aware lineage outcome, and the
/// authority owner's effect ceiling. Coherence is checked with the same
/// predicates admission uses — packet and floor decision, task and fence
/// against the owner inputs — plus entrypoint/phase coherence, so a resume
/// dispatch is bound only at resume phase and any other path only away from
/// it. The presented lineage must validate complete for the phase; binding is
/// for execution, and an incomplete lineage never reaches dispatch.
///
/// This binds facts; it admits nothing. Suitability and authority were decided
/// by [`admit_material_decision`]; a binding over an unadmitted floor cannot
/// exist because the floor handle check requires the admission's own digest.
///
/// # Errors
///
/// [`MaterialDecisionRefusal::Incomplete`] with
/// [`FloorEvidenceStatus::LineageIncomplete`] when the presented lineage is not
/// complete for the phase. [`MaterialDecisionRefusal::Boundary`] for an
/// entrypoint/phase mismatch, an incoherent packet, floor or recipe, a closure
/// that is not this operation's own closure (fence, decision, task or task
/// revision), or a malformed owner input.
pub fn bind_material_dispatch(
    entrypoint: MaterialEntrypointKind,
    owners: &OperationOwnerInputs<'_>,
    effect_ceiling: EffectCeiling,
    closure: &AdmissionInput,
    packet: &AdmittedContextSet,
    floor: &AdmittedDecisionFloor,
    lineage: &DecisionExecutionLineageRefs,
) -> Result<MaterialDispatchBinding, MaterialDecisionRefusal> {
    owners
        .validate()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    let is_resume = owners.phase == DecisionLineagePhase::Resume;
    let wants_resume = matches!(entrypoint, MaterialEntrypointKind::ResumeDispatch);
    if is_resume != wants_resume {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidField("dispatch.entrypoint"),
        ));
    }
    if !fences_match_exact(&packet.binding.state_fence, owners.state_fence) {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidFence,
        ));
    }
    if packet.binding.decision_id != *owners.decision_id
        || packet.binding.task_id.as_str() != owners.task_id.as_str()
    {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::IdentityConflict,
        ));
    }
    if floor.floor.decision_id != *owners.decision_id
        || floor.floor.acceptance_revision != owners.acceptance_revision
        || !fences_match_exact(&floor.floor.state_fence, owners.state_fence)
    {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::IdentityConflict,
        ));
    }
    floor
        .validate()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    // The binding records `recipe_sha256` from the presented closure, so the
    // closure must be this operation's own closure before its recipe is bound.
    // Without this the binder would stamp a foreign or substituted closure's
    // recipe revision into this operation's dispatch binding — a same-fence
    // packet compiled under a different action/recipe would pass, which is
    // exactly what the fence/decision/task/floor checks above exclude for every
    // other bound fact. Same predicate as admission, one shared helper.
    check_closure_is_this_operation(owners, closure).map_err(MaterialDecisionRefusal::Boundary)?;
    if !owner_text(&closure.recipe.recipe_sha256) {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidField("dispatch.recipe"),
        ));
    }
    let completeness = lineage
        .validate_for_phase(owners.phase)
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if completeness != DecisionLineageCompleteness::Complete {
        let references = affected_lineage_references(lineage, owners.phase);
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::LineageIncomplete,
            allowed_lineage_action(completeness),
            std::slice::from_ref(&owners.rule_evidence),
            "the decision lineage is not complete for the current decision phase",
            None,
            references,
        ));
    }
    let packet_digest = packet
        .canonical_payload_digest()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    let mut sources = Vec::with_capacity(floor.delivered.len());
    for atom_id in &floor.delivered {
        let Some(record) = packet
            .records
            .iter()
            .find(|record| record.candidate.atom_id == *atom_id)
        else {
            return Err(MaterialDecisionRefusal::Boundary(
                ContextError::IdentityConflict,
            ));
        };
        sources.push(BoundSourceRevision {
            atom_id: atom_id.clone(),
            revision: record.candidate.source.revision.clone(),
            content_sha256: record.candidate.source.content_sha256.clone(),
        });
    }
    sources.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    let mut binding = MaterialDispatchBinding {
        entrypoint,
        decision_id: owners.decision_id.clone(),
        state_fence: owners.state_fence.clone(),
        task_id: owners.task_id.clone(),
        acceptance_revision: owners.acceptance_revision,
        requested_resources: owners.requested_resources.clone(),
        impact_class: owners.impact_class,
        effect_ceiling,
        governance_profile_ref: owners.governance_profile_ref.to_owned(),
        authority_ref: owners.authority_ref.to_owned(),
        recipe_sha256: closure.recipe.recipe_sha256.clone(),
        sources,
        packet_digest,
        floor: floor.clone(),
        phase: owners.phase,
        lineage_completeness: completeness,
        handle: String::new(),
    };
    binding.handle =
        dispatch_binding_handle(&binding).map_err(MaterialDecisionRefusal::Boundary)?;
    binding
        .validate()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    Ok(binding)
}

/// Revalidate one bound operation against current owner evidence at effect
/// dispatch (issue #1742, work item 4).
///
/// Every bound fact is content-compared, never trusted from the handle alone:
/// the current fence must still equal the bound fence, the acceptance revision
/// and authority reference must be unchanged, the authority owner's ceiling
/// must equal the checked ceiling, the presented packet must digest to the
/// bound packet digest with identical per-atom source revisions, and the
/// presented lineage must still validate complete for the bound phase. A
/// swapped packet after admission, an effect invoked without the admitted
/// packet, a saved valid lease from another operation, or a widened ceiling
/// each fail here, before any effectful owner call. `I7.20` applies unchanged:
/// fence and identity mismatches are boundary failures, stale or drifted owner
/// evidence is `DECISION_CONTEXT_INCOMPLETE` with a refresh action, and an
/// incomplete lineage keeps its exact affected references.
///
/// # Errors
///
/// [`MaterialDecisionRefusal::Incomplete`] for drifted revision, ceiling or
/// authority evidence (refresh) or a lineage that no longer validates complete
/// for the phase. [`MaterialDecisionRefusal::Boundary`] for a tampered
/// binding, a moved fence, or a substituted packet or source.
pub fn revalidate_material_dispatch(
    binding: &MaterialDispatchBinding,
    current: &DispatchOwnerState<'_>,
) -> Result<(), MaterialDecisionRefusal> {
    binding
        .validate()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if !fences_match_exact(current.state_fence, &binding.state_fence) {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidFence,
        ));
    }
    if current.acceptance_revision != binding.acceptance_revision {
        return Err(dispatch_refusal(
            binding,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Refresh,
            "the task/acceptance revision moved after admission; re-resolve the owner inputs and recompile the closure at the current fence",
        ));
    }
    if current.effect_ceiling != binding.effect_ceiling {
        return Err(dispatch_refusal(
            binding,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Refresh,
            "the authority owner's effect ceiling changed after admission; the bound ceiling no longer covers this dispatch",
        ));
    }
    if !owner_text(current.authority_ref) || current.authority_ref != binding.authority_ref {
        return Err(dispatch_refusal(
            binding,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Refresh,
            "the authority backing the operation changed after admission; obtain the current authority and rebind",
        ));
    }
    let packet_digest = current
        .packet
        .canonical_payload_digest()
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if packet_digest != binding.packet_digest {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::IdentityConflict,
        ));
    }
    for bound in &binding.sources {
        let source_matches = current
            .packet
            .records
            .iter()
            .find(|record| record.candidate.atom_id == bound.atom_id)
            .is_some_and(|record| {
                record.candidate.source.revision == bound.revision
                    && record.candidate.source.content_sha256 == bound.content_sha256
            });
        if !source_matches {
            return Err(MaterialDecisionRefusal::Boundary(
                ContextError::IdentityConflict,
            ));
        }
    }
    let completeness = current
        .lineage
        .validate_for_phase(binding.phase)
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if completeness != DecisionLineageCompleteness::Complete {
        let references = affected_lineage_references(current.lineage, binding.phase);
        return Err(dispatch_lineage_refusal(binding, completeness, references));
    }
    Ok(())
}

/// Build one dispatch-time `DECISION_CONTEXT_INCOMPLETE` refusal over the
/// binding's own rule evidence, phase and floor context.
fn dispatch_refusal(
    binding: &MaterialDispatchBinding,
    evidence_status: FloorEvidenceStatus,
    allowed_action: AllowedFloorAction,
    reason: &str,
) -> MaterialDecisionRefusal {
    let mut incomplete = DecisionContextIncomplete::new(binding.floor.floor.rule_evidence.clone());
    incomplete
        .missing
        .push(binding.floor.floor.rule_evidence.clone());
    incomplete
        .reopening_requirements
        .push(action_text(allowed_action));
    if owner_text(reason) {
        incomplete.reopening_requirements.push(reason.to_owned());
    }
    DecisionFloorRefusal {
        incomplete,
        phase: binding.phase,
        evidence_status,
        affected_references: Vec::new(),
        allowed_action,
        missing_owner: None,
    }
    .into_material()
}

/// Build the dispatch-time lineage refusal with the exact affected references.
fn dispatch_lineage_refusal(
    binding: &MaterialDispatchBinding,
    completeness: DecisionLineageCompleteness,
    references: Vec<AffectedLineageReference>,
) -> MaterialDecisionRefusal {
    let mut incomplete = DecisionContextIncomplete::new(binding.floor.floor.rule_evidence.clone());
    incomplete
        .missing
        .push(binding.floor.floor.rule_evidence.clone());
    let allowed_action = allowed_lineage_action(completeness);
    incomplete
        .reopening_requirements
        .push(action_text(allowed_action));
    incomplete
        .reopening_requirements
        .push("the decision lineage is no longer complete for the bound decision phase".to_owned());
    DecisionFloorRefusal {
        incomplete,
        phase: binding.phase,
        evidence_status: FloorEvidenceStatus::LineageIncomplete,
        affected_references: references,
        allowed_action,
        missing_owner: None,
    }
    .into_material()
}

/// Retained history a resumed material decision must consume (issue #1742,
/// work item 6).
///
/// This is #1730's retained checkpoint plus its resume-time revalidation,
/// reused verbatim — never reimplemented, re-sealed, or treated as a fresh
/// authority source — together with the rebuilt current delta View the resume
/// owner presents. The checkpoint carries the capture boundary: the task and
/// attempt, the retained fence and generations, the in-flight effects with
/// their dispositions, the known losses, and the unavailable work members.
/// Compaction keeps those; it mints no authority, so continuing under the
/// retained fence after a generation or fence change is refused until the
/// current delta View and the current authority are bound instead.
pub struct ResumeHistoryInputs<'a> {
    /// Retained checkpoint with the resume-time revalidation the resume owner
    /// computed over current observations.
    pub retained: &'a RetainedHandoffCheckpoint,
    /// Rebuilt current delta View: a digest-bound immutable artifact observed
    /// now, never the retained diff restamped.
    pub current_delta_view: &'a PublicReference,
}

/// Admit one resumed material decision under retained history (issue #1742,
/// work item 6).
///
/// History is consumed before the shared check runs, in fail-closed order:
///
/// 1. The decision phase must be resume: any other phase has no retained
///    history to consume and is a boundary misuse of this entrypoint.
/// 2. The retained checkpoint with its revalidation must pass the owner's own
///    [`RetainedHandoffCheckpoint::validate`]; a reassigned or mismatched
///    revalidation is a boundary failure, never a silent pass.
/// 3. The rebuilt delta View must be a valid digest-bound reference: an
///    undigested view proves no immutable current content.
/// 4. The decision fence must be the applicable fence — the unchanged retained
///    fence when no generation or fence moved, the revalidated current fence
///    otherwise. A changed world resumed under the retained fence, or any
///    third fence, is `DECISION_CONTEXT_INCOMPLETE` with a refresh action:
///    rebuild the delta View and obtain the new authority first.
/// 5. When a generation or the fence changed, the delta View must differ from
///    the retained digest-bound diff: restamping the old diff is not a
///    rebuild.
/// 6. A blocking critical attention item surviving the boundary keeps the
///    dependent action blocked: the resume is refused as incomplete until the
///    item is resolved or a new explicitly narrower proposal is submitted.
/// 7. The lineage `handoff` slot must presently cite exactly the retained
///    checkpoint reference: a summary, a different checkpoint, or an explicit
///    unknown in place of the consumed checkpoint fails the resume.
/// 8. Every retained known loss must be named by the lineage `omissions`
///    relation, and any known loss or unavailable member requires that
///    relation to exist explicitly: unavailable or erased originals stay
///    visible, never compacted away.
/// 9. The shared suitability-and-authority check
///    ([`admit_material_decision`]) then runs unchanged, so the resume-phase
///    lineage rule — already-due execution and outcome records present or
///    explicitly unknown — and the full floor, coverage and delivery proofs
///    apply to resumed work exactly as to new effects.
///
/// Traceability is preserved by these bindings; it proves no beneficial use,
/// causal improvement, or task completion.
///
/// # Errors
///
/// [`MaterialDecisionRefusal::Incomplete`] for a stale fence, a restamped
/// delta, a blocking survivor, an uncited checkpoint, or unnamed losses, and
/// for every refusal the shared check itself produces.
/// [`MaterialDecisionRefusal::Boundary`] for a non-resume phase or a malformed
/// retained, delta, or owner input.
#[allow(clippy::too_many_lines)]
pub fn admit_material_resume(
    owners: &OperationOwnerInputs<'_>,
    policies: &[FloorAtomPolicy],
    closure: &AdmissionInput,
    lineage: &DecisionExecutionLineageRefs,
    history: &ResumeHistoryInputs<'_>,
) -> Result<AdmittedDecisionFloor, MaterialDecisionRefusal> {
    if owners.phase != DecisionLineagePhase::Resume {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidField("resume.phase"),
        ));
    }
    history.retained.validate().map_err(|_| {
        MaterialDecisionRefusal::Boundary(ContextError::InvalidField("resume.retained_checkpoint"))
    })?;
    history.current_delta_view.validate().map_err(|_| {
        MaterialDecisionRefusal::Boundary(ContextError::InvalidField("resume.current_delta_view"))
    })?;
    if history.current_delta_view.digest.is_none() {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidField("resume.current_delta_view.digest"),
        ));
    }
    let checkpoint = &history.retained.checkpoint;
    let revalidation = &history.retained.revalidation;
    let changed = history.retained.requires_fresh_authority_before_execution();
    let applicable = if changed {
        &revalidation.current_fence
    } else {
        &checkpoint.state_fence
    };
    if !fences_match_exact(owners.state_fence, applicable) {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Refresh,
            &[],
            "the resumed decision is not bound to the applicable fence: the unchanged retained fence, or the revalidated current fence once a generation or the fence moved",
            None,
            Vec::new(),
        ));
    }
    if changed && history.current_delta_view.digest == checkpoint.diff_ref.digest {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Refresh,
            &[],
            "a generation or the fence moved, but the presented delta View restamps the retained diff; rebuild a current delta View and obtain the new authority before continuing",
            None,
            Vec::new(),
        ));
    }
    if checkpoint.dependent_action_blocked() {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RepresentationNotDeliverable,
            AllowedFloorAction::Narrow,
            &[],
            "a blocking critical attention item survives the capture boundary; the dependent action stays blocked until the item is resolved",
            None,
            Vec::new(),
        ));
    }
    let checkpoint_ref = history.retained.checkpoint_ref().map_err(|_| {
        MaterialDecisionRefusal::Boundary(ContextError::InvalidField("resume.checkpoint_ref"))
    })?;
    let cites_checkpoint = matches!(
        &lineage.handoff,
        DecisionLineageSlot::Present { value } if value.reference == checkpoint_ref
    );
    if !cites_checkpoint {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::LineageIncomplete,
            AllowedFloorAction::Expand,
            std::slice::from_ref(&owners.rule_evidence),
            "the resumed lineage does not cite the retained checkpoint; derived summaries never replace the original rationale and evidence",
            None,
            affected_lineage_references(lineage, owners.phase),
        ));
    }
    if !checkpoint.known_losses.is_empty() || !checkpoint.work.unavailable.is_empty() {
        let named = omissions_named_references(lineage);
        let unnamed = checkpoint
            .known_losses
            .iter()
            .any(|loss| !named.contains(&&loss.subject_ref));
        let explicit = matches!(
            &lineage.omissions,
            DecisionLineageSlot::Present { .. } | DecisionLineageSlot::Unknown { .. }
        );
        if !explicit || unnamed {
            return Err(typed_refusal(
                owners,
                FloorEvidenceStatus::LineageIncomplete,
                AllowedFloorAction::Expand,
                std::slice::from_ref(&owners.rule_evidence),
                "a retained known loss or unavailable member is not explicit in the resumed lineage omissions; unavailable and erased originals stay named",
                None,
                affected_lineage_references(lineage, owners.phase),
            ));
        }
    }
    admit_material_decision(owners, policies, closure, lineage)
}

/// Every public reference the lineage `omissions` relation names, whatever its
/// slot shape: present values, policy references behind an inapplicable or
/// deferred relation, or evidence behind an explicit unknown.
fn omissions_named_references(lineage: &DecisionExecutionLineageRefs) -> Vec<&PublicReference> {
    let mut named = Vec::new();
    match &lineage.omissions {
        DecisionLineageSlot::Present { value } => {
            named.extend(value.iter().map(|reference| &reference.reference));
        }
        DecisionLineageSlot::NotApplicable { policy, .. }
        | DecisionLineageSlot::NotYetProduced { policy, .. } => {
            named.push(&policy.reference);
        }
        DecisionLineageSlot::Unknown { evidence, .. } => {
            named.push(&evidence.reference);
        }
    }
    named
}
