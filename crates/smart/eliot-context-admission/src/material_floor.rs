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
//!   declared dependency references, and counts the required identities per
//!   semantic role. It reads no caller packet, recipe, compiled floor, tool name
//!   or `read_only` bit, so a caller cannot narrow the floor.
//! - [`admit_material_decision`] then invokes the existing pure compiler
//!   ([`crate::admit_context_traced`]) over the owner-resolved closure, proves
//!   that the compiled delivery actually covers the derived floor with the
//!   representations the owner policy permits, and validates the phase-aware
//!   `I12.31` lineage for the current decision phase.
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

use eliot_authority::ImpactClass;
use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmittedContextSet, AtomAvailability, ContextError,
    ContextOutcome, DecisionContextIncomplete, DecisionExecutionLineageRefs,
    DecisionLineageCompleteness, DecisionLineagePhase, DecisionLineageRef, DecisionLineageSlot,
    DecisionLineageSupersession, LossPolicy, OmissionRecord, RepresentationKind, RoleLossRule,
    SemanticRole, canonical_digest,
};
use eliot_contracts::{
    ArtifactId, DecisionId, StateFence, TaskId, TaskRevision, fences_match_exact,
};
use eliot_receipts::ProofCeiling;
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
/// their declared dependencies. The compiled packet floor is *checked against*
/// this set, never the other way round.
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
/// enough: every applicable identity, every declared dependency and every
/// semantic role the owner bound is counted, and any identity the closure cannot
/// supply is returned as an exact `missing` gap rather than dropped.
///
/// # Errors
///
/// Returns [`MaterialDecisionRefusal::Incomplete`] with
/// [`FloorEvidenceStatus::OwnerPolicyMissing`] when no owner-issued policy is
/// applicable to the resolved impact class, and with
/// [`FloorEvidenceStatus::RequiredAtomMissing`] naming the exact atom identities
/// the declared dependency closure cannot supply. A malformed owner input or
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
    let undeliverable = undeliverable_dependencies(&selected, closure)
        .map_err(MaterialDecisionRefusal::Boundary)?;
    if !undeliverable.is_empty() {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RequiredAtomMissing,
            AllowedFloorAction::Expand,
            &undeliverable,
            "the applicable floor requires an atom the owner-resolved closure does not supply",
            None,
            Vec::new(),
        ));
    }
    Ok(ApplicableFloor {
        decision_id: owners.decision_id.clone(),
        state_fence: owners.state_fence.clone(),
        impact_class: owners.impact_class,
        governance_profile_ref: owners.governance_profile_ref.to_owned(),
        authority_ref: owners.authority_ref.to_owned(),
        acceptance_revision: owners.acceptance_revision,
        required: selected.required.into_values().collect(),
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

/// Close the selected requirements over their declared and observed dependencies,
/// counting every visited identity and reporting every identity the closure
/// cannot supply.
///
/// The bound is fail-closed: an over-large closure is a `Bounds` boundary
/// failure, never a silently truncated requirement set.
fn undeliverable_dependencies(
    selected: &SelectedFloorRequirements,
    closure: &AdmissionInput,
) -> Result<Vec<ArtifactId>, ContextError> {
    let mut queue: Vec<ArtifactId> = Vec::new();
    queue.extend(selected.required.keys().cloned());
    queue.extend(selected.declared.iter().cloned());
    let mut visited: BTreeSet<ArtifactId> = BTreeSet::new();
    let mut undeliverable: Vec<ArtifactId> = Vec::new();
    while let Some(atom_id) = queue.pop() {
        if !visited.insert(atom_id.clone()) {
            continue;
        }
        if visited.len() > MAX_FLOOR_CLOSURE {
            return Err(ContextError::Bounds {
                field: "floor.closure",
            });
        }
        match closure
            .candidates
            .candidates
            .iter()
            .find(|candidate| candidate.atom_id == atom_id)
        {
            Some(candidate) => queue.extend(candidate.dependencies.iter().cloned()),
            None if !undeliverable.contains(&atom_id) => undeliverable.push(atom_id),
            None => {}
        }
    }
    undeliverable.sort();
    Ok(undeliverable)
}

/// Compile and prove delivery of the applicable floor, or refuse with the exact
/// typed `DECISION_CONTEXT_INCOMPLETE` limitation.
///
/// Order of operations, each step fail-closed:
///
/// 1. [`derive_applicable_floor`] from the owner inputs, never from the caller's
///    packet or recipe.
/// 2. Validate the `I12.31` [`DecisionExecutionLineageRefs`] for the current
///    decision phase through the shared `validate_for_phase`, so a new effect
///    binds its proposal, authorization and required future observable without
///    demanding a not-yet-existing execution or outcome receipt, while resume,
///    verification and finish require the already-due observed or explicitly
///    unknown records.
/// 3. Invoke the existing pure compiler ([`crate::admit_context_traced`]) over the
///    owner-resolved closure. Its `Incomplete` outcome is carried through
///    verbatim; its boundary refusals are preserved uncollapsed.
/// 4. Prove the delivery: every derived requirement is in the compiled floor,
///    admitted, and carried in a representation its owner policy permits. A handle
///    satisfies a requirement only when the exact source is currently present or
///    carries a reversible owner expansion handle, so a handle for absent or
///    non-current material is a delivery gap rather than a satisfied requirement.
/// 5. Return the exact floor, the delivered identities, the permitted loss and
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
    if !fences_match_exact(&closure.binding.state_fence, owners.state_fence) {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidFence,
        ));
    }
    if closure.binding.decision_id != *owners.decision_id {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::IdentityConflict,
        ));
    }
    // The closure must be the closure of THIS operation: a packet compiled for
    // another task, even at the same fence, is a substituted packet, not
    // evidence for this decision.
    if closure.binding.task_id.as_str() != owners.task_id.as_str() {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::IdentityConflict,
        ));
    }
    if closure.binding.state_fence.task_revision != Some(owners.acceptance_revision) {
        return Err(MaterialDecisionRefusal::Boundary(
            ContextError::InvalidField("closure.task_revision"),
        ));
    }
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
    let undelivered = undelivered_atoms(&floor, admitted, closure);
    if !undelivered.is_empty() {
        return Err(typed_refusal(
            owners,
            FloorEvidenceStatus::RepresentationNotDeliverable,
            AllowedFloorAction::Expand,
            &undelivered,
            "the compiled delivery does not carry the applicable floor in an owner-permitted representation",
            None,
            Vec::new(),
        ));
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

/// Required atoms the compiled delivery does not actually carry.
///
/// A requirement is satisfied only when the atom is in the compiled floor, is
/// admitted, and carries a representation its owner policy permits. A handle-only
/// delivery additionally requires the exact source to be currently present or to
/// carry a reversible owner expansion handle, because possession of a handle for
/// absent or non-current material is not access.
fn undelivered_atoms(
    floor: &ApplicableFloor,
    admitted: &AdmittedContextSet,
    closure: &AdmissionInput,
) -> Vec<ArtifactId> {
    let mut undelivered = Vec::new();
    for required in &floor.required {
        if !admitted.floor.mandatory_atoms.contains(&required.atom_id) {
            undelivered.push(required.atom_id.clone());
            continue;
        }
        let Some(record) = admitted
            .records
            .iter()
            .find(|record| record.candidate.atom_id == required.atom_id)
        else {
            undelivered.push(required.atom_id.clone());
            continue;
        };
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
        if !admitted_kind || !permitted || !deliverable {
            undelivered.push(required.atom_id.clone());
        }
    }
    undelivered.sort();
    undelivered.dedup();
    undelivered
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
