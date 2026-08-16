//! Store-neutral Smart contracts and pure compilation for ELIOT context.
//!
//! This crate owns the derived understanding view and its admission rules.  It
//! does not own canonical memory, a graph index, a model route, or a write
//! authority.  Inputs are already admitted records; outputs retain handles,
//! fences, omissions and explicit uncertainty so a caller can rebuild or
//! inspect every decision made by the compiler.

#![forbid(unsafe_code)]

use std::cmp::Ordering;

use eliot_contracts::{ArtifactId, ContractVersion, DecisionId, StateFence, TaskRevision};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};
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
        for role in &self.required_roles {
            if !self.role_budgets.iter().any(|budget| budget.role == *role) {
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
        for atom in &self.atoms {
            atom.validate()?;
            if !self.state_fence.is_compatible_with(&atom.state_fence) {
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
        input.validate()?;
        recipe.validate()?;
        let mut candidates = input.atoms.clone();
        candidates.sort_by(Self::candidate_order);
        let mut units = Vec::new();
        let mut handles = Vec::new();
        let mut admissions = Vec::with_capacity(candidates.len());
        let mut spent_total = 0_u32;
        let mut spent_roles: Vec<(ContextRole, u32)> = Vec::new();

        for atom in candidates {
            let role_spent = spent_roles
                .iter()
                .find(|(role, _)| *role == atom.role)
                .map_or(0, |(_, spent)| *spent);
            let role_limit = recipe.budget_for(atom.role);
            let fits = spent_total.saturating_add(atom.cost) <= recipe.total_cost
                && role_spent.saturating_add(atom.cost) <= role_limit;
            let freshness_ok = matches!(
                atom.freshness,
                EvidenceFreshness::ExactCandidate
                    | EvidenceFreshness::ExactCommit
                    | EvidenceFreshness::ExactQuiescedWorktree
            );
            let safe = atom.assertability != Assertability::AbstainOrFence
                && !matches!(atom.status, EpistemicStatus::Rejected);
            let disposition = if !safe {
                AdmissionDisposition::Quarantined
            } else if !freshness_ok {
                AdmissionDisposition::Revalidate
            } else if fits {
                units.push(atom.clone());
                spent_total = spent_total.saturating_add(atom.cost);
                if let Some((_, spent)) =
                    spent_roles.iter_mut().find(|(role, _)| *role == atom.role)
                {
                    *spent = spent.saturating_add(atom.cost);
                } else {
                    spent_roles.push((atom.role, atom.cost));
                }
                AdmissionDisposition::Included
            } else if atom.required || atom.protected {
                handles.push(atom.atom_id.clone());
                AdmissionDisposition::HandleOnly
            } else {
                AdmissionDisposition::Suppressed
            };
            admissions.push(AdmissionDecision {
                atom_id: atom.atom_id,
                protected: atom.protected,
                reason: reason_for(disposition),
                disposition,
            });
        }

        let mut unknowns = input.unknowns.clone();
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

/// Cue kind used by deterministic push orientation.
///
/// Declaration order is the stable ordering used by [`CueIndex`].
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CueKind {
    Path,
    Symbol,
    Error,
    Command,
    Service,
    TaskClass,
    Concept,
    Problem,
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
    pub fn normalized_value(&self) -> Result<String, ContextError> {
        text(self.scope.as_str(), "cue.scope")?;
        text(self.value.as_str(), "cue.value")?;
        let normalized = match self.kind {
            CueKind::Path | CueKind::Symbol => self.value.trim().to_owned(),
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
            CueKind::Path | CueKind::Symbol => value.trim().to_owned(),
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
    use super::CueKind;

    #[test]
    fn cue_kind_order_matches_deterministic_index_contract() {
        let expected = [
            CueKind::Path,
            CueKind::Symbol,
            CueKind::Error,
            CueKind::Command,
            CueKind::Service,
            CueKind::TaskClass,
            CueKind::Concept,
            CueKind::Problem,
        ];
        let mut actual = expected;
        actual.reverse();
        actual.sort();

        assert_eq!(actual, expected);
    }
}
