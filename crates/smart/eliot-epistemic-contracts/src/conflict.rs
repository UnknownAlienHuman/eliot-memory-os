//! Conflict set: every position preserved, no winner by arithmetic.
//!
//! A [`ConflictSet`] references the canonical owner shapes — task, source,
//! fence, and lineage identities come from the foundation and identity crates
//! and are never duplicated here — while preserving every local position with
//! its source, stance, assumptions, counters, and minority flag, plus the
//! common lineage, unresolved residue and owners, discriminative probe, and
//! receipt digest. Positions form a meaningful sequence: declaration order is
//! preserved on the wire so reviewers read the debate as recorded.
//!
//! Count, recency, and scalar confidence never resolve a conflict. There is
//! deliberately no resolution constructor: a set closes only when its
//! unresolved residue is empty and its lifecycle says so.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_POSITIONS, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT, shape_digest,
    validate_bounded_text, validate_digest,
};
use crate::identity::LineageRootId;

/// The eight canonical conflict kinds of I13.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictKind {
    /// Incompatible claims, models, or evidence.
    Epistemic,
    /// Revision, fence, or write race.
    State,
    /// Competing task paths or owners.
    Plan,
    /// Overlapping or absent permission.
    Authority,
    /// Incompatible outputs or patches.
    Artifact,
    /// Conflicting human, architecture, policy, or skill constraints.
    Instruction,
    /// Queue, budget, or module contention.
    Resource,
    /// Implementation cannot satisfy stated intent.
    Architecture,
}

impl ConflictKind {
    /// Returns the exact frozen wire name of this conflict kind.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Epistemic => "EPISTEMIC",
            Self::State => "STATE",
            Self::Plan => "PLAN",
            Self::Authority => "AUTHORITY",
            Self::Artifact => "ARTIFACT",
            Self::Instruction => "INSTRUCTION",
            Self::Resource => "RESOURCE",
            Self::Architecture => "ARCHITECTURE",
        }
    }
}

/// Claim acceptability inside one conflict set, per I13.2.
///
/// This axis describes support and attack relations inside the set. It is
/// orthogonal to epistemic status and to the set lifecycle below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArgumentAcceptability {
    /// Supported by an admitted, undefeated argument.
    Grounded,
    /// Coherent support and an undefeated attack coexist.
    Contested,
    /// Support invalidated.
    Defeated,
    /// Valid only under a named assumption set.
    AssumptionDependent,
    /// No sufficient argument either way.
    Undecided,
}

impl ArgumentAcceptability {
    /// Returns the exact frozen wire name of this acceptability.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Grounded => "GROUNDED",
            Self::Contested => "CONTESTED",
            Self::Defeated => "DEFEATED",
            Self::AssumptionDependent => "ASSUMPTION_DEPENDENT",
            Self::Undecided => "UNDECIDED",
        }
    }
}

/// Lifecycle of the conflict set itself; conflict is localized state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictLifecycle {
    /// Recorded and not yet investigated.
    Open,
    /// Under investigation.
    Investigating,
    /// Decided by the owning decision owner.
    Decided,
    /// Replaced by a later set, retained as history.
    Superseded,
    /// Closed with empty unresolved residue.
    Resolved,
}

impl ConflictLifecycle {
    /// Returns the exact frozen wire name of this lifecycle state.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Investigating => "INVESTIGATING",
            Self::Decided => "DECIDED",
            Self::Superseded => "SUPERSEDED",
            Self::Resolved => "RESOLVED",
        }
    }
}

/// One preserved position inside a conflict set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConflictPosition {
    /// Source holding this position.
    pub source: SourceId,
    /// Bounded stance text of the position.
    pub stance: String,
    /// Named assumptions the position depends on; order carries no meaning.
    pub assumptions: BTreeSet<String>,
    /// Counter handles raised against this position; order carries no meaning.
    pub counters: BTreeSet<ArtifactId>,
    /// Whether this position is a recorded minority.
    pub minority: bool,
}

impl ConflictPosition {
    /// Constructs a conflict position after validation.
    pub fn new(
        source: SourceId,
        stance: impl Into<String>,
        assumptions: BTreeSet<String>,
        counters: BTreeSet<ArtifactId>,
        minority: bool,
    ) -> Result<Self, ContractError> {
        let position = Self {
            source,
            stance: stance.into(),
            assumptions,
            counters,
            minority,
        };
        position.validate()?;
        Ok(position)
    }

    /// Validates stance, assumptions, and counters.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.stance, "conflict.stance", MAX_STATEMENT_TEXT)?;
        if self.assumptions.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "conflict.assumptions",
            });
        }
        for assumption in &self.assumptions {
            validate_bounded_text(assumption.as_str(), "conflict.assumptions", MAX_SHORT_TEXT)?;
        }
        if self.counters.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "conflict.counters",
            });
        }
        Ok(())
    }
}

/// The preserved conflict set: every position, owner, and residue kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConflictSet {
    /// Stable conflict identity.
    pub conflict_id: String,
    /// Canonical conflict kind.
    pub kind: ConflictKind,
    /// Scope the conflict is localized to.
    pub scope: String,
    /// Task binding, when the conflict is task-localized.
    pub task_id: Option<TaskId>,
    /// Preserved positions in declaration order.
    pub positions: Vec<ConflictPosition>,
    /// Evidence and lineage handles behind the set; order carries no meaning.
    pub evidence_refs: BTreeSet<ArtifactId>,
    /// Authority owners of the set; order carries no meaning.
    pub owners: BTreeSet<SourceId>,
    /// Shared lineage suspected as a common-mode source; order carries no meaning.
    pub common_lineage: BTreeSet<LineageRootId>,
    /// Resolved parts of the conflict; order carries no meaning.
    pub resolved_parts: BTreeSet<String>,
    /// Unresolved residue that keeps the set open; order carries no meaning.
    pub unresolved: BTreeSet<String>,
    /// Owners whose positions remain unresolved; order carries no meaning.
    pub unresolved_owners: BTreeSet<SourceId>,
    /// Acceptability of the claims inside this set.
    pub acceptability: ArgumentAcceptability,
    /// Defeated argument references; order carries no meaning.
    pub defeated_refs: BTreeSet<ArtifactId>,
    /// Discriminative probe separating the positions, when one is known.
    pub probe: Option<String>,
    /// Owner deciding the set.
    pub decision_owner: SourceId,
    /// Affected actions, in declaration order.
    pub affected_actions: Vec<String>,
    /// Lifecycle of the set itself.
    pub lifecycle: ConflictLifecycle,
    /// Digest of the bounded receipt behind the set.
    pub receipt_digest: String,
    /// Canonical digest of the set shape, excluding this field.
    pub digest: String,
}

/// Canonical digest shape of a conflict set, excluding the frozen digest field.
#[derive(Serialize)]
struct ConflictDigestShape<'a> {
    conflict_id: &'a str,
    kind: &'a ConflictKind,
    scope: &'a str,
    task_id: &'a Option<TaskId>,
    positions: &'a [ConflictPosition],
    evidence_refs: &'a BTreeSet<ArtifactId>,
    owners: &'a BTreeSet<SourceId>,
    common_lineage: &'a BTreeSet<LineageRootId>,
    resolved_parts: &'a BTreeSet<String>,
    unresolved: &'a BTreeSet<String>,
    unresolved_owners: &'a BTreeSet<SourceId>,
    acceptability: &'a ArgumentAcceptability,
    defeated_refs: &'a BTreeSet<ArtifactId>,
    probe: &'a Option<String>,
    decision_owner: &'a SourceId,
    affected_actions: &'a [String],
    lifecycle: &'a ConflictLifecycle,
    receipt_digest: &'a str,
}

impl ConflictSet {
    /// Constructs a conflict set and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conflict_id: impl Into<String>,
        kind: ConflictKind,
        scope: impl Into<String>,
        task_id: Option<TaskId>,
        positions: Vec<ConflictPosition>,
        evidence_refs: BTreeSet<ArtifactId>,
        owners: BTreeSet<SourceId>,
        common_lineage: BTreeSet<LineageRootId>,
        resolved_parts: BTreeSet<String>,
        unresolved: BTreeSet<String>,
        unresolved_owners: BTreeSet<SourceId>,
        acceptability: ArgumentAcceptability,
        defeated_refs: BTreeSet<ArtifactId>,
        probe: Option<String>,
        decision_owner: SourceId,
        affected_actions: Vec<String>,
        lifecycle: ConflictLifecycle,
        receipt_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut set = Self {
            conflict_id: conflict_id.into(),
            kind,
            scope: scope.into(),
            task_id,
            positions,
            evidence_refs,
            owners,
            common_lineage,
            resolved_parts,
            unresolved,
            unresolved_owners,
            acceptability,
            defeated_refs,
            probe,
            decision_owner,
            affected_actions,
            lifecycle,
            receipt_digest: receipt_digest.into(),
            digest: String::new(),
        };
        set.validate_shape()?;
        set.digest = set.compute_digest()?;
        Ok(set)
    }

    /// Recomputes the canonical digest of the set shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&ConflictDigestShape {
            conflict_id: self.conflict_id.as_str(),
            kind: &self.kind,
            scope: self.scope.as_str(),
            task_id: &self.task_id,
            positions: self.positions.as_slice(),
            evidence_refs: &self.evidence_refs,
            owners: &self.owners,
            common_lineage: &self.common_lineage,
            resolved_parts: &self.resolved_parts,
            unresolved: &self.unresolved,
            unresolved_owners: &self.unresolved_owners,
            acceptability: &self.acceptability,
            defeated_refs: &self.defeated_refs,
            probe: &self.probe,
            decision_owner: &self.decision_owner,
            affected_actions: self.affected_actions.as_slice(),
            lifecycle: &self.lifecycle,
            receipt_digest: self.receipt_digest.as_str(),
        })
    }

    /// Returns whether the set is closed with empty residue.
    pub fn is_closed(&self) -> bool {
        self.lifecycle == ConflictLifecycle::Resolved
            && self.unresolved.is_empty()
            && self.unresolved_owners.is_empty()
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.conflict_id, "conflict.conflict_id", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "conflict.scope", MAX_SHORT_TEXT)?;
        if self.positions.len() < 2 {
            return Err(ContractError::EmptyCollection {
                field: "conflict.positions",
            });
        }
        if self.positions.len() > MAX_POSITIONS {
            return Err(ContractError::TooMany {
                field: "conflict.positions",
            });
        }
        for position in &self.positions {
            position.validate()?;
        }
        if self.evidence_refs.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "conflict.evidence_refs",
            });
        }
        if self.owners.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "conflict.owners",
            });
        }
        if self.common_lineage.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "conflict.common_lineage",
            });
        }
        for text in self.resolved_parts.iter().chain(self.unresolved.iter()) {
            validate_bounded_text(text.as_str(), "conflict.residue", MAX_SHORT_TEXT)?;
        }
        if let Some(probe) = &self.probe {
            validate_bounded_text(probe.as_str(), "conflict.probe", MAX_SHORT_TEXT)?;
        }
        if self.affected_actions.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "conflict.affected_actions",
            });
        }
        for action in &self.affected_actions {
            validate_bounded_text(action.as_str(), "conflict.affected_actions", MAX_SHORT_TEXT)?;
        }
        if self.lifecycle == ConflictLifecycle::Resolved
            && (!self.unresolved.is_empty() || !self.unresolved_owners.is_empty())
        {
            return Err(ContractError::ImpossibleCombination {
                field: "conflict.lifecycle",
            });
        }
        validate_digest(&self.receipt_digest, "conflict.receipt_digest")?;
        Ok(())
    }

    /// Validates the set shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "conflict.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "conflict.digest",
            });
        }
        Ok(())
    }
}
