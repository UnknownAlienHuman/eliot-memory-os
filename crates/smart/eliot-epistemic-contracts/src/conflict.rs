//! Conflict set: every position preserved, no winner by arithmetic.
//!
//! A [`ConflictSet`] preserves every local position with source, stance, assumptions, counters, and minority
//! flag, plus common lineage, unresolved residue and owners, probe, and receipt digest. Count, recency, and
//! scalar confidence never resolve a conflict: a set closes only when its residue is empty and its lifecycle
//! says so.
//!
//! A member of the position denominator may be declared but not carried, and the set says so in its own
//! typed vocabulary rather than by dropping the member. [`MissingConflictPosition`] pairs the absent owner
//! with the [`MemberDisposition`] its owner issued for that member, and [`ConflictSet::position_denominator`]
//! counts a carried position and a still-open declared member alike. Qualification is the disposition's and
//! never a flag: [`MemberDisposition::is_terminal`] closes a member on observed presence or authoritative
//! absence, so a closed member is refused here and an open one stays in the denominator as a named gap. The
//! absent owner must also appear in the set's own `unresolved_owners` residue, so a set cannot claim a rival
//! exists that its own declaration does not name.
use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_POSITIONS, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT, check_frozen,
    shape_digest, validate_bounded_text, validate_digest,
};
use crate::identity::LineageRootId;
use crate::receipt::MemberDisposition;

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

/// Claim acceptability inside one conflict set, per I13.2: support and attack relations inside the set,
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

/// One declared-but-absent member of a conflict set's position denominator.
///
/// A member the set's own `unresolved_owners` residue names whose stance this
/// set does not carry. It is recorded here rather than dropped, because a
/// dropped member is a suppressed one: the set would then analyze a narrower
/// conflict than the one its own declaration admits exists.
///
/// The disposition is this crate's canonical per-member outcome vocabulary
/// ([`MemberDisposition`]) and it is the whole of the qualification, not a
/// boolean. [`MemberDisposition::is_terminal`] is the documented discriminator
/// — only observed presence and authoritative absence close a member — so a
/// member whose outcome is still open stays in the denominator as a named gap,
/// while a member whose outcome has closed is not a rival of this conflict at
/// all and is refused. A caller therefore cannot manufacture a conflict by
/// asserting a rival exists: it has to record the typed outcome its owner
/// issued for that rival, and a closed outcome does not widen the denominator.
///
/// The reason is bounded prose rather than an enum because the disposition
/// already says what KIND of gap this is, not which member of the set it
/// belongs to. It is preserved verbatim and never parsed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MissingConflictPosition {
    /// Owner whose declared position this set does not carry.
    pub owner: SourceId,
    /// Owner-issued outcome for that absent member.
    pub disposition: MemberDisposition,
    /// Bounded reason the owner's position is not in the set.
    pub reason: String,
}
impl MissingConflictPosition {
    /// Constructs a declared-but-absent member after validating its reason.
    pub fn new(
        owner: SourceId,
        disposition: MemberDisposition,
        reason: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let missing = Self {
            owner,
            disposition,
            reason: reason.into(),
        };
        missing.validate()?;
        Ok(missing)
    }
    /// Validates the bounded reason; the disposition vocabulary is closed by type.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(
            &self.reason,
            "conflict.missing_position.reason",
            MAX_SHORT_TEXT,
        )
    }
    /// Returns whether this member is still open and therefore in the denominator.
    ///
    /// A terminal disposition means the owner's question is settled, so the
    /// member is not a live rival and does not count toward the denominator.
    pub const fn is_in_denominator(&self) -> bool {
        !self.disposition.is_terminal()
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
    /// Declared-but-absent members of the position denominator, in declaration
    /// order. Empty for an ordinary set; a set carrying one member here and one
    /// position still holds a two-member denominator, which is the one shape
    /// that is a conflict with fewer than two carried positions. The field is
    /// part of the frozen digest shape, so a document that omits it is refused
    /// rather than read as an ordinary set.
    pub missing_positions: Vec<MissingConflictPosition>,
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
    missing_positions: &'a [MissingConflictPosition],
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
/// Named constructor arguments for [`ConflictSet::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct ConflictSetParams {
    pub conflict_id: String,
    pub kind: ConflictKind,
    pub scope: String,
    pub task_id: Option<TaskId>,
    pub positions: Vec<ConflictPosition>,
    pub evidence_refs: BTreeSet<ArtifactId>,
    pub owners: BTreeSet<SourceId>,
    pub common_lineage: BTreeSet<LineageRootId>,
    pub resolved_parts: BTreeSet<String>,
    pub unresolved: BTreeSet<String>,
    pub unresolved_owners: BTreeSet<SourceId>,
    pub acceptability: ArgumentAcceptability,
    pub defeated_refs: BTreeSet<ArtifactId>,
    pub probe: Option<String>,
    pub decision_owner: SourceId,
    pub affected_actions: Vec<String>,
    pub lifecycle: ConflictLifecycle,
    pub receipt_digest: String,
}
impl ConflictSet {
    /// Constructs an ordinary set: every declared member is carried as a position.
    pub fn new(params: ConflictSetParams) -> Result<Self, ContractError> {
        Self::new_with_missing_positions(params, Vec::new())
    }
    /// Constructs a set that also declares members of its position denominator it
    /// does not carry, each with the outcome its owner issued for that member.
    ///
    /// The declared-but-absent members are named as a separate argument rather
    /// than as a [`ConflictSetParams`] field so the ordinary construction path
    /// is unchanged for every caller that has no absent member to declare, and
    /// so admitting one is a deliberate act of this constructor rather than a
    /// value a caller can leave at its default. Both constructors run the same
    /// `validate_shape` and mint the digest the same way, so an absent member is
    /// bound into the frozen digest exactly like any other field.
    pub fn new_with_missing_positions(
        params: ConflictSetParams,
        missing_positions: Vec<MissingConflictPosition>,
    ) -> Result<Self, ContractError> {
        let mut set = Self {
            conflict_id: params.conflict_id,
            kind: params.kind,
            scope: params.scope,
            task_id: params.task_id,
            positions: params.positions,
            missing_positions,
            evidence_refs: params.evidence_refs,
            owners: params.owners,
            common_lineage: params.common_lineage,
            resolved_parts: params.resolved_parts,
            unresolved: params.unresolved,
            unresolved_owners: params.unresolved_owners,
            acceptability: params.acceptability,
            defeated_refs: params.defeated_refs,
            probe: params.probe,
            decision_owner: params.decision_owner,
            affected_actions: params.affected_actions,
            lifecycle: params.lifecycle,
            receipt_digest: params.receipt_digest,
            digest: String::new(),
        };
        set.validate_shape()?;
        set.digest = set.compute_digest()?;
        Ok(set)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&ConflictDigestShape {
            conflict_id: self.conflict_id.as_str(),
            kind: &self.kind,
            scope: self.scope.as_str(),
            task_id: &self.task_id,
            positions: self.positions.as_slice(),
            missing_positions: self.missing_positions.as_slice(),
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
    /// Returns the exact, recheckable width of the position denominator.
    ///
    /// A carried position and a declared-but-absent member are both members of
    /// the denominator and are counted by their own declaration, so a caller
    /// cannot narrow a conflict by dropping a member it already declared. Only
    /// a member whose owner-issued outcome is still open counts: a member whose
    /// outcome has closed is not a position of this conflict at all, and
    /// counting it would be inventing a rival rather than preserving one.
    pub fn position_denominator(&self) -> usize {
        self.positions.len()
            + self
                .missing_positions
                .iter()
                .filter(|missing| missing.is_in_denominator())
                .count()
    }
    /// Returns the set's declared-but-absent members, in declaration order.
    pub fn missing_positions(&self) -> &[MissingConflictPosition] {
        &self.missing_positions
    }
    /// Checks that every declared-but-absent member agrees with the set declaring it.
    ///
    /// Three things must hold for one record, and each is a different way the
    /// record could overstate the denominator: it may not name a member the set
    /// already carries or name one twice, its own owner-issued outcome may not
    /// have closed the member, and its owner must be one the set's own residue
    /// names. The last is what stops the record from being an unowned assertion
    /// that a rival exists.
    fn validate_missing_positions(&self) -> Result<(), ContractError> {
        let carried: BTreeSet<&SourceId> = self
            .positions
            .iter()
            .map(|position| &position.source)
            .collect();
        let mut absent: BTreeSet<&SourceId> = BTreeSet::new();
        for missing in &self.missing_positions {
            missing.validate()?;
            if carried.contains(&missing.owner) || !absent.insert(&missing.owner) {
                return Err(ContractError::Duplicate {
                    field: "conflict.missing_positions",
                });
            }
            if !missing.is_in_denominator() {
                return Err(ContractError::ImpossibleCombination {
                    field: "conflict.missing_positions",
                });
            }
            if !self.unresolved_owners.contains(&missing.owner) {
                return Err(ContractError::MissingReference {
                    field: "conflict.missing_positions",
                });
            }
        }
        Ok(())
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.conflict_id, "conflict.conflict_id", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "conflict.scope", MAX_SHORT_TEXT)?;
        if self.positions.len() + self.missing_positions.len() > MAX_POSITIONS {
            return Err(ContractError::TooMany {
                field: "conflict.positions",
            });
        }
        for position in &self.positions {
            position.validate()?;
        }
        self.validate_missing_positions()?;
        if self.positions.is_empty() {
            // A denominator made only of declared-but-absent members carries no
            // claim at all, so there is nothing to disagree with. The qualified
            // shape is exactly one carried position plus an open absent member,
            // never zero carried positions.
            return Err(ContractError::EmptyCollection {
                field: "conflict.positions",
            });
        }
        if self.position_denominator() < 2 {
            return Err(ContractError::EmptyCollection {
                field: "conflict.positions",
            });
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
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "conflict.digest")
    }
}
