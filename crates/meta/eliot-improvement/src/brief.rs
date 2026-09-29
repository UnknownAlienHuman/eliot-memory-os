//! Owner-facing improvement brief at a safe boundary (I12.24:74).
//!
//! `ImprovementBrief` shows problem, evidence, likely benefit, risk, proposed
//! owner, cost, next reversible step and what remains unknown. The named
//! decision owner does not search raw metrics: [`record_owner_decision`]
//! only records the owner's disposition over an already-validated brief and
//! mutates nothing. Briefs are constructed only via
//! [`brief_at_safe_boundary`], which requires an active Main Agent or Human
//! reference at a safe boundary.
//!
//! # The boundary is OBSERVED, never named
//!
//! [`SafeBoundary`] has no public fields and no literal construction. Its only
//! constructor, [`SafeBoundary::from_observed_closure`], reads the Governor's
//! OWN committed learning-closure image
//! ([`eliot_governor::CanonicalLearningDeltaStore`]) and takes the boundary
//! from a record an owner actually closed. Both values on the result are
//! therefore observations:
//!
//! - `active_main_agent_or_human_ref` is the `actor_id` the closure owner
//!   recorded for the attempt (`ClosureIdentityInput::actor_id`), i.e. the
//!   identity that executed the consequential work — a principal, not a label.
//! - `boundary_ref` is the `consequential_boundary` that
//!   `eliot_learning_delta::derive_boundaries` DERIVED from the lifecycle
//!   activities the same owner recorded. I12.24:181 makes that derivation the
//!   definition of a consequential boundary and states that an ordinary
//!   `read_file`/`read`/`grep` is not one; a non-consequential activity set
//!   never reaches the store at all, because
//!   `LearningClosureService::close_attempt` returns
//!   `NonConsequential` before committing. So a record in that image already
//!   IS a derived consequential boundary and is read here, never asserted.
//!
//! An empty image, or an unreadable one, is [`ImprovementError::UnsafeBoundary`]:
//! the fail-closed direction. No formatted constant, owner name, or scope
//! reference stands in for an observation that was not made.

use eliot_governor::CanonicalLearningDeltaStore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ImprovementCandidate, ImprovementError};

/// Advisory owner-facing brief over one candidate revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImprovementBrief {
    pub brief_id: String,
    pub candidate_id: String,
    pub candidate_revision: u64,
    pub problem: String,
    pub evidence_refs: Vec<String>,
    pub likely_benefit: String,
    pub risk: String,
    pub proposed_owner: String,
    pub cost: String,
    pub next_reversible_step: String,
    pub unknowns: Vec<String>,
    pub created_at: OffsetDateTime,
}

impl ImprovementBrief {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        non_empty(&self.brief_id, "brief_id")?;
        non_empty(&self.candidate_id, "candidate_id")?;
        non_empty(&self.problem, "problem")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        non_empty(&self.likely_benefit, "likely_benefit")?;
        non_empty(&self.risk, "risk")?;
        non_empty(&self.proposed_owner, "proposed_owner")?;
        non_empty(&self.cost, "cost")?;
        non_empty(&self.next_reversible_step, "next_reversible_step")?;
        require_refs(&self.unknowns, "unknowns")?;
        Ok(())
    }
}

/// Owner disposition over a brief; recording mutates nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerDecisionKind {
    Reject,
    Investigate,
    WorkItem,
    Experiment,
}

impl OwnerDecisionKind {
    /// Whether this disposition authorizes no change (I12.24:81-82, "advisory —
    /// default; changes nothing until owner acts").
    ///
    /// `reject` and `investigate` are the two non-mutating selections of
    /// I12.24:65; `work_item` and `experiment` release into the mutating
    /// work-item/canary/rollback lane. The property lives on the KIND so an
    /// intake can refuse a mutating disposition before it has an owner to record
    /// it under; [`OwnerDecision::is_non_mutating`] applies the same property to
    /// the produced record.
    #[must_use]
    pub const fn is_non_mutating(self) -> bool {
        matches!(self, Self::Reject | Self::Investigate)
    }
}

/// Pure record of the named owner's decision on a brief.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OwnerDecision {
    pub brief_id: String,
    pub candidate_id: String,
    pub owner: String,
    pub kind: OwnerDecisionKind,
    pub note: String,
    pub decided_at: OffsetDateTime,
}

impl OwnerDecision {
    /// Whether this recorded disposition authorizes no change.
    ///
    /// Checked against the RECORD rather than against a caller's assertion, so
    /// an intake that only admits non-mutating dispositions verifies the exact
    /// artifact it is about to make durable.
    #[must_use]
    pub fn is_non_mutating(&self) -> bool {
        self.kind.is_non_mutating()
    }
}

/// Safe-boundary gate: an active Main Agent or Human plus a boundary ref.
///
/// # Why the fields are private
///
/// The fields are private and the only constructor is
/// [`Self::from_observed_closure`], which takes its two values from a record
/// the Governor's learning-closure owner actually committed. That is what makes
/// the boundary DERIVED rather than NAMED: with a public struct literal, any
/// caller could satisfy the gate by formatting a string, which is precisely the
/// "a check that reads a literal" shape this type must not have. Serialization
/// is retained so a brief committed alongside the boundary still round-trips
/// the two observed values into the durable learning record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SafeBoundary {
    /// Identity that executed the consequential attempt (`actor_id`).
    active_main_agent_or_human_ref: String,
    /// Derived consequential boundary name the closure recorded.
    boundary_ref: String,
}

impl SafeBoundary {
    /// Reads the boundary from the owner-observed closure image.
    ///
    /// `store` is the single Governor-owned
    /// [`eliot_governor::CanonicalLearningDeltaStore`] the daemon already holds
    /// (`DaemonComposition::learning_closure().store()`); this performs a read
    /// of already-committed in-process state and opens no transport, no store
    /// client and no new durability path.
    ///
    /// The MOST RECENT committed record is the one observed boundary: a closure
    /// commit appends to the image, so the last element is the newest
    /// owner-observed consequential boundary this process holds. Both values are
    /// that record's own fields —
    /// `StoredLearningDelta::consequential_boundary` and
    /// `StoredLearningDelta::actor_id` — and neither is formatted, defaulted or
    /// synthesized here.
    ///
    /// # Errors
    ///
    /// [`ImprovementError::UnsafeBoundary`] when the image is empty, when the
    /// store cannot be read, or when the observed record carries an empty
    /// principal or boundary. An absent observation is a refusal, never a
    /// substituted constant.
    pub fn from_observed_closure(
        store: &CanonicalLearningDeltaStore,
    ) -> Result<Self, ImprovementError> {
        let (records, _version) = store
            .load()
            .map_err(|_| ImprovementError::UnsafeBoundary)?;
        let record = records.last().ok_or(ImprovementError::UnsafeBoundary)?;
        // The boundary enum type itself is deliberately not named: this crate
        // has no `eliot-learning-delta` edge, and reading the record's own
        // public field is the whole observation. `as_str` is the boundary's own
        // canonical spelling, so the recorded name is the owner's vocabulary
        // rather than a string spelled here.
        let boundary_ref = record.consequential_boundary.as_str().to_owned();
        let active_main_agent_or_human_ref = record.actor_id.clone();
        let boundary = Self {
            active_main_agent_or_human_ref,
            boundary_ref,
        };
        boundary.validate()?;
        Ok(boundary)
    }

    /// Rejects a boundary that names no principal or no derived boundary.
    ///
    /// This is a shape check on values that
    /// [`Self::from_observed_closure`] already read from a committed record;
    /// it cannot be satisfied by a formatted constant because the struct has no
    /// public constructor. It remains because a deserialized boundary reaches
    /// the same gate through [`brief_at_safe_boundary`].
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.active_main_agent_or_human_ref.trim().is_empty()
            || self.boundary_ref.trim().is_empty()
        {
            return Err(ImprovementError::UnsafeBoundary);
        }
        Ok(())
    }
}

/// Build a brief for `candidate` at `boundary`.
///
/// Validates the boundary first, then the candidate, then the brief fields.
/// The brief carries the candidate's evidence refs and revision by value.
#[allow(
    clippy::too_many_arguments,
    reason = "brief assembly takes one concise field per I12.24:74 decision slot"
)]
pub fn brief_at_safe_boundary(
    candidate: &ImprovementCandidate,
    problem: &str,
    likely_benefit: &str,
    risk: &str,
    proposed_owner: &str,
    cost: &str,
    next_reversible_step: &str,
    unknowns: Vec<String>,
    boundary: &SafeBoundary,
) -> Result<ImprovementBrief, ImprovementError> {
    boundary.validate()?;
    candidate.validate()?;
    non_empty(problem, "problem")?;
    non_empty(likely_benefit, "likely_benefit")?;
    non_empty(risk, "risk")?;
    non_empty(proposed_owner, "proposed_owner")?;
    non_empty(cost, "cost")?;
    non_empty(next_reversible_step, "next_reversible_step")?;
    require_refs(&unknowns, "unknowns")?;
    Ok(ImprovementBrief {
        brief_id: Uuid::now_v7().to_string(),
        candidate_id: candidate.candidate_id.clone(),
        candidate_revision: candidate.revision,
        problem: problem.to_string(),
        evidence_refs: candidate.evidence_refs.clone(),
        likely_benefit: likely_benefit.to_string(),
        risk: risk.to_string(),
        proposed_owner: proposed_owner.to_string(),
        cost: cost.to_string(),
        next_reversible_step: next_reversible_step.to_string(),
        unknowns,
        created_at: OffsetDateTime::now_utc(),
    })
}

/// Record the named owner's decision over an already-validated brief.
///
/// Pure record construction: validates the brief, owner, and note, then
/// returns the decision. Records mutate nothing.
pub fn record_owner_decision(
    brief: &ImprovementBrief,
    owner: &str,
    kind: OwnerDecisionKind,
    note: &str,
) -> Result<OwnerDecision, ImprovementError> {
    brief.validate()?;
    non_empty(owner, "owner")?;
    non_empty(note, "note")?;
    Ok(OwnerDecision {
        brief_id: brief.brief_id.clone(),
        candidate_id: brief.candidate_id.clone(),
        owner: owner.to_string(),
        kind,
        note: note.to_string(),
        decided_at: OffsetDateTime::now_utc(),
    })
}

fn non_empty(value: &str, field: &'static str) -> Result<(), ImprovementError> {
    if value.trim().is_empty() {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_refs(values: &[String], field: &'static str) -> Result<(), ImprovementError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}
