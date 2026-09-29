//! Owner-facing improvement brief at a safe boundary (I12.24:74).
//!
//! `ImprovementBrief` shows problem, evidence, likely benefit, risk, proposed
//! owner, cost, next reversible step and what remains unknown. The named
//! decision owner does not search raw metrics: [`record_owner_decision`]
//! only records the owner's disposition over an already-validated brief and
//! mutates nothing. Briefs are constructed only via
//! [`brief_at_safe_boundary`], which requires an active Main Agent or Human
//! reference at a safe boundary.

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
    pub fn is_non_mutating(&self) -> bool {
        matches!(
            self.kind,
            OwnerDecisionKind::Reject | OwnerDecisionKind::Investigate
        )
    }
}

/// Safe-boundary gate: an active Main Agent or Human plus a boundary ref.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SafeBoundary {
    pub active_main_agent_or_human_ref: String,
    pub boundary_ref: String,
}

impl SafeBoundary {
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
