//! Governed, advisory self-improvement candidates.
//!
//! This crate deliberately stops at the promotion boundary.  It records a
//! replayable proposal and produces an outcome-linked input for an external
//! governor decision; no API in this crate can make a candidate active.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementSurface {
    Memory,
    Skill,
    ToolProfile,
    Rule,
    PacketCompiler,
    Verifier,
    Scheduler,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateState {
    Candidate,
    ReplayPending,
    Evaluating,
    Rejected,
    Retired,
}

impl CandidateState {
    pub fn is_experimental(self) -> bool {
        matches!(
            self,
            Self::Candidate | Self::ReplayPending | Self::Evaluating
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayPlan {
    pub fixed_replay_refs: Vec<String>,
    pub holdout_refs: Vec<String>,
    pub transfer_refs: Vec<String>,
    pub counter_metric_names: Vec<String>,
    pub verifier_refs: Vec<String>,
}

impl ReplayPlan {
    fn validate(&self) -> Result<(), ImprovementError> {
        require_refs(&self.fixed_replay_refs, "fixed_replay_refs")?;
        require_refs(&self.holdout_refs, "holdout_refs")?;
        require_refs(&self.verifier_refs, "verifier_refs")?;
        require_names(&self.counter_metric_names, "counter_metric_names")?;
        if self.transfer_refs.is_empty() {
            return Err(ImprovementError::MissingField("transfer_refs"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImprovementCandidate {
    pub candidate_id: String,
    pub project_id: String,
    pub target_surface: ImprovementSurface,
    pub proposed_change: String,
    pub applies_when: Vec<String>,
    pub does_not_apply_when: Vec<String>,
    pub source_trace_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub replay_plan: ReplayPlan,
    pub baseline_metrics: BTreeMap<String, f64>,
    pub state: CandidateState,
    pub revision: u64,
    pub advisory_only: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl ImprovementCandidate {
    #[allow(
        clippy::too_many_arguments,
        reason = "this public constructor is the established candidate protocol façade"
    )]
    pub fn new(
        project_id: impl Into<String>,
        target_surface: ImprovementSurface,
        proposed_change: impl Into<String>,
        applies_when: Vec<String>,
        does_not_apply_when: Vec<String>,
        source_trace_refs: Vec<String>,
        evidence_refs: Vec<String>,
        replay_plan: ReplayPlan,
        baseline_metrics: BTreeMap<String, f64>,
    ) -> Result<Self, ImprovementError> {
        let now = OffsetDateTime::now_utc();
        let candidate = Self {
            candidate_id: Uuid::now_v7().to_string(),
            project_id: project_id.into(),
            target_surface,
            proposed_change: proposed_change.into(),
            applies_when,
            does_not_apply_when,
            source_trace_refs,
            evidence_refs,
            replay_plan,
            baseline_metrics,
            state: CandidateState::Candidate,
            revision: 0,
            advisory_only: true,
            created_at: now,
            updated_at: now,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn validate(&self) -> Result<(), ImprovementError> {
        non_empty(&self.project_id, "project_id")?;
        non_empty(&self.proposed_change, "proposed_change")?;
        require_refs(&self.source_trace_refs, "source_trace_refs")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        require_names(&self.applies_when, "applies_when")?;
        require_names(&self.does_not_apply_when, "does_not_apply_when")?;
        if self
            .applies_when
            .iter()
            .any(|rule| self.does_not_apply_when.contains(rule))
        {
            return Err(ImprovementError::ConflictingScopeRule);
        }
        self.replay_plan.validate()?;
        if !self.advisory_only {
            return Err(ImprovementError::SelfPromotionForbidden);
        }
        if self
            .baseline_metrics
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        Ok(())
    }

    pub fn transition(
        &mut self,
        expected_revision: u64,
        next: CandidateState,
    ) -> Result<(), ImprovementError> {
        self.validate()?;
        if self.revision != expected_revision {
            return Err(ImprovementError::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        let allowed = matches!(
            (self.state, next),
            (CandidateState::Candidate, CandidateState::ReplayPending)
                | (CandidateState::ReplayPending, CandidateState::Evaluating)
                | (CandidateState::Evaluating, CandidateState::Rejected)
                | (CandidateState::Evaluating, CandidateState::Retired)
                | (CandidateState::ReplayPending, CandidateState::Rejected)
                | (CandidateState::Candidate, CandidateState::Rejected)
                | (CandidateState::Rejected, CandidateState::Retired)
        );
        if !allowed || next == CandidateState::Candidate {
            return Err(ImprovementError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        self.revision += 1;
        self.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    pub fn promotion_input(
        &self,
        outcome: OutcomeEvidence,
    ) -> Result<PromotionInput, ImprovementError> {
        self.validate()?;
        if !matches!(self.state, CandidateState::Evaluating) {
            return Err(ImprovementError::OutcomeRequiresEvaluation);
        }
        outcome.validate_for(self)?;
        let digest = promotion_digest(self, &outcome);
        Ok(PromotionInput {
            input_id: Uuid::now_v7().to_string(),
            candidate_id: self.candidate_id.clone(),
            project_id: self.project_id.clone(),
            candidate_revision: self.revision,
            target_surface: self.target_surface,
            outcome,
            evidence_digest: digest,
            direct_promotion: false,
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutcomeEvidence {
    pub outcome_ref: String,
    pub downstream_outcome_ref: String,
    pub verifier_ref: String,
    pub verifier_passed: bool,
    pub replay_refs: Vec<String>,
    pub holdout_refs: Vec<String>,
    pub transfer_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub observed_metrics: BTreeMap<String, f64>,
    pub counter_metrics: BTreeMap<String, f64>,
}

impl OutcomeEvidence {
    fn validate_for(&self, candidate: &ImprovementCandidate) -> Result<(), ImprovementError> {
        non_empty(&self.outcome_ref, "outcome_ref")?;
        non_empty(&self.downstream_outcome_ref, "downstream_outcome_ref")?;
        non_empty(&self.verifier_ref, "verifier_ref")?;
        if !self.verifier_passed {
            return Err(ImprovementError::VerifierNotPassed);
        }
        require_refs(&self.replay_refs, "replay_refs")?;
        require_refs(&self.holdout_refs, "holdout_refs")?;
        require_refs(&self.transfer_refs, "transfer_refs")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        if !self
            .replay_refs
            .iter()
            .all(|item| candidate.replay_plan.fixed_replay_refs.contains(item))
            || !self
                .holdout_refs
                .iter()
                .all(|item| candidate.replay_plan.holdout_refs.contains(item))
            || !self
                .transfer_refs
                .iter()
                .all(|item| candidate.replay_plan.transfer_refs.contains(item))
            || !candidate
                .replay_plan
                .verifier_refs
                .contains(&self.verifier_ref)
        {
            return Err(ImprovementError::OutcomeOutsidePlan);
        }
        if self
            .counter_metrics
            .keys()
            .any(|name| !candidate.replay_plan.counter_metric_names.contains(name))
        {
            return Err(ImprovementError::UnknownCounterMetric);
        }
        if self
            .observed_metrics
            .values()
            .chain(self.counter_metrics.values())
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PromotionInput {
    pub input_id: String,
    pub candidate_id: String,
    pub project_id: String,
    pub candidate_revision: u64,
    pub target_surface: ImprovementSurface,
    pub outcome: OutcomeEvidence,
    pub evidence_digest: String,
    pub direct_promotion: bool,
    pub created_at: OffsetDateTime,
}

impl PromotionInput {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.direct_promotion {
            return Err(ImprovementError::SelfPromotionForbidden);
        }
        non_empty(&self.evidence_digest, "evidence_digest")?;
        non_empty(&self.candidate_id, "candidate_id")?;
        non_empty(&self.project_id, "project_id")?;
        Ok(())
    }
}

fn promotion_digest(candidate: &ImprovementCandidate, outcome: &OutcomeEvidence) -> String {
    let mut hasher = Hasher::new();
    hasher.update(candidate.candidate_id.as_bytes());
    hasher.update(candidate.revision.to_string().as_bytes());
    hasher.update(outcome.outcome_ref.as_bytes());
    hasher.update(outcome.downstream_outcome_ref.as_bytes());
    hasher.update(outcome.verifier_ref.as_bytes());
    hasher.finalize().to_hex().to_string()
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

fn require_names(values: &[String], field: &'static str) -> Result<(), ImprovementError> {
    require_refs(values, field)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ImprovementError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("candidate scope contains both apply and exclusion rule")]
    ConflictingScopeRule,
    #[error("non-finite metric is not admissible")]
    NonFiniteMetric,
    #[error("candidate lifecycle revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("invalid candidate lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: CandidateState,
        to: CandidateState,
    },
    #[error("improvement candidates cannot self-promote")]
    SelfPromotionForbidden,
    #[error("outcome input requires an evaluating candidate")]
    OutcomeRequiresEvaluation,
    #[error("verifier outcome did not pass")]
    VerifierNotPassed,
    #[error("outcome references data outside the candidate replay plan")]
    OutcomeOutsidePlan,
    #[error("outcome contains an undeclared counter metric")]
    UnknownCounterMetric,
}
