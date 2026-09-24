//! Sourced evidence adapters for improvement candidates.
//!
//! Wires `eliot-improvement` into the Meta-owned improvement path per
//! `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`.
//! The I12.24 trigger set (I12.24:40-55: attempt, evaluator verdict, campaign
//! closure, conformance diagnosis, security incident, implementation
//! deviation, complaint, watchdog, dreamer, concilium) maps to
//! [`EvidenceSource`]; candidate details follow the I12.24 candidate schema
//! (I12.24:20-38) and are enforced strictly via
//! [`ImprovementCandidate::validate`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ImprovementCandidate, ImprovementError, ImprovementSurface, ReplayPlan};

/// I12.24 trigger source that raised a piece of improvement evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Attempt,
    EvaluatorVerdict,
    CampaignClosure,
    ConformanceDiagnosis,
    SecurityIncident,
    ImplementationDeviation,
    Complaint,
    Watchdog,
    Dreamer,
    Concilium,
}

/// Evidence bundle attributed to one [`EvidenceSource`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourcedEvidence {
    pub source: EvidenceSource,
    pub evidence_refs: Vec<String>,
    pub trace_refs: Vec<String>,
    pub trigger_problem_or_metric: String,
    pub root_cause_hypotheses: Vec<String>,
    pub counter_metrics: BTreeMap<String, f64>,
    pub validity_scope: String,
    pub owner_and_decision_authority: String,
}

impl SourcedEvidence {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        require_refs(&self.evidence_refs, "evidence_refs")?;
        require_refs(&self.trace_refs, "trace_refs")?;
        non_empty(&self.trigger_problem_or_metric, "trigger_problem_or_metric")?;
        non_empty(&self.validity_scope, "validity_scope")?;
        non_empty(
            &self.owner_and_decision_authority,
            "owner_and_decision_authority",
        )?;
        if self
            .counter_metrics
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        Ok(())
    }

    pub fn lineage_refs(&self) -> Vec<String> {
        lineage_union(&self.evidence_refs, &self.trace_refs)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "evidence-bound candidate assembly takes one field group per I12.24 schema block"
)]
pub fn candidate_from_evidence(
    project_id: &str,
    target_surface: ImprovementSurface,
    proposed_change: &str,
    evidence: &SourcedEvidence,
    replay_plan: ReplayPlan,
    baseline_metrics: BTreeMap<String, f64>,
    delivery_target: &str,
    canary_plan: &str,
    rollback: &str,
    stop_condition: &str,
) -> Result<ImprovementCandidate, ImprovementError> {
    evidence.validate()?;
    let mut candidate = ImprovementCandidate::new(
        project_id,
        target_surface,
        proposed_change,
        vec![format!(
            "evidence:{}",
            evidence_source_slug(evidence.source)
        )],
        vec!["authority-change".to_string()],
        evidence.trace_refs.clone(),
        evidence.lineage_refs(),
        replay_plan,
        baseline_metrics,
    )?;
    candidate.set_details(
        evidence.trigger_problem_or_metric.clone(),
        evidence.root_cause_hypotheses.clone(),
        evidence.counter_metrics.clone(),
        evidence.validity_scope.clone(),
        evidence.owner_and_decision_authority.clone(),
        delivery_target,
        canary_plan,
        rollback,
        stop_condition,
    );
    candidate.validate()?;
    Ok(candidate)
}

pub fn sourced_evidence_from_repeated_verifier_failure(
    verifier_ref: &str,
    failure_refs: &[String],
    trace_refs: &[String],
    owner_and_decision_authority: &str,
    trigger_problem_or_metric: &str,
) -> Result<SourcedEvidence, ImprovementError> {
    non_empty(verifier_ref, "verifier_ref")?;
    non_empty(owner_and_decision_authority, "owner_and_decision_authority")?;
    non_empty(trigger_problem_or_metric, "trigger_problem_or_metric")?;
    require_refs(failure_refs, "failure_refs")?;
    require_refs(trace_refs, "trace_refs")?;
    let verifier = verifier_ref.trim();
    let mut evidence_refs: Vec<String> = failure_refs.to_vec();
    evidence_refs.push(format!("verifier:{verifier}"));
    Ok(SourcedEvidence {
        source: EvidenceSource::EvaluatorVerdict,
        evidence_refs,
        trace_refs: trace_refs.to_vec(),
        trigger_problem_or_metric: trigger_problem_or_metric.to_string(),
        root_cause_hypotheses: vec![format!("repeated verifier failure: {verifier}")],
        counter_metrics: BTreeMap::new(),
        validity_scope: format!("verifier:{verifier}"),
        owner_and_decision_authority: owner_and_decision_authority.to_string(),
    })
}

fn evidence_source_slug(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::Attempt => "attempt",
        EvidenceSource::EvaluatorVerdict => "evaluator_verdict",
        EvidenceSource::CampaignClosure => "campaign_closure",
        EvidenceSource::ConformanceDiagnosis => "conformance_diagnosis",
        EvidenceSource::SecurityIncident => "security_incident",
        EvidenceSource::ImplementationDeviation => "implementation_deviation",
        EvidenceSource::Complaint => "complaint",
        EvidenceSource::Watchdog => "watchdog",
        EvidenceSource::Dreamer => "dreamer",
        EvidenceSource::Concilium => "concilium",
    }
}

fn lineage_union(first: &[String], second: &[String]) -> Vec<String> {
    let mut union = BTreeSet::new();
    for value in first.iter().chain(second.iter()) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            union.insert(trimmed.to_string());
        }
    }
    union.into_iter().collect()
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
