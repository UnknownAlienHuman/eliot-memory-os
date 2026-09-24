//! Self-Quality conformance-diagnosis handoff projection.
//!
//! Projects one inert [`SelfQualityHandoff`] (issue #971 vocabulary) into an
//! [`SourcedEvidence`](eliot_improvement::evidence_sources::SourcedEvidence)
//! bundle for the improvement pipeline (issue #1867, I12.24 trigger
//! "Architecture/Implementation/runtime conformance gap").
//!
//! The handoff stays inert: this module creates no job, plan, or effect. It
//! only projects refs into `SourcedEvidence` with
//! [`EvidenceSource::ConformanceDiagnosis`](eliot_improvement::evidence_sources::EvidenceSource).
//! Diagnosis never proves cause (see `diagnose.rs`): symptom refs map to
//! `unproven-symptom:{ref}` hypotheses, never to proven-cause claims.

use std::collections::BTreeSet;

use eliot_conformance_contracts::SelfQualityHandoff;
use eliot_improvement::evidence_sources::{EvidenceSource, SourcedEvidence, sourced_evidence};

use crate::error::SelfQualityError;

/// Owner-and-decision authority string for a handoff.
///
/// Pure: formats the [`SelfQualityHandoffOwner`](eliot_conformance_contracts::SelfQualityHandoffOwner)
/// `Debug` spelling under the `self-quality:` prefix, lowercased.
pub fn handoff_owner_authority(handoff: &SelfQualityHandoff) -> String {
    format!("self-quality:{:?}", handoff.owner).to_lowercase()
}

/// Project one handoff's refs into [`SourcedEvidence`].
///
/// Requires non-empty `evidence_refs` (else `EmptyMapping("evidence_refs")`),
/// a non-empty symptom + problem + applicability union (else
/// `EmptyMapping("trace_refs")`), and non-empty `trigger_problem_or_metric`
/// and `validity_scope` (else `EmptyMapping` naming the offending field).
/// The bundle is validated via [`SourcedEvidence::validate`]; any validation
/// failure maps to `EmptyMapping("evidence_refs")`.
pub fn sourced_evidence_from_handoff(
    handoff: &SelfQualityHandoff,
    trigger_problem_or_metric: &str,
    validity_scope: &str,
) -> Result<SourcedEvidence, SelfQualityError> {
    if handoff.evidence_refs.is_empty() {
        return Err(SelfQualityError::EmptyMapping("evidence_refs"));
    }
    let mut trace_set = BTreeSet::new();
    for value in handoff
        .symptom_refs
        .iter()
        .chain(handoff.problem_refs.iter())
        .chain(handoff.applicability_refs.iter())
    {
        trace_set.insert(value.clone());
    }
    if trace_set.is_empty() {
        return Err(SelfQualityError::EmptyMapping("trace_refs"));
    }
    if trigger_problem_or_metric.is_empty() {
        return Err(SelfQualityError::EmptyMapping("trigger_problem_or_metric"));
    }
    if validity_scope.is_empty() {
        return Err(SelfQualityError::EmptyMapping("validity_scope"));
    }
    let trace_refs: Vec<String> = trace_set.into_iter().collect();
    let root_cause_hypotheses: Vec<String> = handoff
        .symptom_refs
        .iter()
        .map(|value| format!("unproven-symptom:{value}"))
        .collect();
    sourced_evidence(
        EvidenceSource::ConformanceDiagnosis,
        &handoff.evidence_refs,
        &trace_refs,
        trigger_problem_or_metric,
        &root_cause_hypotheses,
        validity_scope,
        &handoff_owner_authority(handoff),
    )
    .map_err(|_| SelfQualityError::EmptyMapping("evidence_refs"))
}
