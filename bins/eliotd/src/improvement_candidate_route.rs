//! Production `TestD` terminal consumer for Governor improvement admission.
//!
//! The old public forwarder was not an execution path. This module is called
//! only by the daemon's existing `TestD` terminal drain. It rehydrates the
//! durable improvement sidecar and the canonical verifier fact, projects the
//! exact independent evidence axes, asks Governor maintenance for a candidate
//! disposition, and returns an outcome for the authenticated owner
//! acknowledgement. It never opens a store, launches a process, or promotes a
//! generation.

use std::collections::BTreeMap;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_governor::CanonicalVerifierExecutionFact;
use eliot_maintenance::{
    ImprovementTerminalDisposition, build_improvement_outcome, evaluate_improvement_experiment,
};
use eliot_store_api::WriteReceipt;
use eliot_testd_core::{
    ImprovementExperimentOutcome, ImprovementExperimentRecord, ImprovementExperimentState,
    ImprovementMetricDisposition, ImprovementSourceBinding, IndependentExecutionEvidence,
};

/// Failure in the production terminal consumer. It is surfaced to the
/// existing daemon drain diagnostics and never converted into a candidate
/// acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImprovementRouteError {
    /// The canonical fact or durable sidecar is not an exact join.
    InvalidBinding(String),
    /// Governor maintenance refused the evidence.
    Admission(String),
    /// The durable outcome could not be built.
    Outcome(String),
}

impl std::fmt::Display for ImprovementRouteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBinding(reason) | Self::Admission(reason) | Self::Outcome(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

impl std::error::Error for ImprovementRouteError {}

/// Consumes one canonical verifier fact for one durable improvement sidecar.
///
/// `committed_receipt` is the canonical owner receipt returned by the
/// Governor verifier-fact publication. Its digest is part of the independent
/// evidence identity; a worker receipt or caller-provided boolean is not
/// accepted.
pub fn consume_improvement_terminal(
    record: &ImprovementExperimentRecord,
    fact: &CanonicalVerifierExecutionFact,
    committed_receipt: &WriteReceipt,
    prior_attempts: &[eliot_testd_core::ImprovementPriorAttempt],
    recorded_at_unix_ms: u64,
) -> Result<ImprovementExperimentOutcome, ImprovementRouteError> {
    record
        .validate()
        .map_err(|error| ImprovementRouteError::InvalidBinding(error.to_string()))?;
    if record.state != ImprovementExperimentState::TerminalEvidencePending
        || record.source_observation.is_none()
    {
        return Err(ImprovementRouteError::InvalidBinding(
            "improvement sidecar is not in terminal-evidence-pending state".to_owned(),
        ));
    }
    fact.validate(&record.proposal.state_fence)
        .map_err(|error| ImprovementRouteError::InvalidBinding(error.to_string()))?;
    committed_receipt
        .validate()
        .map_err(|error| ImprovementRouteError::InvalidBinding(error.to_string()))?;
    if fact.job_id != record.job_id
        || fact.task_id != record.proposal.target.task_id
        || fact.state_fence != record.proposal.state_fence
        || record.source_observation.as_ref().is_some_and(|source| {
            fact.source_observation.as_ref().is_none_or(|range| {
                range.before.repository_root != source.repository_root
                    || range.before.branch != source.branch
                    || range.before.commit != source.commit
                    || range.before.dirty_state_sha256 != source.dirty_state_sha256
            })
        })
    {
        return Err(ImprovementRouteError::InvalidBinding(
            "canonical verifier fact does not bind the durable improvement job/fence".to_owned(),
        ));
    }
    let receipt_sha256 = canonical_receipt_digest(committed_receipt)?;
    let fact_bytes = canonical_json_bytes(fact)
        .map_err(|error| ImprovementRouteError::InvalidBinding(error.to_string()))?;
    let fact_digest = sha256_hex(&fact_bytes);
    let evidence = independent_evidence_from_fact(record, fact, receipt_sha256, fact_digest)?;
    let disposition = evaluate_improvement_experiment(&record.proposal, &evidence, prior_attempts)
        .map_err(|error| ImprovementRouteError::Admission(error.to_string()))?;
    build_improvement_outcome(
        &record.proposal,
        &evidence,
        &disposition,
        recorded_at_unix_ms,
    )
    .map_err(|error| ImprovementRouteError::Outcome(error.to_string()))
}

/// Projects only identities and measured values already present in the
/// canonical verifier fact. Missing metric values become `Incomplete`; they do
/// not become a pass by default.
fn independent_evidence_from_fact(
    record: &ImprovementExperimentRecord,
    fact: &CanonicalVerifierExecutionFact,
    committed_receipt_sha256: String,
    fact_digest: String,
) -> Result<IndependentExecutionEvidence, ImprovementRouteError> {
    let source_binding = match &fact.source_observation {
        Some(range) if range.before == range.after => ImprovementSourceBinding::ExactUnchanged,
        Some(_) => ImprovementSourceBinding::Changed,
        None => ImprovementSourceBinding::Absent,
    };
    let mut observed_metric_deltas = BTreeMap::new();
    let mut counter_metric_deltas = BTreeMap::new();
    let mut metric_dispositions = BTreeMap::new();
    for name in &record.proposal.request.expected_metric_names {
        match metric_delta(&fact.verification_run, name) {
            Some(value) => {
                let expected = record
                    .proposal
                    .request
                    .expected_deltas
                    .get(name)
                    .copied()
                    .unwrap_or(f64::NAN);
                metric_dispositions.insert(
                    name.clone(),
                    if value >= expected {
                        ImprovementMetricDisposition::Meets
                    } else {
                        ImprovementMetricDisposition::Misses
                    },
                );
                observed_metric_deltas.insert(name.clone(), value);
            }
            None => {
                metric_dispositions.insert(name.clone(), ImprovementMetricDisposition::Incomplete);
            }
        }
    }
    for name in &record.proposal.request.counter_metric_names {
        match metric_delta(&fact.verification_run, name) {
            Some(value) => {
                metric_dispositions.insert(
                    name.clone(),
                    if value < 0.0 {
                        ImprovementMetricDisposition::Regresses
                    } else {
                        ImprovementMetricDisposition::Meets
                    },
                );
                counter_metric_deltas.insert(name.clone(), value);
            }
            None => {
                metric_dispositions.insert(name.clone(), ImprovementMetricDisposition::Incomplete);
            }
        }
    }
    let raw_evidence_refs = fact
        .raw_artifact_bindings
        .iter()
        .map(|artifact| artifact.handle.clone())
        .collect();
    let normalized_evidence_refs = fact
        .verification_run
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id.to_string())
        .collect();
    let evidence = IndependentExecutionEvidence {
        evidence_id: fact_digest,
        verifier_id: fact.verification_run.verifier.to_string(),
        verifier_run_id: fact.verification_run.run_id.to_string(),
        job_id: fact.job_id.clone(),
        operation_id: record
            .proposal
            .operation_id(eliot_testd_core::ImprovementOperationKind::Evaluate)
            .ok_or_else(|| {
                ImprovementRouteError::InvalidBinding(
                    "improvement proposal has no evaluator operation".to_owned(),
                )
            })?
            .to_owned(),
        executed_operation_id: fact.receipt.operation_id.clone(),
        invocation_id: fact.verification_run.invocation_id.to_string(),
        outcome: fact.verification_run.outcome,
        coverage: fact.verification_run.coverage,
        freshness: fact.verification_run.freshness,
        source_binding,
        observed_metric_deltas,
        counter_metric_deltas,
        metric_dispositions,
        raw_evidence_refs,
        normalized_evidence_refs,
        state_fence: fact.state_fence.clone(),
        committed_receipt_sha256,
    };
    evidence
        .validate_for(&record.proposal, &record.job_id)
        .map_err(|error| ImprovementRouteError::InvalidBinding(error.to_string()))?;
    Ok(evidence)
}

fn metric_delta(run: &eliot_instrument_api::VerificationRun, metric_name: &str) -> Option<f64> {
    run.evidence.iter().find_map(|evidence| {
        let value = evidence.value.get("metric_deltas")?.as_object()?;
        value.get(metric_name)?.as_f64()
    })
}

fn canonical_receipt_digest(receipt: &WriteReceipt) -> Result<String, ImprovementRouteError> {
    let bytes = canonical_json_bytes(receipt)
        .map_err(|error| ImprovementRouteError::InvalidBinding(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Returns the Governor owner identity for diagnostics and owner joins.
#[must_use]
pub const fn improvement_route_owner() -> &'static str {
    eliot_maintenance::IMPROVEMENT_PIPELINE_OWNER
}

/// Converts a maintenance decision to its stable testd disposition without
/// re-deciding it in the daemon.
#[must_use]
pub fn durable_disposition(
    disposition: &ImprovementTerminalDisposition,
) -> eliot_testd_core::ImprovementExperimentDisposition {
    disposition.durable_disposition()
}
