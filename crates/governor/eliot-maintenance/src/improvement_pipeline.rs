//! Governor-maintenance admission over exact `TestD`/Instrument evidence.
//!
//! This module is the decision owner, not an executor. `TestD` owns the
//! predeclared experiment, raw process evidence, and durable sidecar; the
//! Instrument verifier owns the independent run. Maintenance receives the
//! canonical verifier fact already published by Governor and can only return a
//! candidate disposition. Kernel remains the separate canary/generation owner,
//! and Product activation is never called here.

use eliot_testd_core::{
    ImprovementExperimentDisposition, ImprovementExperimentOutcome, ImprovementMetricDisposition,
    ImprovementOperationKind, ImprovementPriorAttempt, ImprovementPriorOutcome,
    ImprovementProposal, ImprovementSourceBinding, IndependentExecutionEvidence,
    is_improvement_no_progress,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Governor maintenance owner for the candidate decision.
pub const IMPROVEMENT_PIPELINE_OWNER: &str = "governor-maintenance-G-19";
/// `TestD` experiment owner.
pub const TESTD_OWNER: &str = "eliot-testd-20";
/// Independent Instrument verifier owner family.
pub const VERIFIER_OWNER_FAMILY: &str = "instrument-verifier-20-1111";
/// Kernel generation/canary owner; this module only emits a handoff.
pub const KERNEL_CANARY_OWNER: &str = "eliot-kernel-canary-11";
/// Product activation owner, deliberately outside this pipeline.
pub const PRODUCT_ACTIVATION_OWNER: &str = "eliot-product-activation-11";
/// Effect ceiling admitted by this owner.
pub const IMPROVEMENT_EFFECT_CEILING: &str = "candidate-only";
/// Risk marker required by the admission contract.
pub const IMPROVEMENT_RISK_MARKER: &str = "bounded-reversible";

/// Distinct operation identities retained in the `TestD` proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementOperation {
    /// Candidate proposal.
    Propose,
    /// Admission of a bounded experiment.
    AdmitExperiment,
    /// `TestD` experiment execution.
    ExecuteExperiment,
    /// `TestD` measurement.
    Measure,
    /// Independent Instrument evaluation.
    Evaluate,
    /// Governor candidate admission after evaluation.
    AdmitCanary,
    /// Kernel canary handoff.
    CanaryHandoff,
    /// Product activation, never called here.
    Promote,
    /// Owner-bound rollback or forward repair.
    Rollback,
}

impl ImprovementOperation {
    /// Returns the stable operation identity string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Propose => "improvement.propose",
            Self::AdmitExperiment => "improvement.admit-experiment",
            Self::ExecuteExperiment => "improvement.execute-experiment",
            Self::Measure => "improvement.measure",
            Self::Evaluate => "improvement.evaluate",
            Self::AdmitCanary => "improvement.admit-canary",
            Self::CanaryHandoff => "improvement.canary-handoff",
            Self::Promote => "improvement.promote",
            Self::Rollback => "improvement.rollback",
        }
    }

    /// Returns the fixed owner for this stage.
    #[must_use]
    pub fn owner(self, rollback_owner: &str) -> &str {
        match self {
            Self::Propose | Self::AdmitExperiment | Self::AdmitCanary => IMPROVEMENT_PIPELINE_OWNER,
            Self::ExecuteExperiment | Self::Measure => TESTD_OWNER,
            Self::Evaluate => VERIFIER_OWNER_FAMILY,
            Self::CanaryHandoff => KERNEL_CANARY_OWNER,
            Self::Promote => PRODUCT_ACTIVATION_OWNER,
            Self::Rollback => rollback_owner,
        }
    }

    /// Maps the public operation to the durable `TestD` operation kind.
    #[must_use]
    pub const fn durable_kind(self) -> ImprovementOperationKind {
        match self {
            Self::Propose => ImprovementOperationKind::Propose,
            Self::AdmitExperiment => ImprovementOperationKind::AdmitExperiment,
            Self::ExecuteExperiment => ImprovementOperationKind::ExecuteExperiment,
            Self::Measure => ImprovementOperationKind::Measure,
            Self::Evaluate => ImprovementOperationKind::Evaluate,
            Self::AdmitCanary => ImprovementOperationKind::AdmitCanary,
            Self::CanaryHandoff => ImprovementOperationKind::CanaryHandoff,
            Self::Promote => ImprovementOperationKind::Promote,
            Self::Rollback => ImprovementOperationKind::Rollback,
        }
    }
}

/// A terminal candidate decision. No variant carries activation or Finish
/// authority; `CanaryHandoffPending` is only a typed Kernel handoff.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum ImprovementTerminalDisposition {
    /// Independent evidence is exact but negative.
    Rejected {
        /// Stable negative reason.
        reason: String,
        /// Governor owner retaining the decision.
        owner_id: String,
    },
    /// Evidence was incomplete, stale, partial, or otherwise inconclusive.
    Inconclusive {
        /// Stable reason and exact missing/weak axis.
        reason: String,
        /// Evaluator owner that must produce more evidence.
        owner_id: String,
    },
    /// A counter metric regressed; exact rollback/forward repair is required.
    RegressionRollbackHandoff {
        /// Regression reason.
        reason: String,
        /// Rollback owner.
        rollback_owner_id: String,
        /// Rollback operation or recipe.
        rollback_ref: String,
        /// Forward-repair operation or recipe.
        forward_repair_ref: String,
        /// Exact invalidation set.
        invalidation_set: Vec<String>,
    },
    /// External outcome is unknown and must be reconciled before retry.
    UnknownRequiresReconciliation {
        /// Stable unknown-outcome reason.
        reason: String,
        /// Owner retaining the exact unknown identity.
        owner_id: String,
    },
    /// A materially identical failed repeat has no new discriminator.
    NoProgress {
        /// Prior job identity that proves repetition.
        prior_job_id: String,
        /// Owner retaining the repeat debt.
        owner_id: String,
    },
    /// Governor admits only a candidate canary handoff.
    CanaryHandoffPending {
        /// Exact proposal identity.
        proposal_id: String,
        /// Exact proposal digest.
        proposal_digest: String,
        /// Candidate identity, never an activation identity.
        candidate_id: String,
        /// Kernel operation identity that must independently authorize canary.
        canary_operation_id: String,
        /// Kernel owner that must receive the handoff.
        canary_owner_id: String,
        /// Exact rollback route retained with the handoff.
        rollback_ref: String,
        /// Exact forward-repair route retained with the handoff.
        forward_repair_ref: String,
    },
}

impl ImprovementTerminalDisposition {
    /// Maps the Governor decision to the durable `TestD` sidecar enum.
    #[must_use]
    pub const fn durable_disposition(&self) -> ImprovementExperimentDisposition {
        match self {
            Self::Rejected { .. } => ImprovementExperimentDisposition::Rejected,
            Self::Inconclusive { .. } => ImprovementExperimentDisposition::Inconclusive,
            Self::RegressionRollbackHandoff { .. } => {
                ImprovementExperimentDisposition::RegressionRollbackHandoff
            }
            Self::UnknownRequiresReconciliation { .. } => {
                ImprovementExperimentDisposition::UnknownRequiresReconciliation
            }
            Self::NoProgress { .. } => ImprovementExperimentDisposition::NoProgress,
            Self::CanaryHandoffPending { .. } => {
                ImprovementExperimentDisposition::CanaryHandoffPending
            }
        }
    }
}

/// Errors are structural refusals. They never become a successful candidate
/// decision and therefore cannot be acknowledged as terminal improvement
/// evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PipelineError {
    /// The proposal or independent evidence failed exact binding validation.
    #[error("improvement evidence binding rejected: {0}")]
    InvalidBinding(String),
    /// The durable outcome could not be constructed for the decision.
    #[error("improvement outcome construction rejected: {0}")]
    InvalidOutcome(String),
}

/// Evaluates one exact independent execution against one immutable proposal.
///
/// `prior_attempts` is read from the same durable `TestD` owner store by the
/// daemon consumer. It is evidence of prior identity, never a caller boolean.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered evidence-to-disposition proof keeps all negative branches together"
)]
pub fn evaluate_improvement_experiment(
    proposal: &ImprovementProposal,
    evidence: &IndependentExecutionEvidence,
    prior_attempts: &[ImprovementPriorAttempt],
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    proposal
        .validate()
        .map_err(|error| PipelineError::InvalidBinding(error.to_string()))?;
    evidence
        .validate_for(proposal, &proposal.experiment_id)
        .map_err(|error| PipelineError::InvalidBinding(error.to_string()))?;

    let current_discriminator = proposal
        .request
        .new_discriminator
        .as_ref()
        .map(|value| value.discriminator_id.as_str());
    if let Some(prior) = prior_attempts.iter().find(|prior| {
        prior.outcome == ImprovementPriorOutcome::Unknown
            && prior.material_digest == proposal.material_digest
            && prior.discriminator_id.as_deref() == current_discriminator
    }) {
        return Ok(
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                reason: format!("prior-unknown-outcome:{}", prior.job_id),
                owner_id: IMPROVEMENT_PIPELINE_OWNER.to_owned(),
            },
        );
    }
    if let Some(prior) = prior_attempts.iter().find(|prior| {
        prior.outcome == ImprovementPriorOutcome::Failed
            && is_improvement_no_progress(proposal, std::slice::from_ref(prior))
    }) {
        return Ok(ImprovementTerminalDisposition::NoProgress {
            prior_job_id: prior.job_id.clone(),
            owner_id: IMPROVEMENT_PIPELINE_OWNER.to_owned(),
        });
    }

    let expected_complete = proposal
        .request
        .expected_metric_names
        .iter()
        .all(|name| evidence.metric_dispositions.contains_key(name));
    if !expected_complete
        || evidence
            .metric_dispositions
            .values()
            .any(|value| matches!(value, ImprovementMetricDisposition::Incomplete))
    {
        return Ok(ImprovementTerminalDisposition::Inconclusive {
            reason: "independent-metric-table-incomplete".to_owned(),
            owner_id: evidence.verifier_id.clone(),
        });
    }
    if evidence.source_binding != ImprovementSourceBinding::ExactUnchanged
        || evidence.coverage != eliot_instrument_api::EvidenceCoverage::CompleteForScope
        || !matches!(
            evidence.freshness,
            eliot_instrument_api::EvidenceFreshness::ExactCandidate
                | eliot_instrument_api::EvidenceFreshness::ExactCommit
                | eliot_instrument_api::EvidenceFreshness::ExactQuiescedWorktree
        )
    {
        return Ok(ImprovementTerminalDisposition::Inconclusive {
            reason: "stale-or-incomplete-independent-execution-binding".to_owned(),
            owner_id: evidence.verifier_id.clone(),
        });
    }
    if evidence
        .metric_dispositions
        .values()
        .any(|value| matches!(value, ImprovementMetricDisposition::Regresses))
    {
        return Ok(ImprovementTerminalDisposition::RegressionRollbackHandoff {
            reason: "independent-counter-metric-regressed".to_owned(),
            rollback_owner_id: proposal.request.rollback.owner_id.clone(),
            rollback_ref: proposal.request.rollback.rollback_ref.clone(),
            forward_repair_ref: proposal.request.rollback.forward_repair_ref.clone(),
            invalidation_set: proposal.request.rollback.invalidation_set.clone(),
        });
    }
    if evidence
        .metric_dispositions
        .values()
        .any(|value| matches!(value, ImprovementMetricDisposition::Misses))
    {
        return Ok(ImprovementTerminalDisposition::Rejected {
            reason: "independent-expected-delta-not-met".to_owned(),
            owner_id: IMPROVEMENT_PIPELINE_OWNER.to_owned(),
        });
    }
    match evidence.outcome {
        eliot_instrument_api::VerificationOutcome::Pass => {
            let canary_operation_id = proposal
                .operation_id(ImprovementOperationKind::CanaryHandoff)
                .ok_or_else(|| {
                    PipelineError::InvalidBinding(
                        "proposal has no canary handoff operation".to_owned(),
                    )
                })?
                .to_owned();
            Ok(ImprovementTerminalDisposition::CanaryHandoffPending {
                proposal_id: proposal.proposal_id.clone(),
                proposal_digest: proposal.proposal_digest.clone(),
                candidate_id: proposal.request.candidate_id.clone(),
                canary_operation_id,
                canary_owner_id: KERNEL_CANARY_OWNER.to_owned(),
                rollback_ref: proposal.request.rollback.rollback_ref.clone(),
                forward_repair_ref: proposal.request.rollback.forward_repair_ref.clone(),
            })
        }
        eliot_instrument_api::VerificationOutcome::Fail => {
            Ok(ImprovementTerminalDisposition::Rejected {
                reason: "independent-verifier-failed".to_owned(),
                owner_id: IMPROVEMENT_PIPELINE_OWNER.to_owned(),
            })
        }
        eliot_instrument_api::VerificationOutcome::Unknown
        | eliot_instrument_api::VerificationOutcome::Blocked => Ok(
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                reason: "independent-verifier-outcome-unknown".to_owned(),
                owner_id: IMPROVEMENT_PIPELINE_OWNER.to_owned(),
            },
        ),
        eliot_instrument_api::VerificationOutcome::Partial
        | eliot_instrument_api::VerificationOutcome::Cancelled => {
            Ok(ImprovementTerminalDisposition::Inconclusive {
                reason: "independent-verifier-did-not-complete".to_owned(),
                owner_id: evidence.verifier_id.clone(),
            })
        }
    }
}

/// Builds the exact durable `TestD` outcome from a Governor disposition.
///
/// This is intentionally a constructor at the owner boundary: the daemon
/// cannot replace the proposal digest, evidence identity, rollback set, or
/// operation identity after evaluation.
pub fn build_improvement_outcome(
    proposal: &ImprovementProposal,
    evidence: &IndependentExecutionEvidence,
    disposition: &ImprovementTerminalDisposition,
    recorded_at_unix_ms: u64,
) -> Result<ImprovementExperimentOutcome, PipelineError> {
    if recorded_at_unix_ms <= proposal.mechanism_receipt.declared_at_unix_ms {
        return Err(PipelineError::InvalidOutcome(
            "terminal outcome must be recorded after declaration".to_owned(),
        ));
    }
    let decision_operation_id = match disposition {
        ImprovementTerminalDisposition::Rejected { .. }
        | ImprovementTerminalDisposition::Inconclusive { .. }
        | ImprovementTerminalDisposition::NoProgress { .. } => proposal
            .operation_id(ImprovementOperationKind::AdmitCanary)
            .ok_or_else(|| {
                PipelineError::InvalidOutcome("missing canary admission operation".to_owned())
            })?,
        ImprovementTerminalDisposition::RegressionRollbackHandoff { .. } => proposal
            .operation_id(ImprovementOperationKind::Rollback)
            .ok_or_else(|| {
                PipelineError::InvalidOutcome("missing rollback operation".to_owned())
            })?,
        ImprovementTerminalDisposition::UnknownRequiresReconciliation { .. } => proposal
            .operation_id(ImprovementOperationKind::Evaluate)
            .ok_or_else(|| {
                PipelineError::InvalidOutcome("missing evaluation operation".to_owned())
            })?,
        ImprovementTerminalDisposition::CanaryHandoffPending { .. } => proposal
            .operation_id(ImprovementOperationKind::CanaryHandoff)
            .ok_or_else(|| {
                PipelineError::InvalidOutcome("missing canary handoff operation".to_owned())
            })?,
    };
    let outcome = ImprovementExperimentOutcome {
        schema: eliot_testd_core::IMPROVEMENT_EXPERIMENT_SCHEMA.to_owned(),
        proposal_id: proposal.proposal_id.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        job_id: proposal.experiment_id.clone(),
        candidate_id: proposal.request.candidate_id.clone(),
        disposition: disposition.durable_disposition(),
        decision_operation_id: decision_operation_id.to_owned(),
        evidence_id: evidence.evidence_id.clone(),
        verifier_run_id: evidence.verifier_run_id.clone(),
        committed_receipt_sha256: evidence.committed_receipt_sha256.clone(),
        canonical_fact_id: evidence.evidence_id.clone(),
        canonical_fact_sha256: evidence.evidence_id.clone(),
        activation_attempt_id: None,
        activation_status: None,
        invalidation_set: proposal.request.rollback.invalidation_set.clone(),
        invalidation_set_digest: proposal.request.rollback.invalidation_set_digest.clone(),
        rollback_owner_id: proposal.request.rollback.owner_id.clone(),
        rollback_ref: proposal.request.rollback.rollback_ref.clone(),
        forward_repair_ref: proposal.request.rollback.forward_repair_ref.clone(),
        recorded_at_unix_ms,
    };
    outcome
        .validate_for(proposal, &proposal.experiment_id)
        .map_err(|error| PipelineError::InvalidOutcome(error.to_string()))?;
    Ok(outcome)
}

/// Returns the stable proposal digest for diagnostics and replay joins.
#[must_use]
pub fn proposal_digest(proposal: &ImprovementProposal) -> &str {
    &proposal.proposal_digest
}
