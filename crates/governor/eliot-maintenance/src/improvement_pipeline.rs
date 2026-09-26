//! Governor-owned improvement candidate to experiment to evaluation to admission pipeline.
//!
//! Experiment execution is owned by Testd (`#20`), independent evaluation by the
//! Instrument verifier family (`#20`/`#1111`), admission by Governor maintenance
//! `G-19` (`#18`), and generation/canary activation by the Kernel
//! generation/canary path (`#11`, handoff only, never executed here).
//!
//! This module is advisory-only: it never edits source, configuration, or
//! policy, never installs artifacts, never activates a generation, never issues
//! authority, and never emits `VERIFIED_COMPLETE`. A successful run ends at a
//! canary handoff request string that the Kernel owner must independently
//! authorize and execute.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::improvement_admission::{
    ImprovementAdmissionDecision, ImprovementAdmissionPolicy, ImprovementCandidateView,
    ImprovementEvidenceView, admit_improvement_candidate,
};

/// Governor maintenance owner for the improvement pipeline (`G-19`).
pub const IMPROVEMENT_PIPELINE_OWNER: &str = "governor-maintenance-G-19";
/// Testd owner for bounded experiment execution (`#20`).
pub const TESTD_OWNER: &str = "testd-20";
/// Independent Instrument verifier owner family (`#20`/`#1111`).
pub const VERIFIER_OWNER_FAMILY: &str = "instrument-verifier-20-1111";
/// Kernel generation/canary activation owner (`#11`, handoff only).
pub const KERNEL_CANARY_OWNER: &str = "kernel-generation-canary-11";
/// Operation identity for proposing an improvement candidate.
pub const OP_PROPOSE: &str = "improvement.propose";
/// Operation identity for Testd-owned experiment execution.
pub const OP_EXECUTE_EXPERIMENT: &str = "improvement.execute_experiment";
/// Operation identity for Testd-owned measurement.
pub const OP_MEASURE: &str = "improvement.measure";
/// Operation identity for independent verifier evaluation.
pub const OP_EVALUATE: &str = "improvement.evaluate";
/// Operation identity for Governor maintenance admission.
pub const OP_ADMIT: &str = "improvement.admit";
/// Operation identity for Kernel-owned canary activation (handoff only).
pub const OP_CANARY_ACTIVATE: &str = "improvement.canary_activate";
/// Operation identity for Governor policy promotion bookkeeping (advisory only).
pub const OP_PROMOTE: &str = "improvement.promote";
/// Operation identity for rollback owned by the named rollback contract owner.
pub const OP_ROLLBACK: &str = "improvement.rollback";
/// Only effect ceiling this pipeline admits.
pub const IMPROVEMENT_EFFECT_CEILING: &str = "advisory-only";
/// Required risk-ceiling marker proving the candidate stays bounded.
pub const IMPROVEMENT_RISK_MARKER: &str = "bounded";
/// Forbidden proof claim: product-level promotion is never admitted here.
pub const FORBIDDEN_PRODUCT_PROMOTION: &str = "product-promotion";
/// Forbidden completion claim: this pipeline never emits completion authority.
pub const FORBIDDEN_VERIFIED_COMPLETE: &str = "VERIFIED_COMPLETE";

/// Distinct pipeline operation with a fixed owner per step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementOperation {
    /// Governor-owned candidate proposal.
    Propose,
    /// Testd-owned bounded experiment execution.
    ExecuteExperiment,
    /// Testd-owned measurement of the bounded run.
    Measure,
    /// Independent verifier evaluation of measured evidence.
    Evaluate,
    /// Governor maintenance admission for experiment only.
    Admit,
    /// Kernel-owned canary activation (handoff only, never executed here).
    CanaryActivate,
    /// Governor policy promotion bookkeeping (advisory only, never an effect).
    Promote,
    /// Rollback owned by the rollback contract owner.
    Rollback,
}

impl ImprovementOperation {
    /// Returns the stable operation string for this step.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Propose => OP_PROPOSE,
            Self::ExecuteExperiment => OP_EXECUTE_EXPERIMENT,
            Self::Measure => OP_MEASURE,
            Self::Evaluate => OP_EVALUATE,
            Self::Admit => OP_ADMIT,
            Self::CanaryActivate => OP_CANARY_ACTIVATE,
            Self::Promote => OP_PROMOTE,
            Self::Rollback => OP_ROLLBACK,
        }
    }

    /// Returns the owning identity for this step.
    ///
    /// The rollback owner is caller-supplied because it comes from the bound
    /// rollback contract; every other step has a fixed pipeline owner.
    pub fn owner(self, rollback_owner_id: &str) -> &str {
        match self {
            Self::Propose | Self::Admit | Self::Promote => IMPROVEMENT_PIPELINE_OWNER,
            Self::ExecuteExperiment | Self::Measure => TESTD_OWNER,
            Self::Evaluate => VERIFIER_OWNER_FAMILY,
            Self::CanaryActivate => KERNEL_CANARY_OWNER,
            Self::Rollback => rollback_owner_id,
        }
    }
}

/// Pre-registered causal mechanism declared before any results are observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MechanismDeclaration {
    /// Stable mechanism identity.
    pub mechanism_id: String,
    /// Falsifiable hypothesis the experiment tests.
    pub hypothesis: String,
    /// Causal link from intervention to expected effect.
    pub causal_link: String,
    /// Reference proving the declaration was recorded.
    pub declared_ref: String,
    /// Must be true; post-hoc mechanisms are never admitted.
    pub declared_before_results: bool,
}

/// Bounded experiment plan executed by Testd under an independent evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperimentPlan {
    /// Stable experiment identity.
    pub experiment_id: String,
    /// Testd owner executing the bounded run.
    pub testd_owner_id: String,
    /// Independent evaluator that must verify the run.
    pub evaluator_id: String,
    /// Scope the experiment must not exceed.
    pub scope_ref: String,
    /// Budget the experiment must not exceed.
    pub budget_ref: String,
    /// Deadline or expiry the experiment must not exceed.
    pub deadline_ref: String,
    /// Operation this plan binds (must match the proposal).
    pub operation_ref: String,
    /// Idempotency key this plan binds (must match the proposal).
    pub idempotency_key: String,
}

/// Independent activation evidence bound to one candidate and one experiment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationEvidence {
    /// Stable evidence identity.
    pub evidence_id: String,
    /// Independent verifier that produced this evidence.
    pub verifier_id: String,
    /// Whether the verifier is independent of the candidate source.
    pub independent: bool,
    /// Whether the independent verifier passed the candidate.
    pub verifier_passed: bool,
    /// Opaque reference to the raw measured evidence.
    pub raw_evidence_ref: String,
    /// Must always be false; simulated runs never admit.
    pub simulated: bool,
    /// Candidate this evidence is bound to.
    pub bound_candidate_id: String,
    /// Experiment this evidence is bound to.
    pub bound_experiment_id: String,
}

/// Rollback contract named before any experiment is admitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackContract {
    /// Rollback contract reference with the external rollback owner.
    pub rollback_ref: String,
    /// Disable contract reference with the external rollback owner.
    pub disable_ref: String,
    /// Reopen contract reference with the external owner.
    pub reopen_ref: String,
    /// Expiry reference binding the admitted operation.
    pub expiry_ref: String,
    /// Rollback owner identity.
    pub rollback_owner_id: String,
    /// Forward-repair reference for incomplete rollback effects.
    pub forward_repair_ref: String,
    /// Invalidation set the rollback must cover.
    pub invalidation_set: Vec<String>,
}

/// Governor-side improvement proposal for one bounded experiment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementProposal {
    /// Stable proposal identity.
    pub proposal_id: String,
    /// Improvement candidate identity.
    pub candidate_id: String,
    /// Campaign the candidate learns from.
    pub campaign_id: String,
    /// Closure candidate identity.
    pub closure_id: String,
    /// Closure evidence digest (opaque).
    pub closure_digest: String,
    /// Opaque evidence references supporting the proposal.
    pub evidence_refs: Vec<String>,
    /// Capability the experiment targets.
    pub target_capability: String,
    /// Generation the experiment targets (observation only, never activated here).
    pub target_generation: String,
    /// Causal mechanism declared before results.
    pub mechanism: MechanismDeclaration,
    /// Expected advisory-only delta.
    pub expected_delta: String,
    /// Risk ceiling; must stay bounded.
    pub risk_ceiling: String,
    /// Effect ceiling; must stay advisory-only.
    pub effect_ceiling: String,
    /// Budget the experiment must not exceed.
    pub budget_ref: String,
    /// Deadline the experiment must not exceed.
    pub deadline_ref: String,
    /// Privacy class of the proposal inputs.
    pub privacy_class: String,
    /// Invalidation set covered by the rollback contract.
    pub invalidation_set: Vec<String>,
    /// Operation this proposal binds.
    pub operation_ref: String,
    /// Idempotency key this proposal binds.
    pub idempotency_key: String,
    /// Source identity of the proposal.
    pub source_identity: String,
    /// Runtime identity of the proposal.
    pub runtime_identity: String,
    /// Data identity of the proposal.
    pub data_identity: String,
}

impl ImprovementProposal {
    /// Validates proposal shape, ceilings, and pre-declaration.
    ///
    /// Rejects empty fields, post-hoc mechanisms, non-advisory effects,
    /// promotion or completion claims, and unbounded risk ceilings. Returns a
    /// [`PipelineError`] describing the first violation found.
    pub fn validate(&self) -> Result<(), PipelineError> {
        text(&self.proposal_id, "proposal_id")?;
        text(&self.candidate_id, "candidate_id")?;
        text(&self.campaign_id, "campaign_id")?;
        text(&self.closure_id, "closure_id")?;
        text(&self.closure_digest, "closure_digest")?;
        text(&self.target_capability, "target_capability")?;
        text(&self.target_generation, "target_generation")?;
        text(&self.expected_delta, "expected_delta")?;
        text(&self.risk_ceiling, "risk_ceiling")?;
        text(&self.effect_ceiling, "effect_ceiling")?;
        text(&self.budget_ref, "budget_ref")?;
        text(&self.deadline_ref, "deadline_ref")?;
        text(&self.privacy_class, "privacy_class")?;
        text(&self.operation_ref, "operation_ref")?;
        text(&self.idempotency_key, "idempotency_key")?;
        text(&self.source_identity, "source_identity")?;
        text(&self.runtime_identity, "runtime_identity")?;
        text(&self.data_identity, "data_identity")?;
        text(&self.mechanism.mechanism_id, "mechanism.mechanism_id")?;
        text(&self.mechanism.hypothesis, "mechanism.hypothesis")?;
        text(&self.mechanism.causal_link, "mechanism.causal_link")?;
        text(&self.mechanism.declared_ref, "mechanism.declared_ref")?;
        if self.evidence_refs.is_empty() {
            return Err(PipelineError::MissingField("evidence_refs"));
        }
        for value in &self.evidence_refs {
            text(value, "evidence_refs")?;
        }
        if self.invalidation_set.is_empty() {
            return Err(PipelineError::MissingField("invalidation_set"));
        }
        for value in &self.invalidation_set {
            text(value, "invalidation_set")?;
        }
        if !self.mechanism.declared_before_results {
            return Err(PipelineError::MechanismNotPredeclared);
        }
        if self.effect_ceiling != IMPROVEMENT_EFFECT_CEILING {
            return Err(PipelineError::AdmissionFailed(format!(
                "effect ceiling {:?} widens beyond {}",
                self.effect_ceiling, IMPROVEMENT_EFFECT_CEILING
            )));
        }
        for watched in [
            &self.expected_delta,
            &self.target_capability,
            &self.target_generation,
            &self.risk_ceiling,
            &self.effect_ceiling,
        ] {
            if watched.contains(FORBIDDEN_PRODUCT_PROMOTION)
                || watched.contains(FORBIDDEN_VERIFIED_COMPLETE)
            {
                return Err(PipelineError::AdmissionFailed(format!(
                    "promotion claim {watched:?} exceeds advisory-only proof ceiling"
                )));
            }
        }
        if !self.risk_ceiling.contains(IMPROVEMENT_RISK_MARKER) {
            return Err(PipelineError::AdmissionFailed(format!(
                "risk ceiling {:?} must contain {:?}",
                self.risk_ceiling, IMPROVEMENT_RISK_MARKER
            )));
        }
        Ok(())
    }
}

/// Terminal disposition for one improvement candidate pipeline run.
///
/// Advisory-only: no variant performs promotion, activation, canary cutover, or
/// completion. `CanaryAdmitted` carries only a handoff request string for the
/// Kernel owner, never a permit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementTerminalDisposition {
    /// Candidate is rejected with a stable reason.
    Rejected {
        /// Stable rejection reason naming exact evidence.
        reason: String,
    },
    /// Candidate is well-formed but evidence is incomplete.
    Inconclusive {
        /// Exact missing evidence.
        missing: String,
    },
    /// Candidate regressed the measured outcome and is rejected.
    RegressionRejected {
        /// Stable regression reason naming exact evidence.
        reason: String,
    },
    /// External outcome is unknown; reconciliation is required before retry.
    UnknownRequiresReconciliation {
        /// What must be reconciled before any retry.
        reason: String,
    },
    /// Candidate is rolled back under the named rollback contract.
    RolledBack {
        /// Rollback contract reference owning the repair.
        contract_ref: String,
    },
    /// Materially identical repeat without a new discriminator.
    NoProgress {
        /// Prior digest this repeats, with exact debt retained.
        reason: String,
    },
    /// Candidate is admitted for one bounded canary handoff request.
    CanaryAdmitted {
        /// Handoff request for Kernel activation; never a permit.
        canary_permit_request: String,
    },
}

/// Borrowed inputs for one pure pipeline run.
#[derive(Clone, Copy, Debug)]
pub struct ImprovementPipelineInputs<'a> {
    /// Governor-side proposal under review.
    pub proposal: &'a ImprovementProposal,
    /// Testd-owned bounded experiment plan.
    pub experiment: &'a ExperimentPlan,
    /// Independent activation evidence for the bound candidate and experiment.
    pub evidence: &'a ActivationEvidence,
    /// Rollback contract named before admission.
    pub rollback: &'a RollbackContract,
    /// Candidate view consumed by Governor admission.
    pub candidate: &'a ImprovementCandidateView,
    /// Independent evidence view consumed by Governor admission.
    pub admission_evidence: &'a ImprovementEvidenceView,
    /// Policy governing Governor admission.
    pub policy: &'a ImprovementAdmissionPolicy,
}

/// Typed pipeline failures. Malformed or unbound input never decides.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PipelineError {
    /// A required field is missing or empty.
    #[error("improvement pipeline field is missing: {0}")]
    MissingField(&'static str),
    /// The causal mechanism was not declared before results were observed.
    #[error("improvement mechanism was not predeclared before results")]
    MechanismNotPredeclared,
    /// Two pipeline operation identities collide.
    #[error("improvement operation identity collision: {detail}")]
    OperationIdentityCollision {
        /// What collided.
        detail: String,
    },
    /// Evidence is not independent, did not pass, or names no raw evidence.
    #[error("improvement evidence is not independent")]
    EvidenceNotIndependent,
    /// Simulated evidence can never admit a candidate.
    #[error("improvement simulated evidence is forbidden")]
    SimulatedEvidenceForbidden,
    /// Evidence, experiment, or proposal bindings diverge.
    #[error("improvement evidence is unbound: {detail}")]
    UnboundEvidence {
        /// What diverged.
        detail: String,
    },
    /// The rollback contract leaves a gap before experiment.
    #[error("improvement rollback contract gap: {detail}")]
    RollbackContractGap {
        /// What is missing.
        detail: String,
    },
    /// Governor admission refused or failed with the inner reason.
    #[error("improvement admission failed: {0}")]
    AdmissionFailed(String),
}

/// Returns the stable digest for one proposal.
///
/// Deterministic FNV-1a 64-bit hex over the proposal, mechanism, target,
/// operation, and idempotency identities plus the sorted evidence and
/// invalidation sets. Sorted sets keep the digest stable under input order.
/// No `Debug` formatting is used.
pub fn proposal_digest(proposal: &ImprovementProposal) -> String {
    let mut evidence = proposal.evidence_refs.clone();
    evidence.sort();
    let mut invalidation = proposal.invalidation_set.clone();
    invalidation.sort();
    let mut canonical = String::new();
    for part in [
        proposal.proposal_id.as_str(),
        proposal.candidate_id.as_str(),
        proposal.campaign_id.as_str(),
        proposal.closure_id.as_str(),
        proposal.closure_digest.as_str(),
        proposal.mechanism.mechanism_id.as_str(),
        proposal.target_capability.as_str(),
        proposal.target_generation.as_str(),
        proposal.operation_ref.as_str(),
        proposal.idempotency_key.as_str(),
    ] {
        canonical.push_str(part);
        canonical.push('|');
    }
    canonical.push_str(&evidence.join(","));
    canonical.push('|');
    canonical.push_str(&invalidation.join(","));
    fnv1a_hex(canonical.as_bytes())
}

/// Reports whether a proposal repeats a prior digest without new signal.
///
/// Returns true exactly when the current digest equals the prior digest and no
/// new discriminator is present.
pub fn detect_no_progress(
    prior_digest: &str,
    proposal: &ImprovementProposal,
    new_discriminator: bool,
) -> bool {
    proposal_digest(proposal) == prior_digest && !new_discriminator
}

/// Reconciles an unknown external activation outcome without retrying blindly.
///
/// Maps `RequiresReconciliation` to the unknown-reconciliation disposition and
/// every other decision to an inconclusive disposition naming the prior state.
pub fn reconcile_unknown_activation(
    prior: &ImprovementAdmissionDecision,
) -> ImprovementTerminalDisposition {
    match prior {
        ImprovementAdmissionDecision::RequiresReconciliation { reason } => {
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                reason: reason.clone(),
            }
        }
        ImprovementAdmissionDecision::AdmitForExperiment { candidate_id, .. } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: format!(
                    "unknown-activation: prior admission for {candidate_id} reconciles before retry"
                ),
            }
        }
        ImprovementAdmissionDecision::Reject { reason, .. } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: format!("unknown-activation: prior rejection reconciles: {reason}"),
            }
        }
        ImprovementAdmissionDecision::NeedsMoreEvidence { missing, .. } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: format!("unknown-activation: prior evidence gap reconciles: {missing}"),
            }
        }
        ImprovementAdmissionDecision::Blocked { reason, .. } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: format!("unknown-activation: prior block reconciles: {reason}"),
            }
        }
        ImprovementAdmissionDecision::NoProgress { reason, .. } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: format!("unknown-activation: prior no-progress reconciles: {reason}"),
            }
        }
    }
}

/// Runs the advisory-only candidate to experiment to evaluation to admission pipeline.
///
/// Pure orchestrator over borrowed inputs: validates the proposal, checks that
/// the eight operation identities are pairwise distinct, binds the experiment
/// and evidence to the proposal, rejects simulated or dependent evidence,
/// requires a gap-free rollback contract, then delegates the admission verdict
/// to `improvement_admission::admit_improvement_candidate`. Never performs
/// promotion, activation, canary cutover, authority issuance, or completion.
pub fn run_improvement_candidate_pipeline(
    inputs: ImprovementPipelineInputs<'_>,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    inputs.proposal.validate()?;
    check_operation_identities()?;
    if inputs.experiment.experiment_id.trim().is_empty() {
        return Err(PipelineError::MissingField("experiment.experiment_id"));
    }
    if inputs.experiment.testd_owner_id.trim().is_empty() {
        return Err(PipelineError::MissingField("experiment.testd_owner_id"));
    }
    if inputs.experiment.evaluator_id.trim().is_empty() {
        return Err(PipelineError::MissingField("experiment.evaluator_id"));
    }
    if inputs.experiment.scope_ref.trim().is_empty() {
        return Err(PipelineError::MissingField("experiment.scope_ref"));
    }
    if inputs.experiment.budget_ref.trim().is_empty() {
        return Err(PipelineError::MissingField("experiment.budget_ref"));
    }
    if inputs.experiment.deadline_ref.trim().is_empty() {
        return Err(PipelineError::MissingField("experiment.deadline_ref"));
    }
    if inputs.experiment.operation_ref != inputs.proposal.operation_ref
        || inputs.experiment.idempotency_key != inputs.proposal.idempotency_key
    {
        return Err(PipelineError::UnboundEvidence {
            detail: "experiment operation/idempotency must match proposal: binding-mismatch"
                .to_string(),
        });
    }
    if inputs.evidence.bound_candidate_id != inputs.proposal.candidate_id
        || inputs.evidence.bound_experiment_id != inputs.experiment.experiment_id
    {
        return Err(PipelineError::UnboundEvidence {
            detail: "evidence candidate/experiment binding must match proposal and plan: binding-mismatch"
                .to_string(),
        });
    }
    if inputs.evidence.simulated {
        return Err(PipelineError::SimulatedEvidenceForbidden);
    }
    if !inputs.evidence.independent
        || !inputs.evidence.verifier_passed
        || inputs.evidence.raw_evidence_ref.trim().is_empty()
    {
        return Err(PipelineError::EvidenceNotIndependent);
    }
    if inputs.evidence.evidence_id.trim().is_empty() {
        return Err(PipelineError::MissingField("evidence.evidence_id"));
    }
    if inputs.evidence.verifier_id.trim().is_empty() {
        return Err(PipelineError::MissingField("evidence.verifier_id"));
    }
    check_rollback_contract(inputs.rollback)?;
    let decision =
        admit_improvement_candidate(inputs.candidate, inputs.admission_evidence, inputs.policy)
            .map_err(|err| PipelineError::AdmissionFailed(err.to_string()))?;
    Ok(map_decision(
        &decision,
        inputs.proposal,
        inputs.experiment,
        inputs.evidence,
        inputs.rollback,
    ))
}

/// Verifies the eight pipeline operation strings are pairwise distinct.
fn check_operation_identities() -> Result<(), PipelineError> {
    let operations = [
        OP_PROPOSE,
        OP_EXECUTE_EXPERIMENT,
        OP_MEASURE,
        OP_EVALUATE,
        OP_ADMIT,
        OP_CANARY_ACTIVATE,
        OP_PROMOTE,
        OP_ROLLBACK,
    ];
    for (index, first) in operations.iter().enumerate() {
        for second in &operations[index + 1..] {
            if first == second {
                return Err(PipelineError::OperationIdentityCollision {
                    detail: format!("duplicate operation identity {first:?}"),
                });
            }
        }
    }
    Ok(())
}

/// Requires a gap-free rollback contract before any experiment is admitted.
fn check_rollback_contract(contract: &RollbackContract) -> Result<(), PipelineError> {
    if contract.rollback_ref.trim().is_empty() {
        return Err(PipelineError::RollbackContractGap {
            detail: "missing-rollback: rollback contract required before experiment".to_string(),
        });
    }
    if contract.disable_ref.trim().is_empty() {
        return Err(PipelineError::RollbackContractGap {
            detail: "missing-disable: disable contract required before experiment".to_string(),
        });
    }
    if contract.reopen_ref.trim().is_empty() {
        return Err(PipelineError::RollbackContractGap {
            detail: "missing-reopen: reopen contract required before experiment".to_string(),
        });
    }
    if contract.expiry_ref.trim().is_empty() {
        return Err(PipelineError::RollbackContractGap {
            detail: "missing-expiry: expiry must bind the admitted operation".to_string(),
        });
    }
    if contract.forward_repair_ref.trim().is_empty() {
        return Err(PipelineError::RollbackContractGap {
            detail: "missing-forward-repair: forward repair required before experiment".to_string(),
        });
    }
    if contract.rollback_owner_id.trim().is_empty() {
        return Err(PipelineError::RollbackContractGap {
            detail: "missing-rollback-owner: rollback owner required before experiment".to_string(),
        });
    }
    if contract.invalidation_set.is_empty() {
        return Err(PipelineError::RollbackContractGap {
            detail: "missing-invalidation: invalidation set required before experiment".to_string(),
        });
    }
    for value in &contract.invalidation_set {
        if value.trim().is_empty() {
            return Err(PipelineError::RollbackContractGap {
                detail: "missing-invalidation: invalidation entry must not be empty".to_string(),
            });
        }
    }
    Ok(())
}

/// Maps a Governor admission decision to the advisory-only terminal disposition.
fn map_decision(
    decision: &ImprovementAdmissionDecision,
    proposal: &ImprovementProposal,
    experiment: &ExperimentPlan,
    evidence: &ActivationEvidence,
    rollback: &RollbackContract,
) -> ImprovementTerminalDisposition {
    match decision {
        ImprovementAdmissionDecision::AdmitForExperiment {
            candidate_id,
            evaluator_id,
            rollback_owner_id,
            ..
        } => ImprovementTerminalDisposition::CanaryAdmitted {
            canary_permit_request: format!(
                "canary-handoff: candidate {candidate_id} proposal-digest {} experiment {} evaluator {evaluator_id} rollback-owner {rollback_owner_id}; #11 Kernel activation required, not executed here; verifier {} evidence {}",
                proposal_digest(proposal),
                experiment.experiment_id,
                evidence.verifier_id,
                evidence.evidence_id
            ),
        },
        ImprovementAdmissionDecision::Reject { reason, .. } => {
            if reason.contains("pulse-regression") || reason.contains("regression") {
                ImprovementTerminalDisposition::RegressionRejected {
                    reason: reason.clone(),
                }
            } else {
                ImprovementTerminalDisposition::Rejected {
                    reason: reason.clone(),
                }
            }
        }
        ImprovementAdmissionDecision::NeedsMoreEvidence { missing, .. } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: missing.clone(),
            }
        }
        ImprovementAdmissionDecision::Blocked { reason, .. } => {
            if reason.contains("rollback")
                || reason.contains("disable")
                || reason.contains("reopen")
                || reason.contains("expiry")
                || reason.contains("stale")
            {
                ImprovementTerminalDisposition::RolledBack {
                    contract_ref: rollback.rollback_ref.clone(),
                }
            } else {
                ImprovementTerminalDisposition::Rejected {
                    reason: reason.clone(),
                }
            }
        }
        ImprovementAdmissionDecision::RequiresReconciliation { reason } => {
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                reason: reason.clone(),
            }
        }
        ImprovementAdmissionDecision::NoProgress { reason, .. } => {
            ImprovementTerminalDisposition::NoProgress {
                reason: reason.clone(),
            }
        }
    }
}

/// Computes deterministic FNV-1a 64-bit hex over raw bytes.
fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let mut out = String::with_capacity(16);
    for shift in [60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0] {
        let nibble = ((hash >> shift) & 0xf) as u8;
        out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
    }
    out
}

/// Reads one required text field without accepting empty or blank values.
fn text(value: &str, field: &'static str) -> Result<(), PipelineError> {
    if value.trim().is_empty() {
        Err(PipelineError::MissingField(field))
    } else {
        Ok(())
    }
}
