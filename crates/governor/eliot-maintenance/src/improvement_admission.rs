//! Governor-owned candidate admission for improvement proposals.
//!
//! Maintenance (`G-19`) is the sole admission owner for
//! `meta.learning.closure` (`#819`) and `meta.improvement.promotion_input`
//! (`#972`) candidates. This module binds those two proved cells to one
//! deterministic admission decision without importing their crates: the
//! candidate is admitted **for bounded experiment only**, never for promotion,
//! activation, canary cutover, policy change, or task Finish.
//!
//! The improvement crates remain the candidate owners; this module is their
//! real Governor-side consumer. Experiment execution stays with Testd /
//! Instrument (`#20`/`#1111`, handoff) and production activation stays with
//! the Kernel generation/canary path (`#11`, handoff). Unknown external
//! outcomes reconcile before retry; an exact canonical replay of a retained
//! proposal commitment disposes as no-progress rather than improvement, no
//! caller-settable boolean and no caller-authored assessment can establish
//! progress or clear an unknown external effect, and an absent or
//! non-discriminating retained record establishes nothing at all.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::improvement_pipeline::{
    ImprovementCurrentProposal, ImprovementReplayAssessment, ProposalCommitment,
    RetainedImprovementProposal, UnestablishedPriorCause, assess_improvement_progress,
};

/// Improvement closure cell identity (mirrors `meta.learning.closure`).
pub const IMPROVEMENT_CLOSURE_MODULE: &str = "meta.learning.closure";
/// Improvement promotion-input cell identity
/// (mirrors `meta.improvement.promotion_input`).
pub const IMPROVEMENT_PROMOTION_MODULE: &str = "meta.improvement.promotion_input";
/// Product pulse observed as evidence only, never emitted.
pub const IMPROVEMENT_PRODUCT_PULSE: &str = "ONLINE_LEARNING_INNER_LOOP_PULSE_01";
/// Only proof ceiling this gate admits.
pub const IMPROVEMENT_PROOF_CEILING: &str = "module-proof-only";
/// Only effect class this gate admits.
pub const IMPROVEMENT_REQUESTED_EFFECT: &str = "advisory-only";

/// Opaque product-pulse outcome bound to the exact pulse identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementPulseOutcome {
    /// Exact pulse passed with a bound evidence ref.
    Pass,
    /// Exact pulse regressed; the candidate is rejected, never retried blindly.
    Regression,
    /// Pulse outcome unknown; reconciled before retry.
    Unknown,
    /// Pulse evidence missing; package-green is never a substitute.
    Missing,
}

/// Opaque candidate view over the two proved improvement cells.
///
/// Binds one closure candidate (`#819`) and, when present, its promotion-input
/// advisory (`#972`) by exact identity and digest. No candidate internals are
/// reinterpreted here; digests are opaque and order-invariant at the source.
///
/// `admitted_scope_ref` is the `WorkScope` the candidate owner proved for this
/// candidate. It is the only admitted scope evidence: the experiment scope is
/// never derived from the candidate identity. An absent binding stays a named
/// gap and is disposed as `Blocked`, never replaced by a default.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementCandidateView {
    /// Improvement candidate identity.
    pub candidate_id: String,
    /// Campaign the candidate learns from.
    pub campaign_id: String,
    /// Closure candidate identity (`#819`).
    pub closure_id: String,
    /// Closure evidence digest (opaque, order-invariant at the source).
    pub closure_digest: String,
    /// Promotion-input advisory identity (`#972`), when prepared.
    pub promotion_input_id: Option<String>,
    /// Promotion evidence digest (opaque), when prepared.
    pub promotion_digest: Option<String>,
    /// Admitted work scope the candidate owner proved; absent stays a named gap.
    pub admitted_scope_ref: Option<String>,
    /// Proof ceiling claimed by the candidate; must stay candidate-only.
    pub proof_ceiling: String,
    /// Requested effect class; must stay advisory-only.
    pub requested_effect: String,
    /// Must always be false; a true value is self-promotion.
    pub direct_promotion: bool,
    /// Must always be none; permits are issued only by the external owner.
    pub active_permit: Option<String>,
    /// Must always be none; receipts are issued only by the external owner.
    pub promotion_receipt: Option<String>,
    /// Operation the candidate binds.
    pub operation_ref: String,
    /// Idempotency key the candidate binds.
    pub idempotency_key: String,
}

/// Independent experiment evidence bound to the exact candidate.
///
/// A later independent admission review may legitimately carry a different
/// `verifier_id` than the experiment evaluation. What binds it is the typed
/// relation to the same candidate, experiment, and evaluated content revision,
/// never an indiscriminate comparison of verifier identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ImprovementEvidenceView {
    /// Independent evaluator identity.
    pub verifier_id: String,
    /// Candidate this admission review is bound to.
    pub bound_candidate_id: String,
    /// Experiment this admission review is bound to.
    pub bound_experiment_id: String,
    /// Exact content revision this admission review evaluated.
    pub content_revision_ref: String,
    /// Exact run this admission review observed.
    pub run_ref: String,
    /// Whether the evaluator is independent of the candidate source.
    pub independent: bool,
    /// Whether the independent evaluator passed the candidate.
    pub verifier_passed: bool,
    /// Product-pulse outcome for the exact pulse identity.
    pub pulse: ImprovementPulseOutcome,
    /// Pulse evidence ref (required on pass).
    pub pulse_ref: Option<String>,
    /// Whether harm was observed on any denominator member.
    pub harm_observed: bool,
    /// Whether the external execution outcome is unknown.
    pub outcome_unknown: bool,
    /// Whether the closure binding is currently valid.
    pub closure_valid: bool,
    /// Whether the closure binding went stale (reuse-invalid).
    pub closure_stale: bool,
    /// Rollback contract ref with the external rollback owner.
    pub rollback_ref: Option<String>,
    /// Disable contract ref with the external rollback owner.
    pub disable_ref: Option<String>,
    /// Reopen contract ref with the external owner.
    pub reopen_ref: Option<String>,
    /// Rollback owner identity; must match policy.
    pub rollback_owner_id: String,
    /// Expiry ref; must bind the admitted operation.
    pub expiry_ref: Option<String>,
    /// Retained prior proposal record this admission is compared against.
    ///
    /// This is a retained record, never a verdict. The gate derives the
    /// assessment itself from this record and the current record the pipeline
    /// committed, so no caller can assert a repeat, a new discriminator, or any
    /// progress by spelling a boolean or a verdict. `None` means no retained
    /// record was supplied; that establishes nothing, is never read as novelty,
    /// and clears no external effect.
    pub retained_prior_proposal: Option<RetainedImprovementProposal>,
}

/// Policy governing improvement admission. No clock, I/O, or live query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementAdmissionPolicy {
    /// Governor admission owner deciding here.
    pub external_owner_id: String,
    /// Rollback owner named before any experiment is admitted.
    pub rollback_owner_id: String,
    /// Operation this admission binds.
    pub operation_ref: String,
    /// Idempotency key this admission binds.
    pub idempotency_key: String,
    /// Whether independent verification is required (always true in practice).
    pub require_independent_verifier: bool,
}

/// Owner-defined cause of a rejected improvement candidate.
///
/// The cause is typed machine state, not prose. Explanatory reason text may be
/// reworded without changing this value, and this value is never inferred from
/// the words of a reason string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementRejectCause {
    /// The closure binding is invalid.
    InvalidClosureBinding,
    /// Harm was observed on a denominator member and is never compensated.
    HarmObserved,
    /// The product pulse regressed on the exact pulse identity.
    PulseRegression,
}

/// Owner-defined cause of a blocked improvement candidate.
///
/// A block names a prerequisite that is still missing or a binding that must be
/// revalidated. It is neither a rejection nor an observed completed rollback,
/// and a named rollback contract never supplies the cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementBlockCause {
    /// A required rollback contract reference is still missing.
    MissingRollback,
    /// A required disable contract reference is still missing.
    MissingDisable,
    /// A required reopen contract reference is still missing.
    MissingReopen,
    /// A required expiry binding is still missing.
    MissingExpiry,
    /// The evidence rollback owner differs from the policy rollback owner.
    RollbackOwnerGap,
    /// The candidate carries no owner-proved admitted scope binding.
    MissingAdmittedScope,
    /// The closure binding went stale and reuse is invalid.
    StaleClosure,
}

/// What a blocked candidate's owner must do before it may be re-evaluated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementBlockRemedy {
    /// A named prerequisite contract reference is still missing.
    MissingPrerequisite,
    /// The candidate must be revalidated against current evidence bindings.
    RevalidationRequired,
}

impl ImprovementBlockCause {
    /// Returns the remedy the responsible owner must complete.
    ///
    /// Derived from the typed cause so the obligation cannot drift with the
    /// wording of an explanation.
    pub const fn remedy(self) -> ImprovementBlockRemedy {
        match self {
            Self::MissingRollback
            | Self::MissingDisable
            | Self::MissingReopen
            | Self::MissingExpiry => ImprovementBlockRemedy::MissingPrerequisite,
            Self::RollbackOwnerGap | Self::MissingAdmittedScope | Self::StaleClosure => {
                ImprovementBlockRemedy::RevalidationRequired
            }
        }
    }
}

/// Maintenance-owned admission decision for one improvement candidate.
///
/// `AdmitForExperiment` releases the candidate to bounded Testd/Instrument
/// execution only. Every other variant keeps the candidate out of the
/// experiment path with exact missing evidence and owner. No variant performs
/// promotion, activation, canary cutover, rollback execution, or Finish, and no
/// variant ever reports an observed completed rollback.
///
/// Wire revision: `Reject` and `Blocked` carry a typed `cause`, and
/// `RequiresReconciliation` carries the owner holding the reconciliation debt.
/// Unknown fields are refused, so bytes written before that revision no longer
/// decode into a current decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ImprovementAdmissionDecision {
    /// Candidate may proceed to one bounded experiment under Testd ownership.
    AdmitForExperiment {
        /// Candidate admitted.
        candidate_id: String,
        /// Campaign the experiment must run against.
        campaign_id: String,
        /// Scope the experiment must not exceed, taken from the candidate's
        /// owner-proved admitted scope binding.
        experiment_scope_ref: String,
        /// Evaluator that must independently verify the run.
        evaluator_id: String,
        /// Rollback owner that must stay named for the run.
        rollback_owner_id: String,
    },
    /// Candidate is rejected; the scope is retained, nothing is removed silently.
    Reject {
        /// Owner-defined rejection cause.
        cause: ImprovementRejectCause,
        /// Stable rejection reason naming exact evidence.
        reason: String,
        /// Owner holding the retained scope.
        owner_id: String,
    },
    /// Candidate is well-formed but evidence is incomplete; no admission inferred.
    NeedsMoreEvidence {
        /// Exact missing evidence, bounded and redacted.
        missing: String,
        /// Owner that must supply it.
        owner_id: String,
    },
    /// Candidate is well-formed but blocked on a rollback prerequisite, a
    /// missing admitted scope, or a stale closure binding.
    Blocked {
        /// Owner-defined block cause.
        cause: ImprovementBlockCause,
        /// Stable block reason naming exact evidence.
        reason: String,
        /// Owner that must clear it.
        owner_id: String,
    },
    /// External outcome is unknown; blind retry is forbidden until reconciled.
    RequiresReconciliation {
        /// What must be reconciled before any retry.
        reason: String,
        /// Owner holding the unresolved reconciliation debt.
        owner_id: String,
    },
    /// The current canonical proposal bytes exactly replay a retained prior
    /// commitment under the same logical operation. An exact repeat is not
    /// progress, and no caller assertion can make it one.
    NoProgress {
        /// Prior commitment this exactly replays, with exact debt retained.
        reason: String,
        /// Owner holding the repeat-review debt.
        owner_id: String,
    },
}

/// Typed admission failures. Malformed or self-promoting input never decides.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ImprovementAdmissionError {
    /// A required field is missing or empty.
    #[error("improvement admission field is missing: {0}")]
    MissingField(&'static str),
    /// Same-field identity divergence across candidate, evidence, and policy.
    #[error("improvement admission identity mismatch: {detail}")]
    IdentityMismatch {
        /// What diverged.
        detail: String,
    },
    /// The candidate claims promotion output; advisory-only is violated.
    #[error("improvement candidates cannot self-promote")]
    SelfPromotionForbidden,
    /// The candidate widens proof, privacy, or effect beyond the ceiling.
    #[error("improvement admission widening rejected: {detail}")]
    WideningRejected {
        /// What widened.
        detail: String,
    },
}

/// Admit one improvement candidate for bounded experiment or dispose it.
///
/// Pure function of its four inputs: no ambient clock, I/O, or live query.
/// Returns one [`ImprovementAdmissionDecision`] for well-formed input, or an
/// [`ImprovementAdmissionError`] for malformed, self-promoting, or widening
/// input. Admission is experiment-only; canary activation, production
/// promotion, and rollback execution stay with their external owners.
///
/// `current` is the record `improvement_pipeline` committed for the exact
/// proposal bytes it checked, and the retained prior record travels on
/// `evidence`. The gate owns the verdict: it derives the assessment from those
/// two records itself and accepts no assessment, boolean, or reason from a
/// caller, so no field of a record can manufacture progress. Integrity stays
/// separate from semantic progress: an exact replay is no progress, changed
/// content under one operation and idempotency key is a typed identity conflict
/// that performs no transition, a retained record written under another domain,
/// encoding revision, or algorithm is unestablished and requires reconciliation,
/// a new proposal identity or a different digest establishes nothing on its
/// own, and a new causal discriminator requires both a changed discriminator
/// projection and owner-issued evidence the retained record did not declare.
/// With no retained record at all, no progress is established.
pub fn admit_improvement_candidate(
    candidate: &ImprovementCandidateView,
    evidence: &ImprovementEvidenceView,
    policy: &ImprovementAdmissionPolicy,
    current: &ImprovementCurrentProposal,
) -> Result<ImprovementAdmissionDecision, ImprovementAdmissionError> {
    validate_candidate(candidate)?;
    validate_policy(policy, candidate)?;
    validate_evidence(evidence)?;

    if evidence.outcome_unknown {
        return Ok(ImprovementAdmissionDecision::RequiresReconciliation {
            reason: "unknown-execution-outcome: reconcile exact external effect before retry"
                .to_string(),
            owner_id: policy.external_owner_id.clone(),
        });
    }
    if !evidence.closure_valid {
        return Ok(ImprovementAdmissionDecision::Reject {
            cause: ImprovementRejectCause::InvalidClosureBinding,
            reason: "invalid-closure-binding: valid closure required".to_string(),
            owner_id: policy.external_owner_id.clone(),
        });
    }
    if evidence.closure_stale {
        return Ok(ImprovementAdmissionDecision::Blocked {
            cause: ImprovementBlockCause::StaleClosure,
            reason: "stale-closure-binding: reuse-invalid; revalidation required".to_string(),
            owner_id: policy.external_owner_id.clone(),
        });
    }
    if evidence.harm_observed {
        return Ok(ImprovementAdmissionDecision::Reject {
            cause: ImprovementRejectCause::HarmObserved,
            reason: "harm-observed: harm is never compensated".to_string(),
            owner_id: policy.external_owner_id.clone(),
        });
    }
    match &evidence.pulse {
        ImprovementPulseOutcome::Regression => {
            return Ok(ImprovementAdmissionDecision::Reject {
                cause: ImprovementRejectCause::PulseRegression,
                reason: "pulse-regression: positive candidate blocked".to_string(),
                owner_id: policy.external_owner_id.clone(),
            });
        }
        ImprovementPulseOutcome::Unknown | ImprovementPulseOutcome::Missing => {
            return Ok(ImprovementAdmissionDecision::NeedsMoreEvidence {
                missing: "missing-product-pulse: package-green is not pulse".to_string(),
                owner_id: evidence.verifier_id.clone(),
            });
        }
        ImprovementPulseOutcome::Pass => {
            if evidence
                .pulse_ref
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Ok(ImprovementAdmissionDecision::NeedsMoreEvidence {
                    missing: "missing-product-pulse: pulse evidence ref required".to_string(),
                    owner_id: evidence.verifier_id.clone(),
                });
            }
        }
    }
    if (policy.require_independent_verifier && !evidence.independent) || !evidence.verifier_passed {
        return Ok(ImprovementAdmissionDecision::NeedsMoreEvidence {
            missing: "independent-evaluation-required: self-report cannot admit".to_string(),
            owner_id: evidence.verifier_id.clone(),
        });
    }
    if let Some((cause, reason)) = rollback_gap(evidence, policy) {
        return Ok(ImprovementAdmissionDecision::Blocked {
            cause,
            reason,
            owner_id: policy.rollback_owner_id.clone(),
        });
    }
    let admitted_scope_ref = match require_admitted_scope(candidate, &policy.external_owner_id) {
        Ok(scope) => scope,
        Err(decision) => return Ok(decision),
    };
    // Integrity, not a progress claim. The assessment is derived here from the
    // record this run committed and the retained record the admission evidence
    // carries, so a caller can neither manufacture progress nor suppress a
    // repeat by omitting a field or spelling a boolean. It is evaluated after
    // the unknown-outcome branch above, which no prior record, no new
    // discriminator, and no named rollback contract may clear.
    let assessment =
        assess_improvement_progress(evidence.retained_prior_proposal.as_ref(), current);
    if let Some(outcome) = replay_forced_outcome(&assessment, &policy.external_owner_id) {
        return outcome;
    }
    Ok(ImprovementAdmissionDecision::AdmitForExperiment {
        candidate_id: candidate.candidate_id.clone(),
        campaign_id: candidate.campaign_id.clone(),
        experiment_scope_ref: admitted_scope_ref.to_string(),
        evaluator_id: evidence.verifier_id.clone(),
        rollback_owner_id: policy.rollback_owner_id.clone(),
    })
}

/// Returns the owner-proved admitted scope, or the block the gap produces.
///
/// The `Err` case is a disposition, not a failure: an absent binding stays a
/// named gap with its typed cause and is never replaced by a default scope.
fn require_admitted_scope<'a>(
    candidate: &'a ImprovementCandidateView,
    owner_id: &str,
) -> Result<&'a str, ImprovementAdmissionDecision> {
    match candidate
        .admitted_scope_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(scope) => Ok(scope),
        None => Err(ImprovementAdmissionDecision::Blocked {
            cause: ImprovementBlockCause::MissingAdmittedScope,
            reason: "missing-admitted-scope: owner-proved work scope required before experiment"
                .to_string(),
            owner_id: owner_id.to_owned(),
        }),
    }
}

/// Maps one derived replay assessment to the admission outcome it forces.
///
/// `None` means the assessment establishes a new causal discriminator, so the
/// candidate is released as an ordinary new candidate. That is the only case
/// that proceeds, and it is never described as an improvement: it required both
/// a changed discriminator projection and owner-issued evidence the retained
/// record did not declare.
///
/// Every other case stops the transition. An exact replay, an absent retained
/// record, and an unchanged discriminator are all no progress; a changed content
/// under one operation and idempotency key is a typed identity conflict that
/// performs no transition (I5.27); and a retained record written under another
/// domain, encoding revision, or algorithm is unestablished and must be
/// reconciled rather than matched.
fn replay_forced_outcome(
    assessment: &ImprovementReplayAssessment,
    owner_id: &str,
) -> Option<Result<ImprovementAdmissionDecision, ImprovementAdmissionError>> {
    match assessment {
        ImprovementReplayAssessment::ExactReplay { commitment } => {
            Some(Ok(no_progress(exact_replay_reason(commitment), owner_id)))
        }
        ImprovementReplayAssessment::IdentityConflict {
            operation_ref,
            idempotency_key,
        } => Some(Err(identity_conflict_error(operation_ref, idempotency_key))),
        ImprovementReplayAssessment::UnestablishedPrior {
            cause,
            prior_domain,
            prior_encoding_version,
            prior_algorithm,
        } => Some(Ok(requires_reconciliation(
            unestablished_reason(cause, prior_domain, prior_encoding_version, prior_algorithm),
            owner_id,
        ))),
        ImprovementReplayAssessment::NoRetainedPrior { commitment } => Some(Ok(no_progress(
            no_retained_record_reason(commitment),
            owner_id,
        ))),
        ImprovementReplayAssessment::NoProgressEstablished { commitment } => Some(Ok(no_progress(
            unchanged_discriminator_reason(commitment),
            owner_id,
        ))),
        ImprovementReplayAssessment::EstablishedNewDiscriminator {
            new_evidence_refs, ..
        } => {
            // Only an established new discriminator proceeds, and it is an
            // ordinary new candidate rather than a progress claim. An empty
            // reference set is no evidence, and no evidence is no progress.
            if new_evidence_refs.is_empty() {
                Some(Ok(no_progress(
                    "no-new-owner-evidence: an established discriminator with no owner-issued evidence reference establishes no progress"
                        .to_string(),
                    owner_id,
                )))
            } else {
                None
            }
        }
    }
}

/// Names the exact current commitment an exact replay reproduces.
fn exact_replay_reason(commitment: &ProposalCommitment) -> String {
    format!(
        "exact-replay-of-retained-commitment: current {}/{} digest {} repeats the retained prior commitment under operation {}; an identical repeat is not improvement",
        commitment.algorithm,
        commitment.encoding_version,
        commitment.digest,
        commitment.operation_ref
    )
}

/// Names the current commitment and the retained operation that conflict.
fn identity_conflict_error(
    operation_ref: &str,
    idempotency_key: &str,
) -> ImprovementAdmissionError {
    ImprovementAdmissionError::IdentityMismatch {
        detail: format!(
            "proposal-commitment: operation {operation_ref} and idempotency key {idempotency_key} carry different current canonical content; an identity conflict performs no transition"
        ),
    }
}

/// Names the typed cause and the identity a retained record was written under.
fn unestablished_reason(
    cause: UnestablishedPriorCause,
    prior_domain: &str,
    prior_encoding_version: &str,
    prior_algorithm: &str,
) -> String {
    format!(
        "unestablished-prior-commitment: {} retained {prior_domain}/{prior_encoding_version}/{prior_algorithm} record is not a current-version value; its owner reconciles it before retry",
        cause.label()
    )
}

/// Names the current commitment that carries no retained record at all.
fn no_retained_record_reason(commitment: &ProposalCommitment) -> String {
    format!(
        "no-retained-prior-commitment: current {}/{} digest {} carries no retained record under operation {}; an unestablished comparison is not novelty and establishes no progress",
        commitment.algorithm,
        commitment.encoding_version,
        commitment.digest,
        commitment.operation_ref
    )
}

/// Names the current commitment whose discriminator is not new.
fn unchanged_discriminator_reason(commitment: &ProposalCommitment) -> String {
    format!(
        "no-new-causal-discriminator: current {}/{} digest {} is not a new causal discriminator of the retained record under operation {}; a new proposal identity or a different digest is not evidence of improvement",
        commitment.algorithm,
        commitment.encoding_version,
        commitment.digest,
        commitment.operation_ref
    )
}

/// Returns the no-progress decision that keeps the candidate out of experiment.
fn no_progress(reason: String, owner_id: &str) -> ImprovementAdmissionDecision {
    ImprovementAdmissionDecision::NoProgress {
        reason,
        owner_id: owner_id.to_owned(),
    }
}

/// Returns the reconciliation decision for an unestablished retained record.
fn requires_reconciliation(reason: String, owner_id: &str) -> ImprovementAdmissionDecision {
    ImprovementAdmissionDecision::RequiresReconciliation {
        reason,
        owner_id: owner_id.to_owned(),
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ImprovementAdmissionError> {
    if value.trim().is_empty() {
        Err(ImprovementAdmissionError::MissingField(field))
    } else {
        Ok(())
    }
}

fn validate_candidate(
    candidate: &ImprovementCandidateView,
) -> Result<(), ImprovementAdmissionError> {
    text(&candidate.candidate_id, "candidate_id")?;
    text(&candidate.campaign_id, "campaign_id")?;
    text(&candidate.closure_id, "closure_id")?;
    text(&candidate.closure_digest, "closure_digest")?;
    text(&candidate.operation_ref, "operation_ref")?;
    text(&candidate.idempotency_key, "idempotency_key")?;
    if candidate.direct_promotion
        || candidate.active_permit.is_some()
        || candidate.promotion_receipt.is_some()
    {
        return Err(ImprovementAdmissionError::SelfPromotionForbidden);
    }
    if candidate.proof_ceiling != IMPROVEMENT_PROOF_CEILING {
        return Err(ImprovementAdmissionError::WideningRejected {
            detail: format!(
                "proof ceiling {:?} widens beyond {IMPROVEMENT_PROOF_CEILING}",
                candidate.proof_ceiling
            ),
        });
    }
    if candidate.requested_effect != IMPROVEMENT_REQUESTED_EFFECT {
        return Err(ImprovementAdmissionError::WideningRejected {
            detail: format!(
                "requested effect {:?} widens beyond {IMPROVEMENT_REQUESTED_EFFECT}",
                candidate.requested_effect
            ),
        });
    }
    Ok(())
}

fn validate_policy(
    policy: &ImprovementAdmissionPolicy,
    candidate: &ImprovementCandidateView,
) -> Result<(), ImprovementAdmissionError> {
    text(&policy.external_owner_id, "external_owner_id")?;
    text(&policy.rollback_owner_id, "rollback_owner_id")?;
    text(&policy.operation_ref, "operation_ref")?;
    text(&policy.idempotency_key, "idempotency_key")?;
    if policy.operation_ref != candidate.operation_ref {
        return Err(ImprovementAdmissionError::IdentityMismatch {
            detail: "policy operation vs candidate operation: operation-mismatch".to_string(),
        });
    }
    if policy.idempotency_key != candidate.idempotency_key {
        return Err(ImprovementAdmissionError::IdentityMismatch {
            detail: "policy idempotency vs candidate idempotency: idempotency-mismatch".to_string(),
        });
    }
    Ok(())
}

fn validate_evidence(evidence: &ImprovementEvidenceView) -> Result<(), ImprovementAdmissionError> {
    text(&evidence.verifier_id, "verifier_id")?;
    text(&evidence.bound_candidate_id, "bound_candidate_id")?;
    text(&evidence.bound_experiment_id, "bound_experiment_id")?;
    text(&evidence.content_revision_ref, "content_revision_ref")?;
    text(&evidence.run_ref, "run_ref")?;
    text(&evidence.rollback_owner_id, "rollback_owner_id")?;
    Ok(())
}

/// Returns the typed cause and bounded reason of a missing rollback prerequisite.
///
/// The cause is machine state; the reason is explanatory text. Neither is ever
/// derived from the other's wording.
fn rollback_gap(
    evidence: &ImprovementEvidenceView,
    policy: &ImprovementAdmissionPolicy,
) -> Option<(ImprovementBlockCause, String)> {
    if evidence
        .rollback_ref
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Some((
            ImprovementBlockCause::MissingRollback,
            "missing-rollback: rollback contract required before experiment".to_string(),
        ));
    }
    if evidence
        .disable_ref
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Some((
            ImprovementBlockCause::MissingDisable,
            "missing-disable: disable contract required before experiment".to_string(),
        ));
    }
    if evidence
        .reopen_ref
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Some((
            ImprovementBlockCause::MissingReopen,
            "missing-reopen: reopen contract required before experiment".to_string(),
        ));
    }
    if evidence.rollback_owner_id != policy.rollback_owner_id {
        return Some((
            ImprovementBlockCause::RollbackOwnerGap,
            "rollback-owner-gap: evidence owner must match policy rollback owner".to_string(),
        ));
    }
    if evidence
        .expiry_ref
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Some((
            ImprovementBlockCause::MissingExpiry,
            "missing-expiry: expiry must bind the admitted operation".to_string(),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::improvement_pipeline::{
        IMPROVEMENT_DISCRIMINATOR_DOMAIN, IMPROVEMENT_DISCRIMINATOR_ENCODING_VERSION,
        IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN, IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM,
        IMPROVEMENT_PROPOSAL_ENCODING_VERSION, ImprovementDiscriminatorProjection,
    };

    fn candidate() -> ImprovementCandidateView {
        ImprovementCandidateView {
            candidate_id: "cand-1145-a".to_string(),
            campaign_id: "campaign-1145-a".to_string(),
            closure_id: "closure-1145-a".to_string(),
            closure_digest: "digest-closure-1145-a".to_string(),
            promotion_input_id: Some("promo-cand-1145-a".to_string()),
            promotion_digest: Some("digest-promo-1145-a".to_string()),
            admitted_scope_ref: Some("scope-1145-a".to_string()),
            proof_ceiling: IMPROVEMENT_PROOF_CEILING.to_string(),
            requested_effect: IMPROVEMENT_REQUESTED_EFFECT.to_string(),
            direct_promotion: false,
            active_permit: None,
            promotion_receipt: None,
            operation_ref: "op-1145-a".to_string(),
            idempotency_key: "idem-1145-a".to_string(),
        }
    }

    fn evidence() -> ImprovementEvidenceView {
        ImprovementEvidenceView {
            verifier_id: "verifier-1145-a".to_string(),
            bound_candidate_id: "cand-1145-a".to_string(),
            bound_experiment_id: "exp-1145-a".to_string(),
            content_revision_ref: "revision-1145-a".to_string(),
            run_ref: "run-1145-a".to_string(),
            independent: true,
            verifier_passed: true,
            pulse: ImprovementPulseOutcome::Pass,
            pulse_ref: Some("pulse-evidence-1145-a".to_string()),
            harm_observed: false,
            outcome_unknown: false,
            closure_valid: true,
            closure_stale: false,
            rollback_ref: Some("rollback-1145-a".to_string()),
            disable_ref: Some("disable-1145-a".to_string()),
            reopen_ref: Some("reopen-1145-a".to_string()),
            rollback_owner_id: "rollback-1145".to_string(),
            expiry_ref: Some("op-1145-a".to_string()),
            retained_prior_proposal: None,
        }
    }

    fn policy() -> ImprovementAdmissionPolicy {
        ImprovementAdmissionPolicy {
            external_owner_id: "governor-1145".to_string(),
            rollback_owner_id: "rollback-1145".to_string(),
            operation_ref: "op-1145-a".to_string(),
            idempotency_key: "idem-1145-a".to_string(),
            require_independent_verifier: true,
        }
    }

    // `None` is the canonical "no retained prior record" input, so the fixtures
    // below still describe a candidate that never reached a prior record. The
    // replay test below supplies real records.
    fn decide(
        candidate: &ImprovementCandidateView,
        evidence: &ImprovementEvidenceView,
        policy: &ImprovementAdmissionPolicy,
    ) -> ImprovementAdmissionDecision {
        match admit_improvement_candidate(candidate, evidence, policy, &current()) {
            Ok(decision) => decision,
            Err(err) => panic!("admission must decide, got error {err:?}"),
        }
    }

    fn decide_err(
        candidate: &ImprovementCandidateView,
        evidence: &ImprovementEvidenceView,
        policy: &ImprovementAdmissionPolicy,
    ) -> ImprovementAdmissionError {
        match admit_improvement_candidate(candidate, evidence, policy, &current()) {
            Err(err) => err,
            Ok(decision) => panic!("admission must fail, got decision {decision:?}"),
        }
    }

    #[test]
    fn admits_complete_candidate_for_bounded_experiment_only() {
        let decision = decide(&candidate(), &evidence(), &policy());
        match decision {
            ImprovementAdmissionDecision::AdmitForExperiment {
                candidate_id,
                campaign_id,
                evaluator_id,
                rollback_owner_id,
                ..
            } => {
                assert_eq!(candidate_id, "cand-1145-a");
                assert_eq!(campaign_id, "campaign-1145-a");
                assert_eq!(evaluator_id, "verifier-1145-a");
                assert_eq!(rollback_owner_id, "rollback-1145");
            }
            other => panic!("complete candidate must admit for experiment, got {other:?}"),
        }
    }

    #[test]
    fn harm_rejects_and_is_never_compensated() {
        let mut ev = evidence();
        ev.harm_observed = true;
        match decide(&candidate(), &ev, &policy()) {
            ImprovementAdmissionDecision::Reject { reason, .. } => {
                assert!(reason.contains("harm"));
            }
            other => panic!("harm must reject, got {other:?}"),
        }
    }

    #[test]
    fn pulse_regression_rejects_and_missing_pulse_needs_evidence() {
        let mut regressed = evidence();
        regressed.pulse = ImprovementPulseOutcome::Regression;
        match decide(&candidate(), &regressed, &policy()) {
            ImprovementAdmissionDecision::Reject { reason, .. } => {
                assert!(reason.contains("pulse-regression"));
            }
            other => panic!("regression must reject, got {other:?}"),
        }

        let mut missing = evidence();
        missing.pulse = ImprovementPulseOutcome::Missing;
        match decide(&candidate(), &missing, &policy()) {
            ImprovementAdmissionDecision::NeedsMoreEvidence { missing, .. } => {
                assert!(missing.contains("missing-product-pulse"));
            }
            other => panic!("missing pulse must need evidence, got {other:?}"),
        }
    }

    #[test]
    fn self_report_cannot_admit() {
        let mut dependent = evidence();
        dependent.independent = false;
        match decide(&candidate(), &dependent, &policy()) {
            ImprovementAdmissionDecision::NeedsMoreEvidence { missing, .. } => {
                assert!(missing.contains("independent"));
            }
            other => panic!("self-report must need evidence, got {other:?}"),
        }

        let mut failed = evidence();
        failed.verifier_passed = false;
        match decide(&candidate(), &failed, &policy()) {
            ImprovementAdmissionDecision::NeedsMoreEvidence { .. } => {}
            other => panic!("failed verifier must need evidence, got {other:?}"),
        }
    }

    #[test]
    fn rollback_gaps_block_before_experiment() {
        let mut ev = evidence();
        ev.rollback_ref = None;
        match decide(&candidate(), &ev, &policy()) {
            ImprovementAdmissionDecision::Blocked { reason, .. } => {
                assert!(reason.contains("missing-rollback"));
            }
            other => panic!("rollback gap must block, got {other:?}"),
        }
    }

    #[test]
    fn unknown_outcome_requires_reconciliation_before_retry() {
        let mut ev = evidence();
        ev.outcome_unknown = true;
        match decide(&candidate(), &ev, &policy()) {
            ImprovementAdmissionDecision::RequiresReconciliation { reason, .. } => {
                assert!(reason.contains("reconcile"));
            }
            other => panic!("unknown must reconcile, got {other:?}"),
        }
    }

    /// One retained prior commitment fixture, shaped by the current identity
    /// constants so it can never be mistaken for a legacy value.
    fn prior_commitment(digest: &str, operation_ref: &str) -> ProposalCommitment {
        ProposalCommitment {
            domain: IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN.to_string(),
            encoding_version: IMPROVEMENT_PROPOSAL_ENCODING_VERSION.to_string(),
            algorithm: IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM.to_string(),
            operation_ref: operation_ref.to_string(),
            idempotency_key: "idem-1145-a".to_string(),
            digest: digest.to_string(),
            canonical_bytes: 512,
        }
    }

    /// Discriminator projection of one fixture proposal content.
    fn projection(hypothesis: &str, evidence_ref: &str) -> ImprovementDiscriminatorProjection {
        ImprovementDiscriminatorProjection {
            domain: IMPROVEMENT_DISCRIMINATOR_DOMAIN.to_string(),
            encoding_version: IMPROVEMENT_DISCRIMINATOR_ENCODING_VERSION.to_string(),
            source_identity: "source-1145-a".to_string(),
            runtime_identity: "runtime-1145-a".to_string(),
            data_identity: "data-1145-a".to_string(),
            target_capability: "capability-1145-a".to_string(),
            target_generation: "generation-1145-a".to_string(),
            mechanism_id: "mechanism-1145-a".to_string(),
            hypothesis: hypothesis.to_string(),
            causal_link: "causal-link-1145-a".to_string(),
            expected_delta: "expected-delta-1145-a".to_string(),
            declared_evidence_refs: vec![evidence_ref.to_string()],
        }
    }

    /// The one current checked record the gate is given: a single commitment
    /// plus the discriminator projection of the same content.
    fn current() -> ImprovementCurrentProposal {
        ImprovementCurrentProposal {
            commitment: prior_commitment("commitment-1145-a", "op-1145-a"),
            discriminator: projection("hypothesis-1145-a", "evidence-1145-a"),
        }
    }

    #[test]
    fn exact_canonical_repeat_is_no_progress() {
        // Byte-identical canonical proposal: the retained prior and the current
        // commitment agree under one logical operation, which is an exact
        // replay and never progress.
        let current = current();
        let mut ev = evidence();
        ev.retained_prior_proposal = Some(RetainedImprovementProposal {
            commitment: current.commitment.clone(),
            discriminator: current.discriminator.clone(),
        });
        match admit_improvement_candidate(&candidate(), &ev, &policy(), &current) {
            Ok(ImprovementAdmissionDecision::NoProgress { reason, .. }) => {
                assert!(reason.contains("repeat"));
            }
            other => panic!("exact replay must dispose as no-progress, got {other:?}"),
        }

        // A different logical operation is an ordinary new candidate. It is
        // admitted on its own evidence and is never described as progress. The
        // retained record below is a different proposal: it declares its own
        // discriminator and its own evidence reference, so the current
        // candidate's evidence is new relative to it.
        let mut fresh = evidence();
        fresh.retained_prior_proposal = Some(RetainedImprovementProposal {
            commitment: prior_commitment("commitment-1144-z", "op-1144-z"),
            discriminator: projection("hypothesis-1144-z", "evidence-1144-z"),
        });
        assert!(matches!(
            admit_improvement_candidate(&candidate(), &fresh, &policy(), &current),
            Ok(ImprovementAdmissionDecision::AdmitForExperiment { .. })
        ));
    }

    #[test]
    fn self_promotion_and_widening_never_decide() {
        let mut promoted = candidate();
        promoted.direct_promotion = true;
        assert_eq!(
            decide_err(&promoted, &evidence(), &policy()),
            ImprovementAdmissionError::SelfPromotionForbidden
        );

        let mut permitted = candidate();
        permitted.active_permit = Some("permit-1145".to_string());
        assert_eq!(
            decide_err(&permitted, &evidence(), &policy()),
            ImprovementAdmissionError::SelfPromotionForbidden
        );

        let mut widened = candidate();
        widened.proof_ceiling = "product-promotion".to_string();
        assert!(matches!(
            decide_err(&widened, &evidence(), &policy()),
            ImprovementAdmissionError::WideningRejected { .. }
        ));
    }

    #[test]
    fn operation_mismatch_conflicts_and_replay_is_stable() {
        let mut other = policy();
        other.operation_ref = "op-foreign-1145".to_string();
        assert!(matches!(
            decide_err(&candidate(), &evidence(), &other),
            ImprovementAdmissionError::IdentityMismatch { .. }
        ));

        let first = decide(&candidate(), &evidence(), &policy());
        let second = decide(&candidate(), &evidence(), &policy());
        assert_eq!(first, second);
    }

    #[test]
    fn contract_identities_bind_the_proved_cells() {
        assert_eq!(IMPROVEMENT_CLOSURE_MODULE, "meta.learning.closure");
        assert_eq!(
            IMPROVEMENT_PROMOTION_MODULE,
            "meta.improvement.promotion_input"
        );
        assert_eq!(
            IMPROVEMENT_PRODUCT_PULSE,
            "ONLINE_LEARNING_INNER_LOOP_PULSE_01"
        );
        assert_eq!(IMPROVEMENT_PROOF_CEILING, "module-proof-only");
        assert_eq!(IMPROVEMENT_REQUESTED_EFFECT, "advisory-only");
    }
}
