//! Governor-owned improvement candidate to experiment to evaluation to admission pipeline.
//!
//! Experiment execution is owned by Testd (`#20`), independent evaluation by the
//! Instrument verifier family (`#20`/`#1111`), admission by Governor maintenance
//! `G-19` (`#18`), and generation/canary activation by the Kernel
//! generation/canary path (`#11`, handoff only, never executed here).
//!
//! This module is advisory-only: it never edits source, configuration, or
//! policy, never installs artifacts, never activates a generation, never issues
//! authority, and never emits `VERIFIED_COMPLETE`. A successful run ends at an
//! inspectable, non-authorizing canary handoff that the Kernel owner must
//! independently authorize and execute.
//!
//! # One joined input, one meaning, one commitment
//!
//! `run_improvement_candidate_pipeline` builds one private checked view over the
//! seven borrowed inputs and the result mapper consumes that view instead of
//! unchecked arguments, so two individually valid identity groups can never be
//! mixed into a single handoff. The checked view has no public constructor and
//! cannot be bypassed.
//!
//! The admission decision is mapped to its own meaning: a blocked candidate
//! stays blocked with its typed cause, owner, and required remedy, a regression
//! subtype needs typed pulse evidence, and this admission-only entry point
//! never constructs an observed completed rollback. No result variant
//! establishes execution, independence, or canary permission.
//!
//! The proposal commitment is a versioned, domain-separated SHA-256 over one
//! canonical JSON envelope holding the complete normalized proposal. The
//! pipeline computes exactly one commitment and carries it into the handoff.
//!
//! # Wire revision
//!
//! [`IMPROVEMENT_PIPELINE_WIRE_REVISION`] is `2`. Revision `2` adds typed
//! `cause`/`remedy` fields to the rejection and block branches, adds the
//! `Blocked` disposition and the inspectable canary handoff, binds
//! candidate/experiment/content-revision/run identities onto the admission
//! evidence view, the bounded experiment plan, and the activation evidence, and
//! replaces the free-form proposal digest string with [`ProposalCommitment`].
//! Deserialization is fail-closed: bytes written at revision `1` no longer
//! decode, so a stale disposition cannot be read as a current one. Historical
//! revision-`1` FNV-1a 64-bit digests stay explicitly
//! [`IMPROVEMENT_LEGACY_DIGEST_ALGORITHM`] observations; they are never padded,
//! reinterpreted as SHA-256, or matched against a current proposal.

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::improvement_admission::{
    ImprovementAdmissionDecision, ImprovementAdmissionPolicy, ImprovementBlockCause,
    ImprovementBlockRemedy, ImprovementCandidateView, ImprovementEvidenceView,
    ImprovementRejectCause, admit_improvement_candidate,
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
/// The only risk-ceiling value this pipeline admits, exactly.
///
/// `unbounded`, any qualified form such as `bounded-until-ok`, and every other
/// value are refused. The old substring marker is gone: `unbounded` used to
/// satisfy it.
pub const IMPROVEMENT_RISK_CEILING_BOUNDED: &str = "bounded";
/// Version of the supported risk-ceiling value set admitted at this revision.
pub const IMPROVEMENT_RISK_CEILING_ENCODING_VERSION: &str = "1";
/// Fixed domain separator of the improvement proposal commitment.
pub const IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN: &str = "eliot.improvement.proposal.commitment";
/// Canonical encoding revision of the proposal commitment preimage.
pub const IMPROVEMENT_PROPOSAL_ENCODING_VERSION: &str = "1";
/// Hash algorithm carried with every current proposal commitment.
pub const IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM: &str = "sha256";
/// Identity of the retired FNV-1a 64-bit proposal digest.
///
/// Values produced under this identity are historical observations only. They
/// are not padded, not reinterpreted as SHA-256, and never matched against a
/// current proposal.
pub const IMPROVEMENT_LEGACY_DIGEST_ALGORITHM: &str = "fnv1a-64-legacy";
/// Wire revision of the improvement pipeline result and identity contracts.
pub const IMPROVEMENT_PIPELINE_WIRE_REVISION: u32 = 2;
/// Maximum members in one declared set of the committed proposal.
///
/// Matches the nearest existing declared-set ceiling in the repository
/// (`eliot_observation_contracts::MAX_OBSERVATION_REFS`).
pub const IMPROVEMENT_MAX_SET_MEMBERS: usize = 256;
/// Maximum byte length of one committed identity or reference field.
///
/// Matches the nearest existing revision/reference ceiling in the repository
/// (`eliot_observation_contracts::MAX_SOURCE_REVISION_CHARS`).
pub const IMPROVEMENT_MAX_REFERENCE_BYTES: usize = 256;
/// Maximum byte length of one committed prose field.
///
/// Matches the nearest existing bounded-text ceiling in the repository
/// (`eliot_observation_contracts::MAX_OBSERVATION_TEXT`).
pub const IMPROVEMENT_MAX_TEXT_BYTES: usize = 1_024;
/// Maximum byte length of the total committed proposal content.
///
/// Matches the nearest existing bounded-payload ceiling in the repository
/// (`eliot_bootstrap::normative::MAX_RECEIPT_BYTES`). The improvement route
/// had no transport ceiling of its own, so this value is recorded as a
/// derived ceiling rather than an unlimited default.
pub const IMPROVEMENT_MAX_COMMITMENT_BYTES: usize = 16 * 1024;
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

/// One resource dimension and the ceiling the admitting owner proved for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedResourceCeiling {
    /// Resource dimension this ceiling applies to.
    pub dimension: String,
    /// Owner-issued ceiling reference for that dimension.
    pub ceiling_ref: String,
}

/// Explicit owner-backed evidence that a bounded experiment narrows the
/// admitted contract instead of replacing it.
///
/// Reference strings are never ordered lexically and a nonblank replacement is
/// never accepted on its own. A different scope, budget, or deadline reference
/// is admitted only when this record re-establishes the exact admitted
/// references, names the narrowed references the plan actually uses, carries the
/// owner's evidence reference, and states each narrowing relation explicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedScopeRefinement {
    /// Admitted scope this record narrows.
    pub admitted_scope_ref: String,
    /// Admitted budget this record narrows.
    pub admitted_budget_ref: String,
    /// Admitted deadline this record narrows.
    pub admitted_deadline_ref: String,
    /// Narrowed scope the plan may use.
    pub refined_scope_ref: String,
    /// Narrowed budget the plan may use.
    pub refined_budget_ref: String,
    /// Narrowed deadline the plan may use.
    pub refined_deadline_ref: String,
    /// Each resource dimension the owner proved inside its ceiling.
    pub resource_ceilings: Vec<AdmittedResourceCeiling>,
    /// Owner that issued this refinement evidence.
    pub refinement_owner_id: String,
    /// Refinement evidence reference produced by that owner.
    pub refinement_ref: String,
    /// Owner states the refined scope stays inside the admitted set.
    pub scope_within_admitted: bool,
    /// Owner states every resource dimension stays within its ceiling.
    pub budget_within_ceiling: bool,
    /// Owner states the time window cannot widen.
    pub deadline_not_widened: bool,
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
    /// Owner-backed narrowing evidence, required only when the scope, budget, or
    /// deadline reference differs from the admitted one.
    pub scope_refinement: Option<AdmittedScopeRefinement>,
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
    /// Exact run the verifier evaluated.
    pub run_ref: String,
    /// Exact content revision the verifier evaluated.
    pub content_revision_ref: String,
    /// Must always be false; simulated runs never admit.
    pub simulated: bool,
    /// Candidate this evidence is bound to.
    pub bound_candidate_id: String,
    /// Experiment this evidence is bound to.
    pub bound_experiment_id: String,
}

/// Rollback contract named before any experiment is admitted.
///
/// Naming a rollback, disable, reopen, expiry, or forward-repair contract proves
/// that a repair path exists. It never proves that a rollback was requested,
/// partially applied, or completed.
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
    /// Stable proposal identity. Kept separate from `candidate_id`: a proposal
    /// identity is not necessarily the candidate identity.
    pub proposal_id: String,
    /// Improvement candidate identity.
    pub candidate_id: String,
    /// Campaign the candidate learns from.
    pub campaign_id: String,
    /// Closure candidate identity.
    pub closure_id: String,
    /// Closure evidence digest (opaque).
    pub closure_digest: String,
    /// Opaque evidence references supporting the proposal. Declared set: order
    /// is normalized, duplicates are refused.
    pub evidence_refs: Vec<String>,
    /// Capability the experiment targets.
    pub target_capability: String,
    /// Generation the experiment targets (observation only, never activated here).
    pub target_generation: String,
    /// Causal mechanism declared before results.
    pub mechanism: MechanismDeclaration,
    /// Expected advisory-only delta.
    pub expected_delta: String,
    /// Risk ceiling; must be exactly [`IMPROVEMENT_RISK_CEILING_BOUNDED`].
    pub risk_ceiling: String,
    /// Effect ceiling; must stay advisory-only.
    pub effect_ceiling: String,
    /// Budget the experiment must not exceed.
    pub budget_ref: String,
    /// Deadline the experiment must not exceed.
    pub deadline_ref: String,
    /// Privacy class of the proposal inputs.
    pub privacy_class: String,
    /// Invalidation set covered by the rollback contract. Declared set: order is
    /// normalized, duplicates are refused.
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
    /// promotion or completion claims, and every risk ceiling other than the
    /// exact supported versioned value. Returns a [`PipelineError`] describing
    /// the first violation found.
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
        check_commitment_profile(self)?;
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
        if self.risk_ceiling != IMPROVEMENT_RISK_CEILING_BOUNDED {
            return Err(PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            });
        }
        Ok(())
    }
}

/// Canonical preimage of one improvement proposal commitment.
///
/// The envelope carries a fixed domain, an encoding revision, the hash
/// algorithm identity, and the complete normalized proposal. The commitment
/// itself is never part of this preimage, no `Debug` text is hashed, and no
/// manually concatenated delimiter is used.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementProposalCommitmentEnvelope {
    /// Fixed proposal domain separator.
    pub domain: String,
    /// Canonical encoding revision of the committed bytes.
    pub encoding_version: String,
    /// Hash algorithm applied to the canonical bytes.
    pub algorithm: String,
    /// Complete normalized proposal content.
    pub proposal: ImprovementProposal,
}

/// Versioned, domain-separated content commitment to one complete proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalCommitment {
    /// Fixed proposal domain separator.
    pub domain: String,
    /// Canonical encoding revision of the committed preimage.
    pub encoding_version: String,
    /// Hash algorithm identity.
    pub algorithm: String,
    /// Logical operation the committed bytes belong to.
    pub operation_ref: String,
    /// Idempotency namespace the committed bytes belong to.
    pub idempotency_key: String,
    /// Lowercase digest over the canonical preimage bytes.
    pub digest: String,
    /// Size of the canonical preimage in bytes, for inspection.
    pub canonical_bytes: usize,
}

/// Inspectable, non-authorizing canary handoff for one joined run.
///
/// Every field is an exact identity taken from the checked records. The
/// readable projection is a convenience, never a machine join and never a
/// permit: `execution_authorized` is false in every construction, and
/// `activation_owner_id` names the Kernel owner that must independently
/// authorize and execute activation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementCanaryHandoff {
    /// Proposal identity, kept separate from the candidate identity.
    pub proposal_id: String,
    /// The single commitment computed for the exact proposal bytes.
    pub proposal_commitment: ProposalCommitment,
    /// Candidate identity the handoff is bound to.
    pub candidate_id: String,
    /// Campaign the handoff is bound to.
    pub campaign_id: String,
    /// Closure identity the handoff is bound to.
    pub closure_id: String,
    /// Versioned closure commitment the handoff is bound to.
    pub closure_digest: String,
    /// Capability the handoff targets.
    pub target_capability: String,
    /// Generation the handoff observes; never activated by it.
    pub target_generation: String,
    /// Experiment plan identity.
    pub experiment_id: String,
    /// Logical operation the handoff belongs to.
    pub operation_ref: String,
    /// Idempotency namespace the handoff belongs to.
    pub idempotency_key: String,
    /// Admitted experiment scope the handoff stays inside.
    pub experiment_scope_ref: String,
    /// Budget the handoff stays inside.
    pub budget_ref: String,
    /// Deadline the handoff stays inside.
    pub deadline_ref: String,
    /// Independent evaluation identities.
    pub evidence_id: String,
    /// Competent evaluator the plan declared and the evidence names.
    pub evidence_verifier_id: String,
    /// Run the competent evaluator evaluated.
    pub evidence_run_ref: String,
    /// Content revision the competent evaluator evaluated.
    pub evidence_content_revision_ref: String,
    /// Raw measured evidence reference.
    pub raw_evidence_ref: String,
    /// Admission-review evaluator, which may differ from the experiment
    /// evaluator while staying bound to the same candidate and experiment.
    pub admission_evaluator_id: String,
    /// Run the admission review observed.
    pub admission_run_ref: String,
    /// Content revision the admission review observed.
    pub admission_content_revision_ref: String,
    /// Pulse evidence the admission review relied on.
    pub admission_pulse_ref: String,
    /// Governor admission owner that decided.
    pub admission_owner_id: String,
    /// Rollback and repair bindings the handoff stays inside.
    pub rollback_ref: String,
    /// Disable contract reference.
    pub disable_ref: String,
    /// Reopen contract reference.
    pub reopen_ref: String,
    /// Expiry reference.
    pub expiry_ref: String,
    /// Forward-repair reference for incomplete rollback effects.
    pub forward_repair_ref: String,
    /// Rollback owner that must stay named for the run.
    pub rollback_owner_id: String,
    /// Invalidation targets the handoff may invalidate. This is the proposal's
    /// admitted set, never the rollback's wider coverage.
    pub invalidation_set: Vec<String>,
    /// Kernel owner that must independently authorize activation.
    pub activation_owner_id: String,
    /// Readable projection of the handoff; never a permit.
    pub handoff_projection: String,
    /// Always false. No shape, digest, or match authorizes execution.
    pub execution_authorized: bool,
}

/// Terminal disposition for one improvement candidate pipeline run.
///
/// Advisory-only: no variant performs promotion, activation, canary cutover, or
/// completion. `CanaryAdmitted` carries only an inspectable, non-authorizing
/// handoff for the Kernel owner, never a permit. The name of this enum does not
/// make every advisory decision a terminal lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ImprovementTerminalDisposition {
    /// Candidate is rejected with a typed cause, owner, and stable reason.
    Rejected {
        /// Owner-defined rejection cause.
        cause: ImprovementRejectCause,
        /// Stable rejection reason naming exact evidence.
        reason: String,
        /// Owner holding the rejected scope.
        owner_id: String,
    },
    /// Candidate is well-formed but evidence is incomplete.
    Inconclusive {
        /// Exact missing evidence.
        missing: String,
        /// Owner that must supply it.
        owner_id: String,
    },
    /// Candidate regressed the measured outcome and is rejected. Reached only
    /// from typed pulse regression evidence.
    RegressionRejected {
        /// Owner-defined rejection cause.
        cause: ImprovementRejectCause,
        /// Stable regression reason naming exact evidence.
        reason: String,
        /// Owner holding the rejected scope.
        owner_id: String,
    },
    /// External outcome is unknown; reconciliation is required before retry.
    UnknownRequiresReconciliation {
        /// What must be reconciled before any retry.
        reason: String,
        /// Owner holding the reconciliation debt.
        owner_id: String,
    },
    /// Retained historical representation of an observed completed rollback.
    ///
    /// The admission-only pipeline in this module never constructs this
    /// variant: it receives a rollback contract, never a rollback execution or
    /// result receipt, and no existing owner path supplies a validated
    /// completed-rollback result. Bytes written under this variant stay
    /// readable so history is preserved, but they are an unqualified historical
    /// observation and must not be presented as newly verified completed
    /// effects.
    RolledBack {
        /// Rollback contract reference owning the repair.
        contract_ref: String,
    },
    /// Materially identical repeat without a new discriminator.
    NoProgress {
        /// Prior digest this repeats, with exact debt retained.
        reason: String,
        /// Owner holding the repeat-review debt.
        owner_id: String,
    },
    /// Candidate is blocked on a named prerequisite or revalidation. It is
    /// neither a rejection nor an observed completed rollback.
    Blocked {
        /// Owner-defined block cause.
        cause: ImprovementBlockCause,
        /// Remedy the responsible owner must complete.
        remedy: ImprovementBlockRemedy,
        /// Stable block reason naming exact evidence.
        reason: String,
        /// Owner that must clear the block.
        owner_id: String,
    },
    /// Candidate is admitted for one bounded, non-authorizing canary handoff.
    CanaryAdmitted {
        /// Inspectable handoff the Kernel owner must authorize independently.
        /// Boxed so the disposition stays small enough to carry alongside the
        /// other branches.
        handoff: Box<ImprovementCanaryHandoff>,
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
    /// One required cross-input relation is not bound.
    ///
    /// `relation` names the diverging relation. It never copies proposal text.
    #[error("improvement input relation is not bound: {relation}")]
    UnboundRelation {
        /// Static identity of the diverging relation.
        relation: &'static str,
    },
    /// The rollback contract leaves a gap before experiment.
    #[error("improvement rollback contract gap: {detail}")]
    RollbackContractGap {
        /// What is missing.
        detail: String,
    },
    /// The declared risk ceiling is not the admitted bounded value.
    #[error(
        "improvement risk ceiling is not the admitted bounded value at encoding version {encoding_version}"
    )]
    UnsupportedRiskCeiling {
        /// Version of the supported risk-ceiling value set.
        encoding_version: &'static str,
    },
    /// A declared-set field repeats one identity the contract requires to be a set.
    #[error("improvement declared set contains a duplicate: {0}")]
    DuplicateSetMember(&'static str),
    /// The admitted input profile exceeds an owner or transport ceiling.
    #[error("improvement input profile exceeds its ceiling: {0}")]
    InputProfileCeiling(&'static str),
    /// The versioned proposal commitment could not be produced.
    #[error("improvement proposal commitment failed: {0}")]
    CommitmentFailed(&'static str),
    /// Governor admission refused or failed with the inner reason.
    #[error("improvement admission failed: {0}")]
    AdmissionFailed(String),
}

/// Returns the versioned content commitment for one complete proposal.
///
/// Computes a domain-separated, versioned SHA-256 over the canonical JSON
/// envelope holding the complete normalized proposal. Only the declared sets
/// are normalized: they get deterministic byte ordering and an explicit
/// duplicate rejection. Reference bytes, Unicode, punctuation, and ordered
/// prose are committed unchanged. The admitted input, count, string, and
/// total-size profile is validated before any clone, sort, or serialization,
/// and a serialization failure is propagated as a typed error rather than a
/// fallback or legacy hash.
pub fn proposal_digest(
    proposal: &ImprovementProposal,
) -> Result<ProposalCommitment, PipelineError> {
    commitment_of(&canonical_proposal(proposal)?)
}

/// Exact-repeat and identity-conflict assessment for one proposal.
///
/// Integrity and semantic progress stay separate. An exact replay reproduces
/// the complete current commitment under its original logical operation. The
/// same operation and idempotency key with different content is an identity
/// conflict, not the old request and not an automatic retry. A retained
/// commitment written under another domain, encoding revision, or algorithm — a
/// legacy FNV-1a value, for example — stays an unqualified historical
/// observation until its owner reconciles it. A different logical operation is
/// not progress evidence either: a new proposal identity or a different digest
/// establishes nothing.
pub fn assess_improvement_replay(
    prior: &ProposalCommitment,
    proposal: &ImprovementProposal,
) -> Result<ImprovementReplayAssessment, PipelineError> {
    let current = proposal_digest(proposal)?;
    if prior.operation_ref != current.operation_ref
        || prior.idempotency_key != current.idempotency_key
    {
        return Ok(ImprovementReplayAssessment::NoProgressEstablished {
            commitment: current,
        });
    }
    if prior.domain != current.domain
        || prior.encoding_version != current.encoding_version
        || prior.algorithm != current.algorithm
    {
        return Ok(ImprovementReplayAssessment::UnestablishedPrior {
            prior_domain: prior.domain.clone(),
            prior_encoding_version: prior.encoding_version.clone(),
            prior_algorithm: prior.algorithm.clone(),
        });
    }
    if prior.digest == current.digest {
        return Ok(ImprovementReplayAssessment::ExactReplay {
            commitment: current,
        });
    }
    Ok(ImprovementReplayAssessment::IdentityConflict {
        operation_ref: current.operation_ref,
        idempotency_key: current.idempotency_key,
    })
}

/// Outcome of comparing one current commitment with a retained prior one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum ImprovementReplayAssessment {
    /// The current bytes reproduce the retained commitment under the same
    /// logical operation. An exact replay is not progress.
    ExactReplay {
        /// The current commitment.
        commitment: ProposalCommitment,
    },
    /// The same operation and idempotency key carry different content. This is
    /// an identity conflict, not the old request and not an automatic retry.
    IdentityConflict {
        /// Conflicting logical operation.
        operation_ref: String,
        /// Conflicting idempotency namespace.
        idempotency_key: String,
    },
    /// The retained commitment is not a current-version commitment. It stays an
    /// unqualified historical observation and requires reconciliation or
    /// revalidation by its owner.
    UnestablishedPrior {
        /// Domain the retained value was written under.
        prior_domain: String,
        /// Encoding revision the retained value was written under.
        prior_encoding_version: String,
        /// Algorithm the retained value was written under.
        prior_algorithm: String,
    },
    /// A different logical operation. No progress is established here, and no
    /// external effect is cleared.
    NoProgressEstablished {
        /// The current commitment.
        commitment: ProposalCommitment,
    },
}

/// Reconciles an unknown external activation outcome without retrying blindly.
///
/// Exhaustive and meaning-preserving: an unresolved prior outcome stays
/// `UnknownRequiresReconciliation`, and every other prior decision keeps its own
/// typed cause, owner, and remedy instead of collapsing into an evidence gap. A
/// named rollback contract still never clears an unknown external effect.
pub fn reconcile_unknown_activation(
    prior: &ImprovementAdmissionDecision,
) -> ImprovementTerminalDisposition {
    match prior {
        ImprovementAdmissionDecision::RequiresReconciliation { reason, owner_id } => {
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                reason: reason.clone(),
                owner_id: owner_id.clone(),
            }
        }
        ImprovementAdmissionDecision::Reject {
            cause,
            reason,
            owner_id,
        } => map_rejection(*cause, reason, owner_id),
        ImprovementAdmissionDecision::NeedsMoreEvidence { missing, owner_id } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: missing.clone(),
                owner_id: owner_id.clone(),
            }
        }
        ImprovementAdmissionDecision::Blocked {
            cause,
            reason,
            owner_id,
        } => map_block(*cause, reason, owner_id),
        ImprovementAdmissionDecision::NoProgress { reason, owner_id } => {
            ImprovementTerminalDisposition::NoProgress {
                reason: reason.clone(),
                owner_id: owner_id.clone(),
            }
        }
        ImprovementAdmissionDecision::AdmitForExperiment {
            candidate_id,
            rollback_owner_id,
            ..
        } => ImprovementTerminalDisposition::Inconclusive {
            missing: format!(
                "unknown-activation: prior admission for {candidate_id} reconciles before retry"
            ),
            owner_id: rollback_owner_id.clone(),
        },
    }
}

/// Runs the advisory-only candidate to experiment to evaluation to admission pipeline.
///
/// Pure orchestrator over borrowed inputs: it builds the private checked view
/// over the proposal, experiment, evaluation, rollback, and admission records,
/// refuses a diverged relation before any positive path, requires a gap-free
/// rollback contract, then delegates the admission verdict to
/// `improvement_admission::admit_improvement_candidate` and maps that verdict
/// through the same checked view. Never performs promotion, activation, canary
/// cutover, authority issuance, or completion, and never reports an observed
/// completed rollback.
pub fn run_improvement_candidate_pipeline(
    inputs: ImprovementPipelineInputs<'_>,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    let joined = join_improvement_inputs(inputs)?;
    let decision =
        admit_improvement_candidate(joined.candidate, joined.admission_evidence, joined.policy)
            .map_err(|err| PipelineError::AdmissionFailed(err.to_string()))?;
    map_decision(&decision, &joined)
}

/// One private checked view over the seven borrowed pipeline inputs.
///
/// The view has no public constructor and no bypass flag: the only way to hold
/// one is to satisfy every relation check below.
struct JoinedImprovementInputs<'a> {
    proposal: &'a ImprovementProposal,
    experiment: &'a ExperimentPlan,
    evidence: &'a ActivationEvidence,
    rollback: &'a RollbackContract,
    candidate: &'a ImprovementCandidateView,
    admission_evidence: &'a ImprovementEvidenceView,
    policy: &'a ImprovementAdmissionPolicy,
    /// The single normalized proposal whose bytes were committed.
    normalized: ImprovementProposal,
    /// The single commitment computed for those bytes.
    commitment: ProposalCommitment,
    /// Admitted scope the candidate owner proved for this candidate.
    admitted_scope_ref: String,
}

/// Joins every input into one checked view or refuses a diverged relation.
fn join_improvement_inputs(
    inputs: ImprovementPipelineInputs<'_>,
) -> Result<JoinedImprovementInputs<'_>, PipelineError> {
    inputs.proposal.validate()?;
    check_operation_identities()?;
    check_experiment_shape(inputs.experiment)?;
    check_evaluation_shape(inputs.evidence)?;
    let normalized = canonical_proposal(inputs.proposal)?;
    let commitment = commitment_of(&normalized)?;
    check_proposal_candidate_join(inputs.proposal, inputs.candidate)?;
    check_proposal_experiment_join(inputs.experiment, inputs.proposal, inputs.candidate)?;
    check_experiment_evaluation_join(inputs.evidence, inputs.proposal, inputs.experiment)?;
    check_admission_evidence_join(
        inputs.admission_evidence,
        inputs.evidence,
        inputs.proposal,
        inputs.experiment,
    )?;
    check_rollback_join(
        inputs.rollback,
        inputs.admission_evidence,
        inputs.policy,
        inputs.proposal,
    )?;
    // A candidate with no owner-proved scope binding carries an empty admitted
    // scope here. That is not a default: the inner admission owns the
    // disposition and reports the named `missing-admitted-scope` gap, and no
    // experiment scope is ever derived from the candidate identity.
    let admitted_scope_ref = admitted_scope(inputs.candidate)
        .unwrap_or_default()
        .to_string();
    Ok(JoinedImprovementInputs {
        proposal: inputs.proposal,
        experiment: inputs.experiment,
        evidence: inputs.evidence,
        rollback: inputs.rollback,
        candidate: inputs.candidate,
        admission_evidence: inputs.admission_evidence,
        policy: inputs.policy,
        normalized,
        commitment,
        admitted_scope_ref,
    })
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

/// Requires every required bounded-plan field to be present and bounded.
fn check_experiment_shape(experiment: &ExperimentPlan) -> Result<(), PipelineError> {
    for (field, value) in [
        (
            "experiment.experiment_id",
            experiment.experiment_id.as_str(),
        ),
        (
            "experiment.testd_owner_id",
            experiment.testd_owner_id.as_str(),
        ),
        ("experiment.evaluator_id", experiment.evaluator_id.as_str()),
        ("experiment.scope_ref", experiment.scope_ref.as_str()),
        ("experiment.budget_ref", experiment.budget_ref.as_str()),
        ("experiment.deadline_ref", experiment.deadline_ref.as_str()),
        (
            "experiment.operation_ref",
            experiment.operation_ref.as_str(),
        ),
        (
            "experiment.idempotency_key",
            experiment.idempotency_key.as_str(),
        ),
    ] {
        bounded_text(value, field, IMPROVEMENT_MAX_REFERENCE_BYTES)?;
    }
    Ok(())
}

/// Requires independent, passed, non-simulated evidence of a real run.
fn check_evaluation_shape(evidence: &ActivationEvidence) -> Result<(), PipelineError> {
    bounded_text(
        &evidence.evidence_id,
        "evidence.evidence_id",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    bounded_text(
        &evidence.verifier_id,
        "evidence.verifier_id",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    bounded_text(
        &evidence.run_ref,
        "evidence.run_ref",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    bounded_text(
        &evidence.content_revision_ref,
        "evidence.content_revision_ref",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    bounded_text(
        &evidence.raw_evidence_ref,
        "evidence.raw_evidence_ref",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    if evidence.simulated {
        return Err(PipelineError::SimulatedEvidenceForbidden);
    }
    if !evidence.independent || !evidence.verifier_passed {
        return Err(PipelineError::EvidenceNotIndependent);
    }
    Ok(())
}

/// Requires the proposal and the candidate to declare the same identities.
///
/// `proposal_id` is deliberately not compared: a proposal identity is not
/// necessarily the candidate identity.
fn check_proposal_candidate_join(
    proposal: &ImprovementProposal,
    candidate: &ImprovementCandidateView,
) -> Result<(), PipelineError> {
    for (relation, declared, bound) in [
        (
            "proposal-candidate: candidate-identity-mismatch",
            proposal.candidate_id.as_str(),
            candidate.candidate_id.as_str(),
        ),
        (
            "proposal-candidate: campaign-identity-mismatch",
            proposal.campaign_id.as_str(),
            candidate.campaign_id.as_str(),
        ),
        (
            "proposal-candidate: closure-identity-mismatch",
            proposal.closure_id.as_str(),
            candidate.closure_id.as_str(),
        ),
        (
            "proposal-candidate: closure-digest-mismatch",
            proposal.closure_digest.as_str(),
            candidate.closure_digest.as_str(),
        ),
        (
            "proposal-candidate: operation-mismatch",
            proposal.operation_ref.as_str(),
            candidate.operation_ref.as_str(),
        ),
        (
            "proposal-candidate: idempotency-mismatch",
            proposal.idempotency_key.as_str(),
            candidate.idempotency_key.as_str(),
        ),
    ] {
        if declared != bound {
            return Err(PipelineError::UnboundRelation { relation });
        }
    }
    Ok(())
}

/// Requires the plan's operation join and its admitted scope, budget, and
/// deadline relation.
fn check_proposal_experiment_join(
    experiment: &ExperimentPlan,
    proposal: &ImprovementProposal,
    candidate: &ImprovementCandidateView,
) -> Result<(), PipelineError> {
    if experiment.operation_ref != proposal.operation_ref
        || experiment.idempotency_key != proposal.idempotency_key
    {
        return Err(PipelineError::UnboundRelation {
            relation: "proposal-experiment: operation-idempotency-mismatch",
        });
    }
    if let Some(admitted_scope_ref) = admitted_scope(candidate) {
        check_scope_refinement(experiment, proposal, admitted_scope_ref)?;
    }
    Ok(())
}

/// Returns the owner-proved admitted scope, or `None` for a named gap.
fn admitted_scope(candidate: &ImprovementCandidateView) -> Option<&str> {
    candidate
        .admitted_scope_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Admits an identical scope, budget, and deadline reference, or requires the
/// owner's explicit narrowing evidence for a different one.
fn check_scope_refinement(
    experiment: &ExperimentPlan,
    proposal: &ImprovementProposal,
    admitted_scope_ref: &str,
) -> Result<(), PipelineError> {
    if experiment.scope_ref == admitted_scope_ref
        && experiment.budget_ref == proposal.budget_ref
        && experiment.deadline_ref == proposal.deadline_ref
    {
        return Ok(());
    }
    let Some(refinement) = experiment.scope_refinement.as_ref() else {
        return Err(PipelineError::UnboundRelation {
            relation: "proposal-experiment: unproven-narrowed-scope-budget-or-deadline",
        });
    };
    if !refinement.scope_within_admitted
        || !refinement.budget_within_ceiling
        || !refinement.deadline_not_widened
    {
        return Err(PipelineError::UnboundRelation {
            relation: "proposal-experiment: refinement-declares-widening",
        });
    }
    if refinement.admitted_scope_ref != admitted_scope_ref
        || refinement.admitted_budget_ref != proposal.budget_ref
        || refinement.admitted_deadline_ref != proposal.deadline_ref
    {
        return Err(PipelineError::UnboundRelation {
            relation: "proposal-experiment: refinement-admitted-binding-mismatch",
        });
    }
    if refinement.refined_scope_ref != experiment.scope_ref
        || refinement.refined_budget_ref != experiment.budget_ref
        || refinement.refined_deadline_ref != experiment.deadline_ref
    {
        return Err(PipelineError::UnboundRelation {
            relation: "proposal-experiment: refinement-refined-binding-mismatch",
        });
    }
    bounded_text(
        &refinement.refinement_owner_id,
        "experiment.scope_refinement.refinement_owner_id",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    bounded_text(
        &refinement.refinement_ref,
        "experiment.scope_refinement.refinement_ref",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    check_resource_ceilings(&refinement.resource_ceilings)
}

/// Requires at least one bounded, nonblank, distinct resource ceiling.
fn check_resource_ceilings(ceilings: &[AdmittedResourceCeiling]) -> Result<(), PipelineError> {
    const FIELD: &str = "experiment.scope_refinement.resource_ceilings";
    if ceilings.is_empty() || ceilings.len() > IMPROVEMENT_MAX_SET_MEMBERS {
        return Err(PipelineError::InputProfileCeiling(FIELD));
    }
    let mut seen = BTreeSet::new();
    for ceiling in ceilings {
        bounded_text(
            &ceiling.dimension,
            "experiment.scope_refinement.resource_ceilings.dimension",
            IMPROVEMENT_MAX_REFERENCE_BYTES,
        )?;
        bounded_text(
            &ceiling.ceiling_ref,
            "experiment.scope_refinement.resource_ceilings.ceiling_ref",
            IMPROVEMENT_MAX_REFERENCE_BYTES,
        )?;
        if !seen.insert(ceiling.dimension.as_str()) {
            return Err(PipelineError::DuplicateSetMember(
                "experiment.scope_refinement.resource_ceilings.dimension",
            ));
        }
    }
    Ok(())
}

/// Requires the independent evaluation to name the planned experiment, the
/// candidate, and the competent evaluator the plan declared.
fn check_experiment_evaluation_join(
    evidence: &ActivationEvidence,
    proposal: &ImprovementProposal,
    experiment: &ExperimentPlan,
) -> Result<(), PipelineError> {
    if evidence.bound_candidate_id != proposal.candidate_id {
        return Err(PipelineError::UnboundRelation {
            relation: "experiment-evaluation: candidate-binding-mismatch",
        });
    }
    if evidence.bound_experiment_id != experiment.experiment_id {
        return Err(PipelineError::UnboundRelation {
            relation: "experiment-evaluation: experiment-binding-mismatch",
        });
    }
    if evidence.verifier_id != experiment.evaluator_id {
        return Err(PipelineError::UnboundRelation {
            relation: "experiment-evaluation: evaluator-is-not-the-competent-planned-evaluator",
        });
    }
    Ok(())
}

/// Requires the admission-review evidence to name the same candidate, the same
/// experiment, and the same content revision the experiment evaluation did.
///
/// A later independent admission review may legitimately carry a different
/// verifier identity, so verifier identities are never compared with each
/// other. The typed relationship to the same candidate, experiment, and content
/// revision is what is required.
fn check_admission_evidence_join(
    admission: &ImprovementEvidenceView,
    evaluation: &ActivationEvidence,
    proposal: &ImprovementProposal,
    experiment: &ExperimentPlan,
) -> Result<(), PipelineError> {
    if admission.bound_candidate_id != proposal.candidate_id {
        return Err(PipelineError::UnboundRelation {
            relation: "admission-evidence: candidate-binding-mismatch",
        });
    }
    if admission.bound_experiment_id != experiment.experiment_id {
        return Err(PipelineError::UnboundRelation {
            relation: "admission-evidence: experiment-binding-mismatch",
        });
    }
    if admission.content_revision_ref != evaluation.content_revision_ref {
        return Err(PipelineError::UnboundRelation {
            relation: "admission-evidence: content-revision-mismatch",
        });
    }
    bounded_text(
        &admission.run_ref,
        "admission_evidence.run_ref",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )
}

/// Requires one rollback owner and agreeing rollback, disable, reopen, and
/// expiry references, plus coverage of every required proposal invalidation.
fn check_rollback_join(
    rollback: &RollbackContract,
    admission: &ImprovementEvidenceView,
    policy: &ImprovementAdmissionPolicy,
    proposal: &ImprovementProposal,
) -> Result<(), PipelineError> {
    check_rollback_contract(rollback)?;
    if rollback.rollback_owner_id != policy.rollback_owner_id {
        return Err(PipelineError::UnboundRelation {
            relation: "rollback-policy: rollback-owner-mismatch",
        });
    }
    if rollback.rollback_owner_id != admission.rollback_owner_id {
        return Err(PipelineError::UnboundRelation {
            relation: "rollback-evidence: rollback-owner-mismatch",
        });
    }
    for (relation, declared, bound) in [
        (
            "rollback-evidence: rollback-reference-disagreement",
            admission.rollback_ref.as_deref(),
            rollback.rollback_ref.as_str(),
        ),
        (
            "rollback-evidence: disable-reference-disagreement",
            admission.disable_ref.as_deref(),
            rollback.disable_ref.as_str(),
        ),
        (
            "rollback-evidence: reopen-reference-disagreement",
            admission.reopen_ref.as_deref(),
            rollback.reopen_ref.as_str(),
        ),
        (
            "rollback-evidence: expiry-reference-disagreement",
            admission.expiry_ref.as_deref(),
            rollback.expiry_ref.as_str(),
        ),
    ] {
        agree_declared_reference(relation, declared, bound)?;
    }
    check_invalidation_coverage(proposal, rollback)
}

/// Requires two declared references to agree when both sides declare one.
///
/// An absent side stays a named gap that the inner admission disposes with a
/// typed prerequisite cause. This join never invents a default and never reads
/// absence as agreement.
fn agree_declared_reference(
    relation: &'static str,
    declared: Option<&str>,
    bound: &str,
) -> Result<(), PipelineError> {
    let Some(declared) = declared.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if declared != bound {
        return Err(PipelineError::UnboundRelation { relation });
    }
    Ok(())
}

/// Requires the rollback contract to cover every required proposal invalidation.
///
/// Wider rollback coverage is a repair-path fact, not permission to invalidate
/// targets outside the proposal's admitted set, so the handoff carries the
/// proposal's own set.
fn check_invalidation_coverage(
    proposal: &ImprovementProposal,
    rollback: &RollbackContract,
) -> Result<(), PipelineError> {
    let covered: BTreeSet<&str> = rollback
        .invalidation_set
        .iter()
        .map(String::as_str)
        .collect();
    if covered.len() != rollback.invalidation_set.len() {
        return Err(PipelineError::DuplicateSetMember(
            "rollback.invalidation_set",
        ));
    }
    for target in &proposal.invalidation_set {
        if !covered.contains(target.as_str()) {
            return Err(PipelineError::UnboundRelation {
                relation: "rollback-proposal: required-invalidation-not-covered",
            });
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
    if contract.invalidation_set.len() > IMPROVEMENT_MAX_SET_MEMBERS {
        return Err(PipelineError::InputProfileCeiling(
            "rollback.invalidation_set",
        ));
    }
    for value in &contract.invalidation_set {
        bounded_text(
            value,
            "rollback.invalidation_set",
            IMPROVEMENT_MAX_REFERENCE_BYTES,
        )?;
    }
    Ok(())
}

/// Maps a Governor admission decision through the checked joined view.
fn map_decision(
    decision: &ImprovementAdmissionDecision,
    joined: &JoinedImprovementInputs<'_>,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    Ok(match decision {
        ImprovementAdmissionDecision::AdmitForExperiment {
            candidate_id,
            campaign_id,
            experiment_scope_ref,
            evaluator_id,
            rollback_owner_id,
        } => {
            check_inner_decision_binding(
                joined,
                candidate_id,
                campaign_id,
                experiment_scope_ref,
                evaluator_id,
                rollback_owner_id,
            )?;
            ImprovementTerminalDisposition::CanaryAdmitted {
                handoff: Box::new(build_canary_handoff(joined)?),
            }
        }
        ImprovementAdmissionDecision::Reject {
            cause,
            reason,
            owner_id,
        } => map_rejection(*cause, reason, owner_id),
        ImprovementAdmissionDecision::NeedsMoreEvidence { missing, owner_id } => {
            ImprovementTerminalDisposition::Inconclusive {
                missing: missing.clone(),
                owner_id: owner_id.clone(),
            }
        }
        ImprovementAdmissionDecision::Blocked {
            cause,
            reason,
            owner_id,
        } => map_block(*cause, reason, owner_id),
        ImprovementAdmissionDecision::RequiresReconciliation { reason, owner_id } => {
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                reason: reason.clone(),
                owner_id: owner_id.clone(),
            }
        }
        ImprovementAdmissionDecision::NoProgress { reason, owner_id } => {
            ImprovementTerminalDisposition::NoProgress {
                reason: reason.clone(),
                owner_id: owner_id.clone(),
            }
        }
    })
}

/// Maps one typed rejection. A regression subtype needs typed pulse evidence.
fn map_rejection(
    cause: ImprovementRejectCause,
    reason: &str,
    owner_id: &str,
) -> ImprovementTerminalDisposition {
    match cause {
        ImprovementRejectCause::PulseRegression => {
            ImprovementTerminalDisposition::RegressionRejected {
                cause,
                reason: reason.to_string(),
                owner_id: owner_id.to_string(),
            }
        }
        ImprovementRejectCause::InvalidClosureBinding | ImprovementRejectCause::HarmObserved => {
            ImprovementTerminalDisposition::Rejected {
                cause,
                reason: reason.to_string(),
                owner_id: owner_id.to_string(),
            }
        }
    }
}

/// Maps one typed block. A block is never a rejection and never a completed
/// rollback; the remedy is derived from the typed cause.
fn map_block(
    cause: ImprovementBlockCause,
    reason: &str,
    owner_id: &str,
) -> ImprovementTerminalDisposition {
    ImprovementTerminalDisposition::Blocked {
        cause,
        remedy: cause.remedy(),
        reason: reason.to_string(),
        owner_id: owner_id.to_string(),
    }
}

/// Requires the admitted decision's candidate, campaign, evaluator, scope, and
/// rollback owner to still match the checked records that created the handoff.
fn check_inner_decision_binding(
    joined: &JoinedImprovementInputs<'_>,
    candidate_id: &str,
    campaign_id: &str,
    experiment_scope_ref: &str,
    evaluator_id: &str,
    rollback_owner_id: &str,
) -> Result<(), PipelineError> {
    for (relation, declared, bound) in [
        (
            "inner-decision: candidate-identity-mismatch",
            candidate_id,
            joined.proposal.candidate_id.as_str(),
        ),
        (
            "inner-decision: campaign-identity-mismatch",
            campaign_id,
            joined.proposal.campaign_id.as_str(),
        ),
        (
            "inner-decision: evaluator-identity-mismatch",
            evaluator_id,
            joined.admission_evidence.verifier_id.as_str(),
        ),
        (
            "inner-decision: rollback-owner-mismatch",
            rollback_owner_id,
            joined.rollback.rollback_owner_id.as_str(),
        ),
        (
            "inner-decision: admitted-scope-mismatch",
            experiment_scope_ref,
            joined.admitted_scope_ref.as_str(),
        ),
    ] {
        if declared != bound {
            return Err(PipelineError::UnboundRelation { relation });
        }
    }
    Ok(())
}

/// Builds the inspectable, non-authorizing handoff from the checked view.
fn build_canary_handoff(
    joined: &JoinedImprovementInputs<'_>,
) -> Result<ImprovementCanaryHandoff, PipelineError> {
    let admission_pulse_ref = joined
        .admission_evidence
        .pulse_ref
        .as_deref()
        .ok_or(PipelineError::UnboundRelation {
            relation: "inner-decision: admitted-pulse-evidence-missing",
        })?
        .to_string();
    let handoff = ImprovementCanaryHandoff {
        proposal_id: joined.proposal.proposal_id.clone(),
        proposal_commitment: joined.commitment.clone(),
        candidate_id: joined.proposal.candidate_id.clone(),
        campaign_id: joined.proposal.campaign_id.clone(),
        closure_id: joined.proposal.closure_id.clone(),
        closure_digest: joined.proposal.closure_digest.clone(),
        target_capability: joined.proposal.target_capability.clone(),
        target_generation: joined.proposal.target_generation.clone(),
        experiment_id: joined.experiment.experiment_id.clone(),
        operation_ref: joined.proposal.operation_ref.clone(),
        idempotency_key: joined.proposal.idempotency_key.clone(),
        experiment_scope_ref: joined.admitted_scope_ref.clone(),
        budget_ref: joined.experiment.budget_ref.clone(),
        deadline_ref: joined.experiment.deadline_ref.clone(),
        evidence_id: joined.evidence.evidence_id.clone(),
        evidence_verifier_id: joined.evidence.verifier_id.clone(),
        evidence_run_ref: joined.evidence.run_ref.clone(),
        evidence_content_revision_ref: joined.evidence.content_revision_ref.clone(),
        raw_evidence_ref: joined.evidence.raw_evidence_ref.clone(),
        admission_evaluator_id: joined.admission_evidence.verifier_id.clone(),
        admission_run_ref: joined.admission_evidence.run_ref.clone(),
        admission_content_revision_ref: joined.admission_evidence.content_revision_ref.clone(),
        admission_pulse_ref,
        admission_owner_id: joined.policy.external_owner_id.clone(),
        rollback_ref: joined.rollback.rollback_ref.clone(),
        disable_ref: joined.rollback.disable_ref.clone(),
        reopen_ref: joined.rollback.reopen_ref.clone(),
        expiry_ref: joined.rollback.expiry_ref.clone(),
        forward_repair_ref: joined.rollback.forward_repair_ref.clone(),
        rollback_owner_id: joined.rollback.rollback_owner_id.clone(),
        invalidation_set: joined.normalized.invalidation_set.clone(),
        activation_owner_id: KERNEL_CANARY_OWNER.to_string(),
        handoff_projection: String::new(),
        execution_authorized: false,
    };
    Ok(ImprovementCanaryHandoff {
        handoff_projection: format!(
            "canary-handoff: proposal {} candidate {} campaign {} experiment {} admitted-scope {} budget {} deadline {} commitment {}/{} run {} revision {} verifier {} reviewer {} rollback-owner {}; #11 Kernel activation required, not executed here; not a permit",
            handoff.proposal_id,
            handoff.candidate_id,
            handoff.campaign_id,
            handoff.experiment_id,
            handoff.experiment_scope_ref,
            handoff.budget_ref,
            handoff.deadline_ref,
            handoff.proposal_commitment.encoding_version,
            handoff.proposal_commitment.digest,
            handoff.evidence_run_ref,
            handoff.evidence_content_revision_ref,
            handoff.evidence_verifier_id,
            handoff.admission_evaluator_id,
            handoff.rollback_owner_id,
        ),
        ..handoff
    })
}

/// Returns the complete normalized proposal whose exact bytes are committed.
fn canonical_proposal(
    proposal: &ImprovementProposal,
) -> Result<ImprovementProposal, PipelineError> {
    check_commitment_profile(proposal)?;
    Ok(ImprovementProposal {
        evidence_refs: declared_set(&proposal.evidence_refs, "evidence_refs")?,
        invalidation_set: declared_set(&proposal.invalidation_set, "invalidation_set")?,
        ..proposal.clone()
    })
}

/// Commits one already-normalized proposal with the current identity.
fn commitment_of(normalized: &ImprovementProposal) -> Result<ProposalCommitment, PipelineError> {
    let envelope = ImprovementProposalCommitmentEnvelope {
        domain: IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN.to_string(),
        encoding_version: IMPROVEMENT_PROPOSAL_ENCODING_VERSION.to_string(),
        algorithm: IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM.to_string(),
        proposal: normalized.clone(),
    };
    let bytes = canonical_json_bytes(&envelope)
        .map_err(|_| PipelineError::CommitmentFailed("canonical-json-bytes-unavailable"))?;
    if bytes.len() > IMPROVEMENT_MAX_COMMITMENT_BYTES {
        return Err(PipelineError::InputProfileCeiling(
            "proposal-commitment-bytes",
        ));
    }
    Ok(ProposalCommitment {
        domain: envelope.domain,
        encoding_version: envelope.encoding_version,
        algorithm: envelope.algorithm,
        operation_ref: normalized.operation_ref.clone(),
        idempotency_key: normalized.idempotency_key.clone(),
        digest: sha256_hex(&bytes),
        canonical_bytes: bytes.len(),
    })
}

/// Validates the admitted input, count, string, and total-size profile before
/// any clone, sort, or serialization happens.
fn check_commitment_profile(proposal: &ImprovementProposal) -> Result<(), PipelineError> {
    for (field, value) in [
        ("proposal_id", proposal.proposal_id.as_str()),
        ("candidate_id", proposal.candidate_id.as_str()),
        ("campaign_id", proposal.campaign_id.as_str()),
        ("closure_id", proposal.closure_id.as_str()),
        ("closure_digest", proposal.closure_digest.as_str()),
        ("target_capability", proposal.target_capability.as_str()),
        ("target_generation", proposal.target_generation.as_str()),
        ("operation_ref", proposal.operation_ref.as_str()),
        ("idempotency_key", proposal.idempotency_key.as_str()),
        ("privacy_class", proposal.privacy_class.as_str()),
        ("risk_ceiling", proposal.risk_ceiling.as_str()),
        ("effect_ceiling", proposal.effect_ceiling.as_str()),
        ("budget_ref", proposal.budget_ref.as_str()),
        ("deadline_ref", proposal.deadline_ref.as_str()),
        ("source_identity", proposal.source_identity.as_str()),
        ("runtime_identity", proposal.runtime_identity.as_str()),
        ("data_identity", proposal.data_identity.as_str()),
        (
            "mechanism.mechanism_id",
            proposal.mechanism.mechanism_id.as_str(),
        ),
    ] {
        bounded_text(value, field, IMPROVEMENT_MAX_REFERENCE_BYTES)?;
    }
    for (field, value) in [
        (
            "mechanism.hypothesis",
            proposal.mechanism.hypothesis.as_str(),
        ),
        (
            "mechanism.causal_link",
            proposal.mechanism.causal_link.as_str(),
        ),
        (
            "mechanism.declared_ref",
            proposal.mechanism.declared_ref.as_str(),
        ),
        ("expected_delta", proposal.expected_delta.as_str()),
    ] {
        bounded_text(value, field, IMPROVEMENT_MAX_TEXT_BYTES)?;
    }
    for (field, values) in [
        ("evidence_refs", &proposal.evidence_refs),
        ("invalidation_set", &proposal.invalidation_set),
    ] {
        if values.is_empty() {
            return Err(PipelineError::MissingField(field));
        }
        if values.len() > IMPROVEMENT_MAX_SET_MEMBERS {
            return Err(PipelineError::InputProfileCeiling(field));
        }
        for value in values {
            bounded_text(value, field, IMPROVEMENT_MAX_REFERENCE_BYTES)?;
        }
    }
    if proposal_total_bytes(proposal) > IMPROVEMENT_MAX_COMMITMENT_BYTES {
        return Err(PipelineError::InputProfileCeiling("proposal-total-bytes"));
    }
    Ok(())
}

/// Returns the summed byte length of every committed string in the proposal.
fn proposal_total_bytes(proposal: &ImprovementProposal) -> usize {
    let scalars: [&str; 22] = [
        proposal.proposal_id.as_str(),
        proposal.candidate_id.as_str(),
        proposal.campaign_id.as_str(),
        proposal.closure_id.as_str(),
        proposal.closure_digest.as_str(),
        proposal.target_capability.as_str(),
        proposal.target_generation.as_str(),
        proposal.mechanism.mechanism_id.as_str(),
        proposal.mechanism.hypothesis.as_str(),
        proposal.mechanism.causal_link.as_str(),
        proposal.mechanism.declared_ref.as_str(),
        proposal.expected_delta.as_str(),
        proposal.risk_ceiling.as_str(),
        proposal.effect_ceiling.as_str(),
        proposal.budget_ref.as_str(),
        proposal.deadline_ref.as_str(),
        proposal.privacy_class.as_str(),
        proposal.operation_ref.as_str(),
        proposal.idempotency_key.as_str(),
        proposal.source_identity.as_str(),
        proposal.runtime_identity.as_str(),
        proposal.data_identity.as_str(),
    ];
    let total: usize = scalars.iter().map(|value| value.len()).sum();
    total
        + proposal
            .evidence_refs
            .iter()
            .map(String::len)
            .sum::<usize>()
        + proposal
            .invalidation_set
            .iter()
            .map(String::len)
            .sum::<usize>()
}

/// Normalizes one declared set: deterministic byte ordering, explicit duplicate
/// rejection, and reference bytes left unchanged.
///
/// Ordering is a declared property of the set, so a permutation preserves the
/// commitment. A repeated identity is refused instead of silently collapsed,
/// because collapsing conflicting evidence destroys the difference it encodes.
/// Ordered and prose content is never normalized.
fn declared_set(values: &[String], field: &'static str) -> Result<Vec<String>, PipelineError> {
    let mut ordered = Vec::with_capacity(values.len());
    for value in values {
        if ordered.contains(value) {
            return Err(PipelineError::DuplicateSetMember(field));
        }
        ordered.push(value.clone());
    }
    ordered.sort();
    Ok(ordered)
}

/// Reads one required field, keeping stored bytes unchanged.
fn text(value: &str, field: &'static str) -> Result<(), PipelineError> {
    if value.trim().is_empty() {
        Err(PipelineError::MissingField(field))
    } else {
        Ok(())
    }
}

/// Reads one required field and refuses it above the admitted byte ceiling.
fn bounded_text(value: &str, field: &'static str, limit: usize) -> Result<(), PipelineError> {
    text(value, field)?;
    if value.len() > limit {
        return Err(PipelineError::InputProfileCeiling(field));
    }
    Ok(())
}
