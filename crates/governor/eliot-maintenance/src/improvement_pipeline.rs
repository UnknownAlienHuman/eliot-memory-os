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
//! # Routing is a contract, not prose
//!
//! The declared experiment executor must be the Testd owner and the independent
//! Evaluate step must be owned by the Instrument verifier family, and that
//! verifier must be a different principal from the Testd executor, the
//! Governor admission owner, and the rollback owner. Both requirements are
//! refusals with a typed relation identity, so an experiment cannot be executed
//! by a self-chosen principal or evaluated by the party proposing it.
//!
//! Activation evidence carries the I0.5 `EvidenceExecutionStatus` dimension
//! rather than a boolean. Only `EXECUTED` may support admission:
//! `NOT_EXECUTED` and `SIMULATED` can never become accepted improvement, and
//! `UNKNOWN_OUTCOME` is refused here and reconciles before any retry. A model
//! score, a self-report, and a zero exit code are none of these states, so none
//! of them admits.
//!
//! The proposal commitment is a versioned, domain-separated SHA-256 over one
//! canonical JSON envelope holding the complete normalized proposal. The
//! pipeline computes exactly one commitment and carries that same value into
//! the canary handoff and into the admission gate, so no consumer in this
//! repository recomputes it and none can substitute a fallback, empty, or legacy
//! digest.
//!
//! That one commitment decides integrity. Semantic progress is a different
//! question, so it gets a separately named and versioned
//! [`ImprovementDiscriminatorProjection`] over the current source/target
//! context and the owner-issued evidence references the proposal declares. The
//! admission gate derives the assessment from the two records themselves and
//! never accepts an assessment from a caller, so no field of a record can
//! assert that a repeat happened or that a new discriminator exists. Integrity
//! and semantic progress stay separate: an exact replay is no progress, changed
//! content under one operation and idempotency key is a typed identity conflict,
//! a retained record written under another domain, encoding revision, or
//! algorithm is unestablished and requires reconciliation, and a different
//! logical operation is a new causal discriminator only when the current
//! projection differs from the retained one *and* the current proposal declares
//! owner-issued evidence the retained record did not. No retained record at all
//! establishes nothing and is reported as no progress; absence is never read as
//! novelty, and no progress claim clears an unknown external effect.
//!
//! Material equality is a third and separate question again. A repeat is not
//! recognized by an identical digest: the same declared mechanism, target
//! capability, target generation, budget, deadline, bounded experiment, and
//! declared evidence is one attempt whatever operation identity, idempotency
//! key, or digest it carries. The separately named and versioned
//! [`ImprovementMaterialEquality`] key answers exactly that and feeds
//! [`ImprovementReplayAssessment::MaterialNoProgress`], so a repeated
//! materially identical experiment is visible as no-progress evidence in the
//! assessment itself instead of being inferred from digest equality. A
//! materially identical experiment that is nevertheless materially *changed* is
//! not a repeat; only the key decides that, never a caller assertion.
//!
//! # Wire revision
//!
//! [`IMPROVEMENT_PIPELINE_WIRE_REVISION`] is `7`. Revision `2` added typed
//! `cause`/`remedy` fields to the rejection and block branches, added the
//! `Blocked` disposition and the inspectable canary handoff, bound
//! candidate/experiment/content-revision/run identities onto the admission
//! evidence view, the bounded experiment plan, and the activation evidence, and
//! replaced the free-form proposal digest string with [`ProposalCommitment`].
//! Revision `3` removes the two caller-settable booleans that let a caller
//! assert a repeat or a new discriminator from the admission evidence view, and
//! replaces them with the retained prior [`ProposalCommitment`] those bytes are
//! compared against, so the progress decision is derived from canonical bytes.
//! Revision `4` replaces that bare retained commitment with the retained record
//! [`RetainedImprovementProposal`], which pairs the commitment with the
//! discriminator projection of the same retained bytes; adds the
//! `NoRetainedPrior`, `EstablishedNewDiscriminator`, and typed
//! `UnestablishedPriorCause` cases so an absent record and an unchanged
//! discriminator are distinguishable outcomes instead of novelty; threads the
//! current [`ImprovementCurrentProposal`] the pipeline computed into the
//! admission gate instead of a caller-authored verdict; carries the checked
//! discriminator projection in the canary handoff next to the checked
//! commitment; and stops collapsing a typed admission refusal into reason text.
//! Revision `5` replaces the `simulated` boolean on [`ActivationEvidence`] with
//! the I0.5 `EvidenceExecutionStatus` dimension
//! [`ImprovementEvidenceExecution`], requires the declared experiment executor
//! to be the Testd owner and the independent Evaluate step to be owned by the
//! Instrument verifier family and to be a distinct principal from the executor,
//! the admission owner, and the rollback owner; adds the `improvement_candidate`
//! ingress operation identity; and adds the material-equality projection,
//! comparator, and `MateriallyEquivalentRepeat` outcome.
//! Revision `6` requires an exact replay to reproduce the retained experiment
//! plan as well as the retained commitment, so a changed proposal, mechanism,
//! target, or experiment under one operation and idempotency key is a typed
//! identity conflict instead of a replay and never an automatic retry; carries
//! the exact checked experiment plan on both the retained and the current
//! record; carries the committed candidate identity on the current record; and
//! replaces the unknown-outcome disposition's reason text with the typed
//! [`ImprovementUnknownEffect`] obligation, which names the exact unresolved
//! external effect and carries the [`improvement_retry_permitted`] gate so an
//! unknown activation or effect outcome cannot be retried blindly. Revision `7`
//! removes the caller-supplied reconciliation reference from that obligation
//! and helper; absent an existing owner-validated outcome seam, an unknown
//! effect remains unresolved and retry is always denied.
//!
//! Deserialization is fail-closed: bytes written before the current revision no
//! longer decode, so a stale disposition cannot be read as a current one.
//! Historical revision-`1` FNV-1a 64-bit digests stay explicitly
//! [`IMPROVEMENT_LEGACY_DIGEST_ALGORITHM`] observations; they are never padded,
//! reinterpreted as SHA-256, or matched against a current proposal.

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::improvement_admission::{
    IMPROVEMENT_PROOF_CEILING, IMPROVEMENT_REQUESTED_EFFECT, ImprovementAdmissionDecision,
    ImprovementAdmissionError, ImprovementAdmissionPolicy, ImprovementBlockCause,
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
/// Operation identity of the `improvement_candidate` ingress step.
///
/// This is the step that admits one improvement-candidate declaration into the
/// Governor contract. It is a proposal-side step, not a new authority: it
/// resolves to the same single production owner as every other Governor-owned
/// step, because the improvement candidate contract and the improvement
/// maintenance pipeline are one cognitive mechanism with one production owner.
pub const OP_CANDIDATE_INGRESS: &str = "improvement_candidate";
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
/// Fixed domain separator of the improvement discriminator projection.
///
/// The projection is a separately named object, not a second commitment: it
/// answers whether the causal discriminator of a candidate changed and whether
/// new owner-issued evidence backs it, never whether two byte strings are equal.
pub const IMPROVEMENT_DISCRIMINATOR_DOMAIN: &str = "eliot.improvement.proposal.discriminator";
/// Canonical encoding revision of the discriminator projection.
///
/// A retained projection written under any other revision cannot be compared
/// against a current one and stays an unestablished observation.
pub const IMPROVEMENT_DISCRIMINATOR_ENCODING_VERSION: &str = "1";
/// Fixed domain separator of the improvement material-equality projection.
///
/// The material-equality key answers the third question: "is this the same
/// experiment?" It binds mechanism, target, budget, deadline, and the declared
/// evidence set, so a byte-identical digest is neither necessary nor sufficient
/// to call a repeat a repeat. A new proposal identity, a new operation, or a
/// new idempotency key can all spell the same experiment, and only this key
/// says so.
pub const IMPROVEMENT_MATERIAL_EQUALITY_DOMAIN: &str =
    "eliot.improvement.proposal.material_equality";
/// Canonical encoding revision of the material-equality projection.
///
/// A retained key written under any other revision cannot be compared against a
/// current one and stays an unestablished observation.
pub const IMPROVEMENT_MATERIAL_EQUALITY_ENCODING_VERSION: &str = "1";
/// Wire revision of the improvement pipeline result and identity contracts.
pub const IMPROVEMENT_PIPELINE_WIRE_REVISION: u32 = 7;
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
    /// Governor-owned ingress of one improvement-candidate declaration into the
    /// Governor contract.
    IngestCandidate,
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
            Self::IngestCandidate => OP_CANDIDATE_INGRESS,
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
    ///
    /// Candidate ingress resolves to the same production owner as proposal and
    /// admission, because the improvement candidate contract and this pipeline
    /// are one cognitive mechanism with one production owner. Ingesting a
    /// candidate grants nothing.
    pub fn owner(self, rollback_owner_id: &str) -> &str {
        match self {
            Self::Propose | Self::IngestCandidate | Self::Admit | Self::Promote => {
                IMPROVEMENT_PIPELINE_OWNER
            }
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

/// Execution status of one independent evaluation, exactly as `I0.5` defines
/// `EvidenceExecutionStatus`.
///
/// The status is machine state, never prose, and it is orthogonal to
/// independence and to the verdict: a verifier can be independent, can pass, and
/// still have produced nothing that ran. `I0.5` forbids substituting
/// [`Self::NotExecuted`] or [`Self::Simulated`] for real execution evidence, so
/// this pipeline admits exactly one status and treats the other three as
/// refusals rather than as weaker successes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementEvidenceExecution {
    /// The evaluation was never run. Identity binding cannot replace it.
    NotExecuted,
    /// The evaluation was simulated. Simulation never admits a candidate.
    Simulated,
    /// The independent evaluation actually ran. The only admitted status.
    Executed,
    /// The evaluation's own outcome is unknown and must be reconciled.
    UnknownOutcome,
}

impl ImprovementEvidenceExecution {
    /// Returns the stable label of this status as it appears in an error.
    ///
    /// Derived from the typed status so the refusal cannot drift away from the
    /// machine state it reports.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotExecuted => "not-executed",
            Self::Simulated => "simulated",
            Self::Executed => "executed",
            Self::UnknownOutcome => "unknown-outcome",
        }
    }
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
    /// Whether the evaluation actually executed. Only
    /// [`ImprovementEvidenceExecution::Executed`] may support activation; a
    /// model score, a self-report, a planned run, or a local exit zero is
    /// `NotExecuted` and is refused rather than downgraded.
    pub execution: ImprovementEvidenceExecution,
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

/// Separately named, versioned projection of one proposal's causal
/// discriminator.
///
/// [`ProposalCommitment`] answers "are these the same bytes?". This projection
/// answers a different question — "did the discriminator of this candidate
/// change, and does new owner-issued evidence back the change?" — so it is a
/// separate object with its own fixed domain and encoding revision, never a
/// second opinion about the commitment and never a second digest. It is derived
/// from the same normalized bytes the commitment covers, so it cannot name a
/// context, target, hypothesis, or evidence reference that the committed
/// proposal does not contain, and a caller cannot establish a new discriminator
/// by spelling a reference the proposal never declared.
///
/// Every field is copied unchanged from the committed content. Reference bytes,
/// punctuation, and ordered prose are not normalized here; only the declared
/// evidence set is carried in its committed deterministic order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementDiscriminatorProjection {
    /// Fixed discriminator-projection domain separator.
    pub domain: String,
    /// Canonical encoding revision of this projection.
    pub encoding_version: String,
    /// Current source identity of the candidate.
    pub source_identity: String,
    /// Current runtime identity of the candidate.
    pub runtime_identity: String,
    /// Current data identity of the candidate.
    pub data_identity: String,
    /// Capability the candidate currently targets.
    pub target_capability: String,
    /// Generation the candidate currently observes.
    pub target_generation: String,
    /// Declared mechanism identity.
    pub mechanism_id: String,
    /// Declared falsifiable hypothesis, verbatim.
    pub hypothesis: String,
    /// Declared causal link, verbatim.
    pub causal_link: String,
    /// Declared expected delta, verbatim.
    pub expected_delta: String,
    /// Owner-issued evidence references in committed deterministic order.
    pub declared_evidence_refs: Vec<String>,
}

/// Separately named, versioned key of one proposal's *material* experiment
/// identity.
///
/// [`ProposalCommitment`] answers "are these the same bytes?".
/// [`ImprovementDiscriminatorProjection`] answers "did the causal context
/// change?". This key answers the third question: "is this the same
/// experiment?" It is bound to the mechanism, the target capability and
/// generation, the budget, the deadline, the bounded experiment identity, and
/// the declared evidence set, and to nothing else.
///
/// It exists because an identical digest is not enough for no-progress. A retry
/// may carry a new proposal identity, a new operation reference, and a new
/// idempotency key — every identity a caller controls — while repeating one and
/// the same bounded experiment. Byte equality would miss that repeat, and a
/// new identity must not be read as novelty. Comparing this key instead makes
/// the repeat visible as a material fact derived from the checked records, never
/// from a caller assertion.
///
/// Every field is copied from the checked records: the proposal supplies
/// mechanism, target, budget, deadline, and evidence; the joined experiment plan
/// supplies the bounded experiment identity. A caller cannot widen the admitted
/// material by spelling a reference the bound records do not contain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementMaterialEquality {
    /// Fixed material-equality domain separator.
    pub domain: String,
    /// Canonical encoding revision of this key.
    pub encoding_version: String,
    /// Declared mechanism identity the experiment tests.
    pub mechanism_id: String,
    /// Capability the experiment targets.
    pub target_capability: String,
    /// Generation the experiment observes.
    pub target_generation: String,
    /// Budget the experiment must not exceed.
    pub budget_ref: String,
    /// Deadline the experiment must not exceed.
    pub deadline_ref: String,
    /// Bounded experiment identity the plan declared.
    pub experiment_id: String,
    /// Owner-issued evidence references in committed deterministic order.
    pub declared_evidence_refs: Vec<String>,
}

/// One retained prior proposal record.
///
/// A record, never a verdict. It pairs the retained content commitment with the
/// discriminator projection and the material-equality key computed from those
/// same retained bytes and the exact retained experiment plan, so a consumer
/// can compare the current candidate against the retained one without
/// re-committing either. The full plan is retained separately from the
/// intentionally narrower cross-operation material-equality key.
/// The record supplies no judgement: a caller may read it, carry it, or withhold
/// it, and withholding it establishes nothing.
///
/// Durable retention of this record is owned outside this module. Nothing here
/// stores it, so the record's authenticity is only as good as the owner that
/// issued it, and this module never treats its presence as evidence of
/// improvement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedImprovementProposal {
    /// Retained content commitment with its own version identity.
    pub commitment: ProposalCommitment,
    /// Discriminator projection of the same retained bytes.
    pub discriminator: ImprovementDiscriminatorProjection,
    /// Material-equality key of the same retained bytes and retained
    /// experiment.
    pub material_equality: ImprovementMaterialEquality,
    /// Exact checked experiment plan that accompanied the retained proposal.
    pub experiment_plan: ExperimentPlan,
}

/// The current proposal exactly as the pipeline committed it.
///
/// The one commitment this run computed, plus the projection, material-equality
/// key, and exact joined experiment plan that accompany the same normalized
/// proposal. The pipeline builds it once and hands the same value to the
/// admission gate and to the canary handoff, so a consumer reads the checked
/// version instead of computing a second opinion. It carries no decision: the
/// assessment belongs to [`compare_improvement_commitments`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementCurrentProposal {
    /// Candidate identity the committed proposal declares. Carried from the
    /// same committed bytes, so an obligation built on this record names the
    /// exact candidate whose external effect is unresolved.
    pub candidate_id: String,
    /// The single commitment computed for these exact bytes.
    pub commitment: ProposalCommitment,
    /// Discriminator projection of the same normalized bytes.
    pub discriminator: ImprovementDiscriminatorProjection,
    /// Material-equality key of the same bytes and the same joined experiment.
    pub material_equality: ImprovementMaterialEquality,
    /// Exact checked experiment plan joined to the normalized proposal.
    pub experiment_plan: ExperimentPlan,
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
    /// The discriminator projection of those same bytes, carried so a consumer
    /// compares progress against the checked content instead of recomputing it.
    /// It is a projection, not a permit and not a second commitment.
    pub proposal_discriminator: ImprovementDiscriminatorProjection,
    /// The material-equality key of those same bytes and the same joined
    /// experiment, carried for the same reason: a consumer compares repeats on
    /// the experiment, not on digest equality, and reads the checked key instead
    /// of recomputing one. It is a key, not a permit and not a third commitment.
    pub proposal_material_equality: ImprovementMaterialEquality,
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

/// Exact unresolved external effect that must be reconciled before any retry.
///
/// An unknown activation or effect outcome is a distinct machine state, not a
/// weaker success and not an absent result. `I0.5` names it
/// `EvidenceExecutionStatus::UNKNOWN_OUTCOME`, I12.24 records it as
/// `materially_equivalent_to_prior_attempt: unknown`, and I14.24 requires an
/// unknown effect to be preserved rather than assumed away. This type is the one
/// representation of that debt inside this pipeline: it names the exact
/// candidate, experiment, and commitment whose external effect is unresolved,
/// the owner holding the reconciliation, and the rollback contract's
/// forward-repair and invalidation bindings that cover it.
///
/// A retry is a *new* attempt only after this obligation is discharged. The
/// obligation is deliberately not self-clearing: it carries no proof that the
/// effect happened or did not happen. This module has no owner-validated
/// activation outcome to consume, and this record does not bind an owning
/// operation or effect identity. Therefore [`Self::retry_permitted`] always
/// returns false. Naming a rollback contract, supplying a caller string, or
/// using a proposal, new identity, or new idempotency key does not discharge it.
///
/// The forward-repair and invalidation bindings are copied from the checked
/// [`RollbackContract`], never from the caller. They make the repair path part
/// of the debt this obligation names, so an unresolved effect carries the exact
/// invalidation targets it may have to quarantine instead of leaving the
/// pipeline holding a rollback contract that no disposition ever references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementUnknownEffect {
    /// Candidate whose external activation or effect outcome is unresolved.
    pub candidate_id: String,
    /// Exact bounded experiment the unresolved effect belongs to.
    pub experiment_id: String,
    /// Current proposal commitment the unresolved effect is bound to.
    pub commitment: ProposalCommitment,
    /// Owner that holds the unresolved reconciliation debt.
    pub owner_id: String,
    /// Forward-repair reference the checked rollback contract names for an
    /// incomplete rollback effect.
    pub forward_repair_ref: String,
    /// Invalidation targets the checked rollback contract covers, in the
    /// contract's own committed order.
    pub invalidation_set: Vec<String>,
}

impl ImprovementUnknownEffect {
    /// Returns whether a new attempt is allowed after an unknown effect.
    ///
    /// This pipeline has no owner-validated reconciliation outcome to consume,
    /// so every unknown effect remains unresolved and retry is denied. A
    /// reference string or other caller assertion is not evidence of a
    /// completed effect or of a proved non-effect.
    #[must_use]
    pub fn retry_permitted(&self) -> bool {
        false
    }
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
    ///
    /// The obligation is a value, not a sentence: a consumer reads the exact
    /// candidate, experiment, commitment, owner, and the retry gate directly
    /// from it, so no wording of the reason can be reinterpreted as a
    /// reconciliation. Until a validated owner outcome seam is available,
    /// [`ImprovementUnknownEffect::retry_permitted`] remains false.
    UnknownRequiresReconciliation {
        /// Exact unresolved external effect owed by its owner.
        obligation: Box<ImprovementUnknownEffect>,
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
    /// The current canonical proposal bytes exactly replay a retained prior
    /// commitment under the same logical operation. An exact repeat is not
    /// progress, and no caller assertion can make it one.
    NoProgress {
        /// Prior commitment this exactly replays, with exact debt retained.
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

/// One improvement-candidate declaration entering the Governor contract
/// through the `improvement_candidate` ingress step.
///
/// The ingress step exists because the improvement candidate contract
/// (`eliot-improvement`) and this pipeline are one cognitive mechanism with one
/// production owner. A caller therefore hands the ingress the candidate's exact
/// identities plus the owner-issued bounded-run records, and it builds the
/// Governor-side candidate view itself. The improvement package cannot supply
/// that view, so it cannot widen its own ceiling: `proof_ceiling`,
/// `requested_effect`, `direct_promotion`, `active_permit`, and
/// `promotion_receipt` are fixed here rather than read from the declaration.
///
/// It is a proposal-side step, not a new authority. Ingesting a candidate grants
/// nothing, promotes nothing, and admits nothing on its own; the only path past
/// the ingress is the ordinary bounded experiment to independent evaluation to
/// Governor admission sequence, and the only positive result remains a
/// non-authorizing canary handoff.
#[derive(Clone, Copy, Debug)]
pub struct ImprovementCandidateIngress<'a> {
    /// Improvement candidate identity, exactly as the improvement package's
    /// intake produced it.
    pub candidate_id: &'a str,
    /// Campaign the candidate learns from.
    pub campaign_id: &'a str,
    /// Closure candidate identity (`#819`).
    pub closure_id: &'a str,
    /// Closure evidence digest, opaque at this boundary.
    pub closure_digest: &'a str,
    /// Admitted work scope the candidate owner proved. An absent or blank
    /// binding is not defaulted here: it stays a named gap that the admission
    /// gate disposes as a typed block.
    pub admitted_scope_ref: Option<&'a str>,
    /// Governor-side proposal declaring the mechanism, expected delta, and
    /// every exact current-evidence, target, budget, deadline, privacy, and
    /// invalidation binding.
    pub proposal: &'a ImprovementProposal,
    /// Testd-owned bounded experiment plan. Only the Testd owner may have
    /// executed it.
    pub experiment: &'a ExperimentPlan,
    /// Independent evaluation record of that exact run, produced by the
    /// Instrument verifier family and carrying an executed status.
    pub evidence: &'a ActivationEvidence,
    /// Rollback contract named before admission.
    pub rollback: &'a RollbackContract,
    /// Independent admission-review evidence observed by the Governor owner.
    pub admission_evidence: &'a ImprovementEvidenceView,
    /// Policy governing Governor admission.
    pub policy: &'a ImprovementAdmissionPolicy,
}

/// Admits one improvement-candidate declaration into the Governor contract.
///
/// The single production entry point of this module and the only way a
/// candidate reaches the bounded experiment path. It builds the Governor-side
/// candidate view from the declaration with the non-self-promoting values fixed
/// in code, then runs the ordinary advisory-only pipeline, so the improvement
/// package can never hand this pipeline a widened ceiling, a self-issued
/// permit, or a self-issued promotion receipt.
///
/// Ingesting grants nothing. The result is the pipeline's own terminal
/// disposition: rejected, inconclusive, blocked, requiring reconciliation,
/// no-progress, or a non-authorizing canary handoff. There is no variant that
/// promotes, activates, installs, completes, or issues authority.
pub fn ingest_improvement_candidate(
    ingress: ImprovementCandidateIngress<'_>,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    let candidate = ImprovementCandidateView {
        candidate_id: ingress.candidate_id.to_string(),
        campaign_id: ingress.campaign_id.to_string(),
        closure_id: ingress.closure_id.to_string(),
        closure_digest: ingress.closure_digest.to_string(),
        // The improvement package prepares advisory promotion input on its own
        // side. This owner does not re-read or reinterpret it, and a candidate
        // that never prepared one is admitted on its own evidence.
        promotion_input_id: None,
        promotion_digest: None,
        admitted_scope_ref: ingress.admitted_scope_ref.map(str::to_string),
        // Fixed in code, never read from the declaration: the package cannot
        // widen its own proof ceiling, effect class, or promotion state.
        proof_ceiling: IMPROVEMENT_PROOF_CEILING.to_string(),
        requested_effect: IMPROVEMENT_REQUESTED_EFFECT.to_string(),
        direct_promotion: false,
        active_permit: None,
        promotion_receipt: None,
        operation_ref: ingress.proposal.operation_ref.clone(),
        idempotency_key: ingress.proposal.idempotency_key.clone(),
    };
    run_improvement_candidate_pipeline(ImprovementPipelineInputs {
        proposal: ingress.proposal,
        experiment: ingress.experiment,
        evidence: ingress.evidence,
        rollback: ingress.rollback,
        candidate: &candidate,
        admission_evidence: ingress.admission_evidence,
        policy: ingress.policy,
    })
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

/// One identity component of a record that this crate does not recognize.
///
/// A checked record carries the SAME domain, encoding revision, and algorithm
/// constants the producer stamps. A consumer that accepts a record carrying any
/// other identity accepts content the producer never vouched for, so the
/// mismatch is a typed refusal rather than a tolerated value: no digest is
/// substituted, no legacy or empty value is filled in, and the record is not
/// compared at all.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("checked identity mismatch on {component}: record carries {found}, this build checks {expected}")]
pub struct UncheckedRecordIdentity {
    /// Which identity component of the record disagreed.
    pub component: &'static str,
    /// The identity the record carries.
    pub found: String,
    /// The identity this build checks.
    pub expected: &'static str,
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
    /// The independent evaluation did not execute, so it can never support
    /// activation.
    ///
    /// `I0.5` forbids substituting `NOT_EXECUTED` or `SIMULATED` for real
    /// execution evidence, so every status other than `EXECUTED` is refused
    /// here instead of being downgraded into weaker evidence. The status is
    /// machine state carried whole, never inferred from a reason string.
    #[error(
        "improvement evidence execution status {status} cannot support activation; only executed independent evidence may"
    )]
    EvidenceNotExecuted {
        /// Typed execution status that is refused.
        status: &'static str,
    },
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
    ///
    /// `detail` carries the serializer's OWN failure text, so a serialization
    /// refusal crosses every layer boundary as itself and is never flattened
    /// into a placeholder reason, an empty value, or a substitute digest.
    #[error("improvement proposal commitment failed: {detail}")]
    CommitmentFailed {
        /// The canonical serializer's own failure text.
        detail: String,
    },
    /// A record presented for comparison does not carry this crate's checked
    /// identity, so its digest is not a current commitment.
    #[error("improvement record identity is not the checked version: {0}")]
    UncheckedRecordIdentity(#[from] UncheckedRecordIdentity),
    /// Governor admission refused the candidate with a typed failure.
    ///
    /// The admission error is carried whole, so an identity conflict stays an
    /// identity conflict across this layer boundary and never collapses into
    /// reason text or a generic code.
    #[error("improvement admission refused: {0}")]
    AdmissionRefused(#[from] ImprovementAdmissionError),
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
///
/// This is the crate's public one-shot commitment entry point, for a caller that
/// holds a proposal and no commitment yet. The pipeline itself reaches the
/// commitment through `current_proposal_of`, so a commitment and its
/// discriminator projection always describe the same bytes, and every consumer
/// of a checked record reads that record instead of committing again. The digest
/// describes content and never declares it admissible, so this function
/// deliberately does not validate the proposal.
pub fn proposal_digest(
    proposal: &ImprovementProposal,
) -> Result<ProposalCommitment, PipelineError> {
    commitment_of(&canonical_proposal(proposal)?)
}

/// Builds the one checked current record from already-normalized bytes.
///
/// The single producer of [`ImprovementCurrentProposal`]: the commitment, the
/// discriminator projection, the material-equality key, and exact experiment
/// plan are derived or copied here, together, from the same normalized
/// proposal and the same joined experiment plan, so no consumer can hold
/// identities that describe different content or experiments. The experiment
/// is a required argument rather than an optional refinement because a
/// no-progress decision over the wrong experiment is not a no-progress
/// decision.
fn current_proposal_of(
    normalized: &ImprovementProposal,
    experiment: &ExperimentPlan,
) -> Result<ImprovementCurrentProposal, PipelineError> {
    Ok(ImprovementCurrentProposal {
        candidate_id: normalized.candidate_id.clone(),
        commitment: commitment_of(normalized)?,
        discriminator: discriminator_of(normalized),
        material_equality: material_equality_of(normalized, experiment),
        experiment_plan: experiment.clone(),
    })
}

/// Refuses a record that does not carry this build's checked identity.
///
/// Every consumer of a [`ImprovementCurrentProposal`] calls this before the
/// record is compared, propagated, or named in an obligation. The comparison is
/// against the SAME constants the producer stamps in `commitment_of`, so a
/// record written under another domain, encoding revision, or algorithm is a
/// typed refusal rather than a tolerated value: nothing is substituted for it,
/// no legacy digest is reinterpreted, and no assessment is derived from a
/// record this build cannot read.
///
/// The refusal names the disagreeing component and both identities, so a caller
/// cannot repair the record by guessing.
pub fn check_checked_record_identity(
    current: &ImprovementCurrentProposal,
) -> Result<(), UncheckedRecordIdentity> {
    let identities: [(&'static str, &str, &'static str); 7] = [
        (
            "commitment.domain",
            &current.commitment.domain,
            IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN,
        ),
        (
            "commitment.encoding_version",
            &current.commitment.encoding_version,
            IMPROVEMENT_PROPOSAL_ENCODING_VERSION,
        ),
        (
            "commitment.algorithm",
            &current.commitment.algorithm,
            IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM,
        ),
        (
            "discriminator.domain",
            &current.discriminator.domain,
            IMPROVEMENT_DISCRIMINATOR_DOMAIN,
        ),
        (
            "discriminator.encoding_version",
            &current.discriminator.encoding_version,
            IMPROVEMENT_DISCRIMINATOR_ENCODING_VERSION,
        ),
        (
            "material_equality.domain",
            &current.material_equality.domain,
            IMPROVEMENT_MATERIAL_EQUALITY_DOMAIN,
        ),
        (
            "material_equality.encoding_version",
            &current.material_equality.encoding_version,
            IMPROVEMENT_MATERIAL_EQUALITY_ENCODING_VERSION,
        ),
    ];
    for (component, found, expected) in identities {
        if found != expected {
            return Err(UncheckedRecordIdentity {
                component,
                found: found.to_owned(),
                expected,
            });
        }
    }
    Ok(())
}

/// Derives the discriminator projection of one normalized proposal.
fn discriminator_of(normalized: &ImprovementProposal) -> ImprovementDiscriminatorProjection {
    ImprovementDiscriminatorProjection {
        domain: IMPROVEMENT_DISCRIMINATOR_DOMAIN.to_string(),
        encoding_version: IMPROVEMENT_DISCRIMINATOR_ENCODING_VERSION.to_string(),
        source_identity: normalized.source_identity.clone(),
        runtime_identity: normalized.runtime_identity.clone(),
        data_identity: normalized.data_identity.clone(),
        target_capability: normalized.target_capability.clone(),
        target_generation: normalized.target_generation.clone(),
        mechanism_id: normalized.mechanism.mechanism_id.clone(),
        hypothesis: normalized.mechanism.hypothesis.clone(),
        causal_link: normalized.mechanism.causal_link.clone(),
        expected_delta: normalized.expected_delta.clone(),
        declared_evidence_refs: normalized.evidence_refs.clone(),
    }
}

/// Derives the material-equality key of one normalized proposal and its plan.
///
/// Every field is copied from the two checked records. The declared evidence set
/// arrives already in its committed deterministic order, so a permutation of the
/// same declared set is one material experiment and not two.
fn material_equality_of(
    normalized: &ImprovementProposal,
    experiment: &ExperimentPlan,
) -> ImprovementMaterialEquality {
    ImprovementMaterialEquality {
        domain: IMPROVEMENT_MATERIAL_EQUALITY_DOMAIN.to_string(),
        encoding_version: IMPROVEMENT_MATERIAL_EQUALITY_ENCODING_VERSION.to_string(),
        mechanism_id: normalized.mechanism.mechanism_id.clone(),
        target_capability: normalized.target_capability.clone(),
        target_generation: normalized.target_generation.clone(),
        budget_ref: experiment.budget_ref.clone(),
        deadline_ref: experiment.deadline_ref.clone(),
        experiment_id: experiment.experiment_id.clone(),
        declared_evidence_refs: normalized.evidence_refs.clone(),
    }
}

/// Exact-repeat and identity-conflict assessment for one uncommitted proposal.
///
/// Integrity and semantic progress stay separate. An exact replay reproduces
/// the complete current proposal commitment and experiment plan under its
/// original logical operation. The same operation and idempotency key with
/// different proposal or plan content is an identity conflict, not the old
/// request and not an automatic retry. A retained record
/// written under another domain, encoding revision, or algorithm — a legacy
/// FNV-1a value, for example — stays an unqualified historical observation
/// until its owner reconciles it. A different logical operation is not progress
/// evidence either: a new proposal identity or a different digest establishes
/// nothing on its own, and a repeat of the same bounded experiment under fresh
/// identities is no progress rather than novelty.
///
/// `experiment` is required because the material-equality key binds the bounded
/// experiment the plan actually declared. Assessing a repeat against a
/// different experiment would answer a question nobody asked.
///
/// This entry exists for a caller that holds a proposal and has not committed
/// it yet, and it commits those bytes exactly once. A caller that already holds
/// the checked record must call [`compare_improvement_commitments`] with it
/// instead of re-committing the proposal here.
pub fn assess_improvement_replay(
    retained: &RetainedImprovementProposal,
    proposal: &ImprovementProposal,
    experiment: &ExperimentPlan,
) -> Result<ImprovementReplayAssessment, PipelineError> {
    compare_improvement_commitments(
        retained,
        &current_proposal_of(&canonical_proposal(proposal)?, experiment)?,
    )
    .map_err(PipelineError::from)
}

/// Assesses the current record against the retained prior record, if any.
///
/// The only construction site of [`ImprovementReplayAssessment::NoRetainedPrior`]:
/// an absent retained record is a state this crate reports, not a verdict it
/// infers. Absence is never novelty and never evidence of improvement.
pub(crate) fn assess_improvement_progress(
    retained: Option<&RetainedImprovementProposal>,
    current: &ImprovementCurrentProposal,
) -> Result<ImprovementReplayAssessment, UncheckedRecordIdentity> {
    match retained {
        Some(retained) => compare_improvement_commitments(retained, current),
        None => {
            check_checked_record_identity(current)?;
            Ok(ImprovementReplayAssessment::NoRetainedPrior {
                commitment: current.commitment.clone(),
            })
        }
    }
}

/// Compares a retained prior record with the current checked record.
///
/// The single owner of the integrity decision, over the current proposal's
/// canonical bytes and exact checked experiment plan: no caller boolean, no
/// legacy value reinterpreted as a current commitment, and no effect state.
/// Integrity is decided first and stays separate from semantic progress.
///
/// Under one logical operation and idempotency key, `ExactReplay` requires both
/// a byte-identical current-version proposal commitment and an equal complete
/// experiment plan; changed proposal or plan content is `IdentityConflict`. A
/// retained value written under another domain, encoding revision, or algorithm
/// is `UnestablishedPrior` and cannot be matched. Outside that operation, a
/// repeat of the same bounded experiment — same mechanism, target, budget,
/// deadline, experiment, and evidence — is `MaterialNoProgress`, which is
/// decided from the material-equality key rather than from digest equality, so
/// a fresh proposal identity or a new idempotency key cannot disguise a repeat.
/// Only a current-version retained projection that differs from the current
/// one, together with owner-issued evidence the current proposal declares and
/// the retained record did not, is an `EstablishedNewDiscriminator` — and even
/// that is an ordinary new candidate, never a progress claim. Without a
/// retained record nothing is established at all. None of these clears an
/// unknown external effect; effect retry stays with its own owner.
///
/// # The current record must be this build's checked version
///
/// Every assessment this function returns is derived only after
/// [`check_checked_record_identity`] confirms that `current` carries the SAME
/// domain, encoding revision, and algorithm the producer stamps. Comparing a
/// record against another record is not enough: two records that agree with each
/// other but not with this build agree about content no version of this
/// pipeline committed, and a consumer that tolerates that reads a foreign
/// digest as a replay, a conflict, or an established discriminator. The refusal
/// is therefore returned as [`UncheckedRecordIdentity`] rather than resolved
/// into an assessment, and no substitute digest, legacy value, or recomputation
/// over local state stands in for the record.
pub fn compare_improvement_commitments(
    retained: &RetainedImprovementProposal,
    current: &ImprovementCurrentProposal,
) -> Result<ImprovementReplayAssessment, UncheckedRecordIdentity> {
    check_checked_record_identity(current)?;
    Ok(if let Some(assessment) = same_operation_replay(retained, current) {
        assessment
    } else if let Some(assessment) = unestablished_projection(retained, current) {
        assessment
    } else if let Some(assessment) = material_repeat(retained, current) {
        assessment
    } else {
        changed_discriminator(retained, current)
    })
}

/// Decides the outcomes that belong to the retained record's own operation.
///
/// `None` means the retained record does not describe this logical operation,
/// which is not a conclusion about progress: that decision belongs to
/// [`changed_discriminator`].
fn same_operation_replay(
    retained: &RetainedImprovementProposal,
    current: &ImprovementCurrentProposal,
) -> Option<ImprovementReplayAssessment> {
    let prior = &retained.commitment;
    if prior.operation_ref != current.commitment.operation_ref
        || prior.idempotency_key != current.commitment.idempotency_key
    {
        return None;
    }
    if prior.domain != current.commitment.domain
        || prior.encoding_version != current.commitment.encoding_version
        || prior.algorithm != current.commitment.algorithm
    {
        return Some(unestablished_prior(
            UnestablishedPriorCause::UnknownCommitmentEncoding,
            prior,
        ));
    }
    if prior.digest == current.commitment.digest
        && retained.experiment_plan == current.experiment_plan
    {
        return Some(ImprovementReplayAssessment::ExactReplay {
            commitment: current.commitment.clone(),
        });
    }
    Some(ImprovementReplayAssessment::IdentityConflict {
        operation_ref: current.commitment.operation_ref.clone(),
        idempotency_key: current.commitment.idempotency_key.clone(),
    })
}

/// Reports a retained record whose projection cannot be compared to a current
/// one, and `None` when both projections carry the current identity.
fn unestablished_projection(
    retained: &RetainedImprovementProposal,
    current: &ImprovementCurrentProposal,
) -> Option<ImprovementReplayAssessment> {
    if retained.discriminator.domain == current.discriminator.domain
        && retained.discriminator.encoding_version == current.discriminator.encoding_version
    {
        return None;
    }
    Some(unestablished_prior(
        UnestablishedPriorCause::UnknownDiscriminatorEncoding,
        &retained.commitment,
    ))
}

/// Decides whether the current candidate repeats a retained *experiment*, as
/// opposed to repeating a set of bytes.
///
/// `None` means the current candidate is not materially equivalent to the
/// retained one, so the decision belongs to [`changed_discriminator`]. A
/// retained key written under another domain or encoding revision cannot be
/// compared at all and stays an unestablished observation.
fn material_repeat(
    retained: &RetainedImprovementProposal,
    current: &ImprovementCurrentProposal,
) -> Option<ImprovementReplayAssessment> {
    if retained.material_equality.domain != current.material_equality.domain
        || retained.material_equality.encoding_version != current.material_equality.encoding_version
    {
        return Some(unestablished_prior(
            UnestablishedPriorCause::UnknownMaterialEqualityEncoding,
            &retained.commitment,
        ));
    }
    if retained.material_equality == current.material_equality {
        return Some(ImprovementReplayAssessment::MaterialNoProgress {
            commitment: current.commitment.clone(),
            material_equality: current.material_equality.clone(),
        });
    }
    None
}

/// Decides whether a changed discriminator is backed by new owner-issued
/// evidence.
///
/// Both conditions are required. A changed projection alone is a different
/// spelling, and new evidence against an unchanged projection is more of the
/// same candidate, so either alone reports no progress.
fn changed_discriminator(
    retained: &RetainedImprovementProposal,
    current: &ImprovementCurrentProposal,
) -> ImprovementReplayAssessment {
    if retained.discriminator == current.discriminator {
        return ImprovementReplayAssessment::NoProgressEstablished {
            commitment: current.commitment.clone(),
        };
    }
    let retained_evidence: BTreeSet<&str> = retained
        .discriminator
        .declared_evidence_refs
        .iter()
        .map(String::as_str)
        .collect();
    let new_evidence: Vec<String> = current
        .discriminator
        .declared_evidence_refs
        .iter()
        .filter(|value| !retained_evidence.contains(value.as_str()))
        .cloned()
        .collect();
    if new_evidence.is_empty() {
        return ImprovementReplayAssessment::NoProgressEstablished {
            commitment: current.commitment.clone(),
        };
    }
    ImprovementReplayAssessment::EstablishedNewDiscriminator {
        commitment: current.commitment.clone(),
        new_evidence_refs: new_evidence,
    }
}

/// Names one unestablished retained record by its typed cause and identity.
fn unestablished_prior(
    cause: UnestablishedPriorCause,
    prior: &ProposalCommitment,
) -> ImprovementReplayAssessment {
    ImprovementReplayAssessment::UnestablishedPrior {
        cause,
        prior_domain: prior.domain.clone(),
        prior_encoding_version: prior.encoding_version.clone(),
        prior_algorithm: prior.algorithm.clone(),
    }
}

/// Typed cause of an unestablished retained record.
///
/// The cause is machine state, never the wording of a reason string. Each
/// variant is a real, distinguishable state of a record that cannot be compared
/// against a current one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnestablishedPriorCause {
    /// The retained commitment carries another domain, encoding revision, or
    /// algorithm, including a legacy FNV-1a value. It is never reinterpreted as
    /// a current commitment and never matched against current content.
    UnknownCommitmentEncoding,
    /// The retained discriminator projection carries another projection domain
    /// or encoding revision, so a changed discriminator cannot be established
    /// against it.
    UnknownDiscriminatorEncoding,
    /// The retained material-equality key carries another key domain or encoding
    /// revision, so a repeated experiment cannot be established against it.
    UnknownMaterialEqualityEncoding,
}

impl UnestablishedPriorCause {
    /// Returns the stable label of the cause as it appears in a reason.
    ///
    /// Derived from the typed cause so the explanation cannot drift away from
    /// the machine state it reports.
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnknownCommitmentEncoding => "unknown-commitment-encoding",
            Self::UnknownDiscriminatorEncoding => "unknown-discriminator-encoding",
            Self::UnknownMaterialEqualityEncoding => "unknown-material-equality-encoding",
        }
    }
}

/// Outcome of comparing the current checked record with a retained prior one.
///
/// Every variant is derived from the two records. No caller supplies one, and no
/// variant clears an unknown external effect.
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
    /// The retained record is not a current-version record. It stays an
    /// unqualified historical observation and requires reconciliation or
    /// revalidation by its owner.
    UnestablishedPrior {
        /// Why the retained record cannot be compared.
        cause: UnestablishedPriorCause,
        /// Domain the retained value was written under.
        prior_domain: String,
        /// Encoding revision the retained value was written under.
        prior_encoding_version: String,
        /// Algorithm the retained value was written under.
        prior_algorithm: String,
    },
    /// No retained record was supplied at all. There is no owner-backed
    /// discriminator evidence, so no progress is established and nothing is
    /// cleared; absence is not novelty.
    NoRetainedPrior {
        /// The current commitment.
        commitment: ProposalCommitment,
    },
    /// The current candidate repeats a retained *experiment* rather than a set
    /// of bytes: same mechanism, target, budget, deadline, bounded experiment,
    /// and declared evidence, under any operation or idempotency key.
    ///
    /// This is the no-progress case a digest comparison cannot see. A repeat
    /// that arrives with a new proposal identity, a new operation, and a new
    /// idempotency key is still a repeat, and a repeat without a new
    /// discriminator is no-progress evidence rather than improvement.
    MaterialNoProgress {
        /// The current commitment.
        commitment: ProposalCommitment,
        /// The current material-equality key that repeats the retained one.
        material_equality: ImprovementMaterialEquality,
    },
    /// A new causal discriminator is established: the current projection
    /// differs from a current-version retained one and the current proposal
    /// declares owner-issued evidence the retained record did not. This is an
    /// ordinary new candidate, never a progress claim.
    EstablishedNewDiscriminator {
        /// The current commitment.
        commitment: ProposalCommitment,
        /// Owner-issued evidence references the current proposal declares and the
        /// retained record did not.
        new_evidence_refs: Vec<String>,
    },
    /// No new causal discriminator is established from the available records.
    /// No progress is established either.
    NoProgressEstablished {
        /// The current commitment.
        commitment: ProposalCommitment,
    },
}

/// Builds the typed disposition for an unknown external activation outcome.
///
/// This maps a prior decision; it does not reconcile the effect or authorize a
/// retry. An unresolved prior outcome stays `UnknownRequiresReconciliation` and
/// carries the typed [`ImprovementUnknownEffect`] obligation built from the
/// checked record. Every other prior decision keeps its typed cause, owner, and
/// remedy instead of collapsing into an evidence gap. A named rollback
/// contract still never clears an unknown external effect.
///
/// `current` is the checked record this run committed and `rollback` the
/// gap-free contract it was admitted against. Both are required, not optional:
/// an obligation without the exact commitment and experiment that went unknown
/// would name a debt against a candidate nobody can identify, and an
/// unidentifiable debt is one no owner can discharge, while an obligation
/// without the contract's forward-repair and invalidation bindings would name a
/// repair path no disposition can be held to. The reconciliation debt is about
/// *this* attempt, not a remembered sentence, so those checked records remain
/// bound to the returned obligation.
///
/// No caller-supplied evidence reference is accepted. The current improvement
/// route has no owner-validated activation outcome seam, so a resulting unknown
/// effect remains unresolved and [`ImprovementUnknownEffect::retry_permitted`]
/// continues to deny retry.
pub fn reconcile_unknown_activation(
    prior: &ImprovementAdmissionDecision,
    current: &ImprovementCurrentProposal,
    rollback: &RollbackContract,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    check_checked_record_identity(current)?;
    Ok(match prior {
        ImprovementAdmissionDecision::RequiresReconciliation { owner_id, .. } => {
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                obligation: Box::new(unknown_effect_of(current, rollback, owner_id)),
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
                "unknown-activation: owner-validated outcome required before retry for {candidate_id}"
            ),
            owner_id: rollback_owner_id.clone(),
        },
    })
}

/// Builds the unresolved external-effect obligation from checked records only.
///
/// The single construction site of [`ImprovementUnknownEffect`]. Every identity
/// is copied from a record this run checked — the candidate and experiment from
/// the committed record, the repair bindings from the gap-free rollback
/// contract — and the owner is the decision's own owner. Nothing here is read
/// from a reason string or supplied by a caller, so the obligation cannot name a
/// candidate, an experiment, or a repair path the checked records do not
/// contain.
fn unknown_effect_of(
    current: &ImprovementCurrentProposal,
    rollback: &RollbackContract,
    owner_id: &str,
) -> ImprovementUnknownEffect {
    ImprovementUnknownEffect {
        candidate_id: current.candidate_id.clone(),
        experiment_id: current.experiment_plan.experiment_id.clone(),
        commitment: current.commitment.clone(),
        owner_id: owner_id.to_string(),
        forward_repair_ref: rollback.forward_repair_ref.clone(),
        invalidation_set: rollback.invalidation_set.clone(),
    }
}

/// Returns whether a disposition permits a retry attempt.
///
/// One gate over the whole terminal disposition, so a caller reads the retry
/// answer from the typed outcome instead of re-deciding it. The match names
/// every variant and carries no wildcard, so the answer for a variant is read
/// off that variant rather than inherited from an unexamined default: adding a
/// disposition is a compile error here until its retry answer is decided from
/// the evidence the pipeline actually holds.
pub fn improvement_retry_permitted(disposition: &ImprovementTerminalDisposition) -> bool {
    match disposition {
        // The one disposition whose own owner has not settled what happened.
        // The answer is read from the obligation itself rather than assumed.
        ImprovementTerminalDisposition::UnknownRequiresReconciliation { obligation } => {
            obligation.retry_permitted()
        }
        // The retained historical completed-rollback representation. This
        // pipeline holds no owner-validated rollback result — it receives a
        // contract, never an execution or readback receipt — so a bare
        // `contract_ref` is not the owner evidence a completed rollback
        // requires, and the gate refuses rather than certifying a fresh
        // attempt from an unverified historical value. Naming this arm is what
        // keeps that refusal explicit: under a wildcard the same variant would
        // have inherited permission without ever being examined.
        ImprovementTerminalDisposition::RolledBack { .. } => false,
        // Every remaining outcome names the owner that holds the next step, and
        // a fresh attempt is that owner's to make: the rejection, the typed
        // regression, the evidence gap, the missing prerequisite, the exact
        // repeat, and the bound advisory handoff each carry their own owner and
        // remedy, and this gate does not discharge any of them.
        ImprovementTerminalDisposition::Rejected { .. }
        | ImprovementTerminalDisposition::Inconclusive { .. }
        | ImprovementTerminalDisposition::RegressionRejected { .. }
        | ImprovementTerminalDisposition::NoProgress { .. }
        | ImprovementTerminalDisposition::Blocked { .. }
        | ImprovementTerminalDisposition::CanaryAdmitted { .. } => true,
    }
}

/// Runs the advisory-only candidate to experiment to evaluation to admission pipeline.
///
/// Pure orchestrator over borrowed inputs: it builds the private checked view
/// over the proposal, experiment, evaluation, rollback, and admission records,
/// refuses a diverged relation before any positive path, requires a gap-free
/// rollback contract, computes the single commitment and discriminator
/// projection for the normalized proposal, hands that one record to
/// `improvement_admission::admit_improvement_candidate`, and maps the resulting
/// verdict through the same checked view. Never performs promotion, activation,
/// canary cutover, authority issuance, or completion, and never reports an
/// observed completed rollback.
pub fn run_improvement_candidate_pipeline(
    inputs: ImprovementPipelineInputs<'_>,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    let joined = join_improvement_inputs(inputs)?;
    // The gate receives the record this run committed, never a verdict. A typed
    // admission refusal, including the identity conflict, crosses this boundary
    // as itself and is never collapsed into reason text.
    let decision = admit_improvement_candidate(
        joined.candidate,
        joined.admission_evidence,
        joined.policy,
        &joined.current,
    )?;
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
    /// The single normalized proposal whose exact bytes were committed.
    normalized: ImprovementProposal,
    /// The single commitment computed for those bytes, with the discriminator
    /// projection of the same bytes. The gate and the handoff read this one
    /// value; neither recomputes it.
    current: ImprovementCurrentProposal,
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
    check_experiment_owner_routing(inputs.experiment)?;
    check_evaluation_shape(inputs.evidence)?;
    let normalized = canonical_proposal(inputs.proposal)?;
    // The material-equality key binds the bounded experiment, so the joined
    // experiment plan is part of the one checked record. It is built here, after
    // the plan's own shape check, and is never recomputed downstream.
    let current = current_proposal_of(&normalized, inputs.experiment)?;
    check_proposal_candidate_join(inputs.proposal, inputs.candidate)?;
    check_proposal_experiment_join(inputs.experiment, inputs.proposal, inputs.candidate)?;
    check_experiment_evaluation_join(
        inputs.evidence,
        inputs.proposal,
        inputs.experiment,
        inputs.policy,
    )?;
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
        current,
        admitted_scope_ref,
    })
}

/// Verifies the nine pipeline operation strings are pairwise distinct.
fn check_operation_identities() -> Result<(), PipelineError> {
    let operations = [
        OP_PROPOSE,
        OP_CANDIDATE_INGRESS,
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

/// Requires independent, passed, executed evidence of a real run.
///
/// Execution is checked before independence so a never-run or simulated
/// evaluation is refused as what it is. The status is machine state: no reason
/// text, self-report, planned run, or local exit zero can supply it.
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
    // `I0.5` forbids substituting `NOT_EXECUTED` or `SIMULATED` for real
    // execution evidence, and `UNKNOWN_OUTCOME` is reconciled by its own owner
    // rather than admitted. Only `EXECUTED` reaches the independence check, and
    // a status is machine state: a model score, a self-report, a planned run, and
    // a local exit zero are none of these.
    if evidence.execution != ImprovementEvidenceExecution::Executed {
        return Err(PipelineError::EvidenceNotExecuted {
            status: evidence.execution.label(),
        });
    }
    if !evidence.independent || !evidence.verifier_passed {
        return Err(PipelineError::EvidenceNotIndependent);
    }
    Ok(())
}

/// Requires the independent evaluation to be a competent verifier, the
/// Instrument verifier owner family, and a principal distinct from the executor,
/// the admitting Governor owner, and the rollback owner.
///
/// A0.3 treats a verifier that is the party whose change it verifies as hidden
/// control capture, and `ARCH-GROUND-01` requires evidence to be independent of
/// the thing it grounds. Independence is a relation between named principals, so
/// it is checked against the exact owner identities the other records already
/// carry — the same strings the canary handoff publishes — rather than against a
/// caller-set independence boolean.
fn check_evaluator_independence(
    evidence: &ActivationEvidence,
    experiment: &ExperimentPlan,
    policy: &ImprovementAdmissionPolicy,
) -> Result<(), PipelineError> {
    // The evidence must name the planned evaluator: any competent verifier inside
    // the owner family is admissible, but only the one the plan declared.
    if evidence.verifier_id != experiment.evaluator_id {
        return Err(PipelineError::UnboundRelation {
            relation: "experiment-evaluation: evaluator-is-not-the-competent-planned-evaluator",
        });
    }
    // Every verifier admitted here is owned by the Instrument verifier family
    // (`#20`/`#1111`). A proposal author, a test executor, or a model cannot be
    // the independent evaluator of its own candidate.
    if !evidence.verifier_id.starts_with(VERIFIER_OWNER_FAMILY) {
        return Err(PipelineError::UnboundRelation {
            relation: "experiment-evaluation: evaluator-is-not-the-instrument-verifier-family",
        });
    }
    for (relation, evaluator, principal) in [
        (
            "experiment-evaluation: evaluator-is-the-experiment-executor",
            evidence.verifier_id.as_str(),
            experiment.testd_owner_id.as_str(),
        ),
        (
            "experiment-evaluation: evaluator-is-the-governor-admission-owner",
            evidence.verifier_id.as_str(),
            policy.external_owner_id.as_str(),
        ),
        (
            "experiment-evaluation: evaluator-is-the-rollback-owner",
            evidence.verifier_id.as_str(),
            policy.rollback_owner_id.as_str(),
        ),
    ] {
        if evaluator == principal {
            return Err(PipelineError::UnboundRelation { relation });
        }
    }
    Ok(())
}

/// Requires the plan's experiment execution and evaluation to be routed to their
/// external owners.
///
/// `W5` routes bounded experiments through Testd and independent evaluation
/// through the Instrument verifier family. Both routings are refusals with a
/// typed relation identity, not documentation: a plan that names any other
/// executor or evaluator is unbound, so the pipeline cannot be reached by an
/// experiment its own proposer executes or grades.
fn check_experiment_owner_routing(experiment: &ExperimentPlan) -> Result<(), PipelineError> {
    if experiment.testd_owner_id != TESTD_OWNER {
        return Err(PipelineError::UnboundRelation {
            relation: "experiment-execution: executor-is-not-the-testd-owner",
        });
    }
    if !experiment.evaluator_id.starts_with(VERIFIER_OWNER_FAMILY) {
        return Err(PipelineError::UnboundRelation {
            relation: "experiment-evaluation: evaluator-is-not-the-instrument-verifier-family",
        });
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
    policy: &ImprovementAdmissionPolicy,
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
    check_evaluator_independence(evidence, experiment, policy)
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
        // The obligation is built from the checked record and the gap-free
        // rollback contract, not from the decision's reason text: the reason is
        // prose the owner may reword, while the obligation names the exact
        // candidate, experiment, commitment, repair bindings and owner this run
        // checked. This route has no validated owner outcome to consume, so the
        // typed obligation remains unresolved and `improvement_retry_permitted`
        // denies another attempt.
        ImprovementAdmissionDecision::RequiresReconciliation { owner_id, .. } => {
            ImprovementTerminalDisposition::UnknownRequiresReconciliation {
                obligation: Box::new(unknown_effect_of(
                    &joined.current,
                    joined.rollback,
                    owner_id,
                )),
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
        proposal_commitment: joined.current.commitment.clone(),
        proposal_discriminator: joined.current.discriminator.clone(),
        proposal_material_equality: joined.current.material_equality.clone(),
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
    let bytes = canonical_json_bytes(&envelope).map_err(|error| PipelineError::CommitmentFailed {
        detail: error.to_string(),
    })?;
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
