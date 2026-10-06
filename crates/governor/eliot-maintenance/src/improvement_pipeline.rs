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
//! The independent admission review is held to the same principal relation
//! through the same shared predicate. The two records may name different
//! verifiers, and their identities are never compared with each other, but
//! neither reviewer may be the experiment executor, the admitting Governor
//! owner, or the rollback owner. The admission review is the record the decision
//! leans on hardest — it carries the pulse outcome, the harm observation, and the
//! pass verdict — so a review written by the party that executed the experiment
//! is the party grading its own work, and both records' own `independent` flag is
//! a caller-set boolean that establishes nothing by itself.
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
//! [`IMPROVEMENT_PIPELINE_WIRE_REVISION`] is `8`. Revision `2` added typed
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
//! and helper. The obligation is then bound to the effect owner's own validated
//! [`EffectReceipt`] — the existing receipt owner, reused rather than duplicated
//! — and both answers are read off that stored value. The retry gate denies an
//! absent, unsettled, foreign, still-unknown, committed or compensated outcome,
//! and requires positive owner evidence rather than a bare discriminant: a
//! `Rejected` outcome the owner never settled against a canonical receipt is
//! denied too. A completed effect is not denied and forgotten either — it is
//! reconciled from the result its owner already retained through
//! [`retained_improvement_completion`] instead of authorizing a second
//! execution. A retry is permitted only by an owner-settled non-success
//! terminal outcome: an [`EffectOutcome::Rejected`] the owner validated against
//! its own canonical receipt whose disposition is `FAILURE` or `CANCELLED`,
//! bound to this obligation's exact operation identity. Revision `8` puts the
//! revision where it was always claimed to be: [`ImprovementCanaryHandoff`]
//! carries the [`IMPROVEMENT_PIPELINE_WIRE_REVISION`] its producer wrote, and
//! [`check_handoff_wire_revision`] compares that recorded value against this
//! build's constant at the handoff boundary, so a handoff assembled under
//! another wire revision is a typed [`UncheckedWireRevision`] rather than a
//! tolerated record. The constant was never compared before revision `8`; it is
//! now read at the boundary whose shape it describes. Revision `9` puts the
//! staleness discriminator where the claim already said it was. The receipt
//! owner's `validate_terminal_receipt` binds a terminal outcome to its effect on
//! three things — operation id, idempotency key, and state fence — and this
//! module re-established only the first two. The third is now compared too, on
//! two values that are both recorded and both owned elsewhere: the `state_fence`
//! on the authorized effect's `OperationBinding` and the `state_fence` on the
//! operation binding inside the retained `ReceiptEnvelope` (see
//! `ImprovementUnknownEffect::binds_effect_fence`). Both carry an authority
//! epoch — an exact `(lineage_id, sequence)` tuple — and a resource generation,
//! and they are compared with `fences_match_exact`, so a receipt whose outcome
//! was recorded under a superseded epoch or an earlier generation than the
//! effect it claims to settle is refused as a typed
//! [`UnboundOwnerOutcome::DivergentStateFence`] at the attaching seam and denied
//! by [`improvement_retry_permitted`]. Nothing was invented to make that
//! comparison possible: no clock, no nonce, no epoch of this module's own, and
//! no constant that would let it pass. It is not a wire-revision change either —
//! the owner outcome is skipped on serialize, so the bytes of an already-written
//! obligation are unchanged, which is why
//! [`IMPROVEMENT_PIPELINE_WIRE_REVISION`] stays at `8`.
//!
//! ## The staleness check this module can and cannot make
//!
//! Stated here rather than left to be discovered, because the difference is the
//! whole of what a reader may rely on.
//!
//! What it makes: an outcome whose two recorded fences disagree is refused, so
//! a receipt cannot pair an effect admitted under one authority epoch or
//! resource generation with a settlement observed under another and pass as that
//! operation's outcome. `EffectReceipt` is an open all-`pub` struct, so a value
//! reaching the seam need not have passed `EffectReceipt::terminal`, and this is
//! a live comparison rather than a restatement of a constructor's guarantee.
//!
//! What it cannot make, because the value does not exist here: a comparison
//! against a *current* fence. This module records no current authority epoch and
//! no current resource generation, and it holds no fence of its own on
//! [`ImprovementUnknownEffect`], on [`ProposalCommitment`], on
//! [`ImprovementProposal`], or on [`ImprovementCandidateView`]. The one
//! generation-shaped field on the proposal, `target_generation`, is a
//! `String` documented as observation-only and never activated here, so it is
//! not a [`StateFence`] value and comparing it against a `ResourceGeneration`
//! would assert an identity nobody defines. The candidate's
//! `validity_scope` in `eliot-improvement` is likewise a `String` and does not
//! reach this crate at all. So a receipt that is *internally* consistent but was
//! settled under a fence that has since been superseded still reaches the gate.
//!
//! Closing that would require the daemon to supply one value this crate does not
//! currently receive: the admitted `StateFence` — at minimum the authority epoch
//! and resource generation — that the candidate was admitted under, carried on
//! the intake path beside the candidate identity, and bound to the obligation at
//! the module's single `unknown_effect_of` construction site the way
//! [`RollbackContract::forward_repair_ref`] is. The comparison would then be
//! three-sided: this receipt's fence, the fence the effect was authorized under,
//! and the fence the run was admitted under. Until that value exists, inventing
//! a stand-in for it — a clock read, a locally held epoch, a constant — would
//! produce a check that looks present and can only ever pass, which is worse than
//! the recorded gap.
//!
//! That is precisely what the gate establishes, and the module claims no more.
//! A `FAILURE` or `CANCELLED` disposition records what the owner observed about
//! its own operation; it is **not** proof that nothing was applied externally —
//! `ReceiptDisposition::Partial` exists precisely to name sub-effects and
//! artifacts that did apply while other gaps remain, and nothing here inspects
//! the disposition to assert a whole-world non-effect. A permitted retry is
//! therefore a *newly admitted* operation under the same identity and the same
//! commitments, never a replay of the rejected receipt and never a second
//! opinion about what that attempt left behind.
//!
//! The stored value is reachable only through the checked attaching seam
//! [`ImprovementUnknownEffect::with_settled_owner_outcome`], which re-checks the
//! binding before it accepts anything; the field itself is private, so no caller
//! can hand-build a receipt that opens either gate. That binding is NOT a wire
//! revision: the owner outcome is skipped on serialize and defaults to absent on
//! deserialize, so the bytes of an already-written obligation are unchanged by
//! it. The absent default is the
//! denying direction, so a re-read obligation is unresolved until its owner
//! reattaches its receipt — and nothing in this workspace performs that attach
//! today, so the gate denies every obligation it builds until the external
//! effect owner settles one.
//!
//! Deserialization is fail-closed: bytes written before the current revision no
//! longer decode, so a stale disposition cannot be read as a current one.
//! Historical revision-`1` FNV-1a 64-bit digests stay explicitly
//! [`IMPROVEMENT_LEGACY_DIGEST_ALGORITHM`] observations; they are never padded,
//! reinterpreted as SHA-256, or matched against a current proposal.

use std::collections::BTreeSet;

use eliot_authority::{EffectOutcome, EffectReceipt};
use eliot_contracts::{StateFence, canonical_json_bytes, fences_match_exact, sha256_hex};
use eliot_receipts::{OperationBinding, ReceiptEnvelope};
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
///
/// Compared against the revision a producer recorded, by
/// [`check_handoff_wire_revision`]. A record stamped with any other value is a
/// typed [`UncheckedWireRevision`]: the revision is never rounded to this one,
/// never padded, and never read as if the current shape had produced it.
pub const IMPROVEMENT_PIPELINE_WIRE_REVISION: u32 = 8;
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
        // A blank risk qualifier is UNSUPPORTED, not absent. `risk_ceiling` names a
        // closed typed policy value with exactly one admitted member, so a value
        // that carries no qualifier at all is the same closed-set violation as
        // `unbounded` and must not be reported as a missing field. Checked here,
        // before the input profile, so no later field check can relabel it.
        check_risk_ceiling_present(&self.risk_ceiling)?;
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
    /// Wire revision of the record shape this handoff was written under.
    ///
    /// The producer stamps [`IMPROVEMENT_PIPELINE_WIRE_REVISION`] here and a
    /// consumer compares the recorded value against its own constant through
    /// [`check_handoff_wire_revision`]. The value is never inferred from the
    /// presence of a field, from a digest, or from the rest of the record, so a
    /// handoff assembled under another wire revision cannot be read as a
    /// current one.
    pub wire_revision: u32,
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
/// A retry is a *new* attempt only after this obligation is discharged, and the
/// discharge is an owner-validated outcome rather than an assertion. The private
/// `owner_outcome` field holds the effect owner's own [`EffectReceipt`] for this
/// obligation's exact operation, or `None` while the owner has not settled the
/// effect. That value is the existing receipt owner's, not a re-derivation: the
/// owner binds the outcome to the authorized operation id, idempotency key and
/// state fence when it builds it, so this module adds no second reconciliation,
/// no second digest and no second persistence owner. It is not writable from
/// outside this module; the only way in is
/// [`Self::with_settled_owner_outcome`], which re-checks the binding and refuses
/// a receipt that names another operation, carries no canonical receipt, or is
/// still unknown. [`Self::retry_permitted`] then reads that stored outcome and
/// nothing else, and a completed effect is settled by reconciling the result its
/// owner retained through [`retained_improvement_completion`] rather than by
/// running again. Naming a rollback contract, supplying a caller string, or
/// using a proposal, new identity, or new idempotency key discharges nothing.
///
/// What the retry gate establishes is exactly this: the owner settled a
/// non-success terminal outcome, validated by the owner itself against a
/// canonical receipt whose disposition is `FAILURE` or `CANCELLED`, for this
/// obligation's exact operation identity. It is not a proof that nothing was
/// applied externally, and this type never claims to be one — a `PARTIAL`
/// disposition is the repository's own way of saying that named sub-effects did
/// apply while other gaps remain, and the gate does not and cannot rule that
/// out. The consequence is a bounded, honest one: a permitted retry is a newly
/// admitted operation under the same identity, never a replay of the receipt
/// that was rejected and never a second execution of a settled effect.
///
/// Both mechanisms depend on the effect owner, and that dependency is the honest
/// limit of this type. The owner attaches its own receipt through
/// [`Self::with_settled_owner_outcome`]; nothing in this workspace performs that
/// attach, so every obligation this crate builds is unresolved and every gate
/// here denies until the external effect owner settles one.
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
    /// The effect owner's own validated reconciliation outcome for this
    /// obligation's operation, or `None` while that outcome is unresolved.
    ///
    /// This is the effect/receipt owner's value, stored as given: it is never a
    /// projection, a re-derivation, or a locally invented outcome, so a stored
    /// receipt has already passed the owner's binding of outcome to operation
    /// id, idempotency key and state fence. It is boxed so the retained
    /// authorization and canonical receipt do not enlarge the obligation the
    /// disposition already holds behind one pointer.
    ///
    /// The field is private on purpose. `EffectReceipt` is an open struct whose
    /// fields are all public, so a public field here would let any caller write
    /// `{ outcome: Rejected, canonical_receipt: None, .. }` directly and open
    /// the retry gate without ever reaching the owner's validating constructor.
    /// The only writer is [`Self::with_settled_owner_outcome`], which re-checks
    /// the binding; the only direct writer is this module's single construction
    /// site [`unknown_effect_of`], which stores `None`, and it is reachable only
    /// through [`reconcile_retained_unknown_effect`].
    ///
    /// The value is not part of this obligation's wire form. The owner's receipt
    /// type carries no serializable projection here, and inventing one would be
    /// a second claim about an effect this module does not own, so a decoded
    /// obligation reads as unresolved — the denying direction — and the owner
    /// reattaches its value.
    #[serde(skip)]
    #[schemars(skip)]
    owner_outcome: Option<Box<EffectReceipt>>,
}

impl ImprovementUnknownEffect {
    /// Attaches the effect owner's settled outcome to this obligation.
    ///
    /// The one way a value ever reaches the private `owner_outcome` field from
    /// outside this module, and a checked seam rather than an assignment: the
    /// binding is re-verified here even though the field starts empty and
    /// nothing else can write it, because a receipt is an untrusted input at this
    /// boundary. Five conditions must hold together, and each refusal is a typed
    /// [`UnboundOwnerOutcome`] rather than a silently dropped value:
    ///
    /// 1. the outcome is terminal — an `UnknownOutcome` is a still-unsettled
    ///    effect, never a discharge;
    /// 2. a canonical receipt is present — an outcome the owner merely carried
    ///    without settling it against a receipt is not owner evidence, and this
    ///    is the exact case that must not open the retry gate;
    /// 3. the receipt's authorized effect names this obligation's own operation
    ///    id and idempotency key;
    /// 4. the canonical receipt itself names that same operation id and
    ///    idempotency key, so a receipt bound elsewhere cannot ride in on an
    ///    authorized effect that happens to match; and
    /// 5. the canonical receipt was recorded under the *same* state fence as the
    ///    authorized effect it settles, so an outcome observed under a superseded
    ///    authority epoch or an earlier resource generation cannot be replayed as
    ///    this operation's settlement (see `Self::binds_effect_fence`).
    ///
    /// It borrows `&mut self` rather than consuming `self`. The obligation is
    /// held by its owning disposition behind a `Box` and its owner updates it in
    /// place as evidence arrives, so a consuming setter would force every caller
    /// to move the value out of its disposition just to offer it a receipt, and
    /// would then have to carry the whole obligation back inside the error to
    /// avoid dropping a named external debt. Borrowing keeps the debt in place on
    /// both paths, so a refusal cannot lose it: the obligation stays owed and
    /// the gate stays closed. Consuming would also buy no extra guarantee, since
    /// the obligation is `Clone` and a caller can keep a copy of the unsettled
    /// value either way — what actually matters is that the field cannot be
    /// written un-checked, and that is the field's privacy plus the re-checks
    /// above, not the borrow.
    ///
    /// The identity compared here is the same one the read side
    /// (`owning_outcome`, which re-checks the authorized effect on every query)
    /// uses, so a receipt that could not be attached is also a receipt that could
    /// never have been believed.
    pub fn with_settled_owner_outcome(
        &mut self,
        receipt: EffectReceipt,
    ) -> Result<(), UnboundOwnerOutcome> {
        if matches!(&receipt.outcome, EffectOutcome::UnknownOutcome { .. }) {
            return Err(UnboundOwnerOutcome::StillUnsettled);
        }
        let Some(canonical) = receipt.canonical_receipt.as_ref() else {
            return Err(UnboundOwnerOutcome::UnsettledEffect);
        };
        let observed = &canonical.core.operation;
        let authorized = &receipt.authorized_effect.proposal.operation;
        if !self.binds_operation(authorized) {
            return Err(UnboundOwnerOutcome::ForeignOperation {
                side: "authorized_effect",
                operation_id: authorized.operation_id.as_str().to_owned(),
                idempotency_key: authorized.idempotency_key.as_str().to_owned(),
            });
        }
        if !self.binds_operation(observed) {
            return Err(UnboundOwnerOutcome::ForeignOperation {
                side: "canonical_receipt",
                operation_id: observed.operation_id.as_str().to_owned(),
                idempotency_key: observed.idempotency_key.as_str().to_owned(),
            });
        }
        if !Self::binds_effect_fence(authorized, observed) {
            return Err(UnboundOwnerOutcome::DivergentStateFence {
                authorized: Box::new(authorized.state_fence.clone()),
                observed: Box::new(observed.state_fence.clone()),
            });
        }
        self.owner_outcome = Some(Box::new(receipt));
        Ok(())
    }

    /// Returns whether a new attempt is allowed after an unknown effect.
    ///
    /// The answer is read from the effect owner's stored validated outcome and
    /// from nothing else — never from a constant, a reason string, or the mere
    /// presence of a lookup reference. An outcome the owner has not settled yet,
    /// a stored outcome whose bound operation is foreign to this obligation, a
    /// stored outcome whose canonical receipt was recorded under a different
    /// state fence than the authorized effect it settles, and a still-unknown
    /// outcome all deny. A completed effect denies as well: a committed or
    /// compensated outcome is reconciled from the result its owner already
    /// retained through [`retained_improvement_completion`], never authorized a
    /// second time.
    ///
    /// Opening the gate requires positive owner evidence, not a bare
    /// discriminant: the outcome must be `Rejected` *and* the owner must have
    /// actually settled the effect against a canonical receipt. A `Rejected`
    /// discriminant carrying no canonical receipt is precisely the
    /// merely-present-and-never-validated case, and it denies. A settled
    /// `Rejected` outcome is an owner-validated terminal outcome whose canonical
    /// receipt disposition is `FAILURE` or `CANCELLED`.
    ///
    /// The fence condition is the stale-outcome refusal, and it is a real
    /// comparison of two recorded values rather than a test that can only pass:
    /// `Self::binds_effect_fence` reads the state fence the authorized effect
    /// was admitted under and the state fence the canonical receipt was recorded
    /// under, and denies when they are not the same fence — which also keeps the
    /// "a canonical receipt must be present" requirement stated in one place
    /// rather than as a separate flag. What it cannot do is compare either of
    /// them against a *current* fence, because this module records none; the
    /// honest limit is stated in this module's header and is not papered over
    /// here.
    ///
    /// That is the whole of the guarantee, and it is stated rather than
    /// overstated: a non-success disposition is not by itself proof that nothing
    /// was applied externally — `ReceiptDisposition::Partial` is how this
    /// repository names sub-effects that did apply while other gaps remain, and
    /// the gate does not inspect the disposition to exclude that. So the attempt
    /// this permits is a newly admitted operation under this obligation's exact
    /// identity and commitments, never a replay of the receipt that was rejected
    /// and never a second execution of a settled effect.
    #[must_use]
    pub fn retry_permitted(&self) -> bool {
        self.owning_outcome().is_some_and(|receipt| {
            matches!(&receipt.outcome, EffectOutcome::Rejected)
                && receipt.canonical_receipt.as_ref().is_some_and(|canonical| {
                    Self::binds_effect_fence(
                        &receipt.authorized_effect.proposal.operation,
                        &canonical.core.operation,
                    )
                })
        })
    }

    /// Returns the retained result of a COMPLETED effect, or `None`.
    ///
    /// The private half of [`retained_improvement_completion`]: the single read
    /// of the owner's retained [`ReceiptEnvelope`], and the only public name for
    /// that read is that crate entry point. It is deliberately narrower than
    /// "any receipt that happens to carry a canonical receipt": only a `Committed`
    /// or `Compensated` outcome is a completion, so an unsettled, foreign,
    /// still-unknown, or merely non-success outcome has no completion to
    /// reconcile. The envelope is borrowed as the owner wrote it — neither copied
    /// nor revalidated here — so reconciling a completed effect reads the result
    /// its owner already holds.
    #[must_use]
    fn settled_completion_result(&self) -> Option<&ReceiptEnvelope> {
        let receipt = self.owning_outcome()?;
        if !matches!(
            &receipt.outcome,
            EffectOutcome::Committed | EffectOutcome::Compensated
        ) {
            return None;
        }
        receipt.canonical_receipt.as_ref()
    }

    /// Returns whether one owner-side operation binding is this obligation's own.
    ///
    /// The single identity comparison of this type, shared by the write side
    /// ([`Self::with_settled_owner_outcome`], which checks both the authorized
    /// effect and the retained canonical receipt) and the read side
    /// ([`Self::owning_outcome`], which re-checks the authorized effect on every
    /// query). Sharing it is deliberate: if the two sides could disagree about
    /// what "this obligation's operation" means, a receipt could be accepted at
    /// the seam and then silently ignored by the gate, which is a decision that
    /// rests on a private helper rather than on the identity.
    fn binds_operation(&self, operation: &OperationBinding) -> bool {
        operation.operation_id.as_str() == self.commitment.operation_ref.as_str()
            && operation.idempotency_key.as_str() == self.commitment.idempotency_key.as_str()
    }

    /// Returns whether one owner-side operation binding was recorded under the
    /// same state fence as the other.
    ///
    /// The staleness discriminator of this type, and the second half of the
    /// receipt owner's own terminal binding: the effect owner's
    /// `validate_terminal_receipt` relates the retained canonical receipt's
    /// `OperationBinding` to the authorized effect's on the operation id, the
    /// idempotency key **and** the state fence, and this module re-establishes
    /// the third of those three the same way it re-establishes the first two.
    ///
    /// The two values compared are both recorded and both owned elsewhere. They
    /// are the `state_fence` on the authorized effect's own `OperationBinding`
    /// and the `state_fence` on the operation binding inside the retained
    /// `ReceiptEnvelope`, reached only through `eliot_authority::EffectReceipt`.
    /// Each carries an authority epoch — an exact `(lineage_id, sequence)` tuple
    /// — and a resource generation, so a receipt settled under a superseded
    /// epoch or an earlier generation is a *different recorded value* from one
    /// settled under the fence the effect was authorized in, not a matter of
    /// wording. They are compared with `fences_match_exact`, the repository's own
    /// both-directions exact fence comparison, so a `None` revision on one side
    /// never satisfies a `Some` revision on the other and an equal sequence from
    /// a different lineage never matches. Nothing here is derived, defaulted,
    /// sampled or invented: no clock, no counter invented for this module, no
    /// nonce, and no constant that would make the comparison vacuous.
    ///
    /// `EffectReceipt` is an open struct whose three fields are all public, so a
    /// value arriving at this seam need not have passed
    /// `EffectReceipt::terminal`, and a receipt is treated here as the untrusted
    /// input it is. That is what makes this comparison load-bearing rather than
    /// decorative: a hand-built receipt can pair an authorized effect with a
    /// canonical receipt recorded under a different fence, and the operation
    /// identity alone would accept it.
    ///
    /// WHAT THIS DOES NOT ESTABLISH, stated rather than implied: the comparison
    /// is between two recorded fences inside one receipt, so it establishes that
    /// the outcome was settled under the fence of the effect it claims to settle.
    /// It does **not** establish that either fence is *current*. This module
    /// records no current fence, so a receipt that is internally consistent but
    /// was settled under a fence that has since been superseded still passes
    /// here. The value that would detect that is the admitted fence the candidate
    /// was proposed under, and it does not reach this crate: see the staleness
    /// note in this module's header for the exact missing input and the owner
    /// that has to supply it.
    fn binds_effect_fence(authorized: &OperationBinding, observed: &OperationBinding) -> bool {
        fences_match_exact(&authorized.state_fence, &observed.state_fence)
    }

    /// Returns the stored owner outcome only when the operation it was bound to
    /// is this obligation's own, so a receipt for another operation can answer
    /// neither the retry question nor the retained-result question here.
    ///
    /// The two comparable identities are the owner-side operation id and
    /// idempotency key against this obligation's committed logical operation and
    /// idempotency namespace, and they are the same pair on the write seam and on
    /// the read side. What that pair is NOT is an identity the effect owner
    /// already relates to this pipeline: the receipt owner's own
    /// `validate_terminal_receipt` relates the receipt's operation binding to the
    /// authorized effect's, both inside the receipt, and never to a
    /// [`ProposalCommitment`]. On the live improvement path
    /// `ProposalCommitment.operation_ref` carries a maintenance-observation
    /// identity, so no `OperationBinding` derived from it exists anywhere yet.
    /// The comparison is therefore a fail-closed binding, not an established
    /// correspondence: a receipt minted for a different operation is refused, and
    /// until an owner mints one for this operation there is simply no receipt to
    /// accept. That direction is the safe one, and it is why binding on this pair
    /// is preferred over binding on nothing at all.
    ///
    /// The owner's effect payload digest is deliberately not compared here because
    /// it digests the effect payload, while [`ProposalCommitment::digest`] digests
    /// the whole normalized proposal envelope, so the two are not the same
    /// preimage and matching them would assert an identity neither owner defines.
    ///
    /// The fence relation is different in kind from the operation identity above,
    /// and is not folded into this filter for that reason. The operation pair
    /// relates an owner-side value to this obligation's commitment and no owner
    /// defines that correspondence yet. The fence relation relates two values
    /// *inside* the same receipt, and the receipt owner defines it exactly —
    /// `validate_terminal_receipt` requires the retained canonical receipt's
    /// state fence to equal the authorized effect's. Filtering it in here would
    /// change what [`Self::settled_completion_result`] hands back, so it is
    /// applied where the unknown-outcome debt is discharged instead: at the
    /// attaching seam and at [`Self::retry_permitted`].
    fn owning_outcome(&self) -> Option<&EffectReceipt> {
        self.owner_outcome
            .as_deref()
            .filter(|receipt| self.binds_operation(&receipt.authorized_effect.proposal.operation))
    }

    /// The durable identity of this obligation, as its owner must commit it.
    ///
    /// The one projection of this obligation a caller may persist, and the one
    /// [`reconcile_retained_unknown_effect`] consumes. Every field is copied
    /// from this obligation — including the whole [`ProposalCommitment`] — so a
    /// consumer commits the Governor owner's own record rather than restating
    /// the candidate, experiment and operation identity as loose strings it could
    /// disagree with. That is what makes a retained debt re-bindable to the exact
    /// proposal bytes it was raised over: the digest, domain, encoding revision,
    /// algorithm, operation reference, idempotency namespace and canonical size
    /// travel together and are compared together.
    ///
    /// It carries no outcome, no receipt and no authority. The owner's validated
    /// outcome stays behind the private `owner_outcome` field, so a decoded
    /// identity is the unresolved direction on its own and the owner re-attaches
    /// what it holds.
    #[must_use]
    pub fn retained_identity(&self) -> ImprovementUnknownEffectIdentity {
        ImprovementUnknownEffectIdentity {
            candidate_id: self.candidate_id.clone(),
            experiment_id: self.experiment_id.clone(),
            commitment: self.commitment.clone(),
            owner_id: self.owner_id.clone(),
            forward_repair_ref: self.forward_repair_ref.clone(),
            invalidation_set: self.invalidation_set.clone(),
        }
    }
}

/// The durable identity of one unresolved external effect.
///
/// This is the record a named external debt is committed under and read back as,
/// so a reconciliation can be re-bound to the SAME candidate, experiment and
/// committed proposal bytes after a process restart instead of to a fresh
/// in-process value. I14.21 requires the unknown outcome to be preserved against
/// the operation's original identity and reconciled against the owner's own
/// record of that identity, and this is that identity as the owner writes it.
///
/// The commitment is the owner's own [`ProposalCommitment`] rather than a pair of
/// loose operation and idempotency strings, so a retained debt cannot disagree
/// with the commitment the pipeline computed for it, and
/// [`ImprovementUnknownEffectIdentity::validate`] re-checks the content identity
/// of that commitment against this build's constants before anything reads it.
///
/// It carries NO outcome, NO receipt, NO permit and NO authority. The effect
/// owner's validated outcome is attached to the rebuilt obligation through
/// [`ImprovementUnknownEffect::with_settled_owner_outcome`], so a decoded
/// identity alone never discharges a debt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementUnknownEffectIdentity {
    /// Candidate whose external activation or effect outcome is unresolved.
    pub candidate_id: String,
    /// Exact bounded experiment the unresolved effect belongs to.
    pub experiment_id: String,
    /// The Governor owner's own committed content identity for that candidate.
    pub commitment: ProposalCommitment,
    /// Owner that holds the unresolved reconciliation debt.
    pub owner_id: String,
    /// Forward-repair reference the checked rollback contract named.
    pub forward_repair_ref: String,
    /// Invalidation targets the checked rollback contract covers, in the
    /// contract's own committed order.
    pub invalidation_set: Vec<String>,
}

impl ProposalCommitment {
    /// Refuses a commitment that does not carry this build's checked content
    /// identity.
    ///
    /// The three components compared are the SAME constants
    /// [`commitment_of`] stamps and the same ones
    /// [`check_checked_record_identity`] enforces, read against the ORIGINAL
    /// recorded values rather than against anything recomputed from local
    /// state. A commitment written under another domain, encoding revision or
    /// algorithm is a typed refusal rather than a tolerated record, and nothing
    /// is padded, rounded or reinterpreted toward the current identity.
    ///
    /// This is the one commitment-identity comparison in the crate.
    /// [`ImprovementUnknownEffectIdentity::validate`] and
    /// [`ImprovementTerminalDecision::validate`] both delegate to it, so the
    /// durable obligation and the durable terminal decision cannot drift apart in
    /// what counts as a current record.
    pub fn validate(&self) -> Result<(), UncheckedRecordIdentity> {
        for (component, found, expected) in [
            (
                "commitment.domain",
                self.domain.as_str(),
                IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN,
            ),
            (
                "commitment.encoding_version",
                self.encoding_version.as_str(),
                IMPROVEMENT_PROPOSAL_ENCODING_VERSION,
            ),
            (
                "commitment.algorithm",
                self.algorithm.as_str(),
                IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM,
            ),
        ] {
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
}

impl ImprovementUnknownEffectIdentity {
    /// Refuses a retained identity whose commitment does not carry this build's
    /// checked content identity.
    ///
    /// The check is [`ProposalCommitment::validate`] itself, so this module has
    /// exactly one statement of what a current commitment is. A retained record
    /// written under another domain, encoding revision or algorithm is a typed
    /// refusal rather than a tolerated debt, and nothing is padded, rounded or
    /// reinterpreted toward the current identity.
    ///
    /// The candidate, experiment and owner identities are not checked here: they
    /// are compared against the current checked record by
    /// [`reconcile_retained_unknown_effect`], which is the only place that
    /// holds both sides.
    pub fn validate(&self) -> Result<(), UncheckedRecordIdentity> {
        self.commitment.validate()
    }
}

/// The independent evaluation identities one terminal decision was made against.
///
/// This is a projection of the run's own [`ActivationEvidence`], field for field,
/// and nothing else. It exists because a terminal decision has to be durable, and
/// a durable decision that cannot say WHICH evaluation it was made against cannot
/// be re-proved by a later reader: the reader holds the record, not the process
/// that produced it. Every field is copied, so a decision can never carry an
/// evaluation the run did not hold.
///
/// It carries no outcome authority. [`ImprovementEvidenceExecution`] is the
/// machine state the pipeline read, `independent` and `verifier_passed` are the
/// two booleans it read, and the three references name the run and the raw
/// measurement that were (or were not) recorded. Nothing here decides anything:
/// the decision's own disposition is the verdict, and this is the evidence the
/// verdict is checked against.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementEvaluationBinding {
    /// Stable evidence identity the run held.
    pub evidence_id: String,
    /// Verifier principal the run held.
    pub verifier_id: String,
    /// Whether the run's evidence record stated the verifier was independent.
    pub independent: bool,
    /// Whether the run's evidence record stated the verifier passed.
    pub verifier_passed: bool,
    /// The `I0.5` execution status the run's evidence record carried.
    pub execution: ImprovementEvidenceExecution,
    /// Exact run the run's evidence record named; may be empty when none ran.
    pub run_ref: String,
    /// Exact content revision the run's evidence record named.
    pub content_revision_ref: String,
    /// Raw measured evidence reference the run's evidence record named.
    pub raw_evidence_ref: String,
    /// Candidate the run's evidence record was bound to.
    pub bound_candidate_id: String,
    /// Experiment the run's evidence record was bound to.
    pub bound_experiment_id: String,
}

impl ImprovementEvaluationBinding {
    /// Copies one run's evaluation record into its durable binding.
    ///
    /// The single construction site. Every field is a copy, so the binding cannot
    /// describe an evaluation the run did not hold, and the reader compares the
    /// binding against the decision's own disposition.
    fn of(evidence: &ActivationEvidence) -> Self {
        Self {
            evidence_id: evidence.evidence_id.clone(),
            verifier_id: evidence.verifier_id.clone(),
            independent: evidence.independent,
            verifier_passed: evidence.verifier_passed,
            execution: evidence.execution,
            run_ref: evidence.run_ref.clone(),
            content_revision_ref: evidence.content_revision_ref.clone(),
            raw_evidence_ref: evidence.raw_evidence_ref.clone(),
            bound_candidate_id: evidence.bound_candidate_id.clone(),
            bound_experiment_id: evidence.bound_experiment_id.clone(),
        }
    }
}

/// Durable identity of one terminal improvement decision.
///
/// This is the record a consumer reads when the process that made the decision is
/// gone. It binds the decision to the EXACT candidate identity and candidate
/// REVISION it was made on, to the exact bounded experiment, to the exact
/// committed proposal bytes when the run reached the admitted branch, to the
/// evaluation record the verdict was made against, and to the pipeline's own
/// advisory-only disposition verbatim.
///
/// # Why the candidate revision is bound
///
/// A candidate's revision advances when the deduplication registry merges a new
/// evidence lineage into it. A decision recorded against an earlier revision was
/// made about content that has since changed, so a later reader must be able to
/// see that from the record alone. Binding the revision makes the comparison
/// possible without keeping the proposal bytes; it does not decide the
/// comparison, which stays with the owner that holds the current candidate.
///
/// # What this record is NOT
///
/// It is not a permit, not an activation, not an effect outcome, and not an
/// authority to retry. `ImprovementTerminalDisposition::CanaryAdmitted` inside it
/// still carries `execution_authorized == false` and still requires the Kernel
/// `#11` owner to authorize and execute activation independently. The retry and
/// completion booleans a consumer reads are the Governor owner's own answers,
/// and the owner outcome they depend on stays private to this module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImprovementTerminalDecision {
    /// Candidate identity the decision was made on.
    pub candidate_id: String,
    /// Candidate REVISION the decision was made on.
    pub candidate_revision: u64,
    /// Proposal identity the decision was made over.
    pub proposal_id: String,
    /// Bounded experiment the decision was made over.
    pub experiment_id: String,
    /// Logical operation the decision belongs to.
    pub operation_ref: String,
    /// Idempotency namespace the decision belongs to.
    pub idempotency_key: String,
    /// The single content commitment this run committed, present EXACTLY when
    /// the run published one. Only the admitted branch publishes a checked
    /// current record, so only that branch carries a commitment here; a refusal
    /// disposition commits nothing and carries none.
    pub proposal_commitment: Option<ProposalCommitment>,
    /// The independent evaluation record this run held, whatever its status.
    ///
    /// Present whenever the run held an evaluation record at all, including the
    /// never-ran one. Its absence means the run held no evaluation record, which
    /// a later reader re-checks against the disposition.
    pub evaluation: Option<ImprovementEvaluationBinding>,
    /// The pipeline's own advisory-only terminal disposition, verbatim.
    pub disposition: ImprovementTerminalDisposition,
}

/// Why a durable terminal decision was refused.
///
/// Every variant is a refusal to BELIEVE the record, so none of them ever
/// produces a decision, a handoff, or a permit: the disposition stays where it
/// was and the caller learns the record cannot be read as a current decision.
/// They are distinct because they are distinct facts — a missing bounded
/// experiment, an evaluation bound to another candidate, a verdict with no
/// evaluation record behind it, and a verdict that disagrees with the recorded
/// evidence are four different things a reader has to go and fix.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UnboundDecisionRecord {
    /// A required identity is missing or past the admitted byte ceiling, so the
    /// record does not establish which decision it is.
    #[error("improvement terminal decision identity {field} is absent or oversized")]
    MissingIdentity {
        /// Which identity the record left unusable.
        field: &'static str,
    },
    /// The decision names no bounded experiment, or names a different one than
    /// the evaluation and the admitted handoff bind.
    #[error("improvement terminal decision experiment binding is not established: {relation}")]
    UnboundExperiment {
        /// Static identity of the diverging experiment relation.
        relation: &'static str,
    },
    /// The decision's disposition is not the one its own bound records support.
    #[error("improvement terminal decision disagrees with its recorded evidence: {relation}")]
    UnverifiableVerdict {
        /// Static identity of the diverging verdict relation.
        relation: &'static str,
    },
    /// A recorded commitment does not carry this build's checked content identity.
    #[error("improvement terminal decision commitment identity is unchecked: {0}")]
    UncheckedCommitment(#[from] UncheckedRecordIdentity),
}

impl ImprovementTerminalDecision {
    /// Re-proves this record against its OWN fields, with no other input.
    ///
    /// This is the reader half of [`improvement_terminal_decision`], and it is
    /// what a later pass uses after the process that made the decision is gone.
    /// It is deliberately narrower than the producer: it can compare the
    /// decision's identities with each other, but it cannot re-derive the
    /// proposal bytes, so it never claims the commitment is a current one for
    /// THIS proposal — only that it carries this build's checked commitment
    /// identity, which is what a spliced document would fail.
    ///
    /// The four questions are decided in the order they differ:
    ///
    /// 1. every identity the record must carry is present and bounded;
    /// 2. the bounded experiment is established — named once, and named by the
    ///    evaluation record too when one is present;
    /// 3. the disposition is the one the bound records support: only the admitted
    ///    branch may carry a commitment and an executed evaluation, and only the
    ///    refused branches must carry neither;
    /// 4. the admitted branch's own handoff agrees with the record's identity,
    ///    with the recorded commitment, and carries no execution authority.
    pub fn validate(&self) -> Result<(), UnboundDecisionRecord> {
        self.check_identities()?;
        if let Some(commitment) = self.proposal_commitment.as_ref() {
            commitment.validate()?;
        }
        // The evaluation, when present, must be bound to the SAME candidate and
        // experiment the decision names. An evaluation of some other candidate is
        // not evidence about this one, whatever its own status.
        if let Some(evaluation) = self.evaluation.as_ref() {
            for (relation, bound, decided) in [
                (
                    "decision-evaluation: candidate-binding-mismatch",
                    evaluation.bound_candidate_id.as_str(),
                    self.candidate_id.as_str(),
                ),
                (
                    "decision-evaluation: experiment-binding-mismatch",
                    evaluation.bound_experiment_id.as_str(),
                    self.experiment_id.as_str(),
                ),
            ] {
                if bound != decided {
                    return Err(UnboundDecisionRecord::UnboundExperiment { relation });
                }
            }
        }
        match &self.disposition {
            ImprovementTerminalDisposition::CanaryAdmitted { handoff } => {
                self.check_admitted_branch(handoff)
            }
            // Every refused branch, named explicitly so a new disposition is a
            // compile error here until its own answer is decided rather than
            // inheriting an unexamined default.
            ImprovementTerminalDisposition::Rejected { .. }
            | ImprovementTerminalDisposition::Inconclusive { .. }
            | ImprovementTerminalDisposition::RegressionRejected { .. }
            | ImprovementTerminalDisposition::UnknownRequiresReconciliation { .. }
            | ImprovementTerminalDisposition::RolledBack { .. }
            | ImprovementTerminalDisposition::NoProgress { .. }
            | ImprovementTerminalDisposition::Blocked { .. } => self.check_refused_branch(),
        }
    }

    /// Requires every identity this record must carry to be present and bounded.
    ///
    /// Presence, not shape: an absent identity means the record names no
    /// candidate, no proposal, no bounded experiment or no operation, and an
    /// identity past the admitted reference ceiling cannot be read back inside
    /// the bounds this crate commits under. Both are the same fact about this
    /// record — it does not establish which decision this is — so both are
    /// [`UnboundDecisionRecord::MissingIdentity`].
    fn check_identities(&self) -> Result<(), UnboundDecisionRecord> {
        for (field, value) in [
            ("candidate_id", self.candidate_id.as_str()),
            ("proposal_id", self.proposal_id.as_str()),
            ("experiment_id", self.experiment_id.as_str()),
            ("operation_ref", self.operation_ref.as_str()),
            ("idempotency_key", self.idempotency_key.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > IMPROVEMENT_MAX_REFERENCE_BYTES {
                return Err(UnboundDecisionRecord::MissingIdentity { field });
            }
        }
        Ok(())
    }

    /// Requires the ADMITTED branch to arrive with everything it claims.
    ///
    /// The admitted branch is the only one that can support activation, so it is
    /// the only one that must arrive with the committed proposal bytes and with
    /// an executed, independent, passing evaluation by a verifier principal that
    /// is neither the experiment executor nor the admitting Governor owner. A
    /// verdict with no evaluation record behind it, or with a recorded evaluation
    /// that never executed or did not pass, is a verdict that disagrees with its
    /// own evidence — and it is REFUSED, never downgraded to a rejection and
    /// never treated as a canary.
    ///
    /// The handoff is then re-proved against the record: same candidate, same
    /// experiment, same operation and idempotency namespace, the same committed
    /// bytes, and no execution authority. A handoff this crate can never build is
    /// not a stronger decision when it appears in a durable record.
    fn check_admitted_branch(
        &self,
        handoff: &ImprovementCanaryHandoff,
    ) -> Result<(), UnboundDecisionRecord> {
        let Some(commitment) = self.proposal_commitment.as_ref() else {
            return Err(UnboundDecisionRecord::UnverifiableVerdict {
                relation: "decision-admitted: no-committed-proposal-bytes",
            });
        };
        let Some(evaluation) = self.evaluation.as_ref() else {
            return Err(UnboundDecisionRecord::UnverifiableVerdict {
                relation: "decision-admitted: no-evaluation-record",
            });
        };
        if evaluation.execution != ImprovementEvidenceExecution::Executed
            || !evaluation.independent
            || !evaluation.verifier_passed
        {
            return Err(UnboundDecisionRecord::UnverifiableVerdict {
                relation: "decision-admitted: evaluation-is-not-executed-independent-and-passing",
            });
        }
        if !evaluation.verifier_id.starts_with(VERIFIER_OWNER_FAMILY)
            || evaluation.verifier_id == TESTD_OWNER
            || evaluation.verifier_id == IMPROVEMENT_PIPELINE_OWNER
            || evaluation.verifier_id == self.operation_ref
        {
            return Err(UnboundDecisionRecord::UnverifiableVerdict {
                relation: "decision-admitted: evaluator-is-not-an-independent-verifier-principal",
            });
        }
        for (relation, held, recorded) in [
            (
                "decision-admitted: handoff-candidate-mismatch",
                handoff.candidate_id.as_str(),
                self.candidate_id.as_str(),
            ),
            (
                "decision-admitted: handoff-experiment-mismatch",
                handoff.experiment_id.as_str(),
                self.experiment_id.as_str(),
            ),
            (
                "decision-admitted: handoff-operation-mismatch",
                handoff.operation_ref.as_str(),
                self.operation_ref.as_str(),
            ),
            (
                "decision-admitted: handoff-idempotency-mismatch",
                handoff.idempotency_key.as_str(),
                self.idempotency_key.as_str(),
            ),
        ] {
            if held != recorded {
                return Err(UnboundDecisionRecord::UnverifiableVerdict { relation });
            }
        }
        if &handoff.proposal_commitment != commitment {
            return Err(UnboundDecisionRecord::UnverifiableVerdict {
                relation: "decision-admitted: handoff-commitment-differs-from-the-recorded-one",
            });
        }
        if handoff.execution_authorized {
            return Err(UnboundDecisionRecord::UnverifiableVerdict {
                relation: "decision-admitted: handoff-claims-execution-authority",
            });
        }
        Ok(())
    }

    /// Requires a REFUSED branch to have committed nothing.
    ///
    /// No refused branch publishes a checked current record, so none of them may
    /// carry a proposal commitment: a refusal that carries committed proposal
    /// bytes is a spliced document, and a reader that believed it would read a
    /// rejection as though the same bytes had been admitted. This is the same
    /// direction as the admitted branch's checks — what a decision claims must be
    /// what its own records support — read for the branches that claim nothing.
    fn check_refused_branch(&self) -> Result<(), UnboundDecisionRecord> {
        if self.proposal_commitment.is_some() {
            return Err(UnboundDecisionRecord::UnverifiableVerdict {
                relation: "decision-refused: a-refused-decision-committed-proposal-bytes",
            });
        }
        Ok(())
    }
}

/// Builds the durable terminal decision for one checked pipeline run.
///
/// This is the ONE producer of [`ImprovementTerminalDecision`] and the seam a
/// caller reaches for after [`run_improvement_candidate_pipeline`] returned a
/// disposition. Every field is copied from a record the run already checked: the
/// candidate and proposal identities from the proposal, the bounded experiment
/// from the plan, the evaluation binding from the run's own
/// [`ActivationEvidence`], and the disposition verbatim. Nothing is derived,
/// recomputed, or supplied by the caller except the candidate REVISION, which the
/// caller holds because the candidate record is the candidate owner's.
///
/// `current` is the run's own checked current record, read out of its canary
/// handoff. It is present EXACTLY on the admitted branch, and that is checked
/// rather than assumed: a caller that pairs the committed bytes with a refusal,
/// or omits them from an admission, is refused.
///
/// `candidate_id` is the candidate identity the caller's own record holds, and it
/// must equal the proposal's. That is the "bound to the same candidate identity"
/// half of the record, and it is a refusal rather than a silent rewrite.
/// `candidate_revision` is not checked against the candidate record here: the
/// owner of the candidate holds that, and the caller checks it against the record
/// it read before committing.
///
/// Four refusals are reachable and all of them are typed
/// [`UnboundDecisionRecord`] values, never a default, a skip, or a
/// treat-as-admitted:
///
/// 1. a MISSING BOUNDED EXPERIMENT — the plan names none, or the evaluation is
///    bound to a different candidate or experiment than the proposal;
/// 2. a VERDICT WITHOUT ITS EVALUATION RECORD — the admitted branch arriving with
///    no evaluation record, or with one that never executed, is not independent, or
///    did not pass;
/// 3. A VERDICT THAT DISAGREES WITH THE RECORDED EVIDENCE — a refused branch
///    carrying committed proposal bytes, a committed identity that is not this
///    build's, or an admitted handoff that disagrees with the record about the
///    candidate, the experiment, the operation, or the commitment;
/// 4. a MISSING IDENTITY — a record naming no candidate, proposal, experiment or
///    operation at all.
///
/// The candidate REVISION is the fourth obligation this record carries and the
/// only one this crate cannot check for itself; see [`ImprovementTerminalDecision`]
/// for why it is bound and what it does and does not establish.
pub fn improvement_terminal_decision(
    candidate_id: &str,
    candidate_revision: u64,
    proposal: &ImprovementProposal,
    experiment: &ExperimentPlan,
    evidence: &ActivationEvidence,
    current: Option<&ImprovementCurrentProposal>,
    disposition: &ImprovementTerminalDisposition,
) -> Result<ImprovementTerminalDecision, UnboundDecisionRecord> {
    if candidate_id.trim().is_empty() || candidate_id != proposal.candidate_id.as_str() {
        return Err(UnboundDecisionRecord::UnboundExperiment {
            relation: "decision-proposal: candidate-identity-mismatch",
        });
    }
    if experiment.experiment_id.trim().is_empty() {
        return Err(UnboundDecisionRecord::UnboundExperiment {
            relation: "decision-plan: names-no-bounded-experiment",
        });
    }
    if evidence.bound_candidate_id != proposal.candidate_id {
        return Err(UnboundDecisionRecord::UnboundExperiment {
            relation: "decision-evaluation: candidate-binding-mismatch",
        });
    }
    if evidence.bound_experiment_id != experiment.experiment_id {
        return Err(UnboundDecisionRecord::UnboundExperiment {
            relation: "decision-evaluation: experiment-binding-mismatch",
        });
    }
    let decision = ImprovementTerminalDecision {
        candidate_id: candidate_id.to_owned(),
        candidate_revision,
        proposal_id: proposal.proposal_id.clone(),
        experiment_id: experiment.experiment_id.clone(),
        operation_ref: proposal.operation_ref.clone(),
        idempotency_key: proposal.idempotency_key.clone(),
        proposal_commitment: current.map(|current| current.commitment.clone()),
        evaluation: Some(ImprovementEvaluationBinding::of(evidence)),
        disposition: disposition.clone(),
    };
    decision.validate()?;
    Ok(decision)
}

/// Why a receipt was refused as this obligation's settled owner outcome.
///
/// Every variant is a refusal to *believe* something, so none of them discharges
/// the obligation: the debt stays owed and the retry gate stays closed. They are
/// distinct because they are distinct facts about the receipt — a still-unknown
/// effect, an effect the owner never settled against a receipt, a receipt that
/// belongs to a different operation, and an outcome recorded under a state fence
/// other than the one its effect was authorized under are four different things a
/// caller has to go and fix.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UnboundOwnerOutcome {
    /// The outcome is still `UnknownOutcome`, so the effect is not settled at
    /// all. The owner must reconcile it first.
    #[error("improvement owner outcome is still unknown: the effect is unsettled")]
    StillUnsettled,
    /// The outcome carries no canonical receipt, so the owner never validated it
    /// against one. Presence of an outcome is not evidence of anything.
    #[error(
        "improvement owner outcome carries no canonical receipt: the owner never settled the effect"
    )]
    UnsettledEffect,
    /// The receipt is bound to a different operation than this obligation's.
    /// `side` names which part of the receipt disagrees: the authorized effect
    /// the owner settled, or the canonical receipt it retained.
    #[error(
        "improvement owner outcome {side} is bound to another operation: {operation_id} / {idempotency_key}"
    )]
    ForeignOperation {
        /// Which side of the receipt carries the foreign identity.
        side: &'static str,
        /// Operation id that side of the receipt is bound to.
        operation_id: String,
        /// Idempotency key that side of the receipt is bound to.
        idempotency_key: String,
    },
    /// The two halves of the receipt were recorded under different state
    /// fences, so the outcome is not a settlement of the effect it rides on.
    ///
    /// `authorized` is the fence the owner admitted the effect under and
    /// `observed` is the fence the retained canonical receipt was recorded
    /// under. They are the two recorded values the staleness refusal actually
    /// compares, carried whole so the owner can see which epoch or generation
    /// disagrees rather than being told only that something did. This is the
    /// refusal the effect owner itself issues as `ReceiptMismatch` when it
    /// builds a terminal receipt; a hand-built `EffectReceipt` reaches this
    /// module without passing that constructor, so the relation is re-checked
    /// here.
    #[error(
        "improvement owner outcome was recorded under a different state fence than the effect it settles: authorized {authorized:?} vs canonical receipt {observed:?}"
    )]
    DivergentStateFence {
        /// Fence the authorized effect was admitted under.
        ///
        /// Boxed for the same storage reason `owner_outcome` is: two whole
        /// fences inline made this error enum larger than every other value on
        /// the reconciliation seam, and the two are only ever read together
        /// through a reference. This is a storage detail — the comparison that
        /// produces them is unchanged and both recorded values are still
        /// carried whole.
        authorized: Box<StateFence>,
        /// Fence the retained canonical receipt was recorded under.
        observed: Box<StateFence>,
    },
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
    /// reconciliation. The obligation also carries the effect owner's own
    /// validated outcome, and [`ImprovementUnknownEffect::retry_permitted`]
    /// answers from that value alone: it denies while the owner has not settled
    /// the effect, denies a receipt carrying no canonical receipt, denies a
    /// foreign or still-unknown outcome, and denies a completed effect, whose
    /// retained result is read instead through
    /// [`retained_improvement_completion`]. It permits a retry only from an
    /// owner-settled non-success terminal outcome — a `Rejected` outcome the
    /// owner validated against a canonical receipt whose disposition is `FAILURE`
    /// or `CANCELLED`, bound to this obligation's exact operation identity. That
    /// is what the gate establishes and no more: a non-success disposition is not
    /// itself proof that nothing was applied externally, so a permitted retry is
    /// a newly admitted operation under that same identity, never a replay of the
    /// rejected receipt.
    UnknownRequiresReconciliation {
        /// Exact unresolved external effect owed by its owner.
        obligation: Box<ImprovementUnknownEffect>,
    },
    /// Retained historical representation of an observed completed rollback.
    ///
    /// The admission-only pipeline in this module never constructs this
    /// variant: it receives a rollback contract, never a rollback execution or
    /// result receipt, so a bare `contract_ref` names no validated result. When
    /// an owner has validated one, the value is reached through the unknown
    /// effect's own outcome — the receipt owner settles an effect, the
    /// obligation carries that receipt, and
    /// [`retained_improvement_completion`] reads the retained result off it —
    /// rather than by restating a completion as a disposition variant. Bytes
    /// written under this variant stay readable so history is preserved, but
    /// they are an unqualified historical observation and must not be presented
    /// as newly verified completed effects.
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
#[error(
    "checked identity mismatch on {component}: record carries {found}, this build checks {expected}"
)]
pub struct UncheckedRecordIdentity {
    /// Which identity component of the record disagreed.
    pub component: &'static str,
    /// The identity the record carries.
    pub found: String,
    /// The identity this build checks.
    pub expected: &'static str,
}

/// One wire-revision component of a record that this build does not read.
///
/// The wire revision describes the serialized SHAPE of the record, not the
/// content it commits, so it needs its own named refusal: folding a `u32` into
/// the string components of [`UncheckedRecordIdentity`] would render it as
/// prose and let a reader guess which revision was meant. The value is carried
/// whole, so a caller cannot repair the record by guessing, and no revision is
/// substituted, padded, or rounded toward the one this build checks.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("checked wire revision mismatch: record carries {found}, this build checks {expected}")]
pub struct UncheckedWireRevision {
    /// The wire revision the record carries.
    pub found: u32,
    /// The wire revision this build checks.
    pub expected: u32,
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
    /// A record presented for reading was written under another wire revision,
    /// so its serialized shape is not the one this build decodes.
    #[error("improvement record wire revision is not the checked version: {0}")]
    UncheckedWireRevision(#[from] UncheckedWireRevision),
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
    /// The effect owner offered a reconciliation outcome this obligation refused.
    ///
    /// The refusal is carried whole, so a still-unsettled effect, an outcome
    /// never settled against a canonical receipt, a receipt bound to another
    /// operation and an outcome recorded under a divergent state fence stay four
    /// distinct facts across this layer boundary instead of collapsing into one
    /// reason string. A refusal never discharges the obligation: the debt stays
    /// owed and the retry gate stays closed, which is the same denying direction
    /// an absent owner outcome produces.
    #[error("improvement owner outcome was refused: {0}")]
    UnboundOwnerOutcome(#[from] UnboundOwnerOutcome),
    /// The durable terminal decision for this run was refused.
    ///
    /// This is the seam a caller reaches for after the pipeline returned a
    /// disposition, and it is the one place on the improvement path where a
    /// decision can fail to be RECORDED even though the pipeline produced one.
    /// The refusal travels whole, so a missing bounded experiment, a verdict with
    /// no evaluation record behind it, and a verdict that disagrees with its own
    /// recorded evidence stay distinguishable across this layer boundary. None of
    /// them produces a record, a handoff, or a permit, and none of them is
    /// resolved into a weaker disposition: the caller sees the refusal and the
    /// decision it belonged to is not durable.
    #[error("improvement terminal decision record was refused: {0}")]
    UnboundDecisionRecord(#[from] UnboundDecisionRecord),
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

/// Refuses a handoff written under another wire revision of this record shape.
///
/// [`check_checked_record_identity`] compares the CONTENT identity a proposal
/// commitment carries: its domain, encoding revision, and algorithm. The wire
/// revision is a different identity and answers a different question — which
/// serialized SHAPE the record was written under — so it is checked separately
/// against the SAME constant the producer stamps into
/// [`ImprovementCanaryHandoff::wire_revision`].
///
/// The comparison is against the ORIGINAL value the producer recorded. Nothing
/// is recomputed, defaulted, rounded, or reinterpreted: a handoff carrying
/// revision `7` is refused as revision `7`, is not padded to the current
/// revision, and is not read as though the current shape had produced it. The
/// refusal is typed and carries both revisions, so a caller cannot repair the
/// record by guessing.
pub fn check_handoff_wire_revision(
    handoff: &ImprovementCanaryHandoff,
) -> Result<(), UncheckedWireRevision> {
    if handoff.wire_revision != IMPROVEMENT_PIPELINE_WIRE_REVISION {
        return Err(UncheckedWireRevision {
            found: handoff.wire_revision,
            expected: IMPROVEMENT_PIPELINE_WIRE_REVISION,
        });
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
    if let Some(retained) = retained {
        return compare_improvement_commitments(retained, current);
    }
    check_checked_record_identity(current)?;
    Ok(ImprovementReplayAssessment::NoRetainedPrior {
        commitment: current.commitment.clone(),
    })
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
    Ok(
        if let Some(assessment) = same_operation_replay(retained, current) {
            assessment
        } else if let Some(assessment) = unestablished_projection(retained, current) {
            assessment
        } else if let Some(assessment) = material_repeat(retained, current) {
            assessment
        } else {
            changed_discriminator(retained, current)
        },
    )
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
/// An unknown activation outcome is an unknown effect, not a missing-evidence
/// sentence: it reaches the same [`ImprovementUnknownEffect`] obligation the
/// reconciliation decision reaches, built by the same single construction site.
/// Routing it anywhere else would make a disposition variant, not the owner's
/// validated outcome, decide whether the effect may be attempted again. The
/// built obligation carries the owner from the prior decision, and its private
/// `owner_outcome` field starts unresolved: the checked records this run holds
/// contain no owner-validated outcome, so the effect owner attaches one through
/// [`ImprovementUnknownEffect::with_settled_owner_outcome`] and
/// [`ImprovementUnknownEffect::retry_permitted`] then answers from that value
/// alone.
pub fn reconcile_unknown_activation(
    prior: &ImprovementAdmissionDecision,
    current: &ImprovementCurrentProposal,
    rollback: &RollbackContract,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    check_checked_record_identity(current)?;
    Ok(match prior {
        ImprovementAdmissionDecision::RequiresReconciliation { owner_id, .. } => {
            reconcile_retained_unknown_effect(
                &unknown_effect_identity_of(current, rollback, owner_id),
                current,
                None,
            )?
        }
        // An unknown activation outcome is an unknown effect owed by the owner
        // that must stay named for the run, so it is the same typed obligation
        // and not an evidence gap. Building a sentence here would hand the
        // retry decision to `Inconclusive`, which is the variant that permits
        // another attempt, and the decision would then rest on which variant a
        // formatted message happened to land in rather than on any owner
        // outcome.
        ImprovementAdmissionDecision::AdmitForExperiment {
            rollback_owner_id, ..
        } => reconcile_retained_unknown_effect(
            &unknown_effect_identity_of(current, rollback, rollback_owner_id),
            current,
            None,
        )?,
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
    })
}

/// Reconciles one retained unresolved external effect against the owner's outcome.
///
/// This is the single place a named external debt is discharged, and the one
/// public way a caller turns a persisted
/// [`ImprovementUnknownEffectIdentity`] back into a live typed obligation. The
/// guarantee is established here in the order its questions differ:
///
/// 1. **The retained record must be readable by this build.** `retained.validate`
///    re-checks the ORIGINAL recorded domain, encoding revision and algorithm of
///    the retained commitment, and `current` is checked by
///    [`check_checked_record_identity`]. A record written under another identity
///    is a typed refusal on either side, and nothing is recomputed, padded or
///    reinterpreted toward the current identity.
/// 2. **The retained record must BE this operation's debt.** The comparison is
///    over content, never over presence or shape: the retained commitment must
///    equal the current checked commitment as a whole record - domain, encoding
///    revision, algorithm, operation reference, idempotency namespace, digest
///    and canonical size together - and the retained candidate and experiment
///    identities must equal the ones the current record commits. A foreign or
///    stale debt, or a spliced one naming another candidate, experiment or
///    operation, is refused and discharges nothing.
/// 3. **The owner's outcome is consumed through the owner's own checked seam.**
///    `owner_outcome` is the effect owner's own [`EffectReceipt`] and is attached
///    through [`ImprovementUnknownEffect::with_settled_owner_outcome`], which
///    re-checks that the outcome is terminal, that a canonical receipt is
///    present, that the authorized effect and that receipt both name this
///    obligation's exact operation id and idempotency key, and that the two were
///    recorded under the same state fence. An unknown, unsettled, foreign or
///    divergent outcome is a typed [`UnboundOwnerOutcome`] and the debt stays
///    owed. `None` is the absent-outcome case and the same denying direction: the
///    owner has not settled the effect.
/// 4. **The returned disposition carries the answer, not a verdict about it.**
///    [`improvement_retry_permitted`] then answers from the stored outcome alone,
///    and [`retained_improvement_completion`] returns the retained result of a
///    COMPLETED effect rather than authorizing a second execution of it. This
///    function decides neither.
///
/// [`reconcile_unknown_activation`] routes both of its unknown arms through here
/// with an absent owner outcome, so a decision-mapped debt and a
/// read-back-and-reconciled debt reach the same obligation through the same
/// checks: there is no second reconciliation path and no second identity.
pub fn reconcile_retained_unknown_effect(
    retained: &ImprovementUnknownEffectIdentity,
    current: &ImprovementCurrentProposal,
    owner_outcome: Option<&EffectReceipt>,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    retained.validate()?;
    check_checked_record_identity(current)?;
    // CONTENT, not existence or shape. The whole committed record travels and is
    // compared together, so a debt raised over other proposal bytes, another
    // operation namespace or another idempotency namespace stays a different debt
    // even when every other field it carries happens to look familiar.
    if retained.commitment != current.commitment {
        return Err(PipelineError::UnboundRelation {
            relation: "retained-unknown-effect: commitment-is-not-the-current-checked-record",
        });
    }
    for (relation, retained_id, current_id) in [
        (
            "retained-unknown-effect: candidate-identity-mismatch",
            retained.candidate_id.as_str(),
            current.candidate_id.as_str(),
        ),
        (
            "retained-unknown-effect: experiment-identity-mismatch",
            retained.experiment_id.as_str(),
            current.experiment_plan.experiment_id.as_str(),
        ),
    ] {
        if retained_id != current_id {
            return Err(PipelineError::UnboundRelation { relation });
        }
    }
    let mut obligation = unknown_effect_of(retained);
    if let Some(receipt) = owner_outcome {
        obligation.with_settled_owner_outcome(receipt.clone())?;
    }
    Ok(
        ImprovementTerminalDisposition::UnknownRequiresReconciliation {
            obligation: Box::new(obligation),
        },
    )
}

/// Builds the unresolved external-effect identity from checked records only.
///
/// The single construction site of [`ImprovementUnknownEffectIdentity`]. Every
/// identity is copied from a record this run checked - the candidate, experiment
/// and commitment from the committed record, the repair bindings from the
/// gap-free rollback contract - and the owner is the decision's own owner.
/// Nothing here is read from a reason string or supplied by a caller, so the
/// identity cannot name a candidate, an experiment or a repair path the checked
/// records do not contain.
///
/// The owner's outcome is absent because the checked records hold none: this run
/// admits a candidate, it does not observe an effect, so supplying a reconciled
/// outcome here would be a fabricated observation. Absent is the denying value,
/// and the effect owner attaches its own validated receipt through
/// [`ImprovementUnknownEffect::with_settled_owner_outcome`] to discharge it.
fn unknown_effect_identity_of(
    current: &ImprovementCurrentProposal,
    rollback: &RollbackContract,
    owner_id: &str,
) -> ImprovementUnknownEffectIdentity {
    ImprovementUnknownEffectIdentity {
        candidate_id: current.candidate_id.clone(),
        experiment_id: current.experiment_plan.experiment_id.clone(),
        commitment: current.commitment.clone(),
        owner_id: owner_id.to_string(),
        forward_repair_ref: rollback.forward_repair_ref.clone(),
        invalidation_set: rollback.invalidation_set.clone(),
    }
}

/// Rebuilds the unresolved obligation from a checked identity.
///
/// The identity read here is either the one [`unknown_effect_identity_of`] built
/// from records this run checked, or one a caller retained and presented to
/// [`reconcile_retained_unknown_effect`], which proved its content against the
/// current checked record first. Either way the owner's outcome starts absent:
/// the only value any construction site may write is the absent one, and the
/// single writer of a settled value is the re-checked seam.
fn unknown_effect_of(retained: &ImprovementUnknownEffectIdentity) -> ImprovementUnknownEffect {
    ImprovementUnknownEffect {
        candidate_id: retained.candidate_id.clone(),
        experiment_id: retained.experiment_id.clone(),
        commitment: retained.commitment.clone(),
        owner_id: retained.owner_id.clone(),
        forward_repair_ref: retained.forward_repair_ref.clone(),
        invalidation_set: retained.invalidation_set.clone(),
        owner_outcome: None,
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
        // The one disposition whose own owner may not have settled what
        // happened. The answer is read from the obligation's own owner-validated
        // outcome rather than assumed, and that outcome decides it alone.
        ImprovementTerminalDisposition::UnknownRequiresReconciliation { obligation } => {
            obligation.retry_permitted()
        }
        // The retained historical completed-rollback representation. A validated
        // owner result exists — the effect owner's receipt, held on the
        // unknown-effect obligation — but this variant carries a bare
        // `contract_ref` instead, and a contract reference is not that result.
        // The gate refuses rather than certifying a fresh attempt from an
        // unverified historical value. Naming this arm is what keeps that
        // refusal explicit: under a wildcard the same variant would have
        // inherited permission without ever being examined.
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

/// Returns the owner's retained result for a COMPLETED effect, or `None`.
///
/// The reconciliation half of the unknown-effect debt, and the one public way to
/// reach the owner's retained [`ReceiptEnvelope`]. A completed effect is not
/// retried and is not re-executed: it is reconciled from the result its owner
/// already settled and retained, and this function is where that result is read.
/// The crate owns the obligation, so the crate owns the read; nothing outside
/// this module can re-derive, substitute, or synthesize the retained result, and
/// there is no second reader of the field behind it.
///
/// `Some` is returned only when all of the following hold, and each is decided
/// from the receipt rather than from prose or a flag:
///
/// - the disposition carries an [`ImprovementUnknownEffect`] obligation;
/// - the owner attached a settled outcome through
///   [`ImprovementUnknownEffect::with_settled_owner_outcome`];
/// - that outcome is a completion — `Committed` or `Compensated` — rather than an
///   unsettled, still-unknown, or merely non-success outcome; and
/// - the receipt is bound to this obligation's exact operation identity, so a
///   receipt for another operation can never be handed back as this effect's
///   result.
///
/// Every other disposition, and every unsettled or non-completion outcome, is
/// `None`. `None` is the denying direction throughout: it means this crate holds
/// no owner-settled completion to reconcile, never that one happened.
///
/// The envelope is borrowed exactly as the owner wrote it. It is not copied,
/// re-validated, or re-classified here, so this function adds no second
/// judgement about the effect; reconciling it remains the owner's work, and this
/// hands the owner the bytes it already holds.
///
/// Nothing in this workspace attaches a receipt to an obligation, so in practice
/// this returns `None` for every disposition this module produces until the
/// external effect owner settles one and attaches it.
#[must_use]
pub fn retained_improvement_completion(
    disposition: &ImprovementTerminalDisposition,
) -> Option<&ReceiptEnvelope> {
    match disposition {
        // The one disposition that carries an obligation, and therefore the only
        // place a retained owner result can exist at all.
        ImprovementTerminalDisposition::UnknownRequiresReconciliation { obligation } => {
            obligation.settled_completion_result()
        }
        // Every remaining variant is named explicitly and carries no owner result
        // to read. `RolledBack` is here rather than treated specially because a
        // bare `contract_ref` is not an owner-validated result, exactly as for the
        // retry gate, and naming it keeps that refusal explicit instead of
        // inherited from an unexamined wildcard. The rest describe a decision
        // about the candidate, not an observed external effect. Merging the arms
        // does not weaken the match: every variant is still listed, so adding a
        // disposition remains a compile error here until its retained-result
        // answer is decided.
        ImprovementTerminalDisposition::RolledBack { .. }
        | ImprovementTerminalDisposition::Rejected { .. }
        | ImprovementTerminalDisposition::Inconclusive { .. }
        | ImprovementTerminalDisposition::RegressionRejected { .. }
        | ImprovementTerminalDisposition::NoProgress { .. }
        | ImprovementTerminalDisposition::Blocked { .. }
        | ImprovementTerminalDisposition::CanaryAdmitted { .. } => None,
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

/// Returns the closed terminal disposition of the Governor admission gate over
/// records whose experiment evidence has NOT been checked for execution.
///
/// # Why this exists at all
///
/// [`run_improvement_candidate_pipeline`] refuses a candidate whose experiment
/// evidence is not independent, passed and EXECUTED before it ever reaches
/// `improvement_admission::admit_improvement_candidate`, and it also requires a
/// gap-free rollback contract first. Both refusals are guarantees and neither is
/// touched here. The consequence is that a caller holding no executed evaluation
/// gets a typed [`PipelineError`] and no terminal disposition at all, so "this
/// candidate was refused" has no record to read. This function supplies that
/// record and nothing else: it runs the same admission gate over the same records
/// and returns the gate's own verdict in the same
/// [`ImprovementTerminalDisposition`] vocabulary the full pipeline uses.
///
/// # What it checks, and what it deliberately does not
///
/// It runs the identity half of the join — operation identities, the bounded
/// plan's own shape, its owner routing, the single normalized commitment and the
/// record derived from it, the proposal/candidate identity join including the
/// closure binding, and the proposal/experiment operation, scope, budget and
/// deadline join — then calls `admit_improvement_candidate` with those exact
/// values and maps the decision through this module's own private `map_rejection`
/// / `map_block` projections. A caller therefore cannot present a disposition
/// this crate did not derive from a decision the gate returned, and cannot
/// substitute a hand-built one: this is the checked replacement for making
/// `map_decision` public, not a widened `pub`.
///
/// It does NOT run `check_evaluation_shape` and does NOT run
/// `check_rollback_contract`, and that omission is a CEILING rather than a
/// relaxation. The only two decisions that could use the records those checks
/// guard are refused outright below, so the check they would perform cannot
/// change any outcome this function can return: an admit verdict is an
/// [`PipelineError::UnboundRelation`], never a [`ImprovementTerminalDisposition`],
/// and so is the retained-effect obligation, which needs a gap-free rollback
/// contract to name its repair bindings. No canary handoff is built here either,
/// so `execution_authorized` cannot become true and no record is published for a
/// later pass to compare against.
///
/// It also does not run [`ImprovementProposal::validate`]. That check is a
/// precondition of ADMISSION, and this function admits nothing: a proposal whose
/// shape is incomplete is still disposed by the gate, over the gate's own rules
/// rather than a second set of them. A caller that wants the full precondition
/// set is calling [`run_improvement_candidate_pipeline`], which is unchanged and
/// still validates first.
///
/// # What a caller therefore gets
///
/// One of the gate's own refusal dispositions — for a candidate whose closure
/// binding is not currently valid, that is
/// [`ImprovementTerminalDisposition::Rejected`] with cause
/// [`ImprovementRejectCause::InvalidClosureBinding`] — or the typed error a join
/// check or the gate produced. A proposal the commitment profile refuses is one
/// of those errors, not a disposition: this function never repairs a malformed
/// record to get past it. Never an admit, never a canary handoff, never a
/// promotion, activation, rollback execution or Finish.
pub fn admit_improvement_candidate_without_execution_evidence(
    proposal: &ImprovementProposal,
    experiment: &ExperimentPlan,
    candidate: &ImprovementCandidateView,
    admission_evidence: &ImprovementEvidenceView,
    policy: &ImprovementAdmissionPolicy,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    check_operation_identities()?;
    check_experiment_shape(experiment)?;
    check_experiment_owner_routing(experiment)?;
    // The gate's own fourth input, built by the single producer the full
    // pipeline uses, so a caller never assembles a second commitment and cannot
    // disagree with the one the pipeline commits.
    let normalized = canonical_proposal(proposal)?;
    let current = current_proposal_of(&normalized, experiment)?;
    check_proposal_candidate_join(proposal, candidate)?;
    check_proposal_experiment_join(experiment, proposal, candidate)?;
    // The same bounded-reference ceiling the full pipeline applies to this field
    // in `check_admission_evidence_join`, kept here so an unbounded reference is
    // refused before the gate records it.
    bounded_text(
        &admission_evidence.run_ref,
        "admission_evidence.run_ref",
        IMPROVEMENT_MAX_REFERENCE_BYTES,
    )?;
    check_evaluator_distinct_from_owners(
        admission_evidence.verifier_id.as_str(),
        experiment,
        policy,
        [
            "admission-evidence: reviewer-is-the-experiment-executor",
            "admission-evidence: reviewer-is-the-governor-admission-owner",
            "admission-evidence: reviewer-is-the-rollback-owner",
        ],
    )?;
    // The gate owns the verdict; a typed admission refusal, including the
    // identity conflict, crosses this boundary as itself and is never collapsed
    // into reason text.
    let decision = admit_improvement_candidate(candidate, admission_evidence, policy, &current)?;
    map_unadmitted_decision(&decision)
}

/// Projects a decision this module must refuse into a disposition.
///
/// The two refusals are structural, not incidental: an admit verdict is exactly
/// what the checks this entry point does not run exist to prevent, and a
/// retained-effect obligation is built from a gap-free rollback contract this
/// entry point does not hold. Both are typed [`PipelineError::UnboundRelation`]
/// refusals with a static relation identity, so no caller can mistake them for
/// a disposition and no disposition is invented in their place.
///
/// Every other decision is projected by the SAME private mappers
/// `run_improvement_candidate_pipeline` uses, so a `Rejected` disposition read
/// through this function is byte-for-byte the one the full pipeline would have
/// returned for the same decision.
fn map_unadmitted_decision(
    decision: &ImprovementAdmissionDecision,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    match decision {
        ImprovementAdmissionDecision::AdmitForExperiment { .. } => {
            Err(PipelineError::UnboundRelation {
                relation: "admission-without-execution-evidence: \
                    admit-verdict-requires-independent-executed-evidence-and-a-gap-free-rollback",
            })
        }
        ImprovementAdmissionDecision::RequiresReconciliation { .. } => {
            Err(PipelineError::UnboundRelation {
                relation: "admission-without-execution-evidence: \
                    retained-effect-obligation-requires-a-gap-free-rollback-contract",
            })
        }
        ImprovementAdmissionDecision::Reject {
            cause,
            reason,
            owner_id,
        } => Ok(map_rejection(*cause, reason, owner_id)),
        ImprovementAdmissionDecision::NeedsMoreEvidence { missing, owner_id } => {
            Ok(ImprovementTerminalDisposition::Inconclusive {
                missing: missing.clone(),
                owner_id: owner_id.clone(),
            })
        }
        ImprovementAdmissionDecision::Blocked {
            cause,
            reason,
            owner_id,
        } => Ok(map_block(*cause, reason, owner_id)),
        ImprovementAdmissionDecision::NoProgress { reason, owner_id } => {
            Ok(ImprovementTerminalDisposition::NoProgress {
                reason: reason.clone(),
                owner_id: owner_id.clone(),
            })
        }
    }
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
        inputs.policy,
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
    check_evaluator_distinct_from_owners(
        evidence.verifier_id.as_str(),
        experiment,
        policy,
        [
            "experiment-evaluation: evaluator-is-the-experiment-executor",
            "experiment-evaluation: evaluator-is-the-governor-admission-owner",
            "experiment-evaluation: evaluator-is-the-rollback-owner",
        ],
    )
}

/// Requires one named evaluator to be a principal distinct from the experiment
/// executor, the admitting Governor owner, and the rollback owner.
///
/// The one distinctness comparison this module makes about an evaluator, shared
/// by the experiment evaluation ([`check_evaluator_independence`]) and the
/// independent admission review (`check_admission_evidence_join`). Sharing it is
/// the point: the two evaluators are different records that may legitimately be
/// different people, but neither may be a principal whose interest the evidence
/// serves, and a second hand-written copy of these three relations is a place
/// where the two could drift apart and quietly disagree about who may evaluate.
///
/// The three principals are read from the records that already carry them — the
/// experiment's declared Testd executor, the policy's admission owner, and the
/// policy's rollback owner — never from a caller-set independence boolean.
/// `relations` supplies the three refusal identities, in the fixed order
/// executor, admission owner, rollback owner, so each caller reports under its
/// own relation namespace instead of sharing one another's wording.
fn check_evaluator_distinct_from_owners(
    evaluator: &str,
    experiment: &ExperimentPlan,
    policy: &ImprovementAdmissionPolicy,
    relations: [&'static str; 3],
) -> Result<(), PipelineError> {
    let [executor, admission_owner, rollback_owner] = relations;
    for (relation, principal) in [
        (executor, experiment.testd_owner_id.as_str()),
        (admission_owner, policy.external_owner_id.as_str()),
        (rollback_owner, policy.rollback_owner_id.as_str()),
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
/// experiment, and the same content revision the experiment evaluation did, and
/// to have been produced by a principal distinct from the experiment executor,
/// the admitting Governor owner, and the rollback owner.
///
/// A later independent admission review may legitimately carry a different
/// verifier identity, so verifier identities are never compared with each
/// other. The typed relationship to the same candidate, experiment, and content
/// revision is what is required of the two records together.
///
/// The reviewer itself is a different matter, and it is the record this gate
/// leans on hardest: the admission review is what carries the pulse outcome, the
/// harm observation, and the pass verdict the decision is made from, so a review
/// written by the party that executed the experiment, by the owner that admits
/// it, or by the rollback owner is the party grading its own work. That is the
/// same relation [`check_evaluator_independence`] already refuses for the
/// experiment evaluation, and it is refused here through the same shared
/// predicate rather than through the review's own `independent` flag, which is
/// a caller-set boolean and establishes nothing on its own.
fn check_admission_evidence_join(
    admission: &ImprovementEvidenceView,
    evaluation: &ActivationEvidence,
    proposal: &ImprovementProposal,
    experiment: &ExperimentPlan,
    policy: &ImprovementAdmissionPolicy,
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
    check_evaluator_distinct_from_owners(
        admission.verifier_id.as_str(),
        experiment,
        policy,
        [
            "admission-evidence: reviewer-is-the-experiment-executor",
            "admission-evidence: reviewer-is-the-governor-admission-owner",
            "admission-evidence: reviewer-is-the-rollback-owner",
        ],
    )?;
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
        // checked. The run observed no effect, so the obligation carries no
        // owner outcome yet and `improvement_retry_permitted` denies until the
        // effect owner supplies its own validated receipt through the checked
        // attaching seam. It goes through the same reconciliation entry point a
        // retained debt does, so a decision-mapped obligation and a
        // read-back-and-reconciled one are the same value built the same way.
        ImprovementAdmissionDecision::RequiresReconciliation { owner_id, .. } => {
            reconcile_retained_unknown_effect(
                &unknown_effect_identity_of(&joined.current, joined.rollback, owner_id),
                &joined.current,
                None,
            )?
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
        // The one place a wire revision is stamped onto the handoff. The
        // serialized shape of this record IS this revision, so a record
        // assembled under another one is refused by `check_handoff_wire_revision`
        // before it leaves this module rather than read as a current handoff.
        wire_revision: IMPROVEMENT_PIPELINE_WIRE_REVISION,
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
    let handoff = ImprovementCanaryHandoff {
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
    };
    // The wire boundary itself. This handoff is the serialized record the Kernel
    // owner will later read, so its recorded wire revision is compared against
    // the constant this build checks BEFORE it is returned, exactly as
    // `check_checked_record_identity` compares the commitment's content identity
    // before the current record is compared. A revision mismatch is the typed
    // `UncheckedWireRevision` crossing this layer as itself: no revision is
    // substituted, no legacy shape is padded to this one, and no handoff is
    // emitted for a record this build cannot read as the current shape.
    check_handoff_wire_revision(&handoff)?;
    Ok(handoff)
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
    let bytes =
        canonical_json_bytes(&envelope).map_err(|error| PipelineError::CommitmentFailed {
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

/// Refuses a `risk_ceiling` that carries no qualifier at all.
///
/// `risk_ceiling` is a closed typed policy value, not free text, and its only
/// member is [`IMPROVEMENT_RISK_CEILING_BOUNDED`]. A blank or whitespace-only
/// value is therefore the same closed-set violation as `unbounded` and refuses
/// with the same typed failure; reporting it as a missing field would claim the
/// field is absent from the record when the record carries the field and its
/// value is simply not a member of the closed set.
///
/// This is the single statement of that rule, called both from
/// [`ImprovementProposal::validate`] and from the commitment profile, so every
/// path that reads or canonicalizes a proposal refuses a blank risk ceiling the
/// same way instead of only the admission path doing so.
fn check_risk_ceiling_present(value: &str) -> Result<(), PipelineError> {
    if value.trim().is_empty() {
        return Err(PipelineError::UnsupportedRiskCeiling {
            encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
        });
    }
    Ok(())
}

/// Validates the admitted input, count, string, and total-size profile before
/// any clone, sort, or serialization happens.
fn check_commitment_profile(proposal: &ImprovementProposal) -> Result<(), PipelineError> {
    // Checked ahead of the generic string profile below, which reports a blank
    // value of this field as `MissingField`. A caller that canonicalizes a
    // proposal WITHOUT running `ImprovementProposal::validate` — the gate in
    // `admit_improvement_candidate_without_execution_evidence`, and therefore the
    // daemon route's re-profile of a proposal the admitting path already refused
    // — reaches the closed-set failure here instead of a missing-field error that
    // contradicts what the admitting path reported for the same bytes.
    check_risk_ceiling_present(&proposal.risk_ceiling)?;
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

/// What the joined-input proofs below establish, and what they deliberately do not.
///
/// One complete, individually valid group of seven inputs reaches exactly ONE
/// `ImprovementTerminalDisposition::CanaryAdmitted` carrying an inspectable,
/// non-authorizing handoff, and every substitution below turns exactly one field
/// and refuses with that relation's own typed `PipelineError` before any handoff
/// exists. Two groups that are each individually valid cannot be spliced into
/// one accepted result, and every assertion reads a value or a typed error the
/// pipeline actually returns.
///
/// Every case enters through the one public pipeline entry point, and no
/// production step is reached any other way. What comes from outside that
/// entry point is fixture construction: the retained-prior fixture and the
/// expected side of one assertion are built by this module's own private
/// helpers `canonical_proposal`, `commitment_of`, `discriminator_of` and
/// `material_equality_of`, which only normalize, commit and derive values
/// from records the test itself constructs, and which are never used to
/// invoke a production step.
/// The private joined-input view, its only constructor, and the private result
/// mapper are neither named nor reached here and their visibility is never
/// widened: naming them would assert through a seam this issue closed, and every
/// relation they carry is observable as a typed refusal of that entry point.
/// The one consequence is stated rather than hidden — the result mapper's
/// re-check of the admitted verdict against those same records admits no caller
/// that could make it disagree, so it cannot be driven into disagreement from
/// outside and is therefore asserted here only through the dispositions the
/// public entry point actually returns.
///
/// Two named cases are deliberately ABSENT, because on current `main` they are
/// not constructible without a product change this issue forbids:
///
/// 1. An unrelated, nonblank `run_ref`. `ActivationEvidence.run_ref` and
///    `ImprovementEvidenceView.run_ref` are only checked for presence and
///    boundedness (`check_evaluation_shape` and the closing
///    `check_admission_evidence_join` step). Neither is compared with the other
///    or with any other record, so an unrelated, nonblank, in-bounds run
///    reference still reaches `CanaryAdmitted` and the handoff then publishes two
///    unrelated run references. Asserting a refusal here would assert a check
///    that does not exist, so the case below states the presence and the ceiling
///    the code really enforces and nothing more.
///
/// A BLANK `risk_ceiling` is no longer such a case: `risk_ceiling` is a closed
/// typed policy value whose only member is `IMPROVEMENT_RISK_CEILING_BOUNDED`,
/// so a blank or whitespace-only qualifier is unsupported rather than absent and
/// refuses with `PipelineError::UnsupportedRiskCeiling`, the same typed failure
/// `unbounded` and every other nonblank wrong value produce.
#[cfg(test)]
mod tests {
    use super::*;

    use crate::improvement_admission::{
        IMPROVEMENT_ADMISSION_AUTHORITY, ImprovementPulseOutcome, improvement_admission_policy,
    };

    /// One complete, individually valid joined group.
    ///
    /// The group is valid because every relation the join checks agrees INSIDE
    /// it: proposal, plan, evaluation evidence, rollback contract, candidate
    /// view, admission review and policy all name the same operation and
    /// idempotency namespace, the same candidate, campaign, closure identity and
    /// closure digest, the same bounded experiment and content revision, and the
    /// same rollback owner; the plan's scope, budget and deadline ARE the
    /// admitted ones rather than a narrowing of them; and the admission review
    /// carries a retained prior record, which this fixture must carry because an
    /// absent retained record is assessed as `NoRetainedPrior`, disposes as
    /// no-progress, and can never reach the admitted branch.
    ///
    /// `tag` names the group, so the explicit A/B counterexample builds two
    /// INDEPENDENTLY valid groups instead of mixing halves of one.
    struct Fixture {
        proposal: ImprovementProposal,
        experiment: ExperimentPlan,
        evidence: ActivationEvidence,
        rollback: RollbackContract,
        candidate: ImprovementCandidateView,
        admission_evidence: ImprovementEvidenceView,
        policy: ImprovementAdmissionPolicy,
    }

    impl Fixture {
        /// The seven borrowed inputs of one pure pipeline run.
        fn inputs(&self) -> ImprovementPipelineInputs<'_> {
            ImprovementPipelineInputs {
                proposal: &self.proposal,
                experiment: &self.experiment,
                evidence: &self.evidence,
                rollback: &self.rollback,
                candidate: &self.candidate,
                admission_evidence: &self.admission_evidence,
                policy: &self.policy,
            }
        }

        /// Runs the one production entry point over this group.
        fn run(&self) -> Result<ImprovementTerminalDisposition, PipelineError> {
            run_improvement_candidate_pipeline(self.inputs())
        }

        /// Returns the typed refusal this group must produce.
        ///
        /// `Ok` is a test failure here, not a weaker pass: a positive result is
        /// the thing every substitution below has to make impossible.
        fn refusal(&self) -> PipelineError {
            match self.run() {
                Err(error) => error,
                Ok(disposition) => panic!("joined input must refuse, got {disposition:?}"),
            }
        }

        /// Returns the one non-authorizing handoff this group must reach.
        fn admitted(&self) -> ImprovementCanaryHandoff {
            match self.run() {
                Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => *handoff,
                Ok(other) => panic!("joined input must admit for one canary, got {other:?}"),
                Err(error) => panic!("joined input must admit for one canary, got {error:?}"),
            }
        }

        /// Runs the gate-only entry point and returns its typed refusal.
        ///
        /// This is the second public entry point, and it deliberately does NOT
        /// run `ImprovementProposal::validate`; it canonicalizes the proposal
        /// instead. The daemon route calls it with the same proposal bytes the
        /// admitting path already refused, so the two entries must name the same
        /// violation for the same record.
        fn gate_refusal(&self) -> PipelineError {
            match admit_improvement_candidate_without_execution_evidence(
                &self.proposal,
                &self.experiment,
                &self.candidate,
                &self.admission_evidence,
                &self.policy,
            ) {
                Err(error) => error,
                Ok(disposition) => panic!("gate must refuse, got {disposition:?}"),
            }
        }
    }

    fn fixture(tag: &str) -> Fixture {
        Fixture {
            proposal: proposal(tag),
            experiment: plan(tag),
            evidence: evidence(tag),
            rollback: rollback(tag),
            candidate: candidate(tag),
            admission_evidence: admission_review(tag),
            // The production policy record, so the admission owner and the
            // rollback owner are this owner's own decision and not literals
            // restated here.
            policy: improvement_admission_policy(
                &format!("op-2702-{tag}"),
                &format!("idem-2702-{tag}"),
                &format!("rollback-owner-2702-{tag}"),
            ),
        }
    }

    fn proposal(tag: &str) -> ImprovementProposal {
        ImprovementProposal {
            proposal_id: format!("proposal-2702-{tag}"),
            candidate_id: format!("cand-2702-{tag}"),
            campaign_id: format!("campaign-2702-{tag}"),
            closure_id: format!("closure-2702-{tag}"),
            closure_digest: format!("sha256-closure-2702-{tag}"),
            evidence_refs: vec![format!("evidence-2702-{tag}")],
            target_capability: format!("capability-2702-{tag}"),
            target_generation: format!("generation-2702-{tag}"),
            mechanism: MechanismDeclaration {
                mechanism_id: format!("mechanism-2702-{tag}"),
                hypothesis: format!("hypothesis-2702-{tag}"),
                causal_link: format!("causal-link-2702-{tag}"),
                declared_ref: format!("declared-ref-2702-{tag}"),
                declared_before_results: true,
            },
            expected_delta: format!("expected-delta-2702-{tag}"),
            risk_ceiling: IMPROVEMENT_RISK_CEILING_BOUNDED.to_string(),
            effect_ceiling: IMPROVEMENT_EFFECT_CEILING.to_string(),
            budget_ref: format!("budget-2702-{tag}"),
            deadline_ref: format!("deadline-2702-{tag}"),
            privacy_class: "internal".to_string(),
            invalidation_set: vec![
                "invalidation-cache".to_string(),
                "invalidation-store".to_string(),
            ],
            operation_ref: format!("op-2702-{tag}"),
            idempotency_key: format!("idem-2702-{tag}"),
            source_identity: format!("source-2702-{tag}"),
            runtime_identity: format!("runtime-2702-{tag}"),
            data_identity: format!("data-2702-{tag}"),
        }
    }

    fn plan(tag: &str) -> ExperimentPlan {
        ExperimentPlan {
            experiment_id: format!("exp-2702-{tag}"),
            testd_owner_id: TESTD_OWNER.to_string(),
            evaluator_id: format!("{VERIFIER_OWNER_FAMILY}-eval-{tag}"),
            scope_ref: format!("scope-2702-{tag}"),
            budget_ref: format!("budget-2702-{tag}"),
            deadline_ref: format!("deadline-2702-{tag}"),
            operation_ref: format!("op-2702-{tag}"),
            idempotency_key: format!("idem-2702-{tag}"),
            scope_refinement: None,
        }
    }

    fn evidence(tag: &str) -> ActivationEvidence {
        ActivationEvidence {
            evidence_id: format!("activation-evidence-2702-{tag}"),
            verifier_id: format!("{VERIFIER_OWNER_FAMILY}-eval-{tag}"),
            independent: true,
            verifier_passed: true,
            raw_evidence_ref: format!("raw-evidence-2702-{tag}"),
            run_ref: format!("run-2702-{tag}"),
            content_revision_ref: format!("revision-2702-{tag}"),
            execution: ImprovementEvidenceExecution::Executed,
            bound_candidate_id: format!("cand-2702-{tag}"),
            bound_experiment_id: format!("exp-2702-{tag}"),
        }
    }

    fn rollback(tag: &str) -> RollbackContract {
        RollbackContract {
            rollback_ref: format!("rollback-2702-{tag}"),
            disable_ref: format!("disable-2702-{tag}"),
            reopen_ref: format!("reopen-2702-{tag}"),
            expiry_ref: format!("expiry-2702-{tag}"),
            rollback_owner_id: format!("rollback-owner-2702-{tag}"),
            forward_repair_ref: format!("forward-repair-2702-{tag}"),
            // Deliberately WIDER than the proposal's own invalidation set: wider
            // rollback coverage is a repair-path fact and must never widen what
            // the handoff is allowed to invalidate.
            invalidation_set: vec![
                "invalidation-cache".to_string(),
                "invalidation-store".to_string(),
                "invalidation-index".to_string(),
            ],
        }
    }

    fn candidate(tag: &str) -> ImprovementCandidateView {
        ImprovementCandidateView {
            candidate_id: format!("cand-2702-{tag}"),
            campaign_id: format!("campaign-2702-{tag}"),
            closure_id: format!("closure-2702-{tag}"),
            closure_digest: format!("sha256-closure-2702-{tag}"),
            promotion_input_id: Some(format!("promotion-input-2702-{tag}")),
            promotion_digest: Some(format!("sha256-promotion-2702-{tag}")),
            admitted_scope_ref: Some(format!("scope-2702-{tag}")),
            proof_ceiling: IMPROVEMENT_PROOF_CEILING.to_string(),
            requested_effect: IMPROVEMENT_REQUESTED_EFFECT.to_string(),
            direct_promotion: false,
            active_permit: None,
            promotion_receipt: None,
            operation_ref: format!("op-2702-{tag}"),
            idempotency_key: format!("idem-2702-{tag}"),
        }
    }

    fn admission_review(tag: &str) -> ImprovementEvidenceView {
        ImprovementEvidenceView {
            // A DIFFERENT principal from the experiment evaluator, related to it
            // by the typed binding to the same candidate, experiment and content
            // revision rather than by an identity comparison.
            verifier_id: format!("{VERIFIER_OWNER_FAMILY}-review-{tag}"),
            bound_candidate_id: format!("cand-2702-{tag}"),
            bound_experiment_id: format!("exp-2702-{tag}"),
            content_revision_ref: format!("revision-2702-{tag}"),
            run_ref: format!("review-run-2702-{tag}"),
            independent: true,
            verifier_passed: true,
            pulse: ImprovementPulseOutcome::Pass,
            pulse_ref: Some(format!("pulse-evidence-2702-{tag}")),
            harm_observed: false,
            outcome_unknown: false,
            closure_valid: true,
            closure_stale: false,
            rollback_ref: Some(format!("rollback-2702-{tag}")),
            disable_ref: Some(format!("disable-2702-{tag}")),
            reopen_ref: Some(format!("reopen-2702-{tag}")),
            rollback_owner_id: format!("rollback-owner-2702-{tag}"),
            expiry_ref: Some(format!("expiry-2702-{tag}")),
            retained_prior_proposal: Some(retained_prior(tag)),
        }
    }

    /// The retained prior record of one group: a different bounded experiment
    /// under a different operation AND a different idempotency key, with its own
    /// discriminator projection and its own owner-issued evidence reference.
    ///
    /// Built through this module's own normalizer, commitment, discriminator and
    /// material-equality projections instead of a hand-written digest string, so
    /// the retained record is byte-for-byte the record this module commits for
    /// those prior bytes and no fixture invents a digest nothing can reproduce.
    /// It therefore carries the CURRENT discriminator domain and encoding
    /// revision and the current material-equality domain and revision, so
    /// `unestablished_projection` and `material_repeat` can compare it at all; it
    /// repeats neither the operation identity nor the idempotency key of the
    /// current group, so `same_operation_replay` does not claim an exact replay or
    /// an identity conflict; its whole material-equality key differs, so
    /// `material_repeat` does not call it a repeated experiment; and its declared
    /// evidence refs are not a superset of the current ones, so
    /// `changed_discriminator` finds a changed projection AND owner-issued
    /// evidence the retained record did not declare. That combination is exactly
    /// the one the admission gate releases as an ordinary new candidate.
    fn retained_prior(tag: &str) -> RetainedImprovementProposal {
        let prior = format!("prior-{tag}");
        let normalized = match canonical_proposal(&proposal(&prior)) {
            Ok(normalized) => normalized,
            Err(error) => panic!("the fixture's prior proposal must normalize, got {error:?}"),
        };
        let experiment = plan(&prior);
        RetainedImprovementProposal {
            commitment: match commitment_of(&normalized) {
                Ok(commitment) => commitment,
                Err(error) => {
                    panic!("the fixture's prior proposal must commit, got {error:?}")
                }
            },
            discriminator: discriminator_of(&normalized),
            material_equality: material_equality_of(&normalized, &experiment),
            experiment_plan: experiment,
        }
    }

    #[test]
    fn one_valid_joined_fixture_reaches_the_non_authorizing_canary_handoff() {
        let group = fixture("a");
        let handoff = group.admitted();

        assert_eq!(handoff.wire_revision, IMPROVEMENT_PIPELINE_WIRE_REVISION);
        assert_eq!(check_handoff_wire_revision(&handoff), Ok(()));
        assert_eq!(handoff.proposal_id, "proposal-2702-a");
        assert_eq!(handoff.candidate_id, "cand-2702-a");
        assert_eq!(handoff.campaign_id, "campaign-2702-a");
        assert_eq!(handoff.closure_id, "closure-2702-a");
        assert_eq!(handoff.closure_digest, "sha256-closure-2702-a");
        assert_eq!(handoff.experiment_id, "exp-2702-a");
        assert_eq!(handoff.operation_ref, "op-2702-a");
        assert_eq!(handoff.idempotency_key, "idem-2702-a");
        // The scope is the candidate owner's PROVED admitted scope, not a string
        // derived from the candidate identity.
        assert_eq!(handoff.experiment_scope_ref, "scope-2702-a");
        assert_eq!(handoff.budget_ref, "budget-2702-a");
        assert_eq!(handoff.deadline_ref, "deadline-2702-a");
        assert_eq!(handoff.evidence_id, "activation-evidence-2702-a");
        assert_eq!(
            handoff.evidence_verifier_id,
            "instrument-verifier-20-1111-eval-a"
        );
        assert_eq!(
            handoff.admission_evaluator_id,
            "instrument-verifier-20-1111-review-a"
        );
        assert_eq!(handoff.evidence_run_ref, "run-2702-a");
        assert_eq!(handoff.admission_run_ref, "review-run-2702-a");
        assert_eq!(handoff.evidence_content_revision_ref, "revision-2702-a");
        assert_eq!(handoff.admission_content_revision_ref, "revision-2702-a");
        assert_eq!(handoff.raw_evidence_ref, "raw-evidence-2702-a");
        assert_eq!(handoff.admission_pulse_ref, "pulse-evidence-2702-a");
        assert_eq!(handoff.admission_owner_id, IMPROVEMENT_ADMISSION_AUTHORITY);
        assert_eq!(handoff.rollback_owner_id, "rollback-owner-2702-a");
        assert_eq!(handoff.rollback_ref, "rollback-2702-a");
        assert_eq!(handoff.disable_ref, "disable-2702-a");
        assert_eq!(handoff.reopen_ref, "reopen-2702-a");
        assert_eq!(handoff.expiry_ref, "expiry-2702-a");
        assert_eq!(handoff.forward_repair_ref, "forward-repair-2702-a");
        assert_eq!(handoff.activation_owner_id, KERNEL_CANARY_OWNER);
        // The PROPOSAL's own admitted set, never the rollback's wider coverage,
        // even though this rollback contract covers three targets.
        assert_eq!(
            handoff.invalidation_set,
            vec![
                "invalidation-cache".to_string(),
                "invalidation-store".to_string()
            ]
        );
        // The one commitment this crate computes for these bytes, carried through
        // unchanged: no second digest, no fallback, no legacy value.
        //
        // What the handoff must answer is "is this commitment the commitment OF
        // THIS PROPOSAL", and re-deriving it here with `proposal_digest` cannot
        // answer that: production computes that very value from that very input,
        // so a deterministic function would only be compared with itself. The
        // binding is proved by MUTATION instead — a second proposal differing in
        // exactly one content field, whose commitment must then differ.
        let mut mutated = proposal("a");
        mutated.expected_delta = "expected-delta-2702-b".to_string();
        let mutated_normalized = match canonical_proposal(&mutated) {
            Ok(normalized) => normalized,
            Err(error) => panic!("the mutated fixture proposal must normalize, got {error:?}"),
        };
        let mutated_commitment = match commitment_of(&mutated_normalized) {
            Ok(commitment) => commitment,
            Err(error) => panic!("the mutated fixture proposal must commit, got {error:?}"),
        };
        // The operation and idempotency identities are held constant, so the
        // difference below is content and is not an identity swap in disguise.
        assert_eq!(
            mutated_commitment.operation_ref,
            handoff.proposal_commitment.operation_ref
        );
        assert_eq!(
            mutated_commitment.idempotency_key,
            handoff.proposal_commitment.idempotency_key
        );
        // One content field changed, so this is NOT the admitted handoff's
        // commitment: the digest is bound to the proposal's own bytes.
        assert_ne!(
            mutated_commitment.digest,
            handoff.proposal_commitment.digest
        );
        assert_eq!(
            handoff.proposal_commitment.algorithm,
            IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM
        );
        assert_eq!(
            handoff.proposal_commitment.domain,
            IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN
        );
        // The discriminator projection is bound to the same bytes by the same
        // argument, not by recomputation: the mutated proposal projects the
        // mutated content, and that projection is not the handoff's projection.
        let mutated_discriminator = discriminator_of(&mutated_normalized);
        assert_eq!(
            mutated_discriminator.expected_delta,
            "expected-delta-2702-b"
        );
        assert_ne!(
            mutated_discriminator.expected_delta,
            handoff.proposal_discriminator.expected_delta
        );
        // The readable projection is populated but is not the join and is not a
        // permit.
        assert!(!handoff.handoff_projection.is_empty());
        assert!(!handoff.execution_authorized);
    }

    /// The negative half of the retained-record requirement, so the claim above is
    /// proven and not merely asserted: the SAME complete group with no retained
    /// prior record cannot reach the admitted branch, because an absent retained
    /// record is assessed as no-retained-prior and disposes as no progress.
    /// The reason text is produced by production from the retained commitment, so
    /// this pins the disposition and the owner it charges rather than restating
    /// that prose.
    #[test]
    fn an_absent_retained_prior_record_never_reaches_the_canary_branch() {
        let mut group = fixture("a");
        group.admission_evidence.retained_prior_proposal = None;

        match group.run() {
            Ok(ImprovementTerminalDisposition::NoProgress { owner_id, .. }) => {
                assert_eq!(owner_id, group.policy.external_owner_id);
            }
            Ok(other) => {
                panic!("absent retained record must dispose as no progress, got {other:?}")
            }
            Err(error) => {
                panic!("absent retained record must dispose as no progress, got {error:?}")
            }
        }
    }

    #[test]
    fn an_admitted_handoff_never_authorizes_execution_and_a_spliced_one_is_refused() {
        let group = fixture("a");
        let disposition = match group.run() {
            Ok(disposition) => disposition,
            Err(error) => panic!("the valid fixture must decide, got {error:?}"),
        };
        let handoff = match &disposition {
            ImprovementTerminalDisposition::CanaryAdmitted { handoff } => handoff.as_ref(),
            other => panic!("the valid fixture must be canary-admitted, got {other:?}"),
        };
        assert!(!handoff.execution_authorized);

        // The read view the daemon's own handoff check assembles: the handoff's
        // three identity objects plus the exact plan this run passed. Copied, not
        // derived, so the decision below is proved against the handoff itself.
        let current = ImprovementCurrentProposal {
            candidate_id: handoff.candidate_id.clone(),
            commitment: handoff.proposal_commitment.clone(),
            discriminator: handoff.proposal_discriminator.clone(),
            material_equality: handoff.proposal_material_equality.clone(),
            experiment_plan: group.experiment.clone(),
        };
        let decision = match improvement_terminal_decision(
            "cand-2702-a",
            1,
            &group.proposal,
            &group.experiment,
            &group.evidence,
            Some(&current),
            &disposition,
        ) {
            Ok(decision) => decision,
            Err(error) => panic!("an admitted run must be recordable, got {error:?}"),
        };
        assert_eq!(decision.candidate_id, "cand-2702-a");
        assert_eq!(decision.experiment_id, "exp-2702-a");
        assert_eq!(
            decision.proposal_commitment,
            Some(handoff.proposal_commitment.clone())
        );
        // The disposition is carried VERBATIM, and this is how that is checked
        // without comparing a value with its own clone:
        // `improvement_terminal_decision` takes the disposition by reference and
        // clones it into the record, so `assert_eq!(decision.disposition,
        // disposition)` held by construction and could never fail. What CAN fail
        // is a record that substituted a branch, dropped the handoff, or rewrote
        // any handoff field on the way in. The identities below are literals this
        // module's own fixture builders state, so the admitted branch is pinned
        // without consulting the run's output at all; the equality then pins the
        // transport itself, handoff for handoff.
        match &decision.disposition {
            ImprovementTerminalDisposition::CanaryAdmitted { handoff: recorded } => {
                assert_eq!(recorded.candidate_id, "cand-2702-a");
                assert_eq!(recorded.experiment_id, "exp-2702-a");
                assert_eq!(recorded.rollback_owner_id, "rollback-owner-2702-a");
                assert_eq!(**recorded, *handoff);
            }
            other => panic!("the decision must record the admitted branch, got {other:?}"),
        }

        // The same record with execution authority spliced into it is refused as
        // a verdict that disagrees with its own evidence: no shape and no
        // matching digest establishes execution.
        let mut authorized = handoff.clone();
        authorized.execution_authorized = true;
        let spliced = ImprovementTerminalDisposition::CanaryAdmitted {
            handoff: Box::new(authorized),
        };
        match improvement_terminal_decision(
            "cand-2702-a",
            1,
            &group.proposal,
            &group.experiment,
            &group.evidence,
            Some(&current),
            &spliced,
        ) {
            Err(UnboundDecisionRecord::UnverifiableVerdict { relation }) => assert_eq!(
                relation,
                "decision-admitted: handoff-claims-execution-authority"
            ),
            other => {
                panic!("a handoff claiming execution authority must be refused, got {other:?}")
            }
        }
    }

    #[test]
    fn substituted_candidate_campaign_and_closure_identities_refuse() {
        let mut group = fixture("a");
        group.candidate.candidate_id = "cand-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: candidate-identity-mismatch",
            }
        );

        let mut group = fixture("a");
        group.candidate.campaign_id = "campaign-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: campaign-identity-mismatch",
            }
        );

        let mut group = fixture("a");
        group.candidate.closure_id = "closure-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: closure-identity-mismatch",
            }
        );

        let mut group = fixture("a");
        group.candidate.closure_digest = "sha256-closure-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: closure-digest-mismatch",
            }
        );
    }

    /// `I12.24:76`: replay-only evidence cannot promote. Every status other than
    /// `Executed` refuses, and the refused label is the machine state's own.
    #[test]
    fn evidence_shape_refuses_non_executed_status() {
        let mut group = fixture("a");
        group.evidence.execution = ImprovementEvidenceExecution::NotExecuted;
        assert_eq!(
            group.refusal(),
            PipelineError::EvidenceNotExecuted {
                status: "not-executed",
            }
        );

        let mut group = fixture("a");
        group.evidence.execution = ImprovementEvidenceExecution::Simulated;
        assert_eq!(
            group.refusal(),
            PipelineError::EvidenceNotExecuted {
                status: "simulated",
            }
        );

        let mut group = fixture("a");
        group.evidence.execution = ImprovementEvidenceExecution::UnknownOutcome;
        assert_eq!(
            group.refusal(),
            PipelineError::EvidenceNotExecuted {
                status: "unknown-outcome",
            }
        );
    }

    /// `I12.24:76`: a dependent or failed evaluation is not independent
    /// evidence, even though the evaluation itself did execute.
    #[test]
    fn evidence_shape_refuses_dependent_or_failed_verdict() {
        let mut group = fixture("a");
        group.evidence.independent = false;
        assert_eq!(group.refusal(), PipelineError::EvidenceNotIndependent);

        let mut group = fixture("a");
        group.evidence.verifier_passed = false;
        assert_eq!(group.refusal(), PipelineError::EvidenceNotIndependent);
    }

    #[test]
    fn substituted_operation_and_idempotency_identity_refuse_on_both_joins() {
        // Proposal to candidate: the candidate view no longer declares the
        // operation or idempotency namespace the proposal committed.
        let mut group = fixture("a");
        group.candidate.operation_ref = "op-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: operation-mismatch",
            }
        );

        let mut group = fixture("a");
        group.candidate.idempotency_key = "idem-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: idempotency-mismatch",
            }
        );

        // Proposal to experiment: the plan binds another operation or idempotency
        // namespace than the proposal it runs.
        let mut group = fixture("a");
        group.experiment.operation_ref = "op-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: operation-idempotency-mismatch",
            }
        );

        let mut group = fixture("a");
        group.experiment.idempotency_key = "idem-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: operation-idempotency-mismatch",
            }
        );
    }

    #[test]
    fn substituted_experiment_identity_refuses_on_both_evidence_records() {
        // The experiment evaluation bound to another bounded experiment.
        let mut group = fixture("a");
        group.evidence.bound_experiment_id = "exp-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "experiment-evaluation: experiment-binding-mismatch",
            }
        );

        // The independent admission review bound to another bounded experiment.
        let mut group = fixture("a");
        group.admission_evidence.bound_experiment_id = "exp-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: experiment-binding-mismatch",
            }
        );

        // And the candidate identity each of the two records claims.
        let mut group = fixture("a");
        group.evidence.bound_candidate_id = "cand-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "experiment-evaluation: candidate-binding-mismatch",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.bound_candidate_id = "cand-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: candidate-binding-mismatch",
            }
        );
    }

    #[test]
    fn an_unrelated_evaluator_refuses_before_any_admission() {
        // A competent verifier of the same owner family that the plan did not
        // declare. Family membership is not competence for THIS run.
        let mut group = fixture("a");
        group.evidence.verifier_id = "instrument-verifier-20-1111-unrelated".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "experiment-evaluation: evaluator-is-not-the-competent-planned-evaluator",
            }
        );

        // An evaluator outside the Instrument verifier family, declared by the
        // plan itself: routing refuses it before the evaluation is joined.
        let mut group = fixture("a");
        group.experiment.evaluator_id = "governor-2702-a".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "experiment-evaluation: evaluator-is-not-the-instrument-verifier-family",
            }
        );

        // The experiment's executor is the Testd owner and nothing else.
        let mut group = fixture("a");
        group.experiment.testd_owner_id = "governor-2702-a".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "experiment-execution: executor-is-not-the-testd-owner",
            }
        );
    }

    #[test]
    fn the_admission_reviewer_may_not_be_the_executor_the_admission_owner_or_the_rollback_owner() {
        let mut group = fixture("a");
        group.admission_evidence.verifier_id = TESTD_OWNER.to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: reviewer-is-the-experiment-executor",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.verifier_id = IMPROVEMENT_ADMISSION_AUTHORITY.to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: reviewer-is-the-governor-admission-owner",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.verifier_id = "rollback-owner-2702-a".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: reviewer-is-the-rollback-owner",
            }
        );
    }

    #[test]
    fn substituted_content_revision_refuses_on_the_two_evidence_records() {
        // The independent evaluation graded a different content revision than the
        // admission review observed.
        let mut group = fixture("a");
        group.evidence.content_revision_ref = "revision-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: content-revision-mismatch",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.content_revision_ref = "revision-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: content-revision-mismatch",
            }
        );
    }

    /// What the join really binds about a run reference, and what it does not.
    ///
    /// It requires every run reference to be present and bounded, and it binds
    /// the two evidence records to the same candidate, experiment, content
    /// revision and evaluators. It does NOT compare `evidence.run_ref` with
    /// `admission_evidence.run_ref`, nor either of them with the plan: no relation
    /// between two run references exists in this module, so a nonblank unrelated
    /// run reference is not refused here and an in-bounds one is not a second
    /// run of the same experiment either way. This test therefore states the
    /// presence and the ceiling the code really enforces and asserts nothing
    /// about an equality check that would not exist.
    #[test]
    fn a_run_binding_must_be_present_and_bounded_on_both_evidence_records() {
        let mut group = fixture("a");
        group.evidence.run_ref = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::MissingField("evidence.run_ref")
        );

        let mut group = fixture("a");
        group.admission_evidence.run_ref = String::new();
        assert_eq!(
            group.refusal(),
            PipelineError::MissingField("admission_evidence.run_ref")
        );

        // Past the admitted reference ceiling the same field is a profile
        // refusal, not an absent one.
        let mut group = fixture("a");
        group.admission_evidence.run_ref = "r".repeat(IMPROVEMENT_MAX_REFERENCE_BYTES + 1);
        assert_eq!(
            group.refusal(),
            PipelineError::InputProfileCeiling("admission_evidence.run_ref")
        );
    }

    /// Widening needs the owner-proved admitted scope to be a comparison at all.
    ///
    /// `check_proposal_experiment_join` runs `check_scope_refinement` only when
    /// the candidate view carries a nonblank `admitted_scope_ref`. This fixture
    /// does, so the substitutions below reach the refinement relation itself
    /// rather than the `missing-admitted-scope` block an unscoped candidate
    /// produces instead.
    #[test]
    fn a_widened_scope_budget_or_deadline_refuses_without_owner_proven_narrowing() {
        let mut group = fixture("a");
        group.experiment.scope_ref = "scope-2702-wide".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: unproven-narrowed-scope-budget-or-deadline",
            }
        );

        let mut group = fixture("a");
        group.experiment.budget_ref = "budget-2702-wide".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: unproven-narrowed-scope-budget-or-deadline",
            }
        );

        let mut group = fixture("a");
        group.experiment.deadline_ref = "deadline-2702-wide".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: unproven-narrowed-scope-budget-or-deadline",
            }
        );
    }

    #[test]
    fn owner_proven_narrowing_still_admits_inside_the_admitted_contract() {
        let handoff = narrowing_fixture().admitted();
        // The handoff's scope stays the owner-proved ADMITTED scope; only the
        // plan's own budget and deadline references are the narrowed ones.
        assert_eq!(handoff.experiment_scope_ref, "scope-2702-a");
        assert_eq!(handoff.budget_ref, "budget-2702-a-narrow");
        assert_eq!(handoff.deadline_ref, "deadline-2702-a-narrow");
        assert_eq!(handoff.experiment_id, "exp-2702-a");
        assert!(!handoff.execution_authorized);
    }

    /// The narrowed-scope fixture the refinement cases start from: the admitted
    /// scope, budget and deadline, the narrowed references the plan actually
    /// uses, one owner-issued resource ceiling, and the owner's own refinement
    /// evidence with each narrowing relation stated.
    fn narrowing_fixture() -> Fixture {
        let mut group = fixture("a");
        group.experiment.scope_ref = "scope-2702-a-narrow".to_string();
        group.experiment.budget_ref = "budget-2702-a-narrow".to_string();
        group.experiment.deadline_ref = "deadline-2702-a-narrow".to_string();
        group.experiment.scope_refinement = Some(AdmittedScopeRefinement {
            admitted_scope_ref: "scope-2702-a".to_string(),
            admitted_budget_ref: "budget-2702-a".to_string(),
            admitted_deadline_ref: "deadline-2702-a".to_string(),
            refined_scope_ref: "scope-2702-a-narrow".to_string(),
            refined_budget_ref: "budget-2702-a-narrow".to_string(),
            refined_deadline_ref: "deadline-2702-a-narrow".to_string(),
            resource_ceilings: vec![AdmittedResourceCeiling {
                dimension: "tokens".to_string(),
                ceiling_ref: "ceiling-tokens-2702-a".to_string(),
            }],
            refinement_owner_id: "owner-2702-a".to_string(),
            refinement_ref: "refinement-ref-2702-a".to_string(),
            scope_within_admitted: true,
            budget_within_ceiling: true,
            deadline_not_widened: true,
        });
        group
    }

    #[test]
    fn refinement_evidence_that_declares_a_widening_or_a_foreign_binding_refuses() {
        let mut widened = narrowing_fixture();
        if let Some(refinement) = widened.experiment.scope_refinement.as_mut() {
            refinement.scope_within_admitted = false;
        }
        assert_eq!(
            widened.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: refinement-declares-widening",
            }
        );

        let mut widened_budget = narrowing_fixture();
        if let Some(refinement) = widened_budget.experiment.scope_refinement.as_mut() {
            refinement.budget_within_ceiling = false;
        }
        assert_eq!(
            widened_budget.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: refinement-declares-widening",
            }
        );

        let mut widened_deadline = narrowing_fixture();
        if let Some(refinement) = widened_deadline.experiment.scope_refinement.as_mut() {
            refinement.deadline_not_widened = false;
        }
        assert_eq!(
            widened_deadline.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: refinement-declares-widening",
            }
        );

        // Refinement evidence that re-establishes another admitted contract, or
        // names a refined set the plan does not actually use, is refused as an
        // unbound refinement rather than read as the owner's narrowing.
        let mut foreign_admitted = narrowing_fixture();
        if let Some(refinement) = foreign_admitted.experiment.scope_refinement.as_mut() {
            refinement.admitted_scope_ref = "scope-2702-other".to_string();
        }
        assert_eq!(
            foreign_admitted.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: refinement-admitted-binding-mismatch",
            }
        );

        let mut foreign_refined = narrowing_fixture();
        if let Some(refinement) = foreign_refined.experiment.scope_refinement.as_mut() {
            refinement.refined_scope_ref = "scope-2702-other".to_string();
        }
        assert_eq!(
            foreign_refined.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-experiment: refinement-refined-binding-mismatch",
            }
        );
    }

    #[test]
    fn a_wrong_rollback_owner_or_a_disagreeing_repair_reference_refuses() {
        let mut group = fixture("a");
        group.rollback.rollback_owner_id = "rollback-owner-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "rollback-policy: rollback-owner-mismatch",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.rollback_owner_id = "rollback-owner-2702-b".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "rollback-evidence: rollback-owner-mismatch",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.rollback_ref = Some("rollback-2702-b".to_string());
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "rollback-evidence: rollback-reference-disagreement",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.disable_ref = Some("disable-2702-b".to_string());
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "rollback-evidence: disable-reference-disagreement",
            }
        );

        // The reopen reference is bound exactly as the rollback, disable and
        // expiry references are: a declared review reference that names a
        // different reopen handle than the rollback contract is a disagreement,
        // not a second valid way to reopen. The admitted twin for an UNCHANGED
        // `reopen_ref` is already bound by
        // `one_valid_joined_fixture_reaches_the_non_authorizing_canary_handoff`,
        // which admits this same fixture and carries `reopen-2702-a` into the
        // handoff, so it is not repeated here.
        let mut group = fixture("a");
        group.admission_evidence.reopen_ref = Some("reopen-2702-b".to_string());
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "rollback-evidence: reopen-reference-disagreement",
            }
        );

        let mut group = fixture("a");
        group.admission_evidence.expiry_ref = Some("expiry-2702-b".to_string());
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "rollback-evidence: expiry-reference-disagreement",
            }
        );
    }

    /// Every repair reference and the owner the rollback contract REQUIRES, and
    /// the typed gap production produces for each one.
    ///
    /// `check_rollback_join` calls `check_rollback_contract` FIRST: before it
    /// compares the owner with the policy and with the admission review, and
    /// before it compares the declared references. A contract that names no
    /// repair path is therefore refused as a gap and never reaches those
    /// comparisons, so each case below states what the gap check really returns
    /// rather than what a neighbouring join would return for the same field.
    ///
    /// All six references and the owner are refused by `.trim().is_empty()`, so
    /// an all-whitespace value IS the gap and not a merely unusual one: it names
    /// no contract and no owner, and it is never read as agreement.
    ///
    /// The admitted twin for every case below is the SAME unchanged fixture:
    /// `one_valid_joined_fixture_reaches_the_non_authorizing_canary_handoff`
    /// admits it and carries `rollback-2702-a`, `disable-2702-a`, `reopen-2702-a`,
    /// `expiry-2702-a`, `forward-repair-2702-a`, `rollback-owner-2702-a` and a
    /// three-member invalidation set into that handoff, so it is not repeated.
    #[test]
    fn every_required_rollback_reference_and_owner_must_be_present() {
        let gap_detail = "missing-rollback: rollback contract required before experiment";
        let mut group = fixture("a");
        group.rollback.rollback_ref = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::RollbackContractGap {
                detail: gap_detail.to_string(),
            }
        );

        let gap_detail = "missing-disable: disable contract required before experiment";
        let mut group = fixture("a");
        group.rollback.disable_ref = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::RollbackContractGap {
                detail: gap_detail.to_string(),
            }
        );

        let gap_detail = "missing-reopen: reopen contract required before experiment";
        let mut group = fixture("a");
        group.rollback.reopen_ref = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::RollbackContractGap {
                detail: gap_detail.to_string(),
            }
        );

        let gap_detail = "missing-expiry: expiry must bind the admitted operation";
        let mut group = fixture("a");
        group.rollback.expiry_ref = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::RollbackContractGap {
                detail: gap_detail.to_string(),
            }
        );

        let gap_detail = "missing-forward-repair: forward repair required before experiment";
        let mut group = fixture("a");
        group.rollback.forward_repair_ref = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::RollbackContractGap {
                detail: gap_detail.to_string(),
            }
        );

        // The OWNER is a gap of exactly this kind, not the owner mismatch a
        // different owner produces: the gap check runs first, so a blank owner
        // is never compared against the policy at all.
        let gap_detail = "missing-rollback-owner: rollback owner required before experiment";
        let mut group = fixture("a");
        group.rollback.rollback_owner_id = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::RollbackContractGap {
                detail: gap_detail.to_string(),
            }
        );
    }

    /// The invalidation set is required, ceiled and member-bounded, and those
    /// three refusals are three DIFFERENT variants with three different payloads,
    /// so they are stated separately rather than flattened into one rollback
    /// gap.
    ///
    /// The admitted twin is again the unchanged fixture: the positive handoff
    /// above carries that fixture's three-member set while the handoff itself
    /// keeps the proposal's own two targets.
    #[test]
    fn a_rollback_invalidation_set_must_be_present_ceiled_and_member_bounded() {
        // An absent set is the named gap, and it is a gap rather than the
        // coverage relation a set that covers too little produces.
        let gap_detail = "missing-invalidation: invalidation set required before experiment";
        let mut group = fixture("a");
        group.rollback.invalidation_set = Vec::new();
        assert_eq!(
            group.refusal(),
            PipelineError::RollbackContractGap {
                detail: gap_detail.to_string(),
            }
        );

        // One member past the admitted set ceiling is a PROFILE refusal on the
        // set's own field name, not a gap: the contract does name a repair path,
        // and this run refuses to carry a set that large. The members stay
        // distinct so nothing here depends on the duplicate-set check, which
        // this refusal never reaches.
        let mut wide_set = fixture("a");
        let mut wide_members: Vec<String> = Vec::new();
        for index in 0..=IMPROVEMENT_MAX_SET_MEMBERS {
            wide_members.push(format!("invalidation-wide-{index}"));
        }
        wide_set.rollback.invalidation_set = wide_members;
        assert_eq!(
            wide_set.refusal(),
            PipelineError::InputProfileCeiling("rollback.invalidation_set")
        );

        // A member that names no target is a MISSING FIELD on the set, not a gap
        // and not the coverage relation: the set is present and within its
        // ceiling, so the member itself is what is read, and coverage is only
        // considered after every member passes.
        let mut blank_member = fixture("a");
        blank_member.rollback.invalidation_set[0] = "   ".to_string();
        assert_eq!(
            blank_member.refusal(),
            PipelineError::MissingField("rollback.invalidation_set")
        );

        // Past the reference ceiling that same member is a profile refusal, so
        // the set ceiling and the member ceiling are two rules and not one rule
        // stated twice.
        let mut wide_member = fixture("a");
        wide_member.rollback.invalidation_set[0] = "w".repeat(IMPROVEMENT_MAX_REFERENCE_BYTES + 1);
        assert_eq!(
            wide_member.refusal(),
            PipelineError::InputProfileCeiling("rollback.invalidation_set")
        );
    }

    #[test]
    fn an_uncovered_required_invalidation_target_refuses() {
        let mut group = fixture("a");
        group.rollback.invalidation_set = vec!["invalidation-cache".to_string()];
        assert_eq!(
            group.refusal(),
            PipelineError::UnboundRelation {
                relation: "rollback-proposal: required-invalidation-not-covered",
            }
        );

        // A rollback that covers MORE than the proposal requires still admits, and
        // the handoff keeps the proposal's own two targets: wider coverage is a
        // repair-path fact, not permission to invalidate anything else.
        let group = fixture("a");
        assert_eq!(
            group.admitted().invalidation_set,
            vec![
                "invalidation-cache".to_string(),
                "invalidation-store".to_string()
            ]
        );
        // Admitted for one canary, and admitted without authority to run it.
        assert!(!group.admitted().execution_authorized);
    }

    #[test]
    fn the_risk_ceiling_must_be_exactly_the_supported_bounded_value() {
        // There is no risk-ceiling enum and no `unbounded` constant in this
        // crate: the field is a bare `String` and the only admitted value is this
        // word, so `unbounded` is spelled as the literal that used to satisfy the
        // removed substring marker.
        assert_eq!(IMPROVEMENT_RISK_CEILING_BOUNDED, "bounded");

        let mut group = fixture("a");
        group.proposal.risk_ceiling = "unbounded".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );

        let mut group = fixture("a");
        group.proposal.risk_ceiling = "bounded-until-ok".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );

        let mut group = fixture("a");
        group.proposal.risk_ceiling = "Bounded".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );

        let mut group = fixture("a");
        group.proposal.risk_ceiling = "bounded ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );

        // The blank qualifier refuses with the SAME typed failure as `unbounded`:
        // `risk_ceiling` is a closed typed policy value with one admitted member,
        // so a value carrying no qualifier at all is unsupported, not absent, and
        // is never reported as a missing field.
        let mut group = fixture("a");
        group.proposal.risk_ceiling = "   ".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );

        let mut group = fixture("a");
        group.proposal.risk_ceiling = String::new();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );

        // A tab/CR/LF-only qualifier is the same blank case, refused the same way.
        let mut group = fixture("a");
        group.proposal.risk_ceiling = "\t\r\n".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );
    }

    #[test]
    fn both_public_entry_points_refuse_a_blank_risk_ceiling_identically() {
        // The admitting path and the gate are two public entry points over the
        // same seven records, and the daemon route re-proposes the identical
        // bytes through the gate after the admitting path refuses — the gate's
        // own typed error is the one a caller then receives. If the two named
        // different violations for one record, the route would report a missing
        // field for a field that is present, contradicting what the admitting
        // path said about the very same bytes.
        for blank in ["", "   ", "\t\r\n"] {
            let mut group = fixture("a");
            group.proposal.risk_ceiling = blank.to_string();
            let expected = PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            };
            assert_eq!(
                group.refusal(),
                expected,
                "admitting path must refuse a blank risk ceiling as unsupported, blank={blank:?}"
            );
            assert_eq!(
                group.gate_refusal(),
                expected,
                "gate must refuse a blank risk ceiling as unsupported, blank={blank:?}"
            );
        }

        // DELIBERATE BOUNDARY, not an oversight: this entry point does not enforce the
        // full closed risk set, because its own contract says it applies the
        // gate's rules and not the admission preconditions. What it does not do
        // is misreport a field that IS present as absent — and that is the whole
        // of what this change alters. A nonblank wrong qualifier reaches the
        // admitting path first on the real route, which refuses it as
        // unsupported before the gate is ever called, so widening the gate here
        // would be a second set of admission rules in a function that documents
        // it has none.
        let mut group = fixture("a");
        group.proposal.risk_ceiling = "unbounded".to_string();
        assert_eq!(
            group.refusal(),
            PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
        );
        assert!(!matches!(
            group.gate_refusal(),
            PipelineError::UnsupportedRiskCeiling { .. }
        ));
    }

    #[test]
    fn two_valid_groups_cannot_form_one_accepted_mixed_result() {
        // Both halves are individually complete and individually admitted: this
        // is a counterexample about MIXING, not about either group.
        let group_a = fixture("a");
        let group_b = fixture("b");
        assert_eq!(group_a.admitted().candidate_id, "cand-2702-a");
        assert_eq!(group_b.admitted().candidate_id, "cand-2702-b");
        // Both are admitted handoffs, so both are non-authorizing records: the
        // mixing question never changes what an admission is allowed to grant.
        assert!(!group_a.admitted().execution_authorized);
        assert!(!group_b.admitted().execution_authorized);

        // The explicit A/B counterexample: proposal, plan, evaluation evidence
        // and rollback contract of group A, with the independently valid candidate
        // view, admission review and policy of group B.
        let mut mixed = fixture("a");
        mixed.candidate = group_b.candidate.clone();
        mixed.admission_evidence = group_b.admission_evidence.clone();
        mixed.policy = group_b.policy.clone();
        assert_eq!(
            mixed.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: candidate-identity-mismatch",
            }
        );

        // The other half of the same mixture: group A's own proposal, plan,
        // evaluation, rollback, candidate and policy, with group B's admission
        // review.
        let mut mixed_review = fixture("a");
        mixed_review.admission_evidence = group_b.admission_evidence.clone();
        assert_eq!(
            mixed_review.refusal(),
            PipelineError::UnboundRelation {
                relation: "admission-evidence: candidate-binding-mismatch",
            }
        );

        // And group B's own records are still refused against group A's proposal
        // in the other direction, so the join is symmetric in what it refuses.
        let mut mixed_plan = fixture("b");
        mixed_plan.proposal = group_a.proposal.clone();
        assert_eq!(
            mixed_plan.refusal(),
            PipelineError::UnboundRelation {
                relation: "proposal-candidate: candidate-identity-mismatch",
            }
        );
    }

    #[test]
    fn a_distinct_properly_linked_admission_reviewer_still_admits() {
        let handoff = fixture("a").admitted();

        // Two different reviewer principals, related by the typed binding to the
        // same candidate, experiment and content revision rather than by identity
        // equality.
        assert_ne!(handoff.evidence_verifier_id, handoff.admission_evaluator_id);
        assert_eq!(
            handoff.evidence_verifier_id,
            "instrument-verifier-20-1111-eval-a"
        );
        assert_eq!(
            handoff.admission_evaluator_id,
            "instrument-verifier-20-1111-review-a"
        );
        assert_eq!(
            handoff.admission_content_revision_ref,
            handoff.evidence_content_revision_ref
        );
        assert_eq!(handoff.candidate_id, "cand-2702-a");
        assert_eq!(handoff.experiment_id, "exp-2702-a");
        assert!(!handoff.execution_authorized);
    }

    #[test]
    fn the_admitted_branch_is_unreachable_without_an_admitted_pulse_reference() {
        let mut without_pulse = fixture("a");
        without_pulse.admission_evidence.pulse_ref = None;
        // With no pulse evidence there is no handoff at all: the gate names the
        // missing evidence and the owner that must supply it instead of
        // admitting.
        match without_pulse.run() {
            Ok(ImprovementTerminalDisposition::Inconclusive { missing, owner_id }) => {
                assert_eq!(
                    missing,
                    "missing-product-pulse: pulse evidence ref required"
                );
                assert_eq!(owner_id, "instrument-verifier-20-1111-review-a");
            }
            other => panic!("a review without pulse evidence must not admit, got {other:?}"),
        }

        // A pulse reference the owner never issued is the same absence: the gate
        // reads it as blank, and a handoff is not produced.
        let mut blank_pulse = fixture("a");
        blank_pulse.admission_evidence.pulse_ref = Some("   ".to_string());
        match blank_pulse.run() {
            Ok(ImprovementTerminalDisposition::Inconclusive { missing, .. }) => {
                assert_eq!(
                    missing,
                    "missing-product-pulse: pulse evidence ref required"
                );
            }
            other => panic!("a blank pulse reference must not admit, got {other:?}"),
        }

        // Control: the same group with the owner-issued reference admits, and its
        // handoff carries that exact pulse evidence and no execution authority.
        let control = fixture("a");
        assert_eq!(
            control.admitted().admission_pulse_ref,
            "pulse-evidence-2702-a"
        );
        // The control's handoff is an admitted handoff too, so it carries the
        // owner's pulse evidence AND no execution authority.
        assert!(!control.admitted().execution_authorized);
    }

    /// Norm: `I12.24:60, :76` - the pipeline reaches evaluation before any promotion.
    #[test]
    fn gate_without_execution_evidence_rejects_invalid_closure_and_records_durable_decision() {
        let mut group = fixture("a");
        group.admission_evidence.closure_valid = false;
        // This gate entry is the exact production path the daemon calls when no
        // executed evidence exists, so an invalid closure binding must close here as
        // a recorded `Rejected` disposition - never as an admission, and never as an
        // untyped escape out of the entry point.
        let disposition = match admit_improvement_candidate_without_execution_evidence(
            &group.proposal,
            &group.experiment,
            &group.candidate,
            &group.admission_evidence,
            &group.policy,
        ) {
            Ok(disposition) => disposition,
            Err(error) => panic!("the gate must dispose an invalid closure binding, got {error:?}"),
        };
        match &disposition {
            ImprovementTerminalDisposition::Rejected { cause, reason, .. } => {
                assert_eq!(*cause, ImprovementRejectCause::InvalidClosureBinding);
                assert!(
                    reason.contains("invalid-closure-binding"),
                    "the recorded refusal must name the closure binding, got {reason}"
                );
            }
            other => panic!("an invalid closure binding must reject, got {other:?}"),
        }
        // The terminal outcome is then re-proved into a durable decision bound to
        // the candidate identity AND revision on top of the checked records. `current`
        // is `None` because this path publishes no checked current record, so the
        // proposal commitment stays absent rather than invented.
        let decision = match improvement_terminal_decision(
            group.proposal.candidate_id.as_str(),
            3,
            &group.proposal,
            &group.experiment,
            &group.evidence,
            None,
            &disposition,
        ) {
            Ok(decision) => decision,
            Err(error) => panic!("a recorded refusal must be a durable decision, got {error:?}"),
        };
        assert_eq!(decision.candidate_id, "cand-2702-a");
        assert_eq!(decision.candidate_revision, 3);
        assert_eq!(decision.disposition, disposition);
    }

    /// Norm: `I00-09:7` - the mapper's refusal branches on the real path (AUD7).
    #[test]
    fn stale_closure_binding_maps_to_blocked_with_typed_cause_owner_and_remedy() {
        let mut group = fixture("stale");
        group.admission_evidence.closure_stale = true;
        match group.run() {
            Ok(ImprovementTerminalDisposition::Blocked {
                cause,
                remedy,
                reason,
                owner_id,
            }) => {
                // The typed cause, not the reason wording, carries the verdict:
                // the remedy is derived from the cause, so a reworded reason
                // cannot change what the owner must do. The reason is asserted
                // non-empty only, never by text.
                assert_eq!(cause, ImprovementBlockCause::StaleClosure);
                assert_eq!(remedy, cause.remedy());
                assert_eq!(owner_id, group.policy.external_owner_id);
                assert!(!reason.trim().is_empty());
            }
            Ok(other) => panic!("a stale closure binding must block, got {other:?}"),
            Err(error) => panic!("a stale closure binding must block, got {error:?}"),
        }
    }

    /// Norm: `I00-09:7` - the mapper's refusal branches on the real path (A2).
    #[test]
    fn observed_harm_maps_to_rejected_with_typed_cause() {
        let mut group = fixture("harm");
        group.admission_evidence.harm_observed = true;
        match group.run() {
            Ok(ImprovementTerminalDisposition::Rejected {
                cause,
                reason,
                owner_id,
            }) => {
                assert_eq!(cause, ImprovementRejectCause::HarmObserved);
                assert_eq!(owner_id, group.policy.external_owner_id);
                assert!(!reason.trim().is_empty());
            }
            Ok(other) => panic!("observed harm must reject, got {other:?}"),
            Err(error) => panic!("observed harm must reject, got {error:?}"),
        }
    }

    /// Norm: `I00-09:7` - the mapper's refusal branches on the real path (A3).
    #[test]
    fn pulse_regression_maps_to_regression_rejected_with_typed_cause() {
        let mut group = fixture("regression");
        group.admission_evidence.pulse = ImprovementPulseOutcome::Regression;
        match group.run() {
            Ok(ImprovementTerminalDisposition::RegressionRejected {
                cause,
                reason,
                owner_id,
            }) => {
                assert_eq!(cause, ImprovementRejectCause::PulseRegression);
                assert_eq!(owner_id, group.policy.external_owner_id);
                assert!(!reason.trim().is_empty());
            }
            Ok(other) => panic!("a pulse regression must regress-reject, got {other:?}"),
            Err(error) => panic!("a pulse regression must regress-reject, got {error:?}"),
        }
    }

    /// Norm: `I00-09:7` - the mapper's refusal branches on the real path (A4/A6).
    #[test]
    fn unknown_outcome_maps_to_reconciliation_obligation_bound_to_candidate() {
        let mut group = fixture("unknown");
        group.admission_evidence.outcome_unknown = true;
        match group.run() {
            Ok(ImprovementTerminalDisposition::UnknownRequiresReconciliation { obligation }) => {
                // The obligation is a value bound to the checked records, not a
                // sentence: it names the exact candidate, experiment and owner
                // this run checked.
                assert_eq!(obligation.candidate_id, "cand-2702-unknown");
                assert_eq!(obligation.experiment_id, group.experiment.experiment_id);
                assert_eq!(obligation.owner_id, group.policy.external_owner_id);
                assert!(!obligation.commitment.digest.trim().is_empty());
            }
            Ok(other) => panic!("an unknown outcome must require reconciliation, got {other:?}"),
            Err(error) => panic!("an unknown outcome must require reconciliation, got {error:?}"),
        }
    }

    /// Norm: `I00-09:7` - only the typed no-executed-evidence refusal may reach
    /// the gate (AUD3 trigger).
    #[test]
    fn unexecuted_evidence_refuses_as_typed_not_executed_before_any_disposition() {
        let mut group = fixture("unexecuted");
        group.evidence.execution = ImprovementEvidenceExecution::NotExecuted;
        assert_eq!(
            group.refusal(),
            PipelineError::EvidenceNotExecuted {
                status: "not-executed",
            }
        );
    }
}
