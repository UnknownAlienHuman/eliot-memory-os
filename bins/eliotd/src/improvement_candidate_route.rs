//! Production improvement-candidate route: candidate to experiment to evaluation.
//!
//! This module is the production caller of the Governor-owned improvement
//! pipeline (`#1100`, Governor `#18`, Testd `#20`). One improvement candidate
//! flows through bounded experiment to independent evaluation to Governor
//! admission, ending rejected or canary-admitted.
//!
//! Ownership split (handoff only, never executed here):
//! - Testd (`#20`) executes the bounded experiment and measures it;
//! - the Instrument verifier family (`#20`/`#1111`) independently evaluates;
//! - Governor maintenance (`G-19`, `#18`) admits through
//!   `run_improvement_candidate_pipeline` (transitively
//!   `admit_improvement_candidate`);
//! - Kernel generation/canary activation (`#11`) is a handoff request the
//!   Kernel owner must independently authorize and execute.
//!
//! This route is advisory-only: it never promotes, activates, installs,
//! completes, or issues authority. Pure delegation to the Governor owner
//! crate; no state machines, policy semantics, stores, providers,
//! credentials, or repair logic live here.
//!
//! # One checked commitment, never a second one
//!
//! Every consumer here reads the record the Governor pipeline committed.
//! [`route_improvement_candidate`] returns the disposition whose canary handoff
//! carries that exact commitment and its discriminator projection,
//! [`check_improvement_handoff_identity`] reads a returned handoff against this
//! build's checked wire revision and content identity, and
//! [`assess_improvement_repeat`] compares a retained prior record against that
//! same checked record. None of them computes a digest, substitutes a fallback,
//! empty, or legacy value, or swallows a failure: a hashing or serialization
//! failure is produced once by the pipeline and crosses into the daemon as the
//! typed `PipelineError` it is.
//!
//! # The consumer checks the producer's version or refuses the record
//!
//! Every consumer of a committed record here verifies that the record carries
//! the identity this daemon's build checks — its wire revision, and its domain,
//! encoding revision, or algorithm — so a record written under another identity
//! is a typed refusal ([`eliot_maintenance::UncheckedWireRevision`] or
//! [`eliot_maintenance::UncheckedRecordIdentity`]) and never a tolerated value.
//! The recorded digest is validated against the value the producer recorded; it
//! is never recomputed over local state, and no digest, placeholder, or empty
//! string stands in for a record this build cannot read.
//!
//! # The external effect is read from its owner, never settled here
//!
//! [`read_improvement_effect_state`] is the one place this route answers "what
//! happened to the external effect this candidate names", and it answers it by
//! forwarding to the Governor owner: the retry gate from
//! [`improvement_candidate_retry_permitted`] and the owner's retained result
//! from [`retained_improvement_candidate_completion`]. It attaches nothing. The
//! owner's outcome field is private to the Governor module, its only writer
//! re-checks the receipt's binding to the obligation's exact operation identity,
//! and no producer of such a receipt exists in this workspace — so every answer
//! this route produces is the denying one, which is stated on
//! [`ImprovementEffectState`] rather than papered over with a receipt this daemon
//! would have had to invent.

use eliot_maintenance::improvement_pipeline::{
    ImprovementCurrentProposal, RetainedImprovementProposal, compare_improvement_commitments,
};
use eliot_maintenance::{
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_PIPELINE_OWNER, ImprovementAdmissionDecision,
    ImprovementAdmissionPolicy, ImprovementCanaryHandoff, ImprovementCandidateView,
    ImprovementEvidenceView, ImprovementOperation, ImprovementPipelineInputs, ImprovementProposal,
    ImprovementTerminalDisposition, RollbackContract, check_checked_record_identity,
    check_handoff_wire_revision, improvement_retry_permitted, reconcile_unknown_activation,
    retained_improvement_completion, run_improvement_candidate_pipeline,
};
use serde::Serialize;

/// Borrowed inputs for one production improvement-candidate route call.
///
/// Mirrors [`eliot_maintenance::ImprovementPipelineInputs`] so the production
/// caller forwards the exact borrowed set the Governor pipeline owns, without
/// restating any validation, binding, or admission semantics.
#[derive(Clone, Copy, Debug)]
pub struct ImprovementRouteRequest<'a> {
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

/// Routes one improvement candidate through the Governor-owned pipeline.
///
/// This is the production caller of
/// [`eliot_maintenance::run_improvement_candidate_pipeline`] (and transitively
/// of `admit_improvement_candidate`). Pure thin forwarder: it constructs the
/// Governor-owned [`eliot_maintenance::ImprovementPipelineInputs`] from the
/// borrowed request and returns the advisory-only terminal disposition.
///
/// The route deliberately computes no proposal digest of its own. The checked
/// pipeline joins the inputs, computes exactly one commitment and the
/// discriminator projection of the same bytes, and carries that one record both
/// into the joined result and into the canary handoff, so a pre-validation
/// digest computed here could only disagree with the committed one. A hashing
/// or serialization failure is produced once, by the pipeline, and crosses this
/// boundary as the typed [`eliot_maintenance::PipelineError`] it is: there is no
/// fallback digest, no empty digest, and no legacy value substituted for it.
/// Never promotes, activates, or completes; a `CanaryAdmitted` disposition
/// carries an inspectable, non-authorizing handoff for Kernel (`#11`)
/// authorization.
pub fn route_improvement_candidate(
    request: ImprovementRouteRequest<'_>,
) -> Result<eliot_maintenance::ImprovementTerminalDisposition, eliot_maintenance::PipelineError> {
    run_improvement_candidate_pipeline(ImprovementPipelineInputs {
        proposal: request.proposal,
        experiment: request.experiment,
        evidence: request.evidence,
        rollback: request.rollback,
        candidate: request.candidate,
        admission_evidence: request.admission_evidence,
        policy: request.policy,
    })
}

/// Reads one `CanaryAdmitted` handoff against this build's checked identity.
///
/// The daemon-side read of a handoff the pipeline committed. A handoff is a
/// RECORD — the exact commitment, discriminator projection and
/// material-equality key the pipeline derived from one normalized proposal —
/// and this is the point at which the daemon checks that record against the
/// same constants this build commits with, before the handoff is named as
/// anything other than an opaque log line.
///
/// Two existing owner checks are applied, in the order their two questions
/// differ:
///
/// 1. [`eliot_maintenance::check_handoff_wire_revision`] — WHICH serialized
///    shape the record was written under. The recorded `wire_revision` is
///    compared against the constant the producer stamps; it is never rounded,
///    padded, or read as though the current shape had produced it.
/// 2. [`eliot_maintenance::check_checked_record_identity`] — WHICH content
///    identity the record carries: the domain, encoding revision and algorithm
///    of the handoff's own `proposal_commitment`, `proposal_discriminator` and
///    `proposal_material_equality`.
///
/// Nothing is recomputed. The commitment is validated as the ORIGINAL recorded
/// value against the producer's own constants: no digest is re-derived over
/// local state and called a match, and no substitute, empty, or legacy digest
/// stands in for a record this build cannot read. A refusal crosses this
/// boundary as the typed [`eliot_maintenance::PipelineError`] the owner check
/// produced — [`eliot_maintenance::UncheckedWireRevision`] or
/// [`eliot_maintenance::UncheckedRecordIdentity`], each through its own `From`
/// arm — and never as a tolerated handoff or a log string standing in for one.
///
/// # Why an `ImprovementCurrentProposal` view is assembled here
///
/// The content-identity check is typed over [`ImprovementCurrentProposal`], and
/// that is the shape it is compared on everywhere else in the owner crate. The
/// view below carries the handoff's OWN three identity objects — its recorded
/// commitment, discriminator and material-equality key, copied, never derived —
/// together with the candidate identity the handoff itself records and the
/// exact experiment plan this same route call passed to the pipeline. No field
/// is invented and no value is derived: the check reads only the three identity
/// objects, so the view exists solely to reach the existing owner check rather
/// than to restate it. This is a read view, never a committed record, never a
/// stored record, and never an input to a progress assessment — a retained
/// record and a real comparison stay with
/// [`assess_improvement_repeat`], which is the only function here that compares
/// records.
///
/// A `CanaryAdmitted` handoff is still NOT an activation: nothing here
/// promotes, activates, installs, completes, or issues authority, and
/// `execution_authorized` stays false in every construction the pipeline makes.
pub fn check_improvement_handoff_identity(
    handoff: &ImprovementCanaryHandoff,
    experiment: &ExperimentPlan,
) -> Result<(), eliot_maintenance::PipelineError> {
    check_handoff_wire_revision(handoff)?;
    // `From<UncheckedRecordIdentity>` and `From<UncheckedWireRevision>` are
    // separate arms of `PipelineError`, so each owner refusal keeps its own
    // type across this boundary instead of collapsing into one reason string.
    check_checked_record_identity(&ImprovementCurrentProposal {
        candidate_id: handoff.candidate_id.clone(),
        commitment: handoff.proposal_commitment.clone(),
        discriminator: handoff.proposal_discriminator.clone(),
        material_equality: handoff.proposal_material_equality.clone(),
        experiment_plan: experiment.clone(),
    })?;
    Ok(())
}

/// Returns the owning identity for each of the eight distinct pipeline operations.
///
/// Production caller of [`ImprovementOperation::owner`]: Propose/Admit/Promote
/// resolve to Governor maintenance, Execute/Measure to Testd, Evaluate to the
/// independent Instrument verifier, `CanaryActivate` to Kernel (handoff only),
/// and Rollback to the bound rollback-contract owner.
///
/// # This map is READ on the live route, not merely published
///
/// The daemon consults this map at the ONE point where it decides the routing of
/// its own records:
/// `improvement_candidate_dispatch::dispatch_improvement_candidate_route` reads
/// it before it builds anything, and the owner identities it then writes into
/// its `ExperimentPlan`, `ActivationEvidence`, `ImprovementEvidenceView` and
/// `RollbackContract` come from here rather than from a constant re-spelled at
/// the field. The Governor crate then re-checks those very fields independently —
/// `check_experiment_owner_routing` refuses an executor that is not the Testd
/// owner, `check_evaluator_independence` refuses an evidence verifier that is not
/// the planned one or that is the executor, the admission owner or the rollback
/// owner (A14.6, A5.5), and `check_rollback_join` refuses a rollback owner that
/// disagrees with the admission policy — so a map entry that ever resolved
/// elsewhere would REFUSE the route rather than be recorded and discarded.
///
/// `rollback_owner_id` is the map's only input because Rollback is the one
/// operation with no fixed pipeline owner. On the live path the value passed is
/// the same `G-19` admission policy record's own
/// [`eliot_maintenance::ImprovementAdmissionPolicy::rollback_owner_id`] the
/// request already carries, so the owner the map names and the owner the
/// pipeline compares against are one value read once, never a literal.
///
/// The map projects all eight operations and the daemon reads three of them
/// (`ExecuteExperiment`, `Evaluate`, `Rollback`), because those are the three
/// whose owner the daemon has to state in a record it builds. The remaining five
/// are stamped or decided inside the Governor crate this route calls — including
/// the `CanaryActivate` owner the pipeline writes into the handoff's
/// `activation_owner_id` and the daemon only reads — so there is no daemon-side
/// field for them to appear in, and the map is left complete rather than trimmed
/// to what one caller happens to read.
#[must_use]
pub fn improvement_operation_owners(rollback_owner_id: &str) -> [(&'static str, String); 8] {
    [
        (
            ImprovementOperation::Propose.as_str(),
            ImprovementOperation::Propose
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::ExecuteExperiment.as_str(),
            ImprovementOperation::ExecuteExperiment
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Measure.as_str(),
            ImprovementOperation::Measure
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Evaluate.as_str(),
            ImprovementOperation::Evaluate
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Admit.as_str(),
            ImprovementOperation::Admit
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::CanaryActivate.as_str(),
            ImprovementOperation::CanaryActivate
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Promote.as_str(),
            ImprovementOperation::Promote
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::Rollback.as_str(),
            ImprovementOperation::Rollback
                .owner(rollback_owner_id)
                .to_string(),
        ),
    ]
}

/// Assesses one retained prior record against the current checked record.
///
/// Production caller of
/// [`eliot_maintenance::improvement_pipeline::compare_improvement_commitments`].
/// Both arguments are records the Governor pipeline already committed: `current`
/// is the exact commitment and discriminator projection the pipeline computed
/// and carried into the canary handoff, and `retained` is the prior record its
/// owner retained. This route commits nothing and hashes nothing, so it can
/// neither substitute a second opinion, an empty digest, nor a legacy value.
///
/// # The consumer uses the producer's checked version, or refuses
///
/// The assessment is derived only when `current` carries the SAME domain,
/// encoding revision, and algorithm this daemon's build checks. A record under
/// any other identity is refused as the typed
/// [`eliot_maintenance::UncheckedRecordIdentity`], which crosses into the
/// daemon as the [`eliot_maintenance::PipelineError`] it wraps rather than
/// becoming a verdict:
/// there is no fallback assessment, no empty or legacy digest standing in for
/// the record, and no digest recomputed over what this process happens to hold.
/// A digest is validated against the ORIGINAL recorded value; it is never
/// recomputed over local state and called a match.
///
/// The caller supplies no progress boolean: a new proposal identity, a different
/// digest, or a repeat all establish no progress by themselves, an absent or
/// non-discriminating retained record establishes nothing, and no unknown
/// external effect is cleared here. Effect retry stays with its own owner.
pub fn assess_improvement_repeat(
    retained: &RetainedImprovementProposal,
    current: &ImprovementCurrentProposal,
) -> Result<eliot_maintenance::ImprovementReplayAssessment, eliot_maintenance::PipelineError> {
    compare_improvement_commitments(retained, current).map_err(Into::into)
}

/// Preserves an unknown external activation outcome without retrying blindly.
///
/// Production caller of [`reconcile_unknown_activation`]. The prior decision,
/// the checked record this run committed, and the gap-free rollback contract
/// this run was admitted against are all required: the resulting
/// [`eliot_maintenance::ImprovementUnknownEffect`] obligation names the exact
/// candidate, experiment, commitment, owner and forward-repair/invalidation
/// bindings whose external effect is unresolved. No owner-validated effect
/// outcome is consumed here, so the obligation remains unresolved and its
/// retry gate stays closed.
///
/// This route records the unresolved disposition and issues no new attempt.
/// Effect reconciliation and retry stay with the external owners.
///
/// The obligation names the exact commitment this run checked, so `current`
/// must carry this build's checked identity: a record under another domain,
/// encoding revision, or algorithm is refused as the typed
/// [`eliot_maintenance::UncheckedRecordIdentity`] rather than bound into an
/// obligation whose named debt no owner can verify.
pub fn reconcile_improvement_unknown(
    prior: &ImprovementAdmissionDecision,
    current: &ImprovementCurrentProposal,
    rollback: &RollbackContract,
) -> Result<eliot_maintenance::ImprovementTerminalDisposition, eliot_maintenance::PipelineError> {
    reconcile_unknown_activation(prior, current, rollback)
}

/// Returns whether one candidate disposition permits a retry attempt.
///
/// Production caller of [`eliot_maintenance::improvement_retry_permitted`]. The
/// Governor gate it forwards to is exhaustive, so this wrapper inherits a
/// decided answer for every disposition and re-decides none of them here. An
/// unresolved external effect closes the gate because its owner has not settled
/// what happened, and a retained historical completed-rollback value closes it
/// too: the Governor pipeline holds no owner-validated rollback result, so a
/// contract reference alone is not evidence that a rollback completed. A
/// rejection, an inconclusive, a typed regression, a block, an exact repeat, and
/// a bound advisory handoff each leave the gate open because each carries its
/// own owner and remedy, and a fresh attempt is that owner's to make.
#[must_use]
pub fn improvement_candidate_retry_permitted(disposition: &ImprovementTerminalDisposition) -> bool {
    improvement_retry_permitted(disposition)
}

/// Returns the owner-retained result of a completed external effect, if any.
///
/// Production forwarder to the Governor-owned
/// [`eliot_maintenance::retained_improvement_completion`], the crate that owns
/// the unknown-effect obligation and is therefore the only place the owner's
/// retained receipt may be read. It decides nothing here: the Governor entry
/// point returns the retained result only for a settled `Committed` or
/// `Compensated` outcome bound to that obligation's exact operation identity,
/// and `None` for an unsettled, foreign, unknown, merely non-success, or
/// non-obligation disposition. `None` is the denying direction — this route
/// never invents a result, re-classifies an outcome, or turns a bare rollback
/// contract reference into a completion.
///
/// # What the daemon does not do yet
///
/// The daemon DOES produce a request for this route now
/// (`improvement_candidate_dispatch::dispatch_improvement_candidate_route`
/// builds one per maintenance observation), and it does read the disposition
/// that comes back. This forwarder is read through
/// [`read_improvement_effect_state`], which every dispatched route step calls,
/// so it is no longer an uncalled mechanism. What it still does not do is
/// discharge an effect: nothing in this workspace produces an owner-settled
/// [`eliot_authority::EffectReceipt`] for an improvement operation, so the
/// receipt this forwarder would return does not exist yet, and the Governor
/// entry point therefore returns `None` for every disposition the pipeline
/// produces today. Reading it as a running reconciliation would overstate the
/// daemon. The owner that could attach one is named in the report rather than
/// simulated: see [`UnknownEffectObligation::owner_id`].
#[must_use]
pub fn retained_improvement_candidate_completion(
    disposition: &ImprovementTerminalDisposition,
) -> Option<&eliot_receipts::ReceiptEnvelope> {
    retained_improvement_completion(disposition)
}

/// The exact identity of one unresolved external effect, as its owner must see
/// it.
///
/// Every field is copied from the Governor pipeline's own
/// [`eliot_maintenance::ImprovementUnknownEffect`], which its single
/// construction site builds from checked records only: the candidate and
/// experiment from the committed record, the operation and idempotency namespace
/// from that record's proposal commitment, and the forward-repair reference and
/// invalidation targets from the gap-free rollback contract. Nothing here is
/// derived, defaulted, or supplied by this daemon, so a durable copy of this
/// value can name no debt the Governor owner did not check.
///
/// The operation and idempotency pair is what the Governor owner re-checks when
/// a receipt is offered to the obligation, so it is carried verbatim rather than
/// restated: a receipt that names another operation is refused at that seam, and
/// this projection must not appear to relax it by spelling a different identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnknownEffectObligation {
    /// Owner that holds the unresolved reconciliation debt.
    pub owner_id: String,
    /// Candidate whose external activation or effect outcome is unresolved.
    pub candidate_id: String,
    /// Exact bounded experiment the unresolved effect belongs to.
    pub experiment_id: String,
    /// Committed logical operation an owner receipt must name.
    pub operation_ref: String,
    /// Committed idempotency namespace the same receipt must name.
    pub idempotency_key: String,
    /// Forward-repair reference the checked rollback contract names for an
    /// incomplete rollback effect.
    pub forward_repair_ref: String,
    /// Invalidation targets the checked rollback contract covers, in the
    /// contract's own committed order.
    pub invalidation_set: Vec<String>,
}

/// What one terminal disposition says about the external effect it names.
///
/// Both answers are read from the Governor owner and re-decided by nothing here:
/// the retry gate from [`improvement_candidate_retry_permitted`] and the owner's
/// retained result from [`retained_improvement_candidate_completion`]. An
/// unsettled, foreign, still-unknown, or merely non-success outcome therefore
/// denies the retry gate and retains no result, and a completed effect denies
/// the gate while its retained result is what the owner reads back — this
/// projection reports those two answers verbatim and never turns one into the
/// other.
///
/// # The absent owner, named rather than simulated
///
/// The effect owner's outcome is private to the Governor module and reachable
/// only through `ImprovementUnknownEffect::with_settled_owner_outcome`, whose
/// four re-checks this route cannot and does not bypass. No producer for such a
/// receipt exists in this workspace, so every `ImprovementEffectState` this
/// daemon builds today is the denying one: no obligation settled, no retry
/// permitted, no completion retained. That is the honest live report. Supplying a
/// receipt to discharge the debt is [`UnknownEffectObligation::owner_id`]'s
/// work, over [`ImprovementTerminalDisposition::UnknownRequiresReconciliation`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImprovementEffectState {
    /// The Governor gate's own answer for this disposition.
    pub retry_permitted: bool,
    /// Whether the effect owner has retained a result for a COMPLETED effect.
    pub completion_retained: bool,
    /// The unresolved obligation to route to its named owner, present only when
    /// the disposition carries one.
    pub obligation: Option<UnknownEffectObligation>,
}

/// Reads one terminal disposition's external-effect state from its owner.
///
/// Production caller of both effect forwarders above, in one place, so a consumer
/// never re-derives either answer. Every disposition is answered, and the
/// obligation projection names every variant explicitly rather than behind a
/// wildcard: adding a disposition stays a compile error here until its
/// obligation answer is decided, so a future variant cannot silently inherit "no
/// unresolved effect" from an unexamined default.
#[must_use]
pub fn read_improvement_effect_state(
    disposition: &ImprovementTerminalDisposition,
) -> ImprovementEffectState {
    ImprovementEffectState {
        retry_permitted: improvement_candidate_retry_permitted(disposition),
        completion_retained: retained_improvement_candidate_completion(disposition).is_some(),
        obligation: obligation_of(disposition),
    }
}

/// Projects the owner-facing identity of a disposition's unresolved effect.
///
/// `None` for every disposition that names no external effect. `RolledBack` is
/// named here for the same reason the Governor entry points name it: a bare
/// `contract_ref` is a contract reference, not a named unresolved effect, and
/// reading it as one would invent debt the checked records do not carry.
fn obligation_of(disposition: &ImprovementTerminalDisposition) -> Option<UnknownEffectObligation> {
    match disposition {
        ImprovementTerminalDisposition::UnknownRequiresReconciliation { obligation } => {
            Some(UnknownEffectObligation {
                owner_id: obligation.owner_id.clone(),
                candidate_id: obligation.candidate_id.clone(),
                experiment_id: obligation.experiment_id.clone(),
                operation_ref: obligation.commitment.operation_ref.clone(),
                idempotency_key: obligation.commitment.idempotency_key.clone(),
                forward_repair_ref: obligation.forward_repair_ref.clone(),
                invalidation_set: obligation.invalidation_set.clone(),
            })
        }
        ImprovementTerminalDisposition::RolledBack { .. }
        | ImprovementTerminalDisposition::Rejected { .. }
        | ImprovementTerminalDisposition::Inconclusive { .. }
        | ImprovementTerminalDisposition::RegressionRejected { .. }
        | ImprovementTerminalDisposition::NoProgress { .. }
        | ImprovementTerminalDisposition::Blocked { .. }
        | ImprovementTerminalDisposition::CanaryAdmitted { .. } => None,
    }
}

/// Returns the Governor maintenance owner identity for the improvement route.
pub fn improvement_route_owner() -> &'static str {
    IMPROVEMENT_PIPELINE_OWNER
}
