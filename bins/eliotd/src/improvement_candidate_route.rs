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
    ImprovementTerminalDisposition, ImprovementUnknownEffectIdentity, RollbackContract,
    check_checked_record_identity, check_handoff_wire_revision, improvement_retry_permitted,
    reconcile_unknown_activation, retained_improvement_completion,
    run_improvement_candidate_pipeline,
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

/// Returns the owning identity for each of the nine distinct pipeline operations.
///
/// Production caller of [`ImprovementOperation::owner`]:
/// Propose/IngestCandidate/Admit/Promote resolve to Governor maintenance,
/// Execute/Measure to Testd, Evaluate to the
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
/// The map projects all nine operations and the daemon reads three of them
/// (`ExecuteExperiment`, `Evaluate`, `Rollback`), because those are the three
/// whose owner the daemon has to state in a record it builds. The remaining six
/// are stamped or decided inside the Governor crate this route calls — including
/// the `CanaryActivate` owner the pipeline writes into the handoff's
/// `activation_owner_id` and the daemon only reads — so there is no daemon-side
/// field for them to appear in, and the map is left complete rather than trimmed
/// to what one caller happens to read.
#[must_use]
pub fn improvement_operation_owners(rollback_owner_id: &str) -> [(&'static str, String); 9] {
    [
        (
            ImprovementOperation::Propose.as_str(),
            ImprovementOperation::Propose
                .owner(rollback_owner_id)
                .to_string(),
        ),
        (
            ImprovementOperation::IngestCandidate.as_str(),
            ImprovementOperation::IngestCandidate
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
/// simulated: see [`ImprovementUnknownEffectIdentity::owner_id`].
#[must_use]
pub fn retained_improvement_candidate_completion(
    disposition: &ImprovementTerminalDisposition,
) -> Option<&eliot_receipts::ReceiptEnvelope> {
    retained_improvement_completion(disposition)
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
/// The obligation is the Governor owner's OWN durable record,
/// [`eliot_maintenance::ImprovementUnknownEffectIdentity`], read through
/// `ImprovementUnknownEffect::retained_identity`. It is deliberately not a
/// daemon-local projection: a second, looser shape carrying the operation and
/// idempotency namespace as bare strings would be a second record for the same
/// debt, one no owner re-checks, and a reader could not tell which of the two it
/// was reading. Reading the owner's own record instead means the durable copy
/// carries the whole `ProposalCommitment` the pipeline computed — domain, encoding
/// revision, algorithm, operation reference, idempotency namespace, digest and
/// canonical size together — so the debt can be re-bound to the exact proposal
/// bytes it was raised over and the owner can content-check it on read-back.
///
/// # The absent owner, named rather than simulated
///
/// The effect owner's outcome is private to the Governor module and reachable
/// only through `ImprovementUnknownEffect::with_settled_owner_outcome`, whose
/// re-checks this route cannot and does not bypass. No producer for such a
/// receipt exists in this workspace, so every `ImprovementEffectState` this
/// daemon builds today is the denying one: no obligation settled, no retry
/// permitted, no completion retained. That is the honest live report. Supplying a
/// receipt to discharge the debt is
/// [`eliot_maintenance::ImprovementUnknownEffectIdentity::owner_id`]'s work,
/// over [`ImprovementTerminalDisposition::UnknownRequiresReconciliation`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImprovementEffectState {
    /// The Governor gate's own answer for this disposition.
    pub retry_permitted: bool,
    /// Whether the effect owner has retained a result for a COMPLETED effect.
    pub completion_retained: bool,
    /// The unresolved obligation to route to its named owner, present only when
    /// the disposition carries one. This is the Governor owner's own durable
    /// record, never a daemon-local restatement of it.
    pub obligation: Option<ImprovementUnknownEffectIdentity>,
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
///
/// The arm hands back the Governor owner's own durable record, read through
/// `retained_identity`, so the value committed for this debt and the value a
/// later pass reconciles are the same record rather than two shapes that can
/// drift apart.
fn obligation_of(
    disposition: &ImprovementTerminalDisposition,
) -> Option<ImprovementUnknownEffectIdentity> {
    match disposition {
        ImprovementTerminalDisposition::UnknownRequiresReconciliation { obligation } => {
            Some(obligation.retained_identity())
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

/// What the daemon-side route proofs establish, and what they deliberately do not.
///
/// The route is a thin forwarder, so what these proofs establish is that it
/// changes nothing: for the same seven records,
/// [`route_improvement_candidate`] returns the SAME
/// `Result<ImprovementTerminalDisposition, PipelineError>` the Governor owner's
/// own [`run_improvement_candidate_pipeline`] returns — the identical typed
/// disposition, and through the `CanaryAdmitted` variant the identical handoff,
/// field for field across all thirty-seven public fields of
/// [`eliot_maintenance::ImprovementCanaryHandoff`], because a handoff
/// difference IS a disposition difference. For the explicit A/B mixed pair,
/// where both halves are individually valid and admitted, both paths return
/// the identical typed `Err`, relation name included. And an admitted handoff
/// on either path carries `execution_authorized == false` under the Kernel
/// canary owner: the daemon wrapper never turns the Governor owner's advisory
/// record into a permit.
///
/// What these proofs deliberately do NOT establish is the per-field forwarding
/// of the seven arguments. The compiler settles that, not an assertion:
/// [`route_improvement_candidate`] is a struct-literal forwarder whose seven
/// forwarded field types are pairwise distinct, so a transposed or dropped
/// argument cannot compile at all. What is under test here is therefore the
/// route's result equivalence and its refusal equivalence - not the type-level
/// forwarding the type system already guarantees.
///
/// Every case drives the two REAL production entry points over real records and
/// reads only a value or a typed error they actually return. Nothing here names
/// the Governor crate's private joined-input view, its constructor, or its
/// private result mapper, and nothing widens their visibility to observe them:
/// the wrapper is proved through its own public result, which is the only thing
/// a daemon consumer ever reads.
#[cfg(test)]
mod tests {
    use super::*;

    use eliot_maintenance::improvement_pipeline::{
        IMPROVEMENT_DISCRIMINATOR_DOMAIN, IMPROVEMENT_DISCRIMINATOR_ENCODING_VERSION,
        IMPROVEMENT_MATERIAL_EQUALITY_DOMAIN, IMPROVEMENT_MATERIAL_EQUALITY_ENCODING_VERSION,
        IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN, IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM,
        IMPROVEMENT_PROPOSAL_ENCODING_VERSION, ImprovementDiscriminatorProjection,
    };
    use eliot_maintenance::{
        IMPROVEMENT_EFFECT_CEILING, IMPROVEMENT_LEGACY_DIGEST_ALGORITHM,
        IMPROVEMENT_PIPELINE_WIRE_REVISION, IMPROVEMENT_PROOF_CEILING,
        IMPROVEMENT_REQUESTED_EFFECT, IMPROVEMENT_RISK_CEILING_BOUNDED, ImprovementBlockCause,
        ImprovementEvidenceExecution, ImprovementMaterialEquality, ImprovementPulseOutcome,
        ImprovementRejectCause, KERNEL_CANARY_OWNER, MechanismDeclaration, OP_ADMIT, OP_PROPOSE,
        PipelineError, ProposalCommitment, TESTD_OWNER, VERIFIER_OWNER_FAMILY,
        improvement_admission_policy,
    };

    /// The rollback-contract owner a caller supplies, exactly as
    /// [`ImprovementOperation::owner`] requires of its `Rollback` arm. It is
    /// distinct from the executor, the admission authority, and the verifier
    /// family, which are the three principals the pipeline compares a reviewer
    /// against.
    const ROLLBACK_OWNER: &str = "external-rollback-owner-2702";

    /// The seven borrowed records of one joined group, owned so a test can mix
    /// two groups before either path is called.
    struct JoinedGroup {
        proposal: ImprovementProposal,
        experiment: ExperimentPlan,
        evidence: ActivationEvidence,
        rollback: RollbackContract,
        candidate: ImprovementCandidateView,
        admission_evidence: ImprovementEvidenceView,
        policy: ImprovementAdmissionPolicy,
    }

    /// The logical operation and idempotency namespace one group binds.
    fn idempotency_key(group: &str) -> String {
        format!("improvement-admission-2702-{group}")
    }

    /// The logical operation and idempotency namespace the RETAINED prior record
    /// binds.
    ///
    /// Deliberately not the current group's: the retained record must belong to
    /// another logical operation AND another idempotency namespace, so the
    /// replay gate cannot read it as an exact repeat of this run's operation.
    fn retained_idempotency_key(group: &str) -> String {
        format!("improvement-admission-2702-retained-{group}")
    }

    /// Reads one owner identity out of the production operation map.
    fn operation_owner(
        owners: &[(&'static str, String); 9],
        operation: ImprovementOperation,
    ) -> String {
        let name = operation.as_str();
        for (operation_name, owner) in owners {
            if *operation_name == name {
                return owner.clone();
            }
        }
        panic!("the operation owner map must project {name}")
    }

    /// The independent evaluator this daemon states in the records it builds,
    /// read from the route's own operation map rather than spelled at the field.
    fn experiment_evaluator() -> String {
        operation_owner(
            &improvement_operation_owners(ROLLBACK_OWNER),
            ImprovementOperation::Evaluate,
        )
    }

    /// Norm: `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md:60`
    /// - the pipeline runs to evaluation before any promotion, so the `Evaluate` row
    /// is what binds the record's grader.
    #[test]
    fn evaluate_row_binds_the_verifier_family_not_the_executor() {
        // Read the Evaluate row out of the production map rather than restating the
        // family literal beside it, so this proof covers the same projection the
        // route builds its records from.
        let owners = improvement_operation_owners(ROLLBACK_OWNER);
        let evaluator = operation_owner(&owners, ImprovementOperation::Evaluate);
        assert_eq!(evaluator, VERIFIER_OWNER_FAMILY);
        assert!(
            evaluator.starts_with("instrument-verifier-"),
            "the Evaluate row must name the Instrument verifier family, got {evaluator}"
        );
        // The executor is a different principal: A14.6 separates the production path
        // (Testd executes the bounded experiment) from the measurement path (the
        // verifier grades it), and A00.3 requires fail-closed behaviour where an
        // error could create hidden control capture - a party grading its own
        // experiment. `check_evaluator_independence` in the pipeline enforces the
        // same split.
        let executor = operation_owner(&owners, ImprovementOperation::ExecuteExperiment);
        assert_eq!(executor, TESTD_OWNER);
        assert_ne!(evaluator, executor);
        assert_eq!(evaluator, experiment_evaluator());
        // The records the route submits carry that map row, because `joined_group`
        // builds the plan and the evidence through `experiment_evaluator()`; a drift
        // between map and record refuses downstream as `UnboundRelation` instead of
        // passing silently.
        let group = joined_group("a");
        assert_eq!(group.experiment.evaluator_id, evaluator);
        assert_eq!(group.evidence.verifier_id, evaluator);
    }

    /// The admission policy record, built by its own owner-side constructor.
    fn policy_of(group: &str) -> ImprovementAdmissionPolicy {
        improvement_admission_policy(OP_ADMIT, &idempotency_key(group), ROLLBACK_OWNER)
    }

    /// The Governor-side proposal of one group.
    fn proposal_of(group: &str) -> ImprovementProposal {
        ImprovementProposal {
            proposal_id: format!("improvement-proposal-2702-{group}"),
            candidate_id: format!("improvement-candidate-2702-{group}"),
            campaign_id: format!("improvement-campaign-2702-{group}"),
            closure_id: format!("meta.learning.closure-2702-{group}"),
            closure_digest: format!("closure-digest-2702-{group}"),
            evidence_refs: vec![
                format!("owner-evidence-2702-{group}-alpha"),
                format!("owner-evidence-2702-{group}-beta"),
            ],
            target_capability: format!("maintenance-capability-2702-{group}"),
            target_generation: format!("resource-generation-2702-{group}"),
            mechanism: MechanismDeclaration {
                mechanism_id: format!("improvement-mechanism-2702-{group}"),
                hypothesis: format!(
                    "the bounded repair declared for group {group} removes one no-progress loop"
                ),
                causal_link: format!(
                    "the repair declared for group {group} is the intervention its delta tests"
                ),
                declared_ref: format!("improvement-proposal-declaration-2702-{group}"),
                declared_before_results: true,
            },
            expected_delta: format!(
                "advisory-only: the group-{group} counter-metric does not rise in scope"
            ),
            risk_ceiling: IMPROVEMENT_RISK_CEILING_BOUNDED.to_owned(),
            effect_ceiling: IMPROVEMENT_EFFECT_CEILING.to_owned(),
            budget_ref: format!("improvement-budget-2702-{group}"),
            deadline_ref: format!("improvement-deadline-2702-{group}"),
            privacy_class: "internal-maintenance".to_owned(),
            invalidation_set: vec![format!("invalidation-target-2702-{group}")],
            operation_ref: OP_ADMIT.to_owned(),
            idempotency_key: idempotency_key(group),
            source_identity: format!("source-identity-2702-{group}"),
            runtime_identity: format!("runtime-identity-2702-{group}"),
            data_identity: format!("data-identity-2702-{group}"),
        }
    }

    /// The Governor-side candidate view of one group.
    fn candidate_of(group: &str) -> ImprovementCandidateView {
        ImprovementCandidateView {
            candidate_id: format!("improvement-candidate-2702-{group}"),
            campaign_id: format!("improvement-campaign-2702-{group}"),
            closure_id: format!("meta.learning.closure-2702-{group}"),
            closure_digest: format!("closure-digest-2702-{group}"),
            promotion_input_id: None,
            promotion_digest: None,
            admitted_scope_ref: Some(format!("admitted-scope-2702-{group}")),
            proof_ceiling: IMPROVEMENT_PROOF_CEILING.to_owned(),
            requested_effect: IMPROVEMENT_REQUESTED_EFFECT.to_owned(),
            direct_promotion: false,
            active_permit: None,
            promotion_receipt: None,
            operation_ref: OP_ADMIT.to_owned(),
            idempotency_key: idempotency_key(group),
        }
    }

    /// The Testd-owned bounded plan of one group, using the identical admitted
    /// scope, budget, and deadline references, so no narrowing is claimed.
    fn experiment_of(group: &str, evaluator: &str) -> ExperimentPlan {
        ExperimentPlan {
            experiment_id: format!("improvement-experiment-2702-{group}"),
            testd_owner_id: TESTD_OWNER.to_owned(),
            evaluator_id: evaluator.to_owned(),
            scope_ref: format!("admitted-scope-2702-{group}"),
            budget_ref: format!("improvement-budget-2702-{group}"),
            deadline_ref: format!("improvement-deadline-2702-{group}"),
            operation_ref: OP_ADMIT.to_owned(),
            idempotency_key: idempotency_key(group),
            scope_refinement: None,
        }
    }

    /// The independent activation evidence of one group.
    fn activation_evidence_of(group: &str, evaluator: &str) -> ActivationEvidence {
        ActivationEvidence {
            evidence_id: format!("activation-evidence-2702-{group}"),
            verifier_id: evaluator.to_owned(),
            independent: true,
            verifier_passed: true,
            raw_evidence_ref: format!("raw-evidence-2702-{group}"),
            run_ref: format!("bounded-experiment-run-2702-{group}"),
            content_revision_ref: format!("content-revision-2702-{group}"),
            execution: ImprovementEvidenceExecution::Executed,
            bound_candidate_id: format!("improvement-candidate-2702-{group}"),
            bound_experiment_id: format!("improvement-experiment-2702-{group}"),
        }
    }

    /// The gap-free rollback contract of one group.
    fn rollback_of(group: &str) -> RollbackContract {
        RollbackContract {
            rollback_ref: format!("rollback-contract-2702-{group}"),
            disable_ref: format!("disable-contract-2702-{group}"),
            reopen_ref: format!("reopen-contract-2702-{group}"),
            expiry_ref: format!("expiry-contract-2702-{group}"),
            rollback_owner_id: ROLLBACK_OWNER.to_owned(),
            forward_repair_ref: format!("forward-repair-contract-2702-{group}"),
            invalidation_set: vec![format!("invalidation-target-2702-{group}")],
        }
    }

    /// The independent admission review of one group.
    fn admission_evidence_of(
        group: &str,
        evaluator: &str,
        rollback: &RollbackContract,
    ) -> ImprovementEvidenceView {
        ImprovementEvidenceView {
            verifier_id: evaluator.to_owned(),
            bound_candidate_id: format!("improvement-candidate-2702-{group}"),
            bound_experiment_id: format!("improvement-experiment-2702-{group}"),
            content_revision_ref: format!("content-revision-2702-{group}"),
            run_ref: format!("admission-review-run-2702-{group}"),
            independent: true,
            verifier_passed: true,
            pulse: ImprovementPulseOutcome::Pass,
            pulse_ref: Some(format!("product-pulse-2702-{group}")),
            harm_observed: false,
            outcome_unknown: false,
            closure_valid: true,
            closure_stale: false,
            rollback_ref: Some(rollback.rollback_ref.clone()),
            disable_ref: Some(rollback.disable_ref.clone()),
            reopen_ref: Some(rollback.reopen_ref.clone()),
            rollback_owner_id: ROLLBACK_OWNER.to_owned(),
            expiry_ref: Some(rollback.expiry_ref.clone()),
            retained_prior_proposal: Some(retained_prior_of(group, evaluator)),
        }
    }

    /// The retained prior record the admission review is compared against.
    ///
    /// This fixture must carry one: an absent retained record is assessed as
    /// `NoRetainedPrior`, which the replay gate maps to no progress, so no
    /// admitted case is reachable without it. It carries this build's checked
    /// commitment, discriminator, and material-equality identity, so the gate can
    /// compare it at all rather than reporting an unestablished observation; it
    /// binds a DIFFERENT operation and a DIFFERENT idempotency namespace than the
    /// joined group, so it is not this operation's exact replay; its whole
    /// material-equality key differs, so it is not a repeated bounded
    /// experiment; and it declares a strict subset of the group's owner-issued
    /// evidence references, so the gate's own comparison — not a caller flag — is
    /// what establishes a changed discriminator.
    fn retained_prior_of(group: &str, evaluator: &str) -> RetainedImprovementProposal {
        RetainedImprovementProposal {
            commitment: ProposalCommitment {
                domain: IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN.to_owned(),
                encoding_version: IMPROVEMENT_PROPOSAL_ENCODING_VERSION.to_owned(),
                algorithm: IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM.to_owned(),
                operation_ref: OP_PROPOSE.to_owned(),
                idempotency_key: retained_idempotency_key(group),
                digest: format!("retained-commitment-digest-2702-{group}"),
                canonical_bytes: 512,
            },
            discriminator: ImprovementDiscriminatorProjection {
                domain: IMPROVEMENT_DISCRIMINATOR_DOMAIN.to_owned(),
                encoding_version: IMPROVEMENT_DISCRIMINATOR_ENCODING_VERSION.to_owned(),
                source_identity: format!("source-identity-2702-{group}-prior"),
                runtime_identity: format!("runtime-identity-2702-{group}-prior"),
                data_identity: format!("data-identity-2702-{group}-prior"),
                target_capability: format!("maintenance-capability-2702-{group}-prior"),
                target_generation: format!("resource-generation-2702-{group}-prior"),
                mechanism_id: format!("improvement-mechanism-2702-{group}-prior"),
                hypothesis: format!("the prior declared hypothesis of group {group}"),
                causal_link: format!("the prior declared causal link of group {group}"),
                expected_delta: format!("the prior declared advisory delta of group {group}"),
                declared_evidence_refs: vec![format!("owner-evidence-2702-{group}-alpha")],
            },
            material_equality: ImprovementMaterialEquality {
                domain: IMPROVEMENT_MATERIAL_EQUALITY_DOMAIN.to_owned(),
                encoding_version: IMPROVEMENT_MATERIAL_EQUALITY_ENCODING_VERSION.to_owned(),
                mechanism_id: format!("improvement-mechanism-2702-{group}-prior"),
                target_capability: format!("maintenance-capability-2702-{group}-prior"),
                target_generation: format!("resource-generation-2702-{group}-prior"),
                budget_ref: format!("improvement-budget-2702-{group}-prior"),
                deadline_ref: format!("improvement-deadline-2702-{group}-prior"),
                experiment_id: format!("improvement-experiment-2702-{group}-prior"),
                declared_evidence_refs: vec![format!("owner-evidence-2702-{group}-alpha")],
            },
            experiment_plan: ExperimentPlan {
                experiment_id: format!("improvement-experiment-2702-{group}-prior"),
                testd_owner_id: TESTD_OWNER.to_owned(),
                evaluator_id: evaluator.to_owned(),
                scope_ref: format!("admitted-scope-2702-{group}-prior"),
                budget_ref: format!("improvement-budget-2702-{group}-prior"),
                deadline_ref: format!("improvement-deadline-2702-{group}-prior"),
                operation_ref: OP_PROPOSE.to_owned(),
                idempotency_key: retained_idempotency_key(group),
                scope_refinement: None,
            },
        }
    }

    /// One group whose seven records agree with each other.
    fn joined_group(group: &str) -> JoinedGroup {
        let evaluator = experiment_evaluator();
        let rollback = rollback_of(group);
        let experiment = experiment_of(group, &evaluator);
        let evidence = activation_evidence_of(group, &evaluator);
        let candidate = candidate_of(group);
        let admission_evidence = admission_evidence_of(group, &evaluator, &rollback);
        let policy = policy_of(group);
        JoinedGroup {
            proposal: proposal_of(group),
            experiment,
            evidence,
            rollback,
            candidate,
            admission_evidence,
            policy,
        }
    }

    /// The explicit A/B counterexample: one group's proposal-side records joined
    /// to another group's admission-side records.
    fn mixed_groups(first: &JoinedGroup, second: &JoinedGroup) -> JoinedGroup {
        JoinedGroup {
            proposal: first.proposal.clone(),
            experiment: first.experiment.clone(),
            evidence: first.evidence.clone(),
            rollback: first.rollback.clone(),
            candidate: second.candidate.clone(),
            admission_evidence: second.admission_evidence.clone(),
            policy: second.policy.clone(),
        }
    }

    /// The Governor owner's own entry point, called directly.
    fn pipeline_result(
        group: &JoinedGroup,
    ) -> Result<ImprovementTerminalDisposition, PipelineError> {
        run_improvement_candidate_pipeline(ImprovementPipelineInputs {
            proposal: &group.proposal,
            experiment: &group.experiment,
            evidence: &group.evidence,
            rollback: &group.rollback,
            candidate: &group.candidate,
            admission_evidence: &group.admission_evidence,
            policy: &group.policy,
        })
    }

    /// The daemon wrapper under test, called with the same records.
    fn route_result(group: &JoinedGroup) -> Result<ImprovementTerminalDisposition, PipelineError> {
        route_improvement_candidate(ImprovementRouteRequest {
            proposal: &group.proposal,
            experiment: &group.experiment,
            evidence: &group.evidence,
            rollback: &group.rollback,
            candidate: &group.candidate,
            admission_evidence: &group.admission_evidence,
            policy: &group.policy,
        })
    }

    /// Compares every returned handoff field of the two paths by name.
    fn assert_identical_handoffs(
        from_route: &ImprovementCanaryHandoff,
        from_pipeline: &ImprovementCanaryHandoff,
    ) {
        assert_eq!(from_route.wire_revision, from_pipeline.wire_revision);
        assert_eq!(from_route.proposal_id, from_pipeline.proposal_id);
        assert_eq!(
            from_route.proposal_commitment,
            from_pipeline.proposal_commitment
        );
        assert_eq!(
            from_route.proposal_discriminator,
            from_pipeline.proposal_discriminator
        );
        assert_eq!(
            from_route.proposal_material_equality,
            from_pipeline.proposal_material_equality
        );
        assert_eq!(from_route.candidate_id, from_pipeline.candidate_id);
        assert_eq!(from_route.campaign_id, from_pipeline.campaign_id);
        assert_eq!(from_route.closure_id, from_pipeline.closure_id);
        assert_eq!(from_route.closure_digest, from_pipeline.closure_digest);
        assert_eq!(
            from_route.target_capability,
            from_pipeline.target_capability
        );
        assert_eq!(
            from_route.target_generation,
            from_pipeline.target_generation
        );
        assert_eq!(from_route.experiment_id, from_pipeline.experiment_id);
        assert_eq!(from_route.operation_ref, from_pipeline.operation_ref);
        assert_eq!(from_route.idempotency_key, from_pipeline.idempotency_key);
        assert_eq!(
            from_route.experiment_scope_ref,
            from_pipeline.experiment_scope_ref
        );
        assert_eq!(from_route.budget_ref, from_pipeline.budget_ref);
        assert_eq!(from_route.deadline_ref, from_pipeline.deadline_ref);
        assert_eq!(from_route.evidence_id, from_pipeline.evidence_id);
        assert_eq!(
            from_route.evidence_verifier_id,
            from_pipeline.evidence_verifier_id
        );
        assert_eq!(from_route.evidence_run_ref, from_pipeline.evidence_run_ref);
        assert_eq!(
            from_route.evidence_content_revision_ref,
            from_pipeline.evidence_content_revision_ref
        );
        assert_eq!(from_route.raw_evidence_ref, from_pipeline.raw_evidence_ref);
        assert_eq!(
            from_route.admission_evaluator_id,
            from_pipeline.admission_evaluator_id
        );
        assert_eq!(
            from_route.admission_run_ref,
            from_pipeline.admission_run_ref
        );
        assert_eq!(
            from_route.admission_content_revision_ref,
            from_pipeline.admission_content_revision_ref
        );
        assert_eq!(
            from_route.admission_pulse_ref,
            from_pipeline.admission_pulse_ref
        );
        assert_eq!(
            from_route.admission_owner_id,
            from_pipeline.admission_owner_id
        );
        assert_eq!(from_route.rollback_ref, from_pipeline.rollback_ref);
        assert_eq!(from_route.disable_ref, from_pipeline.disable_ref);
        assert_eq!(from_route.reopen_ref, from_pipeline.reopen_ref);
        assert_eq!(from_route.expiry_ref, from_pipeline.expiry_ref);
        assert_eq!(
            from_route.forward_repair_ref,
            from_pipeline.forward_repair_ref
        );
        assert_eq!(
            from_route.rollback_owner_id,
            from_pipeline.rollback_owner_id
        );
        assert_eq!(from_route.invalidation_set, from_pipeline.invalidation_set);
        assert_eq!(
            from_route.activation_owner_id,
            from_pipeline.activation_owner_id
        );
        assert_eq!(
            from_route.handoff_projection,
            from_pipeline.handoff_projection
        );
        assert_eq!(
            from_route.execution_authorized,
            from_pipeline.execution_authorized
        );
    }

    #[test]
    fn route_returns_the_pipeline_disposition_and_handoff_for_a_joined_group() {
        let mut group = joined_group("a");
        let routed = route_result(&group);
        let direct = pipeline_result(&group);
        // Both sides are the same `Result<ImprovementTerminalDisposition,
        // PipelineError>` type, so this one comparison covers the identical typed
        // disposition AND, through the `CanaryAdmitted` variant, the identical
        // handoff: a handoff difference changes the disposition value.
        assert_eq!(routed, direct);
        let routed_handoff = match routed {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => handoff,
            other => panic!("the routed disposition must be a canary handoff, got {other:?}"),
        };
        let direct_handoff = match direct {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => handoff,
            other => panic!("the pipeline disposition must be a canary handoff, got {other:?}"),
        };
        assert_identical_handoffs(&routed_handoff, &direct_handoff);
        assert_eq!(routed_handoff.candidate_id, group.candidate.candidate_id);
        assert_eq!(routed_handoff.campaign_id, group.proposal.campaign_id);
        assert_eq!(routed_handoff.closure_id, group.candidate.closure_id);
        assert_eq!(
            routed_handoff.closure_digest,
            group.candidate.closure_digest
        );
        assert_eq!(routed_handoff.experiment_scope_ref, "admitted-scope-2702-a");
        assert_eq!(routed_handoff.budget_ref, group.proposal.budget_ref);
        assert_eq!(routed_handoff.deadline_ref, group.proposal.deadline_ref);
        assert_eq!(routed_handoff.experiment_id, group.experiment.experiment_id);
        assert_eq!(routed_handoff.evidence_verifier_id, VERIFIER_OWNER_FAMILY);
        assert_eq!(routed_handoff.admission_evaluator_id, VERIFIER_OWNER_FAMILY);
        assert_eq!(routed_handoff.admission_pulse_ref, "product-pulse-2702-a");
        assert_eq!(routed_handoff.rollback_owner_id, ROLLBACK_OWNER);
        assert_eq!(
            routed_handoff.invalidation_set,
            vec!["invalidation-target-2702-a".to_owned()]
        );
        assert_eq!(
            routed_handoff.proposal_commitment.domain,
            IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN
        );
        assert_eq!(
            routed_handoff.proposal_commitment.encoding_version,
            IMPROVEMENT_PROPOSAL_ENCODING_VERSION
        );
        assert_eq!(
            routed_handoff.proposal_commitment.algorithm,
            IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM
        );
        assert_eq!(
            routed_handoff.proposal_discriminator.domain,
            IMPROVEMENT_DISCRIMINATOR_DOMAIN
        );
        assert_eq!(
            routed_handoff.proposal_material_equality.domain,
            IMPROVEMENT_MATERIAL_EQUALITY_DOMAIN
        );

        // The equality at the top of this test cannot on its own tell a
        // forwarder from a wrapper that returned one constant built from the
        // same request: both sides would then be that constant, and the
        // comparison would still pass. What separates the two is that the
        // result is DERIVED FROM THE RECORDS, so exactly one field of exactly
        // one borrowed record is mutated here and both results must move
        // together, to the refusal production itself produces for that record.
        // `check_evaluation_shape` admits exactly `Executed` and returns
        // `EvidenceNotExecuted` for every other status, so the mutated group is
        // refused before any later join is reached and a wrapper that returned
        // a fixed admitted handoff could not produce this value.
        group.evidence.execution = ImprovementEvidenceExecution::NotExecuted;
        let mutated_direct = pipeline_result(&group);
        let mutated_routed = route_result(&group);
        let not_executed = PipelineError::EvidenceNotExecuted {
            status: ImprovementEvidenceExecution::NotExecuted.label(),
        };
        assert_eq!(mutated_direct, Err(not_executed.clone()));
        assert_eq!(mutated_routed, Err(not_executed));
    }

    #[test]
    fn the_mixed_a_proposal_b_admission_group_refuses_identically_on_both_paths() {
        let group_a = joined_group("a");
        let group_b = joined_group("b");

        // Group B is individually joined and admitting on its own, so the
        // refusal below is not one malformed record meeting another.
        match pipeline_result(&group_b) {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => {
                assert_eq!(handoff.candidate_id, group_b.candidate.candidate_id);
                assert_eq!(handoff.campaign_id, group_b.proposal.campaign_id);
                assert_eq!(handoff.experiment_scope_ref, "admitted-scope-2702-b");
                assert_eq!(handoff.rollback_owner_id, ROLLBACK_OWNER);
                // This arm reads an ADMITTED handoff, so it is bound by the same
                // rule the module doc states for every admitted handoff: the
                // advisory record is not an execution permit. The daemon wrapper
                // never turns it into one, and the card requires this assertion
                // on every admitted handoff, not only the joined-group one.
                assert!(
                    !handoff.execution_authorized,
                    "the group B admitted handoff must not authorize execution"
                );
            }
            other => panic!("group B must admit on its own, got {other:?}"),
        }

        let mut mixed = mixed_groups(&group_a, &group_b);
        let routed = route_result(&mixed);
        let direct = pipeline_result(&mixed);
        assert_eq!(routed, direct);
        let expected = PipelineError::UnboundRelation {
            relation: "proposal-candidate: candidate-identity-mismatch",
        };
        assert_eq!(direct, Err(expected.clone()));
        assert_eq!(routed, Err(expected));
        match routed {
            Err(PipelineError::UnboundRelation { relation }) => {
                assert_eq!(relation, "proposal-candidate: candidate-identity-mismatch");
            }
            other => panic!("the mixed pair must be an unbound relation, got {other:?}"),
        }

        // The refusal equivalence is proved the same way the admitted
        // equivalence is: one field of one borrowed record is re-bound so the
        // FIRST relation the proposal/candidate join compares now agrees, and
        // the NEXT relation it compares is the one that refuses. Both paths must
        // follow the records to that different relation, which neither could
        // have produced from the mixed pair as it stood above.
        mixed.candidate.candidate_id = group_a.candidate.candidate_id.clone();
        let repaired_direct = pipeline_result(&mixed);
        let repaired_routed = route_result(&mixed);
        let next_relation = PipelineError::UnboundRelation {
            relation: "proposal-candidate: campaign-identity-mismatch",
        };
        assert_eq!(repaired_direct, Err(next_relation.clone()));
        assert_eq!(repaired_routed, Err(next_relation));
    }

    #[test]
    fn the_admitted_handoff_is_not_an_execution_permit_on_either_path() {
        let group = joined_group("a");
        let routed_handoff = match route_result(&group) {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => handoff,
            other => panic!("the routed disposition must be a canary handoff, got {other:?}"),
        };
        let direct_handoff = match pipeline_result(&group) {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => handoff,
            other => panic!("the pipeline disposition must be a canary handoff, got {other:?}"),
        };
        assert!(
            !routed_handoff.execution_authorized,
            "the routed handoff must not authorize execution"
        );
        assert!(
            !direct_handoff.execution_authorized,
            "the pipeline handoff must not authorize execution"
        );
        assert_eq!(routed_handoff.activation_owner_id, KERNEL_CANARY_OWNER);
        assert_eq!(direct_handoff.activation_owner_id, KERNEL_CANARY_OWNER);
        assert_eq!(
            routed_handoff.wire_revision,
            IMPROVEMENT_PIPELINE_WIRE_REVISION
        );
        assert_eq!(
            direct_handoff.wire_revision,
            IMPROVEMENT_PIPELINE_WIRE_REVISION
        );
    }

    /// Norm: `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md:69`.
    #[test]
    fn unknown_effect_without_receipt_denies_retry_and_retains_nothing() {
        let group = joined_group("a");
        let handoff = match route_result(&group) {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => handoff,
            other => panic!("must admit, got {other:?}"),
        };
        // The checked current record is the handoff's OWN three identity objects
        // and the exact plan this run passed, so the obligation the owner raises
        // names this attempt's proposal bytes and nothing restated beside them.
        let current = ImprovementCurrentProposal {
            candidate_id: handoff.candidate_id.clone(),
            commitment: handoff.proposal_commitment.clone(),
            discriminator: handoff.proposal_discriminator.clone(),
            material_equality: handoff.proposal_material_equality.clone(),
            experiment_plan: group.experiment.clone(),
        };
        let prior = ImprovementAdmissionDecision::RequiresReconciliation {
            reason: "unknown-execution-outcome: reconcile exact external effect before retry"
                .to_string(),
            owner_id: "external-owner-2702-a".to_string(),
        };
        let disposition = reconcile_improvement_unknown(&prior, &current, &group.rollback)
            .expect("unknown reconciles");
        assert!(matches!(
            disposition,
            ImprovementTerminalDisposition::UnknownRequiresReconciliation { .. }
        ));
        // The norm routes the delayed outcome through rollback reconciliation, so
        // with no owner-settled receipt the debt stays owed and the retry gate
        // stays closed: this is the denying direction A00.03 requires, not a
        // missing-evidence sentence that would permit another attempt.
        let state = read_improvement_effect_state(&disposition);
        assert!(
            !state.retry_permitted,
            "an unsettled external effect must deny the retry gate"
        );
        assert!(
            !state.completion_retained,
            "no owner-settled receipt may be retained for an unsettled effect"
        );
        assert!(
            state.obligation.is_some(),
            "the unresolved obligation must stay named for its owner"
        );
    }

    /// Norm: `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md:69`.
    #[test]
    fn unknown_effect_tampered_identity_refuses_reconciliation() {
        let group = joined_group("a");
        let handoff = match route_result(&group) {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => handoff,
            other => panic!("must admit, got {other:?}"),
        };
        let current = ImprovementCurrentProposal {
            candidate_id: handoff.candidate_id.clone(),
            commitment: handoff.proposal_commitment.clone(),
            discriminator: handoff.proposal_discriminator.clone(),
            material_equality: handoff.proposal_material_equality.clone(),
            experiment_plan: group.experiment.clone(),
        };
        // The retained debt re-binds itself to the exact proposal bytes it was
        // raised over, so an identity naming ANOTHER candidate is a different
        // debt: the Governor entry point is called directly here because
        // `reconcile_improvement_unknown` builds the retained identity FROM
        // `current` and could therefore never be handed a spliced one.
        let retained = ImprovementUnknownEffectIdentity {
            candidate_id: "cand-2702-tampered".to_string(),
            experiment_id: group.experiment.experiment_id.clone(),
            commitment: handoff.proposal_commitment.clone(),
            owner_id: "external-owner-2702-a".to_string(),
            forward_repair_ref: group.rollback.forward_repair_ref.clone(),
            invalidation_set: group.rollback.invalidation_set.clone(),
        };
        let result = eliot_maintenance::improvement_pipeline::reconcile_retained_unknown_effect(
            &retained, &current, None,
        );
        assert_eq!(
            result,
            Err(PipelineError::UnboundRelation {
                relation: "retained-unknown-effect: candidate-identity-mismatch"
            })
        );
    }

    /// Norm: `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md:76`.
    /// A7: the daemon consumes the handoff under the identity this build
    /// checks. The genuinely routed handoff passes; a copy drifted to a stale
    /// wire revision or a legacy algorithm refuses through the same forwarder
    /// `check_handoff_consumable` reads, with no substitute digest.
    #[test]
    fn daemon_consumer_passes_routed_handoff_while_drift_refuses() {
        let group = joined_group("a");
        let handoff = match route_result(&group) {
            Ok(ImprovementTerminalDisposition::CanaryAdmitted { handoff }) => handoff,
            other => panic!("must admit, got {other:?}"),
        };
        assert_eq!(
            check_improvement_handoff_identity(&handoff, &group.experiment),
            Ok(())
        );
        // The drift starts from the genuinely produced record and changes one
        // identity field, so the refusal below proves the consumer reads the
        // record rather than trusting it.
        let mut stale_wire = (*handoff).clone();
        stale_wire.wire_revision = IMPROVEMENT_PIPELINE_WIRE_REVISION - 1;
        assert!(matches!(
            check_improvement_handoff_identity(&stale_wire, &group.experiment),
            Err(PipelineError::UncheckedWireRevision(_))
        ));
        let mut legacy_algorithm = (*handoff).clone();
        legacy_algorithm.proposal_commitment.algorithm =
            IMPROVEMENT_LEGACY_DIGEST_ALGORITHM.to_string();
        assert!(matches!(
            check_improvement_handoff_identity(&legacy_algorithm, &group.experiment),
            Err(PipelineError::UncheckedRecordIdentity(_))
        ));
    }

    /// Norm: `I00-09:7` - the daemon wrapper returns the pipeline's own
    /// refusal dispositions, not its own restatement of them (AUD7/A1).
    #[test]
    fn routed_stale_closure_blocks_with_typed_cause_and_remedy() {
        let mut group = joined_group("stale");
        group.admission_evidence.closure_stale = true;
        match route_result(&group) {
            Ok(ImprovementTerminalDisposition::Blocked {
                cause,
                remedy,
                owner_id,
                ..
            }) => {
                assert_eq!(cause, ImprovementBlockCause::StaleClosure);
                assert_eq!(remedy, cause.remedy());
                assert_eq!(owner_id, group.policy.external_owner_id);
            }
            Ok(other) => panic!("a stale closure binding must block, got {other:?}"),
            Err(error) => panic!("a stale closure binding must block, got {error:?}"),
        }
    }

    /// Norm: `I00-09:7` - the daemon wrapper returns the pipeline's own
    /// refusal dispositions (AUD7/A2).
    #[test]
    fn routed_harm_rejects_with_typed_cause() {
        let mut group = joined_group("harm");
        group.admission_evidence.harm_observed = true;
        match route_result(&group) {
            Ok(ImprovementTerminalDisposition::Rejected {
                cause, owner_id, ..
            }) => {
                assert_eq!(cause, ImprovementRejectCause::HarmObserved);
                assert_eq!(owner_id, group.policy.external_owner_id);
            }
            Ok(other) => panic!("observed harm must reject, got {other:?}"),
            Err(error) => panic!("observed harm must reject, got {error:?}"),
        }
    }

    /// Norm: `I00-09:7` - the daemon wrapper returns the pipeline's own
    /// refusal dispositions (AUD7/A3).
    #[test]
    fn routed_pulse_regression_regress_rejects_with_typed_cause() {
        let mut group = joined_group("regression");
        group.admission_evidence.pulse = ImprovementPulseOutcome::Regression;
        match route_result(&group) {
            Ok(ImprovementTerminalDisposition::RegressionRejected {
                cause, owner_id, ..
            }) => {
                assert_eq!(cause, ImprovementRejectCause::PulseRegression);
                assert_eq!(owner_id, group.policy.external_owner_id);
            }
            Ok(other) => panic!("a pulse regression must regress-reject, got {other:?}"),
            Err(error) => panic!("a pulse regression must regress-reject, got {error:?}"),
        }
    }

    /// Norm: `I00-09:7` - the daemon wrapper returns the pipeline's own
    /// refusal dispositions (AUD7/A4/A6).
    #[test]
    fn routed_unknown_outcome_requires_reconciliation_bound_to_candidate() {
        let mut group = joined_group("unknown");
        group.admission_evidence.outcome_unknown = true;
        match route_result(&group) {
            Ok(ImprovementTerminalDisposition::UnknownRequiresReconciliation { obligation }) => {
                assert_eq!(obligation.candidate_id, group.candidate.candidate_id);
                assert_eq!(obligation.experiment_id, group.experiment.experiment_id);
            }
            Ok(other) => panic!("an unknown outcome must require reconciliation, got {other:?}"),
            Err(error) => panic!("an unknown outcome must require reconciliation, got {error:?}"),
        }
    }
}
