//! Live construction and dispatch of the Governor improvement-candidate route
//! (issue #1145, I12.24:57-96).
//!
//! `ImprovementRouteRequest` (`improvement_candidate_route.rs`) is a set of
//! BORROWED Governor-owned records, so it can only be built by a caller that
//! already holds the matching proposal, experiment plan, activation evidence,
//! rollback contract, candidate view, evidence view and admission policy. Until
//! this module existed, nothing in `eliotd` held any of them, so
//! `route_improvement_candidate` had no caller at all and the whole
//! candidate → experiment → evaluation → admission path was unreachable from the
//! daemon.
//!
//! This module is that caller. It takes the ONE observation the daemon already
//! produced this pass — the advisory improvement artifact
//! ([`ImprovementArtifact`]), the `G-19` improvement admission policy read from
//! the live maintenance owner, and the admitted Kernel fence — and assembles the
//! seven borrowed records out of their OWN fields, then hands them to
//! [`route_improvement_candidate`]. Each record is built by its own
//! `route_*` helper so that the reasoning for a field stays attached to the
//! field, and so a reader auditing one record never has to read the other six.
//!
//! # Every value is a function of what the daemon already observed
//!
//! Nothing here invents an observation. The proposal's evidence set is the
//! candidate's own canonical evidence lineage; its target is the candidate's own
//! recorded surface and delivery target; its source identity is the candidate's
//! own delivery target; its data identity is the `eliot-improvement` owner's own
//! evidence-lineage digest over that lineage; its runtime identity is the
//! candidate's own admitted validity scope (the admitted authority epoch and
//! resource generation); its operation and idempotency namespaces are the `G-19`
//! policy record's own; its risk and effect ceilings are the pipeline's own
//! admitted constants; and its rollback owner is the one the same policy record
//! names. See each field's `ASSUMPTION` note for what a value is and is not.
//!
//! # The owner routing a plan declares is not a claim that anything ran
//!
//! [`ExperimentPlan::testd_owner_id`] and [`ExperimentPlan::evaluator_id`] name
//! the Testd owner and the independent Instrument verifier family because the
//! Governor pipeline REQUIRES that routing (W5) — a plan routed to any other
//! executor or evaluator is refused as unbound. Declaring the routing is a
//! statement about who would run and who would grade the bounded experiment; it
//! is not a statement that either happened.
//!
//! The claim that something ran lives in
//! [`ActivationEvidence::execution`], and this module sets it to its honest
//! value: [`ImprovementEvidenceExecution::NotExecuted`]. This daemon starts no
//! experiment, so it holds no independent executed evaluation, and
//! `verifier_passed` is `false` for the same reason. I12.24:76 ("Replay-only
//! evidence cannot promote") and `I0.5` are honoured by that value, not worked
//! around: nothing here substitutes a self-report, a model score, or an exit zero
//! for a real run.
//!
//! # What the daemon does not hold, stated rather than filled
//!
//! Three things this path would need have no daemon-owned value, and they are
//! left empty rather than relabelled from something else:
//!
//! 1. **The learning-closure binding.** [`ImprovementProposal::closure_id`] /
//!    [`ImprovementProposal::closure_digest`] bind the `meta.learning.closure`
//!    cell (`#819`). This daemon's maintenance intake produces an
//!    `ImprovementCandidate`, a brief and an owner decision; it does not
//!    assemble a `CampaignLearningClosure`, and nothing on the maintenance path
//!    publishes one. Binding the improvement candidate's own identity to a field
//!    that means a different proved cell would be exactly the misattribution
//!    `improvement_intake_dispatch::maintenance_evidence_source` was written to
//!    remove, so the binding stays absent and the pipeline refuses it.
//! 2. **The privacy class.** No owner vocabulary for classifying the privacy
//!    class of a maintenance improvement proposal is reachable from this daemon,
//!    so [`ImprovementProposal::privacy_class`] is empty rather than guessed.
//! 3. **The executed-evaluation and repair-path references.**
//!    [`ActivationEvidence::run_ref`] and
//!    [`ActivationEvidence::raw_evidence_ref`], plus the reopen, expiry and
//!    forward-repair references of [`RollbackContract`], name a run that did not
//!    happen and repair paths this daemon holds no record of. The candidate's own
//!    recorded rollback and stop-condition references ARE real and are bound; the
//!    rest stay absent.
//!
//! # The terminal disposition this path actually produces
//!
//! A typed [`PipelineError`] from the Governor pipeline, over a real request
//! built from a real observation. The pipeline checks the proposal shape before
//! it checks the experiment evidence, so on this workspace the FIRST refusal is
//! [`PipelineError::MissingField`] naming `closure_id` (and `privacy_class`
//! behind it) — the absent learning-closure binding, not a verdict on the
//! candidate. Behind that gate sits the substantive one: even with those fields
//! bound, `check_evaluation_shape` refuses this evidence as
//! [`PipelineError::EvidenceNotExecuted`] because its execution status is
//! `NotExecuted`, which is the I12.24:76 refusal. Both are refusals. Neither is
//! a promotion: no result of this path promotes, activates, installs, completes
//! or issues authority, and the advisory application-class ceiling (I12.24:81)
//! is enforced upstream by
//! `improvement_intake_dispatch::enforce_advisory_class_gate` on the artifact
//! this function is given, so it is not duplicated here.
//!
//! # The daemon CONSUMES the handoff, so the daemon checks its revision
//!
//! The Governor crate checks the handoff's recorded wire revision where it
//! builds the record. That is the producer checking its own stamp. This daemon
//! is the other side of the boundary: it is the first holder of
//! `ImprovementCanaryHandoff` as a value it did not assemble field by field,
//! and the last one before the record is presented to the Kernel `#11` owner as
//! an inspectable, non-authorizing handoff.
//! [`check_handoff_consumable`] therefore compares the handoff's ORIGINAL
//! recorded `wire_revision` against this build's
//! `IMPROVEMENT_PIPELINE_WIRE_REVISION`, through the crate's existing
//! [`check_handoff_wire_revision`], and a mismatch becomes
//! [`PipelineError::UncheckedWireRevision`] with no disposition returned. See
//! that function for why the original value is the one compared, and why a
//! refusal is propagated rather than resolved into a substitute.
//!
//! # No second owner, store, digest or write path
//!
//! This module computes no proposal digest: the Governor pipeline computes
//! exactly one commitment and carries it into its own result, so a digest
//! computed here could only disagree with the committed one. It opens no store,
//! reads no record, starts no flight, and writes nothing. It adds no scheduler,
//! no maintenance owner and no dependency, and it has no blocking `attach_*`
//! call. Durability of the artifact it reads stays with the existing
//! [`crate::DaemonComposition::commit_learning_record`] seam in
//! `daemon_runtime::run_improvement_intake`.
//!
//! # What is still not wired
//!
//! [`crate::improvement_candidate_route::assess_improvement_repeat`] has no
//! caller and this change does not give it one. It needs a
//! `RetainedImprovementProposal` and an `ImprovementCurrentProposal`, and the
//! only producer of the latter is the pipeline's private
//! `current_proposal_of`; no retained proposal record has a durable owner in
//! this daemon either. Supplying either would mean inventing a record or adding
//! a store, so the forwarder stays honestly unreachable and is named here rather
//! than faked.
//!
//! The revision check added here also stops at this boundary. The Kernel `#11`
//! owner that independently authorizes and EXECUTES canary activation is a
//! different subsystem, outside `eliotd`; it is where a handoff is finally
//! decoded from bytes rather than handed over in process, and it needs the same
//! [`eliot_maintenance::check_handoff_wire_revision`] against the same
//! constant. That call site is the Kernel owner's to write, and is named here
//! rather than faked with a consumer in this crate.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_improvement::ImprovementCandidate;
use eliot_improvement::candidate_bounds::{canonical_evidence_lineage, evidence_lineage_digest};
use eliot_maintenance::{
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    IMPROVEMENT_EFFECT_CEILING, IMPROVEMENT_PROOF_CEILING, IMPROVEMENT_REQUESTED_EFFECT,
    IMPROVEMENT_RISK_CEILING_BOUNDED, ImprovementAdmissionPolicy, ImprovementCandidateView,
    ImprovementEvidenceExecution, ImprovementEvidenceView, ImprovementProposal,
    ImprovementPulseOutcome, ImprovementTerminalDisposition, MechanismDeclaration, PipelineError,
    RollbackContract, TESTD_OWNER, VERIFIER_OWNER_FAMILY, check_handoff_wire_revision,
};

use super::improvement_candidate_route::{ImprovementRouteRequest, route_improvement_candidate};
use super::improvement_intake_dispatch::ImprovementArtifact;

/// Builds the Governor improvement-candidate request from one real maintenance
/// observation and runs the production route over it.
///
/// `artifact` is the advisory candidate/brief/owner-decision artifact this
/// daemon assembled and durably committed for the current maintenance
/// observation, `policy` is the `G-19` improvement admission policy read from
/// the live maintenance owner for that same observation, and `state_fence` is
/// the Kernel fence the observation was admitted under. All three are real
/// daemon-held values; the seven records this assembles are functions of their
/// own fields, as the module documentation states field by field.
///
/// Returns the pipeline's own advisory-only terminal disposition, or the typed
/// [`PipelineError`] the pipeline refused with. It never promotes, activates,
/// installs, completes, or issues authority, and it performs no durability of
/// its own: the caller commits through the existing
/// [`crate::DaemonComposition::commit_learning_record`] seam.
pub fn dispatch_improvement_candidate_route(
    artifact: &ImprovementArtifact,
    policy: &ImprovementAdmissionPolicy,
    state_fence: &StateFence,
) -> Result<ImprovementTerminalDisposition, PipelineError> {
    let candidate = &artifact.candidate;
    let disposition = route_improvement_candidate(ImprovementRouteRequest {
        proposal: &route_proposal(candidate, policy, state_fence),
        experiment: &route_experiment(candidate, policy),
        evidence: &route_activation_evidence(candidate),
        rollback: &route_rollback_contract(candidate, policy),
        candidate: &route_candidate_view(candidate, policy),
        admission_evidence: &route_admission_evidence(candidate, policy),
        policy,
    })?;
    check_handoff_consumable(&disposition)?;
    Ok(disposition)
}

/// Consumes the `CanaryAdmitted` handoff under the wire revision THIS build
/// checks, and refuses a record written under any other one.
///
/// # The consuming side, not the producing side
///
/// The Governor crate checks the handoff's recorded wire revision inside
/// `build_canary_handoff`, immediately before the record leaves the producer.
/// That check proves the producer's own stamp agrees with the producer's own
/// constant. It does not make the CONSUMER safe, and this is the consumer: the
/// daemon is the first process that holds
/// [`eliot_maintenance::ImprovementCanaryHandoff`] as a value it did not
/// assemble field by field, and the last one before the record is presented to
/// the Kernel `#11` owner as an inspectable, non-authorizing handoff. Reading
/// the record's content while declining to read its shape is how a handoff
/// stamped under a foreign revision gets presented as a current one, so the
/// shape is checked here against the same
/// [`eliot_maintenance::IMPROVEMENT_PIPELINE_WIRE_REVISION`] constant, through
/// the crate's existing [`check_handoff_wire_revision`].
///
/// # The ORIGINAL recorded value is what is compared
///
/// Nothing is recomputed, defaulted, rounded, or padded, and no second encoder,
/// hasher, or identity type is introduced. The comparison reads
/// [`eliot_maintenance::ImprovementCanaryHandoff::wire_revision`] exactly as
/// the producer recorded it: a handoff carrying revision `7` is refused as
/// revision `7`, is not padded up to this build's `8`, and is not read as
/// though the current shape had produced it. The refusal crosses into the
/// daemon as the typed [`eliot_maintenance::PipelineError::UncheckedWireRevision`]
/// it wraps, carrying both revisions, so no caller can repair the record by
/// guessing.
///
/// # No substitute on failure
///
/// A refusal is propagated, never resolved. There is no fallback digest, no
/// empty string, no default revision, no legacy value, and no recomputed hash
/// standing in for a record this build cannot read. The disposition is NOT
/// returned in a weakened form: a foreign-revision handoff produces the typed
/// error and no disposition at all, so the caller never sees a handoff it might
/// present as current.
///
/// The same holds for a HASHING failure. The commitment this daemon receives is
/// the one the pipeline computed; the `?` on `route_improvement_candidate`
/// carries the pipeline's own [`PipelineError::CommitmentFailed`] — and with it
/// the canonical serializer's own `detail` text — across this boundary as
/// itself. Nothing here catches it, matches on its reason text, or substitutes
/// a digest for the commitment that could not be produced, so a serialization
/// refusal reaches `run_improvement_intake` still naming what the serializer
/// said rather than a placeholder.
///
/// # The honest limit of this check
///
/// On the live path today the Governor crate that produced the handoff is the
/// same build that stamps the constant, so this comparison can only pass. What
/// it establishes is that the CONSUMPTION is refused rather than trusted, and
/// it is the check that holds when the record reaches the daemon as decoded
/// bytes rather than as a same-process value: the record is
/// `Serialize`/`Deserialize` with `deny_unknown_fields` and is declared the
/// wire shape the Kernel owner will later read, so the daemon reading a
/// `CanaryAdmitted` disposition must not assume the producer's stamp describes
/// a shape this build understands. The Kernel `#11` owner that independently
/// authorizes activation is a different subsystem's boundary and is not
/// reachable from this crate; the symbol it needs is the same
/// [`check_handoff_wire_revision`].
///
/// Every other disposition variant carries no handoff and is passed through
/// exactly as the pipeline produced it.
fn check_handoff_consumable(
    disposition: &ImprovementTerminalDisposition,
) -> Result<(), PipelineError> {
    if let ImprovementTerminalDisposition::CanaryAdmitted { handoff } = disposition {
        check_handoff_wire_revision(handoff)?;
    }
    Ok(())
}

/// The Governor-side proposal this daemon raises over one real observation.
fn route_proposal(
    candidate: &ImprovementCandidate,
    policy: &ImprovementAdmissionPolicy,
    state_fence: &StateFence,
) -> ImprovementProposal {
    let candidate_id = candidate.candidate_id.as_str();
    // The admitted boundary of this observation. It is the candidate's OWN
    // recorded validity scope, which `assemble_improvement_artifact` set to the
    // daemon's admitted fence (authority epoch lineage + sequence, and resource
    // generation), so the experiment scope and the invalidation target are both
    // the boundary the observation was actually evaluated under.
    //
    // `ASSUMPTION:` this is the owner-proved admitted scope for the candidate.
    // The daemon proves no `WorkScope` for a maintenance observation, but it
    // does hold the admitted Kernel fence, and that fence is the only scope
    // under which the candidate is valid. The pipeline treats an ABSENT binding
    // as a typed block and never defaults one; an absent scope would leave
    // `experiment.scope_ref` with no honest value either, so both read the one
    // real boundary rather than one inventing a scope and the other lacking it.
    let admitted_scope = candidate.validity_scope.clone();
    let counter_metrics = candidate.replay_plan.counter_metric_names.join(",");
    let generation = state_fence.resource_generation.value();
    let surface = candidate.target_surface.closed_name();
    let project_id = candidate.project_id.as_str();
    ImprovementProposal {
        // `ASSUMPTION:` the proposal identity is derived from the candidate
        // identity. A proposal identity is deliberately NOT the candidate
        // identity, and this daemon proposes exactly one proposal per candidate,
        // so the candidate identity names it without a second counter.
        proposal_id: format!("maintenance-improvement-proposal:{candidate_id}"),
        candidate_id: candidate.candidate_id.clone(),
        // `ASSUMPTION:` the daemon runs exactly one improvement campaign — its
        // own maintenance cadence — so the campaign is the candidate's own
        // recorded project identity (this daemon's service scope) bound to that
        // purpose. The candidate carries the project identity the intake gave it,
        // so the campaign is a function of the artifact rather than a literal.
        campaign_id: format!("{project_id}-maintenance-improvement"),
        // No `meta.learning.closure` record is held for a maintenance
        // observation; see the module documentation. Absent, never relabelled.
        closure_id: String::new(),
        closure_digest: String::new(),
        // The candidate's own canonical evidence lineage, verbatim. Declared set:
        // the intake assembled it through `canonical_evidence_lineage`, so it is
        // already duplicate-free and deterministic.
        evidence_refs: candidate.evidence_refs.clone(),
        // The capability the bounded experiment would target: the candidate's
        // OWN recorded surface, spelled through the owner's closed surface name
        // so a surface rename cannot desynchronize it from the wire spelling.
        target_capability: format!("maintenance-surface:{surface}"),
        // The generation the experiment observes and never activates: the
        // admitted resource generation this daemon holds in its own fence.
        target_generation: format!("resource-generation:{generation}"),
        mechanism: route_mechanism(candidate),
        // The advisory delta the bounded experiment would look for: the
        // candidate's OWN counter-metric names, which are what must not
        // regress, against the admitted boundary. It is an expectation, never a
        // measurement — this daemon measures nothing here.
        expected_delta: format!(
            "advisory-only: {counter_metrics} does not increase within {admitted_scope}"
        ),
        // The ceilings the pipeline admits, read from its own constants rather
        // than spelled: risk is bounded and the effect stays advisory-only.
        risk_ceiling: IMPROVEMENT_RISK_CEILING_BOUNDED.to_owned(),
        effect_ceiling: IMPROVEMENT_EFFECT_CEILING.to_owned(),
        // The G-19 owner's decided candidate-bound revision; see
        // `route_budget_ref`.
        budget_ref: route_budget_ref(),
        // The candidate's OWN recorded stop condition; see the field note in
        // `route_deadline_ref`.
        deadline_ref: route_deadline_ref(candidate),
        // No owner privacy-class vocabulary is reachable here; see the module
        // documentation. Absent, never guessed.
        privacy_class: String::new(),
        // The exact set the rollback contract must cover: the admitted boundary
        // this candidate is valid only within.
        invalidation_set: vec![admitted_scope],
        // The `G-19` policy record's own operation and idempotency namespaces,
        // which `improvement_bound_operation` / `improvement_bound_idempotency_key`
        // derived from this very observation.
        operation_ref: policy.operation_ref.clone(),
        idempotency_key: policy.idempotency_key.clone(),
        // The source the change applies to: the candidate's own recorded
        // delivery target (the maintenance family it was raised against).
        source_identity: candidate.delivery_target.clone(),
        // The runtime this candidate is bound to: its own admitted validity
        // scope, i.e. the admitted authority epoch and resource generation.
        runtime_identity: candidate.validity_scope.clone(),
        // The owner crate's own digest over the candidate's evidence lineage;
        // see `route_data_identity`.
        data_identity: route_data_identity(candidate),
    }
}

/// The causal mechanism this daemon declares BEFORE any result exists.
fn route_mechanism(candidate: &ImprovementCandidate) -> MechanismDeclaration {
    let candidate_id = candidate.candidate_id.as_str();
    // It is declared from the observation and before any result exists — this
    // daemon runs no experiment, so there is no result to be post-hoc about —
    // which is exactly what `declared_before_results` asserts. The hypothesis is
    // the candidate's own recorded root-cause hypothesis, still marked unproven
    // by the intake that assembled it; the causal link is the candidate's own
    // recorded proposed change, which is the intervention the claim is about; and
    // `declared_ref` is the durable record key the same pass commits the
    // declaration under.
    //
    // `ASSUMPTION:` the candidate's recorded root-cause hypothesis is this
    // proposal's falsifiable hypothesis. `assemble_improvement_artifact` always
    // records at least one (`sourced_evidence` is called with the
    // `unproven-blocked-automation:<trigger_id>` hypothesis on the maintenance
    // arm, and with the conformance finding's symptom projections on the other),
    // so the field is populated on the live path rather than defaulted.
    MechanismDeclaration {
        mechanism_id: format!("maintenance-mechanism:{candidate_id}"),
        hypothesis: candidate.root_cause_hypotheses.join("; "),
        causal_link: candidate.proposed_change.clone(),
        declared_ref: format!("improvement-candidate:{candidate_id}"),
        declared_before_results: true,
    }
}

/// The owner-decided ceiling this bounded experiment must not exceed.
///
/// `ASSUMPTION:` the experiment budget is the `G-19` owner's decided candidate
/// bound revision for this surface. That bound is the only owner-decided
/// resource ceiling the daemon holds over this candidate, and
/// `admit_improvement_artifact` enforced it under that very revision in the
/// same pass, so this names a ceiling that really applied rather than an
/// invented one.
fn route_budget_ref() -> String {
    format!("maintenance-candidate-bounds:{IMPROVEMENT_CANDIDATE_BOUNDS_REVISION}")
}

/// The experiment-window bound the candidate itself declared.
///
/// `ASSUMPTION:` a stop condition is the expiry of the bounded experiment. The
/// daemon holds no separate expiry record, and this is the only experiment bound
/// the candidate records, so the two are the same value rather than one being
/// invented to fill the other's slot.
fn route_deadline_ref(candidate: &ImprovementCandidate) -> String {
    candidate.stop_condition.clone()
}

/// The data identity: the `eliot-improvement` owner's own digest over the
/// candidate's canonical evidence lineage.
///
/// Computed by the owner crate that defines it, over content the daemon already
/// holds. This is NOT the proposal commitment, which the Governor pipeline
/// computes exactly once and this module never touches.
fn route_data_identity(candidate: &ImprovementCandidate) -> String {
    evidence_lineage_digest(&canonical_evidence_lineage(&candidate.evidence_refs))
}

/// The Testd-owned bounded experiment this candidate would be released to.
fn route_experiment(
    candidate: &ImprovementCandidate,
    policy: &ImprovementAdmissionPolicy,
) -> ExperimentPlan {
    let candidate_id = candidate.candidate_id.as_str();
    // The experiment identity of this candidate. Derived from the candidate's
    // content-derived identity, so a repeat of the same evidence lineage names
    // the same bounded experiment rather than minting a new one per cadence.
    let experiment_id = format!("maintenance-improvement-experiment:{candidate_id}");
    ExperimentPlan {
        experiment_id,
        // Owner routing the pipeline requires (W5), declared and not claimed to
        // have happened; see the module documentation.
        testd_owner_id: TESTD_OWNER.to_owned(),
        evaluator_id: VERIFIER_OWNER_FAMILY.to_owned(),
        scope_ref: candidate.validity_scope.clone(),
        // Identical to the proposal's admitted budget and deadline, so no scope
        // refinement is claimed: `scope_refinement` stays absent rather than
        // asserting an owner narrowing this daemon holds no evidence for.
        budget_ref: route_budget_ref(),
        deadline_ref: route_deadline_ref(candidate),
        operation_ref: policy.operation_ref.clone(),
        idempotency_key: policy.idempotency_key.clone(),
        scope_refinement: None,
    }
}

/// The independent activation evidence bound to this candidate and experiment.
fn route_activation_evidence(candidate: &ImprovementCandidate) -> ActivationEvidence {
    let candidate_id = candidate.candidate_id.as_str();
    ActivationEvidence {
        evidence_id: format!("maintenance-activation-evidence:{candidate_id}"),
        // The verifier family the plan declared, as a routing identity. It is
        // NOT a claim that this family evaluated anything: `execution` below is
        // the machine state that says so, and the pipeline reads it first.
        verifier_id: VERIFIER_OWNER_FAMILY.to_owned(),
        // Honest: no independent evaluation of this candidate exists, and none
        // passed. Both are false because this daemon starts no experiment, not
        // because a weaker success is being downgraded.
        independent: false,
        verifier_passed: false,
        // No run happened and no raw measurement was taken, so the run and raw
        // evidence references are absent rather than named after something that
        // did not execute. See the module documentation.
        raw_evidence_ref: String::new(),
        run_ref: String::new(),
        content_revision_ref: route_content_revision_ref(candidate),
        // The I0.5 execution dimension, at its honest value. This is the field
        // that keeps replay-only evidence from promoting (I12.24:76).
        execution: ImprovementEvidenceExecution::NotExecuted,
        bound_candidate_id: candidate.candidate_id.clone(),
        bound_experiment_id: format!("maintenance-improvement-experiment:{candidate_id}"),
    }
}

/// The content revision any independent evaluation would have to observe.
///
/// `ASSUMPTION:` the candidate's revision counter is the content revision of the
/// change: it is the daemon's own monotonic revision of exactly the candidate
/// content the evidence is bound to, and no other content revision of this
/// candidate exists in this process.
fn route_content_revision_ref(candidate: &ImprovementCandidate) -> String {
    let candidate_id = candidate.candidate_id.as_str();
    let revision = candidate.revision;
    format!("{candidate_id}/r{revision}")
}

/// The repair path named before any experiment is admitted.
fn route_rollback_contract(
    candidate: &ImprovementCandidate,
    policy: &ImprovementAdmissionPolicy,
) -> RollbackContract {
    RollbackContract {
        // The candidate's OWN recorded repair references, bound verbatim.
        rollback_ref: candidate.rollback.clone(),
        // The stop condition is the change's disable path, and the candidate
        // records it as such.
        disable_ref: route_deadline_ref(candidate),
        // Reopen, expiry and forward repair name contracts with the external
        // rollback owner that this daemon holds no record of; they stay absent,
        // which the pipeline disposes as a named prerequisite gap rather than a
        // default.
        reopen_ref: String::new(),
        expiry_ref: String::new(),
        // The rollback owner is the one the same `G-19` policy record declares.
        rollback_owner_id: policy.rollback_owner_id.clone(),
        forward_repair_ref: String::new(),
        invalidation_set: vec![candidate.validity_scope.clone()],
    }
}

/// The Governor-side candidate view, over the cells the owner admits for.
fn route_candidate_view(
    candidate: &ImprovementCandidate,
    policy: &ImprovementAdmissionPolicy,
) -> ImprovementCandidateView {
    let project_id = candidate.project_id.as_str();
    ImprovementCandidateView {
        candidate_id: candidate.candidate_id.clone(),
        campaign_id: format!("{project_id}-maintenance-improvement"),
        closure_id: String::new(),
        closure_digest: String::new(),
        // The improvement package prepares no promotion input on this path, and
        // the owner does not re-read one, so neither is asserted.
        promotion_input_id: None,
        promotion_digest: None,
        admitted_scope_ref: Some(candidate.validity_scope.clone()),
        // Fixed in code from the owner's own admitted values, never read from a
        // declaration: the candidate cannot widen its own proof ceiling, effect
        // class or promotion state, and this daemon holds no permit or receipt
        // to present.
        proof_ceiling: IMPROVEMENT_PROOF_CEILING.to_owned(),
        requested_effect: IMPROVEMENT_REQUESTED_EFFECT.to_owned(),
        direct_promotion: false,
        active_permit: None,
        promotion_receipt: None,
        operation_ref: policy.operation_ref.clone(),
        idempotency_key: policy.idempotency_key.clone(),
    }
}

/// The admission-review evidence the Governor owner would read.
fn route_admission_evidence(
    candidate: &ImprovementCandidate,
    policy: &ImprovementAdmissionPolicy,
) -> ImprovementEvidenceView {
    let candidate_id = candidate.candidate_id.as_str();
    ImprovementEvidenceView {
        // The admission-review evaluator identity the plan declared. No
        // admission review ran; the `independent` / `verifier_passed` pair below
        // is what says so.
        verifier_id: VERIFIER_OWNER_FAMILY.to_owned(),
        bound_candidate_id: candidate.candidate_id.clone(),
        bound_experiment_id: format!("maintenance-improvement-experiment:{candidate_id}"),
        content_revision_ref: route_content_revision_ref(candidate),
        run_ref: String::new(),
        independent: false,
        verifier_passed: false,
        // No product pulse was observed for this candidate, and a package-green
        // result is never one.
        pulse: ImprovementPulseOutcome::Missing,
        pulse_ref: None,
        // Nothing ran, so nothing was harmed and nothing's outcome is unknown:
        // the run did not happen, which is a KNOWN state rather than an
        // unresolved one.
        harm_observed: false,
        outcome_unknown: false,
        // The closure binding this daemon holds is ABSENT (see the module
        // documentation), so it is not established as valid. Reporting it as
        // valid would claim a proved cell this path never observed.
        closure_valid: false,
        closure_stale: false,
        // The repair references the candidate really records, carried alongside
        // the contract so the two agree by content.
        rollback_ref: Some(candidate.rollback.clone()),
        disable_ref: Some(route_deadline_ref(candidate)),
        reopen_ref: None,
        rollback_owner_id: policy.rollback_owner_id.clone(),
        expiry_ref: None,
        // This daemon retains no prior proposal record, so no retained record is
        // presented. Absence establishes nothing: the Governor gate derives its
        // own no-progress outcome from the absent record rather than reading
        // novelty into it.
        retained_prior_proposal: None,
    }
}
