//! Live construction and dispatch of the Governor improvement-candidate route
//! (issue #1145, I12.24:57-96).
//!
//! `ImprovementRouteRequest` (`improvement_candidate_route.rs`) is a set of
//! BORROWED Governor-owned records, so it can only be built by a caller that
//! already holds the matching proposal, experiment plan, activation evidence,
//! rollback contract, candidate view, evidence view and admission policy. Until
//! this module existed, nothing in `eliotd` held any of them, so neither
//! `route_improvement_candidate` nor `assess_improvement_repeat` had a caller at
//! all and the whole candidate → experiment → evaluation → admission → repeat
//! path was unreachable from the daemon.
//!
//! This module is that caller. It takes the ONE observation the daemon already
//! produced this pass — the advisory improvement artifact
//! ([`ImprovementArtifact`]), the `G-19` improvement admission policy read from
//! the live maintenance owner, and the admitted Kernel fence — and assembles the
//! seven borrowed records out of their OWN fields, then hands them to
//! [`route_improvement_candidate`] and, on the admitted branch, to
//! [`assess_improvement_repeat`]. Each record is built by its own `route_*`
//! helper so that the reasoning for a field stays attached to the field, and so
//! a reader auditing one record never has to read the other six.
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
//! names, read back out of the operation owner map's `Rollback` row rather than
//! re-spelled. See each field's `ASSUMPTION` note for what a value is and is not.
//!
//! # One map, one read: the daemon names owners it does not own
//!
//! This daemon raises exactly one proposal and drives the pipeline, so it never
//! executes, measures, evaluates, admits, activates, promotes or rolls back
//! anything itself. It nevertheless has to STATE who owns each of those, in the
//! four records that name an owner: the `ExperimentPlan`'s executor and
//! evaluator, the `ActivationEvidence` and `ImprovementEvidenceView` verifiers,
//! and the `RollbackContract` and `ImprovementEvidenceView` rollback owners. All
//! six fields are read from [`improvement_operation_owners`] — the production
//! projection of [`eliot_maintenance::ImprovementOperation::owner`] — at the one
//! point in [`dispatch_improvement_candidate_route`] where this daemon decides
//! what it is routing. That is what makes the map load-bearing rather than
//! decorative: `check_experiment_owner_routing`, `check_evaluator_independence`
//! and `check_rollback_join` in the Governor crate all re-derive the same
//! question from these fields, so a map entry that diverged from the pipeline's
//! expectation becomes a typed [`PipelineError::UnboundRelation`] on the live
//! route instead of a routing nobody notices.
//!
//! The map's single input is the rollback owner, and it is the same `G-19`
//! admission policy record's own
//! [`eliot_maintenance::ImprovementAdmissionPolicy::rollback_owner_id`] the
//! request already carries — read on the live path from
//! `DaemonComposition::maintenance_improvement_admission_policy`, which hands the
//! `G-19` owner this daemon's own service identity rather than a caller's
//! string. No literal is introduced at this seam, and an operation the map does
//! not resolve is refused rather than defaulted.
//!
//! # The owner routing a plan declares is not a claim that anything ran
//!
//! [`ExperimentPlan::testd_owner_id`] and [`ExperimentPlan::evaluator_id`] are
//! read from the one operation owner map
//! ([`improvement_operation_owners`]) at the start of
//! [`dispatch_improvement_candidate_route`], so the executor and the evaluator
//! are two rows of the same `ImprovementOperation::owner` projection rather than
//! two constants this module spells beside each other. The Governor pipeline
//! REQUIRES that routing (W5) — a plan routed to any other executor or evaluator
//! is refused as unbound — so if the map ever resolved elsewhere the route
//! REFUSES rather than recording a routing nothing checks. Declaring the routing
//! is a statement about who would run and who would grade the bounded experiment;
//! it is not a statement that either happened.
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
//! # The missing producer, named so the next owner does not re-derive it
//!
//! The refusals below are only meaningful if what would clear them is absent
//! for a reason, and not merely unwritten. The absence is measured on this
//! tree, and each count below is what the stated search returns — not an
//! estimate and not a recollection.
//!
//! ## `ImprovementEvidenceExecution::Executed` is constructed nowhere
//!
//! This is the load-bearing count, and it is stronger than "not in
//! production". A workspace-wide search for the variant returns exactly two
//! occurrences, and NEITHER constructs it: the doc comment on
//! [`ImprovementEvidenceExecution::Executed`] itself, and the comparison inside
//! `check_evaluation_shape` that REFUSES every status but this one. There is no
//! construction site in `eliotd`, in `eliot-maintenance`, in `eliot-testd-core`,
//! in `eliot-verifier`, in `eliot-product-evaluation`, or in any test.
//!
//! So the one status that could ever support activation under "only independent
//! executed evidence may support activation" is not merely unexercised on the
//! live path — it is unreachable by any value this workspace can currently
//! build, and the positive half of that guarantee has no producer to draw on.
//! That is the correct state for a boundary nobody has crossed, and it is why
//! this module sets `NotExecuted` rather than reaching for the nearest thing it
//! does hold.
//!
//! ## The pipeline's `ActivationEvidence` is built in exactly one place, and
//! it is this file
//!
//! A workspace search for `ActivationEvidence {` returns four CONSTRUCTION
//! sites. Three of them build an UNRELATED same-named type —
//! `bins/eliotd/src/agent_fabric.rs` declares `ActivationEvidence` for a Kernel
//! ATTEMPT (`admission_id`, `attempt_id`, `activation_digest`, `fence`), and
//! `bins/eliotd/src/solo_agent_driver.rs` plus two `bins/eliotd/tests` fixtures
//! construct it. That is a different record with a different owner and no
//! relation to improvement admission, so none of the three is a producer for the
//! Governor type. The fourth is this file's `route_activation_evidence`, and it
//! is the ONLY one. The Governor `ActivationEvidence` is therefore never built
//! by a test either: the maintenance crate's own fixtures exercise
//! [`eliot_maintenance::ImprovementEvidenceView`], a different record.
//!
//! ## The product pulse has no production producer
//!
//! `ImprovementPulseOutcome` appears in this file once, as the refusal value
//! [`ImprovementPulseOutcome::Missing`] with `pulse_ref: None`. Every
//! non-refusal value — `Pass`, `Regression` — is constructed inside the
//! `#[cfg(test)] mod tests` of `improvement_admission.rs`. A workspace search
//! for `pulse_ref` additionally finds `ProductPulseEvidence` in
//! `eliot-improvement`'s own promotion gate and two fixtures for it; that is a
//! THIRD type with its own `pulse_ref`, not this one, so it does not count.
//! The honest total is: one production construction, and it is the refusal.
//!
//! `eliotd` does depend on `eliot-product-evaluation`, but only through
//! `campaign_evaluation_owner`, which serializes campaign-source publications
//! for the campaign cell. That crate names no `ImprovementPulseOutcome` and is
//! not on this path, so its presence is not a producer.
//!
//! ## No reachable independent evaluation, and why, in three parts
//!
//! 1. **The executor is not reachable from this daemon.** `eliotd` holds four
//!    authenticated Testd operations — `pending-dispatches`, `bind-dispatch`,
//!    `pending-terminals`, `ack-terminal` — and a workspace search finds ZERO
//!    references to [`eliot_testd_core::TESTD_OWNER_SUBMIT_OPERATION`] in
//!    `bins/eliotd`. The submit operation is defined in `eliot-testd-core` and
//!    handled in `bins/eliot-kernel`. So the `ExperimentPlan` this module
//!    builds has no client that could release it: the experiment cannot be
//!    started from here even if a submission were written, which it cannot be —
//!    the submit request additionally requires a `TaskContract` `WorkScope`
//!    result as `source_root` and an owner-observed `TestdProcessToolIntent`,
//!    neither of which a maintenance observation produces.
//! 2. **The evaluator has no executor even in principle.** `eliot-verifier`'s
//!    `execute` is driven by a `&dyn VerifierExecutionPort`, and a workspace
//!    search for `impl VerifierExecutionPort` returns ZERO. `eliotd` does not
//!    depend on `eliot-verifier` at all, so the axis is unreachable from this
//!    crate in two independent ways.
//! 3. **This daemon runs no experiment to evaluate.** The call in
//!    `daemon_runtime::run_improvement_intake` is documented there as pure
//!    with respect to the Kernel — no exchange, no write — over the artifact,
//!    the `G-19` policy and the fence the pass already holds. There is no
//!    experiment on this path to produce an outcome for.
//!
//! A14.6 is the reason these three are the same finding rather than three: it
//! distinguishes the "Production path - what created decisions, actions, and
//! outcome" from the "Measurement path - how outcome became a score or
//! quality claim". This daemon is the production path, and by construction it
//! does not become the measurement path for its own candidate. A14.6 also says
//! "A same-family model judge is not automatically independent", and A5.5 that
//! "A model evaluator is admissible for a subjective property, but its model
//! name does not make it independent" — so the `Evaluate` row read from the
//! operation map cannot stand in for a run either. Naming the evaluator does
//! not perform the evaluation.
//!
//! # What would have to be true for the activation legs to have evidence
//!
//! Stated so the next owner does not have to reconstruct it, and stated as
//! preconditions rather than as an assignment — none of them is this daemon's
//! to satisfy, and satisfying one here would be the self-verification A0.3
//! names as hidden control capture:
//!
//! - Owner `#20`/`#1111` supplies a real `VerifierExecutionPort`
//!   implementation and an independent run over this exact candidate and target,
//!   whose outcome this daemon can read as
//!   [`ImprovementEvidenceExecution::Executed`] with a `run_ref` and a
//!   `raw_evidence_ref` that resolve. A5.5 requires that the Governor bind
//!   such a verifier "to an acceptance item and checks scope and freshness", so
//!   the run must carry the acceptance item, not just a passing verdict.
//! - `eliotd` gains a submit client for
//!   [`eliot_testd_core::TESTD_OWNER_SUBMIT_OPERATION`], and the maintenance
//!   observation can supply the `source_root` and owner-observed tool intent
//!   that request requires, so `ExperimentPlan::testd_owner_id` names an
//!   executor that can actually be reached.
//! - Owner `#11` supplies a product pulse, so
//!   [`ImprovementPulseOutcome`] carries a value other than
//!   [`ImprovementPulseOutcome::Missing`] with a resolving `pulse_ref`.
//!   `eliot-improvement`'s own `ProductPulseEvidence` carries `package_green`
//!   alongside the result, and its own comment is that "package-green never
//!   substitutes"; a green package is therefore not this pulse, and
//!   `ImprovementEvidenceView::pulse` stays `Missing` without `#11`.
//! - The `ImprovementCandidateView` supplies the `meta.learning.closure`
//!   binding, and an owner privacy-class vocabulary is reachable, so
//!   `ImprovementProposal::validate` stops refusing the absent `closure_id` and
//!   `privacy_class`. Those are the FIRST refusals the pipeline reaches on this
//!   path, ahead of every evidence check, so this precondition gates the
//!   evaluation ones rather than being independent of them; it is stated at
//!   "What the daemon does not hold" below.
//!
//! Until then the disposition this path produces is a typed refusal, and the
//! correct outcome of this issue's activation half is that the refusal IS the
//! guarantee: no self-report, no model score, no exit zero, and no absent
//! producer is substituted for the run that never happened.
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
//! # The daemon CONSUMES the handoff, so the daemon checks it
//!
//! The Governor crate checks the handoff's recorded wire revision where it
//! builds the record. That is the producer checking its own stamp. This daemon
//! is the other side of the boundary: it is the first holder of
//! `ImprovementCanaryHandoff` as a value it did not assemble field by field,
//! and the last one before the record is presented to the Kernel `#11` owner as
//! an inspectable, non-authorizing handoff.
//!
//! [`check_handoff_consumable`] therefore runs BOTH Governor-owned checks this
//! build performs on any committed record — the recorded wire revision, then
//! the recorded CONTENT identity of the handoff's own commitment, discriminator
//! projection and material-equality key — through the crate's existing
//! [`check_improvement_handoff_identity`], and a refusal becomes the typed
//! [`PipelineError`] those checks produce with no disposition returned at all,
//! so a caller never sees a handoff it might present as current. See that
//! function for why the original values are the ones compared and why a refusal
//! is propagated rather than resolved into a substitute.
//!
//! # An unresolved external effect is made durable, and how
//!
//! `UnknownRequiresReconciliation { obligation }` names a real external debt:
//! the exact candidate, experiment, commitment, owner and forward-repair /
//! invalidation bindings whose effect is unsettled. It is read and named by
//! `daemon_runtime::report_improvement_candidate_route` through the daemon's
//! existing diagnostics, and [`commit_unknown_effect_obligation`] then makes the
//! named debt durable through the same single seam the rest of the improvement
//! record family uses, so it outlives the pass that observed it. The constraints
//! that decide WHERE it lands are measured rather than assumed:
//!
//! - The closed [`eliot_store_api::LearningRecordKind`] set has no kind for an
//!   unresolved external effect. `Candidate` is the only kind that describes a
//!   record ABOUT a candidate without claiming a promotion, and this daemon
//!   already uses it that way for the candidate artifact, the lineage-merge
//!   receipt and the archive receipt. `ActivationReceipt` would assert that an
//!   activation receipt exists; nothing here activated anything, and
//!   `execution_authorized` is false in every handoff the pipeline builds.
//! - A `Candidate` row is read back EXHAUSTIVELY by
//!   `improvement_dedup_read::read_candidate_scope`, whose `classify_row`
//!   re-proves every document shape it accepts and REFUSES any other row of that
//!   kind. The obligation is therefore the FOURTH shape that reader re-proves
//!   (`classify_reconciliation_obligation`), in the same `DEDUP_SCOPE` the other
//!   three land in. Writing it as an untaught fourth shape would have traded a
//!   named debt for a pass whose deduplication read fails closed.
//! - Inventing a record kind, or opening a second read or write path for the
//!   obligation, is exactly the second owner this module does not add.
//!
//! So the durable record is the named debt plus the owner's DENYING answer: no
//! effect outcome, no receipt, no permit and no authority, because this daemon
//! holds none. The effect OWNER is still the absent half, and that — not a
//! missing call — is what keeps the debt open.
//!
//! # No second owner, store, digest or write path
//!
//! This module computes no proposal digest: the Governor pipeline computes
//! exactly one commitment and carries it into its own result, so a digest
//! computed here could only disagree with the committed one. It reads no record
//! and starts no flight. It adds no scheduler, no maintenance owner and no
//! dependency, and it has no blocking `attach_*` call.
//!
//! The ONE write it performs is [`commit_unknown_effect_obligation`], and it
//! writes through the same single Governor-owned seam every other durable
//! improvement record uses — [`crate::DaemonComposition::commit_learning_record`]
//! over the closed `RecordLearningRecord` mutation, in the same Governor scope
//! and the same closed `candidate` record kind as the candidate artifact, the
//! archive receipts and the lineage-merge receipts
//! (`improvement_intake_dispatch`). No store client is opened here and no
//! operation is invented. It exists because an unresolved external effect is
//! otherwise a debt that lives only in this pass: the record it writes is the
//! named debt's durable, reviewable form, and it carries no permit, no outcome,
//! and no authority — nothing about it promotes, activates, installs,
//! completes, or issues authority.
//!
//! Durability of the artifact the route reads stays with the existing
//! [`crate::DaemonComposition::commit_learning_record`] seam in
//! `daemon_runtime::run_improvement_intake`.
//!
//! # The repeat assessment, and what it honestly reports
//!
//! [`crate::improvement_candidate_route::assess_improvement_repeat`] is called on
//! the `CanaryAdmitted` branch only. That branch is the ONLY one that publishes
//! a checked current record: the pipeline's `ImprovementCanaryHandoff` carries
//! its own `proposal_commitment`, `proposal_discriminator` and
//! `proposal_material_equality`, so the comparison runs against the pipeline's
//! checked content rather than a digest recomputed here. `retained` is the
//! pipeline's own record from an earlier ADMITTED pass, carried by the caller in
//! the run loop's single-owner intake flight; it is `None` on the first pass and
//! after a restart.
//!
//! The current record it is compared against is read out of that handoff AFTER
//! [`check_handoff_consumable`] has refused anything this build cannot read, so
//! a record under a foreign wire revision or content identity never reaches a
//! comparison. The two `ImprovementCurrentProposal` views this module assembles —
//! the one for the identity check and the one for the comparison — are the same
//! read of the handoff's OWN recorded components: neither is derived, neither is
//! stored, and the retained side is always a record the pipeline itself committed
//! on an earlier admitted pass, never a manufactured one.
//!
//! On this workspace the branch is not taken: the execution gate refuses first
//! (see above), so `repeat` is `None` and `retained_next` is `None` on every
//! live pass today. That is the honest live report, not missing coverage. Two
//! prerequisites this daemon cannot supply are named rather than faked: the
//! INDEPENDENT EXECUTED EVALUATION only the Instrument verifier owner family
//! (`#20`/`#1111`) can produce, and a DURABLE owner for
//! `RetainedImprovementProposal` (the run-loop flight is process-local, so the
//! record does not survive a restart). Neither is stubbed here, and an absent
//! record is passed to the pipeline as no record at all, which it disposes as
//! `NoRetainedPrior` — never as novelty.
//!
//! The identity check added here also stops at this boundary. The Kernel `#11`
//! owner that independently authorizes and EXECUTES canary activation is a
//! different subsystem, outside `eliotd`; it is where a handoff is finally
//! decoded from bytes rather than handed over in process, and it needs the same
//! [`eliot_maintenance::check_handoff_wire_revision`] against the same constant.
//! That call site is the Kernel owner's to write, and is named here rather than
//! faked with a consumer in this crate.
//!
//! # The external effect is read from its owner and made durable, never settled
//!
//! Every dispatched route reads the disposition's external-effect state through
//! [`read_improvement_effect_state`], which forwards to the Governor owner's own
//! retry gate and retained-result accessors, and
//! [`commit_unknown_effect_obligation`] then makes a named unresolved
//! obligation durable so the debt outlives the pass.
//!
//! What this module deliberately does NOT do is attach an owner outcome. The
//! only writer of the Governor obligation's outcome is
//! `ImprovementUnknownEffect::with_settled_owner_outcome`, which re-checks that
//! the outcome is terminal, that a canonical receipt is present, and that both
//! the authorized effect and that receipt name the obligation's exact operation
//! id and idempotency key; its input is an `eliot_authority::EffectReceipt`,
//! and this repository has no producer of a SETTLED one —
//! `EffectAuthorizer::compile_effectful_action` is the only production
//! constructor and it itself has no caller, so it is dead along with the
//! terminal paths behind it. Calling the seam with a receipt this daemon
//! assembled would be a fabricated effect outcome, which is precisely the
//! forgery I12.24 and the audit behind AUD2/AUD3 exist to prevent. So the read
//! stays a read, and the named gap is the missing effect owner, not a missing
//! call.
//!
//! # The two halves of this issue, stated separately
//!
//! "Route experiments through Testd/Instrument and activation through Governor →
//! Kernel generation/canary paths" splits into a routing half and an execution
//! half, and only the first is deliverable here.
//!
//! - **Routing is wired and load-bearing.** The executor, the evaluator and the
//!   rollback owner are read from the single
//!   [`eliot_maintenance::ImprovementOperation::owner`] projection, and the
//!   Governor pipeline independently re-derives the same questions:
//!   `check_experiment_owner_routing` refuses any executor other than
//!   `testd-20` and any evaluator outside `instrument-verifier-20-1111`,
//!   `check_evaluator_independence` refuses an evaluator that is the executor,
//!   the admission owner or the rollback owner, and `check_rollback_join`
//!   refuses a rollback owner that disagrees with the policy or the admission
//!   evidence. A map row that diverged becomes a typed refusal on the live
//!   route, so the routing is checked rather than documented.
//! - **Execution is absent, and the absence is measured.** No experiment is
//!   run, no executed evaluation exists, and no product pulse exists. The
//!   counts and the exact missing producers are stated above. Filling them from
//!   this daemon would be self-verification, so they are stated instead.
//!
//! For the guarantee "only independent executed evidence against the exact
//! candidate/target may support activation; model/self-report/exit zero
//! cannot", the negative half holds structurally: the pipeline refuses every
//! non-`Executed` status, refuses a non-independent or non-passing verdict, and
//! refuses an evaluator that is not the declared one, and the status is machine
//! state that no self-report can supply. The positive half has no producer to
//! exercise it, which is stated rather than papered over — and the absence is
//! the safe direction, since an unproven candidate is refused rather than
//! promoted.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_improvement::ImprovementCandidate;
use eliot_improvement::candidate_bounds::{canonical_evidence_lineage, evidence_lineage_digest};
use eliot_maintenance::improvement_pipeline::{
    ImprovementCurrentProposal, RetainedImprovementProposal,
};
use eliot_maintenance::{
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    IMPROVEMENT_EFFECT_CEILING, IMPROVEMENT_PROOF_CEILING, IMPROVEMENT_REQUESTED_EFFECT,
    IMPROVEMENT_RISK_CEILING_BOUNDED, ImprovementAdmissionPolicy, ImprovementCandidateView,
    ImprovementEvidenceExecution, ImprovementEvidenceView, ImprovementOperation,
    ImprovementProposal, ImprovementPulseOutcome, ImprovementReplayAssessment,
    ImprovementTerminalDisposition, MechanismDeclaration, PipelineError, RollbackContract,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    LearningRecordKind, ScopeId, WriteReceipt, canonical_json_bytes, learning_record_commit_params,
    learning_record_mutation_request,
};

use super::DaemonComposition;
use super::improvement_candidate_route::{
    ImprovementEffectState, ImprovementRouteRequest, assess_improvement_repeat,
    check_improvement_handoff_identity, improvement_operation_owners,
    read_improvement_effect_state, route_improvement_candidate,
};
use super::improvement_intake_dispatch::{ImprovementArtifact, ImprovementDispatchError};

/// Closed store scope for the durable unresolved-effect obligation record.
///
/// The SAME Governor scope the candidate artifact, the archive receipts and the
/// lineage-merge receipts are committed under, read from the Governor owner's
/// own published constant rather than spelled here. The obligation is part of
/// the same improvement record family, so it lands where the exhaustive
/// candidate-scope read already looks for it — `improvement_dedup_read` names
/// this scope as its `DEDUP_SCOPE` — and a second scope would be a second
/// durability owner.
const RECONCILIATION_SCOPE: &str = eliot_governor::GOVERNOR_SCOPE_ID;

/// Deadline bounding one durable obligation-commit ingress, in Unix
/// milliseconds.
///
/// The same bound `improvement_intake_dispatch` uses for the candidate and
/// receipt commits it owns, so this commit is bounded identically rather than
/// inventing a second timeout for the same seam.
const RECONCILIATION_COMMIT_DEADLINE_MS: u64 = 30_000;

/// The one bounded route step this daemon performs over one real observation.
///
/// Every borrowed value is something the caller already holds from the SAME
/// maintenance pass, so the request is assembled and consumed here with no
/// exchange, lock or scheduler involved: the route is a pure function of these
/// values.
///
/// `retained` is the pipeline's own checked current record from an earlier
/// ADMITTED pass, or `None` when this process holds none (the first pass, or any
/// pass after a restart). Absence is the denying direction and is presented to
/// the pipeline as no retained record at all, which it disposes as its own
/// `NoRetainedPrior` case; it is never read as novelty.
#[derive(Clone, Copy, Debug)]
pub struct ImprovementRouteDispatch<'a> {
    /// The advisory candidate/brief/owner-decision artifact this daemon
    /// assembled and durably committed for the current maintenance observation.
    pub artifact: &'a ImprovementArtifact,
    /// The `G-19` improvement admission policy read from the live maintenance
    /// owner for that same observation.
    pub policy: &'a ImprovementAdmissionPolicy,
    /// The Kernel fence the observation was admitted under.
    pub state_fence: &'a StateFence,
    /// The pipeline's checked current record from an earlier admitted pass.
    pub retained: Option<&'a RetainedImprovementProposal>,
}

/// What one bounded route step actually produced.
///
/// The optional fields are absent for the honest reason in each case, never
/// dropped: `repeat` exists only when a checked current record was compared
/// against a retained prior record, and `retained_next` exists only when the
/// disposition carried the canary handoff that publishes that record.
/// `experiment` is the exact plan this run passed to the pipeline: the terminal
/// disposition and the repeat assessment alone would leave a consumer unable to
/// bind a returned handoff to the experiment that produced it, because the
/// handoff carries the commitment, the discriminator projection and the
/// material-equality key but not the full plan those keys were derived from.
/// Carrying the plan this same call passed to the pipeline — the identical
/// value, never a second construction — is what lets
/// [`check_improvement_handoff_identity`] reach the Governor-owned
/// content-identity check on the handoff's OWN recorded components. It is a
/// read binding, not a second commitment, a second digest, or a stored record.
/// `effect` is never absent: the Governor owner answers for every disposition,
/// and on this workspace the answer is always the denying one.
#[derive(Clone, Debug)]
pub struct ImprovementRouteOutcome {
    /// The pipeline's own advisory-only terminal disposition.
    pub disposition: ImprovementTerminalDisposition,
    /// The exact experiment plan this run passed to the pipeline, held so a
    /// returned handoff is checked against the record that produced it.
    pub experiment: ExperimentPlan,
    /// The pipeline-derived repeat assessment, when a checked current record and
    /// a retained prior record both existed.
    pub repeat: Option<ImprovementReplayAssessment>,
    /// The record the NEXT pass must retain for its own repeat assessment.
    ///
    /// The same checked record, re-projected into the retained shape. `None`
    /// whenever the pass was not admitted, so an unadmitted pass never
    /// accumulates a record to compare against.
    pub retained_next: Option<RetainedImprovementProposal>,
    /// What the disposition says about the external effect it names, read
    /// through the Governor owner's own retry gate and retained-result
    /// accessors.
    ///
    /// This is the reconciliation read the pass makes before anything is
    /// recorded or retried: nothing here attaches an owner outcome, and nothing
    /// decides a retry this daemon is not already told about.
    pub effect: ImprovementEffectState,
}

/// The three owner identities this dispatch reads out of the operation map.
///
/// Read once, before any record is built, from
/// [`improvement_operation_owners`] — the single projection of
/// [`eliot_maintenance::ImprovementOperation::owner`]. Every owner field below is
/// assigned from one of these three values, never from a constant re-spelled at
/// the field, so the routing this daemon commits and the routing the Governor
/// pipeline independently re-checks are one decision expressed once.
///
/// A14.6 separates the production path, the measurement path and the
/// optimization-feedback path; A5.5 adds that "a model evaluator is admissible
/// for a subjective property, but its model name does not make it independent".
/// That is why the executor and the evaluator are two separate reads of the map
/// rather than one identity used twice: the daemon that proposes is not the
/// owner that executes the bounded experiment, and the owner that executes it is
/// not the owner that independently evaluates the result (A0.3, "hidden control
/// capture").
struct RouteOwners {
    /// Owner of the bounded experiment's execution — `ExecuteExperiment`.
    executor: String,
    /// Owner of the independent evaluation — `Evaluate`.
    evaluator: String,
    /// Owner bound by the rollback contract — `Rollback`.
    rollback: String,
}

impl RouteOwners {
    /// Reads this dispatch's owner identities from the single operation map.
    ///
    /// `rollback_owner_id` is the map's one input and it is the SAME
    /// `G-19` admission policy record's own
    /// [`eliot_maintenance::ImprovementAdmissionPolicy::rollback_owner_id`] that
    /// the request already carries — read on the live path at
    /// `daemon_runtime::improvement_intake_artifact` from
    /// `DaemonComposition::maintenance_improvement_admission_policy`, which
    /// forwards this daemon's own service identity to the `G-19` owner rather
    /// than accepting a caller's string. It is a real owner identity, not a
    /// literal, and not a value invented at this call site: it is the very value
    /// `check_rollback_join` in the Governor crate compares the rollback
    /// contract and the admission evidence against.
    fn read(rollback_owner_id: &str) -> Result<Self, PipelineError> {
        let map = improvement_operation_owners(rollback_owner_id);
        Ok(Self {
            executor: route_operation_owner(&map, ImprovementOperation::ExecuteExperiment)?,
            evaluator: route_operation_owner(&map, ImprovementOperation::Evaluate)?,
            rollback: route_operation_owner(&map, ImprovementOperation::Rollback)?,
        })
    }
}

/// Reads one operation's owner out of the operation map.
///
/// A map that does not carry the requested operation is an unbound relation, not
/// a missing field to be filled with a default: there is no literal here to fall
/// back to, and an owner this daemon cannot resolve must not be guessed, so the
/// dispatch returns the typed [`PipelineError::UnboundRelation`] the Governor
/// pipeline uses for every other diverging owner relation and builds nothing.
fn route_operation_owner(
    map: &[(&'static str, String)],
    operation: ImprovementOperation,
) -> Result<String, PipelineError> {
    map.iter()
        .find(|(name, _)| *name == operation.as_str())
        .map(|(_, owner)| owner.clone())
        .ok_or(PipelineError::UnboundRelation {
            relation: "operation-owner-map: no-owner-for-this-operation",
        })
}

/// Routes one real maintenance observation through the Governor-owned
/// improvement pipeline.
///
/// `dispatch.artifact` is the advisory candidate/brief/owner-decision artifact
/// this daemon assembled and durably committed for the current maintenance
/// observation, `dispatch.policy` is the `G-19` improvement admission policy
/// read from the live maintenance owner for that same observation, and
/// `dispatch.state_fence` is the Kernel fence the observation was admitted
/// under. All three are real daemon-held values; the seven records this
/// assembles are functions of their own fields, as the module documentation
/// states field by field.
///
/// This module is the only place in the repository that constructs an
/// [`ImprovementRouteRequest`], and this function is its production caller: it
/// forwards to [`route_improvement_candidate`], and on the admitted branch to
/// [`assess_improvement_repeat`]. Both are pure delegations: no proposal digest
/// is computed here, no fallback, empty or legacy value is substituted, and the
/// typed [`PipelineError`] the Governor returns — today a refusal, because this
/// daemon holds no independent executed evaluation — crosses this boundary as
/// itself.
///
/// It returns the pipeline's own advisory-only terminal disposition, the exact
/// experiment plan the run committed it over, and the repeat assessment the
/// admitted branch derived — or the typed [`PipelineError`] the pipeline refused
/// with. It never promotes, activates, installs, completes, or issues authority,
/// and it performs no durability of its own: the caller commits through the
/// existing [`crate::DaemonComposition::commit_learning_record`] seam and
/// retains the next pass's record in the intake flight it already owns.
///
/// The route is bounded and non-looping: one call, one decision, per pass. It
/// never promotes, activates, installs, completes, or issues authority, and a
/// `CanaryAdmitted` result is only recorded here as a non-authorizing handoff
/// for the Kernel owner (`#11`) to authorize independently.
pub fn dispatch_improvement_candidate_route(
    dispatch: ImprovementRouteDispatch<'_>,
) -> Result<ImprovementRouteOutcome, PipelineError> {
    let candidate = &dispatch.artifact.candidate;
    // # The one point where this daemon consults the operation owner map
    //
    // This daemon raises exactly one proposal and drives the pipeline, so every
    // owner it has to STATE is read here, once, from the same projection
    // `ImprovementOperation::owner` defines — rather than each record builder
    // naming an owner for itself. I12.24:66-68 puts the experiment, its
    // measurement and the affected-checks/live-shadow evaluation in the hands of
    // the execution and verification owners rather than in the proposer's hands,
    // and the operation map is how the code says so.
    //
    // The rollback owner is the same `G-19` policy record's own value the
    // request already carries, read on the live path from
    // `DaemonComposition::maintenance_improvement_admission_policy` — never a
    // literal at this call site.
    let owners = RouteOwners::read(dispatch.policy.rollback_owner_id.as_str())?;
    // Bound once, so the plan the request borrows, the plan the returned handoff
    // is checked against, and the plan the outcome carries are the same value
    // rather than two constructions that could drift.
    let experiment = route_experiment(candidate, dispatch.policy, &owners);
    let proposal = route_proposal(candidate, dispatch.policy, dispatch.state_fence);
    let disposition = route_improvement_candidate(ImprovementRouteRequest {
        proposal: &proposal,
        experiment: &experiment,
        evidence: &route_activation_evidence(candidate, &owners),
        rollback: &route_rollback_contract(candidate, &owners),
        candidate: &route_candidate_view(candidate, dispatch.policy),
        admission_evidence: &route_admission_evidence(candidate, &owners, dispatch.retained),
        policy: dispatch.policy,
    })?;
    // The handoff is consumed under this build's identity BEFORE anything reads
    // its progress out of it, so the record the repeat assessment compares is
    // always one this build was able to read. A refusal crosses as the typed
    // `PipelineError` those checks produce, with no disposition returned at all.
    check_handoff_consumable(&disposition, &experiment)?;

    // The pipeline publishes its own checked current record inside the canary
    // handoff precisely so a consumer compares progress against the checked
    // content instead of recomputing it. Every identity below is COPIED from
    // that handoff; the only other input is the very `ExperimentPlan` this
    // dispatch submitted and the pipeline joined, held here unchanged. Nothing is
    // derived, so this cannot disagree with the record the pipeline committed.
    let current = checked_current_record(&disposition, &experiment);
    let repeat = match (dispatch.retained, current.as_ref()) {
        (Some(retained), Some(current)) => Some(assess_improvement_repeat(retained, current)?),
        _ => None,
    };
    let retained_next = current.as_ref().map(retained_record_of);
    // The external-effect read, taken from the Governor owner over the
    // disposition this very call produced. It is a read and nothing more: the
    // obligation's owner outcome is private to the Governor module, and this
    // module neither writes it nor re-decides the retry answer. On this
    // workspace the answer is the denying one, because no producer of an
    // owner-settled receipt exists; recording it is what makes that denial
    // visible on the live pass instead of an unexamined omission.
    let effect = read_improvement_effect_state(&disposition);
    Ok(ImprovementRouteOutcome {
        disposition,
        experiment,
        repeat,
        retained_next,
        effect,
    })
}

/// Makes one unresolved external-effect obligation durable for its named owner.
///
/// # Why the debt needs a durable record
///
/// `ImprovementUnknownEffect` is a value. The Governor pipeline builds it from
/// checked records and hands it back inside
/// `ImprovementTerminalDisposition::UnknownRequiresReconciliation`, and if this
/// daemon only logged it the debt would exist for exactly as long as the pass
/// that observed it. So the obligation is committed through the SAME durable
/// seam the rest of the improvement record family already uses:
/// [`DaemonComposition::commit_learning_record`] over the closed
/// `RecordLearningRecord` mutation, in the same Governor scope and the same
/// closed `candidate` record kind, under its own record key. `Ok(None)` is the
/// answer for a disposition that names no unresolved effect — there is nothing
/// to owe anyone, and inventing a record for a disposition that carries no debt
/// would be a fabricated obligation.
///
/// # What the record contains, and what it does NOT
///
/// The document is the obligation's own checked identity, committed verbatim
/// through the Governor owner's own
/// `eliot_maintenance::ImprovementUnknownEffectIdentity`: the whole
/// `ProposalCommitment` the pipeline computed (domain, encoding revision,
/// algorithm, operation reference, idempotency namespace, digest and canonical
/// size together) beside the owner, candidate, experiment, forward-repair
/// reference and invalidation set, plus the two answers the Governor owner gave
/// (`retry_permitted`, `completion_retained`). Carrying the owner's own record
/// rather than a daemon-local restatement of its identities is what lets a later
/// pass re-bind the debt to the exact proposal bytes it was raised over: the
/// binding is a content comparison of that commitment, not the presence of an
/// operation reference.
///
/// It contains NO effect outcome, NO receipt, NO permit and NO authority, because
/// this daemon holds none: the owner's outcome is private to the Governor module
/// and writable only through its own re-checked seam, which nothing in this
/// workspace can satisfy. So the record is a named debt plus the denying answer,
/// never a claim that the effect was settled, completed, or may be retried.
///
/// The key is a function of the obligation's own checked fields and of nothing
/// else, so re-committing the SAME unresolved obligation on a later pass
/// converges on one durable record instead of appending a duplicate, while a
/// genuinely different debt on the same candidate commits as its own record
/// rather than colliding with the first. Proof refs are the candidate's own canonical
/// evidence lineage — the same refs the candidate artifact commits under, so
/// this record cites the evidence its own obligation was raised over.
pub async fn commit_unknown_effect_obligation(
    composition: &mut DaemonComposition,
    artifact: &ImprovementArtifact,
    effect: &ImprovementEffectState,
    state_fence: &StateFence,
) -> Result<Option<WriteReceipt>, ImprovementDispatchError> {
    let Some(obligation) = effect.obligation.as_ref() else {
        return Ok(None);
    };
    let record = serde_json::json!({
        "unknown_effect_obligation": obligation,
        "retry_permitted": effect.retry_permitted,
        "completion_retained": effect.completion_retained,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(RECONCILIATION_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    // The key names THIS DEBT, so the obligation's commit is an operation
    // distinct from the candidate's own commit rather than one key reused for
    // two different documents, and a replay of the same unresolved obligation
    // converges on it. Distinct debts on the same candidate get distinct keys,
    // so neither can absorb the other's operation and experiment binding.
    let record_key = reconciliation_record_key(obligation)?;
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        record_key.clone(),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        record_key.clone(),
    ));
    let identity = reconciliation_commit_identity(&record_key, state_fence)?;
    let scope = ScopeId::new(RECONCILIATION_SCOPE)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let (receipt, _effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope,
            artifact.candidate.evidence_refs.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| {
            let candidate_id = &obligation.candidate_id;
            let owner_id = &obligation.owner_id;
            ImprovementDispatchError::Commit(format!(
                "the unresolved external effect on candidate {candidate_id} owed by owner \
                 {owner_id} could not be made durable: {error}"
            ))
        })?;
    Ok(Some(receipt))
}

/// The closed store handle and idempotency key of one reconciliation record.
///
/// # The key names the DEBT, not merely the candidate the debt is about
///
/// I12.24:69 places "delayed outcome/rework/maintenance window and rollback
/// reconciliation" in the pipeline as a window of its own, and this record is
/// that window's durable receipt: one named external effect whose outcome is
/// unsettled. The identity of such a debt is the whole checked obligation —
/// its owner, candidate, experiment, committed operation and idempotency
/// namespace, forward-repair reference and invalidation set — because those are
/// the bindings an owner settles against. The key therefore folds ALL of them,
/// not only the candidate.
///
/// # Folding the whole obligation duplicates no single debt
///
/// The key folds the Governor owner's own committed identity
/// (`ImprovementUnknownEffectIdentity`, read through
/// `ImprovementUnknownEffect::retained_identity`), so re-observing the SAME
/// unresolved debt on a later pass carries byte-identical values and lands on
/// the same key. What folding that record in costs is therefore nothing for a
/// repeat; what it buys is that two genuinely DIFFERENT debts on one candidate
/// stop converging on one key and stop taking the first debt's operation and
/// experiment binding with them. The earlier candidate-only key lost exactly
/// that binding: a second distinct debt on one candidate could not become a
/// second record, because the store arbitrates receipts by idempotency key first
/// and refuses changed content under a retained key.
///
/// The folded record is the OWNER's, including the whole `ProposalCommitment`,
/// so a debt raised over different proposal bytes is a different key rather than
/// a second document that reuses the first debt's operation binding.
///
/// # Why the identity is folded as a digest rather than spelled inline
///
/// The store bounds BOTH this handle and the idempotency key it doubles as at
/// `MAX_LEARNING_HANDLE_BYTES` (256 bytes), and the obligation's own operation,
/// experiment and repair references are unbounded owner text, so spelling them
/// inline could push an honest debt's key past the bound. A canonical digest is
/// deterministic, adds no nonce, clock read or counter, and is the same
/// derivation this commit already performs for its `scope_digest` and
/// `fence_digest`. The candidate stays in the clear prefix so the record family
/// keeps the `improvement-reconciliation:<candidate>` shape its readers and
/// diagnostics already name.
fn reconciliation_record_key(
    obligation: &eliot_maintenance::ImprovementUnknownEffectIdentity,
) -> Result<String, ImprovementDispatchError> {
    // The Governor owner's own committed identity, serialized whole. Nothing is
    // re-spelled here, so the key cannot disagree with the record the same commit
    // writes under it, and the whole `ProposalCommitment` travels: two debts over
    // different proposal bytes are different keys.
    let debt_identity = serde_json::json!({
        "unknown_effect_obligation": obligation,
    });
    let debt_digest = eliot_contracts::sha256_hex(
        &canonical_json_bytes(&debt_identity)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
    );
    let candidate_id = obligation.candidate_id.trim();
    Ok(format!(
        "improvement-reconciliation:{candidate_id}:{debt_digest}"
    ))
}

/// Derives the admitted commit ingress for one reconciliation record.
///
/// The request metadata is derived from this daemon's own admitted fence and the
/// idempotency key is the owner-derived record key, so an identical unresolved
/// obligation replays convergently under the same key. This mirrors
/// `improvement_intake_dispatch::improvement_commit_identity` field for field
/// rather than calling it: that helper is private to the intake module, and this
/// record is a distinct operation with its own key, so sharing the derivation
/// would couple two commits whose whole point is that they are separate.
fn reconciliation_commit_identity(
    record_key: &str,
    state_fence: &StateFence,
) -> Result<RequestIdentity, ImprovementDispatchError> {
    let now = super::unix_ms_i64();
    let service = super::SERVICE_NAME;
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(format!("{service}:{record_key}"))
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new(service)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        source_id: eliot_contracts::SourceId::new(service)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        state_fence: state_fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata
        .validate()
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    Ok(RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: state_fence.clone(),
        },
        idempotency_key: record_key.to_owned(),
        deadline_unix_ms: super::unix_ms().saturating_add(RECONCILIATION_COMMIT_DEADLINE_MS),
        cancellation_id: format!("{record_key}:cancel"),
    })
}

/// Re-projects one pipeline-checked current record into the retained shape the
/// NEXT pass compares against.
///
/// A field-for-field copy of the pipeline's own commitment, discriminator
/// projection, material-equality key and joined experiment plan. It derives
/// nothing, so a retained record can never carry an identity the pipeline did not
/// commit.
fn retained_record_of(current: &ImprovementCurrentProposal) -> RetainedImprovementProposal {
    RetainedImprovementProposal {
        commitment: current.commitment.clone(),
        discriminator: current.discriminator.clone(),
        material_equality: current.material_equality.clone(),
        experiment_plan: current.experiment_plan.clone(),
    }
}

/// The pipeline's own checked current record, read out of its canary handoff.
///
/// `None` for every disposition that does not publish the record, which is every
/// outcome except `CanaryAdmitted`. Nothing is recomputed: the commitment,
/// discriminator projection and material-equality key are the pipeline's own
/// values, and the experiment plan is the one this dispatch submitted and the
/// pipeline joined. This is the same read of the handoff's own recorded
/// components that [`check_improvement_handoff_identity`] makes, and it is only
/// reached once that check has refused a record this build cannot read.
fn checked_current_record(
    disposition: &ImprovementTerminalDisposition,
    experiment: &ExperimentPlan,
) -> Option<ImprovementCurrentProposal> {
    let ImprovementTerminalDisposition::CanaryAdmitted { handoff } = disposition else {
        return None;
    };
    Some(ImprovementCurrentProposal {
        candidate_id: handoff.candidate_id.clone(),
        commitment: handoff.proposal_commitment.clone(),
        discriminator: handoff.proposal_discriminator.clone(),
        material_equality: handoff.proposal_material_equality.clone(),
        experiment_plan: experiment.clone(),
    })
}

/// Consumes the `CanaryAdmitted` handoff under the identity THIS build checks.
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
/// stamped under a foreign revision gets presented as a current one, so BOTH
/// identities are checked here against this build's own constants, through the
/// crate's existing [`check_improvement_handoff_identity`] forwarder, which
/// applies [`eliot_maintenance::check_handoff_wire_revision`] and then
/// [`eliot_maintenance::check_checked_record_identity`].
///
/// # The ORIGINAL recorded values are what is compared
///
/// Nothing is recomputed, defaulted, rounded, or padded, and no second encoder,
/// hasher, or identity type is introduced. The comparison reads
/// [`eliot_maintenance::ImprovementCanaryHandoff::wire_revision`] and the
/// handoff's own recorded `proposal_commitment`, `proposal_discriminator` and
/// `proposal_material_equality` exactly as the producer recorded them: a handoff
/// carrying revision `7` is refused as revision `7`, is not padded up to this
/// build's `8`, and a commitment naming another domain, encoding revision or
/// algorithm is refused as itself rather than reinterpreted. The refusals cross
/// into the daemon as the typed [`eliot_maintenance::PipelineError`] variants
/// they wrap, carrying the disagreeing component, so no caller can repair the
/// record by guessing.
///
/// # No substitute on failure
///
/// A refusal is propagated, never resolved. There is no fallback digest, no
/// empty string, no default revision, no legacy value, and no recomputed hash
/// standing in for a record this build cannot read. The disposition is NOT
/// returned in a weakened form: a foreign record produces the typed error and
/// no disposition at all, so the caller never sees a handoff it might present
/// as current.
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
/// same build that stamps the constants, so this comparison can only pass. What
/// it establishes is that the CONSUMPTION is refused rather than trusted, and
/// it is the check that holds when the record reaches the daemon as decoded
/// bytes rather than as a same-process value: the record is
/// `Serialize`/`Deserialize` with `deny_unknown_fields` and is declared the
/// wire shape the Kernel owner will later read, so the daemon reading a
/// `CanaryAdmitted` disposition must not assume the producer's stamp describes
/// a shape this build understands. The Kernel `#11` owner that independently
/// authorizes activation is a different subsystem's boundary and is not
/// reachable from this crate; the symbol it needs is the same
/// [`eliot_maintenance::check_handoff_wire_revision`].
///
/// Every other disposition variant carries no handoff and is passed through
/// exactly as the pipeline produced it. `experiment` is the plan this same call
/// passed to the pipeline, carried so the returned handoff is checked against
/// the record that produced it rather than against a reconstruction.
fn check_handoff_consumable(
    disposition: &ImprovementTerminalDisposition,
    experiment: &ExperimentPlan,
) -> Result<(), PipelineError> {
    if let ImprovementTerminalDisposition::CanaryAdmitted { handoff } = disposition {
        check_improvement_handoff_identity(handoff, experiment)?;
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
    owners: &RouteOwners,
) -> ExperimentPlan {
    let candidate_id = candidate.candidate_id.as_str();
    // The experiment identity of this candidate. Derived from the candidate's
    // content-derived identity, so a repeat of the same evidence lineage names
    // the same bounded experiment rather than minting a new one per cadence.
    let experiment_id = format!("maintenance-improvement-experiment:{candidate_id}");
    ExperimentPlan {
        experiment_id,
        // Owner routing read from the operation map rather than spelled here, and
        // declared rather than claimed to have happened; see the module
        // documentation. I12.24:66-67 keeps the isolated experiment and its fixed
        // replay outside the proposer's own hands.
        testd_owner_id: owners.executor.clone(),
        // A14.6: the measurement/evaluation path is distinct from the production
        // path, and A5.5: a model evaluator's name does not make it independent.
        // The evaluator is the map's own `Evaluate` owner, a different read from
        // the executor above.
        evaluator_id: owners.evaluator.clone(),
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
fn route_activation_evidence(
    candidate: &ImprovementCandidate,
    owners: &RouteOwners,
) -> ActivationEvidence {
    let candidate_id = candidate.candidate_id.as_str();
    ActivationEvidence {
        evidence_id: format!("maintenance-activation-evidence:{candidate_id}"),
        // The verifier family the plan declared, read from the same map row the
        // plan's `evaluator_id` was read from, as a routing identity. It is NOT a
        // claim that this family evaluated anything: `execution` below is the
        // machine state that says so, and the pipeline reads it first. A14.6 is
        // the reason the two fields cannot be the same value: the executor of a
        // change is not the independent evaluator of it.
        verifier_id: owners.evaluator.clone(),
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
        //
        // MEASURED, not assumed: `ImprovementEvidenceExecution::Executed` has
        // no construction site anywhere in this workspace — not in `eliotd`,
        // not in `eliot-maintenance`, not in any test. The only other value this
        // enum could be given from an observation this daemon already holds is
        // the one set here, and the status is machine state, so it is set from
        // the fact that no run happened rather than from a verdict. The module
        // documentation names the exact preconditions under which a real
        // evaluation could arrive here; none of them is a field this daemon can
        // fill in without grading its own candidate, which A0.3 forbids.
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
    owners: &RouteOwners,
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
        // The rollback owner, read from the map's own `Rollback` row. The map
        // resolves `Rollback` to the owner it was given, and the owner it was
        // given is the same `G-19` policy record's `rollback_owner_id` the
        // request carries — so this value is the real rollback-contract owner
        // that `check_rollback_join` compares this contract and the admission
        // evidence against, not a copy that could drift from it.
        rollback_owner_id: owners.rollback.clone(),
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
///
/// The `policy` argument this builder used to take is gone: every owner it
/// declared is now read from the map, and the one remaining field it took from
/// the policy record (`rollback_owner_id`) is the map's `Rollback` row, so the
/// parameter had no honest reader left.
fn route_admission_evidence(
    candidate: &ImprovementCandidate,
    owners: &RouteOwners,
    retained: Option<&RetainedImprovementProposal>,
) -> ImprovementEvidenceView {
    let candidate_id = candidate.candidate_id.as_str();
    ImprovementEvidenceView {
        // The admission-review evaluator identity the plan declared, read from
        // the same map row rather than spelled here. No admission review ran; the
        // `independent` / `verifier_passed` pair below is what says so.
        verifier_id: owners.evaluator.clone(),
        bound_candidate_id: candidate.candidate_id.clone(),
        bound_experiment_id: format!("maintenance-improvement-experiment:{candidate_id}"),
        content_revision_ref: route_content_revision_ref(candidate),
        run_ref: String::new(),
        independent: false,
        verifier_passed: false,
        // No product pulse was observed for this candidate, and a package-green
        // result is never one.
        //
        // MEASURED: this is the ONLY production construction of
        // `ImprovementPulseOutcome` in the workspace, and it is the refusal.
        // Every non-refusal value is built inside the `#[cfg(test)] mod tests`
        // of `eliot-maintenance`'s `improvement_admission.rs`. The similarly
        // named `ProductPulseEvidence` in `eliot-improvement`'s own promotion
        // gate is a different type on a different record, so its two test
        // fixtures are not producers of this one. Owner `#11` is what would
        // supply a real pulse; see the module documentation.
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
        // The same map row the rollback contract above was read from, so the
        // evidence and the contract name one owner. `check_rollback_join` refuses
        // the pair if they ever disagree.
        rollback_owner_id: owners.rollback.clone(),
        expiry_ref: None,
        // The caller's own checked prior record, or the pipeline's own
        // no-retained-record case. This is a record, never a verdict: the gate
        // derives its own no-progress outcome from it, so nothing here can assert
        // a repeat, a new discriminator, or progress. Absence establishes
        // nothing either — it is never read as novelty.
        retained_prior_proposal: retained.cloned(),
    }
}
