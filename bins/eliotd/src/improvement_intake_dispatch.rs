//! Production improvement-intake dispatch for `eliotd` (issue #1867 W1,
//! I12.24).
//!
//! This is the production caller for the advisory candidate/brief intake. The
//! daemon run loop reaches it through [`crate::daemon_runtime`]'s retained
//! `ImprovementIntakeFlight`, starting from a live Governor maintenance
//! observation. This intake remains distinct from the full
//! `ImprovementRouteRequest` pipeline, which has no production request source.
//!
//! # The evidence is a real observation this daemon already made
//!
//! The single evidence source is the daemon's OWN live
//! [`eliot_maintenance::AutomationTriggerDecision`] produced by
//! [`crate::DaemonComposition::evaluate_maintenance_trigger`]
//! (`maintenance_trigger_evaluator.rs::DaemonComposition::evaluate_maintenance_trigger`),
//! which the run loop already evaluates per cadence. That decision carries the
//! Governor owner's real `trigger_id`, `family`, `scope_ref`, `reason`,
//! `decision` and `admits_job`, and is bound to the observed evidence
//! references the trigger site passed in. Nothing here invents an observation:
//! every ref below is derived from that decision's own fields.
//!
//! The evidence source is DERIVED from that decision's own closed fields by
//! [`maintenance_evidence_source`], not asserted. It previously claimed
//! [`eliot_improvement::EvidenceSource::Watchdog`] for every decision, which
//! mislabelled the recorded lineage: a conformance-audit family and a
//! security/dependency-scan family both recorded themselves as Watchdog
//! signals, so a later reader could not tell what kind of occurrence the
//! evidence was. The derivation — and why no `Watchdog` label survives it —
//! are documented on that function.
//!
//! # The durable port is the existing Governor/Kernel named mutation
//!
//! The owner-actionable artifact (candidate revision + brief + owner decision)
//! is committed through the EXISTING
//! [`crate::DaemonComposition::commit_learning_record`] seam, which is the one
//! Governor-owned caller of
//! [`eliot_governor::commit_learning_record`] and the only path that reaches
//! the closed `RecordLearningRecord` mutation
//! ([`eliot_store_api::LearningRecordKind::Candidate`]). No second write
//! path, store client or durability scheme is introduced here, and no
//! in-memory `BoundedBacklog` is treated as durable: the backlog is used only
//! for its deduplication registry within this one pass, and the committed
//! record is the durable artifact.
//!
//! # What deduplication is and is NOT guaranteed here
//!
//! The candidate identity is content-derived
//! ([`eliot_improvement::ImprovementCandidate::new`]), so a repeat of the same
//! observation produces the same `candidate_id`, and therefore the same
//! `improvement-candidate:<id>` commit key: the store converges on one row
//! instead of appending a new candidate per cadence tick. That is the durable
//! half of I12.24's "deduplicated by target surface and evidence lineage".
//!
//! The BACKLOG is still constructed per pass in
//! `daemon_runtime::improvement_intake_artifact` and is never read across
//! passes, so the in-memory merge branch of `admit_reporting_pressure` stays
//! unreachable in this daemon and cross-pass archive relief is not restored
//! after a restart. Carrying the registry across restarts needs an owner that
//! reads committed learning rows back into a backlog, which this issue does
//! not create; the statement above is limited to what the code does.
//!
//! # Promotion stays refused, by construction, not by omission
//!
//! The intake's promotion-grade budget gate
//! ([`eliot_improvement::require_matched_budget_for_promotion`]) is NOT
//! satisfied here, because this daemon runs no experiment and therefore
//! holds no real matched-budget live shadow/canary evidence. This module
//! consequently uses the advisory composition of the same
//! `eliot-improvement` owners — [`eliot_improvement::candidate_from_evidence`],
//! [`eliot_improvement::brief_at_safe_boundary`] and
//! [`crate::improvement_intake::record_brief_decision`] — rather than
//! calling [`eliot_improvement::intake_from_evidence`], whose unconditional
//! `require_matched_budget_for_promotion` call would demand fabricated
//! canary refs. This is the honest advisory state I12.24:74-80 describes:
//! "advisory … default; changes nothing until owner acts", and a
//! replay-only candidate that cannot promote. `BLOCKED-BY` promoting this
//! path through `intake_from_evidence` needs an owner that publishes real
//! matched-budget live shadow/canary evidence
//! ([`eliot_improvement::BudgetProof::live_shadow_refs`] /
//! [`::live_canary_refs`]); none exists in this workspace. W1's reachability
//! requirement — a real production caller consuming real evidence and
//! emitting a durably committed owner-actionable artifact — is met without
//! weakening that gate, which stays closed.

//! # The bounded backlog is a GOVERNED admission, not a daemon literal
//!
//! Before this module took the governed path, the only production
//! [`CandidateBoundPolicy`] was a hardcoded literal in this file
//! (`max_active: 8, min_value: 0.0, governor_authority_ref: "eliotd.maintenance",
//! policy_revision: 1`) and it was enforced through the registry-only
//! [`BoundedBacklog::admit`], which performs no authority check at all. The
//! named "Governor authority" was a `const IMPROVEMENT_OWNER` in this file, so
//! the bound was never compared with a live issuance — a bound that no owner
//! decided and that nothing could invalidate.
//!
//! It is now read from the maintenance (`G-19`) decision record through the
//! EXISTING maintenance admission path and enforced against a real
//! owner-issued permit:
//!
//! ```text
//! GovernorOwners::maintenance::improvement_admission_policy   (eliot-maintenance, G-19)
//!   → eliot_maintenance::resolve_candidate_surface_bound       (owner record vs enforced bound)
//!   → issue_learning_admission                                 (eliot-governor, live owner checks)
//!   → CandidateBoundPolicy::validate_governed                  (authority == permit.authority_ref)
//!   → BoundedBacklog::admit_reporting_pressure                 (W1 + W3)
//! ```
//!
//! Three properties of that chain are the guarantee, and each is a CONTENT
//! comparison against the owner's own record rather than a shape check:
//!
//! 1. The bound NUMBERS come from the G-19 policy record. This module
//!    spells none of them: [`maintenance_bound`] reads
//!    `ImprovementAdmissionPolicy::candidate_bounds`, and a surface with no
//!    entry is refused ([`ImprovementBoundError::NoBoundForSurface`]) instead
//!    of defaulted.
//! 2. The bound the daemon will ENFORCE is compared back against the owner's
//!    recorded bound by [`eliot_maintenance::resolve_candidate_surface_bound`]
//!    — `max_active` and `min_value` field by field, with `min_value`
//!    compared by bit pattern so a re-spelled float cannot slip through. A
//!    disagreement is refused with the disagreeing field named.
//! 3. The bound's OWNING AUTHORITY is compared against a live
//!    owner-issued [`LearningAdmissionPermit`]'s `authority_ref` by
//!    [`CandidateBoundPolicy::validate_governed`], which runs inside
//!    [`BoundedBacklog::admit_reporting_pressure`]. A constant that merely
//!    *names* an authority cannot pass that check; only a permit the Governor
//!    minted under the live epoch/generation can.
//!
//! No new scheduler, root record, table, task graph, evaluator or promotion
//! authority is introduced (I12.24:314): the bound is a field group on the
//! existing G-19 admission policy record, read through the existing
//! maintenance owner.
//!
//! # Archive receipts are durable dispositions, not diagnostics (W3)
//!
//! The governed admission returns the [`ArchivedCandidate`] receipts the
//! bound-relief path produced. Each is committed through the SAME
//! [`DaemonComposition::commit_learning_record`] seam and the SAME closed
//! [`eliot_store_api::LearningRecordKind`] this module already uses for the
//! candidate itself, so an archived candidate's summary, cause and recorded
//! [`ImprovementLifecycle`] disposition become durable evidence. No new record
//! kind, table, or write path is added: `Candidate` is the closed kind that
//! covers "recording never performs promotion", and an archive receipt is a
//! record about a candidate.
//!
//! # Cross-task carryover is issued and verified here (W5)
//!
//! [`CrossTaskCarryover::verify`] and the Governor's
//! [`issue_cross_task_admission`](eliot_governor::LearningAdmissionPermit::issue_cross_task_admission)
//! had no non-test caller, so no production code could mint or present a
//! cross-task admission. [`issue_cross_task_carryover`] and
//! [`verify_cross_task_carryover`] are that production path: the first issues
//! the SECOND, distinct admission for a foreign target task through the same
//! live owner checks, the second re-verifies both permits against live owner
//! state and constructs the owner-verified [`CrossTaskCarryover`] a consumer
//! binds to. It uses the Governor-owned record — never the weaker
//! string-typed `eliot_learning_contracts::activation::CrossTaskAdmission`
//! that `candidate_bounds.rs` names as the shape being replaced.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::StateFence;
use eliot_governor::{
    CrossTaskAdmissionError, CrossTaskAdmissionRecord, LearningAdmissionClaim,
    LearningAdmissionError, LearningAdmissionPermit, VerifiedLearningAdmission,
    issue_learning_admission, verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{
    AdmitOutcome, AdmitReport, ArchivedCandidate, BoundedBacklog, CandidateBoundPolicy,
    CrossTaskCarryover, TrackedCandidate,
};
use eliot_improvement::{
    ChangeDescriptor, EvidenceSource, ImprovementBrief, ImprovementCandidate, ImprovementError,
    ImprovementLifecycle, ImprovementSurface, OwnerDecision, OwnerDecisionKind, ReplayPlan,
    SafeBoundary, SourcedEvidence, brief_at_safe_boundary, candidate_from_evidence,
    check_class_gate, classify, sourced_evidence,
};
use eliot_maintenance::{
    IMPROVEMENT_ADMISSION_AUTHORITY, IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    ImprovementAdmissionPolicy, ImprovementBoundError, ImprovementSurfaceBound,
    ImprovementTargetSurface, resolve_candidate_surface_bound,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    LearningRecordKind, ScopeId, canonical_json_bytes, learning_record_commit_params,
    learning_record_mutation_request,
};
use thiserror::Error;

use super::{DaemonComposition, SERVICE_NAME};

/// Closed improvement surface this daemon's own self-quality-debt observations
/// concern, named in the maintenance (`G-19`) closed surface vocabulary so the
/// bound this daemon enforces can be read from the owner's record by key.
const IMPROVEMENT_SURFACE: ImprovementSurface = ImprovementSurface::Memory;

/// The maintenance (`G-19`) closed name of [`IMPROVEMENT_SURFACE`].
///
/// Resolved through the owner's own closed vocabulary rather than spelled as a
/// string, so a surface rename cannot silently leave this daemon looking up a
/// bound under a name the owner no longer defines.
const IMPROVEMENT_SURFACE_NAME: ImprovementTargetSurface = ImprovementTargetSurface::Memory;

/// The candidate's owning decision authority, and the authority the bound is
/// owned by: maintenance (`G-19`), read from
/// [`eliot_maintenance::IMPROVEMENT_ADMISSION_AUTHORITY`] rather than declared
/// here.
///
/// The same value is the learning admission permit's `authority_ref`, which is
/// what makes [`CandidateBoundPolicy::validate_governed`] a real check: the
/// bound's owner is compared against a Governor-minted permit, so this constant
/// cannot admit anything by itself. `ASSUMPTION:` the candidate's
/// `owner_and_decision_authority` is the maintenance admission owner rather
/// than the daemon's service name, because I12.24 requires the decision owner
/// to be the authority that admits the candidate, and `G-19` is declared the
/// sole admission owner for `meta.learning.closure` and
/// `meta.improvement.promotion_input` candidates
/// (`crates/governor/eliot-maintenance/src/improvement_admission.rs:3-4`).
const IMPROVEMENT_OWNER: &str = IMPROVEMENT_ADMISSION_AUTHORITY;

/// Closed store scope for durable improvement-candidate learning records.
///
/// This is the same fixed `governor` scope the Skill lifecycle/evidence owner
/// rows already use (`skill_evidence_read.rs::LIFECYCLE_SCOPE`), so the
/// improvement candidate lands in the Governor-owned scope rather than
/// inventing a second scope.
const IMPROVEMENT_SCOPE: &str = "governor";

/// Deadlines bounding one durable learning-record commit ingress, in Unix
/// milliseconds, matching the retained daemon transport's own operation bound
/// (`experience_runtime.rs::COMMIT_INGRESS_DEADLINE_MS`).
const IMPROVEMENT_COMMIT_DEADLINE_MS: u64 = 30_000;

/// Owner-assessed expected value of one maintenance-debt improvement candidate.
///
/// This is the ASSESSMENT, not the bound: `CandidateBoundPolicy::min_value` is
/// the floor read from the owner's record and is never spelled here, and
/// `max_active` is likewise the owner's. `ASSUMPTION:` a maintenance-debt
/// candidate is worth the neutral `1.0` — the daemon runs no experiment and
/// holds no measured benefit, so it claims neither more nor less, and the value
/// only orders the backlog (I12.24:297) and decides the `LowValue` archive
/// cause against the OWNER's floor. A candidate whose owner assesses less than
/// that floor is refused by the bound, and the daemon's own number is then
/// irrelevant to the outcome.
const IMPROVEMENT_CANDIDED_VALUE: f64 = 1.0;

/// Source campaign identity the daemon's improvement learning belongs to.
///
/// A real, stable, owner-scoped identity rather than a per-observation value:
/// the learning this daemon produces is one maintenance campaign's, and a
/// cross-task carryover is defined as carrying THAT campaign's learning to
/// another task, so a per-observation campaign id would make no carryover
/// representable. `ASSUMPTION:` the daemon's maintenance cadence is one
/// campaign; the daemon has no campaign-creation path of its own, and the
/// admission's own `scope_ref` (the observed maintenance scope) is what
/// distinguishes one observation from another.
const IMPROVEMENT_CAMPAIGN: &str = "eliotd.maintenance.improvement";

/// The independent evaluator that must verify any experiment the maintenance
/// admission owner releases one of these candidates to.
///
/// Named here as the revalidation's evaluator because the maintenance
/// evaluation IS the independent observation that raised the candidate; a
/// revalidation claiming a different evaluator is compared field-by-field
/// against the minted permit and refused, so this value cannot be a free-text
/// pass.
const IMPROVEMENT_EVALUATOR: &str = "maintenance-trigger-evaluator";

/// Typed failures of the production improvement-intake dispatch.
#[derive(Debug, Error)]
pub enum ImprovementDispatchError {
    /// The `eliot-improvement` owner rejected the candidate, brief, or
    /// decision assembly for this real observation.
    #[error("improvement intake: {0}")]
    Improvement(#[from] ImprovementError),
    /// The bounded-backlog registry refused the candidate.
    #[error("improvement backlog: {0}")]
    Backlog(String),
    /// The maintenance (`G-19`) decision record refused the bound this daemon
    /// would enforce: the surface has no owner-decided bound, the bound is
    /// unusable, or the enforced bound disagrees with the owner's own record.
    #[error("improvement bound: {0}")]
    Bound(#[from] ImprovementBoundError),
    /// The live Governor refused to issue or re-verify the learning admission
    /// this governed path requires. The typed owner error travels unchanged,
    /// so "not admitting", "stale epoch", "generation drift", "digest
    /// mismatch" and "fence drift" stay distinguishable.
    #[error("improvement learning admission: {0}")]
    Admission(#[from] LearningAdmissionError),
    /// The Governor refused the distinct cross-task admission, or the
    /// cross-task record failed re-verification. The typed
    /// [`CrossTaskAdmissionError`] travels unchanged.
    #[error("improvement cross-task admission: {0}")]
    CrossTask(#[from] CrossTaskAdmissionError),
    /// The Self-Quality conformance contract refused the diagnosis this
    /// observation would have produced, or the finding had no usable refs for
    /// the improvement funnel. The typed [`eliot_self_quality::SelfQualityError`]
    /// travels unchanged, so a #971 contract rejection and a missing
    /// improvement-mapping ref stay distinguishable here rather than collapsing
    /// into one opaque string.
    #[error("improvement self-quality conformance diagnosis: {0}")]
    SelfQuality(#[from] eliot_self_quality::SelfQualityError),
    /// The durable learning-record commit was refused.
    #[error("improvement learning-record commit: {0}")]
    Commit(String),
    /// The store scope or record identity is not a valid contract value.
    #[error("improvement contract value: {0}")]
    Contract(String),
}

/// One assembled, owner-actionable improvement artifact over a real
/// observation, ready to be made durable.
///
/// Every field is a function of the observed maintenance decision; the
/// `ImprovementBrief` is the exact artifact I12.24:74 requires the decision
/// owner to read (problem, evidence, likely benefit, risk, proposed owner,
/// cost, next reversible step, unknowns) so the owner never searches raw
/// metrics.
#[derive(Clone, Debug)]
pub struct ImprovementArtifact {
    /// The evidence-bound candidate admitted to the deduplication registry.
    pub candidate: ImprovementCandidate,
    /// Owner-actionable brief at the safe boundary.
    pub brief: ImprovementBrief,
    /// Recorded, non-mutating owner decision over that brief.
    pub decision: OwnerDecision,
}

/// Assembles the deduplicated improvement candidate, the owner-actionable
/// brief, and the recorded owner decision from one real maintenance-trigger
/// observation.
///
/// The decision's own `trigger_id`, `family`, `scope_ref`, `reason` and
/// `decision` are the evidence lineage, so two evaluations of the same
/// failure under the same admitted fence deduplicate by content
/// (`BoundedBacklog::admit` merges on overlapping lineage) rather than
/// minting a fresh candidate per observation.
///
/// `state_fence` is the daemon's own admitted Kernel fence for this pass; it
/// becomes the candidate's `validity_scope` (see [`admitted_fence_ref`]), so
/// the artifact is only ever admitted under the same authority epoch and
/// resource generation the observation was evaluated under.
///
/// This performs no durability, no promotion and no activation: it returns the
/// artifact, and the caller commits it through
/// [`crate::DaemonComposition::commit_learning_record`].
///
/// `observed_closures` is the single Governor-owned learning-closure image
/// ([`eliot_governor::CanonicalLearningDeltaStore`]) this daemon already holds,
/// reached as `DaemonComposition::learning_closure().store()`. It is read here,
/// under whatever guard the caller holds, so the brief's safe boundary is an
/// owner-observed consequential boundary rather than a formatted literal (see
/// the `SafeBoundary::from_observed_closure` call below).
pub fn assemble_improvement_artifact(
    decision: &eliot_maintenance::AutomationTriggerDecision,
    state_fence: &StateFence,
    observed_closures: &eliot_governor::CanonicalLearningDeltaStore,
) -> Result<ImprovementArtifact, ImprovementDispatchError> {
    // Evidence lineage: the decision's own stable identity, never a fresh
    // per-observation value, so a repeat deduplicates.
    let evidence_refs = maintenance_evidence_refs(decision);
    let trace_refs = vec![format!("maintenance-family:{}", decision.family)];
    // `MaintenanceFamily` carries a `Display` impl (its canonical SCREAMING
    // spelling); `AutomationDecision` and `DecisionReason` are `Debug`-only
    // closed owner enums and gain no `Display` here, so they are named by
    // their derived variant spelling instead.
    let trigger = maintenance_trigger_text(decision);
    // The replay plan is diagnostic-only (I12.24:76-77): the fixed replay,
    // holdout and transfer legs are the decision's own canonical refs, and the
    // counter metrics name what must not regress. Promotion is separately
    // refused by the intake's budget gate, which this advisory path does not
    // attempt to satisfy.
    let replay_plan = maintenance_replay_plan(decision, &evidence_refs);
    let admitted_scope = admitted_fence_ref(state_fence)?;
    // The evidence bundle is selected by the DERIVED source, not asserted
    // (issue #1867 W2). Every source but one is the maintenance occurrence
    // itself, and is assembled by the funnel's own validated constructor. The
    // conformance-audit source is different in kind: I12.24:50 names the
    // trigger "Architecture/Implementation/runtime conformance gap", so that
    // evidence enters the funnel through the Self-Quality conformance
    // diagnosis contract, which owns the finding's inert owner handoff
    // (`eliot_self_quality::conformance_evidence`), rather than being labelled
    // as a maintenance occurrence and losing the conformance owner, the
    // priority axis and the invalidation set the finding recorded. Both arms
    // terminate in the same `eliot_improvement::sourced_evidence` validation,
    // so neither can bypass it.
    let evidence = match maintenance_evidence_source(decision) {
        EvidenceSource::ConformanceDiagnosis => {
            conformance_diagnosis_evidence(decision, &trigger, &admitted_scope)?
        }
        source => sourced_evidence(
            source,
            &evidence_refs,
            &trace_refs,
            &trigger,
            &[format!(
                "unproven-blocked-automation:{}",
                decision.trigger_id
            )],
            &admitted_scope,
            IMPROVEMENT_OWNER,
        )?,
    };

    let mut candidate = candidate_from_evidence(
        SERVICE_NAME,
        IMPROVEMENT_SURFACE,
        &format!(
            "evaluate and resolve the blocked maintenance family {} at {}",
            decision.family, decision.scope_ref
        ),
        &evidence,
        replay_plan,
        BTreeMap::new(),
        &format!("maintenance-family:{}", decision.family),
        &format!("maintenance-canary:{}", decision.trigger_id),
        &format!("maintenance-rollback:{}", decision.trigger_id),
        &format!("maintenance-stop:{}", decision.trigger_id),
    )?;
    // Admitted intake is triaged for owner review, exactly as the intake
    // path does, so the durable record carries the owner-decision lifecycle.
    candidate.transition_lifecycle(ImprovementLifecycle::Triaged)?;

    // The application-class boundary is enforced HERE, in the production
    // assembly, not only inside `prepare_intake` (issue #1867 W5). Before this
    // the gate had no production caller at all: `classify` and
    // `check_class_gate` were reachable only from `intake_from_evidence`, which
    // this daemon deliberately does not call because its budget gate would
    // demand fabricated canary refs. The class is therefore decided here from
    // the candidate's OWN recorded surface, and a candidate whose recorded
    // surface the owner forbids to the advisory class is refused rather than
    // assembled.
    //
    // Stated plainly so this call is not read as broader than it is: the
    // candidate assembled above records [`IMPROVEMENT_SURFACE`] (`Memory`),
    // which is not a protected surface, so on the live maintenance path the
    // class taken is `Advisory` and the gate passes. What the gate buys here is
    // that the class is a FUNCTION of the candidate's recorded surface rather
    // than of literals — a candidate carrying `Verifier` or `Scheduler` is
    // refused. See `enforce_advisory_class_gate` for the exact ceiling,
    // including the two classes this path cannot represent at all.
    enforce_advisory_class_gate(&candidate)?;

    // The safe boundary is READ, not spelled. It used to be two formatted
    // strings (`owner:{IMPROVEMENT_OWNER}` and `boundary:{scope_ref}`), which
    // satisfied `SafeBoundary::validate` while observing nothing at all: the
    // owner was a constant and the boundary was the scope this very pass is
    // about to write, so the check proved nothing about the operation it claims
    // to gate. `SafeBoundary` now has private fields and one constructor,
    // `SafeBoundary::from_observed_closure`, which takes both values from a
    // record the Governor's learning-closure owner actually committed from
    // owner-recorded lifecycle activities
    // (`crates/governor/eliot-governor/src/learning_closure.rs:483`). That
    // boundary is derived by `derive_boundaries`, which refuses an ordinary
    // read and an empty activity set before anything is committed, per
    // I12.24:181.
    //
    // STATED PLAINLY, because it changes what this pass does: `store` is read
    // from already-committed in-process state and performs no exchange, but an
    // EMPTY closure image is `ImprovementError::UnsafeBoundary`, so this pass
    // now commits nothing until a consequential attempt has actually been
    // closed in this process. That is the fail-closed direction I12.24:64
    // requires — a brief must not reach an owner as though a boundary had been
    // observed when none was — and the refusal is reported as a typed
    // `ImprovementDispatchError::Improvement` by the caller, not swallowed.
    let boundary = SafeBoundary::from_observed_closure(observed_closures)?;

    // The brief's decision information is a PROJECTION OF THAT SAME OBSERVED
    // RECORD, not the raw maintenance trigger text. I12.24:74 requires the
    // named decision owner to read the problem, evidence, likely benefit, risk,
    // cost, next reversible step and unknowns without searching raw metrics;
    // repeating the trigger text satisfied the letter of that and none of its
    // purpose, because it said nothing about what the closure actually
    // recorded.
    //
    // `load` is the same mutex-guarded read `from_observed_closure` just
    // performed on the same image, under the composition guard the caller
    // already holds (`daemon_runtime::improvement_intake_artifact`), and this
    // guarded phase commits nothing, so the newest record here is the record
    // whose `actor_id` and `consequential_boundary` the boundary above names.
    // It is read a second time because the two-string `SafeBoundary` cannot
    // carry the record itself: `eliot-improvement` has no `eliot-learning-delta`
    // edge, so widening `SafeBoundary` to hold one would be a new dependency
    // for a value the brief only needs to quote. The record TYPE is not named
    // here either — `eliotd` has no `eliot-learning-delta` dependency — so it is
    // read by inference and through the record's own accessors. An unreadable
    // or empty image is the same typed `UnsafeBoundary` refusal the boundary
    // constructor returns for the same condition, never a substituted value.
    let observed = newest_observed_closure(observed_closures)?;
    // The durable lineage handle and canonical digest the record itself
    // committed, so the owner can read exactly this closure without searching.
    let (observed_artifact, observed_digest) = (
        observed.lineage_artifact.clone(),
        observed.lineage_digest.clone(),
    );
    // What the observed closure actually concluded about behaviour, read
    // through the record's own predicates rather than re-spelled here.
    let observed_effect = if observed.carries_behavioural_proposal {
        "and proposes a next-behaviour change for the next attempt"
    } else {
        "and closed with no next-behaviour change proposed"
    };
    // The two values below are the boundary's OWN observed strings, so the
    // boundary this brief describes and the boundary it is gated on are
    // literally the same value.
    let principal = boundary.observed_principal_ref();
    let boundary_ref = boundary.observed_boundary_ref();
    let unknowns = observed_unknowns(&observed, decision.family);

    // Why the brief names the OBSERVED principal, and which brief fields the
    // closure record cannot supply, is stated in the module documentation
    // above under "One principal, two roles".
    let brief = brief_at_safe_boundary(
        &candidate,
        &format!(
            "{trigger}; the learning closure this brief is gated on committed durable delta \
             {observed_artifact} (digest {observed_digest}) for attempt {} of campaign {} on \
             route {}, at consequential boundary {boundary_ref} by principal {principal}, over {} \
             observed evidence ref(s)",
            observed.attempt_id,
            observed.campaign_id,
            observed.route_id,
            observed.evidence_ref_count,
        ),
        &format!(
            "the blocked family {} is evaluated on every cadence and cannot start, and the \
             closure this brief is gated on {observed_effect}; giving that family a start route \
             removes a blocked evaluation per cadence",
            decision.family
        ),
        &format!(
            "advisory only; no authority, privacy, finish or durability effect is taken, and the \
             observed boundary {boundary_ref} is not modified by it"
        ),
        principal,
        "one owner triage pass over the stored brief; the observed closure record carries no \
         cost, compute or Human-attention field, so the cost of the decision itself is the only \
         cost this brief can state",
        &format!(
            "triage maintenance trigger {} against the observed boundary {boundary_ref}",
            decision.trigger_id
        ),
        unknowns,
        &boundary,
    )?;

    // The daemon's owner records a non-mutating `Investigate` disposition: the
    // artifact is real and actionable, and recording it changes nothing. This
    // is the production caller of the bridge's
    // `record_brief_decision`, which previously had none.
    //
    // The `owner` here is the maintenance (`G-19`) admission authority and is
    // deliberately NOT the brief's `proposed_owner`: this field names the
    // principal that RECORDED this disposition, which the maintenance owner is
    // (it issued the permit this candidate was assembled under), whereas the
    // brief's `proposed_owner` names the principal proposed to decide. Naming
    // the same constant in both would be the incoherence this region exists to
    // remove; naming them differently, with the difference stated here, is what
    // makes each field mean one thing.
    let decision_record = crate::improvement_intake::record_brief_decision(
        &brief,
        IMPROVEMENT_OWNER,
        OwnerDecisionKind::Investigate,
        &format!("triage blocked maintenance family {}", decision.family),
    )
    .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;

    // Deduplication and bounded admission are NOT done here. They need the
    // live Governor owner (a real permit whose authority the bound is checked
    // against), which this pure assembly deliberately does not take; the
    // governed admission is `admit_improvement_artifact`, whose single
    // production caller is `daemon_runtime::run_improvement_intake`.
    Ok(ImprovementArtifact {
        candidate,
        brief,
        decision: decision_record,
    })
}

/// The evidence lineage this observation raises, over the decision's own
/// stable identity.
///
/// Never a fresh per-observation value: the refs are the decision's own
/// `trigger_id` and `scope_ref`, so two evaluations of the same occurrence
/// under the same admitted fence carry the same lineage and deduplicate.
fn maintenance_evidence_refs(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> Vec<String> {
    vec![
        format!("maintenance-trigger:{}", decision.trigger_id),
        format!("maintenance-scope:{}", decision.scope_ref),
    ]
}

/// The trigger statement the decision's own closed fields make.
///
/// `MaintenanceFamily` carries a `Display` impl (its canonical SCREAMING
/// spelling); `AutomationDecision` and `DecisionReason` are `Debug`-only
/// closed owner enums and gain no `Display` here, so they are named by their
/// derived variant spelling instead.
fn maintenance_trigger_text(decision: &eliot_maintenance::AutomationTriggerDecision) -> String {
    format!(
        "maintenance automation {} evaluated {:?} for reason {:?}",
        decision.family, decision.decision, decision.reason
    )
}

/// The diagnostic-only replay plan for this observation (I12.24:76-77).
///
/// The fixed replay, holdout and transfer legs are the decision's own canonical
/// refs, and the counter metric names what must not regress. Promotion is
/// separately refused by the budget gate, which this advisory path does not
/// attempt to satisfy.
fn maintenance_replay_plan(
    decision: &eliot_maintenance::AutomationTriggerDecision,
    evidence_refs: &[String],
) -> ReplayPlan {
    ReplayPlan {
        fixed_replay_refs: evidence_refs.to_vec(),
        holdout_refs: vec![format!("maintenance-holdout:{}", decision.trigger_id)],
        transfer_refs: vec![format!("maintenance-transfer:{}", decision.scope_ref)],
        counter_metric_names: vec!["blocked_maintenance_runs".to_owned()],
        verifier_refs: vec![format!("maintenance-evaluator:{}", decision.family)],
    }
}

/// The material one observed closure contributes to the brief.
///
/// Owned, not borrowed: the record TYPE cannot be named here — neither `eliotd`
/// nor `eliot-improvement` has an `eliot-learning-delta` edge, and adding one for
/// a value the brief only quotes would be a new dependency. The closure's
/// accessors are read through inference and their results carried by value, so
/// nothing in this module depends on the record's concrete type.
struct ObservedClosure {
    /// Durable lineage handle and canonical digest the record committed.
    lineage_artifact: String,
    lineage_digest: String,
    /// The closed attempt this observation belongs to.
    attempt_id: String,
    /// The campaign that attempt belonged to.
    campaign_id: String,
    /// The route the closed attempt ran.
    route_id: String,
    /// How many evidence refs the record itself observed.
    evidence_ref_count: usize,
    /// The record's own predicate on whether it proposed a behaviour change.
    carries_behavioural_proposal: bool,
    /// Whether the record names a prior-attempt lineage to retry against.
    has_retry_lineage: bool,
}

/// Reads the newest committed closure record, refusing when there is none.
///
/// The same mutex-guarded read [`SafeBoundary::from_observed_closure`] performs
/// on the same image, under the composition guard the caller already holds, so
/// both see the same newest record. An unreadable or empty image is the same
/// typed [`ImprovementError::UnsafeBoundary`] refusal, never a substituted
/// value.
fn newest_observed_closure(
    observed_closures: &eliot_governor::CanonicalLearningDeltaStore,
) -> Result<ObservedClosure, ImprovementError> {
    let (observed_records, _observed_version) = observed_closures
        .load()
        .map_err(|_| ImprovementError::UnsafeBoundary)?;
    let observed = observed_records
        .last()
        .ok_or(ImprovementError::UnsafeBoundary)?;
    let (lineage_artifact, lineage_digest) = observed.lineage_ref();
    Ok(ObservedClosure {
        lineage_artifact: lineage_artifact.to_string(),
        lineage_digest: lineage_digest.to_owned(),
        attempt_id: observed.attempt_id.as_str().to_owned(),
        campaign_id: observed.campaign_id.as_str().to_owned(),
        route_id: observed.route_id.clone(),
        evidence_ref_count: observed.evidence_refs.len(),
        carries_behavioural_proposal: observed.carries_behavioural_proposal(),
        has_retry_lineage: observed.lineage_for_retry().is_some(),
    })
}

/// The unknowns the observed closure could not resolve, plus the one it cannot
/// speak to at all.
///
/// Unknowns are the states the record could NOT resolve. The maintenance
/// start-route question is kept because it is real and no closure record answers
/// it. `require_refs` in [`eliot_improvement::ImprovementBrief::validate`]
/// still hard-requires a non-empty list.
fn observed_unknowns(
    observed: &ObservedClosure,
    family: eliot_maintenance::MaintenanceFamily,
) -> Vec<String> {
    let mut unknowns = vec![format!(
        "unknown whether maintenance family {} has a start route",
        family
    )];
    if !observed.has_retry_lineage {
        unknowns.push(format!(
            "the observed closure of campaign {} records no prior-attempt lineage, so it \
             establishes no repeated-strategy comparison",
            observed.campaign_id
        ));
    }
    unknowns
}

/// Enforces the I12.24 application-class boundary over a real candidate
/// (issue #1867 W5).
///
/// # The descriptor is the candidate's own recorded content
///
/// [`ImprovementCandidate::target_surface`] is the candidate's OWN closed
/// surface record, and it is the only class evidence this path holds. The
/// descriptor is therefore built by
/// [`ChangeDescriptor::from_recorded_surface`], the crate's own constructor for
/// exactly this situation:
///
/// - `touches_protected` is [`eliot_improvement::is_prohibited_tuning_surface`]
///   over that surface, so it is a comparison of the candidate's recorded
///   surface against the owner's closed rule, not a spelled literal. A
///   candidate recorded on [`ImprovementSurface::Verifier`] or
///   [`ImprovementSurface::Scheduler`] classifies as `Protected` and is refused
///   below, because the owner class for those surfaces requires an explicit
///   owner decision and a corresponding migration/proof (I12.24:93) and this
///   path holds neither. `ASSUMPTION:` those two surfaces map to `Protected`
///   rather than to `CodeModuleConfig`, because I12.24:93 names `verifier` and
///   `authority` in the protected class and I12.24:87-88 names
///   `verifier definition` and `Kernel/Watchdog reserve` as never-tuning — so
///   the owner-decision route the crate's own
///   [`eliot_improvement::is_prohibited_tuning_surface`] names for them is the
///   protected one. `Protected` is also the stricter of the two routes that
///   function allows, so the mapping fails closed.
/// - `bounded_tuning` and `has_work_item_ref` are NOT spelled on this call at
///   all, and cannot be: that constructor exposes no parameter for them,
///   precisely because this path holds no evidence for either. I12.24:85 admits
///   pre-authorized tuning only "inside a declared safe range" and the
///   I12.24:20-38 `ImprovementCandidate` schema lists no safe range, so there
///   is nothing to read; I12.24:90 admits code/module/config delivery as a
///   "normal work item", and I12.24:65 places that work item after "decision
///   owner selects reject / investigate / work item / experiment", so the
///   candidate assembled here carries none. `ASSUMPTION:` this path therefore
///   cannot honestly select either class, and the correct outcome is to say so
///   rather than to mint a `true`: the `PreAuthorizedTuning` and
///   `CodeModuleConfig` classes are NOT REACHABLE here, structurally, because
///   the only descriptor this path can build has no way to claim them. A
///   future change that wants either has to add the safe range or the real work
///   item to the candidate first; until then there is nothing for this gate to
///   refuse on those two classes, and this comment does not claim otherwise.
///
/// [`ImprovementCandidate::advisory_only`] is deliberately NOT used as a class
/// flag. It is a real recorded field, but it is not the same thing as these
/// three: `validate_base` refuses any candidate whose `advisory_only` is false
/// (`ImprovementError::SelfPromotionForbidden`), so it is a self-promotion
/// invariant that is already enforced upstream on every candidate, not
/// evidence about which of the four I12.24 classes this change belongs to.
/// Reading it as a class input would re-derive a fact the owner already
/// guarantees and would misreport the class boundary as content-bound when the
/// class content is the surface record above.
///
/// # What the gate actually refuses
///
/// [`check_class_gate`] is asked for the material this path really holds:
/// `rollback_ref` is the candidate's own recorded `rollback`;
/// `owner_approved` is `false` and `migration_proof_ref` is `None` because
/// this path holds no owner decision and no migration/proof, and
/// `work_item_ref` is `None` because the candidate records no work item.
/// Those absences are the fail-closed direction: a candidate whose recorded
/// surface classifies as `Protected` is refused with
/// [`ImprovementError::ApplicationClassViolation`] rather than assembled, and
/// `live_experiments_on_surface` is `0` — this path starts no experiment — but
/// it is not read, because the tuning class is not representable above.
///
/// The refusal is therefore content-bound: it turns on the surface the
/// candidate actually records. It is not a claim that every class upgrade is
/// caught, and no such claim is made here.
fn enforce_advisory_class_gate(
    candidate: &ImprovementCandidate,
) -> Result<(), ImprovementDispatchError> {
    let change = ChangeDescriptor::from_recorded_surface(candidate.target_surface);
    let class = classify(&change);
    check_class_gate(class, &change, 0, &candidate.rollback, None, false, None)?;
    Ok(())
}

/// The I12.24 evidence source this daemon's own maintenance decision belongs
/// to (issue #1867 W2).
///
/// DERIVED from the closed fields the Governor's own decision carries, so the
/// recorded source is a fact about the observation rather than an assumption.
/// Every observation this function labels is the same KIND of occurrence: the
/// maintenance owner's evaluation of one real maintenance trigger — an attempt
/// at admitting that maintenance job together with the outcome it produced.
/// I12.24:43 names that trigger "repeated failure/repair or no-progress loop",
/// the closed I12.24 set spells it [`EvidenceSource::Attempt`], and this
/// issue's own source list names "actual attempts/evaluators" among the sources
/// this path must connect. So the two families whose occurrence is something
/// else carry their own label, and everything else is an attempt:
///
/// - `MaintenanceFamily::SecurityDependencyScan` is the daemon's
///   security/dependency incident family, and I12.24:49 names "security
///   incident".
/// - `MaintenanceFamily::DonorConformance` is the conformance-audit family,
///   and I12.24:50 names "Architecture/Implementation/runtime conformance gap",
///   which the closed set spells [`EvidenceSource::ConformanceDiagnosis`].
/// - every other family, at every decision the evaluator can return, is the
///   attempt itself: `AutomationDecision::Start` admits the job, `Suggest`
///   preserves a recommendation instead, `Defer` holds it for a later eligible
///   window, `Block` and `Escalate` deny or escalate it, and
///   `SuppressDuplicate` records that equivalent work is already active. Each
///   of those is an outcome this daemon itself produced, and none of them is a
///   Watchdog suggestion.
///
/// # Why no decision reaching this function is a `Watchdog` observation
///
/// [`EvidenceSource::Watchdog`] is I12.24:54's "Dreamer/Watchdog/Concilium
/// suggestion". [`eliot_maintenance::AutomationTriggerDecision`]
/// (`crates/governor/eliot-maintenance/src/lib.rs:288-306`) carries
/// `trigger_id`, `family`, `scope_ref`, `decision`, `reason`, `admits_job` and
/// `durable_job_ref` — and no trigger-origin field, so no part of the decision
/// establishes which kind of occurrence proposed the trigger. The origin that
/// maps to `MaintenanceTrigger::WatchdogProblem` is
/// `MaintenanceTriggerOrigin::AdmittedObservation`
/// (`maintenance_trigger_evaluator.rs:125`), while the observation this dispatch
/// records is built from `MaintenanceTriggerOrigin::IdleTransition`
/// (`daemon_runtime.rs:2169`), which maps to `MaintenanceTrigger::Policy`
/// (`maintenance_trigger_evaluator.rs:123`). A policy-driven occurrence is not
/// a Watchdog suggestion, and nothing in the decision could make it one.
///
/// The residual this function used to carry claimed
/// [`EvidenceSource::Watchdog`] for every decision that was neither of the two
/// named families nor a refusal, which covered `Suggest`, `Defer`, `Start` and
/// `SuppressDuplicate`. The refusal test it consulted admitted only `Block` and
/// `Escalate`, although the owner's evaluator pairs `Defer` — never `Block` —
/// with `NotIdle`, `OutsideSchedule`, `RouteUnavailable`, `BudgetUnavailable`
/// and `UserSessionRequired`
/// (`crates/governor/eliot-maintenance/src/lib.rs:628-643`), so it could in
/// fact match `AutomationOff` alone. A label the decision's own content cannot
/// support is the misattribution this issue exists to remove, so the residual
/// is dropped rather than renamed.
///
/// `ASSUMPTION:` I12.24:40-55 names no separate "maintenance" variant, and no
/// field of the maintenance decision carries a Watchdog, Dreamer or Concilium
/// attribution — those three sources therefore stay unreachable from this
/// daemon rather than being mislabelled here. Reaching any of them needs the
/// maintenance trigger ORIGIN to travel with the decision, which is an
/// `eliot-maintenance` contract change this issue does not own; the honest
/// outcome here is the `Attempt` label above plus that stated ceiling, not a
/// refusal to classify a live observation.
pub fn maintenance_evidence_source(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> EvidenceSource {
    use eliot_maintenance::MaintenanceFamily;
    match decision.family {
        MaintenanceFamily::SecurityDependencyScan => EvidenceSource::SecurityIncident,
        MaintenanceFamily::DonorConformance => EvidenceSource::ConformanceDiagnosis,
        _ => EvidenceSource::Attempt,
    }
}

/// Projects one conformance-audit observation into the Self-Quality
/// conformance-diagnosis evidence bundle the improvement funnel takes
/// (issue #1867 W2/A1, I12.24:50).
///
/// # Why the Self-Quality contract and not a label
///
/// [`maintenance_evidence_source`] classifies the observation; this function
/// is what the classification MEANS. A conformance-audit occurrence is not a
/// maintenance occurrence with a different tag, so the evidence that enters
/// the funnel is the finding the conformance owner recorded: the routed owner,
/// the priority axis, the constraint refs and the invalidation set all come
/// from the decision's own closed fields, and the finding is assembled and
/// validated by `eliot_self_quality::conformance_evidence` through the
/// normative `validate_handoff` and then the funnel's own `sourced_evidence`.
/// Nothing here fabricates a cause: every symptom ref is projected as an
/// `unproven-symptom:{ref}` hypothesis, so a diagnosis never states a proven
/// cause it did not observe.
///
/// # Every ref is a decision field, never a literal
///
/// * `handoff_ref` is the Governor owner's own `trigger_id`;
/// * symptom and evidence refs are that same `trigger_id` and the decision's
///   own `scope_ref`, so two evaluations of the same occurrence converge on one
///   finding rather than minting a new one per cadence tick;
/// * the problem ref is the decision's own `family`;
/// * the constraint ref names the family's own evaluator, the same identity
///   `ReplayPlan::verifier_refs` binds;
/// * the invalidation set is the admitted fence ref
///   ([`admitted_fence_ref`]), so the finding is explicitly invalidated when
///   the authority epoch or resource generation it was observed under moves.
///
/// Each ref set is unique by construction, which `validate_handoff` requires
/// (`make_handoff` sorts but does not de-duplicate).
fn conformance_diagnosis_evidence(
    decision: &eliot_maintenance::AutomationTriggerDecision,
    trigger_problem_or_metric: &str,
    validity_scope: &str,
) -> Result<SourcedEvidence, ImprovementDispatchError> {
    use eliot_self_quality::{ConformanceDiagnosis, SelfQualityHandoffOwner};
    let finding = ConformanceDiagnosis {
        handoff_ref: format!("self-quality-handoff:{}", decision.trigger_id),
        // The routing table's own default owner for a conformance-dimension
        // finding with no counterevidence and no special family
        // (`routing.rs::route_owner`, rules 1-9 miss, rule 10 default), i.e.
        // the owner a real conformance finding reaches. `route_owner` itself is
        // not called here because it takes a `SelfQualityObservation` and this
        // daemon holds no frozen #820 observation snapshot; the same default is
        // named rather than re-derived.
        owner: SelfQualityHandoffOwner::DevelopmentDiagnosis675,
        priority: conformance_priority(decision),
        symptom_refs: vec![format!("maintenance-trigger:{}", decision.trigger_id)],
        problem_refs: vec![format!("maintenance-family:{}", decision.family)],
        evidence_refs: vec![
            format!("maintenance-trigger:{}", decision.trigger_id),
            format!("maintenance-scope:{}", decision.scope_ref),
        ],
        missing_evidence_refs: Vec::new(),
        applicability_refs: vec![format!("maintenance-scope:{}", decision.scope_ref)],
        constraint_refs: vec![format!("maintenance-evaluator:{}", decision.family)],
        invalidation_set: vec![validity_scope.to_owned()],
        trigger_problem_or_metric: trigger_problem_or_metric.to_owned(),
        validity_scope: validity_scope.to_owned(),
    };
    Ok(eliot_self_quality::sourced_evidence_from_conformance_diagnosis(&finding)?)
}

/// The priority axis this daemon assigns a conformance finding, DERIVED from
/// the Governor owner's own closed decision rather than spelled.
///
/// `ASSUMPTION:` the maintenance `AutomationDecision` names the urgency the
/// owner itself assigned: `Escalate` is documented as "Escalate to a Human or
/// recovery owner" (`eliot-maintenance/src/lib.rs:194`) and `Block` as
/// "Policy, route, budget or session requirements deny execution" (`:192`), so
/// those two map to `Urgent` and `High` and every remaining decision
/// (`Start`, `Suggest`, `Defer`, `SuppressDuplicate`, none of which hands the
/// occurrence to a Human or a recovery owner) maps to `Medium`. I12.24 does
/// not name a priority for conformance evidence, and priority is an independent
/// axis that never substitutes for status or severity
/// (`self_quality.rs:176-177`), so this derives the owner's escalation and
/// claims nothing about severity.
fn conformance_priority(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> eliot_self_quality::Priority {
    use eliot_maintenance::AutomationDecision;
    use eliot_self_quality::Priority;
    match decision.decision {
        AutomationDecision::Escalate => Priority::Urgent,
        AutomationDecision::Block => Priority::High,
        _ => Priority::Medium,
    }
}

/// The bound the maintenance (`G-19`) owner decides for this surface, read
/// through the existing maintenance admission path.
///
/// Three reads, in order, and none of them can fall back to a value this
/// module spells:
///
/// 1. the owner's own admission policy record, obtained from the live
///    `G-19` maintenance owner on the Governor composition;
/// 2. the owner's recorded bound for `IMPROVEMENT_SURFACE_NAME`, which must
///    exist (an absent bound is [`ImprovementBoundError::NoBoundForSurface`],
///    never a default);
/// 3. the `CandidateBoundPolicy` this daemon will actually enforce, whose
///    `max_active` and `min_value` are then compared back against the owner's
///    recorded values by [`resolve_candidate_surface_bound`] and whose
///    `governor_authority_ref` is the owner's own `external_owner_id`.
///
/// `policy_revision` is the owner's own bound-set revision
/// ([`eliot_maintenance::IMPROVEMENT_CANDIDATE_BOUNDS_REVISION`]), so rotating
/// the owner's decision also rotates the admission epoch `archive_cause_for`
/// compares against, which is what makes an entry admitted under a superseded
/// bound decision stale and archivable.
///
/// This adds no scheduler, root record, or table (I12.24:314): it is a read of
/// the existing G-19 admission policy record through the existing maintenance
/// owner.
pub fn maintenance_bound(
    policy: &ImprovementAdmissionPolicy,
) -> Result<CandidateBoundPolicy, ImprovementDispatchError> {
    let enforced = CandidateBoundPolicy {
        target_surface: IMPROVEMENT_SURFACE,
        // Read from the owner record, then checked back against it below. These
        // two reads are one value: `resolve_candidate_surface_bound` returns the
        // owner's bound only when the enforced bound equals it field by field,
        // so a mismatch is a refusal rather than a silent correction.
        max_active: usize::try_from(decided_bound(policy).max_active).map_err(|_| {
            ImprovementBoundError::InvalidBound("max_active is out of range for this surface")
        })?,
        min_value: decided_bound(policy).min_value,
        governor_authority_ref: policy.external_owner_id.trim().to_owned(),
        policy_revision: IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    };
    let surface = IMPROVEMENT_SURFACE_NAME;
    let decided = resolve_candidate_surface_bound(
        policy,
        surface,
        &ImprovementSurfaceBound {
            target_surface: surface,
            max_active: u32::try_from(enforced.max_active).map_err(|_| {
                ImprovementBoundError::InvalidBound("max_active is out of range for this surface")
            })?,
            min_value: enforced.min_value,
        },
    )?;
    Ok(CandidateBoundPolicy {
        target_surface: IMPROVEMENT_SURFACE,
        max_active: usize::try_from(decided.max_active).map_err(|_| {
            ImprovementBoundError::InvalidBound("max_active is out of range for this surface")
        })?,
        min_value: decided.min_value,
        governor_authority_ref: policy.external_owner_id.trim().to_owned(),
        policy_revision: IMPROVEMENT_CANDIDATE_BOUNDS_REVISION,
    })
}

/// The owner's recorded bound for this surface, or the refusal for having none.
///
/// Split out so `maintenance_bound` reads the owner's decision once and then
/// checks the value it will enforce against it. The `u32 → usize` widening is
/// total on every platform this daemon builds for, and the `try_from` keeps it
/// honest where it is not.
fn decided_bound(policy: &ImprovementAdmissionPolicy) -> ImprovementSurfaceBound {
    policy
        .candidate_bounds
        .iter()
        .copied()
        .find(|bound| bound.target_surface == IMPROVEMENT_SURFACE_NAME)
        .unwrap_or(ImprovementSurfaceBound {
            target_surface: IMPROVEMENT_SURFACE_NAME,
            // An absent bound is a refusal, so this value is never reached
            // with a live policy: it exists only to give `unwrap_or` a
            // well-typed arm, and `max_active: 0` is itself refused by
            // `resolve_candidate_surface_bound`'s shape check, so a policy
            // record that lost its bound entry cannot yield an enforced bound
            // through this path.
            max_active: 0,
            min_value: 0.0,
        })
}

/// The bound-admission operation reference for one real maintenance decision.
///
/// Derived from the decision's own stable identity, so a repeat of the same
/// observation is admitted under the same operation — which is what makes the
/// G-19 policy record for that operation stable across passes, and therefore
/// what makes the bound a decision about a recurring problem rather than about
/// one evaluation. It is a reference, not a scope: the operation the policy
/// binds is the admission operation, while the candidate's own
/// `validity_scope` remains the admitted fence (see [`admitted_fence_ref`]).
pub fn improvement_bound_operation(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> String {
    format!(
        "maintenance-improvement-admission:{}:{}",
        decision.family, decision.trigger_id
    )
}

/// The bound-admission idempotency key for one real maintenance decision.
///
/// The key is derived from the decision's own `trigger_id` and `scope_ref` —
/// the same two fields the candidate's evidence lineage is built from — so
/// two identical observations converge on one policy record and one admission
/// rather than minting a fresh pair per pass.
pub fn improvement_bound_idempotency_key(
    decision: &eliot_maintenance::AutomationTriggerDecision,
) -> String {
    format!(
        "maintenance-improvement-admission:{}@{}",
        decision.trigger_id, decision.scope_ref
    )
}

/// Result of the governed improvement admission over one real observation.
#[derive(Clone, Debug)]
pub struct GovernedImprovementAdmission {
    /// Outcome of the bound-enforced admission or lineage merge.
    pub report: AdmitReport,
    /// The bound that was enforced, as read from the owner's decision record.
    /// Carried so the durable record states WHICH bound admitted the candidate.
    pub bound: CandidateBoundPolicy,
    /// The live owner-issued permit the bound was checked against. Its digest
    /// is the owner-issued identity of that admission and travels into the
    /// durable record, so the persisted artifact names the admission it was
    /// admitted under rather than only that some admission happened.
    pub admission_digest: String,
    /// The surviving backlog entry exactly as
    /// [`BoundedBacklog::admit_reporting_pressure`] left it, when this
    /// admission deduplicated by evidence lineage; `None` when the candidate
    /// was admitted as a new active entry.
    ///
    /// This is the merge RESULT, not the merge event. `report.outcome` already
    /// states that a merge happened and names both candidates; this carries
    /// what the merge produced — the unioned evidence and source lineage, the
    /// `merged_from` absorbed-id list, the retained assessed value and owner,
    /// the retained admission authority, and the advanced candidate revision.
    /// Without it the commit path holds only the INCOMING candidate and the
    /// accumulated lineage a merge built is lost when the pass ends
    /// (I12.24:297: "Duplicates merge by evidence lineage").
    ///
    /// It is captured HERE, inside the only place that still holds the
    /// backlog: `BoundedBacklog` owns its entries privately and the commit
    /// function receives no backlog, so this is the one seam from which the
    /// post-merge entry is reachable. `None` is never reachable for a
    /// [`AdmitOutcome::Merged`] outcome — a merge whose surviving entry could
    /// not be read back is refused, not reported as an admission without one.
    pub merged_survivor: Option<TrackedCandidate>,
}

/// Admit one assembled improvement artifact into the bounded backlog through
/// the GOVERNED path (W1 + W3).
///
/// `governor` is the live owner handle, `policy` the maintenance (`G-19`)
/// decision record read from that composition's maintenance owner, and
/// `state_fence` the daemon's own admitted Kernel fence for this pass. The
/// permit is minted HERE, from a claim whose `authority_ref` is the policy's
/// own owner id, so the bound's owner and the permit's owner are the same
/// value by construction and cannot drift apart silently.
///
/// The chain, and what each step proves:
///
/// 1. [`maintenance_bound`] reads the owner's bound and checks the enforced
///    bound back against it (W1: the numbers are the owner's, not a literal).
/// 2. [`issue_learning_admission`] mints the permit under the live Governor's
///    admitting-state, authority-epoch and generation checks.
/// 3. [`verify_learning_admission`] re-binds that permit to the live owner
///    state and to the exact fence this pass observed, producing the
///    [`VerifiedLearningAdmission`] the backlog gates require. A
///    `VerifiedLearningAdmission` is constructible only here, so no caller can
///    present an admission it did not earn.
/// 4. [`BoundedBacklog::admit_reporting_pressure`] runs
///    [`CandidateBoundPolicy::validate_governed`], which compares the bound's
///    `governor_authority_ref` against the verified permit's `authority_ref`
///    (W1: the owner is checked against a live issuance, not against a
///    constant), and then enforces the bound, merging by evidence lineage or
///    relieving a full bound through the explicit summarized archive
///    transition (W3).
/// 5. [`merged_survivor_entry`] reads the surviving entry back out of the
///    backlog on the merge branch. This is the only seam that still holds the
///    backlog, so the post-merge state is carried out on
///    [`GovernedImprovementAdmission::merged_survivor`] rather than recomputed
///    later from a value the commit path does not hold.
///
/// The `ArchivedCandidate` receipts travel back in the returned
/// [`AdmitReport`] for the caller to make durable; nothing is dropped here.
/// This performs no promotion, no activation and no write of its own.
pub fn admit_improvement_artifact(
    governor: &eliot_governor::Governor,
    policy: &ImprovementAdmissionPolicy,
    backlog: &mut BoundedBacklog,
    artifact: &ImprovementArtifact,
    state_fence: &StateFence,
) -> Result<GovernedImprovementAdmission, ImprovementDispatchError> {
    let bound = maintenance_bound(policy)?;
    let claim = improvement_admission_claim(policy, state_fence);
    let permit = issue_learning_admission(governor, &claim)?;
    let verified = verify_learning_admission(governor, &permit, state_fence)?;
    let report = backlog
        .admit_reporting_pressure(
            artifact.candidate.clone(),
            IMPROVEMENT_CANDIDED_VALUE,
            Some(IMPROVEMENT_OWNER.to_owned()),
            &verified,
        )
        .map_err(|error| ImprovementDispatchError::Backlog(error.to_string()))?;
    let merged_survivor = merged_survivor_entry(&report, backlog)?;
    Ok(GovernedImprovementAdmission {
        report,
        bound,
        admission_digest: permit.digest().to_owned(),
        merged_survivor,
    })
}

/// Reads the SURVIVING backlog entry out of the registry on the merge branch
/// (W3, I12.24:297).
///
/// [`AdmitOutcome::Merged`] states that an incoming candidate deduplicated into
/// an existing one and names both ids, but the state the merge BUILT — the
/// unioned `evidence_refs`/`source_trace_refs`, the `merged_from` absorbed-id
/// list, the retained assessed value and owner, the retained admission
/// authority and the advanced candidate revision, all written by
/// [`BoundedBacklog`]'s own merge transition — lives on the entry, and the
/// entry is the only place it exists. So it is read here, while the backlog is
/// still in hand, and travels back on
/// [`GovernedImprovementAdmission::merged_survivor`] for the commit path to
/// make durable.
///
/// `None` means the outcome was [`AdmitOutcome::Admitted`]: nothing merged, so
/// there is no surviving entry to record. The opposite disagreement — a merge
/// whose surviving entry is not retrievable from the registry that just
/// performed it — is a REFUSAL, not a `None`. Returning `None` there would
/// drop the merge result silently and commit only the event, which is exactly
/// the loss this read closes.
fn merged_survivor_entry(
    report: &AdmitReport,
    backlog: &BoundedBacklog,
) -> Result<Option<TrackedCandidate>, ImprovementDispatchError> {
    let AdmitOutcome::Merged {
        surviving_candidate_id,
        absorbed_candidate_id,
    } = &report.outcome
    else {
        return Ok(None);
    };
    let survivor = backlog.entry_for(surviving_candidate_id).ok_or_else(|| {
        ImprovementDispatchError::Backlog(format!(
            "candidate {absorbed_candidate_id} was merged into {surviving_candidate_id}, \
             but the merged entry is not an active entry of the registry that performed the merge"
        ))
    })?;
    Ok(Some(survivor.clone()))
}

/// The closed learning-admission claim this daemon admits its own improvement
/// candidates under.
///
/// Every field is a real value this daemon or its owner holds, and the two
/// that carry authority are the OWNER's: `authority_ref` is the maintenance
/// admission owner's own id, which is what
/// [`CandidateBoundPolicy::validate_governed`] compares the bound's
/// `governor_authority_ref` against, and `scope_ref` is the decision's own
/// scope. `evaluator_ref` and `rollback_ref` name the maintenance evaluation
/// and rollback owners the same policy record declares, so the five revalidated
/// values a cross-task admission re-checks are this campaign's real ones
/// rather than placeholders.
///
/// The claim binds the candidate subject (`candidate_id`) so the resulting
/// permit authorizes at most this exact candidate.
fn improvement_admission_claim(
    policy: &ImprovementAdmissionPolicy,
    state_fence: &StateFence,
) -> LearningAdmissionClaim {
    LearningAdmissionClaim {
        schema_version: eliot_governor::LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: IMPROVEMENT_CAMPAIGN.to_owned(),
        target_task_id: format!("maintenance-improvement:{SERVICE_NAME}"),
        fence: state_fence.clone(),
        overlay_id: None,
        candidate_id: None,
        scope_ref: policy.operation_ref.clone(),
        authority_ref: policy.external_owner_id.clone(),
        retention_ref: policy.idempotency_key.clone(),
        evaluator_ref: IMPROVEMENT_EVALUATOR.to_owned(),
        rollback_ref: policy.rollback_owner_id.clone(),
    }
}

/// A revalidation claim for carrying one campaign's admitted learning into a
/// different target task (W5, I12.24:295).
///
/// This is the OWNER's revalidation, expressed as a claim the Governor admits
/// or refuses. It is not proof: the distinctness rule, the live epoch and
/// generation checks, and the per-field comparison of the revalidated values
/// against the minted permit all happen inside
/// [`issue_cross_task_admission`](eliot_governor::LearningAdmissionPermit::issue_cross_task_admission)
/// and
/// [`verify_cross_task_admission`](eliot_governor::LearningAdmissionPermit::verify_cross_task_admission).
#[derive(Clone, Debug)]
pub struct CrossTaskCarryoverRequest {
    /// The distinct target task the learning is being carried to. MUST differ
    /// from the local admission's target task; the Governor refuses otherwise
    /// with `TargetNotForeign`.
    pub target_task_id: String,
    /// Revalidated scope for the target task.
    pub scope_ref: String,
    /// Revalidated decision authority for the target task.
    pub authority_ref: String,
    /// Revalidated retention material for the target task.
    pub retention_ref: String,
    /// Revalidated evaluator for the target task.
    pub evaluator_ref: String,
    /// Revalidated rollback path for the target task.
    pub rollback_ref: String,
}

/// Owner-issued cross-task admission, verified against live owner state.
///
/// `carryover` is the [`CrossTaskCarryover`] a consumer binds to; its fields
/// are private, so this value can exist only because the Governor produced both
/// halves. `record` is the verified record as the Governor verifier returned
/// it, not the presented one.
pub struct VerifiedCrossTaskCarryover<'a> {
    /// The distinct cross-task admission a consumer may bind to.
    pub carryover: CrossTaskCarryover<'a>,
    /// The owner-verified record, exactly as re-verification returned it.
    pub record: &'a CrossTaskAdmissionRecord,
}

/// The distinct, owner-issued cross-task admission the Governor minted.
///
/// Both halves are owner-issued and neither is constructible outside the
/// Governor: `permit` is the SECOND [`LearningAdmissionPermit`] for the foreign
/// target task, and `record` is the owner-issued
/// [`CrossTaskAdmissionRecord`] whose `admission_id` is a canonical digest over
/// both issuance digests. They are returned together so a caller can RETAIN
/// them and later present them to
/// [`verify_cross_task_carryover`], which needs them to outlive this call.
pub struct IssuedCrossTaskAdmission {
    /// The distinct cross-task admission for the foreign target task.
    pub permit: LearningAdmissionPermit,
    /// The owner-issued record binding the local and cross-task admissions.
    pub record: CrossTaskAdmissionRecord,
}

/// Issue one distinct cross-task admission under a live Governor permit (W5).
///
/// This is the issuance half of the production path I12.24:295 names: "Cross-
/// task carryover requires a new governed admission that revalidates scope,
/// authority, retention, evaluator, and rollback." It performs
/// [`issue_cross_task_admission`](eliot_governor::LearningAdmissionPermit::issue_cross_task_admission),
/// which mints the SECOND admission for the foreign target task through the
/// same live owner checks as any other admission — no bypass, no revalidation
/// mode on the owner — and returns the owner-issued record. The revalidation
/// values are a claim, never proof: unusable text, a non-admitting Governor, a
/// stale epoch or generation, a re-spelled subject or campaign, an admission
/// that is not distinct, or a revalidation that names the local task are each
/// refused with their typed [`CrossTaskAdmissionError`] before any permit
/// exists.
///
/// The returned halves are retained by the caller so they can be presented to
/// [`verify_cross_task_carryover`] — the verification half, which re-verifies
/// BOTH permits against live owner state and re-checks the record field by
/// field. Issuance alone authorizes nothing.
///
/// The Governor-owned record is the only cross-task representation used here.
/// The weaker string-typed `eliot_learning_contracts::activation::CrossTaskAdmission`
/// that `candidate_bounds.rs` names as the shape being replaced is not
/// touched, and no second cross-task scheme is introduced.
pub fn issue_cross_task_carryover(
    governor: &eliot_governor::Governor,
    local: &LearningAdmissionPermit,
    revalidation: &CrossTaskCarryoverRequest,
    cross_task_fence: &StateFence,
) -> Result<IssuedCrossTaskAdmission, ImprovementDispatchError> {
    // The claim is the owner's revalidation of the five values plus the same
    // source campaign and the same influence subject, which is what the
    // distinctness rule requires a real carryover to hold.
    let claim = LearningAdmissionClaim {
        schema_version: eliot_governor::LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: local.source_campaign_id().to_owned(),
        target_task_id: revalidation.target_task_id.clone(),
        fence: cross_task_fence.clone(),
        overlay_id: local.overlay_id().map(str::to_owned),
        candidate_id: local.candidate_id().map(str::to_owned),
        scope_ref: revalidation.scope_ref.clone(),
        authority_ref: revalidation.authority_ref.clone(),
        retention_ref: revalidation.retention_ref.clone(),
        evaluator_ref: revalidation.evaluator_ref.clone(),
        rollback_ref: revalidation.rollback_ref.clone(),
    };
    let (permit, record) = local.issue_cross_task_admission(governor, &claim)?;
    Ok(IssuedCrossTaskAdmission { permit, record })
}

/// Verify an issued cross-task admission against live owner state and build
/// the [`CrossTaskCarryover`] a consumer binds to (W5).
///
/// This is the verification half, and it is where the five revalidated values
/// are compared as CONTENT against the owner-issued permit rather than shape-
/// checked. It performs:
///
/// 1. [`CrossTaskCarryover::verify`], which re-verifies BOTH permits against
///    live owner state through the same
///    [`verify_learning_admission`] checks — the LOCAL one against
///    `local_fence` (this pass's own fence) and the cross-task one against
///    `cross_task_fence` (the foreign task's) — rebinding each to the live
///    owner epoch/generation, recomputing each digest, and requiring the
///    Governor to be admitting. A rotated epoch or a drifted fence refuses
///    here, before any record is trusted.
/// 2. the record rules against the two already-verified handles: shape,
///    distinctness (a different ticket digest AND a different target task),
///    `admission_id` RECOMPUTED from the two verified issuance digests, the
///    record's two digests equal to the two permits' digests, and the five
///    revalidated values (`scope_ref`, `authority_ref`, `retention_ref`,
///    `evaluator_ref`, `rollback_ref`) equal — FIELD BY FIELD, with the
///    disagreeing field named in `RevalidationMismatch` — to the values the
///    cross-task permit binds.
///
/// That field-by-field step is the guarantee, not a shape check: a well-formed
/// record that re-spells any of the five is refused, and a revalidation that
/// merely copies the local admission is refused structurally
/// (`NotDistinctAdmission`).
///
/// The two handles arrive as `&'a VerifiedLearningAdmission<'a>` because
/// obtaining one already required a prior `verify_learning_admission` against
/// the live Governor; this call re-confirms that against live state and then
/// re-checks the record, so a stale anchor cannot buy a carryover. The
/// returned [`VerifiedCrossTaskCarryover`] holds only Governor-produced values:
/// the `CrossTaskCarryover`'s fields are private, so it can exist only because
/// it was built here from two verified permits and a re-checked record.
pub fn verify_cross_task_carryover<'a>(
    governor: &eliot_governor::Governor,
    local_verified: &'a VerifiedLearningAdmission<'a>,
    cross_task_verified: &'a VerifiedLearningAdmission<'a>,
    issued: &'a IssuedCrossTaskAdmission,
    local_fence: &StateFence,
    cross_task_fence: &StateFence,
) -> Result<VerifiedCrossTaskCarryover<'a>, ImprovementDispatchError> {
    // `CrossTaskCarryover::verify` re-verifies BOTH permits against live owner
    // state internally (each against the fence of its own task) and re-checks
    // the record field by field, so the two `VerifiedLearningAdmission` handles
    // are the anchor the record is checked against. Their existence already
    // required a prior `verify_learning_admission` against the live Governor,
    // and this call re-confirms it — a stale anchor cannot be re-used here.
    let carryover = CrossTaskCarryover::verify(
        governor,
        local_verified,
        cross_task_verified,
        &issued.record,
        local_fence,
        cross_task_fence,
    )?;
    Ok(VerifiedCrossTaskCarryover {
        carryover,
        record: carryover.record(),
    })
}

/// Renders the daemon's own admitted fence as the candidate's stable
/// `validity_scope` reference.
///
/// The improvement candidate's admitted boundary is the real Kernel fence this
/// dispatch observed the maintenance decision under, not a string that only
/// claims to be one: both components the maintenance owner treats as
/// distinct are carried verbatim — the lineage-aware authority epoch (the
/// exact `(lineage_id, sequence)` tuple, per
/// `epoch_identity.rs::EpochId::is_same_authority`) and the monotonic resource
/// generation. A candidate is therefore only ever read back as valid under the
/// same admitted authority and generation that produced it.
fn admitted_fence_ref(state_fence: &StateFence) -> Result<String, ImprovementDispatchError> {
    state_fence
        .validate()
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    Ok(format!(
        "admitted-fence:{}/{}@{}",
        state_fence.authority_epoch.lineage_id.as_str(),
        state_fence.authority_epoch.sequence,
        state_fence.resource_generation.value()
    ))
}

/// Derives the admitted commit ingress for one durable improvement record.
///
/// Mirrors `experience_runtime.rs::derive_commit_ingress`: the request
/// metadata is derived from the daemon's own admitted fence and the
/// idempotency key is the owner-derived record key, so an identical
/// observation replays convergently under the same key. `record_key` names
/// which record this ingress is for, so the candidate's own commit and each
/// archive receipt's commit are distinct, independently idempotent operations
/// rather than one key reused across two different documents.
fn improvement_commit_identity(
    record_key: &str,
    state_fence: &StateFence,
) -> Result<RequestIdentity, ImprovementDispatchError> {
    let now = super::unix_ms_i64();
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(format!("{SERVICE_NAME}:{record_key}"))
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new(SERVICE_NAME)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        source_id: eliot_contracts::SourceId::new(SERVICE_NAME)
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
        deadline_unix_ms: super::unix_ms().saturating_add(IMPROVEMENT_COMMIT_DEADLINE_MS),
        cancellation_id: format!("{record_key}:cancel"),
    })
}

/// Commits one assembled improvement artifact durably through the existing
/// Governor/Kernel `RecordLearningRecord` named mutation, together with the
/// governed admission that bounded it and every archive receipt that
/// admission produced.
///
/// The record kind is the closed
/// [`eliot_store_api::LearningRecordKind::Candidate`]; the record document is
/// the canonical JSON of the candidate + brief + owner decision + the bound
/// that admitted it + the owner-issued admission digest, and the presented
/// `record_digest` is that exact canonical bytes, so the digest IS the
/// immutable revision identity. Durability goes exclusively through
/// [`DaemonComposition::commit_learning_record`]; no second write path and no
/// store client is opened here.
///
/// `admitted.bound` and `admitted.admission_digest` travel INTO the record, so
/// the durable artifact names the owner-decided bound it was admitted under and
/// the owner-issued admission that enforced it. Without those two fields a
/// stored record would assert only that some admission happened, which is the
/// W1 guarantee this path exists to make durable.
///
/// `admitted.report.archived` is committed as ONE additional `Candidate`
/// record per receipt, after the candidate's own commit. Each such record
/// carries that receipt's `cause`, evidence-derived `summary`, merged
/// provenance, canonical evidence lineage, archived revision, and the
/// [`ImprovementLifecycle`] the archive transition actually reached — so an
/// archived candidate's disposition is a durable, reviewable fact rather than
/// a process-local receipt that disappears with the backlog (W3; I12.24:291
/// "Silence is not a disposition, because it hides lost learning").
///
/// `admitted.merged_survivor` is committed, between the candidate's own commit
/// and the archive receipts, as ONE additional `Candidate` record whenever the
/// admission deduplicated by evidence lineage. Without it the daemon durably
/// records THAT a merge happened but never WHAT was merged: the record above
/// carries the INCOMING candidate, while the surviving entry — enriched by the
/// merge with the unioned lineage and the absorbed-id list — exists only in the
/// registry, so the next pass rebuilds from the incoming candidate and the
/// unioned lineage is gone. [`commit_lineage_merge_receipt`] states the shape;
/// `improvement_dedup_read::restored_registry` reads it back.
///
/// Receipt commits are sequenced after the candidate commit and are
/// individually idempotent under their own key, so a receipt committed on one
/// pass converges on a later pass instead of duplicating. A refused receipt
/// commit is a typed `Commit` error carrying the archive that could not be made
/// durable, and the receipts committed before it stay committed: this is a
/// partial commit, and it is visible as such rather than hidden.
pub async fn commit_improvement_artifact(
    composition: &mut DaemonComposition,
    artifact: &ImprovementArtifact,
    admitted: &GovernedImprovementAdmission,
    state_fence: &StateFence,
) -> Result<(eliot_store_api::WriteReceipt, bool), ImprovementDispatchError> {
    let record = serde_json::json!({
        "candidate": artifact.candidate,
        "brief": artifact.brief,
        "owner_decision": artifact.decision,
        "enforced_bound": admitted.bound,
        "governed_admission_digest": admitted.admission_digest,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(IMPROVEMENT_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    let record_key = format!("improvement-candidate:{}", artifact.candidate.candidate_id);
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        record_key.clone(),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        record_key.clone(),
    ));
    let identity = improvement_commit_identity(&record_key, state_fence)?;
    let scope = ScopeId::new(IMPROVEMENT_SCOPE)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    // The durable commit is the whole point of this path: any refusal is a
    // typed diagnostic, never a silent drop.
    let (receipt, effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope.clone(),
            // Proof refs: the candidate's own evidence lineage, verbatim.
            artifact.candidate.evidence_refs.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| ImprovementDispatchError::Commit(error.to_string()))?;
    // The merge result, before the archive receipts: the surviving entry is
    // what the NEXT pass rebuilds its registry from, so it is made durable
    // before any relief disposition is.
    match (&admitted.report.outcome, admitted.merged_survivor.as_ref()) {
        (AdmitOutcome::Admitted { .. }, None) => {}
        (
            AdmitOutcome::Merged {
                absorbed_candidate_id,
                ..
            },
            Some(survivor),
        ) => {
            commit_lineage_merge_receipt(
                composition,
                survivor,
                absorbed_candidate_id,
                &scope,
                state_fence,
            )
            .await?;
        }
        (outcome, _) => {
            // `admit_improvement_artifact` refuses to produce this pair, so it
            // is unreachable in practice; committing the candidate and silently
            // skipping a merge result it cannot describe is not an option, so
            // the disagreement is a typed refusal.
            return Err(ImprovementDispatchError::Backlog(format!(
                "the admission outcome {outcome:?} does not agree with the merge state this commit must record"
            )));
        }
    }
    for archived in &admitted.report.archived {
        commit_archive_receipt(composition, archived, &scope, state_fence).await?;
    }
    Ok((receipt, effective))
}

/// Commits the SURVIVING entry of one evidence-lineage merge as a durable
/// learning record (W3, I12.24:297).
///
/// # What this record is for, and what a record without it would be
///
/// The candidate's own record commits the INCOMING candidate. When the
/// admission deduplicated by evidence lineage, the state that makes the
/// deduplication durable is the SURVIVOR: the entry the merge unioned the
/// incoming lineage into, with its absorbed-id bookkeeping, its retained
/// assessed value, owner and admission authority, and its advanced candidate
/// revision. Committing only the event would leave the daemon asserting that a
/// merge happened while the next pass rebuilt its registry from the pre-merge
/// candidate row — so the unioned lineage a merge produced is lost, and the
/// merge is indistinguishable from two independent candidates that merely
/// co-exist. I12.24:297 says "Duplicates merge by evidence lineage", so the
/// lineage a merge accumulated is the merge's own result and it is committed
/// here.
///
/// # The committed document
///
/// `{merged_survivor, absorbed_candidate_id}` where `merged_survivor` is the
/// surviving [`TrackedCandidate`] verbatim. It is committed verbatim rather
/// than projected onto a narrower shape because it IS the registry entry:
/// `ImprovementCandidate`, the unioned `evidence_refs` and
/// `source_trace_refs`, the `merged_from` absorbed-id list, the retained
/// `value`/`owner`/`admitted_under_authority`, the `lineage_digest` the merge
/// recomputed over the union, and the advanced `revision`. A projection would
/// have to restate which of those the merge produced, and every field omitted
/// would be a field a merge could accumulate and lose.
///
/// No extra digest is added: the record's own `lineage_digest` is the digest of
/// the union, and `admitted_under_authority` is the Governor authority the
/// merge was admitted under. The owner-issued admission digest for the same
/// admission is already durable on the candidate's own record.
///
/// `Candidate` is the same closed kind the candidate and the archive receipts
/// use and no new kind is added. The handle and idempotency key are derived
/// from the surviving entry's OWN identity — its candidate id plus the revision
/// the merge advanced it to — so re-observing the same merge converges on one
/// record instead of appending a duplicate, and a later merge of the same
/// surviving candidate is a distinct, additional record rather than an
/// overwrite of the earlier accumulated state.
///
/// A refused commit is a typed `Commit` error naming the surviving candidate
/// and the one it absorbed, and the candidate's own commit stays committed:
/// this is the same partial-commit behaviour the archive receipts already
/// document, not a rollback.
async fn commit_lineage_merge_receipt(
    composition: &mut DaemonComposition,
    survivor: &TrackedCandidate,
    absorbed_candidate_id: &str,
    scope: &ScopeId,
    state_fence: &StateFence,
) -> Result<eliot_store_api::WriteReceipt, ImprovementDispatchError> {
    let record = serde_json::json!({
        "merged_survivor": survivor,
        "absorbed_candidate_id": absorbed_candidate_id,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(IMPROVEMENT_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    let record_key = lineage_merge_record_key(survivor);
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        record_key.clone(),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        record_key.clone(),
    ));
    let identity = improvement_commit_identity(&record_key, state_fence)?;
    // Proof refs: the SURVIVING entry's own evidence refs, which are the union
    // the merge produced, so the receipt cites the accumulated lineage rather
    // than the incoming candidate's.
    let (receipt, _effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope.clone(),
            survivor.candidate.evidence_refs.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| {
            ImprovementDispatchError::Commit(format!(
                "the merge of {} into surviving candidate {} at revision {} could not be made durable: {error}",
                absorbed_candidate_id, survivor.candidate.candidate_id, survivor.candidate.revision
            ))
        })?;
    Ok(receipt)
}

/// The closed store handle and idempotency key of one lineage-merge receipt.
///
/// Derived from the surviving entry's own `candidate_id` and the
/// `candidate.revision` the merge advanced it to, both of which the merge
/// transition produced, so the key is a function of the merge rather than of
/// the pass that observed it. An identical replay of the same merge converges
/// on one record instead of appending a duplicate accumulated state.
fn lineage_merge_record_key(survivor: &TrackedCandidate) -> String {
    format!(
        "improvement-merge:{}@{}",
        survivor.candidate.candidate_id, survivor.candidate.revision
    )
}

/// Commits one [`ArchivedCandidate`] receipt as a durable learning record.
///
/// `Candidate` is the closed kind that fits and no new kind is added: this is
/// a record about a candidate, and the closed set already covers candidates
/// with the same "recording never performs promotion" property. The handle and
/// idempotency key are the receipt's OWN identity — candidate id plus the
/// archived revision the transition produced — so the same archive of the same
/// candidate converges under one key across passes and a candidate archived
/// again at a later revision is a distinct, additional receipt rather than an
/// overwrite of the earlier disposition.
async fn commit_archive_receipt(
    composition: &mut DaemonComposition,
    archived: &ArchivedCandidate,
    scope: &ScopeId,
    state_fence: &StateFence,
) -> Result<eliot_store_api::WriteReceipt, ImprovementDispatchError> {
    let record = serde_json::json!({
        "archived_candidate": archived,
        "disposition": archived.archived_lifecycle,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(IMPROVEMENT_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    let record_key = archive_record_key(archived);
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        record_key.clone(),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        record_key.clone(),
    ));
    let identity = improvement_commit_identity(&record_key, state_fence)?;
    // Proof refs: the archived candidate's own canonical evidence lineage, so
    // the receipt cites exactly the evidence whose retention review produced
    // it.
    let (receipt, _effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope.clone(),
            archived.evidence_lineage.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| {
            ImprovementDispatchError::Commit(format!(
                "archived candidate {} at revision {} could not be made durable: {error}",
                archived.candidate_id, archived.archived_revision
            ))
        })?;
    Ok(receipt)
}

/// The closed store handle and idempotency key of one archive receipt.
///
/// Derived from the receipt's own `candidate_id` and `archived_revision`, both
/// of which the archive transition produced, so the key is a function of the
/// transition rather than of the pass that observed it. An identical replay of
/// the same transition therefore converges on one record instead of appending a
/// duplicate disposition.
fn archive_record_key(archived: &ArchivedCandidate) -> String {
    format!(
        "improvement-archive:{}@{}",
        archived.candidate_id, archived.archived_revision
    )
}
