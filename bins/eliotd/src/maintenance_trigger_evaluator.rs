//! Production call site for the Governor-owned maintenance trigger
//! evaluator (I14.22, issue #1688).
//!
//! The evaluator itself is **not** defined here.
//! [`eliot_maintenance::MaintenanceController::evaluate_trigger`] already
//! implements the whole deterministic decision surface, and the Governor
//! already composes exactly one instance of it as
//! [`eliot_governor::GovernorOwners::maintenance`]. This module is the
//! `eliotd` seam that reaches that one owner from the daemon's real durable
//! runtime path and turns the typed [`AutomationTriggerDecision`] into an
//! inspectable record.
//!
//! Three properties are load-bearing here:
//!
//! * **Single producer.** The decision comes from the composed Governor owner
//!   through `owners().maintenance`. This module never constructs a
//!   [`MaintenanceController`], never re-implements a mode, a family or a
//!   decision vocabulary, and never adds a queue, a scheduler, a timer thread
//!   or a background maintenance loop. Evaluation is a pure read of the
//!   owner's decision over an input this daemon observed.
//! * **No fabricated authority.** Every
//!   [`MaintenanceTriggerInput`] field is filled from something this daemon
//!   genuinely observed — the live admitted fence, the validated Kernel-issued
//!   owner session, the activation flight state, the caller-carried evidence
//!   identities — or is deliberately held at its fail-closed value because the
//!   owning authority for it does not exist yet. Those held fields are named in
//!   [`UNRESOLVED_AUTHORITIES`] and are the reason several decision values are
//!   unreachable today; they are never guessed.
//! * **Typed end to end.** A rejected evaluation propagates the Governor's own
//!   [`MaintenanceError`] through [`DaemonError::Maintenance`]; it is never
//!   stringified into a lifecycle or transport message.

//! # The observed-origin vocabulary and what is still missing from it
//!
//! [`MaintenanceTriggerOrigin`] names the five durable occurrences this daemon
//! can genuinely observe, and each one's `maintenance_trigger` mapping names
//! the I14.22 origin the Governor evaluator decides with. The map is exhaustive
//! over the origin enum, so extending either enum is a compile-time event
//! rather than a silent mislabel.
//!
//! Five origins exist; four have a production site that constructs them, and the
//! fifth — [`MaintenanceTriggerOrigin::DreamerSuggestion`] — does not yet. That
//! is stated here rather than left for a reader to discover from a match arm:
//! the origin exists because [`MaintenanceTrigger::Dreamer`] is a real I14.22
//! member that the improvement funnel already reads, and until this arm no
//! origin could produce it. The map is now exhaustive over the origins the
//! documents place there; what is absent is the PRODUCER — the durable record
//! the Dreamer would publish and a trigger site to read it — and that gap is
//! measured and named on that method.
//!
//! No origin here is a substitute for another. In particular the store-health
//! poll is [`MaintenanceTriggerOrigin::AdmittedObservation`], a problem/signal
//! recipe, and it is NOT a Dreamer suggestion and NOT a Watchdog suggestion;
//! wiring it into the improvement intake would produce a mislabelled candidate,
//! so it stays out of that path.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_contracts::{OperationId, canonical_json_bytes, sha256_hex};
use eliot_governor::{CompositionError, KernelPortError, KernelTransitionPort};
use eliot_maintenance::{
    AutomationTriggerDecision, CONTRACT_NAME, CONTRACT_VERSION, MaintenanceBrokerEvidence,
    MaintenanceBudgetEvidence, MaintenanceError, MaintenanceFamily, MaintenancePolicyEvidence,
    MaintenanceResultObligation, MaintenanceRouteEvidence, MaintenanceSafetyEvidence,
    MaintenanceScheduleEvidence, MaintenanceTrigger, MaintenanceTriggerInput,
    maintenance_observation_record,
};
use eliot_protocol::{
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID,
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION, MaintenanceTriggerClaim,
    MaintenanceTriggerDecisionReceipt, MaintenanceTriggerRecord, ProtocolError,
};
use eliot_store_api::{StoreError, WriteReceiptStatus};
use thiserror::Error;

use super::DaemonComposition;
use super::DaemonError;
use super::DaemonKernelClient;
use super::notification_state_emit::{
    MaintenanceNotificationEvidence, NotificationEmitError, NotificationStateEmit,
    emit_blocked_automation_notification,
};

/// The maintenance families whose policy owner this daemon cannot yet resolve,
/// as one constant a reader can inspect instead of a scattered `false`.
///
/// Every field held below is held **fail-closed**, never permissively:
///
/// | Held field | Value | Why it is not `true` | Owning issue |
/// |---|---|---|---|
/// | `mode` | [`Off`](eliot_maintenance::MaintenanceAutomationMode::Off) | No Human maintenance-policy owner exists in `eliotd`; `eliot-config` owns only a one-shot *first-run* decision that the daemon runtime never reads. `Off` is I14.22's own "no automatic job or proactive recommendation" value, so an unresolved policy denies automation instead of defaulting to permissive. Since #1693 the catalog in [`maintenance_family_catalog`] is the single place that states the selected mode per registered family, and this seam reads it from there rather than repeating the literal. | #1692, #1693 |
/// | `scheduled_window` | `false` | `eliotd` holds no Host wake / Task Scheduler occurrence. Inventing a window is exactly the "locally invented occurrence" #1692 forbids. | #1692 |
/// | `route_available` | `false` | No maintenance route/credential owner publishes a service-safe route to this daemon. | #1692 |
/// | `budget_available` | `false` | No maintenance budget/quota owner publishes one. | #1692 |
/// | `user_session_required` | `false` | The `interactive_maintenance` policy that would set it does not exist here. Held `false` grants nothing: `route_available` is already `false`, so no route can be selected. | #1692 |
/// | `user_session_available` | `false` | The authenticated daemon transport is not User Broker registration/lease evidence, and Kernel exposes no current broker-status query to this caller. | #1692, #23 |
/// | `explicit_request` | `false` | `eliotd` exposes no authenticated Human UI/CLI maintenance-request ingress; an untrusted flag is not a request. | #1692 |
/// | `safety_required` | `false` | No owner publishes a verified mandatory safety/recovery obligation to this daemon, and the flag must never be asserted to bypass authentication. | #1692 |
/// | `active_job_id` | `None` | [`MaintenanceController`] exposes no probe for an existing active job, so duplicate suppression cannot be fed. | #1694 |
/// | `expires_at_ms` | `None` | No expiry policy is published to this daemon. | #1694 |
///
/// `user_session_available` remains false until the Kernel's User Broker
/// owner exposes a current authenticated registration/lease observation.
pub const UNRESOLVED_AUTHORITIES: &str = "mode,scheduled_window,route_available,budget_available,user_session_required,user_session_available,explicit_request,safety_required,active_job_id,expires_at_ms";

/// The durable maintenance trigger origins this daemon can genuinely observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerOrigin {
    /// Governor owner recovery finished; the freshly rebuilt owners must be
    /// reconciled for pending maintenance at the current fence.
    StartupReconciliation,
    /// The declared startup binding ledger completed, so the obligations that
    /// only exist once the daemon is whole became visible.
    ColdStartCompletion,
    /// An admitted store-health observation arrived on the health heartbeat.
    AdmittedObservation,
    /// The activation poll observed no in-flight admitted activation, so no
    /// conflicting interactive work owns the scope.
    IdleTransition,
    /// The Dreamer published one of its own maintenance suggestions and this
    /// daemon read that published record through the owner that publishes it
    /// (issue #1867 W2, I12.24:54, I9.2:11).
    ///
    /// This is a separate origin rather than a reuse of
    /// [`Self::AdmittedObservation`] because the two occurrences are
    /// different kinds of fact and must never share a label. An admitted
    /// observation is a problem/signal occurrence this daemon recorded about
    /// ITSELF; a Dreamer suggestion is a proposal some other owner authored.
    /// Routing the Dreamer suggestion through the admitted-observation origin
    /// would name it a Watchdog/Doctor problem RECIPE — the exact
    /// name-only conflation this enum exists to keep apart — so it gets its
    /// own member and its own [`MaintenanceTrigger::Dreamer`] arm below.
    DreamerSuggestion,
}

impl MaintenanceTriggerOrigin {
    /// Stable wire name. Part of the deterministic trigger identity, so it is
    /// fixed text rather than anything derived from the clock or a counter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartupReconciliation => "STARTUP_RECONCILIATION",
            Self::ColdStartCompletion => "COLD_START_COMPLETION",
            Self::AdmittedObservation => "ADMITTED_OBSERVATION",
            Self::IdleTransition => "IDLE_TRANSITION",
            Self::DreamerSuggestion => "DREAMER_SUGGESTION",
        }
    }

    /// I14.22's job-origin classification for this trigger.
    ///
    /// `StartupReconciliation` and `IdleTransition` are approved
    /// policy-driven occurrences ("Human-approved idle/scheduled policy"),
    /// `ColdStartCompletion` is a first-run/onboarding occurrence,
    /// `AdmittedObservation` is an admitted problem/signal occurrence
    /// (Watchdog/Doctor problem recipe), and `DreamerSuggestion` is an
    /// occurrence the Dreamer itself proposed. The I14.22 origin enum has no
    /// finer-grained member than these five, so the mapping is exhaustive
    /// over this daemon's observed-origin vocabulary.
    ///
    /// # `DreamerSuggestion` makes [`MaintenanceTrigger::Dreamer`] producible
    ///
    /// [`MaintenanceTrigger::Dreamer`] is documented "Accepted Dreamer
    /// maintenance plan candidate"
    /// (`crates/governor/eliot-maintenance/src/lib.rs:194-195`) and the
    /// improvement funnel already reads it
    /// (`bins/eliotd/src/improvement_intake_dispatch.rs:1888`,
    /// `maintenance_trigger_evidence_source`), but before this arm NO origin
    /// mapped to it: this match named only `Policy`, `Onboarding` and
    /// `WatchdogProblem`, so `git grep MaintenanceTrigger::Dreamer` returned
    /// exactly two non-declaration hits — the classifier and
    /// `maintenance_family_catalog.rs:924`'s origin-name listing — and the
    /// member was UNPRODUCIBLE from any observation. This arm is the contract
    /// half of the fix: a trigger site that genuinely reads a published
    /// Dreamer suggestion now produces a decision whose own `trigger` field
    /// says so, and the funnel labels it `EvidenceSource::Dreamer` rather
    /// than mislabelling it a Watchdog occurrence.
    ///
    /// # The PRODUCER is still absent, and it is named, not assumed
    ///
    /// This arm makes the origin constructible; it does not make anything
    /// construct it, and nothing constructs it on this base. Measured, so the
    /// next owner does not re-derive it:
    ///
    /// * the owner that produces the record this origin names is
    ///   `eliot_dreamer_maintenance_plan::propose_maintenance_plan`
    ///   (`crates/smart/eliot-dreamer-maintenance-plan/src/lib.rs:3256`), whose
    ///   `MaintenancePlanCandidate` (`:1004`) is the typed candidate
    ///   [`MaintenanceTrigger::Dreamer`] documents. It is a pure
    ///   candidate-only zero-effect cell — its own header states it contains
    ///   "no persistence, identifier allocation, ... authority, effect, or
    ///   terminal-completion calls by construction" — and it has ZERO
    ///   production call sites anywhere in the workspace.
    /// * its Governor-owned plan inputs (`MaintenanceObjective`,
    ///   `TriggerEvidence`, `BudgetSlice`, `MaintenancePolicy`, `PriorHistory`)
    ///   are published by no owner to this daemon and are not constructible
    ///   from admitted binary material. That absence is ALREADY recorded, by
    ///   this daemon's own catalog, as
    ///   `crate::maintenance_family_catalog::MaintenanceAdmissionBlocker::MaintenanceJobWire`
    ///   (`maintenance_family_catalog.rs:462`, stated at `:476-478`), so this
    ///   arm does not restate a guess: it names the same publication gap from
    ///   the origin side.
    /// * no Dreamer instance is staffed on this base:
    ///   `staffing_policy.rs:511-521` gives every `dreamer_route_classes` entry
    ///   an explicit defer disposition reading "dreamer route class is
    ///   non-executing on this base", so there is no Dreamer producing
    ///   suggestions to read in the first place.
    /// * the three daemon-side Dreamer lanes that would consume such a record
    ///   each have zero production call sites:
    ///   `dreamer_admission.rs:176::GovernorDreamerAdapter::submit_orientation`
    ///   (the `eliot.kernel.dreamer-job` K2 route),
    ///   `experience_runtime.rs:775::run_experience_quality_event_with_revision`
    ///   (the Dreamer memory-revision `propose`), and
    ///   `negative_memory_action_gate.rs:677::commit_gated_action` (the
    ///   Dreamer negative-memory rule gate). Nothing in
    ///   `experience_runtime.rs`/`negative_memory_action_gate.rs`/`dreamer_*`
    ///   is reached from `daemon_runtime`'s live loop.
    /// * the Dreamer binary's own publication is one stdout line:
    ///   `result_stage.rs:72::emit_jsonl_stdout` renders the `DreamResult`
    ///   (including the `CurationProductPulse`) as JSONL, and no durable owner
    ///   reads it back.
    ///
    /// So the exact remaining step is a daemon trigger site that reads a
    /// PUBLISHED `MaintenancePlanCandidate` and names
    /// [`MaintenanceFamily::DreamerCuration`] — the one registered family whose
    /// own obligation is not an I12.24 source in its own right and whose
    /// catalog entry already lists `Dreamer` among its registered origins
    /// (`maintenance_family_catalog.rs:1388`) — together with the Dreamer's own
    /// suggestion refs in `MaintenanceObservation::evidence_refs`. Until that
    /// record exists, this arm changes nothing this daemon records, which is
    /// the fail-closed direction: an absent Dreamer suggestion produces no
    /// candidate rather than a fabricated one.
    ///
    /// # A second gap the producer must ALSO close, measured here
    ///
    /// Passing the Dreamer's own suggestion refs into
    /// [`MaintenanceObservation::evidence_refs`] is necessary but NOT
    /// sufficient, because the decision this arm produces does not carry them
    /// forward. [`AutomationTriggerDecision`] has no `evidence_refs` field
    /// (`crates/governor/eliot-maintenance/src/lib.rs:317-346`) — the evaluator
    /// validates `input.evidence_refs` for non-emptiness and uniqueness
    /// (`:300-301`) and then drops it. The trigger identity is not a substitute
    /// either: `maintenance_family_catalog::MaintenanceDedupScope::dedup_key`
    /// renders `"{scope}:{origin}:{family}:{scope_ref}@{generation}"`
    /// (`:212-219`), so the Dreamer record's own identity is absent from it. Those
    /// refs therefore reach exactly one place — the catalog's per-family record,
    /// as `MaintenanceObservedEvidence::observed_refs`
    /// (`maintenance_family_catalog.rs:254-258`, bound at `:1120`).
    ///
    /// The improvement funnel does not read that record. Its candidate lineage is
    /// built from the DECISION's own fields only:
    /// `improvement_intake_dispatch::maintenance_evidence_refs` returns exactly
    /// `[maintenance-trigger:{trigger_id}, maintenance-scope:{scope_ref}]`
    /// (`:1037-1044`). So a Dreamer suggestion that DID reach the intake would be
    /// labelled `EvidenceSource::Dreamer` correctly and would still cite none of
    /// its own evidence — the same "a candidate labelled a source it cannot cite"
    /// failure this origin exists to avoid. Closing that is a change in
    /// `improvement_intake_dispatch.rs` and, if the decision itself must carry
    /// the refs, in `eliot-maintenance`'s `AutomationTriggerDecision`. Neither is
    /// this file's, and neither is silently assumed here.
    ///
    /// `ASSUMPTION:` I9.2 is a list of Dreamer RESPONSIBILITIES and names no
    /// store, no record kind and no publication point ("system-maintenance and
    /// configuration-plan candidates", `I09-02-dreamer-service-responsibilities.md:11`),
    /// and `crates/governor/eliot-maintenance/module.toml` does not exist on
    /// this tree (no `module.toml` exists under `crates/governor/` at all). So
    /// "where a Dreamer suggestion is published" is answered by the OWNER THAT
    /// WRITES THE RECORD — `propose_maintenance_plan` and its
    /// `MaintenancePlanCandidate` — and by `MaintenanceTrigger::Dreamer`'s own
    /// "Accepted Dreamer maintenance plan candidate" doc, not by a document
    /// sentence that states a publication site.
    #[must_use]
    const fn maintenance_trigger(self) -> MaintenanceTrigger {
        match self {
            Self::StartupReconciliation | Self::IdleTransition => MaintenanceTrigger::Policy,
            Self::ColdStartCompletion => MaintenanceTrigger::Onboarding,
            Self::AdmittedObservation => MaintenanceTrigger::WatchdogProblem,
            Self::DreamerSuggestion => MaintenanceTrigger::Dreamer,
        }
    }
}

/// Facts this daemon genuinely observed, and nothing it inferred.
///
/// Every other input field is observed by the composition itself (the live
/// admitted fence, the retained Kernel-issued owner session, the wall clock)
/// so a caller cannot pass a stale fence or claim a session it never had.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceObservation {
    /// Which durable event produced this evaluation.
    pub origin: MaintenanceTriggerOrigin,
    /// The registered family this trigger concerns.
    ///
    /// #1693 owns the per-family catalog in [`maintenance_family_catalog`], and
    /// this seam resolves every family through it. The family still arrives
    /// from the caller because it is the caller's real observation: the
    /// catalog decides the mode, the conditions, the deduplication scope and
    /// the route for a family, but it cannot invent which family an observed
    /// signal concerns.
    pub family: MaintenanceFamily,
    /// Real evidence identities observed at the call site.
    ///
    /// Must be non-empty and duplicate-free: the evaluator rejects an empty
    /// evidence set, so a trigger with no observed evidence fails closed
    /// instead of being treated as maintenance-relevant.
    ///
    /// For [`MaintenanceTriggerOrigin::DreamerSuggestion`] these ARE the
    /// Dreamer's own suggestion refs — the published record's identity and
    /// digest — and nothing else may stand in for them. Note the measured limit
    /// on what they can prove: the decision does not carry them past the
    /// evaluator, so they reach the per-family catalog record and not the
    /// improvement candidate's lineage;
    /// see `MaintenanceTriggerOrigin::maintenance_trigger` for the exact
    /// boundary and the two files that have to change to widen it.
    pub evidence_refs: Vec<String>,
    /// Whether an admitted activation is in flight right now.
    pub activation_in_flight: bool,
}

impl DaemonComposition {
    /// Evaluates one durable maintenance trigger through the Governor-owned
    /// evaluator and returns its typed decision (I14.22, issue #1688).
    ///
    /// Readiness is checked first, mirroring every other composition seam, so
    /// the decision is only ever produced on the admitted path. The input is
    /// built from live observations and the composed owner's
    /// [`MaintenanceController`] does the deciding; this method adds no policy.
    ///
    /// Since #1693 the per-family facts are read from the registered
    /// maintenance-family catalog instead of being restated here: the selected
    /// automation mode and the idempotency/deduplication scope both come from
    /// the family's own entry, and the entry records the resolved route
    /// alongside the decision. The catalog does not loosen any gate below and
    /// does not choose the family; it only supplies what the family owns.
    ///
    /// The decision is emitted through the existing minimal operational
    /// diagnostics by
    /// [`emit_maintenance_trigger_decision`](crate::diagnostics::emit_maintenance_trigger_decision)
    /// on every successful evaluation, and the catalog's route and its one
    /// actionable recommendation are emitted next to it, so the decision is
    /// inspectable whether or not the caller keeps the returned value.
    ///
    /// # Errors
    ///
    /// [`DaemonError::Composition`] when the Governor is not ready, or
    /// [`DaemonError::Maintenance`] carrying the owner's own
    /// `MaintenanceError` unchanged.
    pub fn evaluate_maintenance_trigger(
        &self,
        observation: MaintenanceObservation,
    ) -> Result<AutomationTriggerDecision, DaemonError> {
        self.evaluate_maintenance_trigger_with_evidence(observation)
            .map(|(decision, _)| decision)
    }

    /// Evaluates one trigger and retains the exact policy and route evidence
    /// that the canonical notification owner needs for its failure identity.
    ///
    /// # Errors
    ///
    /// Returns the same readiness or maintenance error as
    /// [`Self::evaluate_maintenance_trigger`].
    pub fn evaluate_maintenance_trigger_with_evidence(
        &self,
        observation: MaintenanceObservation,
    ) -> Result<(AutomationTriggerDecision, MaintenanceNotificationEvidence), DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        // The registered entry for the observed family. The lookup is total
        // over `MaintenanceFamily`, so no family can be unregistered here and
        // no caller-supplied family is ever treated as unrecognised.
        let entry = crate::maintenance_family_catalog::entry_for(observation.family);
        // The live admitted fence is read here, never taken from the caller:
        // a transported fence claim is not a current observation.
        let state_fence = self.governor.kernel_snapshot().state_fence().clone();
        let scope_ref = scope_ref_for(&state_fence);
        // The trigger identity is the catalog's canonical deduplication key,
        // so the identity that duplicate suppression compares states which
        // family, event, scope, subset and generation it is, and
        // `MaintenanceController::admit`'s job identity inherits it. The board
        // lookup and the job lookup both consume this same key. This daemon
        // observes no subset identity, so a `FamilyScopeAndSubset` trigger
        // fails closed here rather than coalescing work across subsets it
        // cannot distinguish.
        let trigger_id = entry.dedup.dedup_key(
            &crate::maintenance_family_catalog::MaintenanceDedupIdentity {
                family: observation.family,
                origin: observation.origin.as_str(),
                scope_ref: &scope_ref,
                subset_ref: None,
                resource_generation: state_fence.resource_generation.value(),
            },
        )?;
        let (input, notification_evidence) = {
            // Owner evidence for every gate (I14.22/I14.24, issue #1692). Each
            // value is derived from a Governor-owned evidence owner or held at
            // its fail-closed value because the owning authority does not
            // exist yet (`UNRESOLVED_AUTHORITIES`, and the module-level
            // table); no caller-supplied flag enters the input, so a forged
            // mode/safety/session flag grants nothing. The Human policy owner
            // is unpublished, so the policy evidence records unpublished
            // provenance (no revision/digest, no override provenance, no
            // separate `interactive_maintenance` permission, no effect/budget
            // ceilings) around the registry-selected mode, which is `Off` for
            // every family while no publisher exists; the mode value itself
            // comes from the registered catalog, so no second mode source is
            // invented. The five non-Off modes are enforced by
            // `MaintenanceController::evaluate_trigger` and become reachable
            // only when a publisher appears. The transport session this
            // composition retains is explicitly not User Broker evidence.
            // No accepted Kernel owner query supplies the broker
            // registration/lease/revocation state, so the interactive session
            // gate remains unavailable.
            let policy = MaintenancePolicyEvidence::unpublished(
                entry.mode,
                observation.family,
                scope_ref.clone(),
            );
            let route = MaintenanceRouteEvidence::unpublished();
            let budget = MaintenanceBudgetEvidence::unpublished();
            let schedule = MaintenanceScheduleEvidence::unpublished();
            let broker = MaintenanceBrokerEvidence::owner_query_unavailable();
            let safety = MaintenanceSafetyEvidence::unpublished();
            let input = MaintenanceTriggerInput {
                trigger_id,
                evidence_refs: observation.evidence_refs,
                family: observation.family,
                scope_ref,
                mode: policy.mode(),
                trigger: observation.origin.maintenance_trigger(),
                explicit_request: false,
                // The one gate read from a real observation.
                idle: !observation.activation_in_flight,
                scheduled_window: schedule.is_current_window(),
                route_available: route.is_service_safe(),
                budget_available: budget.has_budget(),
                // Fail closed until the Kernel owner supplies a current
                // authenticated broker registration/lease observation.
                user_session_available: broker.authenticated_session_available(),
                user_session_required: policy.requires_interactive_session(),
                safety_required: safety.is_required(),
                now_ms: crate::unix_ms_i64(),
                expires_at_ms: None,
                active_job_id: None,
            };
            (input, MaintenanceNotificationEvidence { policy, route })
        };
        let decision = self
            .governor
            .owners()
            .maintenance
            .evaluate_trigger(&input)?;
        let _ = crate::diagnostics::emit_maintenance_trigger_decision(&input, &decision);
        // The catalog's half of the record: which registered family this was,
        // where its start would have to go, and the exact unavailable
        // dependency or absent Durable Job route that stops it today. A
        // triggered family is therefore never silently ignored, and no family
        // is ever reported as having run.
        //
        // The observed evidence is bound separately from the Governor
        // projection: the trigger event, the evidence identities actually
        // seen at this call site, and the selected policy revision travel
        // beside the decision rather than being projected from the catalog's
        // requirement lists, and each missing binding stays explicit.
        let observed = crate::maintenance_family_catalog::MaintenanceObservedEvidence {
            trigger_event: observation.origin.as_str(),
            observed_refs: input.evidence_refs.clone(),
            policy_revision: notification_evidence.policy.revision,
        };
        let family_decision = entry.record_start_route(&decision, observed);
        crate::maintenance_dispatch::MaintenanceDispatch::for_decision(&decision, &family_decision)
            .record(&decision);
        Ok((decision, notification_evidence))
    }

    /// Evaluates one durable maintenance trigger and never fails the caller.
    ///
    /// This is the entry the daemon runtime loop uses. A trigger that cannot
    /// be evaluated — the Governor is not ready yet, or the owner rejected the
    /// input — is recorded as an explicit typed gap through the same minimal
    /// operational diagnostics and the daemon continues. A maintenance
    /// observation is never allowed to become a startup gate, a readiness
    /// gate, or a silent drop: I14.22 keeps the trigger durable and surfaces
    /// it on the next eligible startup instead.
    pub fn note_maintenance_trigger(&self, observation: MaintenanceObservation) {
        if let Err(error) = self.evaluate_maintenance_trigger(observation) {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
        }
    }
}

/// What the publication of one maintenance source result actually did.
///
/// Every terminal store receipt is returned as issued. `Reconciled` is a real
/// publication proven by the exact store receipt, and it is the same value a
/// first attempt returns for an identical retry — the store identity, not this
/// enum, is what distinguishes a replay from a first commit. There is no
/// "logged" or "attempted" variant: a diagnostic line is never publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceResultPublication {
    /// The canonical observation is admitted and the exact store receipt is in
    /// hand, whether by the first commit or by reconciling an identical retry.
    Reconciled {
        /// The exact store receipt the canonical owner returned.
        receipt: eliot_store_api::WriteReceipt,
        /// The instant the admitted observation record itself carries.
        ///
        /// This is the record's own observed time, read from the record this
        /// publication built rather than from a second clock reading. It is
        /// what bounds a later delayed comparison's window from below, so the
        /// window is anchored to an admitted observation instead of to when the
        /// evaluator happened to run.
        observed_at_unix_ms: u64,
    },
}

/// Bounded absolute deadline applied to one maintenance result publication, in
/// Unix milliseconds, matching the retained daemon transport's own operation
/// bound used by the notification commit beside it.
const MAINTENANCE_RESULT_PUBLISH_DEADLINE_MS: u64 = 30_000;

/// Derives the admitted publication identity for one maintenance source result.
///
/// The identity is the daemon's own ingress identity at the live admitted fence,
/// with the source result's own publication identity as the idempotency key. It
/// is therefore a pure function of the source event: an identical retry produces
/// byte-equal identity bytes, so the store's
/// `(operation_id, canonical_request_hash)` identity reconciles the retry onto
/// the first commit instead of writing a second record, and a changed result
/// under the same identity fails closed. No clock-derived value, per-call
/// counter, or caller-supplied source enters the key.
///
/// The source and product identities are bound to the daemon service name
/// because `KernelStoreGateway::apply` fences any other caller: a substituted
/// source would be refused rather than written.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidField`] when the publication identity is not
/// a valid contract value or the derived request metadata does not validate.
fn publication_identity(
    publication_id: &str,
    state_fence: &eliot_contracts::StateFence,
) -> Result<eliot_protocol::RequestIdentity, ProtocolError> {
    let now = crate::unix_ms_i64();
    let operation_text = format!(
        "{}:maintenance-result:{publication_id}",
        crate::SERVICE_NAME
    );
    let invalid = |field: &'static str| ProtocolError::InvalidField {
        field,
        reason: "maintenance result publication identity is not a valid contract value",
    };
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(operation_text.clone())
            .map_err(|_| invalid("maintenance_result.request_id"))?,
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new(crate::SERVICE_NAME)
            .map_err(|_| invalid("maintenance_result.product_id"))?,
        source_id: eliot_contracts::SourceId::new(crate::SERVICE_NAME)
            .map_err(|_| invalid("maintenance_result.source_id"))?,
        // The live admitted fence, read from the retained Governor snapshot and
        // never taken from the caller: a transported or cached fence must not be
        // able to substitute for the one the result is admitted under.
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
        .map_err(|_| invalid("maintenance_result.request_metadata"))?;
    Ok(eliot_protocol::RequestIdentity {
        request: eliot_receipts::RequestBinding {
            metadata,
            state_fence: state_fence.clone(),
        },
        idempotency_key: operation_text,
        deadline_unix_ms: crate::unix_ms().saturating_add(MAINTENANCE_RESULT_PUBLISH_DEADLINE_MS),
        cancellation_id: format!(
            "{}:maintenance-result:{publication_id}:cancel",
            crate::SERVICE_NAME
        ),
    })
}

/// Fail-closed refusals of the maintenance result publication path.
///
/// [`DaemonError`] already carries this composition's canonical-admission
/// (`CompositionError`) and maintenance-owner (`MaintenanceError`) refusals as
/// its own typed variants, so those are reused rather than restated here; this
/// enum adds only the protocol-identity refusal the daemon composition does not
/// already own. Nothing is folded into prose between layers, and no refusal is
/// reported as a publication.
#[derive(Debug, Error)]
pub enum MaintenanceResultPublishError {
    /// The publication identity or its base operation is not a valid contract
    /// value.
    #[error("maintenance result publication protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// The canonical route returned a terminal receipt that did not commit, so
    /// the observation was not admitted and the obligation stays owed.
    #[error(
        "maintenance result was not admitted: publication {publication_id} returned {status:?} for {operation_id}"
    )]
    NotAdmitted {
        /// The stable publication identity that was offered.
        publication_id: String,
        /// The exact operation the store issued the terminal receipt for.
        operation_id: OperationId,
        /// The terminal store status, exactly as issued.
        status: WriteReceiptStatus,
    },
    /// The composition, the canonical admission, or the maintenance owner
    /// refused the publication, each in its own typed variant.
    #[error("maintenance result publication: {0}")]
    Daemon(#[from] DaemonError),
}

impl DaemonComposition {
    /// Publishes one maintenance source result into the canonical observation
    /// path and returns the exact store receipt.
    ///
    /// This is the production caller of
    /// `observation_adapters::ForwardingObservationReconciliation::admit_maintenance_result`.
    /// The maintained subsystem's owner produces the obligation, the owner
    /// validates and projects it into the observation-family record, the
    /// Governor checks authority, fence and identity, and the Store returns its
    /// own receipt. The publication identity comes from the source event, so an
    /// identical retry reconciles the existing receipt instead of writing a
    /// second record, and a lost acknowledgement is read back through the same
    /// operation rather than committed again.
    ///
    /// This covers every applicable source result, not only the success branch:
    /// a completion, a bounded partial, a failure, a cancellation, an unknown
    /// outcome and a no-attempt non-execution decision each publish here, and a
    /// failure or an unknown is never dropped for not being a success. A later
    /// reconciliation appends a linked obligation rather than replacing the
    /// earlier one, so the original uncertainty stays visible next to its
    /// resolution.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceResultPublishError`] when the composition is not
    /// ready, the owner refuses the obligation or the record it projects, the
    /// publication identity is not a contract value, or the canonical commit
    /// cannot be completed or reconciled. Every one of those is a refusal, not a
    /// publication, and the caller keeps the obligation durable for the retry.
    pub async fn publish_maintenance_result(
        &self,
        base_operation_text: &str,
        obligation: &MaintenanceResultObligation,
    ) -> Result<MaintenanceResultPublication, MaintenanceResultPublishError> {
        let observed_at_unix_ms = u64::try_from(crate::unix_ms_i64()).unwrap_or_default();
        // The record is built and validated by the maintained subsystem's own
        // owner before it reaches the canonical route, so a malformed obligation
        // never becomes a store write. The owner's own refusal travels on the
        // daemon's existing typed maintenance channel unchanged.
        let record = maintenance_observation_record(obligation, observed_at_unix_ms)
            .map_err(DaemonError::Maintenance)?;
        let base_operation = OperationId::new(base_operation_text.to_owned()).map_err(|_| {
            ProtocolError::InvalidField {
                field: "maintenance_result.base_operation",
                reason: "maintenance result base operation is not a valid contract value",
            }
        })?;
        // The live admitted fence is read here, never taken from the caller.
        let live_fence = self.governor.kernel_snapshot().state_fence().clone();
        let identity = publication_identity(&obligation.publication_id, &live_fence)?;
        // The canonical route's own admission refusal is a
        // `CompositionError`, and this enum reuses [`DaemonError::Composition`]
        // to carry it unchanged rather than restating the cause or reducing it
        // to prose. The readiness refusal of `observation_reconciliation` and
        // the admission refusal below therefore stay distinguishable by variant.
        let receipt = self
            .observation_reconciliation()?
            .admit_maintenance_result(&identity, &base_operation, &record)
            .await
            .map_err(DaemonError::Composition)?;
        // A terminal non-committed receipt is not publication. The route
        // returns every terminal status exactly as issued, so this is where a
        // rejected or dead-lettered observation stops being an admission: it
        // never becomes a receipt the maintenance owner could record as one.
        if receipt.status != WriteReceiptStatus::Committed {
            return Err(MaintenanceResultPublishError::NotAdmitted {
                publication_id: obligation.publication_id.clone(),
                operation_id: receipt.operation_id,
                status: receipt.status,
            });
        }
        Ok(MaintenanceResultPublication::Reconciled {
            receipt,
            observed_at_unix_ms,
        })
    }

    /// Admits the canonical receipt for one published maintenance result onto
    /// the retained durable job revision.
    ///
    /// This is the production call that makes the second of the three states
    /// durable: the maintenance owner already recorded that the work happened
    /// and that an observation was owed, and this records that the observation
    /// was admitted, under the exact receipt the store returned. It settles
    /// only the delivery state — never the lifecycle state, the outcome
    /// reference, or any earlier obligation — so a receipt cannot rewrite the
    /// execution history it observes, and no outcome is ever written here.
    ///
    /// Replaying the same receipt is a reconciliation and persists nothing; a
    /// different receipt under one identity is refused by the owner as a
    /// conflict rather than replacing the first admission.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceResultPublishError`] when the composition is not
    /// ready or the retained-job write is refused. The maintenance owner's own
    /// refusal travels unchanged inside [`DaemonError::Composition`], so a
    /// dangling publication identity stays distinguishable from a transport
    /// failure.
    pub fn admit_maintenance_observation_receipt(
        &mut self,
        job_id: &str,
        publication_id: &str,
        observation_receipt_ref: &str,
    ) -> Result<eliot_maintenance::MaintenanceJob, MaintenanceResultPublishError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceResultPublishError::Daemon(
                DaemonError::Composition(CompositionError::NotReady),
            ));
        }
        self.governor
            .admit_maintenance_observation_receipt(job_id, publication_id, observation_receipt_ref)
            .map_err(|error| MaintenanceResultPublishError::Daemon(DaemonError::Composition(error)))
    }

    /// Appends one delayed utility evaluation for a retained maintenance job.
    ///
    /// This is the production call that turns work performed plus measured
    /// evidence into a delayed utility conclusion (I14.22, issue #1695 W4).
    /// The maintenance owner reads its own retained obligation chain, binds the
    /// caller's measurements to obligations that chain really holds, and appends
    /// the resulting evaluation revision on the same Kernel durable-job ledger
    /// its transitions already write through. The evaluation then reaches the
    /// observation path through the existing
    /// [`Self::publish_maintenance_result`] route like any other source result.
    ///
    /// No verdict is asserted here. `evidence` carries only comparisons this
    /// daemon genuinely observed, and every required metric the comparison did
    /// not observe stays explicitly unknown, so a completed job with no
    /// measured follow-up appends an evaluation that reads `PENDING`.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceResultPublishError::Daemon`] with
    /// [`DaemonError::Composition`] when the composition is not ready or the
    /// retained-job write is refused. The maintenance owner's own refusal
    /// travels unchanged inside that variant, so a malformed comparison stays
    /// distinguishable from a transport failure.
    pub fn evaluate_maintenance_utility(
        &mut self,
        job_id: &str,
        evaluation_window: eliot_observation_contracts::CoverageInterval,
        evidence: &eliot_maintenance::UtilityEvaluationEvidence,
    ) -> Result<eliot_maintenance::MaintenanceJob, MaintenanceResultPublishError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceResultPublishError::Daemon(
                DaemonError::Composition(CompositionError::NotReady),
            ));
        }
        self.governor
            .evaluate_maintenance_utility(job_id, evaluation_window, evidence)
            .map_err(|error| MaintenanceResultPublishError::Daemon(DaemonError::Composition(error)))
    }

    /// Records the explicit coverage gap for one maintenance result writeback
    /// the canonical route refused with a terminal non-committed receipt.
    ///
    /// This is the production call that keeps a refused writeback from
    /// disappearing. The obligation is already durable on the maintenance
    /// store, so nothing is lost either way — but a `Pending` obligation is
    /// indistinguishable from one that was never attempted, and the daemon has
    /// no other durable place to say "the store refused this exact publication
    /// and here is the gap". This settles that on the same Kernel durable-job
    /// ledger the transitions already write through.
    ///
    /// `refused_operation_id` and `refused_status` must be the exact values
    /// [`MaintenanceResultPublishError::NotAdmitted`] carries. A readiness or
    /// transport refusal produced no terminal receipt and must not call this:
    /// the owner has no `Committed` member in its refusal vocabulary precisely
    /// so an admission cannot be recorded twice, once as a receipt and once as
    /// a gap.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceResultPublishError::Daemon`] with
    /// [`DaemonError::Composition`] when the composition is not ready or the
    /// retained-job write is refused. The maintenance owner's own refusal
    /// travels unchanged inside that variant, so a dangling publication
    /// identity and an already-admitted observation stay distinguishable from a
    /// transport failure.
    pub fn record_maintenance_observation_gap(
        &mut self,
        job_id: &str,
        publication_id: &str,
        refused_operation_id: &str,
        refused_status: eliot_maintenance::RefusedReceiptStatus,
    ) -> Result<eliot_maintenance::MaintenanceJob, MaintenanceResultPublishError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceResultPublishError::Daemon(
                DaemonError::Composition(CompositionError::NotReady),
            ));
        }
        self.governor
            .record_maintenance_observation_gap(
                job_id,
                publication_id,
                refused_operation_id,
                refused_status,
            )
            .map_err(|error| MaintenanceResultPublishError::Daemon(DaemonError::Composition(error)))
    }
}

/// Builds the affected-scope identity from the live admitted fence.
///
/// The scope is the canonical generation the evaluation actually runs under:
/// the authority lineage plus its sequence and the resource generation. It
/// carries no clock, counter or process-local value, so the same admitted
/// fence always yields the same scope and therefore the same trigger identity.
fn scope_ref_for(state_fence: &eliot_contracts::StateFence) -> String {
    format!(
        "{}:{}@{}:{}",
        crate::SERVICE_NAME,
        state_fence.authority_epoch.lineage_id,
        state_fence.authority_epoch.sequence.get(),
        state_fence.resource_generation.value()
    )
}

/// The family this daemon's wired trigger sites name for its OWN health and
/// maintenance debt.
///
/// Every trigger origin that observes the daemon's own admitted health and
/// maintenance debt concerns exactly what I14.22's `SelfQualityDebt` family
/// ("self-quality, feedback and maintenance-debt review") covers, so the idle
/// cadence trigger and the admitted store-health observation name it
/// unconditionally. It is also the family the startup and improvement-intake
/// sites name when their own declared-capability evidence shows no gap; when a
/// gap IS observed they name `MaintenanceFamily::DonorConformance` instead,
/// through the daemon runtime's own `conformance_observed_family` (issue
/// #1867 W2/A1). The family is therefore no longer one constant for every
/// site, and this one is no longer a stand-in for families the daemon has no
/// observation for.
///
/// #1693 supplied the registered per-family catalog, so this is no longer a
/// catalog limit: `MaintenanceFamily` carries all fifteen families and
/// [`maintenance_family_catalog::entry_for`] resolves any of them, and
/// [`DaemonComposition::evaluate_maintenance_trigger`] routes whichever one the
/// caller observes. This constant remains the family the daemon's own
/// observable health-and-debt trigger sites name, because the family is the
/// caller's real observation and the catalog must not invent which family an
/// observed signal concerns.
pub const SELF_OBSERVED_FAMILY: MaintenanceFamily = MaintenanceFamily::SelfQualityDebt;

/// Fail-closed refusals of the owner-side maintenance decision commit.
///
/// Every variant keeps its owner's own typed failure: the store contract
/// refusal stays a [`StoreError`], canonical admission stays a
/// [`CompositionError`], the authenticated exchange stays a
/// [`KernelPortError`], the maintenance owner refusal stays a
/// [`MaintenanceError`], and wire validation stays a [`ProtocolError`]. The
/// daemon composition refusal stays a [`DaemonError`] unchanged, so readiness
/// and evaluation denials keep their exact shape. No code is folded into
/// prose between layers.
#[derive(Debug, Error)]
pub enum MaintenanceDecisionCommitError {
    /// The store contract refused the intent commit, the commit receipt, or
    /// the bound decision receipt inputs.
    #[error("maintenance decision commit store: {0}")]
    Store(#[from] StoreError),
    /// Governor-owned canonical admission refused the commit.
    #[error("maintenance decision commit admission: {0}")]
    Admission(#[from] CompositionError),
    /// The authenticated Kernel exchange refused or could not complete the
    /// intent commit or the receipt read-back.
    #[error("maintenance decision commit transport: {0}")]
    Kernel(#[from] KernelPortError),
    /// The maintenance owner refused the commit bindings (stale fence or
    /// claim, or a malformed binding identity).
    #[error("maintenance decision commit owner: {0}")]
    Maintenance(#[from] MaintenanceError),
    /// The retained record, the claim, or the bound receipt failed wire
    /// validation, or the evaluated decision answers a different trigger.
    #[error("maintenance decision commit protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// The daemon composition refused the commit (not ready, not
    /// authenticated, or the owner's own evaluation denial).
    #[error("maintenance decision commit daemon: {0}")]
    Daemon(#[from] DaemonError),
}

impl DaemonComposition {
    /// Commits one retained maintenance trigger decision before any delivery
    /// acknowledgement (I14.22, issue #1694 W4).
    ///
    /// The authenticated daemon resolves the current #1692 policy and the
    /// #1688 decision by reusing
    /// [`Self::evaluate_maintenance_trigger_with_evidence`]: no policy or
    /// evaluation logic is restated here. The durable downstream intent is
    /// retained through its existing outbox owner — the canonical
    /// notification leg for a decision that cannot start — which submits the
    /// Governor `PreparedTransition` to the admitted `ApplyNotificationState`
    /// route over the same authenticated daemon transport (Governor
    /// `PreparedTransition` → Kernel → named Store transaction, I1.8). The
    /// returned [`MaintenanceTriggerDecisionReceipt`] binds the retained
    /// trigger identity and operation hash, the claim row revision, the
    /// evaluator and policy revisions, the affected scope, the
    /// job/recommendation/wake intent references, and the canonical Store
    /// receipt identity with the digest of its exact bytes.
    ///
    /// A decision plus a durable downstream intent is distinct from an
    /// executed job or a delivered notification: this method never admits or
    /// starts a job and never delivers anything. It only records the
    /// commitment the Kernel ledger must validate before acknowledging the
    /// trigger.
    ///
    /// The commit is explicit about what it cannot do yet, and invents
    /// nothing in its place:
    ///
    /// * `Ok(None)` means no durable intent was admitted — automation is off,
    ///   the intent record already stands, or the only intent names a job
    ///   whose canonical commit receipt is not in hand. The trigger stays
    ///   retained under its existing claim; nothing is dropped and no receipt
    ///   is fabricated. Recording that bound receipt into the Kernel delivery
    ///   ledger travels the follow-up daemon-to-Kernel decision route.
    /// * A lost or ambiguous commit receipt read-back is also `Ok(None)`:
    ///   receipt absence during an outage is not proof of non-commit, so the
    ///   trigger stays open for receipt-lookup reconciliation instead of
    ///   being reported either way.
    /// * No wake intent is bound: no wake scheduler publishes to this daemon,
    ///   so `wake_ref` stays `None` rather than naming an owner that does not
    ///   exist. Trigger expiry enforcement stays with the Kernel ledger
    ///   acknowledgement, which refuses stale eligibility; this commit binds
    ///   the live fence and the live claim deadline only.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] keeping each owner's typed
    /// refusal: stale fence or claim deadline, unknown or conflicting trigger
    /// identity, evaluation denial, intent-commit refusal, or an unbound
    /// commit receipt.
    pub async fn commit_maintenance_trigger_decision(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        observation: MaintenanceObservation,
        record: &MaintenanceTriggerRecord,
        claim: &MaintenanceTriggerClaim,
    ) -> Result<Option<MaintenanceTriggerDecisionReceipt>, MaintenanceDecisionCommitError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceDecisionCommitError::Admission(
                CompositionError::NotReady,
            ));
        }
        if self.owner_session.is_none() {
            return Err(MaintenanceDecisionCommitError::Daemon(
                DaemonError::Lifecycle(
                    "owner session is not bound; drop and re-run authenticated connect+start"
                        .to_owned(),
                ),
            ));
        }
        record.validate()?;
        claim.validate()?;
        // The commit authorizes under the live admitted fence only: a claim
        // bound to a superseded generation must fail here, never commit under
        // it. Claim/session echo and revocation stay the Kernel ledger's check
        // at acknowledgement time.
        let live_fence = self.governor.kernel_snapshot().state_fence().clone();
        if claim.daemon_fence != live_fence {
            return Err(MaintenanceDecisionCommitError::Maintenance(
                MaintenanceError::FenceMismatch,
            ));
        }
        if claim.claim_deadline_unix_ms < crate::unix_ms() {
            return Err(MaintenanceDecisionCommitError::Maintenance(
                MaintenanceError::FenceMismatch,
            ));
        }
        if claim.trigger_id != record.trigger_id {
            return Err(MaintenanceDecisionCommitError::Protocol(
                ProtocolError::ReplayConflict,
            ));
        }
        if claim.revision == 0 {
            return Err(MaintenanceDecisionCommitError::Maintenance(
                MaintenanceError::InvalidField("maintenance_trigger_claim.revision"),
            ));
        }
        let (decision, evidence) = self
            .evaluate_maintenance_trigger_with_evidence(observation)
            .map_err(MaintenanceDecisionCommitError::Daemon)?;
        // The decision must answer this exact retained trigger: identical
        // identity and scope. Changed content conflicts; it never re-binds.
        if decision.trigger_id != record.trigger_id || decision.scope_ref != record.scope.reference
        {
            return Err(MaintenanceDecisionCommitError::Protocol(
                ProtocolError::ReplayConflict,
            ));
        }
        // A job reference names an already-durable job only; it is bound as a
        // reference, never admitted or started here. A blank reference binds
        // nothing: the receipt validator would refuse it, so it is dropped up
        // front under the same nonblank rule.
        let job_ref = decision
            .durable_job_ref
            .clone()
            .filter(|reference| is_commit_ref_text(reference));
        // The durable downstream intent through its existing outbox owner.
        // The leg submits the Governor prepared transition to the admitted
        // notification route and proves the canonical commit receipt in hand;
        // `Ok(None)` (automation off, record already standing) admits no
        // intent and therefore binds no receipt.
        let committed =
            emit_blocked_automation_notification(kernel, live_fence, &decision, &evidence)
                .await
                .map_err(|error| match error {
                    NotificationEmitError::Store(error) => {
                        MaintenanceDecisionCommitError::Store(error)
                    }
                    NotificationEmitError::Admission(error) => {
                        MaintenanceDecisionCommitError::Admission(error)
                    }
                    NotificationEmitError::Kernel(error) => {
                        MaintenanceDecisionCommitError::Kernel(error)
                    }
                })?;
        let Some(NotificationStateEmit::Committed {
            notification_id,
            operation_id,
            ..
        }) = committed
        else {
            return Ok(None);
        };
        Self::bind_committed_decision_receipt(
            kernel,
            record,
            DecisionReceiptBindings {
                claim_revision: claim.revision,
                scope_ref: decision.scope_ref.clone(),
                job_ref,
                policy_revision: policy_revision(&evidence.policy),
                notification_id,
            },
            operation_id,
        )
        .await
    }

    /// Binds the canonical commit receipt for an admitted downstream intent.
    ///
    /// The committed intent identity is looked up through the owning read
    /// path rather than trusted from the request. Absence is the ambiguous
    /// case — the commit may have happened across an outage boundary — so
    /// this returns open instead of proof either way.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] for an unbound identity, a
    /// refused or uncommitted receipt, or an unserializable receipt.
    async fn bind_committed_decision_receipt(
        kernel: &Arc<DaemonKernelClient>,
        record: &MaintenanceTriggerRecord,
        bindings: DecisionReceiptBindings,
        operation_id: String,
    ) -> Result<Option<MaintenanceTriggerDecisionReceipt>, MaintenanceDecisionCommitError> {
        // The exact canonical identity of the committed intent, looked up
        // through the owning read path rather than trusted from the request.
        // Absence here is the ambiguous case: the commit may have happened
        // across an outage boundary, so this returns open instead of proof.
        let operation_id = OperationId::new(operation_id).map_err(StoreError::Foundation)?;
        let Some(receipt) = kernel.receipt(operation_id).await? else {
            return Ok(None);
        };
        receipt.validate()?;
        if receipt.status != WriteReceiptStatus::Committed {
            return Err(MaintenanceDecisionCommitError::Store(
                StoreError::Serialization(
                    "maintenance decision intent transition was not committed".to_owned(),
                ),
            ));
        }
        let receipt_bytes = canonical_json_bytes(&receipt)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let decision_receipt = MaintenanceTriggerDecisionReceipt {
            wire_id: MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION,
            trigger_id: record.trigger_id.clone(),
            operation_hash: record.operation_hash.clone(),
            revision: bindings.claim_revision,
            evaluation_revision: format!("{CONTRACT_NAME}:{CONTRACT_VERSION}"),
            policy_revision: bindings.policy_revision,
            scope_ref: bindings.scope_ref,
            job_ref: bindings.job_ref,
            recommendation_ref: Some(bindings.notification_id),
            wake_ref: None,
            canonical_receipt_ref: receipt.operation_id.to_string(),
            receipt_digest: sha256_hex(&receipt_bytes),
        };
        decision_receipt.validate()?;
        Ok(Some(decision_receipt))
    }
}

/// Receipt bindings carried into [`DaemonComposition::bind_committed_decision_receipt`].
///
/// Bundled so the helper stays within the owner argument budget; every field
/// is the exact value the receipt validator checks.
struct DecisionReceiptBindings {
    /// Claim row revision the decision commits under.
    claim_revision: u64,
    /// Affected scope the decision answers.
    scope_ref: String,
    /// Already-durable job reference, if the decision named one.
    job_ref: Option<String>,
    /// Policy revision resolved at decision time.
    policy_revision: String,
    /// Committed notification intent identity.
    notification_id: String,
}

/// Renders the opaque policy revision resolved at decision time.
///
/// A published Human policy revision names its own revision and digest. While
/// no publisher exists the label records the fail-closed provenance — the
/// registry-selected mode the evaluation actually ran under — and never a
/// guessed publisher revision.
fn policy_revision(policy: &MaintenancePolicyEvidence) -> String {
    match (policy.revision, policy.digest.as_deref()) {
        (Some(revision), Some(digest)) => format!("rev{revision}:{digest}"),
        (Some(revision), None) => format!("rev{revision}:unpublished"),
        (None, _) => format!("unpublished:{:?}", policy.mode()),
    }
}

/// Mirrors the protocol's nonblank reference rule for intent bindings.
///
/// A blank, padded, or control-carrying reference binds nothing: the receipt
/// validator would refuse it, so callers drop it up front instead of
/// submitting a receipt that cannot validate.
fn is_commit_ref_text(value: &str) -> bool {
    !value.trim().is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}
