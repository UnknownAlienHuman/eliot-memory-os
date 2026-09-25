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

#![forbid(unsafe_code)]

use eliot_maintenance::{
    AutomationTriggerDecision, MaintenanceAutomationMode, MaintenanceFamily, MaintenanceTrigger,
    MaintenanceTriggerInput,
};

use super::DaemonComposition;
use super::DaemonError;

/// The maintenance families whose policy owner this daemon cannot yet resolve,
/// as one constant a reader can inspect instead of a scattered `false`.
///
/// Every field held below is held **fail-closed**, never permissively:
///
/// | Held field | Value | Why it is not `true` | Owning issue |
/// |---|---|---|---|
/// | `mode` | [`MaintenanceAutomationMode::Off`] | No Human maintenance-policy owner exists in `eliotd`; `eliot-config` owns only a one-shot *first-run* decision that the daemon runtime never reads. `Off` is I14.22's own "no automatic job or proactive recommendation" value, so an unresolved policy denies automation instead of defaulting to permissive. | #1692, #1693 |
/// | `scheduled_window` | `false` | `eliotd` holds no Host wake / Task Scheduler occurrence. Inventing a window is exactly the "locally invented occurrence" #1692 forbids. | #1692 |
/// | `route_available` | `false` | No maintenance route/credential owner publishes a service-safe route to this daemon. | #1692 |
/// | `budget_available` | `false` | No maintenance budget/quota owner publishes one. | #1692 |
/// | `user_session_required` | `false` | The `interactive_maintenance` policy that would set it does not exist here. Held `false` grants nothing: `route_available` is already `false`, so no route can be selected. | #1692 |
/// | `explicit_request` | `false` | `eliotd` exposes no authenticated Human UI/CLI maintenance-request ingress; an untrusted flag is not a request. | #1692 |
/// | `safety_required` | `false` | No owner publishes a verified mandatory safety/recovery obligation to this daemon, and the flag must never be asserted to bypass authentication. | #1692 |
/// | `active_job_id` | `None` | [`MaintenanceController`] exposes no probe for an existing active job, so duplicate suppression cannot be fed. | #1694 |
/// | `expires_at_ms` | `None` | No expiry policy is published to this daemon. | #1694 |
///
/// The one gate that **is** filled from a real observation is
/// `user_session_available`, read from the validated Kernel-issued owner
/// session the daemon already retains.
pub const UNRESOLVED_AUTHORITIES: &str = "mode,scheduled_window,route_available,budget_available,user_session_required,explicit_request,safety_required,active_job_id,expires_at_ms";

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
        }
    }

    /// I14.22's job-origin classification for this trigger.
    ///
    /// `StartupReconciliation` and `IdleTransition` are approved
    /// policy-driven occurrences ("Human-approved idle/scheduled policy"),
    /// `ColdStartCompletion` is a first-run/onboarding occurrence, and
    /// `AdmittedObservation` is an admitted problem/signal occurrence
    /// (Watchdog/Doctor problem recipe). The I14.22 origin enum has no
    /// finer-grained member than these four, so the mapping is exhaustive.
    #[must_use]
    const fn maintenance_trigger(self) -> MaintenanceTrigger {
        match self {
            Self::StartupReconciliation | Self::IdleTransition => MaintenanceTrigger::Policy,
            Self::ColdStartCompletion => MaintenanceTrigger::Onboarding,
            Self::AdmittedObservation => MaintenanceTrigger::WatchdogProblem,
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
    /// #1693 owns the per-family catalog that maps an observation to its
    /// family. Until it lands, callers name the self-review family the
    /// observation actually concerns rather than inventing a maintenance
    /// route for a family whose execution owner is unverified.
    pub family: MaintenanceFamily,
    /// Real evidence identities observed at the call site.
    ///
    /// Must be non-empty and duplicate-free: the evaluator rejects an empty
    /// evidence set, so a trigger with no observed evidence fails closed
    /// instead of being treated as maintenance-relevant.
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
    /// The decision is emitted through the existing minimal operational
    /// diagnostics by
    /// [`emit_maintenance_trigger_decision`](crate::diagnostics::emit_maintenance_trigger_decision)
    /// on every successful evaluation, so the decision is inspectable whether
    /// or not the caller keeps the returned value.
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
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        // The live admitted fence is read here, never taken from the caller:
        // a transported fence claim is not a current observation.
        let state_fence = self.governor.kernel_snapshot().state_fence().clone();
        let scope_ref = scope_ref_for(&state_fence);
        let trigger_id = format!(
            "{}:{}:{scope_ref}",
            observation.origin.as_str(),
            observation.family
        );
        let input = MaintenanceTriggerInput {
            trigger_id,
            evidence_refs: observation.evidence_refs,
            family: observation.family,
            scope_ref,
            // Fail-closed: no Human maintenance-policy owner exists here yet
            // (`UNRESOLVED_AUTHORITIES`). See the module-level table.
            mode: MaintenanceAutomationMode::Off,
            trigger: observation.origin.maintenance_trigger(),
            explicit_request: false,
            // The one gate read from a real observation.
            idle: !observation.activation_in_flight,
            scheduled_window: false,
            route_available: false,
            budget_available: false,
            // Observed, not claimed: the validated Kernel-issued owner session
            // this composition already retains, or the unadmitted gap.
            user_session_available: self.owner_session.is_some(),
            user_session_required: false,
            safety_required: false,
            now_ms: crate::unix_ms_i64(),
            expires_at_ms: None,
            active_job_id: None,
        };
        let decision = self
            .governor
            .owners()
            .maintenance
            .evaluate_trigger(&input)?;
        let _ = crate::diagnostics::emit_maintenance_trigger_decision(&input, &decision);
        Ok(decision)
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

/// The family this daemon's triggers select today.
///
/// Every trigger origin currently concerns the daemon's own admitted health
/// and maintenance debt, which is exactly what I14.22's
/// `SelfQualityDebt` family ("self-quality, feedback and maintenance-debt
/// review") covers. #1693 replaces this with the real per-observation family
/// catalog; naming one family here keeps every decision inspectable and stops
/// the evaluator from silently claiming maintenance work whose execution owner
/// has not been proven.
pub const SELF_OBSERVED_FAMILY: MaintenanceFamily = MaintenanceFamily::SelfQualityDebt;
