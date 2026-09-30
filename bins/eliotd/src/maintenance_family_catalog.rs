//! Registered I14.22 maintenance-family catalog (issue #1693).
//!
//! Architecture: A2.3 (contracts own the vocabulary, the composition root only
//! wires it) and A10.4 (one named owner per delegated effect).
//! Implementation: I14.22 "Maintenance jobs" —
//! `docs/architecture/I14-22-maintenance-jobs.md#i1422-maintenance-jobs`.
//!
//! [`eliot_maintenance::MaintenanceFamily`] is the authority: it already
//! enumerates the fifteen registered families and
//! [`eliot_maintenance::MaintenanceController::evaluate_trigger`] already owns
//! the whole deterministic decision surface. This module adds neither a second
//! family enum nor a second taxonomy, and it defines no decision, mode, or
//! family vocabulary of its own. What it adds is the one thing neither of them
//! carries: the **registry** that says, for each registered family, its
//! selected automation mode, its eligibility predicates, its required
//! route/capability/session conditions, its idempotency/deduplication scope,
//! its execution owner (or the exact capability that is absent), and where its
//! result is observed.
//!
//! Four properties are load-bearing, and they match the three the existing
//! [`crate::maintenance_trigger_evaluator`] seam states for itself:
//!
//! * **No drift from the enum.** Every family is written exactly once, in a
//!   single macro invocation, and that same invocation generates the
//!   exhaustive [`entry_for`] match, the [`ALL`] table and
//!   [`REGISTERED_FAMILY_COUNT`]. Adding a [`MaintenanceFamily`] variant breaks
//!   the generated match at compile time, so the table cannot omit a family
//!   and a family cannot be registered twice.
//! * **No fabricated authority.** The selected automation mode is
//!   [`UNRESOLVED_POLICY_MODE`] for all fifteen families, which is the exact
//!   fail-closed value the existing seam already holds and documents. I14.22
//!   selects the mode per family through a Human policy; no such policy owner
//!   exists in `eliotd` yet, so the catalog names the denial instead of
//!   defaulting to a permissive mode.
//! * **A durable decision, not only a log line.**
//!   [`MaintenanceFamilyEntry::decide`] resolves the whole record — the selected
//!   mode, the deduplication scope, the route, the owner or the exact
//!   unavailable dependency, and the one actionable recommendation with each
//!   element I14.22 names — into a typed [`MaintenanceFamilyDecision`] value
//!   rather than only into prose on an operational line. A triggered family that
//!   cannot start is therefore reportable by something other than a rotatable
//!   log.
//!
//!   Stated rather than implied: the durable carrier of that value is a
//!   different owner's record. `crate::notification_state_emit` resolves this
//!   entry for every decision it emits and puts
//!   [`MaintenanceFamilyEntry::recommendation`] into that record's
//!   `required_action` (through `notification_state_emit`'s private
//!   `automation_failure_key_with_family_decision`),
//!   so a family that cannot start leaves a canonical notification keyed by
//!   this entry's [`MaintenanceDedupScope`] rather than only a log line. What
//!   that owner still cannot do is preserve a decision it failed to write; that
//!   is a durable-intake owner this issue does not have.
//! * **No direct execution.** This module never runs maintenance work, never
//!   constructs an executor, and never calls a family owner. I14.22 requires
//!   every start to be a Durable Job request, and the catalog resolves only
//!   *where* such a request must go. Today it resolves to
//!   [`MaintenanceRoute::DurableJobRequest`] or
//!   [`MaintenanceRoute::Blocked`] for every family, and neither admits a
//!   start, because the maintenance Durable Job admission itself is unreachable
//!   from `eliotd`: see [`DURABLE_JOB_ADMISSION_BLOCKERS`], which names each
//!   missing symbol exactly. A [`MaintenanceRoute::Blocked`] route additionally
//!   never admits a start no matter how that shared list changes, so clearing
//!   the common blockers in a later integration cannot make an unavailable
//!   family look startable. Families are registered and deterministically
//!   blocked with that reason; none is omitted and none is silently ignored.

#![forbid(unsafe_code)]

use eliot_maintenance::{
    AutomationDecision, AutomationTriggerDecision, DecisionReason, MaintenanceAutomationMode,
    MaintenanceError, MaintenanceFamily, MaintenanceTrigger,
};

use crate::SERVICE_NAME;

/// The I14.22 `eliot_system` observation/experience path every maintenance
/// result enters. It is named once here because it is the same path for all
/// fifteen families and must not be re-invented per family.
pub const SYSTEM_OBSERVATION_PATH: &str = "eliot_system";

/// The automation mode the catalog selects for every registered family while
/// no Human maintenance-policy owner exists.
///
/// I14.22 reads: "Human policy selects one `MaintenanceAutomationMode` per
/// family", and `off` means "no automatic job or proactive recommendation,
/// except mandatory safety/recovery obligations". The policy owner that would
/// make that selection does not exist in `eliotd`, so the catalog records the
/// denial rather than a permissive default. It is the same value
/// [`crate::maintenance_trigger_evaluator::UNRESOLVED_AUTHORITIES`] holds and
/// names for the `mode` field, and this catalog is the single place that
/// states it.
pub const UNRESOLVED_POLICY_MODE: MaintenanceAutomationMode = MaintenanceAutomationMode::Off;

/// What a row states when an execution owner arm answered with nothing.
///
/// `MaintenanceExecutionOwner` pairs [`MaintenanceExecutionOwner::Owned`]
/// with a `symbol` and [`MaintenanceExecutionOwner::Unavailable`] with a
/// `dependency`, so exactly one of `owner_symbol()` and
/// `unavailable_dependency()` answers for any given entry and this text is
/// unreachable. It is stated rather than left to a panic, because a row that
/// cannot name an owner must not be able to abort the emission that reports
/// the other fourteen.
const UNRECORDED_EXECUTION_OWNER: &str = "unrecorded";

/// The expiry position every preserved maintenance recommendation carries.
///
/// I14.22 requires a preserved recommendation to state its expiry. No owner
/// publishes a maintenance expiry to this daemon — the seam that builds the
/// trigger input holds `expires_at_ms` at `None` and names the absent authority
/// in [`crate::maintenance_trigger_evaluator::UNRESOLVED_AUTHORITIES`] — so the
/// recommendation states that absence instead of inventing a deadline nobody
/// owns. It is recorded here once so all fifteen families report the same exact
/// gap instead of each inventing its own.
pub const UNPUBLISHED_MAINTENANCE_EXPIRY: &str = "no owner publishes a maintenance expiry to eliotd, so this recommendation carries no deadline of its own; it is not dropped silently, because the record it produces is keyed by the family deduplication scope and is reopened when that key changes";

/// The exact identity components that make two maintenance triggers
/// equivalent, and therefore what duplicate suppression compares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceDedupScope {
    /// `family + scope_ref`: at most one active job per family per affected
    /// scope, for the life of that scope.
    FamilyAndScope,
    /// `family + scope_ref + subset_ref`: at most one active job per family,
    /// scope and named affected subset, so two disjoint subsets of one scope
    /// are not suppressed against each other.
    FamilyScopeAndSubset,
    /// `family + scope_ref + resource_generation`: a new generation admits a
    /// fresh job even while a previous one is active, because the previous one
    /// ran under a superseded fence and its result cannot describe the new
    /// generation.
    FamilyScopeAndGeneration,
}

impl MaintenanceDedupScope {
    /// Stable wire name, so the deduplication scope is part of the inspectable
    /// trigger identity rather than an implicit property of a job identity.
    #[must_use]
    pub const fn scope_name(self) -> &'static str {
        match self {
            Self::FamilyAndScope => "FAMILY_SCOPE",
            Self::FamilyScopeAndSubset => "FAMILY_SCOPE_SUBSET",
            Self::FamilyScopeAndGeneration => "FAMILY_SCOPE_GENERATION",
        }
    }

    /// The exact key components the scope compares, for inspection.
    #[must_use]
    pub const fn key_parts(self) -> &'static [&'static str] {
        match self {
            Self::FamilyAndScope => &["family", "scope_ref"],
            Self::FamilyScopeAndSubset => &["family", "scope_ref", "subset_ref"],
            Self::FamilyScopeAndGeneration => &["family", "scope_ref", "resource_generation"],
        }
    }

    /// Builds the canonical deduplication key for one trigger evaluation.
    ///
    /// This is the one key builder: the trigger path, the board lookup and the
    /// job lookup all compare the key it returns, so two evaluations of the
    /// same family, scope, subset and generation coalesce onto one record and
    /// two disjoint subsets (or two generations) never suppress each other.
    /// The key carries no clock, counter or process-local value.
    ///
    /// `FamilyScopeAndSubset` rejects a missing or empty subset identity
    /// rather than coalescing cross-subset work: without the subset the caller
    /// cannot prove two triggers concern disjoint work, so the evaluation
    /// fails closed. `FamilyScopeAndGeneration` renders the typed generation
    /// explicitly, so a generation change invalidates the old key even though
    /// the scope reference already embeds it; invalidating the key does not
    /// settle the older job's possible effects or release its resource
    /// custody, and that obligation is reconciled at adoption before
    /// conflicting work is allowed.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] when the origin or scope
    /// reference is empty, or when the scope is `FamilyScopeAndSubset` and no
    /// non-empty subset identity is supplied.
    pub fn dedup_key(
        &self,
        identity: &MaintenanceDedupIdentity,
    ) -> Result<String, MaintenanceError> {
        if identity.origin.is_empty() {
            return Err(MaintenanceError::InvalidField("dedup.origin"));
        }
        if identity.scope_ref.is_empty() {
            return Err(MaintenanceError::InvalidField("dedup.scope_ref"));
        }
        match self {
            Self::FamilyAndScope => Ok(format!(
                "{scope}:{origin}:{family}:{scope_ref}",
                scope = self.scope_name(),
                origin = identity.origin,
                family = identity.family,
                scope_ref = identity.scope_ref,
            )),
            Self::FamilyScopeAndSubset => {
                let subset = identity
                    .subset_ref
                    .filter(|subset| !subset.is_empty())
                    .ok_or(MaintenanceError::InvalidField("dedup.subset_ref"))?;
                Ok(format!(
                    "{scope}:{origin}:{family}:{scope_ref}:{subset}",
                    scope = self.scope_name(),
                    origin = identity.origin,
                    family = identity.family,
                    scope_ref = identity.scope_ref,
                    subset = subset,
                ))
            }
            Self::FamilyScopeAndGeneration => Ok(format!(
                "{scope}:{origin}:{family}:{scope_ref}@{generation}",
                scope = self.scope_name(),
                origin = identity.origin,
                family = identity.family,
                scope_ref = identity.scope_ref,
                generation = identity.resource_generation,
            )),
        }
    }
}

/// Typed identity a [`MaintenanceDedupScope`] key is built from.
///
/// Every field is carried separately so the trigger path, the board lookup and
/// the job lookup all compare the same canonical key instead of three
/// spellings of it. `subset_ref` is `None` when the trigger site observes no
/// subset identity; `resource_generation` is the live fence generation the
/// evaluation runs under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceDedupIdentity<'a> {
    /// The registered family the trigger concerns.
    pub family: MaintenanceFamily,
    /// Wire name of the trigger event that raised this evaluation.
    pub origin: &'a str,
    /// Affected scope the evaluation runs under.
    pub scope_ref: &'a str,
    /// Named affected subset, when the trigger site observes one.
    pub subset_ref: Option<&'a str>,
    /// Live resource generation the evaluation runs under.
    pub resource_generation: u64,
}

/// Concrete material one trigger evaluation observed, bound separately from
/// every requirement list.
///
/// [`MaintenanceRecommendation::evidence`] states the evidence kinds a future
/// result must carry; this states what this evaluation actually saw. The two
/// are never mixed: this is never filled from the requirement list, and a
/// missing publisher is carried as `None`/empty rather than as an invented
/// value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceObservedEvidence {
    /// Wire name of the trigger event that raised this evaluation.
    pub trigger_event: &'static str,
    /// Evidence identities actually observed at the trigger site.
    pub observed_refs: Vec<String>,
    /// Selected Human policy revision bound to this evaluation, or `None`
    /// while the policy publisher does not exist.
    pub policy_revision: Option<u64>,
}

/// One admission condition a family's start must clear, in I14.22's own
/// vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceCondition {
    /// A route and credentials admitted for unattended operation. I14.22:
    /// "Scheduled/background maintenance may use only service-safe routes and
    /// credentials explicitly admitted for unattended operation."
    ServiceSafeRoute,
    /// An admitted cost/quota budget slice.
    AdmittedBudget,
    /// An active authenticated User Broker session plus a separate
    /// `interactive_maintenance` policy, for subscription-, IDE-, browser- or
    /// desktop-bound work.
    InteractiveUserSession,
    /// No conflicting interactive work exists in the affected scope.
    NoConflictingInteractiveWork,
    /// An approved schedule window, i.e. a real Task Scheduler or Host wake
    /// occurrence rather than a locally invented one.
    ApprovedScheduleWindow,
    /// An explicit authenticated Human UI or CLI request.
    ExplicitHumanRequest,
}

impl MaintenanceCondition {
    /// Stable wire name for the condition.
    #[must_use]
    pub const fn condition_name(self) -> &'static str {
        match self {
            Self::ServiceSafeRoute => "SERVICE_SAFE_ROUTE",
            Self::AdmittedBudget => "ADMITTED_BUDGET",
            Self::InteractiveUserSession => "INTERACTIVE_USER_SESSION",
            Self::NoConflictingInteractiveWork => "NO_CONFLICTING_INTERACTIVE_WORK",
            Self::ApprovedScheduleWindow => "APPROVED_SCHEDULE_WINDOW",
            Self::ExplicitHumanRequest => "EXPLICIT_HUMAN_REQUEST",
        }
    }
}

/// I14.22's separate-authority predicate: some effects need their own
/// route and authority policy even when the maintenance family itself is
/// automatic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceEffectPolicy {
    /// The family's effect is governed by its own maintenance route and needs
    /// no further authority.
    GovernedByMaintenanceRoute,
    /// The family's effect needs a separate route and authority policy; the
    /// exact effect that needs it is named.
    SeparateAuthority {
        /// The effect that requires its own route and authority policy.
        effect: &'static str,
    },
}

impl MaintenanceEffectPolicy {
    /// Whether this family needs a separate route and authority policy.
    #[must_use]
    pub const fn needs_separate_authority(self) -> bool {
        matches!(self, Self::SeparateAuthority { .. })
    }

    /// The effect that needs a separate policy, or the exact statement that
    /// the maintenance route governs it. Never empty.
    #[must_use]
    pub const fn effect_description(self) -> &'static str {
        match self {
            Self::GovernedByMaintenanceRoute => "governed by the maintenance route",
            Self::SeparateAuthority { effect } => effect,
        }
    }
}

/// The eligibility predicates that belong to the family itself rather than to
/// one evaluation: which I14.22 job origins may raise a trigger for it, and
/// whether its route is admitted for unattended operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceEligibility {
    /// The I14.22 job origins that may produce a trigger for this family.
    pub origins: &'static [MaintenanceTrigger],
    /// Whether this family may use a service-safe route with no interactive
    /// User Broker session. I14.22 requires an active User Broker plus a
    /// separate `interactive_maintenance` policy for subscription-, IDE-,
    /// browser- or desktop-bound agents, and forbids retaining a desktop
    /// credential merely to make a schedule look successful.
    pub unattended_safe: bool,
}

/// The real execution owner for a family, or the exact capability that is
/// absent. Both arms are named references a reader can open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceExecutionOwner {
    /// A real first-party execution owner exists at this exact symbol.
    ///
    /// # `Owned` asserts the symbol exists, not that it is called
    ///
    /// This is a recorded name, never a lookup. Nothing in the tree resolves
    /// the string, parses it, or dispatches through it; it is rendered by
    /// [`MaintenanceFamilyEntry::execution_or_dependency`] into the catalog
    /// row, so it is a claim a reader can open and check by hand. A symbol may
    /// therefore be `Owned` and still have no caller anywhere in the tree, and
    /// one such case is recorded honestly today:
    /// [`MaintenanceFamily::SelfQualityDebt`] names
    /// `bins/eliotd/src/experience_runtime.rs::run_experience_quality_event`,
    /// which is a real symbol with no production caller. The name is retained
    /// because it is the intended owner and the family must not be silently
    /// re-pointed, but the row is not evidence that the work runs.
    Owned {
        /// `path::symbol` of the owner.
        symbol: &'static str,
    },
    /// No execution capability exists. The family stays registered and every
    /// start is deterministically blocked on this exact dependency.
    Unavailable {
        /// The exact absent capability, or the exact record that says so.
        dependency: &'static str,
    },
}

impl MaintenanceExecutionOwner {
    /// The `path::symbol` of the owner, when one exists.
    #[must_use]
    pub const fn owner_symbol(self) -> Option<&'static str> {
        match self {
            Self::Owned { symbol } => Some(symbol),
            Self::Unavailable { .. } => None,
        }
    }

    /// The exact unavailable dependency, when no owner exists.
    #[must_use]
    pub const fn unavailable_dependency(self) -> Option<&'static str> {
        match self {
            Self::Owned { .. } => None,
            Self::Unavailable { dependency } => Some(dependency),
        }
    }

    /// Whether a real execution owner exists for this family.
    #[must_use]
    pub const fn is_owned(self) -> bool {
        matches!(self, Self::Owned { .. })
    }
}

/// Where a family's result is observed and what its receipt must carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceResultObservation {
    /// The owner that reads this family's own effect evidence. For a family
    /// with no execution owner this states the absence explicitly rather than
    /// naming nothing.
    pub effect_evidence_owner: &'static str,
    /// The references the family's receipt must carry for the result to be
    /// auditable. I14.22 evaluates every result against recurrence, product or
    /// recovery delta, false changes, cost and operator burden, and completion
    /// of a maintenance job is not on its own evidence that the maintained
    /// subsystem improved, so a receipt carrying none of these is not a
    /// result.
    pub receipt_refs: &'static [&'static str],
}

/// The exact owner inputs or route that still stop a maintenance start from
/// becoming a Durable Job request, one variant per missing capability.
///
/// These are not cautions. Each is a verified absence, and they apply to all
/// fifteen families because the admission they block is the shared I14.22
/// Durable Job admission rather than a per-family one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceAdmissionBlocker {
    /// `eliot_governor::GovernorComposition` exposes only
    /// `owners(&self) -> &GovernorOwners<P>`; there is no `owners_mut`, so
    /// `eliot_maintenance::MaintenanceController::admit(&mut self, ..)` cannot
    /// be reached from `eliotd`.
    /// `MaintenanceController::admit` requires an
    /// `eliot_runtime_contracts::RuntimeLease`; no `bins/eliotd` source
    /// constructs, retains, or renews one.
    RuntimeLease,
    /// `MaintenanceController::admit` requires `budget_ref` and
    /// `max_attempts`; no budget or quota owner publishes either to `eliotd`,
    /// and `crate::maintenance_trigger_evaluator::UNRESOLVED_AUTHORITIES`
    /// already holds `budget_available` at `false` for that reason.
    BudgetAuthority,
    /// The maintenance execution owner EXISTS and is reachable in the build;
    /// what is missing is that its governed plan inputs are unpublished, so the
    /// request cannot be formed.
    ///
    /// `eliot-dreamer` admits the class at the taxonomy level
    /// (`bins/eliot-dreamer/src/lib.rs::refuse_unsupported_job_class` returns
    /// `Ok(())` for it, and `dispatch_class` returns
    /// `ClassArm::MaintenanceAdmitted`) but REFUSES it at the dispatch stage:
    /// `bins/eliot-dreamer/src/dispatch_stage.rs::dispatch_admitted` matches
    /// `JobClass::Maintenance` and returns
    /// `DreamerError::InvalidAdmission(MAINTENANCE_INPUTS_REFUSAL)`.
    ///
    /// The reason recorded there is the exact unavailable dependency: the native
    /// owner is `eliot-dreamer-maintenance-plan`'s `propose_maintenance_plan`
    /// (`crates/smart/eliot-dreamer-maintenance-plan/src/lib.rs`, a workspace
    /// member), and it takes its own Governor-owned plan inputs -
    /// `MaintenanceObjective`, `TriggerEvidence`, `BudgetSlice`, `MaintenancePolicy`,
    /// `PriorHistory` and the planned-operation/expected-delta/verifier material.
    /// None of that is constructible from admitted binary material, and no owner
    /// publishes it to `eliotd`, so synthesizing it here would be self-issued
    /// authority. This is therefore a PUBLICATION gap over an existing owner, not
    /// a missing capability.
    ///
    /// Secondary and still true: the only Durable Job wire `eliotd` reaches is
    /// `eliot.kernel.dreamer-job`
    /// (`bins/eliotd/src/dreamer_admission.rs::DREAMER_JOB_WIRE_ID`), whose
    /// `JobOperation::Submit` validates an `AdmissionRef` and two
    /// `OpaqueContentRef`s bound to one `WorkScopeBinding`
    /// (`crates/foundation/eliot-protocol/src/dreamer_job.rs::JobSubmission::validate`).
    /// Those refs are a consequence of the publication gap above, not its cause,
    /// so they are recorded as secondary rather than as the blocker.
    MaintenanceJobWire,
}

impl MaintenanceAdmissionBlocker {
    /// The exact missing symbol or absent capability this blocker names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeLease => {
                "eliot_runtime_contracts::RuntimeLease: eliot_maintenance::MaintenanceController::admit requires one and no bins/eliotd source constructs, retains, or renews it"
            }
            Self::BudgetAuthority => {
                "maintenance budget_ref/max_attempts: no budget or quota owner publishes them to eliotd (UNRESOLVED_AUTHORITIES holds budget_available=false)"
            }
            Self::MaintenanceJobWire => {
                "eliot-dreamer refuses JobClass::Maintenance at dispatch (bins/eliot-dreamer/src/dispatch_stage.rs::dispatch_admitted -> DreamerError::InvalidAdmission(MAINTENANCE_INPUTS_REFUSAL)) although the class is admitted at the taxonomy level (bins/eliot-dreamer/src/lib.rs::refuse_unsupported_job_class returns Ok() and dispatch_class returns ClassArm::MaintenanceAdmitted): the native owner eliot_dreamer_maintenance_plan::propose_maintenance_plan exists as a workspace member but its Governor-owned plan inputs (MaintenanceObjective, TriggerEvidence, BudgetSlice, MaintenancePolicy, PriorHistory) are published by no owner to eliotd and are not constructible from admitted binary material, so no maintenance admission owner can form the request; this is a publication gap over an existing owner, not a missing capability. Secondary: eliot.kernel.dreamer-job (bins/eliotd/src/dreamer_admission.rs::DREAMER_JOB_WIRE_ID) is the only Durable Job wire eliotd reaches and its JobOperation::Submit requires an AdmissionRef plus two OpaqueContentRef bound to one WorkScopeBinding - a consequence of the publication gap, not its cause"
            }
        }
    }
}

/// Every family shares the same Durable Job admission blockers, because the
/// admission they block is shared.
pub const DURABLE_JOB_ADMISSION_BLOCKERS: &[MaintenanceAdmissionBlocker] = &[
    MaintenanceAdmissionBlocker::RuntimeLease,
    MaintenanceAdmissionBlocker::BudgetAuthority,
    MaintenanceAdmissionBlocker::MaintenanceJobWire,
];

/// Where a registered family's start must go.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceRoute {
    /// A real first-party execution owner exists at this exact symbol. The
    /// start must be submitted to it as a Durable Job request once `eliotd`
    /// holds that route; this catalog never executes the family and never calls
    /// the owner directly.
    DurableJobRequest {
        /// `path::symbol` of the real owner.
        owner: &'static str,
        /// The exact route `eliotd` does not hold today.
        missing_route: &'static str,
    },
    /// No execution capability exists for this family. The family stays
    /// registered and every start is deterministically blocked on this exact
    /// dependency.
    Blocked {
        /// The exact absent capability.
        dependency: &'static str,
    },
}

impl MaintenanceRoute {
    /// The shared blockers that apply to every start, whatever the route.
    #[must_use]
    pub const fn admission_blockers(&self) -> &'static [MaintenanceAdmissionBlocker] {
        DURABLE_JOB_ADMISSION_BLOCKERS
    }

    /// Whether this route admits a start today.
    ///
    /// It admits none yet, and a `Blocked` route admits none ever through this
    /// function however the shared list below changes. I14.22 routes every
    /// start through a Durable Job request, and
    /// [`DURABLE_JOB_ADMISSION_BLOCKERS`] names every symbol missing from
    /// that request's path out of `eliotd`. Clearing that list is necessary
    /// but not sufficient: the route must also be an implemented family route,
    /// so removing the common blockers in a later integration cannot make an
    /// unavailable family look startable. Per-evaluation admission (the
    /// Governor owner's current decision) is resolved separately in
    /// [`ResolvedMaintenanceCapability`]; the catalog itself grants neither.
    #[must_use]
    pub const fn admits_start(&self) -> bool {
        match self {
            Self::DurableJobRequest { .. } => self.admission_blockers().is_empty(),
            Self::Blocked { .. } => false,
        }
    }

    /// The `path::symbol` of the owner this route targets, or the exact absent
    /// capability when there is no owner. Never empty.
    #[must_use]
    pub const fn target(&self) -> &'static str {
        match *self {
            Self::DurableJobRequest { owner, .. } => owner,
            Self::Blocked { dependency } => dependency,
        }
    }

    /// The exact route `eliotd` does not hold, or the same absent capability
    /// when the family is blocked outright. Never empty.
    #[must_use]
    pub const fn missing(&self) -> &'static str {
        match *self {
            Self::DurableJobRequest { missing_route, .. } => missing_route,
            Self::Blocked { dependency } => dependency,
        }
    }
}

/// Per-evaluation resolved capability, distinct from catalog metadata.
///
/// [`MaintenanceRoute`] is catalog metadata: it says where a family's start
/// must go. It grants nothing by itself. Whether a start is admitted today is
/// resolved per evaluation from the Governor owner's own decision plus the
/// shared wiring state, and this value carries that resolution next to the
/// route instead of folding it into the route. A `Blocked` route never
/// resolves to startable no matter what the other inputs say, so clearing the
/// shared wiring blockers in a later integration cannot enable a family that
/// has no execution owner; unavailable families stay registered with their
/// exact residual.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedMaintenanceCapability {
    /// The Governor owner's per-evaluation admission: only a `Start` decision
    /// admits one job from this evaluation. A `Start` is produced only when
    /// the evaluator's policy, route, budget and session gates all admit, so
    /// this carries the current policy/budget/owner admission the route alone
    /// cannot state. The runtime lease itself is admitted at adopt time by the
    /// narrow Governor maintenance admission, not here.
    pub governor_admits_job: bool,
    /// Whether every shared Durable Job wiring blocker is cleared.
    pub shared_wiring_clear: bool,
}

impl ResolvedMaintenanceCapability {
    /// Resolves the capability for one Governor decision. Pure: no I/O, no
    /// clock, no default.
    #[must_use]
    pub const fn resolve(decision: &AutomationTriggerDecision) -> Self {
        Self {
            governor_admits_job: decision.admits_job,
            shared_wiring_clear: DURABLE_JOB_ADMISSION_BLOCKERS.is_empty(),
        }
    }

    /// Whether a start is admitted today for this route under this resolution.
    ///
    /// Requires all three at once: an implemented family route, the Governor
    /// owner's current admission, and clear shared wiring. The catalog grants
    /// none of them.
    #[must_use]
    pub fn admits_start(&self, route: &MaintenanceRoute) -> bool {
        matches!(route, MaintenanceRoute::DurableJobRequest { .. })
            && self.governor_admits_job
            && self.shared_wiring_clear
    }
}

/// The cost class an admitted job for a family carries.
///
/// I14.22 requires each Durable Job to carry a budget, and requires the
/// recommendation preserved when a start is refused to state its cost. Both are
/// answered from the family's own registered conditions rather than from a
/// runtime resource reading, so the answer is a pure function of the catalog
/// and never a measurement that could differ between two identical catalogs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceCostClass {
    /// This family does not require an admitted budget slice, so its route and
    /// effect policy are the whole cost condition.
    NoAdmittedBudgetRequired,
    /// An admitted budget slice is one of this family's required conditions, so
    /// a start may not proceed on a route that spends admitted model or swarm
    /// budget without one.
    AdmittedBudgetRequired,
}

impl MaintenanceCostClass {
    /// Stable wire name, so the cost class is inspectable beside the mode.
    #[must_use]
    pub const fn class_name(self) -> &'static str {
        match self {
            Self::NoAdmittedBudgetRequired => "NO_ADMITTED_BUDGET_REQUIRED",
            Self::AdmittedBudgetRequired => "ADMITTED_BUDGET_REQUIRED",
        }
    }
}

/// One registered I14.22 family with everything I14.22 requires the registry
/// to record about it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceFamilyEntry {
    /// The registered family. This is the value the catalog is keyed by and
    /// the only place the family is named.
    pub family: MaintenanceFamily,
    /// The I14.22 sentence this entry registers.
    pub obligation: &'static str,
    /// The automation mode selected for this family.
    pub mode: MaintenanceAutomationMode,
    /// The family's own eligibility predicates.
    pub eligibility: MaintenanceEligibility,
    /// Whether the family's effect needs its own route and authority policy.
    pub effect_policy: MaintenanceEffectPolicy,
    /// The route, capability and session conditions a start must clear.
    pub conditions: &'static [MaintenanceCondition],
    /// The idempotency and deduplication scope.
    pub dedup: MaintenanceDedupScope,
    /// The execution owner, or the exact capability that is absent.
    pub owner: MaintenanceExecutionOwner,
    /// Where this family's result is observed.
    pub observation: MaintenanceResultObservation,
}

/// The ONE actionable recommendation I14.22 requires a refused or deferred
/// maintenance start to preserve, with each of the elements I14.22 names held as
/// its own typed field.
///
/// I14.22: "ELIOT preserves one actionable recommendation with reason, evidence,
/// expected benefit, cost, expiry and safe deferral consequence. It does not
/// repeatedly notify or pretend maintenance occurred." Every field below is a
/// pure function of the family's registered entry plus the route the entry
/// resolves to. None is written per family, so the recommendation cannot
/// contradict the mode, the conditions, the owner, the deduplication scope or
/// the admission blockers it is rendered from, and there is exactly one of them
/// per family rather than a list of vague hints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceRecommendation {
    /// The single action a Human or an owning component is required to take.
    /// Never empty, and never a list.
    pub required_action: String,
    /// Why the family does not start now: the exact absent route or the exact
    /// absent execution owner, never a general cause.
    pub reason: String,
    /// The receipt references a result for this family must carry, so the
    /// recommendation is anchored to auditable material rather than to a wish.
    pub evidence: &'static [&'static str],
    /// What discharging this family's obligation buys. It is the obligation
    /// itself, which is the I14.22 sentence that names the work.
    pub expected_benefit: &'static str,
    /// The cost class an admitted job for this family carries.
    pub cost: MaintenanceCostClass,
    /// Whether the family's effect additionally needs its own route and
    /// authority policy. I14.22: paid model calls, swarms, destructive
    /// forgetting or purge, configuration publication, software updates and
    /// migrations "require their separate route/authority policy even when the
    /// maintenance family is automatic", so clearing the maintenance route is
    /// not by itself sufficient for these families.
    pub effect_policy: MaintenanceEffectPolicy,
    /// The expiry position. It names the absent owner instead of inventing a
    /// deadline, because no owner publishes a maintenance expiry to `eliotd`.
    pub expiry: &'static str,
    /// The safe consequence of leaving the work unstarted, derived from the
    /// family's own deduplication scope.
    pub deferral_consequence: String,
}

impl MaintenanceRecommendation {
    /// Renders the one recommendation as the single operator-facing sentence
    /// the durable record and the operational diagnostics both carry.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{action} Reason: {reason}. Expected benefit: {benefit}. Cost: {cost}. \
             Effect policy: {effect}. Evidence a result must carry: {evidence}. \
             Expiry: {expiry}. Safe deferral: {deferral}.",
            action = self.required_action,
            reason = self.reason,
            benefit = self.expected_benefit,
            cost = self.cost.class_name(),
            effect = self.effect_policy.effect_description(),
            evidence = self.evidence.join("+"),
            expiry = self.expiry,
            deferral = self.deferral_consequence,
        )
    }
}

/// The durable, inspectable decision the catalog records for one triggered
/// family.
///
/// I14.22 makes the derived `AutomationTriggerDecision` inspectable and says it
/// "may emit a decision, Human-board item or Durable Job request". The
/// Governor-owned evaluator produces the decision and the reason; this value is
/// the catalog's half of the same record, and it is what a later reader needs
/// in order to answer, for a family that could not start, which mode was
/// selected, which owner or exact absent dependency was resolved, whether the
/// route admits a start, and what the one actionable recommendation is. Without
/// it the only carrier is a log line, which I14.22's own observability rules
/// treat as rotatable rather than as the durable record.
///
/// No field here is a second decision or reason vocabulary: the Governor's own
/// [`AutomationDecision`] and [`DecisionReason`] are carried through unchanged,
/// and the catalog contributes only the registered facts and the resolved route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceFamilyDecision {
    /// The registered family this decision concerns.
    pub family: MaintenanceFamily,
    /// The I14.22 obligation this decision discharges once it starts.
    pub obligation: &'static str,
    /// The automation mode selected for this family.
    pub mode: MaintenanceAutomationMode,
    /// The family's own eligibility predicates.
    pub eligibility: MaintenanceEligibility,
    /// The route, capability and session conditions a start must clear.
    pub conditions: &'static [MaintenanceCondition],
    /// The idempotency and deduplication scope the trigger identity is keyed by.
    pub dedup: MaintenanceDedupScope,
    /// Where this family's start must go, or the exact capability that is absent.
    pub route: MaintenanceRoute,
    /// Whether that route admits a start today.
    ///
    /// Resolved per evaluation from the route plus the Governor owner's own
    /// decision and the shared wiring state (see
    /// [`ResolvedMaintenanceCapability`]), never from the catalog alone.
    pub admits_start: bool,
    /// The per-evaluation capability resolution behind `admits_start`, kept
    /// beside the route so a reader can see which half denied the start.
    pub resolved_capability: ResolvedMaintenanceCapability,
    /// The shared Durable Job admission blockers.
    pub admission_blockers: &'static [MaintenanceAdmissionBlocker],
    /// Where this family's result is observed.
    pub observation: MaintenanceResultObservation,
    /// The one actionable, reasoned recommendation for this family.
    pub recommendation: MaintenanceRecommendation,
    /// The Governor owner's own deterministic action, carried unchanged.
    pub governor_decision: AutomationDecision,
    /// The Governor owner's own stable reason, carried unchanged.
    pub governor_reason: DecisionReason,
    /// Whether the Governor owner admits one job from this decision.
    pub governor_admits_job: bool,
    /// The Governor owner's board/job receipt for this decision, when the
    /// decision admitted one. `None` states explicitly that no job was
    /// admitted on this evaluation; it is never filled from a requirement
    /// list or invented.
    pub durable_job_ref: Option<String>,
    /// The trigger event that raised this evaluation, bound separately from
    /// the trigger identity. `None` states explicitly that the binding leg did
    /// not observe the event (the notification projection re-resolves the
    /// decision without the trigger site beside it).
    pub trigger_event: Option<String>,
    /// Evidence identities actually observed at the trigger site. Empty states
    /// explicitly that none was bound on this leg; these are never filled
    /// from [`MaintenanceRecommendation::evidence`], which states what a
    /// future result must carry rather than what was already observed.
    pub observed_evidence_refs: Vec<String>,
    /// Selected Human policy revision bound to this evaluation. `None` states
    /// explicitly that the policy publisher does not exist; it is never a
    /// defaulted revision.
    pub policy_revision: Option<u64>,
    /// The trigger identity the deduplication scope is applied to.
    pub trigger_id: String,
    /// The affected scope the decision ran under.
    pub scope_ref: String,
}

impl MaintenanceFamilyDecision {
    /// Binds what the trigger site actually observed, separately from the
    /// Governor projection and from every requirement list.
    ///
    /// [`MaintenanceFamilyEntry::decide`] stays a pure projection of the
    /// Governor decision, so the legs that re-resolve it without the trigger
    /// site beside them (the notification projection) keep explicit-missing
    /// evidence instead of invented evidence. The trigger path calls this
    /// once with what it really saw; nothing else may call it.
    pub fn bind_observed(&mut self, observed: MaintenanceObservedEvidence) {
        self.trigger_event = Some(observed.trigger_event.to_owned());
        self.observed_evidence_refs = observed.observed_refs;
        self.policy_revision = observed.policy_revision;
    }
}

impl MaintenanceFamilyDecision {
    /// The execution owner when one exists, or the exact absent dependency.
    ///
    /// Never empty, so a reader never has to distinguish "no owner recorded"
    /// from "owner withheld".
    #[must_use]
    pub const fn owner_or_dependency(&self) -> &'static str {
        self.route.target()
    }

    /// The `path::symbol` of the execution owner, when one exists.
    #[must_use]
    pub const fn execution_owner(&self) -> Option<&'static str> {
        match self.route {
            MaintenanceRoute::DurableJobRequest { owner, .. } => Some(owner),
            MaintenanceRoute::Blocked { .. } => None,
        }
    }

    /// The exact condition names a start must clear, for inspection.
    #[must_use]
    pub fn condition_names(&self) -> Vec<&'static str> {
        self.conditions
            .iter()
            .copied()
            .map(MaintenanceCondition::condition_name)
            .collect()
    }
}

impl MaintenanceFamilyEntry {
    /// Resolves where this family's start must go. Deterministic, performs no
    /// I/O, and never returns a default: the family is either routed to a real
    /// named owner or blocked on an exact named dependency.
    #[must_use]
    pub fn start_route(&self) -> MaintenanceRoute {
        match self.owner {
            MaintenanceExecutionOwner::Owned { symbol } => MaintenanceRoute::DurableJobRequest {
                owner: symbol,
                missing_route: self.missing_route(),
            },
            MaintenanceExecutionOwner::Unavailable { dependency } => {
                MaintenanceRoute::Blocked { dependency }
            }
        }
    }

    /// The exact route `eliotd` does not hold for this family.
    ///
    /// It is stated per family rather than derived from the owner symbol,
    /// because the owner symbol says *who* executes while this says *through
    /// which absent operation* `eliotd` cannot reach them.
    #[must_use]
    fn missing_route(&self) -> &'static str {
        match self.family {
            MaintenanceFamily::BackupRestoreRehearsal => {
                "eliotd publishes no backup capture or verify operation to the Kernel; the daemon's authenticated operations are owner-bundle publish, owner-revision initialize and readback, query_grant_closure_canonical_receipts, daemon_ready, daemon startup evidence, supervision progress, daemon_fatal and local_read_claim/result plus the K2 eliot.kernel.dreamer-job route, and bins/eliotd/src/daemon_kernel_port_adapters.rs reaches only the load_durable_job and save_durable_job maintenance ledger"
            }
            MaintenanceFamily::BlobGcReachability => {
                "eliotd holds no route to the blob store client: BlobStoreClient::gc is the store-neutral closed operation and crates/storage/eliot-blob/src/lib.rs::BlobStoreService is its only admitted implementation, with reachability authority held by BlobLiveSetPort, and eliotd publishes no Kernel or store operation that reaches any of them; the only blob-side classification a daemon-side caller could name is bins/eliot-kernel/src/blob_store_controller.rs::BlobDemand::GarbageCollection, which is process-local to eliot-kernel"
            }
            MaintenanceFamily::ProjectionIndexRebuild => {
                "bins/eliot-store-surreal/src/canonical_event.rs::DoctorRebuildAuthority::doctor_authorize is scoped eliot-doctor/recovery; eliotd is not that scope and no authenticated eliotd operation constructs the authority"
            }
            MaintenanceFamily::CueConceptGraph => {
                "eliotd holds no durable job route to crates/smart/eliot-cue-index, whose builder is a candidate producer that does not authenticate admission, publish a snapshot, or run activation"
            }
            MaintenanceFamily::DreamerCuration => {
                "the K2 eliot.kernel.dreamer-job route admits JobOperation::Submit only with an AdmissionRef and two OpaqueContentRef bound to one WorkScopeBinding, none of which any maintenance admission owner mints for a MaintenanceFamily; bins/eliot-dreamer/src/dispatch_stage.rs additionally refuses JobClass::Maintenance with MAINTENANCE_INPUTS_REFUSAL"
            }
            MaintenanceFamily::IntegrationCapabilitySurvey => {
                "the capability evidence read runs in-line on the daemon's own startup and route gate through bins/eliotd/src/capability_evidence_wiring.rs::GovernorCapabilityAdmission, not from a maintenance Durable Job request"
            }
            MaintenanceFamily::DerivedIndexRebuild => {
                "eliotd holds no durable job route to crates/eliot-engine::CachedDerivationService, which needs a DerivedCacheStore and a TrustPolicy the daemon does not own"
            }
            MaintenanceFamily::GrantDisclosureClosure => {
                "the closure pass runs in-line from the daemon's polled owner feed through bins/eliotd/src/owner_feed.rs::maintain_owner_feed rather than from a maintenance Durable Job request, and no single file may be both the owner and the Durable Job request path"
            }
            MaintenanceFamily::SelfQualityDebt => {
                "no maintenance Durable Job request is the route for this family, and there is currently no in-line route either: bins/eliotd/src/experience_runtime.rs::run_experience_quality_event is the intended in-line leg and has no production caller, so this family has no admitted execution route at all"
            }
            MaintenanceFamily::ResearchExchangeCleanup => {
                "eliotd holds no durable job route to crates/research/eliot-research-exchange::GovernedExchange; the exchange is driven by bins/eliot-mod-research::submit in a separate composition root and eliotd publishes no operation that reaches it"
            }
            MaintenanceFamily::OutboxReceiptReconciliation
            | MaintenanceFamily::CalibrationUnderstanding
            | MaintenanceFamily::SecurityDependencyScan
            | MaintenanceFamily::SessionEpisodeRetrieval
            | MaintenanceFamily::DonorConformance => {
                "no execution owner is admitted for this family, so there is no route to name"
            }
        }
    }

    /// The exact I14.22 origin names that may raise a trigger, for inspection.
    #[must_use]
    pub fn origin_names(&self) -> Vec<&'static str> {
        self.eligibility
            .origins
            .iter()
            .map(|origin| match origin {
                MaintenanceTrigger::Human => "HUMAN",
                MaintenanceTrigger::Dreamer => "DREAMER",
                MaintenanceTrigger::WatchdogProblem => "WATCHDOG_PROBLEM",
                MaintenanceTrigger::Onboarding => "ONBOARDING",
                MaintenanceTrigger::Policy => "POLICY",
                MaintenanceTrigger::Installation => "INSTALLATION",
            })
            .collect()
    }

    /// The one execution-or-absence statement this entry carries.
    ///
    /// I03.04 is load-bearing here: "Registry stores evidence-linked facts, not
    /// vendor labels and booleans." The statement is therefore the named
    /// `path::symbol` or the exact absent capability itself, never a label and
    /// never a bare `owned: true` a reader would have to resolve elsewhere.
    /// [`MaintenanceExecutionOwner::is_owned`] is the fact that decides which
    /// of the two accessors is the evidence, and the accessors are what supply
    /// the text, so owned and unavailable families cannot disagree here.
    #[must_use]
    pub fn execution_or_dependency(&self) -> String {
        if self.owner.is_owned() {
            format!(
                "owner={owner}",
                owner = self
                    .owner
                    .owner_symbol()
                    .unwrap_or(UNRECORDED_EXECUTION_OWNER)
            )
        } else {
            format!(
                "unavailable_dependency={dependency}",
                dependency = self
                    .owner
                    .unavailable_dependency()
                    .unwrap_or(UNRECORDED_EXECUTION_OWNER)
            )
        }
    }

    /// One row of the inspectable catalog table.
    ///
    /// Exactly the five facts A1 names for each family: which registered family
    /// this is, which `MaintenanceAutomationMode` is selected for it, the
    /// execution owner or the exact capability that is absent, whether the
    /// resolved route admits a start today, and the deduplication scope that
    /// coalesces repeated triggers of it. Nothing else is rendered, so a row
    /// cannot drift from the entry it is rendered from.
    #[must_use]
    pub fn catalog_row(&self) -> String {
        let route = self.start_route();
        format!(
            "{family} mode={mode} {execution} admits_start={admits_start} dedup_scope={dedup}",
            family = self.family,
            mode = selected_mode_name(self.mode),
            execution = self.execution_or_dependency(),
            admits_start = route.admits_start(),
            dedup = self.dedup.scope_name(),
        )
    }

    /// The cost class an admitted job for this family carries, read from the
    /// family's own required conditions.
    #[must_use]
    pub fn cost_class(&self) -> MaintenanceCostClass {
        if self
            .conditions
            .contains(&MaintenanceCondition::AdmittedBudget)
        {
            MaintenanceCostClass::AdmittedBudgetRequired
        } else {
            MaintenanceCostClass::NoAdmittedBudgetRequired
        }
    }

    /// The one actionable, reasoned recommendation for a Human or an owning
    /// component.
    ///
    /// It is built from the typed fields rather than written per family, so it
    /// can never contradict the mode, the conditions, the owner, or the
    /// blockers. I14.22 requires exactly one actionable recommendation with a
    /// reason, evidence, expected benefit, cost, expiry and a safe deferral
    /// consequence, and forbids repeated notification or pretending maintenance
    /// occurred; each of those six is a field of the returned value.
    #[must_use]
    pub fn recommendation(&self) -> MaintenanceRecommendation {
        let route = self.start_route();
        let (required_action, reason) = match route {
            MaintenanceRoute::DurableJobRequest { owner, .. } => (
                format!(
                    "Submit a maintenance Durable Job request for {family} to its execution owner {owner} once that route is reachable.",
                    family = self.family,
                ),
                format!(
                    "{family} has a real execution owner but eliotd holds no route to it: {missing}",
                    family = self.family,
                    missing = route.missing(),
                ),
            ),
            MaintenanceRoute::Blocked { .. } => (
                format!(
                    "Provide an execution owner for {family}, then submit a maintenance Durable Job request for it.",
                    family = self.family,
                ),
                format!(
                    "{family} is registered and has no execution owner at all: {dependency}",
                    family = self.family,
                    dependency = route.target(),
                ),
            ),
        };
        MaintenanceRecommendation {
            required_action,
            reason,
            evidence: self.observation.receipt_refs,
            expected_benefit: self.obligation,
            cost: self.cost_class(),
            effect_policy: self.effect_policy,
            expiry: UNPUBLISHED_MAINTENANCE_EXPIRY,
            deferral_consequence: format!(
                "the trigger identity is keyed by {keys}, so repeated blocked starts of this family coalesce onto one record instead of re-notifying, the maintenance debt stays durable and is surfaced on the next eligible startup, and nothing reports this family as maintained",
                keys = self.dedup.key_parts().join("+"),
            ),
        }
    }

    /// The durable, inspectable decision for one triggered family.
    ///
    /// This is the catalog's half of the record the Governor owner's decision
    /// belongs to, and it stays a projection of that decision: no I/O, no
    /// probe, no clock, and no default. The Governor stays the single producer
    /// of the decision and the reason; this only resolves the route, the
    /// per-evaluation capability, the owner or the exact unavailable
    /// dependency, the board/job receipt the decision carried, and the one
    /// recommendation that goes with them. What the trigger site observed
    /// (the event, the observed evidence identities, the selected policy
    /// revision) is bound separately afterwards through
    /// [`MaintenanceFamilyDecision::bind_observed`], never projected from the
    /// requirement lists.
    #[must_use]
    pub fn decide(&self, decision: &AutomationTriggerDecision) -> MaintenanceFamilyDecision {
        let route = self.start_route();
        let resolved_capability = ResolvedMaintenanceCapability::resolve(decision);
        MaintenanceFamilyDecision {
            family: self.family,
            obligation: self.obligation,
            mode: self.mode,
            eligibility: self.eligibility,
            conditions: self.conditions,
            dedup: self.dedup,
            admits_start: resolved_capability.admits_start(&route),
            resolved_capability,
            admission_blockers: route.admission_blockers(),
            route,
            observation: self.observation,
            recommendation: self.recommendation(),
            governor_decision: decision.decision,
            governor_reason: decision.reason,
            governor_admits_job: decision.admits_job,
            durable_job_ref: decision.durable_job_ref.clone(),
            trigger_event: None,
            observed_evidence_refs: Vec::new(),
            policy_revision: None,
            trigger_id: decision.trigger_id.clone(),
            scope_ref: decision.scope_ref.clone(),
        }
    }

    /// Records the deterministic route for one triggered family.
    ///
    /// The Governor stays the single producer of the decision: this only reads
    /// the decision it already made and adds the catalog's half of the record,
    /// namely the selected mode, the deduplication scope, the required
    /// conditions, the route, the owner or the exact unavailable dependency,
    /// the exact missing route, the shared Durable Job admission blockers, and
    /// one actionable recommendation. That is what makes a triggered family
    /// inspectable instead of silently ignored, and it is emitted on the same
    /// `eliotd::diagnostics` target the rest of the daemon uses.
    ///
    /// Every field emitted here is read off the [`MaintenanceFamilyDecision`]
    /// that [`MaintenanceFamilyEntry::decide`] resolves, plus the observed
    /// evidence the trigger site binds through
    /// [`MaintenanceFamilyDecision::bind_observed`], so the operational line
    /// and the durable decision value cannot report different facts about the
    /// same trigger. The line itself is a rotating operational log; the decision
    /// value is what a later durable record carries.
    ///
    /// The receipt references below are named `required_receipt_refs` on
    /// purpose: they are the references a future result for this family must
    /// carry, never receipts already observed. What this evaluation actually
    /// saw travels in the separate `observed_evidence_refs`, `trigger_event`
    /// and `policy_revision` fields, and the board/job receipt in
    /// `durable_job_ref`; each missing binding is stated explicitly rather
    /// than projected from the requirement list.
    pub fn record_start_route(
        &self,
        decision: &AutomationTriggerDecision,
        observed: MaintenanceObservedEvidence,
    ) -> MaintenanceFamilyDecision {
        let mut recorded = self.decide(decision);
        recorded.bind_observed(observed);
        let route = recorded.route;
        let blockers = admission_blocker_text(recorded.admission_blockers);
        let observed_refs = recorded.observed_evidence_refs.join("+");
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.maintenance_family_route",
            service = SERVICE_NAME,
            family = %recorded.family,
            obligation = recorded.obligation,
            mode = ?recorded.mode,
            dedup_scope = recorded.dedup.scope_name(),
            dedup_key = ?recorded.dedup.key_parts(),
            conditions = %recorded.condition_names().join("+"),
            origins = %self.origin_names().join("+"),
            unattended_safe = recorded.eligibility.unattended_safe,
            separate_authority = self.effect_policy.needs_separate_authority(),
            route = ?route,
            owner_or_dependency = recorded.owner_or_dependency(),
            execution_owner = ?recorded.execution_owner(),
            missing_route = route.missing(),
            admits_start = recorded.admits_start,
            shared_wiring_clear = recorded.resolved_capability.shared_wiring_clear,
            admission_blockers = %blockers,
            cost_class = recorded.recommendation.cost.class_name(),
            observation_path = SYSTEM_OBSERVATION_PATH,
            effect_evidence_owner = recorded.observation.effect_evidence_owner,
            required_receipt_refs = %recorded.observation.receipt_refs.join("+"),
            trigger_event = recorded.trigger_event.as_deref().unwrap_or("unobserved"),
            observed_evidence_refs = %if observed_refs.is_empty() { "unobserved" } else { &observed_refs },
            policy_revision = ?recorded.policy_revision,
            durable_job_ref = recorded.durable_job_ref.as_deref().unwrap_or("unrecorded"),
            governor_decision = ?recorded.governor_decision,
            governor_reason = ?recorded.governor_reason,
            governor_admits_job = recorded.governor_admits_job,
            trigger = %crate::diagnostics::sanitize_identity(&recorded.trigger_id),
            scope = %crate::diagnostics::sanitize_identity(&recorded.scope_ref),
            recommendation = %recorded.recommendation.text(),
        );
        recorded
    }
}

/// Renders one closed maintenance discriminator in the wire form its own owner
/// declares.
///
/// `eliot_maintenance::MaintenanceAutomationMode` declares
/// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` and implements no `Display`,
/// so this reads the owner's own declared spelling through the same
/// serialization contract the canonical notification emitter already uses
/// ([`crate::notification_state_emit`]) rather than restating a second spelling
/// here. The catalog therefore still defines no mode, decision, reason or family
/// vocabulary of its own, which is the property its module header claims.
fn selected_mode_name(mode: MaintenanceAutomationMode) -> String {
    serde_json::to_value(mode)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "no declared wire name".to_owned())
}

/// Joins the shared Durable Job admission blockers into one inspectable line.
///
/// This is a complete record, not the recommendation: the recommendation names
/// ONE binding dependency, and this line is where the remaining shared blockers
/// stay inspectable.
fn admission_blocker_text(blockers: &[MaintenanceAdmissionBlocker]) -> String {
    blockers
        .iter()
        .copied()
        .map(MaintenanceAdmissionBlocker::as_str)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Builds a [`MaintenanceExecutionOwner`] for a real owner symbol, or for an
/// exactly named absent capability.
macro_rules! owned_by {
    ($symbol:literal) => {
        MaintenanceExecutionOwner::Owned { symbol: $symbol }
    };
    (unavailable: $dependency:literal) => {
        MaintenanceExecutionOwner::Unavailable {
            dependency: $dependency,
        }
    };
}

/// Builds a [`MaintenanceEffectPolicy`].
macro_rules! effect_policy {
    (governed) => {
        MaintenanceEffectPolicy::GovernedByMaintenanceRoute
    };
    ($effect:literal) => {
        MaintenanceEffectPolicy::SeparateAuthority { effect: $effect }
    };
}

/// Declares every registered I14.22 family exactly once.
///
/// The single invocation below is the whole catalog. From it the macro
/// generates one constant per family, the exhaustive [`entry_for`] match, the
/// [`ALL`] table, and [`REGISTERED_FAMILY_COUNT`], so a new
/// [`MaintenanceFamily`] variant is a compile error here rather than a silently
/// unregistered obligation.
macro_rules! maintenance_family_catalog {
    ($(
        $ident:ident : $variant:ident => {
            obligation: $obligation:literal,
            unattended: $unattended:literal,
            origins: [$($origin:ident),+ $(,)?],
            effect: $effect:expr,
            conditions: [$($condition:ident),+ $(,)?],
            dedup: $dedup:ident,
            owner: $owner:expr,
            observation: $observation:literal,
            receipt: [$($receipt:literal),+ $(,)?],
        }
    )+) => {
        $(
            const $ident: MaintenanceFamilyEntry = MaintenanceFamilyEntry {
                family: MaintenanceFamily::$variant,
                obligation: $obligation,
                mode: UNRESOLVED_POLICY_MODE,
                eligibility: MaintenanceEligibility {
                    origins: &[$(MaintenanceTrigger::$origin),+],
                    unattended_safe: $unattended,
                },
                effect_policy: $effect,
                conditions: &[$(MaintenanceCondition::$condition),+],
                dedup: MaintenanceDedupScope::$dedup,
                owner: $owner,
                observation: MaintenanceResultObservation {
                    effect_evidence_owner: $observation,
                    receipt_refs: &[$($receipt),+],
                },
            };
        )+

        /// The family names this catalog registers, used only to derive the
        /// count so the two cannot disagree.
        const REGISTERED_FAMILY_NAMES: &[&'static str] = &[$( stringify!($variant) ),+];

        /// The number of families the catalog registers. Generated from the one
        /// list below, so it cannot disagree with [`ALL`].
        pub const REGISTERED_FAMILY_COUNT: usize = REGISTERED_FAMILY_NAMES.len();

        /// Every registered I14.22 family, each exactly once, in the order
        /// [`MaintenanceFamily`] declares them.
        pub const ALL: [MaintenanceFamilyEntry; REGISTERED_FAMILY_COUNT] = [$($ident),+];

        /// Returns the registered entry for one family.
        ///
        /// Total by construction: the generated match is exhaustive over
        /// [`MaintenanceFamily`], so no family can be missing, and each arm
        /// names one distinct entry. The assertion catches the only remaining
        /// authoring mistake, an arm pointing at another family's constant.
        #[must_use]
        pub fn entry_for(family: MaintenanceFamily) -> &'static MaintenanceFamilyEntry {
            let entry = match family {
                $(
                    MaintenanceFamily::$variant => &$ident,
                )+
            };
            debug_assert_eq!(
                entry.family,
                family,
                "maintenance family catalog entry does not match its key"
            );
            entry
        }
    };
}

maintenance_family_catalog! {
    BACKUP_RESTORE_REHEARSAL: BackupRestoreRehearsal => {
        obligation: "Backup and restore rehearsal without restoring active authority.",
        unattended: true,
        origins: [Human, Policy, Installation, WatchdogProblem],
        effect: effect_policy!(
            "an isolated restore transaction is migration class and needs its own route and authority"
        ),
        conditions: [ServiceSafeRoute, AdmittedBudget, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("bins/eliot-kernel/src/backup_capture.rs::KernelBackupCapture::verify_only"),
        observation: "bins/eliot-kernel/src/backup_capture.rs::CaptureReport",
        receipt: [
            "backup identity",
            "archive digest",
            "verification level",
            "member dispositions",
            "receipt identity",
        ],
    }
    BLOB_GC_REACHABILITY: BlobGcReachability => {
        obligation: "Blob reachability and garbage-collection analysis.",
        unattended: true,
        origins: [Human, Policy, Installation, WatchdogProblem],
        effect: effect_policy!("destructive forgetting/purge of unreferenced blobs"),
        conditions: [ServiceSafeRoute, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("crates/storage/eliot-blob-api/src/lib.rs::BlobStoreClient::gc"),
        observation: "crates/storage/eliot-blob-api/src/lib.rs::BlobGcReceipt",
        receipt: [
            "gc state",
            "live set proof id and revision",
            "deleted locators",
            "retained locators",
            "anchor fingerprint",
        ],
    }
    OUTBOX_RECEIPT_RECONCILIATION: OutboxReceiptReconciliation => {
        obligation: "Outbox and receipt reconciliation.",
        unattended: true,
        origins: [Human, Policy, WatchdogProblem, Installation],
        effect: effect_policy!(
            "re-publication of canonical outbox intents and receipts after an unknown external outcome needs a reconciliation disposition first"
        ),
        conditions: [ServiceSafeRoute, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!(unavailable: "no outbox and receipt reconciliation implementation is admitted: bins/eliot-kernel/src/shutdown_drain.rs records audit/outbox flush as a Governor and eliotd owned handoff and states it is recorded, not implemented here"),
        observation: "bins/eliot-store-surreal/src/canonical_event.rs::CommittedCanonicalTransition",
        receipt: [
            "outbox cursor",
            "receipt chain head",
            "reconciled disposition",
            "reconciliation evidence ref",
        ],
    }
    PROJECTION_INDEX_REBUILD: ProjectionIndexRebuild => {
        obligation: "Projection and index rebuild.",
        unattended: true,
        origins: [Human, Policy, WatchdogProblem, Installation],
        effect: effect_policy!(
            "Doctor rebuild authority scoped eliot-doctor/recovery; an ordinary semantic write can never initiate it"
        ),
        conditions: [ServiceSafeRoute, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("bins/eliot-store-surreal/src/canonical_event.rs::request_projection_rebuild"),
        observation: "bins/eliot-store-surreal/src/canonical_event.rs::ProjectionRebuildPlan",
        receipt: [
            "projection kind",
            "source generation",
            "target generation",
            "projection definition digest",
        ],
    }
    CUE_CONCEPT_GRAPH: CueConceptGraph => {
        obligation: "Cue, concept and graph maintenance.",
        unattended: true,
        origins: [Human, Policy, Dreamer],
        effect: effect_policy!("destructive forgetting/invalidation of cue, concept and graph records"),
        conditions: [ServiceSafeRoute, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("crates/smart/eliot-cue-index/src/build.rs::rebuild_cue_snapshot"),
        observation: "crates/smart/eliot-cue-index/src/build.rs::build_cue_snapshot",
        receipt: [
            "snapshot digest",
            "member set digest",
            "registry revision",
            "evidence status set",
        ],
    }
    DREAMER_CURATION: DreamerCuration => {
        obligation: "Dreamer curation job.",
        unattended: false,
        origins: [Human, Dreamer, Policy, Onboarding],
        effect: effect_policy!("a paid model call and destructive forgetting/purge of memory candidates"),
        conditions: [
            ServiceSafeRoute,
            AdmittedBudget,
            InteractiveUserSession,
            NoConflictingInteractiveWork,
        ],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("crates/smart/eliot-dreamer-curation/src/lib.rs::route_validated_curation"),
        observation: "crates/foundation/eliot-protocol/src/dreamer_job.rs::DurableJobResponse",
        receipt: [
            "durable job response state",
            "curation candidate set digest",
            "handler port revisions",
            "routing rejection hint",
        ],
    }
    CALIBRATION_UNDERSTANDING: CalibrationUnderstanding => {
        obligation: "Calibration or understanding examination.",
        unattended: true,
        origins: [Human, Policy, Onboarding],
        effect: effect_policy!(governed),
        conditions: [ServiceSafeRoute],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!(unavailable: "no calibration or understanding examination owner is admitted: crates/eliot-app/src/calibration_runtime.rs belongs to the legacy migration and regression facade, and bins/eliot/src/legacy_governor_config.rs states that delegation_calibration policy has no Kernel surface yet with handoff to the Kernel owner in its 1687 follow-up"),
        observation: "crates/smart/eliot-understanding-assessment/src/lib.rs::assess_scoped",
        receipt: [
            "assessment question family set",
            "owner projection handles",
            "per-question dimension outcomes",
            "assessment digest",
        ],
    }
    INTEGRATION_CAPABILITY_SURVEY: IntegrationCapabilitySurvey => {
        obligation: "Integration and capability survey.",
        unattended: true,
        origins: [Human, Policy, Onboarding, Installation],
        effect: effect_policy!(governed),
        conditions: [ServiceSafeRoute],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!(
            "bins/eliotd/src/capability_evidence_wiring.rs::GovernorCapabilityAdmission::plan_evidence_read"
        ),
        observation:
            "bins/eliotd/src/capability_evidence_wiring.rs::GovernorCapabilityAdmission::ingest_evidence_response",
        receipt: [
            "capability evidence state version",
            "required set digest",
            "observed lifecycle summary",
            "stale-evidence set digest",
        ],
    }
    SECURITY_DEPENDENCY_SCAN: SecurityDependencyScan => {
        obligation: "Security or dependency scan.",
        unattended: true,
        origins: [Human, Policy, Installation],
        effect: effect_policy!(governed),
        conditions: [ServiceSafeRoute],
        dedup: FamilyAndScope,
        owner: owned_by!(unavailable: "no runtime scan owner is admitted: docs/DEPENDENCY_POLICY.md pins the scanner to cargo-deny 0.20.2 plus a verified executable digest behind scripts/verify-dependency-policy.py, and no eliotd Kernel operation or Rust owner exposes a scan result to the daemon"),
        observation: "scripts/verify-dependency-policy.py pinned-scanner canonical receipt",
        receipt: [
            "pinned scanner identity and version",
            "scanner executable digest",
            "advisory set digest",
            "policy finding set digest",
            "exception state digest",
        ],
    }
    DERIVED_INDEX_REBUILD: DerivedIndexRebuild => {
        obligation: "Derived-index differential rebuild.",
        unattended: true,
        origins: [Human, Policy, Installation, WatchdogProblem],
        effect: effect_policy!(governed),
        conditions: [ServiceSafeRoute, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndSubset,
        owner: owned_by!("crates/eliot-engine/src/cached_derivation.rs::CachedDerivationService::lookup_governed"),
        observation: "crates/eliot-engine/src/cached_derivation.rs::CachedDerivation",
        receipt: [
            "derived artifact lineage",
            "registry entry identity",
            "resolved executable identity",
            "trust policy revision",
        ],
    }
    SESSION_EPISODE_RETRIEVAL: SessionEpisodeRetrieval => {
        obligation: "`SessionEpisode` cursor and retrieval maintenance.",
        unattended: true,
        origins: [Human, Policy],
        effect: effect_policy!(governed),
        conditions: [ServiceSafeRoute],
        dedup: FamilyAndScope,
        owner: owned_by!(unavailable: "no `SessionEpisode` cursor or retrieval maintenance owner exists anywhere in the workspace: the identifier occurs only in crates/governor/eliot-maintenance/src/lib.rs, where it is the registration of this very family"),
        observation: "no crate or binary owns `SessionEpisode` cursor or retrieval maintenance; the only occurrence is the registration in crates/governor/eliot-maintenance/src/lib.rs",
        receipt: [
            "cursor identity",
            "advanced cursor value",
            "retrieval set digest",
            "rebuilt index digest",
        ],
    }
    GRANT_DISCLOSURE_CLOSURE: GrantDisclosureClosure => {
        obligation: "Grant and disclosure closure reconciliation.",
        unattended: true,
        origins: [Human, Policy, WatchdogProblem, Installation],
        effect: effect_policy!("grant closure publication and disclosure revocation"),
        conditions: [ServiceSafeRoute, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("bins/eliotd/src/owner_feed.rs::maintain_owner_feed"),
        observation: "bins/eliotd/src/owner_feed.rs::read_canonical_closure_receipts",
        receipt: [
            "authority root ref",
            "grant graph revision",
            "closure operation ids",
            "canonical receipt identities",
            "published owner bundle digest",
        ],
    }
    DONOR_CONFORMANCE: DonorConformance => {
        obligation: "Donor or conformance audit.",
        unattended: true,
        origins: [Human, Policy, Onboarding, Installation],
        effect: effect_policy!(governed),
        conditions: [ServiceSafeRoute],
        dedup: FamilyAndScope,
        owner: owned_by!(unavailable: "no donor or conformance audit runner is admitted: crates/foundation/eliot-conformance-contracts is a stateless effect-free contract crate that explicitly does not discover evidence or promote support"),
        observation: "crates/foundation/eliot-conformance-contracts/src/lib.rs::ConformanceContractSet",
        receipt: [
            "contract set digest",
            "domain coverage denominators",
            "capability support row digests",
            "maturity and observation-state set",
        ],
    }
    SELF_QUALITY_DEBT: SelfQualityDebt => {
        obligation: "Self-quality and maintenance-debt review.",
        unattended: true,
        origins: [Human, Policy, WatchdogProblem, Onboarding, Dreamer],
        effect: effect_policy!(governed),
        conditions: [ServiceSafeRoute],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("bins/eliotd/src/experience_runtime.rs::run_experience_quality_event"),
        observation: "bins/eliotd/src/experience_runtime.rs::ExperienceQualityEventOutput",
        receipt: [
            "observation window identity",
            "denominator completeness",
            "recurrence set digest",
            "self-quality candidate digest",
            "maintenance debt items",
        ],
    }
    RESEARCH_EXCHANGE_CLEANUP: ResearchExchangeCleanup => {
        obligation: "External research exchange cleanup/requalification.",
        unattended: true,
        origins: [Human, Policy, Installation],
        effect: effect_policy!("external provider job cancellation and source requalification"),
        conditions: [ServiceSafeRoute, AdmittedBudget, NoConflictingInteractiveWork],
        dedup: FamilyScopeAndGeneration,
        owner: owned_by!("crates/research/eliot-research-exchange/src/lib.rs::GovernedExchange"),
        observation: "crates/research/eliot-research-exchange/src/lib.rs::ExchangeSnapshot",
        receipt: [
            "exchange idempotency key",
            "cancelled job ids",
            "requalification disposition",
            "requalified source handles",
        ],
    }
}

/// Every registered entry, in declaration order. This is the inspectable
/// catalog the acceptance criteria require: it enumerates all fifteen named
/// families and, for each, exposes the selected automation mode, the
/// eligibility predicates, the required conditions, the deduplication scope,
/// the execution owner or the exact unavailable dependency, and the
/// result-observation mapping.
#[must_use]
pub const fn entries() -> &'static [MaintenanceFamilyEntry] {
    &ALL
}

/// Emits the whole registered catalog once, on the daemon's own diagnostics
/// target. This is the one production reader of [`entries`], and therefore of
/// [`ALL`] and [`REGISTERED_FAMILY_COUNT`].
///
/// I14.22:34 says Human policy "selects one `MaintenanceAutomationMode` per
/// family", and A1 asks for a catalog that "enumerates all fifteen named
/// families and, for each, exposes selected automation mode and
/// execution/defer owner". That is a table an operator must be able to read, so
/// the table is published: one event carrying all [`REGISTERED_FAMILY_COUNT`]
/// rows, each rendered by [`MaintenanceFamilyEntry::catalog_row`] from the same
/// entry every other reader sees.
///
/// Three properties are load-bearing and are asserted here rather than assumed:
///
/// * **Bounded.** The event count is one and the row count is
///   [`REGISTERED_FAMILY_COUNT`]. This is called once from the composition
///   startup path, never from
///   [`crate::maintenance_trigger_evaluator::DaemonComposition::evaluate_maintenance_trigger`],
///   so it cannot become per-trigger spam.
/// * **Non-blocking and never a gate.** It opens no store client, performs no
///   I/O, reads no clock, consults no composition state, and returns nothing,
///   so it cannot delay or withhold startup or readiness.
/// * **Not the durable record.** A13.10 lines 5-9 separate operational logs,
///   which "may rotate", from the durable audit of authority, transitions,
///   receipts and incidents. This line is an operational log. The durable
///   record for a family that cannot start is the canonical notification the
///   blocked family submits through
///   [`crate::notification_state_emit::emit_blocked_automation_notification`],
///   which is keyed by the deduplication scope this same table prints.
pub fn record_registered_catalog() {
    let table = entries()
        .iter()
        .map(MaintenanceFamilyEntry::catalog_row)
        .collect::<Vec<_>>()
        .join("; ");
    tracing::info!(
        target: "eliotd::diagnostics",
        event = "eliotd.maintenance_family_catalog",
        service = SERVICE_NAME,
        registered_families = REGISTERED_FAMILY_COUNT,
        families = %table,
    );
}
