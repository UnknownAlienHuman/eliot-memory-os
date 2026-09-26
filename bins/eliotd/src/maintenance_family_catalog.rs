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
//! Three properties are load-bearing, and they match the three the existing
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
//! * **No direct execution.** This module never runs maintenance work, never
//!   constructs an executor, and never calls a family owner. I14.22 requires
//!   every start to be a Durable Job request, and the catalog resolves only
//!   *where* such a request must go. Today it resolves to
//!   [`MaintenanceRoute::DurableJobRequest`] or
//!   [`MaintenanceRoute::Blocked`] for every family, and neither admits a
//!   start, because the maintenance Durable Job admission itself is unreachable
//!   from `eliotd`: see [`DURABLE_JOB_ADMISSION_BLOCKERS`], which names each
//!   missing symbol exactly. Families are registered and deterministically
//!   blocked with that reason; none is omitted and none is silently ignored.

#![forbid(unsafe_code)]

use eliot_maintenance::{
    AutomationTriggerDecision, MaintenanceAutomationMode, MaintenanceFamily, MaintenanceTrigger,
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

/// The exact symbols that stop a maintenance start from becoming a Durable Job
/// request, one variant per missing capability.
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
    MutableOwnerAccess,
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
            Self::MutableOwnerAccess => {
                "eliot_governor::GovernorComposition::owners_mut is absent: composition.rs exposes only owners(&self) -> &GovernorOwners<P>, and eliot_maintenance::MaintenanceController::admit takes &mut self"
            }
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
    MaintenanceAdmissionBlocker::MutableOwnerAccess,
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
    /// It admits none. I14.22 routes every start through a Durable Job request,
    /// and [`DURABLE_JOB_ADMISSION_BLOCKERS`] names every symbol missing from
    /// that request's path out of `eliotd`. The answer becomes `true` only when
    /// that list is empty, which is a change to the list, not to this function.
    #[must_use]
    pub const fn admits_start(&self) -> bool {
        self.admission_blockers().is_empty()
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
                "the quality event runs in-line from the daemon's experience path through bins/eliotd/src/experience_runtime.rs::run_experience_quality_event rather than from a maintenance Durable Job request"
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

    /// The exact condition names a start must clear, for inspection.
    #[must_use]
    pub fn condition_names(&self) -> Vec<&'static str> {
        self.conditions
            .iter()
            .copied()
            .map(MaintenanceCondition::condition_name)
            .collect()
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

    /// The one actionable, reasoned recommendation for a Human or an owning
    /// component.
    ///
    /// It is built from the typed fields rather than written per family, so it
    /// can never contradict the mode, the conditions, the owner, or the
    /// blockers. I14.22 requires exactly one actionable recommendation with a
    /// reason, and forbids repeated notification or pretending maintenance
    /// occurred.
    #[must_use]
    pub fn recommendation(&self) -> String {
        let family = self.family;
        let mode = self.mode;
        let effect = self.effect_policy.effect_description();
        let conditions = self.condition_names().join("+");
        let route = self.start_route();
        let blockers = admission_blocker_text(&route);
        match route {
            MaintenanceRoute::DurableJobRequest { .. } => format!(
                "{family} is registered, mode {mode:?}, and its execution owner is {owner}. It will not start until a maintenance Durable Job request can be submitted: {missing}. Durable Job admission is still blocked by {blockers}. Conditions: {conditions}. Effect policy: {effect}.",
                owner = route.target(),
                missing = route.missing(),
            ),
            MaintenanceRoute::Blocked { .. } => format!(
                "{family} is registered, mode {mode:?}, and has no execution owner: {dependency}. It will not start. Clear that dependency, then submit a maintenance Durable Job request; admission is blocked by {blockers}. Conditions: {conditions}. Effect policy: {effect}.",
                dependency = route.target(),
            ),
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
    pub fn record_start_route(&self, decision: &AutomationTriggerDecision) {
        let route = self.start_route();
        let blockers = admission_blocker_text(&route);
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.maintenance_family_route",
            service = SERVICE_NAME,
            family = %self.family,
            obligation = self.obligation,
            mode = ?self.mode,
            dedup_scope = self.dedup.scope_name(),
            dedup_key = ?self.dedup.key_parts(),
            conditions = %self.condition_names().join("+"),
            origins = %self.origin_names().join("+"),
            unattended_safe = self.eligibility.unattended_safe,
            separate_authority = self.effect_policy.needs_separate_authority(),
            route = ?route,
            owner_or_dependency = route.target(),
            missing_route = route.missing(),
            admits_start = route.admits_start(),
            admission_blockers = %blockers,
            observation_path = SYSTEM_OBSERVATION_PATH,
            effect_evidence_owner = self.observation.effect_evidence_owner,
            receipt_refs = %self.observation.receipt_refs.join("+"),
            governor_decision = ?decision.decision,
            governor_reason = ?decision.reason,
            governor_admits_job = decision.admits_job,
            trigger = %crate::diagnostics::sanitize_identity(&decision.trigger_id),
            scope = %crate::diagnostics::sanitize_identity(&decision.scope_ref),
            recommendation = %self.recommendation(),
        );
    }
}

/// Joins the shared Durable Job admission blockers into one inspectable line.
fn admission_blocker_text(route: &MaintenanceRoute) -> String {
    route
        .admission_blockers()
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
