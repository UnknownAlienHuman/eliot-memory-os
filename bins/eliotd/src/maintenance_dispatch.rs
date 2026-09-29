//! Owner dispatch for one Governor maintenance decision (I14.22, issue #1688).
//!
//! The Governor owner decides. This module only answers the question the
//! decision asks of the rest of the system: **which existing owner must now
//! act, and on what exact condition.** It is a closed mapping over the owner's
//! own [`AutomationDecision`] — one arm per value, no second decision
//! vocabulary, no re-decision and no default.
//!
//! Three properties are load-bearing:
//!
//! * **Dispatch by the decision, never by a Boolean summary.** The owner
//!   already publishes its exact action in
//!   [`AutomationTriggerDecision::decision`]. A caller that reduced it to
//!   "does this admit a job?" conflated `START` with a job that was never
//!   admitted, `DEFER` with `BLOCK`, and `SUPPRESS_DUPLICATE` with a failure,
//!   and could not tell a recommendation from an escalation. Each arm below
//!   names the owner and the exact condition, so the six contract decisions
//!   stay distinguishable all the way to the record.
//! * **Execution stays with the existing owners.** An admitted start is routed
//!   to the Durable Job admission owner by name; a recommendation is routed to
//!   the Human-board adapter; a duplicate is routed to the job that already
//!   owns the work. This module executes nothing, opens no queue, starts no
//!   timer and runs no background loop.
//! * **Every produced reference names the owner record it claims.** The start
//!   arm carries the admission owner's own `path::symbol` and the exact route
//!   `eliotd` does not hold, read from the registered family entry rather than
//!   restated here, so it cannot drift from the catalog it is rendered from.

#![forbid(unsafe_code)]

use eliot_maintenance::{
    AutomationDecision, AutomationTriggerDecision, DecisionReason, MaintenanceFamily,
};

use crate::maintenance_family_catalog::MaintenanceFamilyDecision;

/// The exact absent owner and the exact condition that reopens one decision.
///
/// Every entry is read from the Governor owner's own evaluation order in
/// [`eliot_maintenance::MaintenanceController::evaluate_trigger`]: the
/// `reopen_condition` is the name of the [`MaintenanceTriggerInput`] field that
/// owner's matching arm tests for that reason, and the `missing_owner` is the
/// authority whose absence makes that field false. Nothing here is a timer, a
/// retry budget, or a locally invented occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceDecisionGap {
    /// The exact owner that must act, or the explicit statement that no owner
    /// is missing and the reason is an observed gate rather than an absent
    /// authority. Never empty.
    pub missing_owner: &'static str,
    /// The exact observation that would reopen this decision, named by the
    /// input field the owner evaluates. Never empty.
    pub reopen_condition: &'static str,
}

/// The exact owner gap and reopen condition for one Governor decision reason.
///
/// Total over [`DecisionReason`], so a new reason is a compile error here
/// rather than a silently un-gapped decision. The `AutomationOff` and
/// `SuggestOnly` arms share the maintenance-policy owner because they are the
/// same unresolved policy read at two different modes; `Eligible` and
/// `DuplicateActiveJob` state plainly that no owner is missing, because their
/// reasons are observed gates rather than absent authorities.
#[must_use]
pub const fn decision_gap(reason: DecisionReason) -> MaintenanceDecisionGap {
    match reason {
        DecisionReason::Eligible => MaintenanceDecisionGap {
            missing_owner: "no owner is missing: every gate in the Governor owner's evaluation is satisfied",
            reopen_condition: "not applicable: the decision is already eligible and no reopening is owed",
        },
        DecisionReason::AutomationOff | DecisionReason::SuggestOnly => MaintenanceDecisionGap {
            missing_owner: "the Human maintenance-policy owner that publishes MaintenanceAutomationMode to eliotd (issue #1692); eliotd holds no such publisher and the registered catalog mode is off, so an unresolved policy denies automation instead of defaulting to it",
            reopen_condition: "MaintenanceTriggerInput::mode reads a published mode other than off for this registered family",
        },
        DecisionReason::ExplicitRequestRequired => MaintenanceDecisionGap {
            missing_owner: "the authenticated Human maintenance-request ingress (issue #1692); eliotd exposes no authenticated Human UI or CLI maintenance-request entry, and an untrusted flag is not a request",
            reopen_condition: "MaintenanceTriggerInput::explicit_request reads true from that authenticated ingress",
        },
        DecisionReason::NotIdle => MaintenanceDecisionGap {
            missing_owner: "no owner is missing: the affected scope is observed not idle, which is the condition itself",
            reopen_condition: "MaintenanceTriggerInput::idle reads true, i.e. an observation with no in-flight admitted activation in the affected scope",
        },
        DecisionReason::OutsideSchedule => MaintenanceDecisionGap {
            missing_owner: "the Host wake and Task Scheduler occurrence owner (issue #1692); eliotd holds no real scheduled occurrence, and a locally invented clock event is forbidden",
            reopen_condition: "MaintenanceTriggerInput::scheduled_window reads true from that real Host or Task Scheduler occurrence",
        },
        DecisionReason::RouteUnavailable => MaintenanceDecisionGap {
            missing_owner: "the maintenance route and credential owner (issue #1692); no owner publishes a service-safe unattended route to eliotd",
            reopen_condition: "MaintenanceTriggerInput::route_available reads true from that published service-safe route",
        },
        DecisionReason::BudgetUnavailable => MaintenanceDecisionGap {
            missing_owner: "the maintenance budget and quota owner (issue #1692); no owner publishes an admitted budget slice to eliotd",
            reopen_condition: "MaintenanceTriggerInput::budget_available reads true from that admitted budget slice",
        },
        DecisionReason::UserSessionRequired => MaintenanceDecisionGap {
            missing_owner: "the authenticated User Broker session owner together with the separate interactive_maintenance permission (issue #1692); transport session presence is not broker admission",
            reopen_condition: "MaintenanceTriggerInput::user_session_available reads true from an authenticated interactive session admitted under that separate permission",
        },
        DecisionReason::DuplicateActiveJob => MaintenanceDecisionGap {
            missing_owner: "no owner is missing: an equivalent active request already owns this work, and that request is the owner",
            reopen_condition: "MaintenanceTriggerInput::active_job_id stops naming an active job for this registered deduplication scope",
        },
        DecisionReason::Expired => MaintenanceDecisionGap {
            missing_owner: "the maintenance expiry-policy owner (issue #1694); no owner publishes a maintenance expiry to eliotd",
            reopen_condition: "MaintenanceTriggerInput::expires_at_ms is Some and strictly greater than now_ms",
        },
        DecisionReason::SafetyRecovery => MaintenanceDecisionGap {
            missing_owner: "the protected safety and recovery obligation owner (issue #1692); the registered protected-obligation authority needed to admit safety work is not published to this path",
            reopen_condition: "MaintenanceTriggerInput::safety_required is cleared by that protected recovery owner rather than asserted by the caller",
        },
    }
}

/// Where one Governor maintenance decision must be handed, and on what exact
/// condition.
///
/// One arm per [`AutomationDecision`] value, so the dispatch cannot lose or
/// merge a decision. No arm executes anything: each names an existing owner and
/// the record that owner must produce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceDispatch {
    /// `START`: the existing Durable Job admission owner holds the request.
    ///
    /// The job identity, the lease, the budget slice and the receipt all belong
    /// to `eliot_maintenance::MaintenanceController::admit` and its Kernel
    /// durable-job port. This arm names that owner and the exact route `eliotd`
    /// does not hold, and admits nothing itself: the record it produces is a
    /// retained admission request, never a claim that a job was admitted or
    /// started.
    StartDurableJob {
        /// `path::symbol` of the existing admission owner.
        admission_owner: &'static str,
        /// The exact route `eliotd` does not hold to that owner.
        missing_route: &'static str,
    },
    /// `SUGGEST`: exactly one Human-board recommendation, and no work started.
    SuggestBoardItem {
        /// The exact owner gap and reopen condition behind the suggestion.
        gap: MaintenanceDecisionGap,
    },
    /// `DEFER`: the trigger is retained for a later eligible window. No work
    /// starts; the Human-board adapter records the exact deferral under the
    /// stable family/scope/reason/policy episode identity.
    Defer {
        /// The exact owner gap and reopen condition behind the deferral.
        gap: MaintenanceDecisionGap,
    },
    /// `BLOCK`: policy, route, budget or session requirements deny execution.
    /// The exact missing owner and reopen condition are retained with the
    /// record.
    Block {
        /// The exact owner gap and reopen condition behind the block.
        gap: MaintenanceDecisionGap,
    },
    /// `SUPPRESS_DUPLICATE`: an equivalent active request already owns this
    /// work.
    ///
    /// This is not a failure and not a new occurrence, so it must not create a
    /// record: I11.12 forbids one alert per occurrence, and a record here
    /// would report a duplicate as blocked work. The existing job is the
    /// reference, and the decision that named it is already inspectable
    /// through the operational decision line the evaluator emits.
    ExistingDurableJob {
        /// The existing job identity the owner reported, when it carried one.
        durable_job_ref: Option<String>,
    },
    /// `ESCALATE`: a Human or recovery owner must act rather than wait.
    Escalate {
        /// The exact owner gap and reopen condition behind the escalation.
        gap: MaintenanceDecisionGap,
    },
}

impl MaintenanceDispatch {
    /// Routes one evaluated decision to the owner that must act.
    ///
    /// Pure: it reads the Governor owner's own action and the registered
    /// family's own resolved route, and invents neither. The admission owner and
    /// the missing route come from the family decision's own catalog entry, so a
    /// dispatch can never name a route the catalog does not, and the gap comes
    /// from the owner's own reason, so it cannot disagree with the decision that
    /// produced it.
    #[must_use]
    pub fn for_decision(
        decision: &AutomationTriggerDecision,
        family_decision: &MaintenanceFamilyDecision,
    ) -> Self {
        let gap = decision_gap(decision.reason);
        match decision.decision {
            AutomationDecision::Start => Self::StartDurableJob {
                admission_owner: family_decision.route.target(),
                missing_route: family_decision.route.missing(),
            },
            AutomationDecision::Suggest => Self::SuggestBoardItem { gap },
            AutomationDecision::Defer => Self::Defer { gap },
            AutomationDecision::Block => Self::Block { gap },
            AutomationDecision::SuppressDuplicate => Self::ExistingDurableJob {
                durable_job_ref: decision.durable_job_ref.clone(),
            },
            AutomationDecision::Escalate => Self::Escalate { gap },
        }
    }

    /// The closed wire name of the arm, for inspection.
    ///
    /// It names the dispatch, not the decision: the decision keeps the owner's
    /// own spelling, and a reader that has both can see the routing without
    /// either vocabulary being restated in the other.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::StartDurableJob { .. } => "START_DURABLE_JOB",
            Self::SuggestBoardItem { .. } => "SUGGEST_BOARD_ITEM",
            Self::Defer { .. } => "DEFER",
            Self::Block { .. } => "BLOCK",
            Self::ExistingDurableJob { .. } => "EXISTING_DURABLE_JOB",
            Self::Escalate { .. } => "ESCALATE",
        }
    }

    /// The operator-facing subject line for the record this dispatch produces.
    #[must_use]
    pub fn subject(&self, family: &MaintenanceFamily) -> String {
        match self {
            Self::StartDurableJob { .. } => {
                format!("maintenance start cannot be admitted for {family}")
            }
            Self::SuggestBoardItem { .. } => format!("maintenance recommendation for {family}"),
            Self::Defer { .. } => format!("maintenance deferred for {family}"),
            Self::Block { .. } => format!("blocked maintenance automation {family}"),
            // Never rendered: this arm produces no record. It exists so the
            // subject function stays total over the dispatch.
            Self::ExistingDurableJob { .. } => format!("active maintenance job for {family}"),
            Self::Escalate { .. } => format!("maintenance automation escalated for {family}"),
        }
    }

    /// The owner gap and reopen condition this dispatch retains, when it has
    /// one.
    ///
    /// A start's gap is its admission route, and a duplicate's is the job that
    /// already owns the work, so this is total over the arms that name an
    /// owner rather than over the arms that hold a reference.
    #[must_use]
    pub fn gap(&self) -> MaintenanceDecisionGap {
        match self {
            Self::StartDurableJob {
                admission_owner,
                missing_route,
            } => MaintenanceDecisionGap {
                missing_owner: admission_owner,
                reopen_condition: missing_route,
            },
            Self::SuggestBoardItem { gap }
            | Self::Defer { gap }
            | Self::Block { gap }
            | Self::Escalate { gap } => *gap,
            Self::ExistingDurableJob { .. } => MaintenanceDecisionGap {
                missing_owner: "the equivalent active request that already owns this work",
                reopen_condition: "that request reaches a terminal state, after which active_job_id stops naming it",
            },
        }
    }

    /// The one line added to the record's summary: the owner that must act and
    /// the observation that reopens the decision.
    #[must_use]
    pub fn detail(&self) -> String {
        let gap = self.gap();
        format!(
            "dispatch={dispatch}; missing owner: {owner}; reopens when: {reopen}",
            dispatch = self.wire_name(),
            owner = gap.missing_owner,
            reopen = gap.reopen_condition,
        )
    }

    /// Emits the routing decision for one evaluated trigger, so a reader can
    /// see which owner the decision was handed to and on what exact condition
    /// without reading the canonical record.
    ///
    /// This is an operational line, not the durable record: it rotates, and the
    /// record for the arms that owe one is the canonical notification the
    /// Human-board owner commits. It is written here rather than in the caller
    /// so the emitted line and the dispatch the emitter acted on are the same
    /// value, computed once.
    pub fn record(&self, decision: &AutomationTriggerDecision) {
        let gap = self.gap();
        // Only the duplicate arm holds a job reference. The other arms name an
        // owner instead, so the field is reported as unavailable rather than
        // filled with a placeholder a reader could mistake for an identity.
        let existing_job = match self {
            Self::ExistingDurableJob {
                durable_job_ref: Some(reference),
            } => crate::diagnostics::sanitize_identity(reference),
            Self::ExistingDurableJob {
                durable_job_ref: None,
            } => "the owner reported no job identity".to_owned(),
            _ => "unavailable: this dispatch names an owner, not an existing job".to_owned(),
        };
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.maintenance_dispatch",
            service = crate::SERVICE_NAME,
            dispatch = self.wire_name(),
            family = %decision.family,
            trigger = %crate::diagnostics::sanitize_identity(&decision.trigger_id),
            scope = %crate::diagnostics::sanitize_identity(&decision.scope_ref),
            governor_decision = ?decision.decision,
            governor_reason = ?decision.reason,
            governor_admits_job = decision.admits_job,
            missing_owner = gap.missing_owner,
            reopen_condition = gap.reopen_condition,
            existing_job = %existing_job,
        );
    }
}
