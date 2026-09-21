//! Production settled-plan feed: owner projections to bridge batch.
//!
//! This module is the first non-test caller of
//! [`plan_pending_context_injection`](crate::plan_pending_context_injection):
//! it runs one settled planning evaluation over the six immutable owner
//! projections and, when the planner settles a pending plan, converts it with
//! [`plan_bridge_admissions`](crate::plan_bridge_admissions) into the exact
//! [`BridgeAdmissionBatch`](crate::BridgeAdmissionBatch) the A1 transport
//! admits (`SettledPlanAdmission::admit_settled_plan` / `admit_batch`,
//! `bins/eliot-agent-bridge/src/settled_plan_transport.rs`, A1-owned).
//!
//! Authority boundaries (same cell, no new state machine, no second ledger):
//!
//! ```text
//! feed owns:    one causal production call (projections → plan → batch) and
//!               its honest outcome vocabulary (ready / no-settled-plan /
//!               fail-closed error). It holds no state across calls.
//! plan owns:    item selection, cue binding, firing reference, relations,
//!               scope/governance/fence passthrough, severity, delivery,
//!               dedup keys, skip accounting.
//! bridge owns:  session binding (live attach), ledger mutation, receipts,
//!               stickiness enforcement, normal dedup.
//! governor owns (never produced here): per-item risk tier and any governance
//!               attestation beyond the policy digest.
//! ```
//!
//! Real owned-state source: the six inputs are the exact owner-issued
//! projections the planner validates — the assembled A15
//! [`ContextPlanningView`](eliot_context_contracts::ContextPlanningView), the
//! A10 cue [`ReactiveCueActivation`](crate::ReactiveCueActivation) pair, the
//! [`SessionDeliverySnapshot`](eliot_context_contracts::SessionDeliverySnapshot),
//! the [`CriticalAttentionProjection`](eliot_context_contracts::CriticalAttentionProjection),
//! the [`IntegrationCoverageProfile`](eliot_context_contracts::IntegrationCoverageProfile),
//! and the self-verifying [`ReactiveDeliveryPolicy`](crate::ReactiveDeliveryPolicy).
//! The feed accepts no plan text, no cue text, no digests, and no hand-shaped
//! plan: a caller cannot construct a [`PendingContextInjectionPlan`](crate::PendingContextInjectionPlan)
//! and push it through this feed.
//!
//! Authenticated-cue path: cues enter only through
//! `ReactiveCueActivation.request.seeds[].observed.context`, whose
//! `task_id`/`scope_id`/`state_fence` must equal the view binding (and whose
//! request fence must equal the view fence), enforced by
//! `ReactiveCueActivation::validate_against` inside the planner. Target
//! bindings must join the rendered owner atoms with matching source
//! revision/digest; the policy digest must equal its canonical digest.
//! Forged caller text fails closed as a planning error — never a batch.

use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection, IntegrationCoverageProfile,
    SessionDeliverySnapshot,
};
use eliot_contracts::{ArtifactId, SessionId, StateFence, TaskId};
use eliot_receipts::WorkScopeId;

use crate::bridge_admission::{BridgeAdmissionBatch, BridgeAdmissionError, plan_bridge_admissions};
use crate::input::{ReactiveCueActivation, ReactiveDeliveryPolicy};
use crate::plan::plan_pending_context_injection;
use crate::result::{
    NoInjectionDisposition, PendingContextInjectionPlan, ReactiveContextPlanResult,
    ReactiveContextPlanningError,
};

/// Borrowed owner projections for one feed evaluation.
///
/// Every field is an owner-issued immutable projection, never caller text.
/// The integrator (daemon central export, B2-owned) supplies the live
/// projections; this feed performs exactly one evaluation over them.
/// `Copy` because the struct is only borrowed owner references.
#[derive(Clone, Copy, Debug)]
pub struct SettledPlanFeedInputs<'a> {
    /// Assembled A15 context view (context-assembly owner).
    pub view: &'a ContextPlanningView,
    /// A10 activation request/result pair carrying the authenticated cue
    /// seeds (cue-activation owner).
    pub cue_activation: &'a ReactiveCueActivation,
    /// Immutable session delivery snapshot (session owner).
    pub session_snapshot: &'a SessionDeliverySnapshot,
    /// Critical attention projection (attention owner).
    pub critical_attention: &'a CriticalAttentionProjection,
    /// Integration coverage profile (coverage owner).
    pub integration_coverage: &'a IntegrationCoverageProfile,
    /// Versioned delivery policy with self-verifying digest (policy owner).
    pub policy: &'a ReactiveDeliveryPolicy,
}

/// One settled plan plus its derived bridge batch, produced in a single
/// causal call so the two artifacts cannot diverge.
///
/// A1 admits either half: `plan` via `admit_settled_plan` (which re-runs the
/// producer and aborts on defect) or `batch` via `admit_batch`. Both carry
/// the same `result_digest`; `batch` reconciles with `plan.items`
/// (emitted + skipped counts) by producer construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettledPlanFeed {
    /// Settled pending plan from the real planner over owner projections.
    pub plan: PendingContextInjectionPlan,
    /// Bridge admission batch derived from `plan` in the same call.
    pub batch: BridgeAdmissionBatch,
}

/// Honest feed outcome: either a settled batch is ready for the A1 transport,
/// or the planner settled on no injection (with full accounting, never a
/// silent drop). Planning and producer defects are errors, never outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettledPlanFeedOutcome {
    /// Settled plan + batch ready for `admit_settled_plan` / `admit_batch`.
    Ready(SettledPlanFeed),
    /// Planner settled on no injection; the disposition carries the complete
    /// item ledger, accounting, and reason. Nothing is emitted.
    NoSettledPlan(NoInjectionDisposition),
}

/// Fail-closed feed errors. A malformed projection set or a plan defect
/// surfaces here; the feed never downgrades either into a batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettledPlanFeedError {
    /// The planner rejected the projections (invalid, stale, conflicted, or
    /// caller-forged bindings fail closed here).
    Planning(ReactiveContextPlanningError),
    /// A settled plan item is sourceless, over-bound, or otherwise unusable
    /// as a bridge instruction: a plan defect, surfaced, never downgraded.
    Producer(BridgeAdmissionError),
    /// Supplied projections disagree with the live activation bindings: the
    /// set is internally consistent but stale (or foreign) for the current
    /// activation, so the planner never runs. `projection` names the
    /// disagreeing projection, `field` its exact binding field.
    StaleActivation {
        projection: &'static str,
        field: &'static str,
    },
}

impl std::fmt::Display for SettledPlanFeedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planning(error) => write!(formatter, "settled-plan feed planning: {error:?}"),
            Self::Producer(error) => write!(formatter, "settled-plan feed producer: {error}"),
            Self::StaleActivation { projection, field } => write!(
                formatter,
                "settled-plan feed stale: {projection}.{field} disagrees with the live activation"
            ),
        }
    }
}

impl std::error::Error for SettledPlanFeedError {}

/// Live activation bindings the supplied projections must be current for.
///
/// Projected by the daemon composition from the Governor's authenticated
/// activation snapshot (`read_unique_agent_activation`: task, session,
/// scope, fence, and plan identity cross-checked against the coordination,
/// session, task, scope, and canonical owners). The daemon projects each
/// field through its validated constructor; strings are never authority —
/// only this typed value is. The remaining projection bindings (cue seeds,
/// attention, coverage) reach liveness transitively: the planner already
/// requires them to agree with the view binding, and this gate requires the
/// view binding to agree with the live activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveActivationBindings {
    /// Live task the projections must be planned under.
    pub task_id: TaskId,
    /// Live work scope the projections must be planned under.
    pub scope_id: WorkScopeId,
    /// Live session the delivery history must belong to.
    pub session_id: SessionId,
    /// Live canonical plan the delivery policy must name.
    pub plan_id: ArtifactId,
    /// Live fence every projection must be evaluated under.
    pub state_fence: StateFence,
}

fn stale(projection: &'static str, field: &'static str) -> SettledPlanFeedError {
    SettledPlanFeedError::StaleActivation { projection, field }
}

/// Drive one settled-plan feed evaluation gated on the live activation.
///
/// First verifies the supplied projections are current for `bindings` (view
/// binding, session binding, and policy plan identity against the live
/// task/session/scope/fence/plan), then runs
/// [`produce_settled_plan_feed`]. Internally consistent but rotated or
/// foreign projections fail closed here — the planner, which only checks
/// the projections against each other, can never observe them. Holds no
/// state; Governor risk derivation retention and transport replay retention
/// stay with their owners (A3 derivation, A1 driver).
pub fn drive_live_feed(
    bindings: &LiveActivationBindings,
    inputs: SettledPlanFeedInputs<'_>,
) -> Result<SettledPlanFeedOutcome, SettledPlanFeedError> {
    let view_binding = &inputs.view.view.binding;
    if view_binding.task_id != bindings.task_id {
        return Err(stale("view", "view.binding.task_id"));
    }
    if view_binding.scope_id != bindings.scope_id {
        return Err(stale("view", "view.binding.scope_id"));
    }
    if view_binding.state_fence != bindings.state_fence {
        return Err(stale("view", "view.binding.state_fence"));
    }
    let session = inputs.session_snapshot;
    if session.session_id != bindings.session_id {
        return Err(stale("session", "session.session_id"));
    }
    if session.task_id != bindings.task_id {
        return Err(stale("session", "session.task_id"));
    }
    if session.scope_id != bindings.scope_id {
        return Err(stale("session", "session.scope_id"));
    }
    if session.state_fence != bindings.state_fence {
        return Err(stale("session", "session.state_fence"));
    }
    if inputs.policy.plan_id != bindings.plan_id {
        return Err(stale("policy", "policy.plan_id"));
    }
    produce_settled_plan_feed(inputs)
}

/// Produce one settled-plan feed evaluation from live owner projections.
///
/// Runs [`plan_pending_context_injection`](crate::plan_pending_context_injection)
/// (the first production call site) over the six projections, then
/// [`plan_bridge_admissions`](crate::plan_bridge_admissions) on a pending
/// plan. Holds no state: repeated calls over unchanged projections yield the
/// same outcome (the planner is deterministic); replay protection stays with
/// the A1 transport window and the bridge ledger, never here.
pub fn produce_settled_plan_feed(
    inputs: SettledPlanFeedInputs<'_>,
) -> Result<SettledPlanFeedOutcome, SettledPlanFeedError> {
    let SettledPlanFeedInputs {
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    } = inputs;
    match plan_pending_context_injection(
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    ) {
        ReactiveContextPlanResult::Pending(plan) => {
            let batch = plan_bridge_admissions(&plan).map_err(SettledPlanFeedError::Producer)?;
            Ok(SettledPlanFeedOutcome::Ready(SettledPlanFeed {
                plan,
                batch,
            }))
        }
        ReactiveContextPlanResult::NoInjection(disposition) => {
            Ok(SettledPlanFeedOutcome::NoSettledPlan(disposition))
        }
        ReactiveContextPlanResult::Error(error) => Err(SettledPlanFeedError::Planning(error)),
    }
}
