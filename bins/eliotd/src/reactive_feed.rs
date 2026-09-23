//! Daemon reactive-delivery drive: owner supplier bundle → six-input
//! join → plan, once per bundle (issue #1942).
//!
//! Owner wiring: the six planner inputs arrive as live owner artifacts in
//! one [`ReactiveOwnerSupply`] (assembly closure, exact cue firing pair,
//! issued session history, attention projection, coverage profile,
//! admitted policy). This drive owns only the invocation sequencing
//! between the suppliers and the existing planner: it builds nothing
//! planner-side and mints no identities, revisions, digests, or delivery.
//! Every load-bearing value is adopted and re-proved by the owner
//! producers before the plan runs.
//!
//! Authority boundaries (the drive invents nothing):
//!
//! ```text
//! producers own: artifact adoption, owner validation, view/fence join.
//! planner owns:  item selection, dedup/sticky disposition, budget fit.
//! bridge owns:   session binding, ledger mutation, Delivery/Injection
//!               Receipts, stickiness, normal dedup (delivery owner).
//! ```
//!
//! Call order, one evaluation = one supplied bundle:
//!
//! 1. Suppliers assemble from their owners only. Any absent owner idles
//!    with the exact missing inventory
//!    ([`Withheld`](ReactiveFeedOutcome::Withheld)) — never fabricated at
//!    the call site, never defaulted into a plan.
//! 2. A served-but-refusing artifact fails closed with its lane named
//!    ([`Failed`](ReactiveFeedOutcome::Failed)); identities are
//!    preserved, nothing is re-targeted.
//! 3. The complete join runs the existing
//!    [`plan_pending_context_injection`](eliot_reactive_context_plan::plan_pending_context_injection)
//!    verbatim; its three results map 1:1 to
//!    [`Planned`](ReactiveFeedOutcome::Planned),
//!    [`NoInjection`](ReactiveFeedOutcome::NoInjection), and `Failed`.
//! 4. The drive retains nothing across calls: every evaluation consumes
//!    a fresh supplier bundle and validates fence/digest/revision
//!    agreement per evaluation, so retained projections can never be
//!    served stale under a healthy status (P2-1, #1942). Fence drift or
//!    digest mismatch fails closed as `Failed`, never as a plan.
//!
//! The drive performs no delivery, issues no receipt, mutates no session,
//! and resolves no attention: the returned
//! [`PendingContextInjectionPlan`](eliot_reactive_context_plan::PendingContextInjectionPlan)
//! is inert, and only the delivery owner converts it into a live request
//! (T11.5). Unknown/replay/cancellation preservation: the drive mutates
//! nothing itself; repeated calls over one unchanged bundle re-evaluate
//! deterministically (planning is pure); execution-plane failures must
//! never fail the activation loop that hosts this drive.

use eliot_reactive_context_plan::{
    NoInjectionDisposition, OwnerAssembleError, PendingContextInjectionPlan,
    ReactiveContextPlanResult, ReactiveMissingOwner, ReactiveOwnerSupply,
};

/// Outcome of one reactive-delivery drive evaluation: planned with the
/// inert plan, no-injection with full accounting, withheld with the exact
/// missing owners, or failed with identities preserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveFeedOutcome {
    /// The six owners joined and the planner selected items: the inert
    /// delivery request travels inside `plan` for the delivery owner.
    /// Boxed: the plan is kilobytes next to byte-sized siblings, and the
    /// outcome crosses the daemon dispatch by value.
    Planned {
        /// Complete pending plan; its request is inert and has no
        /// execution receipt.
        plan: Box<PendingContextInjectionPlan>,
    },
    /// The six owners joined but nothing is eligible: explicit no-op
    /// with the same complete accounting as a plan. Boxed for the same
    /// reason as [`Planned`](ReactiveFeedOutcome::Planned).
    NoInjection {
        /// Explicit no-injection disposition with item/budget accounting.
        disposition: Box<NoInjectionDisposition>,
    },
    /// No plan: the exact owners absent on this evaluation, in
    /// deterministic slot order. Normal idle, never an error, never a
    /// default.
    Withheld {
        /// Missing-owner inventory.
        missing: Vec<ReactiveMissingOwner>,
    },
    /// A served artifact or the planner refused, with the refusing lane
    /// and reason preserved. Never fails the activation loop that hosts
    /// this drive.
    Failed(ReactiveFeedError),
}

/// Fail-closed delivery-drive error: the refusing lane plus its exact
/// reason. String-rendered so the outcome stays cloneable and
/// comparable; the owner error is preserved as text, never re-targeted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveFeedError {
    /// Owning lane whose artifact or plan refused.
    pub owner: &'static str,
    /// Exact refusal reason (owner error or planner reason code + detail).
    pub reason: String,
}

/// Drive one reactive-delivery evaluation over an explicit supplier bundle.
///
/// Evaluated in the daemon binary flow by the pending trigger lane: absent
/// owners idle as [`Withheld`](ReactiveFeedOutcome::Withheld) with the
/// exact missing inventory; otherwise the six inputs adopt, join to one
/// view and fence, and the existing planner runs verbatim. Deterministic
/// and side-effect free; one call corresponds to one supplied bundle and
/// retains nothing afterwards.
#[must_use]
pub fn drive_reactive_delivery_once(supply: ReactiveOwnerSupply) -> ReactiveFeedOutcome {
    let _span = tracing::info_span!("eliotd.reactive_delivery_drive").entered();
    let assembled = match supply.assemble() {
        Ok(assembled) => assembled,
        Err(OwnerAssembleError::Missing { missing }) => {
            return ReactiveFeedOutcome::Withheld { missing };
        }
        Err(OwnerAssembleError::Refused { owner, error }) => {
            return ReactiveFeedOutcome::Failed(ReactiveFeedError {
                owner,
                reason: error.to_string(),
            });
        }
    };
    match assembled.plan() {
        ReactiveContextPlanResult::Pending(plan) => {
            tracing::info!(
                items = plan.items.len(),
                "reactive delivery drive planned with inert request"
            );
            ReactiveFeedOutcome::Planned {
                plan: Box::new(plan),
            }
        }
        ReactiveContextPlanResult::NoInjection(disposition) => ReactiveFeedOutcome::NoInjection {
            disposition: Box::new(disposition),
        },
        ReactiveContextPlanResult::Error(error) => ReactiveFeedOutcome::Failed(ReactiveFeedError {
            owner: "reactive planner",
            reason: format!("planning refused ({}): {}", error.reason_code, error.detail),
        }),
    }
}
