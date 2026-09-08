//! Pure policy checks for one Dreamer cycle transition.

use crate::contract::{CyclePhase, CyclePolicy, DreamerCycleState, RequestKind};
use crate::error::CycleError;

/// Checks whether a new owner request may be dispatched.
pub(crate) fn check_dispatch_budget(
    state: &DreamerCycleState,
    policy: &CyclePolicy,
    observation_time_ms: Option<i64>,
) -> Result<(), CycleError> {
    if state.pending.len() > policy.max_pending as usize {
        return Err(CycleError::BudgetBlocked);
    }
    if state.controller_revision >= policy.max_transitions {
        return Err(CycleError::BudgetBlocked);
    }
    if state.cancellation_requested || policy.cancellation_requested {
        return Err(CycleError::BudgetBlocked);
    }
    if state.budget_usage.fits(&state.job.budget).is_err() {
        return Err(CycleError::BudgetBlocked);
    }
    if policy
        .deadline_ms
        .is_some_and(|deadline| observation_time_ms.is_none_or(|observed| observed > deadline))
    {
        return Err(CycleError::BudgetBlocked);
    }
    Ok(())
}

/// Checks a supplied pending request against the frozen per-phase rule.
pub(crate) fn validate_pending_rule(
    pending: &crate::contract::PendingRequest,
    policy: &CyclePolicy,
) -> Result<(), CycleError> {
    let Some(rule) = policy
        .phase_rules
        .iter()
        .find(|rule| rule.phase == pending.phase)
    else {
        return Err(CycleError::PhaseViolation("missing phase policy rule"));
    };
    if pending.owner != rule.owner
        || pending.product_id != rule.product_id
        || pending.source_id != rule.source_id
        || pending.operation_kind != rule.operation_kind
        || pending.effect != rule.effect
        || pending.proof_ceiling != rule.proof_ceiling
        || pending.kind
            != request_kind(pending.phase)
                .ok_or(CycleError::PhaseViolation("phase has no request kind"))?
    {
        return Err(CycleError::BindingMismatch {
            field: "pending.phase_rule",
            reason: "pending request differs from its frozen phase policy",
        });
    }
    Ok(())
}

/// Maps one ordinary phase to its inert owner request kind.
#[must_use]
pub(crate) const fn request_kind(phase: CyclePhase) -> Option<RequestKind> {
    match phase {
        CyclePhase::BundleValidated => Some(RequestKind::BundleValidation),
        CyclePhase::Screened => Some(RequestKind::CurationScreen),
        CyclePhase::ModelObserved => Some(RequestKind::ModelInvocation),
        CyclePhase::GroundingValidated => Some(RequestKind::Grounding),
        CyclePhase::CommonValidated => Some(RequestKind::CommonValidation),
        CyclePhase::HandlerObserved => Some(RequestKind::SemanticHandler),
        CyclePhase::IntrinsicOutputChecked => Some(RequestKind::IntrinsicOutput),
        CyclePhase::ExternalAdmission => Some(RequestKind::ExternalAdmission),
        CyclePhase::ClosureObserved => Some(RequestKind::Closure),
        _ => None,
    }
}
