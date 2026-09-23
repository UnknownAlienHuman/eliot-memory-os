//! Real owner producers for the six reactive planning inputs (#1942).
//!
//! Each producer adopts exactly one live owner artifact (or owner-issued
//! bundle) and returns the corresponding immutable planner input for
//! [`plan_pending_context_injection`](super::plan::plan_pending_context_injection).
//! Nothing here invents owner state: every load-bearing value arrives as a
//! typed owner artifact — the assembled understanding view plus its admitted
//! set (context assembly owner), the exact cue request/result pair (cue
//! activation owner), the owner-issued session/attention/coverage snapshots,
//! and the admitted delivery policy — and every agreement is re-proved by
//! the owning validator before the value is released.
//!
//! Absence is never defaulted here: a missing owner artifact is expressed
//! by the caller holding an empty supplier slot (see
//! [`super::reactive_owner_suppliers`]), which idles the feed as
//! withheld. A present-but-refusing artifact fails closed with the exact
//! owner error, never with a substituted value.
//!
//! Join rule: producers that take `view` bind their output to that exact
//! [`ContextPlanningView`] (task, attempt, scope, fence). A joined input
//! evaluated against another view fails closed in the planner; it is never
//! silently re-targeted.

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextPlanningView, CriticalAttentionProjection,
    IntegrationCoverageProfile, ReactiveInputError, SessionDeliverySnapshot,
};
use eliot_contracts::ArtifactId;
use eliot_cue_contracts::{ActivationRequest, ActivationResult};

use super::input::{ReactiveCueActivation, ReactiveDeliveryPolicy, ReactiveTargetBinding};

/// Adopt the assembly owner's live closure as the planning view (owner:
/// context assembly; T11 lossless A-15 AUV → `ContextPlanningView` adapter).
///
/// `view` is the assembled [`ActiveUnderstandingView`], `admitted` the exact
/// admitted set it was rendered from, and the two byte payloads the rendered
/// canonical forms travelling with them. The payloads are re-proved, not
/// trusted: [`ContextPlanningView::new`] rejects any byte slice whose digest
/// does not reproduce the view's own canonical digest (and the admitted
/// payload digest), so caller bytes can never smuggle a foreign view into
/// the plan.
pub fn produce_planning_view(
    view_id: ArtifactId,
    view: ActiveUnderstandingView,
    admitted: AdmittedContextSet,
    canonical_bytes: Vec<u8>,
    admitted_canonical_bytes: Vec<u8>,
) -> Result<ContextPlanningView, ReactiveInputError> {
    ContextPlanningView::new(
        view_id,
        view,
        admitted,
        canonical_bytes,
        admitted_canonical_bytes,
    )
}

/// Adopt the cue owner's exact firing pair plus the target-to-atom mapping
/// (owner: cue activation), joined to `view`.
///
/// The request/result agreement is owner-checked
/// (`result.validate_against(&request)` inside
/// [`ReactiveCueActivation::validate_against`]); every seed context, the
/// fence, and every target binding is then checked against the joined
/// view, so an activation evaluated elsewhere fails closed instead of
/// planning against foreign atoms. The expected view/admitted joins are
/// bound to this exact view by construction — the join, not a
/// caller-filled slot.
pub fn produce_cue_activation(
    request: ActivationRequest,
    result: ActivationResult,
    target_bindings: Vec<ReactiveTargetBinding>,
    view: &ContextPlanningView,
) -> Result<ReactiveCueActivation, ReactiveInputError> {
    let activation = ReactiveCueActivation {
        request,
        result,
        expected_view_id: Some(view.view_id.clone()),
        expected_admitted_set_digest: Some(view.admitted_canonical_sha256.clone()),
        target_bindings,
    };
    activation.validate_against(view)?;
    Ok(activation)
}

/// Adopt the session owner's issued delivery history (owner: Governor
/// session projection), joined to `view`.
///
/// The snapshot is owner-validated (identity, denominator, historical
/// records, digest); the session/task/attempt/scope/fence binding is then
/// checked against the joined view, so normal-item dedup always runs
/// against the actual session evidence (I7.19) and never against a mixed
/// session.
pub fn produce_session_snapshot(
    snapshot: SessionDeliverySnapshot,
    view: &ContextPlanningView,
) -> Result<SessionDeliverySnapshot, ReactiveInputError> {
    snapshot.validate()?;
    let binding = &view.view.binding;
    if snapshot.task_id != binding.task_id
        || snapshot.attempt_id != binding.attempt_id
        || snapshot.scope_id != binding.scope_id
        || snapshot.state_fence != binding.state_fence
    {
        return Err(ReactiveInputError::BindingMismatch {
            field: "session.view_binding",
        });
    }
    Ok(snapshot)
}

/// Adopt the attention owner's issued projection (owner: critical
/// attention), joined to `view`.
///
/// Members, digest, and task/scope/fence binding are owner-validated;
/// the projection binding is then checked against the joined view, so
/// sticky obligations stay visible until the owner records a durable
/// resolved, waived, or superseded disposition (I7.19).
pub fn produce_attention_projection(
    projection: CriticalAttentionProjection,
    view: &ContextPlanningView,
) -> Result<CriticalAttentionProjection, ReactiveInputError> {
    projection.validate()?;
    let binding = &view.view.binding;
    if projection.task_id != binding.task_id
        || projection.scope_id != binding.scope_id
        || projection.state_fence != binding.state_fence
    {
        return Err(ReactiveInputError::BindingMismatch {
            field: "attention.view_binding",
        });
    }
    Ok(projection)
}

/// Adopt the coverage owner's issued capability profile (owner:
/// host/runtime coverage), joined to `view`.
///
/// Identity, events, gaps, and digest are owner-validated; the fence is
/// then checked against the joined view, so delivery limitations stay
/// visible per evaluation instead of being served stale under a healthy
/// status (P2-1, #1942). This projects the owner-issued contract profile;
/// it never reads the Governor's separate runtime coverage type (a
/// replacement replaces — no alias, no bridge duplicate).
pub fn produce_coverage_profile(
    profile: IntegrationCoverageProfile,
    view: &ContextPlanningView,
) -> Result<IntegrationCoverageProfile, ReactiveInputError> {
    profile.validate()?;
    if profile.state_fence != view.view.binding.state_fence {
        return Err(ReactiveInputError::BindingMismatch {
            field: "coverage.view_binding",
        });
    }
    Ok(profile)
}

/// Adopt the admitted delivery policy (owner: delivery policy admission).
///
/// Identity, limits, digest, and observation clock are owner-validated.
/// The policy carries no fence of its own; fence agreement is enforced
/// per input above and again by the planner.
pub fn produce_delivery_policy(
    policy: ReactiveDeliveryPolicy,
) -> Result<ReactiveDeliveryPolicy, ReactiveInputError> {
    policy.validate()?;
    Ok(policy)
}
