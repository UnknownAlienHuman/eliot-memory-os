//! A4 producer/feed proof: settled plans reach the A1 batch shape only through
//! the production feed over owner projections — never helper-only, never
//! caller text.
//!
//! Positive: owner projections → `produce_settled_plan_feed` → `Ready` with a
//! batch that reconciles with its plan item-for-item and matches a direct
//! planner evaluation (the feed invents nothing).
//! Negative: forged caller text (cue digest, policy digest) fails closed with
//! no batch; a settled no-injection yields `NoSettledPlan` with zero emitted
//! instructions.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/reactive_plan.rs"]
mod support;

use eliot_reactive_context_plan::{
    BridgeAdmissionDelivery, BridgeAdmissionSeverity, PlanningErrorKind, ReactiveContextPlanResult,
    SettledPlanFeedError, SettledPlanFeedInputs, SettledPlanFeedOutcome,
    plan_pending_context_injection, produce_settled_plan_feed,
};

fn feed_inputs(
    open: bool,
    rule: bool,
) -> (
    eliot_context_contracts::ContextPlanningView,
    eliot_reactive_context_plan::ReactiveCueActivation,
    eliot_context_contracts::SessionDeliverySnapshot,
    eliot_context_contracts::CriticalAttentionProjection,
    eliot_context_contracts::IntegrationCoverageProfile,
    eliot_reactive_context_plan::ReactiveDeliveryPolicy,
) {
    support::inputs(open, rule)
}

fn assert_batch_reconciles_with_plan(
    plan: &eliot_reactive_context_plan::PendingContextInjectionPlan,
    batch: &eliot_reactive_context_plan::BridgeAdmissionBatch,
) {
    assert_eq!(batch.session_id, plan.request.session_id);
    assert_eq!(batch.scope_id, plan.request.scope_id);
    assert_eq!(batch.invalidations, plan.invalidation);
    assert_eq!(
        batch.items.len() as u64 + batch.skipped_sticky + batch.skipped_ineligible,
        plan.items.len() as u64,
        "emitted + skipped must reconcile with planned items: no silent drops"
    );
    for instruction in &batch.items {
        let item = plan
            .items
            .iter()
            .find(|candidate| candidate.item_id == instruction.plan_item_id)
            .expect("instruction must reference its plan item");
        assert_eq!(instruction.cue_digest.len(), 64);
        assert!(
            instruction
                .cue_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "cue digest must stay lowercase SHA-256 end to end"
        );
        assert_eq!(
            instruction.rule_id,
            format!("reactive-activation:{}", plan.activation_digest)
        );
        assert!(instruction.relations.len() <= 8);
        assert_eq!(instruction.governance_profile_rev, plan.policy_digest);
        assert_eq!(instruction.fence, plan.request.state_fence);
        assert_eq!(
            instruction.dedup_key,
            format!("{}:{}", plan.result_digest, item.item_id)
        );
        assert_eq!(instruction.plan_result_digest, plan.result_digest);
        assert_eq!(instruction.item_reason, item.reason);
        let sticky = item
            .attention
            .as_ref()
            .is_some_and(|attention| attention.sticky);
        assert_eq!(
            instruction.severity,
            if sticky {
                BridgeAdmissionSeverity::Critical
            } else {
                BridgeAdmissionSeverity::Normal
            },
            "severity follows owner stickiness only"
        );
        let (delivery, status) = match item.disposition {
            eliot_reactive_context_plan::DeliveryDisposition::EventPlan => {
                (BridgeAdmissionDelivery::HostHook, "EVENT_PLAN")
            }
            eliot_reactive_context_plan::DeliveryDisposition::ToolOnlyAdvisory => (
                BridgeAdmissionDelivery::NextBridgeResponse,
                "TOOL_ONLY_ADVISORY",
            ),
            other => panic!("emitted item has non-deliverable disposition {other:?}"),
        };
        assert_eq!(instruction.delivery, delivery);
        assert_eq!(instruction.status, status);
    }
}

#[test]
fn production_feed_delivers_exact_batch_from_owner_projections() {
    let (view, activation, session, attention, coverage, policy) = feed_inputs(false, false);
    let outcome = produce_settled_plan_feed(SettledPlanFeedInputs {
        view: &view,
        cue_activation: &activation,
        session_snapshot: &session,
        critical_attention: &attention,
        integration_coverage: &coverage,
        policy: &policy,
    })
    .expect("owner projections must feed");
    let feed = match outcome {
        SettledPlanFeedOutcome::Ready(feed) => feed,
        SettledPlanFeedOutcome::NoSettledPlan(disposition) => {
            panic!(
                "fixture must settle a plan, got no-injection {}",
                disposition.reason
            )
        }
    };
    assert!(
        !feed.batch.items.is_empty(),
        "tool-only fixture must yield deliverable items"
    );
    assert!(
        feed.batch
            .items
            .iter()
            .all(|item| item.delivery == BridgeAdmissionDelivery::NextBridgeResponse),
        "tool-only plan must route to next-response delivery"
    );
    assert_batch_reconciles_with_plan(&feed.plan, &feed.batch);
    // The feed invents nothing: the same projections through the planner
    // directly settle the identical plan revision.
    let direct = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    match direct {
        ReactiveContextPlanResult::Pending(plan) => {
            assert_eq!(
                plan.result_digest, feed.plan.result_digest,
                "feed plan must equal the direct planner evaluation"
            );
            assert_eq!(plan, feed.plan);
        }
        other => panic!("direct planner must also settle a plan, got {other:?}"),
    }
}

#[test]
fn forged_cue_digest_text_never_drives_feed() {
    let (view, mut activation, session, attention, coverage, policy) = feed_inputs(false, false);
    // Caller-forged digest text over the cue join: the owner atom carries a
    // different source digest, so the binding cross-check must fail closed.
    activation.target_bindings[0].source_digest = Some("f".repeat(64));
    let outcome = produce_settled_plan_feed(SettledPlanFeedInputs {
        view: &view,
        cue_activation: &activation,
        session_snapshot: &session,
        critical_attention: &attention,
        integration_coverage: &coverage,
        policy: &policy,
    });
    match outcome {
        Err(SettledPlanFeedError::Planning(error)) => {
            assert_eq!(
                error.kind,
                PlanningErrorKind::BindingMismatch,
                "forged cue text must fail as a binding mismatch"
            );
        }
        Err(SettledPlanFeedError::Producer(error)) => {
            panic!("forged cue text must fail in planning, not production: {error}")
        }
        Ok(_) => panic!("forged cue digest text must never yield a feed outcome"),
    }
}

#[test]
fn forged_policy_digest_text_never_drives_feed() {
    let (view, activation, session, attention, coverage, mut policy) = feed_inputs(false, false);
    // Caller-forged policy digest: well-formed hex but not the canonical
    // digest of the policy body, so policy validation must fail closed.
    policy.policy_digest = "0".repeat(64);
    let outcome = produce_settled_plan_feed(SettledPlanFeedInputs {
        view: &view,
        cue_activation: &activation,
        session_snapshot: &session,
        critical_attention: &attention,
        integration_coverage: &coverage,
        policy: &policy,
    });
    match outcome {
        Err(SettledPlanFeedError::Planning(_)) => {}
        Err(SettledPlanFeedError::Producer(error)) => {
            panic!("forged policy text must fail in planning, not production: {error}")
        }
        Ok(_) => panic!("forged policy digest text must never yield a feed outcome"),
    }
}

#[test]
fn settled_no_injection_emits_zero_instructions() {
    let (view, activation, _session, attention, coverage, policy) = feed_inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let outcome = produce_settled_plan_feed(SettledPlanFeedInputs {
        view: &view,
        cue_activation: &activation,
        session_snapshot: &delivered,
        critical_attention: &attention,
        integration_coverage: &coverage,
        policy: &policy,
    })
    .expect("delivered session must feed without error");
    match outcome {
        SettledPlanFeedOutcome::NoSettledPlan(disposition) => {
            assert_eq!(
                disposition.accounting.deduped, 1,
                "the exact delivered duplicate must be accounted"
            );
            assert!(
                !disposition.items.is_empty(),
                "no-injection keeps its ledger; it emits no batch"
            );
        }
        SettledPlanFeedOutcome::Ready(feed) => panic!(
            "delivered session must not emit instructions, got {}",
            feed.batch.items.len()
        ),
    }
}
