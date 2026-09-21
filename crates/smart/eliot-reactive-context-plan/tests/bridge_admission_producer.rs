//! C1 producer proof: settled pending plans convert to exact bridge admission
//! instructions through the real planner and the real fixture projections.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/reactive_plan.rs"]
mod support;

use eliot_reactive_context_plan::{
    BridgeAdmissionDelivery, BridgeAdmissionSeverity, ReactiveContextPlanResult,
    plan_bridge_admissions, plan_pending_context_injection,
};

fn assert_instruction_exactness(
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
        assert!(!instruction.cue_id.is_empty());
        assert!(!instruction.cue_source.is_empty());
        assert!(!instruction.cue_source_revision.is_empty());
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
        assert_eq!(
            instruction.governance_profile_rev, plan.policy_digest,
            "governance reference is the policy digest, verbatim"
        );
        assert_eq!(instruction.fence, plan.request.state_fence);
        assert_eq!(
            instruction.dedup_key,
            format!("{}:{}", plan.result_digest, item.item_id)
        );
        assert_eq!(instruction.plan_result_digest, plan.result_digest);
        assert_eq!(instruction.item_reason, item.reason);
        // Severity follows owner-set stickiness, never inference.
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
            }
        );
        // Delivery follows the per-item disposition, nothing else.
        let (delivery, status) = match item.disposition {
            eliot_reactive_context_plan::DeliveryDisposition::EventPlan => (
                BridgeAdmissionDelivery::HostHook,
                "EVENT_PLAN",
            ),
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
fn tool_only_pending_plan_converts_to_next_response_instructions() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view, &activation, &session, &attention, &coverage, &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("fixture must yield a pending plan, got {other:?}"),
    };
    let batch = plan_bridge_admissions(&plan).expect("producer maps settled plan");
    assert!(
        !batch.items.is_empty(),
        "tool-only fixture must yield deliverable items"
    );
    assert!(
        batch
            .items
            .iter()
            .all(|item| item.delivery == BridgeAdmissionDelivery::NextBridgeResponse),
        "tool-only plan must route to next-response delivery"
    );
    assert_instruction_exactness(&plan, &batch);
}

#[test]
fn event_integrated_plan_converts_to_host_hook_instructions() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let mut event_coverage = coverage.clone();
    event_coverage.supported_modes =
        vec![eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated];
    event_coverage.profile_digest = event_coverage.canonical_digest().unwrap();
    let mut event_policy = policy.clone();
    event_policy.allowed_modes =
        vec![eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated];
    event_policy.policy_digest = event_policy.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &event_coverage,
        &event_policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("fixture must yield an event plan, got {other:?}"),
    };
    let batch = plan_bridge_admissions(&plan).expect("producer maps event plan");
    assert!(
        batch
            .items
            .iter()
            .any(|item| item.delivery == BridgeAdmissionDelivery::HostHook),
        "event plan must yield host-hook instructions"
    );
    assert_instruction_exactness(&plan, &batch);
}
