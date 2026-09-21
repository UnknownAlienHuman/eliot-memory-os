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
    BridgeAdmissionDelivery, BridgeAdmissionSeverity, LiveActivationBindings, PlanningErrorKind,
    ReactiveContextPlanResult, SettledPlanFeedError, SettledPlanFeedInputs, SettledPlanFeedOutcome,
    drive_live_feed, plan_pending_context_injection, produce_settled_plan_feed,
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
        Err(SettledPlanFeedError::StaleActivation { .. }) => {
            panic!("forged cue text must fail in planning, not on liveness")
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
        Err(SettledPlanFeedError::StaleActivation { .. }) => {
            panic!("forged policy text must fail in planning, not on liveness")
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

fn live_bindings(
    view: &eliot_context_contracts::ContextPlanningView,
    session: &eliot_context_contracts::SessionDeliverySnapshot,
    policy: &eliot_reactive_context_plan::ReactiveDeliveryPolicy,
) -> LiveActivationBindings {
    LiveActivationBindings {
        task_id: view.view.binding.task_id.clone(),
        scope_id: view.view.binding.scope_id.clone(),
        session_id: session.session_id.clone(),
        plan_id: policy.plan_id.clone(),
        state_fence: view.view.binding.state_fence.clone(),
    }
}

fn rotated_fence() -> eliot_contracts::StateFence {
    eliot_contracts::StateFence::new(
        eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            std::num::NonZeroU64::new(2).unwrap(),
        )
        .unwrap(),
        eliot_contracts::ResourceGeneration::new(1).unwrap(),
    )
}

fn drive_inputs<'a>(
    view: &'a eliot_context_contracts::ContextPlanningView,
    activation: &'a eliot_reactive_context_plan::ReactiveCueActivation,
    session: &'a eliot_context_contracts::SessionDeliverySnapshot,
    attention: &'a eliot_context_contracts::CriticalAttentionProjection,
    coverage: &'a eliot_context_contracts::IntegrationCoverageProfile,
    policy: &'a eliot_reactive_context_plan::ReactiveDeliveryPolicy,
) -> SettledPlanFeedInputs<'a> {
    SettledPlanFeedInputs {
        view,
        cue_activation: activation,
        session_snapshot: session,
        critical_attention: attention,
        integration_coverage: coverage,
        policy,
    }
}

#[test]
fn live_drive_with_matching_activation_settles_ready_batch() {
    let (view, activation, session, attention, coverage, policy) = feed_inputs(false, false);
    let inputs = drive_inputs(&view, &activation, &session, &attention, &coverage, &policy);
    let bindings = live_bindings(&view, &session, &policy);
    let driven = drive_live_feed(&bindings, inputs).expect("matching activation must drive");
    let direct = produce_settled_plan_feed(inputs).expect("direct feed must settle");
    match (driven, direct) {
        (
            SettledPlanFeedOutcome::Ready(driven_feed),
            SettledPlanFeedOutcome::Ready(direct_feed),
        ) => assert_eq!(
            driven_feed, direct_feed,
            "the liveness gate adds currency only, never content"
        ),
        (driven, direct) => {
            panic!("both drives must settle Ready, got {driven:?} vs {direct:?}")
        }
    }
}

#[test]
fn rotated_fence_fails_closed_before_planning() {
    let (view, activation, session, attention, coverage, policy) = feed_inputs(false, false);
    let inputs = drive_inputs(&view, &activation, &session, &attention, &coverage, &policy);
    let mut bindings = live_bindings(&view, &session, &policy);
    bindings.state_fence = rotated_fence();
    match drive_live_feed(&bindings, inputs) {
        Err(SettledPlanFeedError::StaleActivation { projection, field }) => {
            assert_eq!(projection, "view");
            assert_eq!(field, "view.binding.state_fence");
        }
        other => panic!("rotated fence must fail closed as a stale view, got {other:?}"),
    }
    // Control: the same projections through the ungated feed still settle —
    // the gate (not the planner) fired.
    assert!(matches!(
        produce_settled_plan_feed(inputs),
        Ok(SettledPlanFeedOutcome::Ready(_))
    ));
}

#[test]
fn foreign_session_fails_closed_before_planning() {
    let (view, activation, session, attention, coverage, policy) = feed_inputs(false, false);
    let inputs = drive_inputs(&view, &activation, &session, &attention, &coverage, &policy);
    let mut bindings = live_bindings(&view, &session, &policy);
    bindings.session_id = eliot_contracts::SessionId::new("foreign-session").unwrap();
    match drive_live_feed(&bindings, inputs) {
        Err(SettledPlanFeedError::StaleActivation { projection, field }) => {
            assert_eq!(projection, "session");
            assert_eq!(field, "session.session_id");
        }
        other => panic!("foreign session must fail closed, got {other:?}"),
    }
    assert!(matches!(
        produce_settled_plan_feed(inputs),
        Ok(SettledPlanFeedOutcome::Ready(_))
    ));
}

#[test]
fn foreign_scope_fails_closed_before_planning() {
    let (view, activation, session, attention, coverage, policy) = feed_inputs(false, false);
    let inputs = drive_inputs(&view, &activation, &session, &attention, &coverage, &policy);
    let mut bindings = live_bindings(&view, &session, &policy);
    bindings.scope_id = eliot_receipts::WorkScopeId::new("foreign-scope").unwrap();
    match drive_live_feed(&bindings, inputs) {
        Err(SettledPlanFeedError::StaleActivation { projection, field }) => {
            assert_eq!(projection, "view");
            assert_eq!(field, "view.binding.scope_id");
        }
        other => panic!("foreign scope must fail closed, got {other:?}"),
    }
    assert!(matches!(
        produce_settled_plan_feed(inputs),
        Ok(SettledPlanFeedOutcome::Ready(_))
    ));
}

#[test]
fn foreign_plan_fails_closed_before_planning() {
    let (view, activation, session, attention, coverage, policy) = feed_inputs(false, false);
    let inputs = drive_inputs(&view, &activation, &session, &attention, &coverage, &policy);
    let mut bindings = live_bindings(&view, &session, &policy);
    bindings.plan_id = eliot_contracts::ArtifactId::new("foreign-plan").unwrap();
    match drive_live_feed(&bindings, inputs) {
        Err(SettledPlanFeedError::StaleActivation { projection, field }) => {
            assert_eq!(projection, "policy");
            assert_eq!(field, "policy.plan_id");
        }
        other => panic!("foreign plan must fail closed, got {other:?}"),
    }
    assert!(matches!(
        produce_settled_plan_feed(inputs),
        Ok(SettledPlanFeedOutcome::Ready(_))
    ));
}

#[test]
fn policy_seal_computes_digest_and_validates() {
    let (_, _, _, _, _, policy) = feed_inputs(false, false);
    let sealed = eliot_reactive_context_plan::ReactiveDeliveryPolicy::seal(policy)
        .expect("seal computes the policy digest");
    assert_eq!(sealed.policy_digest.len(), 64);
    sealed.validate().expect("sealed policy validates");
}

#[test]
fn mutated_policy_digest_rejected_after_seal() {
    let (_, _, _, _, _, policy) = feed_inputs(false, false);
    let mut sealed = eliot_reactive_context_plan::ReactiveDeliveryPolicy::seal(policy)
        .expect("seal computes the policy digest");
    let replacement = if sealed.policy_digest.starts_with('0') {
        '1'
    } else {
        '0'
    };
    sealed
        .policy_digest
        .replace_range(0..1, &replacement.to_string());
    assert!(matches!(
        sealed.validate(),
        Err(eliot_context_contracts::ReactiveInputError::DigestMismatch { .. })
    ));
}

#[test]
fn activation_pair_check_accepts_evaluated_pair() {
    let (_, activation, _, _, _, _) = feed_inputs(false, false);
    activation
        .check_pair()
        .expect("evaluated result belongs to its request");
}

#[test]
fn activation_pair_check_rejects_mismatched_request() {
    let (_, mut activation, _, _, _, _) = feed_inputs(false, false);
    activation.request.cancelled = true;
    assert!(matches!(
        activation.check_pair(),
        Err(eliot_context_contracts::ReactiveInputError::BindingMismatch { .. })
    ));
}

#[test]
fn activation_assembles_against_live_view() {
    let (view, activation, _, _, _, _) = feed_inputs(false, false);
    let assembled = eliot_reactive_context_plan::ReactiveCueActivation::assemble_for_view(
        activation.request,
        activation.result,
        &view,
    )
    .expect("evaluated pair assembles against its view");
    assert_eq!(assembled.expected_view_id, Some(view.view_id.clone()));
    assert_eq!(
        assembled.expected_admitted_set_digest,
        Some(view.admitted_canonical_sha256.clone())
    );
    assert!(
        assembled.target_bindings.is_empty(),
        "no binding authority is invented across namespaces"
    );
    assembled
        .validate_against(&view)
        .expect("assembled activation validates against the live view");
}

#[test]
fn activation_assembly_rejects_mismatched_pair() {
    let (view, mut activation, _, _, _, _) = feed_inputs(false, false);
    activation.request.cancelled = true;
    let result = eliot_reactive_context_plan::ReactiveCueActivation::assemble_for_view(
        activation.request,
        activation.result,
        &view,
    );
    assert!(matches!(
        result,
        Err(eliot_context_contracts::ReactiveInputError::BindingMismatch { .. })
    ));
}

#[test]
fn unbound_activation_yields_frontier_without_emission() {
    let (view, activation, session, attention, coverage, policy) = feed_inputs(false, false);
    let assembled = eliot_reactive_context_plan::ReactiveCueActivation::assemble_for_view(
        activation.request,
        activation.result,
        &view,
    )
    .expect("evaluated pair assembles against its view");
    let inputs = drive_inputs(&view, &assembled, &session, &attention, &coverage, &policy);
    let outcome = produce_settled_plan_feed(inputs).expect("unbound activation must feed");
    match outcome {
        SettledPlanFeedOutcome::NoSettledPlan(disposition) => {
            assert!(
                disposition
                    .frontier
                    .iter()
                    .any(|entry| entry.starts_with("activation:unmapped:")),
                "unbound targets stay frontier evidence, got {:?}",
                disposition.frontier
            );
        }
        SettledPlanFeedOutcome::Ready(feed) => panic!(
            "unbound activation must not emit instructions, got {}",
            feed.batch.items.len()
        ),
    }
}
