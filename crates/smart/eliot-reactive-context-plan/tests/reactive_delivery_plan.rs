#![allow(clippy::expect_used, clippy::unwrap_used, dead_code)]

#[path = "support/reactive_plan.rs"]
mod support;

use eliot_reactive_context_plan::{
    DeliveryDisposition, PlanningErrorKind, ReactiveContextPlanResult,
    plan_pending_context_injection,
};

#[test]
fn tool_plan_is_replayable_and_event_requires_exact_coverage() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let first = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let second = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert_eq!(first, second);
    assert!(matches!(first, ReactiveContextPlanResult::Pending(_)));
    if let ReactiveContextPlanResult::Pending(plan) = &first {
        assert_eq!(
            plan.request.mode,
            eliot_context_contracts::ReactiveDeliveryMode::ToolOnly
        );
        assert!(plan.items.iter().any(|item| {
            item.disposition == DeliveryDisposition::ToolOnlyAdvisory
                && item.kind == eliot_reactive_context_plan::PlannedItemKind::Context
        }));
    }

    let mut event_coverage = coverage.clone();
    event_coverage.supported_modes =
        vec![eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated];
    event_coverage.profile_digest = event_coverage.canonical_digest().unwrap();
    let mut event_policy = policy.clone();
    event_policy.allowed_modes =
        vec![eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated];
    event_policy.policy_digest = event_policy.canonical_digest().unwrap();
    let unsupported = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &event_coverage,
        &event_policy,
    );
    let event_plan = match unsupported {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected event-integrated plan, got {other:?}"),
    };
    assert_eq!(
        event_plan.request.mode,
        eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated
    );
    assert!(
        event_plan
            .items
            .iter()
            .any(|item| item.disposition == DeliveryDisposition::EventPlan)
    );

    let unsupported = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &event_policy,
    );
    assert!(matches!(
        unsupported,
        ReactiveContextPlanResult::NoInjection(_)
    ));
}

#[test]
fn exact_source_and_profile_identity_control_deduplication() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let duplicate = plan_pending_context_injection(
        &view,
        &activation,
        &delivered,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(
        duplicate,
        ReactiveContextPlanResult::NoInjection(_)
    ));
    if let ReactiveContextPlanResult::NoInjection(noop) = duplicate {
        assert_eq!(
            noop.items
                .iter()
                .filter(|item| item.disposition == DeliveryDisposition::DeliveredDuplicate)
                .count(),
            1,
            "one exact delivered duplicate should be retained"
        );
        assert_eq!(noop.accounting.deduped, 1);
        assert!(noop.items.iter().any(|item| {
            item.item_id == support::a15::id("atom").to_string()
                && item.disposition == DeliveryDisposition::DeliveredDuplicate
        }));
    }
    let mut changed_admitted = view.admitted.clone();
    let changed_source_revision = "r2".to_owned();
    let changed_source_digest = "c".repeat(64);
    changed_admitted.records[0].candidate.source.revision = changed_source_revision.clone();
    changed_admitted.records[0].candidate.source.content_sha256 = changed_source_digest.clone();
    let changed_view = support::reseal_context_view(
        support::a15::id("view-changed"),
        &view.view,
        changed_admitted,
        None,
    );
    let mut changed_activation = activation.clone();
    changed_activation.expected_view_id = Some(changed_view.view_id.clone());
    changed_activation.expected_admitted_set_digest =
        Some(changed_view.admitted_canonical_sha256.clone());
    changed_activation.target_bindings[0].source_revision = Some(changed_source_revision);
    changed_activation.target_bindings[0].source_digest = Some(changed_source_digest);
    let mut fresh_policy = policy.clone();
    fresh_policy.request_id = eliot_contracts::RequestId::new("request-fresh").unwrap();
    fresh_policy.operation_id = eliot_contracts::OperationId::new("operation-fresh").unwrap();
    fresh_policy.idempotency_key = "idempotency-fresh".into();
    fresh_policy.policy_digest = fresh_policy.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &changed_view,
        &changed_activation,
        &delivered,
        &attention,
        &coverage,
        &fresh_policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::Pending(_)));
    if let ReactiveContextPlanResult::Pending(plan) = result {
        assert_eq!(plan.accounting.deduped, 0);
        assert!(plan.items.iter().any(|item| {
            item.item_id == support::a15::id("atom").to_string()
                && item.disposition == DeliveryDisposition::ToolOnlyAdvisory
        }));
    }

    let result = plan_pending_context_injection(
        &changed_view,
        &changed_activation,
        &delivered,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(
        result,
        ReactiveContextPlanResult::Error(error)
            if error.kind == PlanningErrorKind::IdentityConflict
    ));
}

#[test]
fn unknown_inflight_history_is_retained_as_ambiguous() {
    let (view, activation, mut session, attention, coverage, policy) =
        support::inputs(false, false);
    let mut record = support::a15::unknown_record();
    record.item_id = "atom".into();
    record.operation_id = policy.operation_id.clone();
    record.request_id = policy.request_id.clone();
    record.idempotency_key = policy.idempotency_key.clone();
    let atom = &view.view.rendered[0];
    let contract = eliot_protocol::reactive_context_contract_identity().unwrap();
    record.content.contract = contract.clone();
    record
        .content
        .source_revision
        .clone_from(&atom.source_revision);
    record.content.artifact_id = Some(atom.atom_id.clone());
    record.content.content_sha256 =
        eliot_context_contracts::canonical_planning_digest(&atom.representation).unwrap();
    record.content.byte_length = Some(
        eliot_contracts::canonical_json_bytes(&atom.representation)
            .unwrap()
            .len() as u64,
    );
    record.source.contract = contract;
    record
        .source
        .source_revision
        .clone_from(&atom.source_revision);
    record.source.artifact_id = Some(atom.source_id.clone());
    record.source.content_sha256 = view.view.rendered[0].source_digest.clone();
    record.source.byte_length = None;
    record.profile = policy.delivery_profile.clone();
    session.records.push(record);
    session.denominator.observed = 1;
    session.denominator.expected = Some(1);
    session.denominator.completeness = eliot_context_contracts::SnapshotCompleteness::Complete;
    session.snapshot_digest = session.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::NoInjection(_)));
    if let ReactiveContextPlanResult::NoInjection(noop) = result {
        assert_eq!(noop.accounting.planned, 0);
        assert_eq!(noop.accounting.selected_delivery_bytes, 0);
        assert_eq!(noop.accounting.selected_delivery_stu, None);
        assert!(
            noop.items
                .iter()
                .any(|item| item.disposition == DeliveryDisposition::AmbiguousUnknown)
        );
    }
}

#[test]
fn acknowledged_open_attention_stays_sticky_until_owner_resolution() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(true, true);
    let input_member = &attention.members[0];
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::Pending(_)));
    if let ReactiveContextPlanResult::Pending(plan) = result {
        let open_item = plan
            .items
            .iter()
            .find(|item| item.disposition == DeliveryDisposition::StickyPendingResolution)
            .expect("open Attention ledger item");
        let binding = open_item.attention.as_ref().expect("Attention binding");
        assert_eq!(binding.attention_id, input_member.attention_id);
        assert_eq!(binding.claim_artifact_id, input_member.claim_artifact_id);
        assert_eq!(binding.claim_digest, input_member.claim_digest);
        assert_eq!(binding.source_revision, input_member.source_revision);
        assert_eq!(binding.member_owner_id, input_member.owner_id);
        assert_eq!(binding.resolution_owner, input_member.owner_id);
        assert_eq!(
            binding.resolution,
            eliot_context_contracts::AttentionResolution::Open
        );
        assert!(binding.sticky);
        assert!(plan.request.items.iter().any(|item| {
            item.kind == eliot_reactive_context_plan::PlannedItemKind::Attention
                && item.item_id == open_item.item_id
        }));
    }
    let resolved_attention = support::resolved_attention_projection();
    let resolved_member = &resolved_attention.members[0];
    let resolved = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &resolved_attention,
        &coverage,
        &policy,
    );
    assert!(matches!(
        resolved,
        ReactiveContextPlanResult::Pending(_) | ReactiveContextPlanResult::NoInjection(_)
    ));
    let resolved_items = match resolved {
        ReactiveContextPlanResult::Pending(plan) => plan.items,
        ReactiveContextPlanResult::NoInjection(noop) => noop.items,
        ReactiveContextPlanResult::Error(_) => unreachable!(),
    };
    assert!(
        !resolved_items
            .iter()
            .any(|item| item.disposition == DeliveryDisposition::StickyPendingResolution)
    );
    let resolved_item = resolved_items
        .iter()
        .find(|item| item.kind == eliot_reactive_context_plan::PlannedItemKind::Attention)
        .expect("resolved Attention ledger item");
    let binding = resolved_item.attention.as_ref().expect("resolved binding");
    assert_eq!(
        resolved_item.disposition,
        DeliveryDisposition::ExplicitNotSelected
    );
    assert_eq!(binding.attention_id, resolved_member.attention_id);
    assert_eq!(binding.claim_artifact_id, resolved_member.claim_artifact_id);
    assert_eq!(binding.claim_digest, resolved_member.claim_digest);
    assert_eq!(binding.source_revision, resolved_member.source_revision);
    assert_eq!(binding.member_owner_id, resolved_member.owner_id);
    assert_eq!(binding.resolution_owner, resolved_member.owner_id);
    assert_eq!(
        binding.resolution,
        eliot_context_contracts::AttentionResolution::Resolved
    );
    assert!(!binding.sticky);
}

#[test]
fn optional_dependency_closure_is_atomic_and_budgeted() {
    let (view, activation, session, attention, coverage, mut policy) =
        support::optional_dependency_inputs();
    let full = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let full_plan = match full {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected full optional plan, got {other:?}"),
    };
    assert!(full_plan.items.iter().any(|item| {
        item.item_id == support::a15::id("atom").to_string()
            && item.disposition == DeliveryDisposition::ToolOnlyAdvisory
    }));
    assert!(full_plan.items.iter().any(|item| {
        item.item_id == support::a15::id("optional-a").to_string()
            && item.disposition == DeliveryDisposition::ToolOnlyAdvisory
    }));
    assert!(full_plan.items.iter().any(|item| {
        item.item_id == support::a15::id("optional-b").to_string()
            && item.disposition == DeliveryDisposition::ToolOnlyAdvisory
    }));
    let mut requested_ids: Vec<_> = full_plan
        .request
        .items
        .iter()
        .map(|item| item.item_id.clone())
        .collect();
    requested_ids.sort();
    let mut expected_ids = vec![
        support::a15::id("atom").to_string(),
        support::a15::id("optional-a").to_string(),
        support::a15::id("optional-b").to_string(),
    ];
    expected_ids.sort();
    assert_eq!(requested_ids, expected_ids);
    let requested_b = full_plan
        .request
        .items
        .iter()
        .find(|item| item.item_id == support::a15::id("optional-b").to_string())
        .expect("optional B request item");
    let ledger_b = full_plan
        .items
        .iter()
        .find(|item| item.item_id == support::a15::id("optional-b").to_string())
        .expect("optional B ledger item");
    assert_eq!(requested_b.disposition, ledger_b.disposition);
    let reserve_sum = policy
        .fixed_reserve
        .checked_add(policy.protocol_reserve)
        .and_then(|value| value.checked_add(policy.output_reserve))
        .and_then(|value| value.checked_add(policy.review_reserve))
        .and_then(|value| value.checked_add(policy.delivery_reserve))
        .unwrap();
    policy.max_delivery_bytes = reserve_sum + full_plan.request.serialized_bytes - 1;
    policy.policy_digest = policy.canonical_digest().unwrap();
    let limited = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let limited_plan = match limited {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected required-only optional plan, got {other:?}"),
    };
    assert_eq!(
        limited_plan.request.items.len(),
        1,
        "the required floor must remain selected"
    );
    assert_eq!(
        limited_plan.request.items[0].item_id,
        support::a15::id("atom").to_string()
    );
    assert!(limited_plan.items.iter().any(|item| {
        item.item_id == support::a15::id("optional-a").to_string()
            && item.disposition == DeliveryDisposition::WithheldBudget
    }));
    assert!(limited_plan.items.iter().any(|item| {
        item.item_id == support::a15::id("optional-b").to_string()
            && item.disposition == DeliveryDisposition::ExplicitNotSelected
    }));
}

#[test]
fn safety_floor_and_attention_capacity_shortfall_refuse_injection() {
    let (view, activation, session, attention, coverage, mut policy) = support::inputs(true, true);
    policy.max_delivery_bytes = policy.fixed_reserve
        + policy.protocol_reserve
        + policy.output_reserve
        + policy.review_reserve
        + policy.delivery_reserve
        + 1;
    policy.policy_digest = policy.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::NoInjection(_)));
    if let ReactiveContextPlanResult::NoInjection(noop) = result {
        assert_eq!(noop.accounting.planned, 0);
        assert_eq!(noop.accounting.sticky, 1);
        assert!(noop.accounting.required_floor_bytes > 0);
        assert!(!noop.accounting.budget_fit);
        assert!(!noop.items.is_empty());
    }
}
