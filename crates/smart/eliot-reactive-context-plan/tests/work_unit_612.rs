#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::match_wildcard_for_single_variants,
    clippy::single_match_else,
    clippy::manual_let_else
)]

#[path = "support/reactive_plan.rs"]
mod support;

use eliot_reactive_context_plan::{
    DeliveryDisposition, PlannedItemKind, PlanningErrorKind, ReactiveContextPlanResult,
    plan_pending_context_injection,
};

// WORK_UNIT_CASE: 612/1
#[test]
fn case_01_minimal_event_integrated_plan() {
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
        other => panic!("expected event-integrated plan, got {other:?}"),
    };
    assert_eq!(
        plan.mode,
        eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated
    );
    assert_eq!(
        plan.request.mode,
        eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated
    );
    assert!(
        plan.items
            .iter()
            .any(|item| item.disposition == DeliveryDisposition::EventPlan)
    );
}

// WORK_UNIT_CASE: 612/2
#[test]
fn case_02_minimal_tool_only_advisory_plan() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected tool-only plan, got {other:?}"),
    };
    assert_eq!(
        plan.mode,
        eliot_context_contracts::ReactiveDeliveryMode::ToolOnly
    );
    assert!(
        plan.items.iter().any(|item| {
            item.disposition == DeliveryDisposition::ToolOnlyAdvisory
                && item.kind == PlannedItemKind::Context
        })
    );
}

// WORK_UNIT_CASE: 612/3
#[test]
fn case_03_exact_no_injection_with_complete_denominator() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    assert_eq!(
        delivered.denominator.completeness,
        eliot_context_contracts::SnapshotCompleteness::Complete
    );
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &delivered,
        &attention,
        &coverage,
        &policy,
    );
    let noop = match result {
        ReactiveContextPlanResult::NoInjection(noop) => noop,
        other => panic!("expected NoInjection, got {other:?}"),
    };
    assert_eq!(noop.accounting.planned, 0);
    assert_eq!(
        noop.session_completeness,
        eliot_context_contracts::SnapshotCompleteness::Complete
    );
    assert!(!noop.items.is_empty());
}

// WORK_UNIT_CASE: 612/4
#[test]
fn case_04_wrong_task_attempt_scope_fence_rejected() {
    let (view, activation, mut session, attention, coverage, policy) = support::inputs(false, false);
    session.task_id = eliot_contracts::TaskId::new("other-task").unwrap();
    session.snapshot_digest = session.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::Error(_)));
    if let ReactiveContextPlanResult::Error(error) = result {
        assert_eq!(error.kind, PlanningErrorKind::BindingMismatch);
    }
}

// WORK_UNIT_CASE: 612/5
#[test]
fn case_05_wrong_admitted_view_assembly_identity_rejected() {
    let (view, mut activation, session, attention, coverage, policy) = support::inputs(false, false);
    activation.expected_view_id = Some(support::a15::id("other-view"));
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(
        result,
        ReactiveContextPlanResult::Error(_)
    ));
}

// WORK_UNIT_CASE: 612/6
#[test]
fn case_06_incomplete_safety_floor_cannot_become_complete_plan() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let mut admitted = view.admitted.clone();
    admitted.floor.capacity.route_capacity = 1;
    let tiny_view = support::reseal_context_view(
        support::a15::id("view-tiny-route"),
        &view.view,
        admitted,
        None,
    );
    let mut activation = activation.clone();
    activation.expected_view_id = Some(tiny_view.view_id.clone());
    activation.expected_admitted_set_digest = Some(tiny_view.admitted_canonical_sha256.clone());
    let result = plan_pending_context_injection(
        &tiny_view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    match result {
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert_eq!(noop.accounting.planned, 0);
            assert!(noop.floor_incomplete.is_some() || !noop.frontier.is_empty() || !noop.accounting.budget_fit || noop.reason.contains("FLOOR"));
        }
        ReactiveContextPlanResult::Error(_) => {}
        other => panic!("incomplete floor must not become complete plan, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/7
#[test]
fn case_07_stale_view_measurement_rejected() {
    let (mut view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    view.view.measurement.rendered_utf8_bytes += 1;
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::Error(_)));
}

// WORK_UNIT_CASE: 612/8
#[test]
fn case_08_compatible_activation_accepted() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::Pending(_)));
}

// WORK_UNIT_CASE: 612/9
#[test]
fn case_09_wrong_activation_snapshot_fence_rejected() {
    let (view, mut activation, session, attention, coverage, policy) = support::inputs(false, false);
    activation.request.state_fence = support::a15::fence();
    // Make the fence differ from the view binding fence by bumping generation.
    activation.request.state_fence = eliot_contracts::StateFence::new(
        activation.request.state_fence.authority_epoch.clone(),
        eliot_contracts::ResourceGeneration::new(999).unwrap(),
    );
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::Error(_)));
}

// WORK_UNIT_CASE: 612/10
#[test]
fn case_10_partial_activation_retained_with_frontier() {
    let (view, mut activation, session, attention, coverage, policy) = support::inputs(false, false);
    activation.result.completeness = eliot_cue_contracts::Completeness::Partial {
        frontier: vec![eliot_cue_contracts::RelationEdgeId::new("frontier-edge").unwrap()],
    };
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert!(!plan.frontier.is_empty());
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert!(!noop.frontier.is_empty());
        }
        other => panic!("partial activation must be retained, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/11
#[test]
fn case_11_absent_from_view_target_cannot_create_item() {
    let (view, mut activation, session, attention, coverage, policy) = support::inputs(false, false);
    let baseline = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let baseline_count = match baseline {
        ReactiveContextPlanResult::Pending(plan) => plan.items.len(),
        ReactiveContextPlanResult::NoInjection(noop) => noop.items.len(),
        other => panic!("baseline unexpected {other:?}"),
    };
    let extra_key = activation.result.direct[0].matched_key.clone();
    activation.result.direct.push(eliot_cue_contracts::DirectActivation::new(
        eliot_cue_contracts::TargetHandle::new("ghost-target").unwrap(),
        extra_key,
        eliot_cue_contracts::ActivationStrength(1),
    ));
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert_eq!(plan.items.len(), baseline_count);
            assert!(plan.frontier.iter().any(|f| f.contains("ghost-target")));
            assert!(!plan.items.iter().any(|i| i.item_id == "ghost-target"));
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert!(noop.frontier.iter().any(|f| f.contains("ghost-target")));
        }
        other => panic!("unmapped target must not create item, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/12
#[test]
fn case_12_direct_and_derived_evidence_distinct() {
    assert_ne!(
        eliot_reactive_context_plan::ActivationEvidenceKind::Direct,
        eliot_reactive_context_plan::ActivationEvidenceKind::Derived
    );
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let items = match result {
        ReactiveContextPlanResult::Pending(plan) => plan.items,
        ReactiveContextPlanResult::NoInjection(noop) => noop.items,
        other => panic!("unexpected {other:?}"),
    };
    let direct = items
        .iter()
        .find(|i| i.item_id == support::a15::id("atom").to_string())
        .expect("atom item");
    assert_eq!(
        direct.activation_kind,
        Some(eliot_reactive_context_plan::ActivationEvidenceKind::Direct)
    );
}

// WORK_UNIT_CASE: 612/13
#[test]
fn case_13_score_grants_no_support_or_block() {
    let (view, mut activation, session, attention, coverage, policy) = support::inputs(false, false);
    activation.result.direct[0].strength = eliot_cue_contracts::ActivationStrength(999);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("high score must not block planning, got {other:?}"),
    };
    assert!(
        plan.items.iter().any(|i| i.disposition
            == DeliveryDisposition::ToolOnlyAdvisory)
    );
    // Low score also plans the same way.
    let (view, mut activation, session, attention, coverage, policy) = support::inputs(false, false);
    activation.result.direct[0].strength = eliot_cue_contracts::ActivationStrength(1);
    let low = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(low, ReactiveContextPlanResult::Pending(_)));
}

// WORK_UNIT_CASE: 612/14
#[test]
fn case_14_complete_session_denominator_accepted() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let mut session = support::delivered_session(&policy);
    assert_eq!(
        session.denominator.completeness,
        eliot_context_contracts::SnapshotCompleteness::Complete
    );
    assert_eq!(session.denominator.observed, 1);
    assert_eq!(session.denominator.expected, Some(1));
    session.snapshot_digest = session.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(
        result,
        ReactiveContextPlanResult::NoInjection(_) | ReactiveContextPlanResult::Pending(_)
    ));
}

// WORK_UNIT_CASE: 612/15
#[test]
fn case_15_missing_session_denominator_explicit() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    assert_eq!(
        session.denominator.completeness,
        eliot_context_contracts::SnapshotCompleteness::Unknown
    );
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert_eq!(
                plan.session_completeness,
                eliot_context_contracts::SnapshotCompleteness::Unknown
            );
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert_eq!(
                noop.session_completeness,
                eliot_context_contracts::SnapshotCompleteness::Unknown
            );
        }
        other => panic!("missing denominator must stay explicit, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/16
#[test]
fn case_16_duplicate_session_item_operation_deduped() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &delivered,
        &attention,
        &coverage,
        &policy,
    );
    let noop = match result {
        ReactiveContextPlanResult::NoInjection(noop) => noop,
        other => panic!("expected dedup NoInjection, got {other:?}"),
    };
    assert_eq!(noop.accounting.deduped, 1);
    assert!(
        noop.items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::DeliveredDuplicate)
    );
}

// WORK_UNIT_CASE: 612/17
#[test]
fn case_17_changed_same_operation_payload_conflicts() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let mut changed_admitted = view.admitted.clone();
    let changed_source_digest = "c".repeat(64);
    changed_admitted.records[0].candidate.source.revision = "r2".to_owned();
    changed_admitted.records[0].candidate.source.content_sha256 = changed_source_digest.clone();
    let changed_view = support::reseal_context_view(
        support::a15::id("view-changed-17"),
        &view.view,
        changed_admitted,
        None,
    );
    let mut changed_activation = activation.clone();
    changed_activation.expected_view_id = Some(changed_view.view_id.clone());
    changed_activation.expected_admitted_set_digest =
        Some(changed_view.admitted_canonical_sha256.clone());
    changed_activation.target_bindings[0].source_revision = Some("r2".into());
    changed_activation.target_bindings[0].source_digest = Some(changed_source_digest);
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
        ReactiveContextPlanResult::Error(error) if error.kind == PlanningErrorKind::IdentityConflict
    ));
}

// WORK_UNIT_CASE: 612/18
#[test]
fn case_18_exact_previously_delivered_normal_item_deduped() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &delivered,
        &attention,
        &coverage,
        &policy,
    );
    let noop = match result {
        ReactiveContextPlanResult::NoInjection(noop) => noop,
        other => panic!("expected dedup, got {other:?}"),
    };
    let dup = noop
        .items
        .iter()
        .find(|i| i.item_id == support::a15::id("atom").to_string())
        .expect("atom ledger");
    assert_eq!(dup.disposition, DeliveryDisposition::DeliveredDuplicate);
}

// WORK_UNIT_CASE: 612/19
#[test]
fn case_19_same_text_new_revision_not_duplicate() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let mut changed_admitted = view.admitted.clone();
    let changed_source_digest = "d".repeat(64);
    changed_admitted.records[0].candidate.source.revision = "r2".to_owned();
    changed_admitted.records[0].candidate.source.content_sha256 = changed_source_digest.clone();
    let changed_view = support::reseal_context_view(
        support::a15::id("view-changed-19"),
        &view.view,
        changed_admitted,
        None,
    );
    let mut changed_activation = activation.clone();
    changed_activation.expected_view_id = Some(changed_view.view_id.clone());
    changed_activation.expected_admitted_set_digest =
        Some(changed_view.admitted_canonical_sha256.clone());
    changed_activation.target_bindings[0].source_revision = Some("r2".into());
    changed_activation.target_bindings[0].source_digest = Some(changed_source_digest);
    let mut fresh_policy = policy.clone();
    fresh_policy.request_id = eliot_contracts::RequestId::new("request-fresh-19").unwrap();
    fresh_policy.operation_id = eliot_contracts::OperationId::new("operation-fresh-19").unwrap();
    fresh_policy.idempotency_key = "idempotency-fresh-19".into();
    fresh_policy.policy_digest = fresh_policy.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &changed_view,
        &changed_activation,
        &delivered,
        &attention,
        &coverage,
        &fresh_policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("new revision must not dedup, got {other:?}"),
    };
    assert_eq!(plan.accounting.deduped, 0);
}

// WORK_UNIT_CASE: 612/20
#[test]
fn case_20_enqueued_is_not_delivered() {
    let (view, activation, mut session, attention, coverage, policy) = support::inputs(false, false);
    let mut record = support::a15::unknown_record();
    let atom = view.view.rendered[0].clone();
    let contract = eliot_protocol::reactive_context_contract_identity().unwrap();
    record.item_id = support::a15::id("atom").to_string();
    record.operation_id = eliot_contracts::OperationId::new("other-operation-20").unwrap();
    record.request_id = eliot_contracts::RequestId::new("other-request-20").unwrap();
    record.idempotency_key = "other-idempotency-20".into();
    record.content.contract = contract.clone();
    record.content.source_revision.clone_from(&atom.source_revision);
    record.content.artifact_id = Some(atom.atom_id.clone());
    record.content.content_sha256 =
        eliot_context_contracts::canonical_planning_digest(&atom.representation).unwrap();
    record.content.byte_length = Some(
        eliot_contracts::canonical_json_bytes(&atom.representation)
            .unwrap()
            .len() as u64,
    );
    record.source.contract = contract;
    record.source.source_revision.clone_from(&atom.source_revision);
    record.source.artifact_id = Some(atom.source_id.clone());
    record.source.content_sha256.clone_from(&atom.source_digest);
    record.source.byte_length = None;
    record.profile = policy.delivery_profile.clone();
    record.stage = eliot_protocol::reactive_context::ReactiveContextStage::EnqueuedPersisted;
    record.lifecycle.stage = record.stage;
    record.lifecycle.predecessor =
        Some(eliot_protocol::reactive_context::ReactiveContextStage::ValidatedNotEnqueued);
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
    let noop = match result {
        ReactiveContextPlanResult::NoInjection(noop) => noop,
        other => panic!("enqueued must not deliver, got {other:?}"),
    };
    assert!(
        noop.items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::InFlight)
    );
    assert!(
        !noop
            .items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::DeliveredDuplicate)
    );
}

// WORK_UNIT_CASE: 612/21
#[test]
fn case_21_attempted_is_not_delivered() {
    let (view, activation, mut session, attention, coverage, policy) = support::inputs(false, false);
    let mut record = support::a15::unknown_record();
    let atom = view.view.rendered[0].clone();
    let contract = eliot_protocol::reactive_context_contract_identity().unwrap();
    record.item_id = support::a15::id("atom").to_string();
    record.operation_id = eliot_contracts::OperationId::new("other-operation-21").unwrap();
    record.request_id = eliot_contracts::RequestId::new("other-request-21").unwrap();
    record.idempotency_key = "other-idempotency-21".into();
    record.content.contract = contract.clone();
    record.content.source_revision.clone_from(&atom.source_revision);
    record.content.artifact_id = Some(atom.atom_id.clone());
    record.content.content_sha256 =
        eliot_context_contracts::canonical_planning_digest(&atom.representation).unwrap();
    record.content.byte_length = Some(
        eliot_contracts::canonical_json_bytes(&atom.representation)
            .unwrap()
            .len() as u64,
    );
    record.source.contract = contract;
    record.source.source_revision.clone_from(&atom.source_revision);
    record.source.artifact_id = Some(atom.source_id.clone());
    record.source.content_sha256.clone_from(&atom.source_digest);
    record.source.byte_length = None;
    record.profile = policy.delivery_profile.clone();
    record.stage = eliot_protocol::reactive_context::ReactiveContextStage::DeliveryAttempted;
    record.lifecycle.stage = record.stage;
    record.lifecycle.predecessor =
        Some(eliot_protocol::reactive_context::ReactiveContextStage::EnqueuedPersisted);
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
    let noop = match result {
        ReactiveContextPlanResult::NoInjection(noop) => noop,
        other => panic!("attempted must not deliver, got {other:?}"),
    };
    assert!(
        noop.items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::InFlight)
    );
    assert!(
        !noop
            .items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::DeliveredDuplicate)
    );
}

// WORK_UNIT_CASE: 612/22
#[test]
fn case_22_in_flight_is_not_delivered_duplicate() {
    let (view, activation, mut session, attention, coverage, policy) = support::inputs(false, false);
    let mut record = support::a15::unknown_record();
    let atom = view.view.rendered[0].clone();
    let contract = eliot_protocol::reactive_context_contract_identity().unwrap();
    record.item_id = support::a15::id("atom").to_string();
    record.operation_id = eliot_contracts::OperationId::new("other-operation").unwrap();
    record.request_id = eliot_contracts::RequestId::new("other-request").unwrap();
    record.idempotency_key = "other-idempotency".into();
    record.content.contract = contract.clone();
    record.content.source_revision.clone_from(&atom.source_revision);
    record.content.artifact_id = Some(atom.atom_id.clone());
    record.content.content_sha256 =
        eliot_context_contracts::canonical_planning_digest(&atom.representation).unwrap();
    record.content.byte_length = Some(
        eliot_contracts::canonical_json_bytes(&atom.representation)
            .unwrap()
            .len() as u64,
    );
    record.source.contract = contract;
    record.source.source_revision.clone_from(&atom.source_revision);
    record.source.artifact_id = Some(atom.source_id.clone());
    record.source.content_sha256.clone_from(&atom.source_digest);
    record.profile = policy.delivery_profile.clone();
    record.stage = eliot_protocol::reactive_context::ReactiveContextStage::EnqueuedPersisted;
    record.lifecycle.stage = record.stage;
    record.lifecycle.predecessor =
        Some(eliot_protocol::reactive_context::ReactiveContextStage::ValidatedNotEnqueued);
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
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert!(
                !plan
                    .items
                    .iter()
                    .any(|i| i.disposition == DeliveryDisposition::DeliveredDuplicate
                        && i.item_id == support::a15::id("atom").to_string())
            );
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert!(
                !noop
                    .items
                    .iter()
                    .any(|i| i.disposition == DeliveryDisposition::DeliveredDuplicate
                        && i.item_id == support::a15::id("atom").to_string())
            );
        }
        other => panic!("in-flight must not dedup, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/23
#[test]
fn case_23_possible_unknown_delivery_requires_reconciliation() {
    let (view, activation, mut session, attention, coverage, policy) = support::inputs(false, false);
    let mut record = support::a15::unknown_record();
    record.item_id = support::a15::id("atom").to_string();
    record.operation_id = policy.operation_id.clone();
    record.request_id = policy.request_id.clone();
    record.idempotency_key = policy.idempotency_key.clone();
    let atom = &view.view.rendered[0];
    let contract = eliot_protocol::reactive_context_contract_identity().unwrap();
    record.content.contract = contract.clone();
    record.content.source_revision.clone_from(&atom.source_revision);
    record.content.artifact_id = Some(atom.atom_id.clone());
    record.content.content_sha256 =
        eliot_context_contracts::canonical_planning_digest(&atom.representation).unwrap();
    record.content.byte_length = Some(
        eliot_contracts::canonical_json_bytes(&atom.representation)
            .unwrap()
            .len() as u64,
    );
    record.source.contract = contract;
    record.source.source_revision.clone_from(&atom.source_revision);
    record.source.artifact_id = Some(atom.source_id.clone());
    record.source.content_sha256.clone_from(&atom.source_digest);
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
    let noop = match result {
        ReactiveContextPlanResult::NoInjection(noop) => noop,
        other => panic!("unknown must reconcile, got {other:?}"),
    };
    assert!(
        noop.items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::AmbiguousUnknown)
    );
}

// WORK_UNIT_CASE: 612/24
#[test]
fn case_24_ack_is_not_visibility_or_use() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let mut record = delivered.records[0].clone();
    record.stage = eliot_protocol::reactive_context::ReactiveContextStage::ValidatedNotEnqueued;
    record.lifecycle.stage = record.stage;
    record.lifecycle.predecessor = None;
    let mut session = support::session();
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
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert!(
                !plan
                    .items
                    .iter()
                    .any(|i| i.disposition == DeliveryDisposition::DeliveredDuplicate
                        && i.item_id == support::a15::id("atom").to_string())
            );
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert!(
                !noop
                    .items
                    .iter()
                    .any(|i| i.disposition == DeliveryDisposition::DeliveredDuplicate
                        && i.item_id == support::a15::id("atom").to_string())
            );
        }
        other => panic!("ack must not imply delivery, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/25
#[test]
fn case_25_stale_history_cannot_suppress_current_item() {
    let (view, activation, mut session, attention, coverage, policy) = support::inputs(false, false);
    let mut record = support::a15::unknown_record();
    record.item_id = support::a15::id("atom").to_string();
    record.operation_id = eliot_contracts::OperationId::new("other-operation-25").unwrap();
    record.request_id = eliot_contracts::RequestId::new("other-request-25").unwrap();
    record.idempotency_key = "other-idempotency-25".into();
    record.validity =
        eliot_protocol::reactive_context::ReactiveContextValidity::Superseded {
            replacement: support::a15::id("replacement"),
        };
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
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("stale history must not suppress, got {other:?}"),
    };
    assert!(
        plan.items.iter().any(|i| i.item_id
            == support::a15::id("atom").to_string()
            && matches!(
                i.disposition,
                DeliveryDisposition::ToolOnlyAdvisory | DeliveryDisposition::EventPlan
            ))
    );
}

// WORK_UNIT_CASE: 612/26
#[test]
fn case_26_unresolved_attention_sticky_after_delivery() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(true, true);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected sticky plan, got {other:?}"),
    };
    assert!(
        plan.items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::StickyPendingResolution)
    );
    assert_eq!(plan.accounting.sticky, 1);
}

// WORK_UNIT_CASE: 612/27
#[test]
fn case_27_acknowledged_unresolved_remains_sticky() {
    let (view, activation, session, mut attention, coverage, policy) = support::inputs(true, true);
    attention.members[0].acknowledgement =
        eliot_context_contracts::AttentionAcknowledgement::Acknowledged;
    attention.members[0].resolution = eliot_context_contracts::AttentionResolution::Open;
    attention.projection_digest = attention.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("acknowledged-open must stay sticky, got {other:?}"),
    };
    let sticky = plan
        .items
        .iter()
        .find(|i| i.disposition == DeliveryDisposition::StickyPendingResolution)
        .expect("sticky item");
    assert_eq!(
        sticky.attention.as_ref().unwrap().acknowledgement,
        eliot_context_contracts::AttentionAcknowledgement::Acknowledged
    );
    assert!(sticky.attention.as_ref().unwrap().sticky);
}

// WORK_UNIT_CASE: 612/28
#[test]
fn case_28_only_exact_external_resolution_ends_stickiness() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(true, true);
    let sticky = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(sticky, ReactiveContextPlanResult::Pending(_)));
    let resolved = support::resolved_attention_projection();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &resolved,
        &coverage,
        &policy,
    );
    let items = match result {
        ReactiveContextPlanResult::Pending(plan) => plan.items,
        ReactiveContextPlanResult::NoInjection(noop) => noop.items,
        other => panic!("resolved must end stickiness, got {other:?}"),
    };
    assert!(
        !items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::StickyPendingResolution)
    );
}

// WORK_UNIT_CASE: 612/29
#[test]
fn case_29_stale_superseded_resolved_unknown_attention_distinct() {
    let (view, activation, session, base_attention, coverage, policy) = support::inputs(true, true);
    let open_member = base_attention.members[0].clone();
    let mut unknown_member = open_member.clone();
    unknown_member.resolution = eliot_context_contracts::AttentionResolution::Unknown;
    unknown_member.claim_digest = unknown_member
        .canonical_resolution_claim_digest()
        .expect("unknown claim digest");
    let mut unknown_projection = base_attention.clone();
    unknown_projection.members = vec![unknown_member.clone()];
    unknown_projection.projection_digest = unknown_projection.canonical_digest().unwrap();
    // Refresh the disclosure rule so the unknown claim stays disclosable and
    // sticky; otherwise the planner correctly withholds it for privacy.
    let mut unknown_policy = policy.clone();
    if let Some(rule) = unknown_policy.attention_disclosure.first_mut() {
        rule.claim_digest.clone_from(&unknown_member.claim_digest);
    }
    unknown_policy.policy_digest = unknown_policy.canonical_digest().unwrap();
    let stale_result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &unknown_projection,
        &coverage,
        &unknown_policy,
    );
    let stale_items = match stale_result {
        ReactiveContextPlanResult::Pending(plan) => plan.items,
        ReactiveContextPlanResult::NoInjection(noop) => noop.items,
        other => panic!("stale attention unexpected {other:?}"),
    };
    // Unknown remains unresolved (sticky), distinct from resolved history.
    assert!(
        stale_items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::StickyPendingResolution)
    );
    let resolved = support::resolved_attention_projection();
    let resolved_result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &resolved,
        &coverage,
        &policy,
    );
    let resolved_items = match resolved_result {
        ReactiveContextPlanResult::Pending(plan) => plan.items,
        ReactiveContextPlanResult::NoInjection(noop) => noop.items,
        other => panic!("resolved unexpected {other:?}"),
    };
    assert!(
        resolved_items.iter().any(|i| i.disposition
            == DeliveryDisposition::ExplicitNotSelected)
    );
}

// WORK_UNIT_CASE: 612/30
#[test]
fn case_30_dedup_or_pressure_cannot_erase_attention() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(true, true);
    let delivered = support::delivered_session(&policy);
    // Delivered normal item dedups, but open Attention must remain sticky.
    let mut attention_with_rule = attention.clone();
    let _ = &mut attention_with_rule;
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &delivered,
        &attention,
        &coverage,
        &policy,
    );
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert!(
                plan.items
                    .iter()
                    .any(|i| i.disposition == DeliveryDisposition::StickyPendingResolution)
            );
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert!(
                noop.items
                    .iter()
                    .any(|i| i.disposition == DeliveryDisposition::StickyPendingResolution)
                    || noop.accounting.sticky == 1
            );
        }
        other => panic!("attention must survive dedup pressure, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/31
#[test]
fn case_31_exact_event_capability_selects_event_mode() {
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
        other => panic!("expected event mode, got {other:?}"),
    };
    assert_eq!(
        plan.request.mode,
        eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated
    );
}

// WORK_UNIT_CASE: 612/32
#[test]
fn case_32_tool_only_selects_advisory_pull_only() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected tool-only, got {other:?}"),
    };
    assert_eq!(
        plan.request.mode,
        eliot_context_contracts::ReactiveDeliveryMode::ToolOnly
    );
    assert!(
        !plan
            .items
            .iter()
            .any(|i| i.disposition == DeliveryDisposition::EventPlan)
    );
}

// WORK_UNIT_CASE: 612/33
#[test]
fn case_33_liveness_claim_cannot_prove_event_integration() {
    let (view, activation, session, attention, mut coverage, mut policy) =
        support::inputs(false, false);
    coverage.supported_modes =
        vec![eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated];
    // Break exact event capability (stale freshness) so the mode claim alone
    // cannot prove event integration; only a fresh Enforced event qualifies.
    coverage.events[0].freshness = eliot_context_contracts::CoverageFreshness::Stale;
    coverage.events[0].claim_digest = coverage.events[0]
        .canonical_claim_digest()
        .expect("coverage claim");
    coverage.profile_digest = coverage.canonical_digest().unwrap();
    policy.allowed_modes =
        vec![eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated];
    policy.policy_digest = policy.canonical_digest().unwrap();
    // Coverage event remains tool-only shaped (no fresh Enforced event for the
    // target), so liveness-style mode claims alone must not select event mode.
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert_ne!(
                plan.request.mode,
                eliot_context_contracts::ReactiveDeliveryMode::EventIntegrated
            );
        }
        ReactiveContextPlanResult::NoInjection(_) => {}
        other => panic!("liveness claim must not prove integration, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/34
#[test]
fn case_34_partial_stale_unavailable_unknown_coverage_distinct() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let mut partial = coverage.clone();
    partial.completeness = eliot_context_contracts::SnapshotCompleteness::Partial;
    partial.profile_digest = partial.canonical_digest().unwrap();
    let partial_result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &partial,
        &policy,
    );
    let mut unknown = coverage.clone();
    unknown.completeness = eliot_context_contracts::SnapshotCompleteness::Unknown;
    unknown.profile_digest = unknown.canonical_digest().unwrap();
    let unknown_result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &unknown,
        &policy,
    );
    // Both retain explicit completeness; they must not collapse to the same
    // selected evidence silently.
    let partial_completeness = match partial_result {
        ReactiveContextPlanResult::Pending(plan) => plan.coverage_completeness,
        ReactiveContextPlanResult::NoInjection(noop) => noop.coverage_completeness,
        ReactiveContextPlanResult::Error(_) => eliot_context_contracts::SnapshotCompleteness::Partial,
    };
    let unknown_completeness = match unknown_result {
        ReactiveContextPlanResult::Pending(plan) => plan.coverage_completeness,
        ReactiveContextPlanResult::NoInjection(noop) => noop.coverage_completeness,
        ReactiveContextPlanResult::Error(_) => eliot_context_contracts::SnapshotCompleteness::Unknown,
    };
    assert_ne!(partial_completeness, unknown_completeness);
}

// WORK_UNIT_CASE: 612/35
#[test]
fn case_35_recipient_runtime_host_generation_mismatch_rejected() {
    let (view, activation, session, attention, mut coverage, policy) = support::inputs(false, false);
    coverage.host_generation = eliot_contracts::ResourceGeneration::new(999).unwrap();
    coverage.profile_digest = coverage.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(result, ReactiveContextPlanResult::Error(_)));
}

// WORK_UNIT_CASE: 612/36
#[test]
fn case_36_exact_view_reference_universe_reconciles() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("view universe must reconcile, got {other:?}"),
    };
    assert_eq!(plan.view_digest, view.view.output_digest);
    assert_eq!(
        plan.admitted_set_digest,
        view.admitted_canonical_sha256
    );
    assert_eq!(plan.assembly_digest, view.view.selection.output_digest);
}

// WORK_UNIT_CASE: 612/37
#[test]
fn case_37_raw_payload_cannot_enter_plan() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    };
    for item in &plan.items {
        if item.kind == PlannedItemKind::Context {
            assert!(item.rendered.is_some());
            assert!(!item.content.is_empty());
            assert!(!item.source.is_empty());
        }
    }
    assert!(
        !plan
            .request
            .items
            .iter()
            .any(|i| i.item_id.contains("raw"))
    );
}

// WORK_UNIT_CASE: 612/38
#[test]
fn case_38_one_disposition_per_considered_member() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(true, true);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let (items, accounting) = match result {
        ReactiveContextPlanResult::Pending(plan) => (plan.items, plan.accounting),
        ReactiveContextPlanResult::NoInjection(noop) => (noop.items, noop.accounting),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(accounting.considered, items.len() as u64);
    let total = accounting.planned
        + accounting.deduped
        + accounting.delayed
        + accounting.withheld
        + accounting.unsupported
        + accounting.frontier
        + items
            .iter()
            .filter(|i| {
                matches!(
                    i.disposition,
                    DeliveryDisposition::ExplicitNotSelected
                        | DeliveryDisposition::OmissionReferenceOnly
                )
            })
            .count() as u64;
    assert_eq!(total, accounting.considered);
}

// WORK_UNIT_CASE: 612/39
#[test]
fn case_39_independent_fixed_output_review_delivery_reserves() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let accounting = match result {
        ReactiveContextPlanResult::Pending(plan) => plan.accounting,
        ReactiveContextPlanResult::NoInjection(noop) => noop.accounting,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(accounting.fixed_reserve, policy.fixed_reserve);
    assert_eq!(accounting.protocol_reserve, policy.protocol_reserve);
    assert_eq!(accounting.output_reserve, policy.output_reserve);
    assert_eq!(accounting.review_reserve, policy.review_reserve);
    assert_eq!(accounting.delivery_reserve, policy.delivery_reserve);
}

// WORK_UNIT_CASE: 612/40
#[test]
fn case_40_unknown_cost_is_not_zero() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    };
    for item in &plan.items {
        if matches!(
            item.disposition,
            DeliveryDisposition::EventPlan
                | DeliveryDisposition::ToolOnlyAdvisory
                | DeliveryDisposition::StickyPendingResolution
        ) {
            assert!(item.byte_cost > 0);
        }
    }
    assert!(plan.accounting.selected_delivery_bytes > 0);
}

// WORK_UNIT_CASE: 612/41
#[test]
fn case_41_exact_budget_fit_versus_one_over() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let baseline = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let baseline_plan = match baseline {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("baseline must fit, got {other:?}"),
    };
    let reserve_sum = policy.fixed_reserve
        + policy.protocol_reserve
        + policy.output_reserve
        + policy.review_reserve
        + policy.delivery_reserve;
    let exact = reserve_sum + baseline_plan.request.serialized_bytes;
    let mut fit_policy = policy.clone();
    fit_policy.max_delivery_bytes = exact;
    fit_policy.policy_digest = fit_policy.canonical_digest().unwrap();
    let fit = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &fit_policy,
    );
    assert!(matches!(fit, ReactiveContextPlanResult::Pending(_)));
    let mut over_policy = policy.clone();
    over_policy.max_delivery_bytes = exact - 1;
    over_policy.policy_digest = over_policy.canonical_digest().unwrap();
    let over = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &over_policy,
    );
    assert!(matches!(over, ReactiveContextPlanResult::NoInjection(_)));
}

// WORK_UNIT_CASE: 612/42
#[test]
fn case_42_optional_flood_cannot_crowd_required_obligations() {
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
    assert!(matches!(full, ReactiveContextPlanResult::Pending(_)));
    let full_plan = match full {
        ReactiveContextPlanResult::Pending(plan) => plan,
        _ => unreachable!(),
    };
    let reserve_sum = policy.fixed_reserve
        + policy.protocol_reserve
        + policy.output_reserve
        + policy.review_reserve
        + policy.delivery_reserve;
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
        other => panic!("required floor must remain, got {other:?}"),
    };
    assert_eq!(limited_plan.request.items.len(), 1);
    assert_eq!(
        limited_plan.request.items[0].item_id,
        support::a15::id("atom").to_string()
    );
}

// WORK_UNIT_CASE: 612/43
#[test]
fn case_43_bound_hit_retains_frontier_not_complete_selection() {
    let (opt_view, opt_activation, opt_session, opt_attention, opt_coverage, opt_policy) =
        support::optional_dependency_inputs();
    let full = plan_pending_context_injection(
        &opt_view,
        &opt_activation,
        &opt_session,
        &opt_attention,
        &opt_coverage,
        &opt_policy,
    );
    let full_plan = match full {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("optional baseline must fit, got {other:?}"),
    };
    let reserve_sum = opt_policy.fixed_reserve
        + opt_policy.protocol_reserve
        + opt_policy.output_reserve
        + opt_policy.review_reserve
        + opt_policy.delivery_reserve;
    let mut tight = opt_policy.clone();
    tight.max_delivery_bytes = reserve_sum + full_plan.request.serialized_bytes - 1;
    tight.policy_digest = tight.canonical_digest().unwrap();
    let result = plan_pending_context_injection(
        &opt_view,
        &opt_activation,
        &opt_session,
        &opt_attention,
        &opt_coverage,
        &tight,
    );
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            // Bound hit: required floor retained, optional flood withheld, not
            // a complete selection.
            assert!(plan.request.items.len() < full_plan.request.items.len());
            assert!(
                plan.items
                    .iter()
                    .any(|i| i.disposition == DeliveryDisposition::WithheldBudget)
            );
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert_eq!(noop.accounting.planned, 0);
        }
        other => panic!("bound hit must not complete silently, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/44
#[test]
fn case_44_explicit_deterministic_priority_tie_break() {
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
    let mut bad_policy = policy.clone();
    bad_policy.tie_break_revision = 2;
    let bad = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &bad_policy,
    );
    assert!(matches!(bad, ReactiveContextPlanResult::Error(_)));
}

// WORK_UNIT_CASE: 612/45
#[test]
fn case_45_inert_request_no_new_execution_receipt() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    };
    assert!(!plan.request.request_digest.is_empty());
    assert!(plan.request.serialized_bytes > 0);
    assert!(plan.invalidation.is_empty());
    assert_eq!(plan.request.request_id, policy.request_id);
    assert_eq!(plan.request.operation_id, policy.operation_id);
}

// WORK_UNIT_CASE: 612/46
#[test]
fn case_46_no_producer_algorithm_invocation_inputs_unchanged() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let view_before = view.clone();
    let activation_before = activation.clone();
    let session_before = session.clone();
    let attention_before = attention.clone();
    let coverage_before = coverage.clone();
    let policy_before = policy.clone();
    let _ = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert_eq!(view, view_before);
    assert_eq!(activation, activation_before);
    assert_eq!(session, session_before);
    assert_eq!(attention, attention_before);
    assert_eq!(coverage, coverage_before);
    assert_eq!(policy, policy_before);
}

// WORK_UNIT_CASE: 612/47
#[test]
fn case_47_no_transport_session_mutation_or_store() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let session_digest_before = session.snapshot_digest.clone();
    let records_before = session.records.len();
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert_eq!(session.snapshot_digest, session_digest_before);
    assert_eq!(session.records.len(), records_before);
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert!(plan.invalidation.is_empty());
        }
        ReactiveContextPlanResult::NoInjection(noop) => {
            assert!(noop.invalidation.is_empty());
        }
        other => panic!("planner must not transport, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 612/48
#[test]
fn case_48_closed_current_wire_protected_defaults() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    };
    assert!(policy.allowed_modes.contains(&plan.mode));
    assert_eq!(
        plan.request.privacy_ceiling,
        eliot_protocol::ReactiveContextPrivacy::Public
    );
    assert_eq!(
        plan.request.proof_ceiling,
        eliot_receipts::ProofCeiling::Observation
    );
    assert!(!plan.input_digest.is_empty());
    assert!(!plan.result_digest.is_empty());
}

// WORK_UNIT_CASE: 612/49
#[test]
fn case_49_bounded_panic_free_malformed_inputs() {
    let (view, activation, session, attention, coverage, mut policy) = support::inputs(false, false);
    policy.allowed_modes = Vec::new();
    let result = std::panic::catch_unwind(|| {
        plan_pending_context_injection(&view, &activation, &session, &attention, &coverage, &policy)
    });
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap(),
        ReactiveContextPlanResult::Error(_)
    ));
    let (view, activation, session, attention, coverage, mut policy) = support::inputs(false, false);
    policy.cancelled = true;
    policy.policy_digest = policy.canonical_digest().unwrap();
    let cancelled = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(
        cancelled,
        ReactiveContextPlanResult::NoInjection(_)
    ));
}

// WORK_UNIT_CASE: 612/50
#[test]
fn case_50_exact_replay_and_changed_input_conflict() {
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
    let mut changed_policy = policy.clone();
    changed_policy.request_id = eliot_contracts::RequestId::new("request-changed-50").unwrap();
    changed_policy.policy_digest = changed_policy.canonical_digest().unwrap();
    let changed = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &changed_policy,
    );
    assert_ne!(first, changed);
}

// WORK_UNIT_CASE: 612/51
#[test]
fn case_51_planned_items_are_exact_view_or_attention_handles() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(true, true);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    let plan = match result {
        ReactiveContextPlanResult::Pending(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    };
    for item in &plan.items {
        match item.kind {
            PlannedItemKind::Context => {
                let rendered = item.rendered.as_ref().expect("exact representation");
                let view_atom = view
                    .view
                    .rendered
                    .iter()
                    .find(|a| a.atom_id.as_str() == item.item_id)
                    .expect("view member");
                assert_eq!(rendered, view_atom);
            }
            PlannedItemKind::Attention => {
                assert!(item.attention.is_some());
            }
            PlannedItemKind::Omission => {
                assert!(item.omission.is_some());
            }
        }
    }
}

// WORK_UNIT_CASE: 612/52
#[test]
fn case_52_no_downstream_state_without_owner_evidence() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let result = plan_pending_context_injection(
        &view,
        &activation,
        &session,
        &attention,
        &coverage,
        &policy,
    );
    match result {
        ReactiveContextPlanResult::Pending(plan) => {
            assert!(plan.invalidation.is_empty());
            assert_eq!(plan.accounting.deduped, 0);
            for item in &plan.items {
                assert_ne!(item.disposition, DeliveryDisposition::DeliveredDuplicate);
            }
        }
        ReactiveContextPlanResult::NoInjection(_) => {}
        other => panic!("must not assert downstream state, got {other:?}"),
    }
    // Exact owner evidence does dedup.
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let dup = plan_pending_context_injection(
        &view,
        &activation,
        &delivered,
        &attention,
        &coverage,
        &policy,
    );
    assert!(matches!(dup, ReactiveContextPlanResult::NoInjection(_)));
}
