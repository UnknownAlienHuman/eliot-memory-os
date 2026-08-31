use std::collections::BTreeSet;

use eliot_agent_api::{
    AgentLaunchRequest, AgentWorkUnitBrief, BudgetEnvelope, ContractError, EffectCeiling,
    EffectKind, LaunchRequestId, TaskId, WorkUnitId,
};

fn budget() -> BudgetEnvelope {
    BudgetEnvelope {
        context_tokens: 16_000,
        wall_time_ms: 120_000,
        output_bytes: 1_000_000,
        cost_microunits: 10_000,
        max_depth: 3,
        max_descendants: 8,
    }
}

fn ceiling(
    scope_ref: &str,
    allowed: impl IntoIterator<Item = EffectKind>,
    max_external_effects: u32,
) -> EffectCeiling {
    EffectCeiling {
        scope_ref: scope_ref.to_owned(),
        allowed: allowed.into_iter().collect::<BTreeSet<_>>(),
        max_external_effects,
    }
}

fn work_unit(effect_ceiling: EffectCeiling) -> AgentWorkUnitBrief {
    AgentWorkUnitBrief {
        id: WorkUnitId::new("work-unit-1").expect("valid work-unit identity"),
        objective: "produce one bounded candidate".to_owned(),
        causal_property: "effect ceiling remains narrowed".to_owned(),
        scope_ref: "scope:a".to_owned(),
        expected_outputs: vec!["candidate".to_owned()],
        source_refs: vec!["source:contract".to_owned()],
        verifier_ref: "verifier:effect-ceiling".to_owned(),
        integration_owner: "owner:agent-coordinator".to_owned(),
        contract_revision: "eliot-agent-api/v2".to_owned(),
        budget: budget(),
        effect_ceiling,
        stop_condition: "negative and positive fixtures pass".to_owned(),
    }
}

fn launch(root: EffectCeiling, child: EffectCeiling) -> AgentLaunchRequest {
    AgentLaunchRequest {
        id: LaunchRequestId::new("launch-1").expect("valid launch identity"),
        task_id: TaskId::new("task-1").expect("valid task identity"),
        parent_attempt: None,
        work_units: vec![work_unit(child)],
        required_competence: vec!["agent.contracts.effect-candidate".to_owned()],
        allowed_route_classes: vec!["service-safe".to_owned()],
        native_child_policy: "disabled".to_owned(),
        root_context_revision: "context-1".to_owned(),
        context_budget: budget(),
        evidence_capability_refs: vec!["evidence:contract".to_owned()],
        privacy_profile: "local-only".to_owned(),
        effect_ceiling: root,
        max_depth: 3,
        max_fanout: 2,
        cumulative_descendant_budget: budget(),
        verifier_ref: "verifier:effect-ceiling".to_owned(),
        synthesis_owner: "owner:synthesis".to_owned(),
        integration_owner: "owner:agent-coordinator".to_owned(),
        cancellation_policy: "bounded".to_owned(),
    }
}

#[test]
fn equal_effect_ceiling_is_accepted() {
    let root = ceiling(
        "scope:a",
        [EffectKind::Observe, EffectKind::ReadWorkspace],
        0,
    );
    assert!(launch(root.clone(), root).validate().is_ok());
}

#[test]
fn strict_subset_and_lower_external_count_are_accepted() {
    let root = ceiling(
        "scope:a",
        [
            EffectKind::Observe,
            EffectKind::ReadWorkspace,
            EffectKind::WriteCandidate,
            EffectKind::ExternalEffect,
        ],
        3,
    );
    let child = ceiling(
        "scope:a",
        [EffectKind::Observe, EffectKind::ReadWorkspace],
        1,
    );
    assert!(launch(root, child).validate().is_ok());
}

#[test]
fn child_allowed_effect_set_cannot_widen_parent() {
    let root = ceiling("scope:a", [EffectKind::Observe], 0);
    let child = ceiling(
        "scope:a",
        [EffectKind::Observe, EffectKind::WriteCandidate],
        0,
    );
    assert_eq!(
        launch(root, child).validate(),
        Err(ContractError::ChildEffectCeilingExceeded { field: "allowed" })
    );
}

#[test]
fn child_external_effect_count_cannot_widen_parent() {
    let root = ceiling("scope:a", [EffectKind::Observe], 0);
    let child = ceiling("scope:a", [EffectKind::Observe], 1);
    assert_eq!(
        launch(root, child).validate(),
        Err(ContractError::ChildEffectCeilingExceeded {
            field: "max_external_effects"
        })
    );
}

#[test]
fn child_scope_cannot_differ_from_parent_scope() {
    let root = ceiling("scope:a", [EffectKind::Observe], 0);
    let child = ceiling("scope:b", [EffectKind::Observe], 0);
    assert_eq!(
        launch(root, child).validate(),
        Err(ContractError::ChildEffectCeilingExceeded { field: "scope_ref" })
    );
}

#[test]
fn work_unit_scope_and_its_effect_ceiling_must_match() {
    let unit = work_unit(ceiling("scope:b", [EffectKind::Observe], 0));
    assert_eq!(
        unit.validate(),
        Err(ContractError::ChildEffectCeilingExceeded { field: "scope_ref" })
    );
}

#[test]
fn effect_ceiling_wire_shape_round_trips_without_defaults() {
    let original = ceiling(
        "scope:a",
        [EffectKind::Observe, EffectKind::ReadWorkspace],
        0,
    );
    let encoded = serde_json::to_vec(&original).expect("serialize effect ceiling");
    let decoded = serde_json::from_slice::<EffectCeiling>(&encoded).expect("deserialize effect ceiling");
    assert_eq!(decoded, original);
}
