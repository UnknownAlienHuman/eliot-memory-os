//! Independent-audit lane coverage proof for issue #1963 (acceptance A1).
//!
//! Under the assurance preset a task requiring independent review receives a
//! writer plus an independently eligible audit route when the frozen request can
//! actually run both. The audit role is a real second lane here, so the auditor
//! the receipt staffs is a lane the coordinator compiles and the fabric's
//! per-attempt authorization can dispatch — not a trailing receipt entry that
//! reads as satisfied review while nothing reviews anything.
//!
//! Two directions are proven. When the request binds the audit class only to the
//! writer's own lane, no lane could ever run a reviewer, so the receipt escalates
//! that class by name and staffs no phantom auditor. And enforcement binds lanes
//! by route identity in both directions: a receipted route no compiled lane runs
//! is refused, and the compiled lanes' order never decides which receipted lane a
//! plan must match.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_agent_api::{
    AgentLaunchRequest, AgentWorkUnitBrief, BudgetEnvelope, EffectCeiling, EffectKind,
    LaunchRequestId, LowercaseSha256, RouteFingerprint, TaskId, WorkUnitId,
};
use eliot_agent_contracts::RevisionId;
use eliot_agent_coordinator::{
    CandidateId, CoordinatorConfig, LearningRole, RecipeId, RecipeManifest, RoleProfileId,
    RoleProfileManifest, RouteCandidateEvidence, StaffingLaneRequest, StaffingPlanCandidate,
    StaffingPlanRequest,
};
use eliot_contracts::{
    EpochId, EpochLineageId, PolicyRevision, ResourceGeneration, StateFence, sha256_hex,
};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_security_contracts::PrivacyClass;
use eliotd::staffing_policy::{
    UNAUDITABLE_REVIEW_REASON, UnavailableDispositionKind, enforce_plan_receipt,
    plan_coordinator_staffing, verify_receipt_digest,
};
use eliotd::{
    FABRIC_CAPACITY_IDENTITY, FABRIC_CAPACITY_REVISION, daemon_coordinator_config, plan_candidate,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const WRITER_CLASS: &str = "bulk_implementation";
const AUDIT_CLASS: &str = "independent_blind_audit";
const WRITER_FAMILY: &str = "writer-family";
const AUDIT_FAMILY: &str = "audit-family";

fn test_fence() -> TestResult<StateFence> {
    let lineage = EpochLineageId::new(TEST_LINEAGE).map_err(|error| format!("lineage: {error}"))?;
    let sequence = NonZeroU64::new(1).ok_or("non-zero test sequence")?;
    let epoch = EpochId::new(lineage, sequence).map_err(|error| format!("epoch: {error}"))?;
    // Route selection binds to the policy revision captured by the request's
    // State Fence; an absent revision cannot be inspected as a real policy.
    Ok(StateFence {
        policy_revision: Some(PolicyRevision::genesis()),
        ..StateFence::new(epoch, ResourceGeneration::genesis())
    })
}

fn test_digest(seed: &str) -> TestResult<LowercaseSha256> {
    serde_json::from_value(serde_json::json!(sha256_hex(seed.as_bytes()))).map_err(Into::into)
}

fn fixture_reference(
    label: &str,
) -> Result<eliot_agent_contracts::PublicReference, eliot_agent_contracts::ContractError> {
    Ok(eliot_agent_contracts::PublicReference {
        kind: "fixture".to_owned(),
        id: eliot_agent_contracts::TargetId::new(format!("fixture-{label}"))?,
        revision: RevisionId::new("fixture-v1")?,
        digest: None,
    })
}

fn fixture_schema_identity(
    label: &str,
) -> Result<eliot_contracts::ContractIdentity, eliot_contracts::ContractError> {
    eliot_contracts::contract_identity(
        format!("fixture-{label}"),
        eliot_contracts::ContractVersion::new(1, 0, 0),
        &serde_json::json!({ "fixture_schema": label }),
    )
}

fn test_budget() -> BudgetEnvelope {
    BudgetEnvelope {
        context_tokens: 8_000,
        wall_time_ms: 60_000,
        output_bytes: 256_000,
        cost_microunits: 1_000_000,
        max_depth: 3,
        max_descendants: 8,
    }
}

/// Two routes in different host families, so cross-family independence is real
/// rather than asserted. The audit route carries no model cost, so it is not a
/// paid fallback either.
fn writer_route() -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: "writer-family".to_owned(),
        adapter: "adapter-writer".to_owned(),
        protocol_transport: "fabric-fixture".to_owned(),
        runtime_hash: test_digest("writer-runtime")?,
        adapter_hash: test_digest("writer-adapter")?,
        provider: "provider-writer".to_owned(),
        model: "model-writer".to_owned(),
        auth_billing: "writer-account".to_owned(),
        serializer_hash: test_digest("writer-serializer")?,
        tool_semantics_hash: test_digest("writer-tools")?,
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: test_digest("writer-features")?,
    })
}

fn audit_route() -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: "audit-family".to_owned(),
        adapter: "adapter-audit".to_owned(),
        protocol_transport: "fabric-fixture".to_owned(),
        runtime_hash: test_digest("audit-runtime")?,
        adapter_hash: test_digest("audit-adapter")?,
        provider: "provider-audit".to_owned(),
        model: "model-audit".to_owned(),
        auth_billing: "audit-account".to_owned(),
        serializer_hash: test_digest("audit-serializer")?,
        tool_semantics_hash: test_digest("audit-tools")?,
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: test_digest("audit-features")?,
    })
}

fn route_evidence(
    route: &RouteFingerprint,
    classes: &[&str],
    model_cost_micros: u64,
) -> TestResult<RouteCandidateEvidence> {
    Ok(RouteCandidateEvidence {
        route: route.clone(),
        preference_rank: 0,
        capacity_identity: FABRIC_CAPACITY_IDENTITY.to_owned(),
        capacity_revision: RevisionId::new(FABRIC_CAPACITY_REVISION)
            .map_err(|error| format!("capacity rev: {error}"))?,
        capacity_limit: 4,
        budget_evidence: BudgetEvidence {
            arm_id: format!("route-arm-{}", route.host_family),
            model_calls: 1,
            wall_time_ms: 100,
            model_cost_micros,
            ..BudgetEvidence::default()
        },
        route_classes: classes.iter().map(|class| (*class).to_owned()).collect(),
        route_class_evidence_refs: classes
            .iter()
            .map(|class| format!("route-class-evidence-{class}"))
            .collect(),
        privacy_classes: vec![PrivacyClass::Private],
        privacy_evidence_refs: vec!["privacy-evidence-0".to_owned()],
        evidence_refs: vec![format!("route-evidence-{}", route.host_family)],
    })
}

fn work_unit(label: &str) -> TestResult<AgentWorkUnitBrief> {
    Ok(AgentWorkUnitBrief {
        id: WorkUnitId::new(format!("work-{label}"))
            .map_err(|error| format!("work id: {error}"))?,
        objective: format!("bounded responsibility work-{label}"),
        causal_property: format!("causal property work-{label}"),
        scope_ref: format!("scope-work-{label}"),
        expected_outputs: vec!["candidate artifact".to_owned()],
        source_refs: vec!["architecture:10635".to_owned()],
        verifier_ref: "cargo-test".to_owned(),
        integration_owner: "independent-integrator".to_owned(),
        contract_revision: "work-v1".to_owned(),
        budget: test_budget(),
        effect_ceiling: EffectCeiling {
            scope_ref: format!("scope-work-{label}"),
            allowed: BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]),
            max_external_effects: 0,
        },
        stop_condition: "candidate submitted".to_owned(),
    })
}

fn role_profile(
    label: &str,
    classes: &[&str],
    effects: &EffectCeiling,
) -> TestResult<RoleProfileManifest> {
    Ok(RoleProfileManifest {
        role_id: RoleProfileId::new(format!("role-{label}"))
            .map_err(|error| format!("role: {error}"))?,
        manifest_revision: RevisionId::new(format!("role-rev-{label}"))
            .map_err(|error| format!("role rev: {error}"))?,
        schema_identity: fixture_schema_identity(label)?,
        content_digest: test_digest(&format!("role-manifest-{label}"))?,
        required_competence: vec!["rust".to_owned()],
        allowed_operations: vec![fixture_reference("role-operation")?],
        allowed_effects: effects.clone(),
        independence_requirement: fixture_reference("independence-requirement")?,
        input_schemas: vec![fixture_reference("role-input-schema")?],
        output_schemas: vec![fixture_reference("role-output-schema")?],
        visibility_policy: fixture_reference("visibility-policy")?,
        learning_role: LearningRole::NotApplicable,
        stop_condition: fixture_reference("candidate-submitted")?,
        escalation_policy: fixture_reference("integration-owner")?,
        allowed_route_classes: classes.iter().map(|class| (*class).to_owned()).collect(),
        mutation_capable: false,
    })
}

fn lane_request(
    work_label: &str,
    role_label: &str,
    candidates: Vec<RouteCandidateEvidence>,
) -> TestResult<StaffingLaneRequest> {
    Ok(StaffingLaneRequest {
        work_unit_id: WorkUnitId::new(format!("work-{work_label}"))
            .map_err(|error| format!("lane work: {error}"))?,
        role_id: RoleProfileId::new(format!("role-{role_label}"))
            .map_err(|error| format!("lane role: {error}"))?,
        work_class: "swarm".parse().map_err(|error| format!("class: {error}"))?,
        route_candidates: candidates,
        budget: test_budget(),
        priority: 0,
        mutation_scope: None,
    })
}

/// A frozen two-lane assurance request: a writer lane and an audit lane of its
/// own, each binding exactly one I3.6 class.
fn two_lane_request(fence: &StateFence) -> TestResult<StaffingPlanRequest> {
    let writer = work_unit("writer")?;
    let audit = work_unit("audit")?;
    // Two vocabularies meet here, and the fixture keeps them apart on purpose.
    // The I3.6 capability classes are what the staffing policy binds a route
    // into, and they only ever come from the route owner's own declaration
    // (`candidate.route_classes`). The coordinator's own route-class filter
    // matches a declared class against the route's provider, host family or
    // adapter, so the host families are declared too. Because the host families
    // are absent from `candidate.route_classes`, they prove no capability class
    // and never reach the staffing policy.
    let recipe_classes = [WRITER_CLASS, AUDIT_CLASS, WRITER_FAMILY, AUDIT_FAMILY];
    let writer_classes = [WRITER_CLASS, WRITER_FAMILY];
    let audit_classes = [AUDIT_CLASS, AUDIT_FAMILY];
    let recipe = RecipeManifest {
        recipe_id: RecipeId::new("recipe-1963").map_err(|error| format!("recipe: {error}"))?,
        manifest_revision: RevisionId::new("recipe-rev-1963")
            .map_err(|error| format!("recipe rev: {error}"))?,
        schema_identity: fixture_schema_identity("recipe-1963")?,
        content_digest: test_digest("recipe-manifest-1963")?,
        route_policy_revision: RevisionId::new("route-policy-1")
            .map_err(|error| format!("route policy: {error}"))?,
        max_lanes: 2,
        max_descendants: 8,
        stage_templates: vec![fixture_reference("stage-template")?],
        work_item_templates: vec![fixture_reference("work-item-template")?],
        dependency_templates: vec![fixture_reference("dependency-template")?],
        merge_templates: vec![fixture_reference("merge-template")?],
        eligible_route_classes: recipe_classes
            .iter()
            .map(|class| (*class).to_owned())
            .collect(),
        expansion_conditions: vec![fixture_reference("expansion-condition")?],
        contraction_conditions: vec![fixture_reference("contraction-condition")?],
        verifier_requirements: vec![fixture_reference("verifier-requirement")?],
        // A non-empty audit requirement is what makes the recipe request
        // independent review at all.
        audit_requirements: vec![fixture_reference("audit-requirement")?],
        budget: test_budget(),
        partial_result_behavior: fixture_reference("partial-result-behavior")?,
        failure_behavior: fixture_reference("failure-behavior")?,
        role_profiles: vec![
            role_profile("writer", &writer_classes, &writer.effect_ceiling)?,
            role_profile("auditor", &audit_classes, &audit.effect_ceiling)?,
        ],
    };
    let work_units = vec![writer, audit];
    Ok(StaffingPlanRequest {
        candidate_id: CandidateId::new("candidate-1963-two-lane")
            .map_err(|error| format!("candidate: {error}"))?,
        launch: AgentLaunchRequest {
            id: LaunchRequestId::new("launch-1963").map_err(|error| format!("launch: {error}"))?,
            task_id: TaskId::new("task-1963").map_err(|error| format!("task: {error}"))?,
            parent_attempt: None,
            work_units,
            required_competence: vec!["rust".to_owned()],
            allowed_route_classes: recipe_classes
                .iter()
                .map(|class| (*class).to_owned())
                .collect(),
            native_child_policy: "bounded".to_owned(),
            root_context_revision: "root-v1".to_owned(),
            context_budget: test_budget(),
            evidence_capability_refs: vec!["capability-fixture".to_owned()],
            privacy_profile: "PRIVATE".to_owned(),
            effect_ceiling: EffectCeiling {
                scope_ref: "task-scope".to_owned(),
                allowed: BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]),
                max_external_effects: 0,
            },
            max_depth: 3,
            max_fanout: 2,
            cumulative_descendant_budget: test_budget(),
            verifier_ref: "cargo-test".to_owned(),
            synthesis_owner: "synthesis-owner".to_owned(),
            integration_owner: "integration-owner".to_owned(),
            cancellation_policy: "cascade".to_owned(),
        },
        recipe,
        task_revision: "task-rev-1".to_owned(),
        plan_revision: RevisionId::new("plan-rev-1963")
            .map_err(|error| format!("plan rev: {error}"))?,
        state_fence: fence.clone(),
        human_staffing_intent: eliot_agent_coordinator::HumanStaffingIntent {
            preset: eliot_agent_coordinator::StaffingPreset::Assurance,
            per_job_budget: test_budget(),
        },
        privacy_class: PrivacyClass::Private,
        work_class: "swarm".parse().map_err(|error| format!("class: {error}"))?,
        lanes: vec![
            lane_request(
                "writer",
                "writer",
                vec![route_evidence(&writer_route()?, &[WRITER_CLASS], 0)?],
            )?,
            lane_request(
                "audit",
                "auditor",
                vec![route_evidence(&audit_route()?, &[AUDIT_CLASS], 0)?],
            )?,
        ],
    })
}

/// A frozen one-lane assurance request whose single role binds both classes. No
/// lane other than the writer's own could run a reviewer here.
fn one_lane_request(fence: &StateFence) -> TestResult<StaffingPlanRequest> {
    let mut request = two_lane_request(fence)?;
    request.candidate_id = CandidateId::new("candidate-1963-one-lane")
        .map_err(|error| format!("candidate: {error}"))?;
    request.recipe.max_lanes = 1;
    request.launch.max_fanout = 1;
    request.launch.work_units.truncate(1);
    request.recipe.role_profiles.truncate(1);
    // The one surviving role binds both I3.6 classes, and its lane carries both
    // routes, so this single lane is exactly the shape that used to staff a
    // trailing auditor nobody could dispatch.
    request.recipe.role_profiles[0].allowed_route_classes =
        [WRITER_CLASS, WRITER_FAMILY, AUDIT_CLASS, AUDIT_FAMILY]
            .iter()
            .map(|class| (*class).to_owned())
            .collect();
    request.lanes.truncate(1);
    request.lanes[0].route_candidates = vec![
        route_evidence(&writer_route()?, &[WRITER_CLASS], 0)?,
        route_evidence(&audit_route()?, &[AUDIT_CLASS], 0)?,
    ];
    // The coordinator ranks a lane's own candidates by preference then route
    // key; the writer route is preferred here so the single compiled lane is
    // the writer the receipt staffs.
    request.lanes[0].route_candidates[1].preference_rank = 1;
    Ok(request)
}

fn config() -> TestResult<CoordinatorConfig> {
    Ok(daemon_coordinator_config()?)
}

/// The audit role is a lane of its own, so the receipted auditor is a lane the
/// coordinator compiles and the fabric can authorize attempt position 1 on.
#[test]
fn an_audit_lane_of_its_own_is_staffed_and_compiled() -> TestResult {
    let fence = test_fence()?;
    let request = two_lane_request(&fence)?;
    let receipt = plan_coordinator_staffing(&config()?, &request)?;
    verify_receipt_digest(&receipt)?;
    assert_eq!(
        receipt.preset,
        eliot_agent_coordinator::StaffingPreset::Assurance
    );
    assert_eq!(
        receipt.lanes.len(),
        2,
        "the assurance task staffs both roles"
    );
    assert_eq!(receipt.lanes[0].role, "writer");
    assert_eq!(receipt.lanes[0].route_class, WRITER_CLASS);
    assert_eq!(receipt.lanes[1].role, "auditor");
    assert_eq!(receipt.lanes[1].route_class, AUDIT_CLASS);
    assert_eq!(receipt.lanes[0].route.host_family, "writer-family");
    assert_eq!(
        receipt.lanes[1].route.host_family, "audit-family",
        "the audit lane runs a different host family than the writer"
    );
    assert!(
        receipt
            .unavailable
            .iter()
            .all(|item| item.route_class != AUDIT_CLASS),
        "a staffed audit class carries no unavailability disposition"
    );

    // The compiled candidate runs both receipted routes, and the real
    // production plan path accepts the pair.
    let candidate = plan_candidate(&config()?, request)?;
    assert_eq!(candidate.lanes.len(), 2);
    enforce_plan_receipt(&receipt, &candidate)?;
    Ok(())
}

/// Enforcement binds lanes by route identity in both directions, so lane order
/// never decides which receipted lane a plan must match, and a receipted route
/// no compiled lane runs is refused.
#[test]
fn receipt_enforcement_is_route_bound_in_both_directions() -> TestResult {
    let fence = test_fence()?;
    let request = two_lane_request(&fence)?;
    let receipt = plan_coordinator_staffing(&config()?, &request)?;
    let candidate = plan_candidate(&config()?, request)?;

    // Reordering the compiled lanes must not change the verdict: the coordinator
    // sorts lanes by priority, work unit, role and route key, so a positional
    // comparison would compare the writer against the auditor here.
    let reordered = StaffingPlanCandidate {
        lanes: candidate.lanes.iter().rev().cloned().collect(),
        ..candidate.clone()
    };
    enforce_plan_receipt(&receipt, &reordered)?;

    // Dropping the audit lane leaves a receipted route nothing runs: that is the
    // trailing-lane shape, and it is refused.
    let writer_only = StaffingPlanCandidate {
        lanes: vec![candidate.lanes[0].clone()],
        ..candidate.clone()
    };
    let dropped = enforce_plan_receipt(&receipt, &writer_only);
    let message = match dropped {
        Ok(()) => return Err("a receipted independent review lane must never be dropped".into()),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("never dropped"),
        "the refusal must name the dropped receipted lane, got: {message}"
    );

    // Claiming the same receipted route twice is refused as well.
    let twice = StaffingPlanCandidate {
        lanes: vec![candidate.lanes[0].clone(), candidate.lanes[0].clone()],
        ..candidate.clone()
    };
    assert!(
        enforce_plan_receipt(&receipt, &twice).is_err(),
        "one receipted route may back exactly one compiled lane"
    );
    Ok(())
}

/// The audit class the writer's own lane also binds has no lane that could run
/// it, so the receipt escalates that class by name and staffs no phantom auditor.
#[test]
fn an_unauditable_review_class_is_escalated_not_staffed() -> TestResult {
    let fence = test_fence()?;
    let request = one_lane_request(&fence)?;
    let receipt = plan_coordinator_staffing(&config()?, &request)?;
    verify_receipt_digest(&receipt)?;
    assert_eq!(
        receipt.lanes.len(),
        1,
        "no lane of this request can run an auditor, so none is staffed"
    );
    assert_eq!(receipt.lanes[0].role, "writer");
    assert!(
        receipt.lanes.iter().all(|lane| lane.role != "auditor"),
        "an auditor lane nothing would dispatch must never be receipted"
    );
    let audit = receipt
        .unavailable
        .iter()
        .find(|item| item.route_class == AUDIT_CLASS)
        .ok_or("the unavailable audit class carries no disposition")?;
    assert_eq!(audit.disposition, UnavailableDispositionKind::Escalate);
    assert_eq!(
        audit.reason, UNAUDITABLE_REVIEW_REASON,
        "the disposition must name the cause this bridge established"
    );
    // The one-lane plan stays enforceable, because the receipt now authorizes
    // exactly what the plan runs.
    let candidate = plan_candidate(&config()?, request)?;
    assert_eq!(candidate.lanes.len(), 1);
    enforce_plan_receipt(&receipt, &candidate)?;
    Ok(())
}

/// I3.6: a class is unavailable rather than substituted. A cross-family but paid
/// audit route still escalates, because it would escape the selected budget.
#[test]
fn a_paid_audit_route_does_not_satisfy_an_unstaffable_review_class() -> TestResult {
    let fence = test_fence()?;
    let mut request = one_lane_request(&fence)?;
    request.lanes[0].route_candidates[1]
        .budget_evidence
        .model_cost_micros = 5_000;
    let receipt = plan_coordinator_staffing(&config()?, &request)?;
    assert_eq!(receipt.lanes.len(), 1);
    let audit = receipt
        .unavailable
        .iter()
        .find(|item| item.route_class == AUDIT_CLASS)
        .ok_or("the unavailable audit class carries no disposition")?;
    assert_eq!(audit.disposition, UnavailableDispositionKind::Escalate);
    Ok(())
}

/// The work class is threaded unchanged, and the human preset is the assurance
/// intent itself rather than a shape-derived guess.
#[test]
fn the_receipt_records_the_human_selected_preset_and_ceiling() -> TestResult {
    let fence = test_fence()?;
    let request = two_lane_request(&fence)?;
    let receipt = plan_coordinator_staffing(&config()?, &request)?;
    assert_eq!(
        receipt.preset,
        eliot_agent_coordinator::StaffingPreset::Assurance
    );
    assert_eq!(receipt.privacy_ceiling, PrivacyClass::Private);
    assert_eq!(receipt.task_class, "swarm");
    assert!(receipt.route_policy_evidence.len() >= 2);
    Ok(())
}
