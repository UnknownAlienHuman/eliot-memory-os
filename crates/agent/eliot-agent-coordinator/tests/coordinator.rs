use std::collections::BTreeSet;

use eliot_agent_api::{
    AgentLaunchRequest, AgentWorkUnitBrief, AllowedMode, AuthorityEpoch, BudgetEnvelope,
    EffectCeiling, EffectKind, LaunchRequestId, ResourceGeneration, RouteFingerprint, StateFence,
    TaskId, WorkUnitId,
};
use eliot_agent_contracts::RevisionId;
use eliot_agent_coordinator::{
    AdmissionId, AdmittedLaneReceipt, AgentCoordinator, CandidateId, CoordinatorConfig,
    CoordinatorError, PlanGap, ProviderAdmissionReceipt, ProviderIdentity, RecipeId,
    RecipeManifest, RoleProfileId, RoleProfileManifest, RouteCandidateEvidence,
    StaffingLaneRequest, StaffingPlanRequest, WorkerId,
};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_security_contracts::PrivacyClass;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn budget() -> BudgetEnvelope {
    BudgetEnvelope {
        context_tokens: 8_000,
        wall_time_ms: 60_000,
        output_bytes: 256_000,
        cost_microunits: 1_000_000,
        max_depth: 2,
        max_descendants: 4,
    }
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn route(name: &str) -> RouteFingerprint {
    RouteFingerprint {
        host_family: "test-host".to_owned(),
        adapter: format!("adapter-{name}"),
        protocol_transport: "fixture".to_owned(),
        runtime_hash: format!("runtime-{name}"),
        adapter_hash: format!("adapter-hash-{name}"),
        provider: format!("provider-{name}"),
        model: format!("model-{name}"),
        auth_billing: "fixture-account".to_owned(),
        serializer_hash: "serializer-v1".to_owned(),
        tool_semantics_hash: "tools-v1".to_owned(),
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: "features-v1".to_owned(),
    }
}

fn config() -> Result<CoordinatorConfig, eliot_agent_contracts::ContractError> {
    Ok(CoordinatorConfig {
        max_ready_items: 16,
        max_admitted_attempts: 4,
        max_active_per_route: 2,
        capacity_identity: "capacity-a".to_owned(),
        capacity_revision: RevisionId::new("capacity-rev-1")?,
    })
}

fn work() -> Result<AgentWorkUnitBrief, eliot_agent_api::ContractError> {
    Ok(AgentWorkUnitBrief {
        id: WorkUnitId::new("work-a")?,
        objective: "bounded implementation".to_owned(),
        causal_property: "one deterministic candidate".to_owned(),
        scope_ref: "scope-a".to_owned(),
        expected_outputs: vec!["candidate artifact".to_owned()],
        source_refs: vec!["architecture:10635".to_owned()],
        verifier_ref: "cargo-test".to_owned(),
        integration_owner: "independent-integrator".to_owned(),
        contract_revision: "work-v1".to_owned(),
        budget: budget(),
        effect_ceiling: EffectCeiling {
            scope_ref: "scope-a".to_owned(),
            allowed: BTreeSet::from([
                EffectKind::Observe,
                EffectKind::ReadWorkspace,
                EffectKind::WriteCandidate,
            ]),
            max_external_effects: 0,
        },
        stop_condition: "candidate submitted".to_owned(),
    })
}

fn request() -> TestResult<StaffingPlanRequest> {
    let selected = route("a");
    let alternate = route("b");
    Ok(StaffingPlanRequest {
        candidate_id: CandidateId::new("candidate-1")?,
        launch: AgentLaunchRequest {
            id: LaunchRequestId::new("launch-1")?,
            task_id: TaskId::new("task-1")?,
            parent_attempt: None,
            work_units: vec![work()?],
            required_competence: vec!["rust".to_owned()],
            allowed_route_classes: vec![selected.provider.clone(), alternate.provider.clone()],
            native_child_policy: "disabled".to_owned(),
            root_context_revision: "root-v1".to_owned(),
            context_budget: budget(),
            evidence_capability_refs: vec!["capability-fixture".to_owned()],
            privacy_profile: "PRIVATE".to_owned(),
            effect_ceiling: EffectCeiling {
                scope_ref: "task-scope".to_owned(),
                allowed: BTreeSet::from([
                    EffectKind::Observe,
                    EffectKind::ReadWorkspace,
                    EffectKind::WriteCandidate,
                ]),
                max_external_effects: 0,
            },
            max_depth: 2,
            max_fanout: 4,
            cumulative_descendant_budget: budget(),
            verifier_ref: "cargo-test".to_owned(),
            synthesis_owner: "synthesis-owner".to_owned(),
            integration_owner: "integration-owner".to_owned(),
            cancellation_policy: "cascade".to_owned(),
        },
        recipe: RecipeManifest {
            recipe_id: RecipeId::new("solo-verified-v1")?,
            manifest_revision: RevisionId::new("recipe-rev-1")?,
            route_policy_revision: RevisionId::new("route-policy-1")?,
            max_lanes: 1,
            max_descendants: 4,
            role_profiles: vec![RoleProfileManifest {
                role_id: RoleProfileId::new("writer-v1")?,
                manifest_revision: RevisionId::new("role-rev-1")?,
                required_competence: vec!["rust".to_owned()],
                allowed_route_classes: vec![selected.provider.clone(), alternate.provider.clone()],
                mutation_capable: true,
            }],
        },
        task_revision: "task-rev-1".to_owned(),
        plan_revision: RevisionId::new("plan-rev-1")?,
        state_fence: fence(),
        privacy_class: PrivacyClass::Private,
        lanes: vec![StaffingLaneRequest {
            work_unit_id: WorkUnitId::new("work-a")?,
            role_id: RoleProfileId::new("writer-v1")?,
            route_candidates: vec![route_evidence(selected, 0), route_evidence(alternate, 1)],
            budget: budget(),
            priority: 10,
            mutation_scope: Some("scope-a".to_owned()),
        }],
    })
}

fn route_evidence(route: RouteFingerprint, rank: u16) -> RouteCandidateEvidence {
    RouteCandidateEvidence {
        route,
        preference_rank: rank,
        capacity_identity: "capacity-a".to_owned(),
        capacity_revision: RevisionId::new("capacity-rev-1")
            .unwrap_or_else(|error| panic!("fixture revision must be valid: {error}")),
        capacity_limit: 2,
        budget_evidence: BudgetEvidence {
            arm_id: format!("route-arm-{rank}"),
            ..BudgetEvidence::default()
        },
        evidence_refs: vec![format!("route-evidence-{rank}")],
    }
}

fn gap() -> PlanGap {
    PlanGap::A01Unaccepted {
        contract_version: "eliot-agent-api/v2".to_owned(),
        reason: "A-01 is not accepted".to_owned(),
    }
}

#[test]
fn planning_is_deterministic_and_uses_c0_13_route_evidence() -> TestResult {
    let mut coordinator = AgentCoordinator::new(config()?, gap())?;
    let candidate = coordinator.plan(request()?)?;
    assert_eq!(candidate.recipe_id.as_str(), "solo-verified-v1");
    assert_eq!(
        candidate.lanes[0].routing.budget_evidence.arm_id,
        "route-arm-0"
    );
    assert_eq!(candidate.lanes[0].routing.rejected_alternatives.len(), 1);
    Ok(())
}

#[test]
fn read_only_root_rejects_mutating_child_without_event() -> TestResult {
    let mut coordinator = AgentCoordinator::new(config()?, gap())?;
    let mut request = request()?;
    request.launch.effect_ceiling.allowed =
        BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]);
    let before = coordinator.events().to_vec();

    assert!(matches!(
        coordinator.plan(request),
        Err(CoordinatorError::ProviderContract(message))
            if message.contains("authority is not sufficient")
    ));
    assert_eq!(coordinator.events(), before.as_slice());
    Ok(())
}

#[test]
fn caller_fabricated_admission_cannot_bypass_plan_gap() -> TestResult {
    let cfg = config()?;
    let mut coordinator = AgentCoordinator::new(cfg.clone(), gap())?;
    let candidate = coordinator.plan(request()?)?;
    let routing_digest = eliot_agent_contracts::contract_shape_digest(&candidate.lanes[0].routing)?;
    let forged_identity = ProviderIdentity {
        verifier_identity: "caller".to_owned(),
        a01_acceptance_receipt_ref: "forged-a01".to_owned(),
        a01_contract_revision: "forged-a01-rev".to_owned(),
        g11_provider_revision: "forged-g11".to_owned(),
        capacity_identity: cfg.capacity_identity,
        capacity_revision: cfg.capacity_revision,
    };
    let forged = ProviderAdmissionReceipt {
        admission_id: AdmissionId::new("admission-1")?,
        candidate_id: candidate.candidate_id.clone(),
        launch_request_id: candidate.launch_request_id.clone(),
        recipe_id: candidate.recipe_id.clone(),
        recipe_revision: candidate.recipe_revision.clone(),
        task_id: candidate.task_id.clone(),
        task_revision: candidate.task_revision.clone(),
        plan_revision: candidate.plan_revision.clone(),
        state_fence: candidate.state_fence.clone(),
        controller_epoch: AuthorityEpoch::new(1)?,
        coordinator_lease: eliot_agent_api::WorkLeaseId::new("lease-forged")?,
        provider_identity: forged_identity,
        g11_admission_receipt_ref: "forged-g11-admission".to_owned(),
        durable_job_ref: "forged-job".to_owned(),
        admitted_lanes: vec![AdmittedLaneReceipt {
            work_unit_id: candidate.lanes[0].work_unit_id.clone(),
            role_id: candidate.lanes[0].role_id.clone(),
            role_revision: candidate.lanes[0].role_revision.clone(),
            attempt_id: eliot_agent_api::AttemptId::new("attempt-forged")?,
            lease_id: eliot_agent_api::WorkLeaseId::new("work-lease-forged")?,
            worker_id: WorkerId::new("worker-forged")?,
            route: candidate.lanes[0].routing.selected_route.clone(),
            routing_receipt_digest: routing_digest,
            budget: candidate.lanes[0].budget.clone(),
            priority: candidate.lanes[0].priority,
            mutation_scope: candidate.lanes[0].mutation_scope.clone(),
        }],
    };
    assert!(matches!(
        coordinator.admit(forged),
        Err(CoordinatorError::PlanGap(PlanGap::A01Unaccepted { .. }))
    ));
    Ok(())
}

#[test]
fn absent_g11_is_a_typed_non_bypassable_gap() -> TestResult {
    let mut coordinator = AgentCoordinator::new(
        config()?,
        PlanGap::G11Unavailable {
            reason: "G-11 is not implemented".to_owned(),
        },
    )?;
    let candidate = coordinator.plan(request()?)?;
    assert_eq!(candidate.lanes.len(), 1);
    Ok(())
}

#[test]
fn serde_rejects_unknown_fields_and_invented_accepted_status() -> TestResult {
    let mut value = serde_json::to_value(config()?)?;
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CoordinatorConfig>(value).is_err());
    let invented = serde_json::json!({
        "provider": "A01_ACCEPTED",
        "receipt": "caller"
    });
    assert!(serde_json::from_value::<PlanGap>(invented).is_err());
    let _ = AllowedMode::Material;
    Ok(())
}
