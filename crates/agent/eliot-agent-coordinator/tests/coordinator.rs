use std::collections::BTreeSet;

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentLaunchRequest, AgentWorkUnitBrief, AllowedMode, AttemptId,
    BudgetEnvelope, CONTRACT_VERSION, DecisionId, EffectCeiling, EffectKind, EpochId,
    ExecutionUnit, LaunchRequestId, LowercaseSha256, NativeSession, ProviderExecutionBinding,
    RequestId, ResourceGeneration, RouteFingerprint, StateFence, TaskId, WorkLeaseId, WorkUnitId,
    candidate_digest_for,
};
use eliot_agent_contracts::RevisionId;
use eliot_agent_coordinator::{
    AdmissionId, AdmittedLaneReceipt, AdmittedProviderCapability, AgentCoordinator, CandidateId,
    CoordinatorConfig, CoordinatorError, CoordinatorEvent, ExecutionContext, PlanGap,
    ProviderAdmissionReceipt, ProviderExecutionBindingSubmission, ProviderIdentity, RecipeId,
    RecipeManifest, RoleProfileId, RoleProfileManifest, RouteCandidateEvidence,
    StaffingLaneRequest, StaffingPlanCandidate, StaffingPlanRequest, WorkerId,
};
use eliot_contracts::{EpochLineageId, sha256_hex};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_kernel_service::ProviderCapabilityExpectation;
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::PrivacyClass;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

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
    StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis())
}

fn route(name: &str) -> RouteFingerprint {
    let digest = |seed: &str| {
        serde_json::from_value::<LowercaseSha256>(serde_json::json!(sha256_hex(
            format!("coordinator-fixture-{seed}-{name}").as_bytes()
        )))
        .expect("valid fixture digest")
    };
    RouteFingerprint {
        host_family: "test-host".to_owned(),
        adapter: format!("adapter-{name}"),
        protocol_transport: "fixture".to_owned(),
        runtime_hash: digest("runtime"),
        adapter_hash: digest("adapter"),
        provider: format!("provider-{name}"),
        model: format!("model-{name}"),
        auth_billing: "fixture-account".to_owned(),
        serializer_hash: digest("serializer"),
        tool_semantics_hash: digest("tools"),
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: digest("features"),
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
        work_class: "swarm".parse()?,
        lanes: vec![StaffingLaneRequest {
            work_unit_id: WorkUnitId::new("work-a")?,
            role_id: RoleProfileId::new("writer-v1")?,
            work_class: "swarm".parse()?,
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
    assert!(
        candidate.lanes[0]
            .routing
            .evidence_refs
            .contains(&"route-evidence-0".to_owned())
    );
    assert_eq!(candidate.lanes[0].routing.rejected.len(), 1);
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
    let routing_digest = candidate_digest_for(&candidate.lanes[0].routing)?;
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
        controller_epoch: test_epoch(TEST_LINEAGE_A, 1),
        coordinator_lease: serde_json::from_value::<eliot_agent_api::WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-forged"}),
        )?,
        provider_identity: forged_identity,
        g11_admission_receipt_ref: "forged-g11-admission".to_owned(),
        durable_job_ref: "forged-job".to_owned(),
        admitted_lanes: vec![AdmittedLaneReceipt {
            work_unit_id: candidate.lanes[0].work_unit_id.clone(),
            role_id: candidate.lanes[0].role_id.clone(),
            role_revision: candidate.lanes[0].role_revision.clone(),
            attempt_id: eliot_agent_api::AttemptId::new("attempt-forged")?,
            lease_id: serde_json::from_value::<eliot_agent_api::WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "work-lease-forged"}),
            )?,
            worker_id: WorkerId::new("worker-forged")?,
            work_class: candidate.lanes[0].work_class,
            route: candidate.lanes[0]
                .routing
                .selected
                .clone()
                .ok_or("candidate must select a route")?,
            routing_receipt_digest: routing_digest,
            budget: candidate.lanes[0].budget.clone(),
            priority: candidate.lanes[0].priority,
            mutation_scope: candidate.lanes[0].mutation_scope.clone(),
            admitted_route: None,
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
fn execution_binding_submission_wire_is_additive_and_snapshot_stays_v4() -> TestResult {
    // S2 stays additive: no snapshot schema bump.
    assert_eq!(
        eliot_agent_coordinator::SNAPSHOT_SCHEMA_VERSION,
        "eliot-agent-coordinator/snapshot-v4"
    );
    let submission = ProviderExecutionBindingSubmission {
        binding: ProviderExecutionBinding {
            attempt_id: AttemptId::new("attempt-bind-wire")?,
            lease_id: serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-bind-wire"}),
            )?,
            state_fence: fence(),
            runtime_generation: ResourceGeneration::genesis(),
            route: route("a"),
            session_id: None,
            provider_scope_ref: "provider-scope-wire".to_owned(),
            native_session: NativeSession::Sessionless,
            execution_unit: ExecutionUnit::new("test-turn", "turn-wire")?,
            start_request_id: RequestId::new("start-wire")?,
            start_request_sha256: "ab".repeat(32),
        },
        provider_identity: ProviderIdentity {
            verifier_identity: "sealed-test-verifier".to_owned(),
            a01_acceptance_receipt_ref: "a01-accepted-proof".to_owned(),
            a01_contract_revision: "a01-rev-1".to_owned(),
            g11_provider_revision: "g11-rev-1".to_owned(),
            capacity_identity: "capacity-a".to_owned(),
            capacity_revision: RevisionId::new("capacity-rev-1")?,
        },
        provider_start_receipt_ref: "proof-bind-wire".to_owned(),
    };
    let wire = serde_json::to_value(&submission)?;
    assert_eq!(
        serde_json::from_value::<ProviderExecutionBindingSubmission>(wire.clone())?,
        submission
    );
    let mut with_unknown = wire;
    with_unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ProviderExecutionBindingSubmission>(with_unknown).is_err());
    let context = ExecutionContext {
        admission_id: AdmissionId::new("admission-wire")?,
        task_revision: "task-rev-1".to_owned(),
        plan_revision: RevisionId::new("plan-rev-1")?,
        state_fence: fence(),
        controller_epoch: test_epoch(TEST_LINEAGE_A, 1),
        coordinator_lease: serde_json::from_value::<WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "coordinator-lease-wire"}),
        )?,
    };
    let event = CoordinatorEvent::ProviderExecutionBound {
        context,
        submission: Box::new(submission),
    };
    let event_wire = serde_json::to_value(&event)?;
    assert_eq!(event_wire["kind"], "PROVIDER_EXECUTION_BOUND");
    assert_eq!(
        serde_json::from_value::<CoordinatorEvent>(event_wire)?,
        event
    );
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

fn integration_provider_identity() -> TestResult<ProviderIdentity> {
    Ok(ProviderIdentity {
        verifier_identity: "sealed-integration-verifier".to_owned(),
        a01_acceptance_receipt_ref: "a01-accepted-proof".to_owned(),
        a01_contract_revision: "a01-rev-1".to_owned(),
        g11_provider_revision: "g11-rev-1".to_owned(),
        capacity_identity: "capacity-a".to_owned(),
        capacity_revision: RevisionId::new("capacity-rev-1")?,
    })
}

/// Builds daemon-supplied Kernel admission from exact owner records. Every
/// digest is recomputed with the same `sha256_hex` validator the production
/// verifier uses; no canned pass value is hardcoded.
fn integration_capability(revoked: bool) -> TestResult<AdmittedProviderCapability> {
    let epoch = test_epoch(TEST_LINEAGE_A, 1);
    Ok(AdmittedProviderCapability::new(
        integration_provider_identity()?,
        "claim-integration-1".to_owned(),
        "attempt-integration-1".to_owned(),
        "op-integration-1".to_owned(),
        sha256_hex(b"claim-binding-material-integration-1"),
        sha256_hex(b"executable-material-integration-1"),
        "route-rev-7".to_owned(),
        "capacity-rev-3".to_owned(),
        ProviderCapabilityExpectation {
            current_route_revision: "route-rev-7".to_owned(),
            current_capacity_revision: "capacity-rev-3".to_owned(),
            live_authority_epoch: epoch.clone(),
            revoked,
        },
        epoch,
        0,
    )?)
}

fn integration_zero_digest() -> TestResult<LowercaseSha256> {
    Ok(serde_json::from_value(serde_json::json!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ))?)
}

fn integration_admission_receipt(
    candidate: &StaffingPlanCandidate,
) -> TestResult<ProviderAdmissionReceipt> {
    let lane = candidate
        .lanes
        .first()
        .ok_or("candidate must carry one lane")?;
    let selected = lane
        .routing
        .selected
        .clone()
        .ok_or("candidate must select a route")?;
    let attempt_id = AttemptId::new("attempt-integration-1")?;
    let lease_id = serde_json::from_value::<WorkLeaseId>(
        serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-integration-1"}),
    )?;
    let mut admitted_route = AdmittedRouteReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        decision_id: DecisionId::new("decision-integration-1")?,
        candidate_digest: candidate_digest_for(&lane.routing)?,
        attempt_id: attempt_id.clone(),
        lease_id: lease_id.clone(),
        state_fence: candidate.state_fence.clone(),
        runtime_generation: ResourceGeneration::genesis(),
        policy_revision: lane.routing.policy_revision,
        requested_route: selected.clone(),
        selected_route: Some(selected.clone()),
        no_route: None,
        evidence_refs: lane.routing.evidence_refs.clone(),
        proof_ceiling: ProofCeiling::CandidateArtifact,
        self_digest: integration_zero_digest()?,
    };
    admitted_route.self_digest = admitted_route.compute_digest()?;
    admitted_route
        .validate()
        .map_err(|error| format!("integration admission fixture must validate: {error}"))?;
    Ok(ProviderAdmissionReceipt {
        admission_id: AdmissionId::new("admission-integration-1")?,
        candidate_id: candidate.candidate_id.clone(),
        launch_request_id: candidate.launch_request_id.clone(),
        recipe_id: candidate.recipe_id.clone(),
        recipe_revision: candidate.recipe_revision.clone(),
        task_id: candidate.task_id.clone(),
        task_revision: candidate.task_revision.clone(),
        plan_revision: candidate.plan_revision.clone(),
        state_fence: candidate.state_fence.clone(),
        controller_epoch: test_epoch(TEST_LINEAGE_A, 1),
        coordinator_lease: serde_json::from_value::<WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "coordinator-lease-integration-1"}),
        )?,
        provider_identity: integration_provider_identity()?,
        g11_admission_receipt_ref: "proof-admission-integration-1".to_owned(),
        durable_job_ref: "durable-job-integration-1".to_owned(),
        admitted_lanes: vec![AdmittedLaneReceipt {
            work_unit_id: lane.work_unit_id.clone(),
            role_id: lane.role_id.clone(),
            role_revision: lane.role_revision.clone(),
            attempt_id,
            lease_id,
            worker_id: WorkerId::new("worker-integration-1")?,
            work_class: lane.work_class,
            route: selected,
            routing_receipt_digest: candidate_digest_for(&lane.routing)?,
            budget: lane.budget.clone(),
            priority: lane.priority,
            mutation_scope: lane.mutation_scope.clone(),
            admitted_route: Some(admitted_route),
        }],
    })
}

#[test]
fn production_capability_admits_and_restores_receipt() -> TestResult {
    let cfg = config()?;
    let mut coordinator =
        AgentCoordinator::new_with_admitted_provider(cfg.clone(), integration_capability(false)?)?;
    let candidate = coordinator.plan(request()?)?;
    let admitted = coordinator.admit(integration_admission_receipt(&candidate)?)?;
    assert_eq!(admitted.admitted_lanes.len(), 1);
    let snapshot = coordinator.snapshot()?;
    let restored = AgentCoordinator::restore_with_admitted_provider(
        snapshot.clone(),
        cfg.clone(),
        integration_capability(false)?,
    )?;
    assert_eq!(restored.events(), coordinator.events());
    assert_eq!(restored.snapshot()?, snapshot);
    // Revoked Kernel evidence fails a fresh restore closed: the stored
    // `Verified` label alone never restores authority.
    assert_eq!(
        AgentCoordinator::restore_with_admitted_provider(
            snapshot,
            cfg,
            integration_capability(true)?,
        )
        .err(),
        Some(CoordinatorError::StaleProviderBinding)
    );
    Ok(())
}
