use std::collections::BTreeSet;

use eliot_agent_api::{
    AgentLaunchRequest, AgentWorkUnitBrief, AttemptId, AuthorityEpoch, BudgetEnvelope,
    EffectCeiling, EffectKind, LaunchRequestId, ResourceGeneration, RouteFingerprint, StateFence,
    TaskId, WorkLeaseId, WorkUnitId,
};
use eliot_agent_contracts::{RevisionId, contract_shape_digest};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_security_contracts::PrivacyClass;

use super::{AgentCoordinator, ProviderProofKind, ProviderVerifier};
use crate::{
    AdmissionId, AdmittedLaneReceipt, CandidateId, CoordinatorConfig, CoordinatorError,
    CoordinatorEvent, PlanGap, ProviderAdmissionReceipt, ProviderBindingSnapshot, ProviderIdentity,
    RecipeId, RecipeManifest, RoleProfileId, RoleProfileManifest, RouteCandidateEvidence,
    StaffingLaneRequest, StaffingPlanCandidate, StaffingPlanRequest, WorkerId,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct ExactAdmissionProvider {
    identity: ProviderIdentity,
    proof_ref: String,
    expected_payload: String,
    minimum_sequence: u64,
}

impl ProviderVerifier for ExactAdmissionProvider {
    fn binding(&self) -> ProviderBindingSnapshot {
        ProviderBindingSnapshot::Verified {
            identity: self.identity.clone(),
        }
    }

    fn minimum_event_sequence(&self) -> u64 {
        self.minimum_sequence
    }

    fn verify(
        &self,
        kind: ProviderProofKind,
        identity: &ProviderIdentity,
        proof_ref: &str,
        canonical_payload: &str,
    ) -> Result<(), CoordinatorError> {
        if !matches!(kind, ProviderProofKind::Admission)
            || identity != &self.identity
            || proof_ref != self.proof_ref
            || canonical_payload != self.expected_payload
        {
            return Err(CoordinatorError::ProviderVerification(
                "exact admission payload mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

fn rev(value: &str) -> RevisionId {
    RevisionId::new(value)
        .unwrap_or_else(|error| panic!("valid fixture revision required: {error}"))
}

fn config() -> CoordinatorConfig {
    CoordinatorConfig {
        max_ready_items: 8,
        max_admitted_attempts: 8,
        max_active_per_route: 8,
        capacity_identity: "capacity-normalization".to_owned(),
        capacity_revision: rev("capacity-normalization-v1"),
    }
}

fn provider_identity() -> ProviderIdentity {
    ProviderIdentity {
        verifier_identity: "exact-admission-verifier".to_owned(),
        a01_acceptance_receipt_ref: "a01-exact-admission".to_owned(),
        a01_contract_revision: "a01-v1".to_owned(),
        g11_provider_revision: "g11-v1".to_owned(),
        capacity_identity: "capacity-normalization".to_owned(),
        capacity_revision: rev("capacity-normalization-v1"),
    }
}

fn provider(
    proof_ref: &str,
    expected_payload: String,
    minimum_sequence: u64,
) -> ExactAdmissionProvider {
    ExactAdmissionProvider {
        identity: provider_identity(),
        proof_ref: proof_ref.to_owned(),
        expected_payload,
        minimum_sequence,
    }
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

fn effect_ceiling() -> EffectCeiling {
    EffectCeiling {
        scope_ref: "scope:normalization".to_owned(),
        allowed: BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]),
        max_external_effects: 0,
    }
}

fn route(tag: &str) -> RouteFingerprint {
    RouteFingerprint {
        host_family: "fixture-host".to_owned(),
        adapter: format!("adapter-{tag}"),
        protocol_transport: "fixture".to_owned(),
        runtime_hash: format!("runtime-{tag}"),
        adapter_hash: format!("adapter-hash-{tag}"),
        provider: format!("provider-{tag}"),
        model: format!("model-{tag}"),
        auth_billing: "fixture-account".to_owned(),
        serializer_hash: "serializer-v1".to_owned(),
        tool_semantics_hash: "tools-v1".to_owned(),
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: "features-v1".to_owned(),
    }
}

fn work_unit(tag: &str) -> TestResult<AgentWorkUnitBrief> {
    Ok(AgentWorkUnitBrief {
        id: WorkUnitId::new(format!("work-{tag}"))?,
        objective: format!("inspect {tag}"),
        causal_property: format!("admission identity {tag}"),
        scope_ref: "scope:normalization".to_owned(),
        expected_outputs: vec![format!("artifact-{tag}")],
        source_refs: vec!["source:normalization-contract".to_owned()],
        verifier_ref: "verifier:exact-admission".to_owned(),
        integration_owner: "owner:agent-coordinator".to_owned(),
        contract_revision: "work-v1".to_owned(),
        budget: budget(),
        effect_ceiling: effect_ceiling(),
        stop_condition: "admission checked".to_owned(),
    })
}

fn route_evidence(tag: &str) -> RouteCandidateEvidence {
    RouteCandidateEvidence {
        route: route(tag),
        preference_rank: 0,
        capacity_identity: "capacity-normalization".to_owned(),
        capacity_revision: rev("capacity-normalization-v1"),
        capacity_limit: 8,
        budget_evidence: BudgetEvidence {
            arm_id: format!("arm-{tag}"),
            model_calls: 1,
            wall_time_ms: 100,
            ..BudgetEvidence::default()
        },
        evidence_refs: vec![format!("evidence-{tag}")],
    }
}

fn plan_request() -> TestResult<StaffingPlanRequest> {
    let alpha_work = work_unit("alpha")?;
    let beta_work = work_unit("beta")?;
    Ok(StaffingPlanRequest {
        candidate_id: CandidateId::new("candidate-normalization")?,
        launch: AgentLaunchRequest {
            id: LaunchRequestId::new("launch-normalization")?,
            task_id: TaskId::new("task-normalization")?,
            parent_attempt: None,
            work_units: vec![alpha_work, beta_work],
            required_competence: vec!["rust".to_owned()],
            allowed_route_classes: vec!["provider-alpha".to_owned(), "provider-beta".to_owned()],
            native_child_policy: "disabled".to_owned(),
            root_context_revision: "context-v1".to_owned(),
            context_budget: budget(),
            evidence_capability_refs: vec!["capability:fixture".to_owned()],
            privacy_profile: "PRIVATE".to_owned(),
            effect_ceiling: effect_ceiling(),
            max_depth: 2,
            max_fanout: 2,
            cumulative_descendant_budget: budget(),
            verifier_ref: "verifier:exact-admission".to_owned(),
            synthesis_owner: "owner:synthesis".to_owned(),
            integration_owner: "owner:agent-coordinator".to_owned(),
            cancellation_policy: "bounded".to_owned(),
        },
        recipe: RecipeManifest {
            recipe_id: RecipeId::new("recipe-normalization")?,
            manifest_revision: rev("recipe-normalization-v1"),
            route_policy_revision: rev("route-policy-v1"),
            max_lanes: 2,
            max_descendants: 4,
            role_profiles: vec![
                RoleProfileManifest {
                    role_id: RoleProfileId::new("role-alpha")?,
                    manifest_revision: rev("role-alpha-v1"),
                    required_competence: vec!["rust".to_owned()],
                    allowed_route_classes: vec!["provider-alpha".to_owned()],
                    mutation_capable: false,
                },
                RoleProfileManifest {
                    role_id: RoleProfileId::new("role-beta")?,
                    manifest_revision: rev("role-beta-v1"),
                    required_competence: vec!["rust".to_owned()],
                    allowed_route_classes: vec!["provider-beta".to_owned()],
                    mutation_capable: false,
                },
            ],
        },
        task_revision: "task-normalization-v1".to_owned(),
        plan_revision: rev("plan-normalization-v1"),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        privacy_class: PrivacyClass::Private,
        lanes: vec![
            StaffingLaneRequest {
                work_unit_id: WorkUnitId::new("work-alpha")?,
                role_id: RoleProfileId::new("role-alpha")?,
                route_candidates: vec![route_evidence("alpha")],
                budget: budget(),
                priority: 2,
                mutation_scope: None,
            },
            StaffingLaneRequest {
                work_unit_id: WorkUnitId::new("work-beta")?,
                role_id: RoleProfileId::new("role-beta")?,
                route_candidates: vec![route_evidence("beta")],
                budget: budget(),
                priority: 1,
                mutation_scope: None,
            },
        ],
    })
}

fn admission_receipt(
    candidate: &StaffingPlanCandidate,
    proof_ref: &str,
) -> TestResult<ProviderAdmissionReceipt> {
    let admitted_lanes = candidate
        .lanes
        .iter()
        .map(|lane| {
            let suffix = lane.work_unit_id.as_str();
            Ok(AdmittedLaneReceipt {
                work_unit_id: lane.work_unit_id.clone(),
                role_id: lane.role_id.clone(),
                role_revision: lane.role_revision.clone(),
                attempt_id: AttemptId::new(format!("attempt-{suffix}"))?,
                lease_id: WorkLeaseId::new(format!("lease-{suffix}"))?,
                worker_id: WorkerId::new(format!("worker-{suffix}"))?,
                route: lane.routing.selected_route.clone(),
                routing_receipt_digest: contract_shape_digest(&lane.routing)?,
                budget: lane.budget.clone(),
                priority: lane.priority,
                mutation_scope: lane.mutation_scope.clone(),
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(ProviderAdmissionReceipt {
        admission_id: AdmissionId::new("admission-normalization")?,
        candidate_id: candidate.candidate_id.clone(),
        launch_request_id: candidate.launch_request_id.clone(),
        recipe_id: candidate.recipe_id.clone(),
        recipe_revision: candidate.recipe_revision.clone(),
        task_id: candidate.task_id.clone(),
        task_revision: candidate.task_revision.clone(),
        plan_revision: candidate.plan_revision.clone(),
        state_fence: candidate.state_fence.clone(),
        controller_epoch: candidate.state_fence.authority_epoch,
        coordinator_lease: WorkLeaseId::new("coordinator-lease-normalization")?,
        provider_identity: provider_identity(),
        g11_admission_receipt_ref: proof_ref.to_owned(),
        durable_job_ref: "durable-job-normalization".to_owned(),
        admitted_lanes,
    })
}

fn normalize_fixture(receipt: &mut ProviderAdmissionReceipt) {
    receipt.admitted_lanes.sort_by(|left, right| {
        left.work_unit_id
            .cmp(&right.work_unit_id)
            .then_with(|| left.role_id.cmp(&right.role_id))
            .then_with(|| left.attempt_id.cmp(&right.attempt_id))
    });
}

fn prepared_receipts() -> TestResult<(
    StaffingPlanRequest,
    ProviderAdmissionReceipt,
    ProviderAdmissionReceipt,
    String,
    String,
)> {
    let request = plan_request()?;
    let mut planner = AgentCoordinator::new(
        config(),
        PlanGap::G11Unavailable {
            reason: "fixture planning only".to_owned(),
        },
    )?;
    let candidate = planner.plan(request.clone())?;
    let mut incoming = admission_receipt(&candidate, "proof-admission-normalization")?;
    incoming.admitted_lanes.reverse();
    let incoming_payload = serde_json::to_string(&incoming)?;
    let mut normalized = incoming.clone();
    normalize_fixture(&mut normalized);
    let normalized_payload = serde_json::to_string(&normalized)?;
    assert_ne!(incoming_payload, normalized_payload);
    Ok((
        request,
        incoming,
        normalized,
        incoming_payload,
        normalized_payload,
    ))
}

#[test]
fn verifier_event_snapshot_and_return_value_bind_one_normalized_payload() -> TestResult {
    let (request, incoming, normalized, _, normalized_payload) = prepared_receipts()?;
    let cfg = config();
    let proof_ref = incoming.g11_admission_receipt_ref.clone();
    let mut coordinator = AgentCoordinator::with_provider(
        cfg.clone(),
        Box::new(provider(&proof_ref, normalized_payload.clone(), 0)),
    )?;
    let candidate = coordinator.plan(request)?;
    assert_eq!(candidate.candidate_id, incoming.candidate_id);

    let returned = coordinator.admit(incoming)?;
    assert_eq!(returned, normalized);
    assert_eq!(serde_json::to_string(&returned)?, normalized_payload);

    let stored = coordinator
        .events()
        .iter()
        .find_map(|event| match event {
            CoordinatorEvent::PlanAdmitted { receipt } => Some(receipt.as_ref()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("normalized admission event must exist"));
    assert_eq!(stored, &normalized);
    assert_eq!(serde_json::to_string(stored)?, normalized_payload);

    let snapshot = coordinator.snapshot()?;
    let restored = AgentCoordinator::restore_with_provider(
        snapshot.clone(),
        cfg,
        Box::new(provider(
            &proof_ref,
            normalized_payload,
            snapshot.event_sequence,
        )),
    )?;
    assert_eq!(restored.snapshot()?, snapshot);
    Ok(())
}

#[test]
fn proof_bound_to_pre_normalized_order_is_rejected_without_mutation() -> TestResult {
    let (request, incoming, _, incoming_payload, _) = prepared_receipts()?;
    let proof_ref = incoming.g11_admission_receipt_ref.clone();
    let mut coordinator = AgentCoordinator::with_provider(
        config(),
        Box::new(provider(&proof_ref, incoming_payload, 0)),
    )?;
    coordinator.plan(request)?;
    let before = coordinator.snapshot_json()?;
    assert!(matches!(
        coordinator.admit(incoming),
        Err(CoordinatorError::ProviderVerification(_))
    ));
    assert_eq!(coordinator.snapshot_json()?, before);
    Ok(())
}

#[test]
fn semantic_replay_with_another_lane_order_is_idempotent() -> TestResult {
    let (request, incoming, normalized, _, normalized_payload) = prepared_receipts()?;
    let proof_ref = incoming.g11_admission_receipt_ref.clone();
    let mut coordinator = AgentCoordinator::with_provider(
        config(),
        Box::new(provider(&proof_ref, normalized_payload, 0)),
    )?;
    coordinator.plan(request)?;
    let first = coordinator.admit(incoming)?;
    assert_eq!(first, normalized);
    let event_count = coordinator.events().len();

    let mut replay = normalized.clone();
    replay.admitted_lanes.reverse();
    assert_eq!(coordinator.admit(replay)?, normalized);
    assert_eq!(coordinator.events().len(), event_count);
    Ok(())
}
