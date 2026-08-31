use std::collections::BTreeSet;

use eliot_agent_api::{
    ActualRouteReceipt, AgentLaunchRequest, AgentResult, AgentWorkUnitBrief, ArtifactId, AttemptId,
    AuthorityEpoch, BudgetEnvelope, EffectCeiling, EffectKind, LaunchRequestId, QuotaKnowledge,
    ResourceGeneration, ResultDisposition, RouteFingerprint, RouteFingerprintId, StateFence,
    TaskId, UsageReceipt, WorkLeaseId, WorkUnitId,
};
use eliot_agent_contracts::{
    DeliveryPolicy, DescendantClosureReceipt, LivePeerMessage, LivePeerMessageState, RevisionId,
    contract_shape_digest,
};
use eliot_contracts::{IntegrationRevision, PolicyRevision, TaskRevision};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_security_contracts::PrivacyClass;

use crate::core::{ProviderProofKind, ProviderVerifier};
use crate::{
    AdmissionId, AdmittedLaneReceipt, AgentCoordinator, CandidateId, CoordinatorConfig,
    CoordinatorError, DescendantClosureSubmission, ExecutionContext, ObservationId, OperationId,
    OutcomeReconciliationId, PlanGap, ProviderAdmissionReceipt, ProviderBindingSnapshot,
    ProviderIdentity, ProviderReassignmentReceipt, ProviderUnknownOutcomeReconciliation,
    ProviderWorkerFenceReceipt, ReassignmentId, RecipeId, RecipeManifest, ResultSubmission,
    RoleProfileId, RoleProfileManifest, RouteCandidateEvidence, StaffingLaneRequest,
    StaffingPlanCandidate, StaffingPlanRequest, SubmissionId, UnknownOutcomeResolution, WorkerId,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct TestProvider {
    identity: ProviderIdentity,
    proofs: BTreeSet<String>,
    minimum_sequence: u64,
}

impl ProviderVerifier for TestProvider {
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
        _kind: ProviderProofKind,
        identity: &ProviderIdentity,
        proof_ref: &str,
        canonical_payload: &str,
    ) -> Result<(), CoordinatorError> {
        if identity != &self.identity
            || !self.proofs.contains(proof_ref)
            || canonical_payload.is_empty()
        {
            return Err(CoordinatorError::ProviderVerification(
                "test provider rejected proof".to_owned(),
            ));
        }
        Ok(())
    }
}

fn rev(value: &str) -> RevisionId {
    RevisionId::new(value)
        .unwrap_or_else(|error| panic!("valid fixture revision required: {error}"))
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn full_fence() -> StateFence {
    StateFence {
        authority_epoch: AuthorityEpoch::genesis(),
        resource_generation: ResourceGeneration::genesis(),
        task_revision: Some(TaskRevision::genesis()),
        policy_revision: Some(PolicyRevision::genesis()),
        integration_revision: Some(IntegrationRevision::genesis()),
    }
}

fn config(max_attempts: usize, max_route: usize) -> CoordinatorConfig {
    CoordinatorConfig {
        max_ready_items: 32,
        max_admitted_attempts: max_attempts,
        max_active_per_route: max_route,
        capacity_identity: "capacity-a".to_owned(),
        capacity_revision: rev("capacity-rev-1"),
    }
}

fn provider_identity() -> ProviderIdentity {
    ProviderIdentity {
        verifier_identity: "sealed-test-verifier".to_owned(),
        a01_acceptance_receipt_ref: "a01-accepted-proof".to_owned(),
        a01_contract_revision: "a01-rev-1".to_owned(),
        g11_provider_revision: "g11-rev-1".to_owned(),
        capacity_identity: "capacity-a".to_owned(),
        capacity_revision: rev("capacity-rev-1"),
    }
}

fn verifier(proofs: &[&str], minimum_sequence: u64) -> TestProvider {
    TestProvider {
        identity: provider_identity(),
        proofs: proofs.iter().map(|proof| (*proof).to_owned()).collect(),
        minimum_sequence,
    }
}

fn coordinator(
    cfg: CoordinatorConfig,
    proofs: &[&str],
) -> Result<AgentCoordinator, CoordinatorError> {
    AgentCoordinator::with_provider(cfg, Box::new(verifier(proofs, 0)))
}

fn budget() -> BudgetEnvelope {
    BudgetEnvelope {
        context_tokens: 8_000,
        wall_time_ms: 60_000,
        output_bytes: 256_000,
        cost_microunits: 1_000_000,
        max_depth: 3,
        max_descendants: 8,
    }
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

fn route_evidence(route: RouteFingerprint, rank: u16) -> RouteCandidateEvidence {
    RouteCandidateEvidence {
        route,
        preference_rank: rank,
        capacity_identity: "capacity-a".to_owned(),
        capacity_revision: rev("capacity-rev-1"),
        capacity_limit: 4,
        budget_evidence: BudgetEvidence {
            arm_id: format!("route-arm-{rank}"),
            model_calls: 1,
            wall_time_ms: 100,
            ..BudgetEvidence::default()
        },
        evidence_refs: vec![format!("route-evidence-{rank}")],
    }
}

fn work(id: &str, write: bool) -> Result<AgentWorkUnitBrief, eliot_agent_api::ContractError> {
    let mut allowed = BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]);
    if write {
        allowed.insert(EffectKind::WriteCandidate);
    }
    Ok(AgentWorkUnitBrief {
        id: WorkUnitId::new(id)?,
        objective: format!("bounded responsibility {id}"),
        causal_property: format!("causal property {id}"),
        scope_ref: format!("scope-{id}"),
        expected_outputs: vec!["candidate artifact".to_owned()],
        source_refs: vec!["architecture:10635".to_owned()],
        verifier_ref: "cargo-test".to_owned(),
        integration_owner: "independent-integrator".to_owned(),
        contract_revision: "work-v1".to_owned(),
        budget: budget(),
        effect_ceiling: EffectCeiling {
            scope_ref: format!("scope-{id}"),
            allowed,
            max_external_effects: 0,
        },
        stop_condition: "candidate submitted".to_owned(),
    })
}

#[derive(Clone)]
struct LaneSpec<'a> {
    work: &'a str,
    role: &'a str,
    route: &'a str,
    scope: Option<&'a str>,
    write: bool,
    priority: u16,
}

fn request(
    tag: &str,
    specs: &[LaneSpec<'_>],
    parent_attempt: Option<AttemptId>,
) -> TestResult<StaffingPlanRequest> {
    let work_units = specs
        .iter()
        .map(|spec| work(spec.work, spec.write))
        .collect::<Result<Vec<_>, _>>()?;
    let role_profiles = specs
        .iter()
        .map(|spec| {
            Ok(RoleProfileManifest {
                role_id: RoleProfileId::new(spec.role)?,
                manifest_revision: rev(&format!("role-rev-{}", spec.role)),
                required_competence: vec!["rust".to_owned()],
                allowed_route_classes: vec![format!("provider-{}", spec.route)],
                mutation_capable: spec.write,
            })
        })
        .collect::<Result<Vec<_>, CoordinatorError>>()?;
    let route_classes = specs
        .iter()
        .map(|spec| format!("provider-{}", spec.route))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let root_effects = if specs.iter().any(|spec| spec.write) {
        BTreeSet::from([
            EffectKind::Observe,
            EffectKind::ReadWorkspace,
            EffectKind::WriteCandidate,
        ])
    } else {
        BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace])
    };
    Ok(StaffingPlanRequest {
        candidate_id: CandidateId::new(format!("candidate-{tag}"))?,
        launch: AgentLaunchRequest {
            id: LaunchRequestId::new(format!("launch-{tag}"))?,
            task_id: TaskId::new("task-1")?,
            parent_attempt,
            work_units,
            required_competence: vec!["rust".to_owned()],
            allowed_route_classes: route_classes,
            native_child_policy: "bounded".to_owned(),
            root_context_revision: "root-v1".to_owned(),
            context_budget: budget(),
            evidence_capability_refs: vec!["capability-fixture".to_owned()],
            privacy_profile: "PRIVATE".to_owned(),
            effect_ceiling: EffectCeiling {
                scope_ref: "task-scope".to_owned(),
                allowed: root_effects,
                max_external_effects: 0,
            },
            max_depth: 3,
            max_fanout: 8,
            cumulative_descendant_budget: budget(),
            verifier_ref: "cargo-test".to_owned(),
            synthesis_owner: "synthesis-owner".to_owned(),
            integration_owner: "integration-owner".to_owned(),
            cancellation_policy: "cascade".to_owned(),
        },
        recipe: RecipeManifest {
            recipe_id: RecipeId::new(format!("recipe-{tag}"))?,
            manifest_revision: rev(&format!("recipe-rev-{tag}")),
            route_policy_revision: rev("route-policy-1"),
            max_lanes: specs.len(),
            max_descendants: 8,
            role_profiles,
        },
        task_revision: "task-rev-1".to_owned(),
        plan_revision: rev(&format!("plan-rev-{tag}")),
        state_fence: fence(),
        privacy_class: PrivacyClass::Private,
        lanes: specs
            .iter()
            .map(|spec| {
                Ok(StaffingLaneRequest {
                    work_unit_id: WorkUnitId::new(spec.work)?,
                    role_id: RoleProfileId::new(spec.role)?,
                    route_candidates: vec![route_evidence(route(spec.route), 0)],
                    budget: budget(),
                    priority: spec.priority,
                    mutation_scope: spec.scope.map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
    })
}

fn provider_receipt(
    candidate: &StaffingPlanCandidate,
    tag: &str,
) -> TestResult<ProviderAdmissionReceipt> {
    let admitted_lanes = candidate
        .lanes
        .iter()
        .enumerate()
        .map(|(index, lane)| {
            Ok(AdmittedLaneReceipt {
                work_unit_id: lane.work_unit_id.clone(),
                role_id: lane.role_id.clone(),
                role_revision: lane.role_revision.clone(),
                attempt_id: AttemptId::new(format!("attempt-{tag}-{index}"))?,
                lease_id: WorkLeaseId::new(format!("lease-{tag}-{index}"))?,
                worker_id: WorkerId::new(format!("worker-{tag}-{index}"))?,
                route: lane.routing.selected_route.clone(),
                routing_receipt_digest: contract_shape_digest(&lane.routing)?,
                budget: lane.budget.clone(),
                priority: lane.priority,
                mutation_scope: lane.mutation_scope.clone(),
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(ProviderAdmissionReceipt {
        admission_id: AdmissionId::new(format!("admission-{tag}"))?,
        candidate_id: candidate.candidate_id.clone(),
        launch_request_id: candidate.launch_request_id.clone(),
        recipe_id: candidate.recipe_id.clone(),
        recipe_revision: candidate.recipe_revision.clone(),
        task_id: candidate.task_id.clone(),
        task_revision: candidate.task_revision.clone(),
        plan_revision: candidate.plan_revision.clone(),
        state_fence: candidate.state_fence.clone(),
        controller_epoch: AuthorityEpoch::new(1)?,
        coordinator_lease: WorkLeaseId::new(format!("coordinator-lease-{tag}"))?,
        provider_identity: provider_identity(),
        g11_admission_receipt_ref: format!("proof-admission-{tag}"),
        durable_job_ref: format!("durable-job-{tag}"),
        admitted_lanes,
    })
}

fn plan_and_admit(
    coordinator: &mut AgentCoordinator,
    tag: &str,
    specs: &[LaneSpec<'_>],
    parent_attempt: Option<AttemptId>,
) -> TestResult<ProviderAdmissionReceipt> {
    let candidate = coordinator.plan(request(tag, specs, parent_attempt)?)?;
    Ok(coordinator.admit(provider_receipt(&candidate, tag)?)?)
}

fn usage() -> UsageReceipt {
    UsageReceipt {
        input_tokens: Some(100),
        output_tokens: Some(20),
        cost_microunits: Some(1_000),
        quota: QuotaKnowledge::Known,
    }
}

fn result_submission(
    tag: &str,
    lane: &AdmittedLaneReceipt,
    disposition: ResultDisposition,
) -> TestResult<ResultSubmission> {
    Ok(ResultSubmission {
        submission_id: SubmissionId::new(format!("submission-{tag}"))?,
        lease_id: lane.lease_id.clone(),
        worker_id: lane.worker_id.clone(),
        provider_identity: provider_identity(),
        provider_result_receipt_ref: format!("proof-result-{tag}"),
        result: AgentResult {
            attempt_id: lane.attempt_id.clone(),
            disposition,
            artifacts: Vec::<ArtifactId>::new(),
            evidence_refs: if disposition == ResultDisposition::VerifiedComplete {
                vec!["verifier-evidence".to_owned()]
            } else {
                Vec::new()
            },
            proposed_effects: Vec::new(),
            effect_receipts: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: usage(),
            actual_route: ActualRouteReceipt {
                requested: lane.route.clone(),
                observed: Some(lane.route.clone()),
                route_id: RouteFingerprintId::new(format!("route-receipt-{tag}"))?,
                usage: usage(),
                started_at: "2026-08-14T00:00:00Z".to_owned(),
                terminal_at: Some("2026-08-14T00:00:01Z".to_owned()),
            },
            unknown_reason: (disposition == ResultDisposition::UnknownOutcome)
                .then(|| "provider outcome unresolved".to_owned()),
        },
    })
}

#[test]
fn sealed_verifier_rejects_forged_provider_receipt() -> TestResult {
    let mut coordinator = coordinator(config(2, 2), &["proof-admission-good"])?;
    let candidate = coordinator.plan(request(
        "good",
        &[LaneSpec {
            work: "work-good",
            role: "writer-good",
            route: "a",
            scope: Some("scope-a"),
            write: true,
            priority: 1,
        }],
        None,
    )?)?;
    let mut receipt = provider_receipt(&candidate, "good")?;
    receipt.g11_admission_receipt_ref = "caller-forged-proof".to_owned();
    assert!(matches!(
        coordinator.admit(receipt),
        Err(CoordinatorError::ProviderVerification(_))
    ));
    Ok(())
}

#[test]
fn role_route_allowlist_is_enforced_independently_of_launch_allowlist() -> TestResult {
    let mut coordinator = coordinator(config(2, 2), &[])?;
    let mut plan = request(
        "role-route",
        &[LaneSpec {
            work: "work-role-route",
            role: "reader-role-route",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    assert!(
        plan.launch
            .allowed_route_classes
            .contains(&"provider-a".to_owned())
    );
    plan.recipe.role_profiles[0].allowed_route_classes = vec!["provider-b".to_owned()];

    assert_eq!(coordinator.plan(plan), Err(CoordinatorError::RouteEvidence));
    Ok(())
}

#[test]
fn writer_is_retained_until_authenticated_worker_fence() -> TestResult {
    let mut coordinator = coordinator(
        config(3, 3),
        &[
            "proof-admission-old",
            "proof-admission-new",
            "proof-fence-old",
        ],
    )?;
    let old = plan_and_admit(
        &mut coordinator,
        "old",
        &[LaneSpec {
            work: "work-old",
            role: "writer-old",
            route: "a",
            scope: Some("shared-scope"),
            write: true,
            priority: 2,
        }],
        None,
    )?;
    let old_context = ExecutionContext::from(&old);
    let old_lane = old.admitted_lanes[0].clone();
    coordinator.start_attempt(old_context.clone(), old_lane.attempt_id.clone())?;
    let mut forged = worker_fence(&old_lane, "old", "caller-forged")?;
    assert!(matches!(
        coordinator.mark_worker_lost(old_context.clone(), forged.clone()),
        Err(CoordinatorError::ProviderVerification(_))
    ));

    let candidate = coordinator.plan(request(
        "new",
        &[LaneSpec {
            work: "work-new",
            role: "writer-new",
            route: "b",
            scope: Some("shared-scope"),
            write: true,
            priority: 1,
        }],
        None,
    )?)?;
    let new_receipt = provider_receipt(&candidate, "new")?;
    assert!(matches!(
        coordinator.admit(new_receipt.clone()),
        Err(CoordinatorError::MutatingWriterConflict(scope)) if scope == "shared-scope"
    ));
    forged.fence_receipt_ref = "proof-fence-old".to_owned();
    coordinator.mark_worker_lost(old_context, forged)?;
    coordinator.admit(new_receipt)?;
    Ok(())
}

fn worker_fence(
    lane: &AdmittedLaneReceipt,
    tag: &str,
    proof: &str,
) -> TestResult<ProviderWorkerFenceReceipt> {
    Ok(ProviderWorkerFenceReceipt {
        observation_id: ObservationId::new(format!("observation-{tag}"))?,
        attempt_id: lane.attempt_id.clone(),
        lease_id: lane.lease_id.clone(),
        worker_id: lane.worker_id.clone(),
        provider_identity: provider_identity(),
        fence_receipt_ref: proof.to_owned(),
        evidence_ref: format!("host-evidence-{tag}"),
    })
}

#[test]
fn unknown_outcome_retains_writer_until_authenticated_reconciliation() -> TestResult {
    let mut coordinator = coordinator(
        config(3, 3),
        &[
            "proof-admission-unknown",
            "proof-result-unknown",
            "proof-unknown-unknown",
            "proof-admission-after",
        ],
    )?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "unknown",
        &[LaneSpec {
            work: "work-unknown",
            role: "writer-unknown",
            route: "a",
            scope: Some("unknown-scope"),
            write: true,
            priority: 2,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let result = result_submission("unknown", &lane, ResultDisposition::UnknownOutcome)?;
    let submission_id = result.submission_id.clone();
    coordinator.submit_result(context.clone(), result)?;
    assert_eq!(
        coordinator
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("admitted attempt must exist"))
            .state,
        crate::CoordinatedAttemptState::UnknownOutcome
    );

    let candidate = coordinator.plan(request(
        "after",
        &[LaneSpec {
            work: "work-after",
            role: "writer-after",
            route: "b",
            scope: Some("unknown-scope"),
            write: true,
            priority: 1,
        }],
        None,
    )?)?;
    let after = provider_receipt(&candidate, "after")?;
    assert!(matches!(
        coordinator.admit(after.clone()),
        Err(CoordinatorError::MutatingWriterConflict(_))
    ));
    coordinator.reconcile_unknown_outcome(
        context,
        ProviderUnknownOutcomeReconciliation {
            reconciliation_id: OutcomeReconciliationId::new("unknown-final")?,
            submission_id,
            attempt_id: lane.attempt_id,
            lease_id: lane.lease_id,
            worker_id: lane.worker_id,
            provider_identity: provider_identity(),
            resolution: UnknownOutcomeResolution::NoEffect,
            effect_reconciliation_ref: "proof-unknown-unknown".to_owned(),
        },
    )?;
    coordinator.admit(after)?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn admission_bijection_and_reassignment_capacity_fail_closed() -> TestResult {
    let proofs = [
        "proof-admission-bij",
        "proof-admission-a",
        "proof-admission-b",
        "proof-fence-a",
        "proof-reassign-a",
        "proof-reassign-dup",
    ];
    let mut bijection = coordinator(config(4, 2), &proofs)?;
    let candidate = bijection.plan(request(
        "bij",
        &[
            LaneSpec {
                work: "work-bij-a",
                role: "reader-bij-a",
                route: "a",
                scope: None,
                write: false,
                priority: 2,
            },
            LaneSpec {
                work: "work-bij-b",
                role: "reader-bij-b",
                route: "b",
                scope: None,
                write: false,
                priority: 1,
            },
        ],
        None,
    )?)?;
    let mut duplicate = provider_receipt(&candidate, "bij")?;
    let first = duplicate.admitted_lanes[0].clone();
    duplicate.admitted_lanes[1].work_unit_id = first.work_unit_id;
    duplicate.admitted_lanes[1].role_id = first.role_id;
    duplicate.admitted_lanes[1].role_revision = first.role_revision;
    duplicate.admitted_lanes[1].route = first.route;
    duplicate.admitted_lanes[1].routing_receipt_digest = first.routing_receipt_digest;
    duplicate.admitted_lanes[1].budget = first.budget;
    duplicate.admitted_lanes[1].priority = first.priority;
    duplicate.admitted_lanes[1].mutation_scope = first.mutation_scope;
    assert_eq!(
        bijection.admit(duplicate),
        Err(CoordinatorError::DuplicateIdentity(
            "admitted_work_unit_role"
        ))
    );

    let mut capacity = coordinator(config(3, 1), &proofs)?;
    let a = plan_and_admit(
        &mut capacity,
        "a",
        &[LaneSpec {
            work: "work-a",
            role: "reader-a",
            route: "a",
            scope: None,
            write: false,
            priority: 2,
        }],
        None,
    )?;
    let b = plan_and_admit(
        &mut capacity,
        "b",
        &[LaneSpec {
            work: "work-b",
            role: "reader-b",
            route: "b",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&a);
    let a_lane = a.admitted_lanes[0].clone();
    capacity.start_attempt(context.clone(), a_lane.attempt_id.clone())?;
    capacity.start_attempt(
        ExecutionContext::from(&b),
        b.admitted_lanes[0].attempt_id.clone(),
    )?;
    capacity.mark_worker_lost(
        context.clone(),
        worker_fence(&a_lane, "a", "proof-fence-a")?,
    )?;
    let reassignment = ProviderReassignmentReceipt {
        reassignment_id: ReassignmentId::new("reassign-a")?,
        provider_identity: provider_identity(),
        g11_receipt_ref: "proof-reassign-a".to_owned(),
        old_attempt_id: a_lane.attempt_id.clone(),
        old_lease_id: a_lane.lease_id.clone(),
        new_attempt_id: AttemptId::new("attempt-a-new")?,
        new_lease_id: WorkLeaseId::new("lease-a-new")?,
        new_worker_id: WorkerId::new("worker-a-new")?,
        route: b.admitted_lanes[0].route.clone(),
        budget: budget(),
    };
    assert!(matches!(
        capacity.reassign(context.clone(), reassignment),
        Err(CoordinatorError::RouteMismatch)
    ));
    let duplicate_lease = ProviderReassignmentReceipt {
        reassignment_id: ReassignmentId::new("reassign-dup")?,
        provider_identity: provider_identity(),
        g11_receipt_ref: "proof-reassign-dup".to_owned(),
        old_attempt_id: a_lane.attempt_id,
        old_lease_id: a_lane.lease_id,
        new_attempt_id: AttemptId::new("attempt-a-new-2")?,
        new_lease_id: b.admitted_lanes[0].lease_id.clone(),
        new_worker_id: WorkerId::new("worker-a-new-2")?,
        route: route("a"),
        budget: budget(),
    };
    assert_eq!(
        capacity.reassign(context, duplicate_lease),
        Err(CoordinatorError::DuplicateIdentity("new_lease_id"))
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn live_capacity_evidence_limits_admission_and_reassignment() -> TestResult {
    let proofs = [
        "proof-admission-cap-old",
        "proof-admission-cap-second",
        "proof-admission-cap-live",
        "proof-fence-cap-old",
        "proof-reassign-cap-route",
        "proof-reassign-cap-widen",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;

    let mut old_request = request(
        "cap-old",
        &[LaneSpec {
            work: "work-cap-old",
            role: "reader-cap-old",
            route: "a",
            scope: None,
            write: false,
            priority: 2,
        }],
        None,
    )?;
    old_request.lanes[0].route_candidates[0].capacity_limit = 1;
    let old_candidate = coordinator.plan(old_request)?;
    assert_eq!(old_candidate.lanes[0].routing.capacity_limit, 1);
    let old = coordinator.admit(provider_receipt(&old_candidate, "cap-old")?)?;
    let old_lane = old.admitted_lanes[0].clone();
    let old_context = ExecutionContext::from(&old);
    coordinator.start_attempt(old_context.clone(), old_lane.attempt_id.clone())?;

    let mut second_request = request(
        "cap-second",
        &[LaneSpec {
            work: "work-cap-second",
            role: "reader-cap-second",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    second_request.lanes[0].route_candidates[0].capacity_limit = 1;
    let second_candidate = coordinator.plan(second_request)?;
    assert_eq!(
        coordinator.admit(provider_receipt(&second_candidate, "cap-second")?),
        Err(CoordinatorError::Backpressure {
            active: 1,
            requested: 1,
            limit: 1,
        })
    );

    coordinator.mark_worker_lost(
        old_context.clone(),
        worker_fence(&old_lane, "cap-old", "proof-fence-cap-old")?,
    )?;
    let live = plan_and_admit(
        &mut coordinator,
        "cap-live",
        &[LaneSpec {
            work: "work-cap-live",
            role: "reader-cap-live",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;

    let route_change = ProviderReassignmentReceipt {
        reassignment_id: ReassignmentId::new("reassign-cap-route")?,
        provider_identity: provider_identity(),
        g11_receipt_ref: "proof-reassign-cap-route".to_owned(),
        old_attempt_id: old_lane.attempt_id.clone(),
        old_lease_id: old_lane.lease_id.clone(),
        new_attempt_id: AttemptId::new("attempt-cap-route")?,
        new_lease_id: WorkLeaseId::new("lease-cap-route")?,
        new_worker_id: WorkerId::new("worker-cap-route")?,
        route: route("b"),
        budget: budget(),
    };
    assert_eq!(
        coordinator.reassign(old_context.clone(), route_change),
        Err(CoordinatorError::RouteMismatch)
    );

    let widening = ProviderReassignmentReceipt {
        reassignment_id: ReassignmentId::new("reassign-cap-widen")?,
        provider_identity: provider_identity(),
        g11_receipt_ref: "proof-reassign-cap-widen".to_owned(),
        old_attempt_id: old_lane.attempt_id,
        old_lease_id: old_lane.lease_id,
        new_attempt_id: AttemptId::new("attempt-cap-widen")?,
        new_lease_id: WorkLeaseId::new("lease-cap-widen")?,
        new_worker_id: WorkerId::new("worker-cap-widen")?,
        route: live.admitted_lanes[0].route.clone(),
        budget: budget(),
    };
    assert_eq!(
        coordinator.reassign(old_context, widening),
        Err(CoordinatorError::Backpressure {
            active: 1,
            requested: 1,
            limit: 1,
        })
    );
    Ok(())
}

#[test]
fn child_plan_cannot_widen_parent_effect_ceiling() -> TestResult {
    let mut coordinator = coordinator(config(4, 4), &["proof-admission-effect-parent"])?;
    let parent = plan_and_admit(
        &mut coordinator,
        "effect-parent",
        &[LaneSpec {
            work: "effect-work-parent",
            role: "effect-role-parent",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let parent_attempt = parent.admitted_lanes[0].attempt_id.clone();
    let events_before = coordinator.events().len();

    assert!(matches!(
        coordinator.plan(request(
            "effect-child",
            &[LaneSpec {
                work: "effect-work-child",
                role: "effect-role-child",
                route: "b",
                scope: Some("effect-child-scope"),
                write: true,
                priority: 1,
            }],
            Some(parent_attempt),
        )?),
        Err(CoordinatorError::ProviderContract(message))
            if message.contains("authority is not sufficient")
    ));
    assert_eq!(coordinator.events().len(), events_before);
    Ok(())
}

#[test]
fn explicit_peer_delivery_occurs_only_at_next_boundary() -> TestResult {
    let mut coordinator = coordinator(config(4, 4), &["proof-admission-peer"])?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "peer",
        &[
            LaneSpec {
                work: "work-sender",
                role: "reader-sender",
                route: "a",
                scope: None,
                write: false,
                priority: 2,
            },
            LaneSpec {
                work: "work-recipient",
                role: "reader-recipient",
                route: "b",
                scope: None,
                write: false,
                priority: 1,
            },
        ],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let sender = admitted
        .admitted_lanes
        .iter()
        .find(|lane| lane.work_unit_id.as_str() == "work-sender")
        .unwrap_or_else(|| panic!("sender lane must exist"))
        .clone();
    let recipient = admitted
        .admitted_lanes
        .iter()
        .find(|lane| lane.work_unit_id.as_str() == "work-recipient")
        .unwrap_or_else(|| panic!("recipient lane must exist"))
        .clone();
    coordinator.start_attempt(context.clone(), sender.attempt_id.clone())?;
    coordinator.start_attempt(context.clone(), recipient.attempt_id.clone())?;
    let wave = rev("wave-1");
    let message = peer_message(
        "message-1",
        &sender,
        &recipient,
        &context,
        &wave,
        "ToolOnly",
    )?;
    let queued = coordinator.admit_peer_message(context.clone(), message)?;
    assert_eq!(queued.state, LivePeerMessageState::Queued);
    let delivered = coordinator
        .deliver_next_boundary(context.clone(), recipient.attempt_id.clone())?
        .unwrap_or_else(|| panic!("queued message must be delivered"));
    assert_eq!(delivered.state, LivePeerMessageState::Delivered);

    let unavailable = peer_message(
        "message-2",
        &sender,
        &recipient,
        &context,
        &wave,
        "Unavailable",
    )?;
    coordinator.admit_peer_message(context.clone(), unavailable)?;
    assert_eq!(
        coordinator.deliver_next_boundary(context, recipient.attempt_id),
        Err(CoordinatorError::DeliveryUnavailable)
    );
    let _ = DeliveryPolicy::ToolOnly;
    Ok(())
}

fn peer_message(
    id: &str,
    sender: &AdmittedLaneReceipt,
    recipient: &AdmittedLaneReceipt,
    context: &ExecutionContext,
    wave: &RevisionId,
    delivery: &str,
) -> TestResult<LivePeerMessage> {
    Ok(serde_json::from_value(serde_json::json!({
        "message_id": id,
        "sender_attempt_id": sender.attempt_id.as_str(),
        "sender_work_item_id": sender.work_unit_id.as_str(),
        "recipients": [{"attempt_id": recipient.attempt_id.as_str(), "work_item_id": null}],
        "plan_revision": context.plan_revision.as_str(),
        "wave_revision": wave.as_str(),
        "kind": "relevant_finding",
        "concise_delta": "bounded public delta",
        "evidence_refs": [{
            "kind": "verifier",
            "id": "evidence-1",
            "revision": "evidence-rev-1",
            "digest": null
        }],
        "requested_reaction": "inform",
        "urgency": "normal",
        "dedup_key": id,
        "expires_at": null,
        "delivery_policy": delivery,
        "state": "DRAFT",
        "state_fence": {
            "authority_epoch": 1,
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        }
    }))?)
}

#[test]
fn descendant_closure_matches_runtime_before_parent_complete_candidate() -> TestResult {
    let proofs = [
        "proof-admission-parent",
        "proof-admission-child",
        "proof-result-child",
        "proof-result-parent",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let parent = plan_and_admit(
        &mut coordinator,
        "parent",
        &[LaneSpec {
            work: "work-parent",
            role: "reader-parent",
            route: "a",
            scope: None,
            write: false,
            priority: 2,
        }],
        None,
    )?;
    let parent_context = ExecutionContext::from(&parent);
    let parent_lane = parent.admitted_lanes[0].clone();
    coordinator.start_attempt(parent_context.clone(), parent_lane.attempt_id.clone())?;
    let child = plan_and_admit(
        &mut coordinator,
        "child",
        &[LaneSpec {
            work: "work-child",
            role: "reader-child",
            route: "b",
            scope: None,
            write: false,
            priority: 1,
        }],
        Some(parent_lane.attempt_id.clone()),
    )?;
    let child_context = ExecutionContext::from(&child);
    let child_lane = child.admitted_lanes[0].clone();
    coordinator.start_attempt(child_context.clone(), child_lane.attempt_id.clone())?;
    coordinator.submit_result(
        child_context,
        result_submission("child", &child_lane, ResultDisposition::VerifiedComplete)?,
    )?;
    let parent_result =
        result_submission("parent", &parent_lane, ResultDisposition::VerifiedComplete)?;
    assert_eq!(
        coordinator.submit_result(parent_context.clone(), parent_result.clone()),
        Err(CoordinatorError::IncompleteDescendantClosure)
    );
    let closure: DescendantClosureReceipt = serde_json::from_value(serde_json::json!({
        "parent_ref": {"kind":"attempt","id":parent_lane.attempt_id.as_str(),"revision":"parent-rev-1","digest":null},
        "admitted_descendant_ids": [child_lane.attempt_id.as_str()],
        "lineage_revision": "lineage-rev-1",
        "observed_runtime_refs": [{"kind":"runtime","id":"runtime-1","revision":"runtime-rev-1","digest":null}],
        "dispositions": [{
            "attempt_id": child_lane.attempt_id.as_str(),
            "state": "COMPLETED",
            "evidence_refs": [{"kind":"verifier","id":"child-proof","revision":"proof-rev-1","digest":null}]
        }],
        "unreachable_or_unknown_ids": [],
        "observation_coverage_ref": {"kind":"coverage","id":"coverage-1","revision":"coverage-rev-1","digest":null},
        "parent_finish_ceiling": "COMPLETE",
        "coordinator_evidence_refs": [{"kind":"coordinator","id":"coord-proof","revision":"coord-rev-1","digest":null}]
    }))?;
    coordinator.reconcile_descendants(
        parent_context.clone(),
        DescendantClosureSubmission {
            operation_id: OperationId::new("closure-parent")?,
            parent_attempt_id: parent_lane.attempt_id,
            receipt: closure,
        },
    )?;
    let accepted = coordinator.submit_result(parent_context, parent_result)?;
    assert_eq!(
        accepted.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    Ok(())
}

#[test]
fn snapshot_binds_sequence_digest_capacity_and_provider_identity() -> TestResult {
    let proofs = ["proof-admission-snapshot"];
    let cfg = config(2, 2);
    let mut coordinator = coordinator(cfg.clone(), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "snapshot",
        &[LaneSpec {
            work: "work-snapshot",
            role: "reader-snapshot",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    coordinator.start_attempt(
        ExecutionContext::from(&admitted),
        admitted.admitted_lanes[0].attempt_id.clone(),
    )?;
    let snapshot = coordinator.snapshot()?;
    let restored = AgentCoordinator::restore_with_provider(
        snapshot.clone(),
        cfg.clone(),
        Box::new(verifier(&proofs, snapshot.event_sequence)),
    )?;
    assert_eq!(restored.events(), coordinator.events());

    let mut rollback = snapshot.clone();
    rollback.event_sequence -= 1;
    assert_eq!(
        AgentCoordinator::restore_with_provider(
            rollback,
            cfg.clone(),
            Box::new(verifier(&proofs, 0))
        )
        .err(),
        Some(CoordinatorError::SnapshotRollback)
    );
    let mut widened = snapshot.clone();
    widened.config.max_active_per_route += 1;
    assert_eq!(
        AgentCoordinator::restore_with_provider(
            widened,
            cfg.clone(),
            Box::new(verifier(&proofs, 0))
        )
        .err(),
        Some(CoordinatorError::StaleCapacity)
    );
    assert_eq!(
        AgentCoordinator::restore_with_provider(
            snapshot.clone(),
            cfg.clone(),
            Box::new(verifier(&proofs, snapshot.event_sequence + 1))
        )
        .err(),
        Some(CoordinatorError::SnapshotRollback)
    );
    let mut tampered = snapshot;
    tampered.event_digest = "0".repeat(64);
    assert_eq!(
        AgentCoordinator::restore_with_provider(tampered, cfg, Box::new(verifier(&proofs, 0)))
            .err(),
        Some(CoordinatorError::SnapshotDigest)
    );
    Ok(())
}

#[test]
fn public_restore_with_missing_provider_remains_plan_gap() -> TestResult {
    let cfg = config(2, 2);
    let gap = PlanGap::G11Unavailable {
        reason: "G-11 absent".to_owned(),
    };
    let mut coordinator = AgentCoordinator::new(cfg.clone(), gap.clone())?;
    coordinator.plan(request(
        "gap-snapshot",
        &[LaneSpec {
            work: "work-gap",
            role: "reader-gap",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?)?;
    let json = coordinator.snapshot_json()?;
    let restored = AgentCoordinator::restore_json(&json, cfg, gap)?;
    assert_eq!(restored.events(), coordinator.events());
    Ok(())
}

#[test]
fn coordinator_case_10_exact_state_fence_is_preserved_through_execution() -> TestResult {
    let mut coordinator = coordinator(config(2, 2), &["proof-admission-case-10"])?;
    let mut request = request(
        "case-10",
        &[LaneSpec {
            work: "work-case-10",
            role: "reader-case-10",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    request.state_fence = full_fence();
    let expected = request.state_fence.clone();
    let candidate = coordinator.plan(request)?;
    assert_eq!(candidate.state_fence, expected);
    let admitted = coordinator.admit(provider_receipt(&candidate, "case-10")?)?;
    assert_eq!(admitted.state_fence, expected);
    let context = ExecutionContext::from(&admitted);
    let attempt_id = admitted.admitted_lanes[0].attempt_id.clone();
    coordinator.start_attempt(context.clone(), attempt_id.clone())?;
    assert_eq!(
        coordinator
            .attempt(&attempt_id)
            .map(|attempt| &attempt.state_fence),
        Some(&expected)
    );
    Ok(())
}

#[test]
fn coordinator_case_11_wrong_controller_epoch_has_no_mutation() -> TestResult {
    let mut coordinator = coordinator(config(2, 2), &["proof-admission-case-11"])?;
    let candidate = coordinator.plan(request(
        "case-11",
        &[LaneSpec {
            work: "work-case-11",
            role: "reader-case-11",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?)?;
    let before = coordinator.snapshot_json()?;
    let mut receipt = provider_receipt(&candidate, "case-11")?;
    receipt.controller_epoch = AuthorityEpoch::new(2)?;
    assert_eq!(
        coordinator.admit(receipt).err(),
        Some(CoordinatorError::StaleController)
    );
    assert_eq!(coordinator.snapshot_json()?, before);
    Ok(())
}

#[test]
fn coordinator_case_12_all_state_fence_revision_mismatches_are_stale_before_mutation() -> TestResult
{
    let mut coordinator = coordinator(
        config(2, 2),
        &[
            "proof-admission-case-12-resource",
            "proof-admission-case-12-task",
            "proof-admission-case-12-policy",
            "proof-admission-case-12-integration",
        ],
    )?;
    let mut plan = request(
        "case-12",
        &[LaneSpec {
            work: "work-case-12",
            role: "reader-case-12",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    plan.state_fence = full_fence();
    let candidate = coordinator.plan(plan)?;
    let baseline = coordinator.snapshot_json()?;
    let mut mismatches = [
        ("resource", full_fence()),
        ("task", full_fence()),
        ("policy", full_fence()),
        ("integration", full_fence()),
    ];
    mismatches[0].1.resource_generation = ResourceGeneration::new(2)?;
    mismatches[1].1.task_revision = Some(TaskRevision::new(5)?);
    mismatches[2].1.policy_revision = Some(PolicyRevision::new(6)?);
    mismatches[3].1.integration_revision = Some(IntegrationRevision::new(7)?);
    for (name, mismatch) in mismatches {
        let mut receipt = provider_receipt(&candidate, &format!("case-12-{name}"))?;
        receipt.state_fence = mismatch;
        assert_eq!(
            coordinator.admit(receipt).err(),
            Some(CoordinatorError::StaleFence)
        );
        assert_eq!(coordinator.snapshot_json()?, baseline);
    }
    Ok(())
}

#[test]
fn coordinator_case_13_existing_provider_lease_worker_route_and_capacity_guards_remain_green()
-> TestResult {
    sealed_verifier_rejects_forged_provider_receipt()?;
    admission_bijection_and_reassignment_capacity_fail_closed()?;
    live_capacity_evidence_limits_admission_and_reassignment()?;
    writer_is_retained_until_authenticated_worker_fence()?;
    Ok(())
}

#[test]
fn coordinator_case_14_attempt_identity_is_used_directly_without_reconstruction() -> TestResult {
    let mut coordinator = coordinator(config(2, 2), &["proof-admission-case-14"])?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "case-14",
        &[LaneSpec {
            work: "work-case-14",
            role: "reader-case-14",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let expected = admitted.admitted_lanes[0].attempt_id.clone();
    coordinator.start_attempt(context.clone(), expected.clone())?;
    let view = coordinator.coordination_map(&context, rev("wave-case-14"))?;
    assert_eq!(
        view.entries[0].assigned_attempt_id.as_ref(),
        Some(&expected)
    );
    explicit_peer_delivery_occurs_only_at_next_boundary()?;
    let source = include_str!("core.rs");
    assert!(!source.contains("AgentAttemptId::new(attempt.attempt_id"));
    assert!(!source.contains("AttemptId::new(message.sender_attempt_id"));
    assert!(!source.contains("AgentAttemptId::new(recipient_attempt_id"));
    Ok(())
}

#[test]
fn coordinator_case_15_snapshot_v4_roundtrip_binds_all_properties() -> TestResult {
    let mut coordinator = coordinator(config(2, 2), &["proof-admission-case-15"])?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "case-15",
        &[LaneSpec {
            work: "work-case-15",
            role: "reader-case-15",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    coordinator.start_attempt(context, admitted.admitted_lanes[0].attempt_id.clone())?;
    let snapshot = coordinator.snapshot()?;
    assert_eq!(snapshot.schema_version, crate::SNAPSHOT_SCHEMA_VERSION);
    let restored = AgentCoordinator::restore_with_provider(
        snapshot.clone(),
        config(2, 2),
        Box::new(verifier(
            &["proof-admission-case-15"],
            snapshot.event_sequence,
        )),
    )?;
    assert_eq!(restored.snapshot()?, snapshot);
    Ok(())
}

fn poison_snapshot_fences(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("state_fence") {
                map.insert("state_fence".to_owned(), serde_json::json!("legacy-fence"));
            }
            for child in map.values_mut() {
                poison_snapshot_fences(child);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                poison_snapshot_fences(child);
            }
        }
        _ => {}
    }
}

#[test]
fn coordinator_case_16_snapshot_v3_and_v4_legacy_fence_reject_before_replay() -> TestResult {
    let mut coordinator = coordinator(config(2, 2), &["proof-admission-case-16"])?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "case-16",
        &[LaneSpec {
            work: "work-case-16",
            role: "reader-case-16",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let _ = coordinator.start_attempt(
        ExecutionContext::from(&admitted),
        admitted.admitted_lanes[0].attempt_id.clone(),
    )?;
    let json = coordinator.snapshot_json()?;
    let mut v3: serde_json::Value = serde_json::from_str(&json)?;
    v3["schema_version"] = serde_json::json!("eliot-agent-coordinator/snapshot-v3");
    assert_eq!(
        AgentCoordinator::restore_json(
            &v3.to_string(),
            config(2, 2),
            PlanGap::G11Unavailable {
                reason: "fixture".to_owned()
            }
        )
        .err(),
        Some(CoordinatorError::UnsupportedSnapshot)
    );
    let mut legacy: serde_json::Value = serde_json::from_str(&json)?;
    poison_snapshot_fences(&mut legacy);
    assert!(
        AgentCoordinator::restore_json(
            &legacy.to_string(),
            config(2, 2),
            PlanGap::G11Unavailable {
                reason: "fixture".to_owned()
            }
        )
        .is_err()
    );
    Ok(())
}
