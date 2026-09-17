use std::collections::BTreeSet;

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentLaunchRequest, AgentResult, AgentWorkUnitBrief, ArtifactId,
    AssistantDeltaObservation, AttemptId, BudgetEnvelope, CONTRACT_VERSION, CancelReason,
    ClockReading, ContractError, DecisionId, EffectCeiling, EffectKind, EpochId, EventCursor,
    EventId, ExecutionOutcome, ExecutionUnit, ExecutionUnitObservation,
    HOST_EVENT_CONTRACT_VERSION, HOST_EVENT_DIGEST_ALGORITHM, HostEventDeliveryDisposition,
    HostEventNormalizationReceipt, HostEventPrivacyClass, HostEventQuarantineReason,
    LaunchRequestId, LowercaseSha256, NativeSession, NativeSessionLocator, NormalizationCoverage,
    NormalizedHostEventEnvelope, NormalizedHostEventPayload, PhysicalRouteObservationReceipt,
    ProposedEffect, ProviderExecutionBinding, ProviderObservationLineage, QualifiedSourceDigest,
    QuotaKnowledge, RawSourceRecord, RequestId, ResourceGeneration, RestrictedRawSourceHandle,
    ResultDisposition, RouteFingerprint, RouteObservationState, RouteSelectionCandidate,
    SessionLifecycleObservation, SessionLifecycleTransition, SessionObservation, StateFence,
    TaskId, UnsupportedDisposition, UsageReceipt, WorkLeaseId, WorkUnitId, candidate_digest_for,
};
use eliot_agent_contracts::{
    DeliveryPolicy, DescendantClosureReceipt, LivePeerMessage, LivePeerMessageState, RevisionId,
};
use eliot_contracts::{
    EpochLineageId, IntegrationRevision, PolicyRevision, TaskRevision, sha256_hex,
};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_kernel_service::ProviderCapabilityExpectation;
use eliot_security_contracts::PrivacyClass;

use crate::core::{ProviderProofKind, ProviderVerifier};
use crate::{
    AdmissionId, AdmittedLaneReceipt, AdmittedProviderCapability, AgentCoordinator, CancelCommand,
    CancellationReconciliationId, CandidateId, CoordinatorConfig, CoordinatorError,
    CoordinatorEvent, DescendantClosureSubmission, ExecutionContext, ObservationId, OperationId,
    OutcomeReconciliationId, PlanGap, ProviderAdmissionReceipt, ProviderBindingSnapshot,
    ProviderCancellationReconciliation, ProviderExecutionBindingSubmission, ProviderIdentity,
    ProviderReassignmentReceipt, ProviderUnknownOutcomeReconciliation, ProviderWorkerFenceReceipt,
    ReassignmentId, RecipeId, RecipeManifest, ResultSubmission, RoleProfileId, RoleProfileManifest,
    RouteCandidateEvidence, StaffingLaneRequest, StaffingPlanCandidate, StaffingPlanRequest,
    SubmissionId, UnknownOutcomeResolution, WORK_CLASS_CONTROL, WorkerId, normal_work_class_from_wire,
    validate_work_class, work_class_rank,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

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
    StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis())
}

fn full_fence() -> StateFence {
    StateFence {
        authority_epoch: test_epoch(TEST_LINEAGE_A, 1),
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

fn admitted_capability(minimum_sequence: u64) -> TestResult<AdmittedProviderCapability> {
    admitted_capability_for(
        provider_identity(),
        false,
        "route-rev-7",
        "capacity-rev-3",
        "route-rev-7",
        "capacity-rev-3",
        1,
        1,
        minimum_sequence,
    )
}

/// Builds daemon-supplied Kernel admission from exact owner records. Every
/// digest is recomputed here with the same `sha256_hex` validator the
/// verifier uses; no canned pass value is hardcoded.
#[allow(
    clippy::too_many_arguments,
    reason = "the test fixture mirrors the admitted capability's flat owner tuple one-to-one"
)]
fn admitted_capability_for(
    identity: ProviderIdentity,
    revoked: bool,
    route_revision: &str,
    capacity_revision: &str,
    current_route_revision: &str,
    current_capacity_revision: &str,
    expectation_sequence: u64,
    live_sequence: u64,
    minimum_sequence: u64,
) -> TestResult<AdmittedProviderCapability> {
    let live_epoch = test_epoch(TEST_LINEAGE_A, live_sequence);
    Ok(AdmittedProviderCapability::new(
        identity,
        "claim-t9-05-1".to_owned(),
        "attempt-t9-05-1".to_owned(),
        "op-t9-05-1".to_owned(),
        sha256_hex(b"claim-binding-material-t9-05-1"),
        sha256_hex(b"executable-material-t9-05-1"),
        route_revision.to_owned(),
        capacity_revision.to_owned(),
        ProviderCapabilityExpectation {
            current_route_revision: current_route_revision.to_owned(),
            current_capacity_revision: current_capacity_revision.to_owned(),
            live_authority_epoch: test_epoch(TEST_LINEAGE_A, expectation_sequence),
            revoked,
        },
        live_epoch,
        minimum_sequence,
    )?)
}

fn production_coordinator(cfg: CoordinatorConfig) -> TestResult<AgentCoordinator> {
    Ok(AgentCoordinator::new_with_admitted_provider(
        cfg,
        admitted_capability(0)?,
    )?)
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
        work_class: "swarm".to_owned(),
        lanes: specs
            .iter()
            .map(|spec| {
                Ok(StaffingLaneRequest {
                    work_unit_id: WorkUnitId::new(spec.work)?,
                    role_id: RoleProfileId::new(spec.role)?,
                    work_class: "swarm".to_owned(),
                    route_candidates: vec![route_evidence(route(spec.route), 0)],
                    budget: budget(),
                    priority: spec.priority,
                    mutation_scope: spec.scope.map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
    })
}

fn admitted_route_receipt(
    tag: &str,
    index: usize,
    routing: &RouteSelectionCandidate,
    attempt_id: &AttemptId,
    lease_id: &WorkLeaseId,
    route: &RouteFingerprint,
    fence: &StateFence,
) -> TestResult<AdmittedRouteReceipt> {
    // Test-only mint via the api fixture pattern (lib.rs admitted_fixture):
    // the external admission owner issues the decision; the coordinator only
    // stores/validates. Candidate digest + policy come from the real routing
    // so linkage checks bind exact bytes, never a hardcoded digest.
    let mut receipt = AdmittedRouteReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        decision_id: DecisionId::new(format!("decision-{tag}-{index}"))?,
        candidate_digest: candidate_digest_for(routing)?,
        attempt_id: attempt_id.clone(),
        lease_id: lease_id.clone(),
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::genesis(),
        policy_revision: routing.policy_revision.clone(),
        requested_route: route.clone(),
        selected_route: Some(route.clone()),
        no_route: None,
        evidence_refs: routing.evidence_refs.clone(),
        proof_ceiling: eliot_receipts::ProofCeiling::CandidateArtifact,
        self_digest: zero_digest()?,
    };
    receipt.self_digest = receipt.compute_digest()?;
    receipt
        .validate()
        .map_err(|error| format!("admission fixture must validate: {error}"))?;
    Ok(receipt)
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
            let selected = lane
                .routing
                .selected
                .clone()
                .ok_or("candidate must select a route")?;
            let attempt_id = AttemptId::new(format!("attempt-{tag}-{index}"))?;
            let lease_id = serde_json::from_value::<WorkLeaseId>(serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": format!("lease-{tag}-{index}")}))?;
            let routing_receipt_digest = candidate_digest_for(&lane.routing)?;
            let admitted_route = admitted_route_receipt(
                tag,
                index,
                &lane.routing,
                &attempt_id,
                &lease_id,
                &selected,
                &candidate.state_fence,
            )?;
            Ok(AdmittedLaneReceipt {
                work_unit_id: lane.work_unit_id.clone(),
                role_id: lane.role_id.clone(),
                role_revision: lane.role_revision.clone(),
                attempt_id,
                lease_id,
                worker_id: WorkerId::new(format!("worker-{tag}-{index}"))?,
                work_class: lane.work_class.clone(),
                route: selected,
                routing_receipt_digest,
                budget: lane.budget.clone(),
                priority: lane.priority,
                mutation_scope: lane.mutation_scope.clone(),
                admitted_route: Some(admitted_route),
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
        controller_epoch: test_epoch(TEST_LINEAGE_A, 1),
        coordinator_lease: serde_json::from_value::<WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": format!("coordinator-lease-{tag}")}),
        )?,
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

fn observation_binding(lane: &AdmittedLaneReceipt) -> TestResult<ProviderExecutionBinding> {
    Ok(ProviderExecutionBinding {
        attempt_id: lane.attempt_id.clone(),
        lease_id: lane.lease_id.clone(),
        state_fence: fence(),
        runtime_generation: ResourceGeneration::genesis(),
        route: lane.route.clone(),
        session_id: None,
        provider_scope_ref: "scope:test".to_owned(),
        native_session: NativeSession::Native(NativeSessionLocator::new("thread-1")?),
        execution_unit: ExecutionUnit::new("test-provider", "unit-1")?,
        start_request_id: RequestId::new("req-1")?,
        start_request_sha256: sha256_hex(b"req-1"),
    })
}

fn zero_digest() -> TestResult<LowercaseSha256> {
    Ok(serde_json::from_value(serde_json::json!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ))?)
}

fn stored_admission_digest(lane: &AdmittedLaneReceipt) -> TestResult<LowercaseSha256> {
    // S5 linkage: the observation must reference the stored admission's
    // self_digest. Legacy lanes without stored admission fall back to the
    // zero digest so the observation shape still validates; intake then
    // fails closed on the missing stored decision.
    Ok(lane
        .admitted_route
        .as_ref()
        .map(|admission| admission.self_digest.clone())
        .unwrap_or(try_zero_digest()))
}

fn try_zero_digest() -> LowercaseSha256 {
    serde_json::from_value(serde_json::json!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ))
    .expect("zero digest must decode")
}

fn matched_observation(
    lane: &AdmittedLaneReceipt,
    binding: &ProviderExecutionBinding,
) -> TestResult<PhysicalRouteObservationReceipt> {
    let mut observation = PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: lane.attempt_id.clone(),
        state_fence: fence(),
        runtime_generation: ResourceGeneration::genesis(),
        admitted_route_digest: stored_admission_digest(lane)?,
        binding: binding.clone(),
        requested_route: lane.route.clone(),
        observed_route: Some(lane.route.clone()),
        route_state: RouteObservationState::Matched,
        diverged_fields: Vec::new(),
        execution_outcome: ExecutionOutcome::Observed,
        request_digest: zero_digest()?,
        translation_digest: None,
        raw_evidence_digest: None,
        raw_evidence_ref: None,
        usage: usage(),
        started: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: ClockReading {
            valid_time_ms: Some(2_000),
            known_time_ms: Some(2_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        event_cursor: EventCursor::new("cursor-1")?,
        event_sequence: 1,
        cancellation: None,
        unobserved_reason: None,
        recovery_ref: None,
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: zero_digest()?,
    };
    observation.self_digest = observation.compute_digest()?;
    observation.validate()?;
    Ok(observation)
}

fn unknown_observation(
    lane: &AdmittedLaneReceipt,
    binding: &ProviderExecutionBinding,
) -> TestResult<PhysicalRouteObservationReceipt> {
    let mut observation = PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: lane.attempt_id.clone(),
        state_fence: fence(),
        runtime_generation: ResourceGeneration::genesis(),
        admitted_route_digest: stored_admission_digest(lane)?,
        binding: binding.clone(),
        requested_route: lane.route.clone(),
        observed_route: Some(lane.route.clone()),
        route_state: RouteObservationState::Matched,
        diverged_fields: Vec::new(),
        execution_outcome: ExecutionOutcome::UnknownOutcome,
        request_digest: zero_digest()?,
        translation_digest: None,
        raw_evidence_digest: None,
        raw_evidence_ref: None,
        usage: usage(),
        started: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: ClockReading::default(),
        event_cursor: EventCursor::new("cursor-1")?,
        event_sequence: 1,
        cancellation: None,
        unobserved_reason: None,
        recovery_ref: Some("provider outcome unresolved".to_owned()),
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: zero_digest()?,
    };
    observation.self_digest = observation.compute_digest()?;
    observation.validate()?;
    Ok(observation)
}

fn result_submission(
    tag: &str,
    lane: &AdmittedLaneReceipt,
    disposition: ResultDisposition,
) -> TestResult<ResultSubmission> {
    let binding = observation_binding(lane)?;
    let actual_route = if disposition == ResultDisposition::UnknownOutcome {
        unknown_observation(lane, &binding)?
    } else {
        matched_observation(lane, &binding)?
    };
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
            evidence_refs: if disposition == ResultDisposition::CandidateSucceeded {
                vec!["verifier-evidence".to_owned()]
            } else {
                Vec::new()
            },
            proposed_effects: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: usage(),
            actual_route,
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
        new_lease_id: serde_json::from_value::<WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-a-new"}),
        )?,
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
    assert_eq!(old_candidate.lanes[0].capacity_limit, 1);
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
        new_lease_id: serde_json::from_value::<WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-cap-route"}),
        )?,
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
        new_lease_id: serde_json::from_value::<WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-cap-widen"}),
        )?,
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
            "authority_epoch": {"lineage_id": TEST_LINEAGE_A, "sequence": 1},
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
        result_submission("child", &child_lane, ResultDisposition::CandidateSucceeded)?,
    )?;
    let parent_result = result_submission(
        "parent",
        &parent_lane,
        ResultDisposition::CandidateSucceeded,
    )?;
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
    receipt.controller_epoch = test_epoch(TEST_LINEAGE_A, 2);
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

#[test]
fn coordinator_case_17_candidate_disposition_is_candidate_only_and_capped() -> TestResult {
    let mut coordinator = coordinator(
        config(2, 2),
        &["proof-admission-case-17", "proof-result-case-17"],
    )?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "case-17",
        &[LaneSpec {
            work: "work-case-17",
            role: "reader-case-17",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let result = result_submission("case-17", &lane, ResultDisposition::CandidateSucceeded)?;
    let receipt = coordinator.submit_result(context, result)?;
    assert_eq!(
        receipt.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    assert_eq!(
        receipt.provider_disposition,
        ResultDisposition::CandidateSucceeded
    );
    // Coordinator never produces a finish-level proof.
    assert_ne!(
        receipt.proof_ceiling,
        eliot_receipts::ProofCeiling::ScopedVerification
    );
    // Serialized receipt is candidate-only.
    let wire = serde_json::to_value(&receipt)?;
    assert_eq!(wire["provider_disposition"], "CANDIDATE_SUCCEEDED");
    // No conversion path exists to FinishDecisionOutcome::VerifiedComplete.
    let source = include_str!("core.rs");
    assert!(!source.contains("FinishDecision"));
    assert!(!source.contains("VerifiedComplete"));
    Ok(())
}

#[test]
fn coordinator_case_18_legacy_verified_complete_and_effect_receipts_rejected() -> TestResult {
    // Legacy JSON with VERIFIED_COMPLETE must be rejected, not migrated.
    let legacy_disp = serde_json::json!("VERIFIED_COMPLETE");
    assert!(serde_json::from_value::<ResultDisposition>(legacy_disp).is_err());
    for alias in [
        "VERIFIED_COMPLETE",
        "verified_complete",
        "COMPLETE",
        "DONE",
        "FINISHED",
    ] {
        assert!(serde_json::from_value::<ResultDisposition>(serde_json::json!(alias)).is_err());
    }
    // Legacy numeric / null forms rejected.
    assert!(serde_json::from_value::<ResultDisposition>(serde_json::json!(0)).is_err());
    // Provider result with effect_receipts field is rejected via deny_unknown_fields.
    let route_val = serde_json::to_value(route("a"))?;
    let legacy_result = serde_json::json!({
        "attempt_id": "attempt-legacy",
        "disposition": "CANDIDATE_SUCCEEDED",
        "artifacts": [],
        "evidence_refs": [],
        "proposed_effects": [],
        "effect_receipts": [],
        "unresolved_questions": [],
        "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
        "actual_route": {
            "requested": route_val,
            "observed": route_val,
            "route_id": "route-legacy",
            "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
            "started_at": "2026-08-14T00:00:00Z",
            "terminal_at": null
        },
        "unknown_reason": null
    });
    assert!(serde_json::from_value::<AgentResult>(legacy_result).is_err());
    // Legacy DISPOSITION VERIFIED_COMPLETE with effect_receipts also rejected.
    let legacy_both = serde_json::json!({
        "attempt_id": "attempt-legacy-2",
        "disposition": "VERIFIED_COMPLETE",
        "artifacts": [],
        "evidence_refs": ["evidence"],
        "proposed_effects": [],
        "effect_receipts": [{"effect_id":"e1","authorization_ref":"a","outcome":"ok","observed_at":"now","artifact_refs":[]}],
        "unresolved_questions": [],
        "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
        "actual_route": {
            "requested": route_val,
            "observed": route_val,
            "route_id": "route-legacy-2",
            "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
            "started_at": "2026-08-14T00:00:00Z",
            "terminal_at": null
        },
        "unknown_reason": null
    });
    assert!(serde_json::from_value::<AgentResult>(legacy_both).is_err());
    Ok(())
}

#[test]
fn coordinator_case_19_replay_conflict_and_snapshot_forgery_fail_closed() -> TestResult {
    let proofs = ["proof-admission-case-19", "proof-result-case-19"];
    let mut coordinator = coordinator(config(2, 2), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "case-19",
        &[LaneSpec {
            work: "work-case-19",
            role: "reader-case-19",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let first = result_submission("case-19", &lane, ResultDisposition::CandidateSucceeded)?;
    let first_id = first.submission_id.clone();
    let first_route = first.result.actual_route.clone();
    coordinator.submit_result(context.clone(), first)?;
    // Exact replay under same submission/payload digest is idempotent.
    let mut replay = result_submission("case-19", &lane, ResultDisposition::CandidateSucceeded)?;
    replay.submission_id = first_id.clone();
    replay.result.actual_route = first_route.clone();
    let replayed = coordinator.submit_result(context.clone(), replay)?;
    assert_eq!(replayed.submission_id, first_id);
    // Same identity with different bytes (different disposition) is a conflict.
    let mut conflict = result_submission("case-19", &lane, ResultDisposition::Partial)?;
    conflict.submission_id = first_id.clone();
    assert_eq!(
        coordinator.submit_result(context.clone(), conflict).err(),
        Some(CoordinatorError::IdempotencyConflict)
    );
    // Snapshot event replay with tampered digest fails.
    let mut snapshot = coordinator.snapshot()?;
    let original_digest = snapshot.event_digest.clone();
    snapshot.event_digest = "0".repeat(64);
    assert_eq!(
        AgentCoordinator::restore_with_provider(
            snapshot,
            config(2, 2),
            Box::new(verifier(&proofs, 0))
        )
        .err(),
        Some(CoordinatorError::SnapshotDigest)
    );
    // Forged snapshot JSON with VERIFIED_COMPLETE string inside events fails to deserialize.
    let forged_json = serde_json::to_value(coordinator.snapshot()?)?;
    let forged_str = serde_json::to_string(&forged_json)?;
    let forged_str = forged_str.replace("CANDIDATE_SUCCEEDED", "VERIFIED_COMPLETE");
    assert!(serde_json::from_str::<crate::CoordinatorSnapshot>(&forged_str).is_err());
    let _ = original_digest;
    Ok(())
}

#[test]
fn coordinator_case_20_parent_closure_is_candidate_only_and_requires_descendant_reconciliation()
-> TestResult {
    let proofs = [
        "proof-admission-parent-20",
        "proof-admission-child-20",
        "proof-result-child-20",
        "proof-result-parent-20",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let parent = plan_and_admit(
        &mut coordinator,
        "parent-20",
        &[LaneSpec {
            work: "work-parent-20",
            role: "reader-parent-20",
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
        "child-20",
        &[LaneSpec {
            work: "work-child-20",
            role: "reader-child-20",
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
        result_submission(
            "child-20",
            &child_lane,
            ResultDisposition::CandidateSucceeded,
        )?,
    )?;
    // Parent candidate success without descendant closure must fail.
    let parent_result = result_submission(
        "parent-20",
        &parent_lane,
        ResultDisposition::CandidateSucceeded,
    )?;
    assert_eq!(
        coordinator
            .submit_result(parent_context.clone(), parent_result.clone())
            .err(),
        Some(CoordinatorError::IncompleteDescendantClosure)
    );
    // After closing descendants, parent candidate succeeds but proof remains candidate.
    let closure: eliot_agent_contracts::DescendantClosureReceipt = serde_json::from_value(
        serde_json::json!({
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
        }),
    )?;
    coordinator.reconcile_descendants(
        parent_context.clone(),
        DescendantClosureSubmission {
            operation_id: OperationId::new("closure-parent-20")?,
            parent_attempt_id: parent_lane.attempt_id.clone(),
            receipt: closure,
        },
    )?;
    let receipt = coordinator.submit_result(parent_context, parent_result)?;
    assert_eq!(
        receipt.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    // Even with two levels of CANDIDATE_SUCCEEDED, no task finish is derived.
    let source = include_str!("core.rs");
    assert!(!source.contains("FinishDecision"));
    assert!(!source.contains("CloseCompleted"));
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
fn plan_exact_replay_returns_existing_without_new_event_before_ready_backpressure() -> TestResult {
    let mut coordinator = coordinator(
        CoordinatorConfig {
            max_ready_items: 1,
            max_admitted_attempts: 4,
            max_active_per_route: 4,
            capacity_identity: "capacity-a".to_owned(),
            capacity_revision: rev("capacity-rev-1"),
        },
        &[],
    )?;
    let spec = LaneSpec {
        work: "work-replay",
        role: "reader-replay",
        route: "a",
        scope: None,
        write: false,
        priority: 1,
    };
    let original = request("replay", std::slice::from_ref(&spec), None)?;
    let first = coordinator.plan(original.clone())?;
    assert_eq!(coordinator.events().len(), 1);
    let second = coordinator.plan(original.clone())?;
    assert_eq!(second, first);
    assert_eq!(coordinator.events().len(), 1);
    Ok(())
}

#[test]
fn plan_same_identity_changed_bytes_fails_identity_conflict_before_ready_backpressure() -> TestResult
{
    let mut coordinator = coordinator(
        CoordinatorConfig {
            max_ready_items: 1,
            max_admitted_attempts: 4,
            max_active_per_route: 4,
            capacity_identity: "capacity-a".to_owned(),
            capacity_revision: rev("capacity-rev-1"),
        },
        &[],
    )?;
    let spec = LaneSpec {
        work: "work-conflict",
        role: "reader-conflict",
        route: "a",
        scope: None,
        write: false,
        priority: 1,
    };
    let original = request("conflict", std::slice::from_ref(&spec), None)?;
    coordinator.plan(original.clone())?;
    assert_eq!(coordinator.events().len(), 1);
    let mut changed = original.clone();
    changed.task_revision = "task-rev-conflict-changed".to_owned();
    assert_eq!(
        coordinator.plan(changed),
        Err(CoordinatorError::IdentityConflict("candidate_id"))
    );
    assert_eq!(coordinator.events().len(), 1);
    let fresh = request(
        "conflict-fresh",
        &[LaneSpec {
            work: "work-conflict-fresh",
            role: "reader-conflict-fresh",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    assert_eq!(
        coordinator.plan(fresh),
        Err(CoordinatorError::Backpressure {
            active: 1,
            requested: 1,
            limit: 1
        })
    );
    Ok(())
}

fn binding_submission(
    tag: &str,
    lane: &AdmittedLaneReceipt,
    unit: &str,
    scope: &str,
) -> TestResult<ProviderExecutionBindingSubmission> {
    Ok(ProviderExecutionBindingSubmission {
        binding: ProviderExecutionBinding {
            attempt_id: lane.attempt_id.clone(),
            lease_id: lane.lease_id.clone(),
            state_fence: fence(),
            runtime_generation: ResourceGeneration::genesis(),
            route: lane.route.clone(),
            session_id: None,
            provider_scope_ref: format!("provider-scope-{scope}"),
            native_session: NativeSession::Native(NativeSessionLocator::new(format!(
                "thread-{tag}"
            ))?),
            execution_unit: ExecutionUnit::new("test-turn", format!("turn-{unit}"))?,
            start_request_id: RequestId::new(format!("start-{tag}"))?,
            start_request_sha256: sha256_hex(format!("start-{tag}").as_bytes()),
        },
        provider_identity: provider_identity(),
        provider_start_receipt_ref: format!("proof-bind-{tag}"),
    })
}

fn bind_lane_spec<'a>(work: &'a str, role: &'a str, route: &'a str) -> LaneSpec<'a> {
    LaneSpec {
        work,
        role,
        route,
        scope: None,
        write: false,
        priority: 1,
    }
}

#[test]
fn binding_identical_replay_returns_existing_without_new_event() -> TestResult {
    let proofs = ["proof-admission-bind-a", "proof-bind-bind-a"];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "bind-a",
        &[bind_lane_spec("work-bind-a", "reader-bind-a", "a")],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let submission = binding_submission("bind-a", &lane, "unit-a", "scope-a")?;
    let events_before = coordinator.events().len();
    let first = coordinator.bind_provider_execution(context.clone(), submission.clone())?;
    assert_eq!(coordinator.events().len(), events_before + 1);
    assert_eq!(
        coordinator
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("bound attempt must exist"))
            .provider_binding,
        Some(first.clone())
    );
    let replayed = coordinator.bind_provider_execution(context, submission)?;
    assert_eq!(replayed, first);
    assert_eq!(coordinator.events().len(), events_before + 1);
    Ok(())
}

#[test]
fn binding_second_unit_rebind_conflicts_and_preserves_stored() -> TestResult {
    let proofs = [
        "proof-admission-bind-b",
        "proof-bind-bind-b",
        "proof-bind-bind-b-re",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "bind-b",
        &[bind_lane_spec("work-bind-b", "reader-bind-b", "a")],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    coordinator.bind_provider_execution(
        context.clone(),
        binding_submission("bind-b", &lane, "unit-b1", "scope-b")?,
    )?;
    let events_after_bind = coordinator.events().len();
    assert_eq!(
        coordinator.bind_provider_execution(
            context,
            binding_submission("bind-b-re", &lane, "unit-b2", "scope-b")?
        ),
        Err(CoordinatorError::IdempotencyConflict)
    );
    assert_eq!(coordinator.events().len(), events_after_bind);
    assert_eq!(
        coordinator
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("bound attempt must exist"))
            .provider_binding
            .as_ref()
            .unwrap_or_else(|| panic!("stored binding must survive a rebind conflict"))
            .execution_unit
            .unit_id,
        "turn-unit-b1"
    );
    Ok(())
}

#[test]
fn binding_duplicate_unit_reuse_conflicts_across_attempts() -> TestResult {
    let proofs = [
        "proof-admission-bind-c",
        "proof-bind-bind-c-0",
        "proof-bind-bind-c-1",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "bind-c",
        &[
            bind_lane_spec("work-bind-c-0", "reader-bind-c-0", "a"),
            bind_lane_spec("work-bind-c-1", "reader-bind-c-1", "b"),
        ],
        None,
    )?;
    let first = admitted.admitted_lanes[0].clone();
    let second = admitted.admitted_lanes[1].clone();
    coordinator.start_attempt(ExecutionContext::from(&admitted), first.attempt_id.clone())?;
    coordinator.start_attempt(ExecutionContext::from(&admitted), second.attempt_id.clone())?;
    coordinator.bind_provider_execution(
        ExecutionContext::from(&admitted),
        binding_submission("bind-c-0", &first, "unit-shared", "scope-shared")?,
    )?;
    let events_after_first = coordinator.events().len();
    assert_eq!(
        coordinator.bind_provider_execution(
            ExecutionContext::from(&admitted),
            binding_submission("bind-c-1", &second, "unit-shared", "scope-shared")?
        ),
        Err(CoordinatorError::DuplicateIdentity("execution_unit"))
    );
    assert_eq!(coordinator.events().len(), events_after_first);
    assert_eq!(
        coordinator
            .attempt(&second.attempt_id)
            .unwrap_or_else(|| panic!("second attempt must exist"))
            .provider_binding,
        None
    );
    Ok(())
}

#[test]
fn binding_snapshot_restore_preserves_binding_and_absent_stays_unresolved() -> TestResult {
    let proofs = ["proof-admission-bind-d", "proof-bind-bind-d"];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "bind-d",
        &[bind_lane_spec("work-bind-d", "reader-bind-d", "a")],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let pre_binding = coordinator.snapshot()?;
    let bound = coordinator.bind_provider_execution(
        context,
        binding_submission("bind-d", &lane, "unit-d", "scope-d")?,
    )?;
    let post_binding = coordinator.snapshot()?;
    // Restore without the binding event: the attempt stays unresolved and
    // attribution fails closed; no binding is invented.
    let restored_pre = AgentCoordinator::restore_with_provider(
        pre_binding.clone(),
        config(4, 4),
        Box::new(verifier(&proofs, pre_binding.event_sequence)),
    )?;
    assert_eq!(
        restored_pre
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("restored attempt must exist"))
            .provider_binding,
        None
    );
    assert_eq!(
        restored_pre
            .binding_subject(&lane.attempt_id)?
            .attributable_binding()
            .err(),
        Some(ContractError::BindingMismatch)
    );
    // Restore with the binding event: the binding is preserved and
    // attributable, and the journal matches exactly.
    let restored_post = AgentCoordinator::restore_with_provider(
        post_binding.clone(),
        config(4, 4),
        Box::new(verifier(&proofs, post_binding.event_sequence)),
    )?;
    assert_eq!(
        restored_post
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("restored attempt must exist"))
            .provider_binding,
        Some(bound.clone())
    );
    assert_eq!(
        restored_post
            .binding_subject(&lane.attempt_id)?
            .attributable_binding()?,
        &bound
    );
    assert_eq!(restored_post.events(), coordinator.events());
    Ok(())
}

fn diverged_observation(
    lane: &AdmittedLaneReceipt,
    binding: &ProviderExecutionBinding,
    observed: &RouteFingerprint,
) -> TestResult<PhysicalRouteObservationReceipt> {
    use eliot_agent_api::route_divergence_fields;
    let diverged = route_divergence_fields(&lane.route, observed);
    assert!(!diverged.is_empty(), "diverged fixture must differ");
    let zero = zero_digest()?;
    let admitted_digest = stored_admission_digest(lane)?;
    let mut observation = PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: lane.attempt_id.clone(),
        state_fence: fence(),
        runtime_generation: ResourceGeneration::genesis(),
        admitted_route_digest: admitted_digest,
        binding: binding.clone(),
        requested_route: lane.route.clone(),
        observed_route: Some(observed.clone()),
        route_state: RouteObservationState::Diverged,
        diverged_fields: diverged,
        execution_outcome: ExecutionOutcome::Observed,
        request_digest: zero.clone(),
        translation_digest: None,
        raw_evidence_digest: None,
        raw_evidence_ref: None,
        usage: usage(),
        started: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: ClockReading {
            valid_time_ms: Some(2_000),
            known_time_ms: Some(2_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        event_cursor: EventCursor::new("cursor-diverged")?,
        event_sequence: 2,
        cancellation: None,
        unobserved_reason: None,
        recovery_ref: Some("diverged-quarantine".to_owned()),
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: zero,
    };
    observation.self_digest = observation.compute_digest()?;
    observation.validate()?;
    Ok(observation)
}

fn unobserved_observation(
    lane: &AdmittedLaneReceipt,
    binding: &ProviderExecutionBinding,
) -> TestResult<PhysicalRouteObservationReceipt> {
    let zero = zero_digest()?;
    let admitted_digest = stored_admission_digest(lane)?;
    let mut observation = PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: lane.attempt_id.clone(),
        state_fence: fence(),
        runtime_generation: ResourceGeneration::genesis(),
        admitted_route_digest: admitted_digest,
        binding: binding.clone(),
        requested_route: lane.route.clone(),
        observed_route: None,
        route_state: RouteObservationState::Unobserved,
        diverged_fields: Vec::new(),
        execution_outcome: ExecutionOutcome::UnknownOutcome,
        request_digest: zero.clone(),
        translation_digest: None,
        raw_evidence_digest: None,
        raw_evidence_ref: None,
        usage: usage(),
        started: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: ClockReading::default(),
        event_cursor: EventCursor::new("cursor-unobserved")?,
        event_sequence: 3,
        cancellation: None,
        unobserved_reason: Some("provider did not attest route".to_owned()),
        recovery_ref: Some("unobserved-recovery".to_owned()),
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: zero,
    };
    observation.self_digest = observation.compute_digest()?;
    observation.validate()?;
    Ok(observation)
}

#[test]
fn diverged_observation_is_retained_with_capped_ceiling() -> TestResult {
    let mut coordinator = coordinator(
        config(2, 2),
        &["proof-admission-diverged", "proof-result-diverged"],
    )?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "diverged",
        &[LaneSpec {
            work: "work-diverged",
            role: "reader-diverged",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let binding = observation_binding(&lane)?;
    let observed = route("b");
    let mut submission = result_submission("diverged", &lane, ResultDisposition::Partial)?;
    submission.provider_result_receipt_ref = "proof-result-diverged".to_owned();
    submission.result.actual_route = diverged_observation(&lane, &binding, &observed)?;
    let receipt = coordinator.submit_result(context, submission)?;
    assert_eq!(
        receipt.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    assert_eq!(
        receipt.actual_route.route_state,
        RouteObservationState::Diverged
    );
    assert_eq!(
        receipt.actual_route.observed_route.as_ref(),
        Some(&observed)
    );
    Ok(())
}

#[test]
fn unobserved_observation_is_retained_with_capped_ceiling() -> TestResult {
    let mut coordinator = coordinator(
        config(2, 2),
        &["proof-admission-unobserved", "proof-result-unobserved"],
    )?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "unobserved",
        &[LaneSpec {
            work: "work-unobserved",
            role: "reader-unobserved",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let binding = observation_binding(&lane)?;
    let mut submission = result_submission("unobserved", &lane, ResultDisposition::UnknownOutcome)?;
    submission.provider_result_receipt_ref = "proof-result-unobserved".to_owned();
    submission.result.actual_route = unobserved_observation(&lane, &binding)?;
    submission.result.unknown_reason = Some("provider outcome unresolved".to_owned());
    let receipt = coordinator.submit_result(context, submission)?;
    assert_eq!(
        receipt.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    assert_eq!(
        receipt.actual_route.route_state,
        RouteObservationState::Unobserved
    );
    assert_eq!(receipt.actual_route.observed_route, None);
    Ok(())
}

#[test]
fn mismatched_requested_route_rejects_as_invalid_candidate() -> TestResult {
    let mut coordinator = coordinator(
        config(2, 2),
        &["proof-admission-mismatch", "proof-result-mismatch"],
    )?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "mismatch",
        &[LaneSpec {
            work: "work-mismatch",
            role: "reader-mismatch",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let binding = observation_binding(&lane)?;
    // Requested differs from the admitted/assigned route: invalid candidate.
    // Build a matched observation for a different requested route (b) while
    // keeping the binding attempt so the failure is the requested mismatch.
    let mut forged_lane = lane.clone();
    forged_lane.route = route("b");
    let mut submission = result_submission("mismatch", &lane, ResultDisposition::Partial)?;
    submission.provider_result_receipt_ref = "proof-result-mismatch".to_owned();
    let mut observation = matched_observation(&forged_lane, &binding)?;
    observation.binding = binding.clone();
    observation.self_digest = observation.compute_digest()?;
    submission.result.actual_route = observation;
    assert_eq!(
        coordinator.submit_result(context, submission).err(),
        Some(CoordinatorError::RouteMismatch)
    );
    Ok(())
}

#[test]
fn forged_binding_rejects_at_intake() -> TestResult {
    let mut coordinator = coordinator(
        config(2, 2),
        &["proof-admission-forged", "proof-result-forged"],
    )?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "forged",
        &[LaneSpec {
            work: "work-forged",
            role: "reader-forged",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    // Forge the lease: the presented binding no longer agrees with the
    // admitted attempt on the exact typed lease, so intake fails closed.
    let mut binding = observation_binding(&lane)?;
    binding.lease_id = serde_json::from_value::<WorkLeaseId>(
        serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-forged"}),
    )?;
    let mut submission = result_submission("forged", &lane, ResultDisposition::Partial)?;
    submission.provider_result_receipt_ref = "proof-result-forged".to_owned();
    let mut observation = matched_observation(&lane, &observation_binding(&lane)?)?;
    observation.binding = binding;
    observation.self_digest = observation.compute_digest()?;
    submission.result.actual_route = observation;
    assert_eq!(
        coordinator.submit_result(context, submission).err(),
        Some(CoordinatorError::IdentityConflict("execution_binding"))
    );
    Ok(())
}

#[test]
fn invalid_candidate_selection_rejects_with_route_mismatch() -> TestResult {
    use eliot_agent_api::{
        CandidateSelectionDisposition, PolicyRevision, RejectedRouteCandidate,
        RouteSelectionCandidate,
    };
    let valid = route("a");
    let absent = route("b");
    let candidate = RouteSelectionCandidate {
        capability: "test-capability".to_owned(),
        query_intent: "test-intent".to_owned(),
        scope_ref: "scope:test".to_owned(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![valid],
        selected: Some(absent),
        rejected: Vec::<RejectedRouteCandidate>::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-1".to_owned()],
    };
    assert_eq!(candidate.validate(), Err(ContractError::RouteMismatch));
    Ok(())
}

#[test]
fn s5_stored_admission_closes_binding_and_forged_digest_rejects() -> TestResult {
    // S5 happy path + digest-linkage negative + snapshot preservation.
    // Stored admission comes from the external decision carried in the
    // admitted lane (never minted); intake closes via validate_for_binding
    // and a forged admitted_route_digest fails closed.
    let proofs = [
        "proof-admission-s5a",
        "proof-result-s5a-0",
        "proof-result-s5a-1-forged",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "s5a",
        &[
            LaneSpec {
                work: "work-s5a-0",
                role: "reader-s5a-0",
                route: "a",
                scope: None,
                write: false,
                priority: 2,
            },
            LaneSpec {
                work: "work-s5a-1",
                role: "reader-s5a-1",
                route: "b",
                scope: None,
                write: false,
                priority: 1,
            },
        ],
        None,
    )?;
    // Stored admission is present and equals the presented lane decision.
    for lane in &admitted.admitted_lanes {
        let stored = coordinator
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("admitted attempt must exist"))
            .admitted_route
            .clone();
        assert_eq!(stored, lane.admitted_route);
        assert!(stored.is_some());
    }
    let context = ExecutionContext::from(&admitted);
    let first = admitted.admitted_lanes[0].clone();
    let second = admitted.admitted_lanes[1].clone();
    coordinator.start_attempt(context.clone(), first.attempt_id.clone())?;
    coordinator.start_attempt(context.clone(), second.attempt_id.clone())?;
    // Snapshot round-trip preserves the stored decision; restore-then-submit
    // still closes.
    let snapshot = coordinator.snapshot()?;
    let mut restored = AgentCoordinator::restore_with_provider(
        snapshot.clone(),
        config(4, 4),
        Box::new(verifier(&proofs, snapshot.event_sequence)),
    )?;
    assert_eq!(
        restored
            .attempt(&first.attempt_id)
            .unwrap_or_else(|| panic!("restored attempt must exist"))
            .admitted_route,
        first.admitted_route
    );
    let happy = result_submission("s5a-0", &first, ResultDisposition::Partial)?;
    let receipt = restored.submit_result(context.clone(), happy)?;
    assert_eq!(
        receipt.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    // Forged digest: same attempt/binding/route but a zero digest instead of
    // the stored self_digest. Shape still validates (recomputed self_digest)
    // so only the admission linkage can fail.
    let mut forged = result_submission("s5a-1-forged", &second, ResultDisposition::Partial)?;
    forged.result.actual_route.admitted_route_digest = zero_digest()?;
    forged.result.actual_route.self_digest = forged.result.actual_route.compute_digest()?;
    assert_eq!(
        coordinator.submit_result(context, forged).err(),
        Some(CoordinatorError::IdentityConflict("execution_binding"))
    );
    Ok(())
}

#[test]
fn s5_foreign_turn_binding_admission_triple_mismatch_rejects() -> TestResult {
    // Foreign execution unit and foreign admission digest both fail closed,
    // preserving DIVERGED/UNOBSERVED handling (those stay retained, not
    // rejected as mismatch).
    let proofs = [
        "proof-admission-s5b",
        "proof-result-s5b-foreign-bind",
        "proof-result-s5b-foreign-digest",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "s5b",
        &[
            LaneSpec {
                work: "work-s5b-0",
                role: "reader-s5b-0",
                route: "a",
                scope: None,
                write: false,
                priority: 2,
            },
            LaneSpec {
                work: "work-s5b-1",
                role: "reader-s5b-1",
                route: "b",
                scope: None,
                write: false,
                priority: 1,
            },
        ],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane_a = admitted.admitted_lanes[0].clone();
    let lane_b = admitted.admitted_lanes[1].clone();
    coordinator.start_attempt(context.clone(), lane_a.attempt_id.clone())?;
    coordinator.start_attempt(context.clone(), lane_b.attempt_id.clone())?;
    // Foreign turn: result names attempt A but the embedded binding is B's
    // unit (different attempt/lease). Intake fails closed.
    let binding_b = observation_binding(&lane_b)?;
    let mut foreign_bind =
        result_submission("s5b-foreign-bind", &lane_a, ResultDisposition::Partial)?;
    foreign_bind.result.actual_route.binding = binding_b;
    foreign_bind.result.actual_route.self_digest =
        foreign_bind.result.actual_route.compute_digest()?;
    assert_eq!(
        coordinator
            .submit_result(context.clone(), foreign_bind)
            .err(),
        Some(CoordinatorError::IdentityConflict("execution_binding"))
    );
    // Foreign admission: binding is A's but the digest points at B's
    // decision. Linkage against stored A fails closed.
    let foreign_digest = lane_b
        .admitted_route
        .as_ref()
        .unwrap_or_else(|| panic!("lane must carry stored admission"))
        .self_digest
        .clone();
    let mut foreign_digest_sub =
        result_submission("s5b-foreign-digest", &lane_a, ResultDisposition::Partial)?;
    foreign_digest_sub.result.actual_route.admitted_route_digest = foreign_digest;
    foreign_digest_sub.result.actual_route.self_digest =
        foreign_digest_sub.result.actual_route.compute_digest()?;
    assert_eq!(
        coordinator.submit_result(context, foreign_digest_sub).err(),
        Some(CoordinatorError::IdentityConflict("execution_binding"))
    );
    Ok(())
}

#[test]
fn s5_per_effect_attempt_mismatch_rejects() -> TestResult {
    // Reachable via submit_result: the effect itself satisfies the ceiling
    // so only the S5 per-effect attempt linkage can fail.
    let mut coordinator = coordinator(config(2, 2), &["proof-admission-s5c", "proof-result-s5c"])?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "s5c",
        &[LaneSpec {
            work: "work-s5c",
            role: "reader-s5c",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let mut submission = result_submission("s5c", &lane, ResultDisposition::Partial)?;
    let foreign_effect = ProposedEffect {
        effect_id: "effect-s5c-1".to_owned(),
        attempt_id: AttemptId::new("attempt-s5c-foreign")?,
        kind: EffectKind::Observe,
        scope_ref: "scope-work-s5c".to_owned(),
        payload_digest: serde_json::from_value(serde_json::json!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ))?,
        rationale_ref: None,
    };
    submission.result.proposed_effects = vec![foreign_effect];
    assert_eq!(
        coordinator.submit_result(context, submission).err(),
        Some(CoordinatorError::IdentityConflict("execution_binding"))
    );
    Ok(())
}

#[test]
fn s5_missing_stored_admission_and_reassigned_stays_unresolved() -> TestResult {
    // Legacy `None` (pre-S5 wire) and reassigned attempts (new identity
    // awaiting a new external decision) both fail closed at intake with the
    // admission owner named, never silently upgraded.
    let mut legacy = coordinator(config(2, 2), &["proof-admission-s5d", "proof-result-s5d"])?;
    let candidate = legacy.plan(request(
        "s5d",
        &[LaneSpec {
            work: "work-s5d",
            role: "reader-s5d",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?)?;
    let mut receipt = provider_receipt(&candidate, "s5d")?;
    receipt.admitted_lanes[0].admitted_route = None;
    let admitted = legacy.admit(receipt)?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    assert_eq!(
        legacy
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("legacy attempt must exist"))
            .admitted_route,
        None
    );
    legacy.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let submission = result_submission("s5d", &lane, ResultDisposition::Partial)?;
    assert_eq!(
        legacy.submit_result(context, submission).err(),
        Some(CoordinatorError::IdentityConflict("admitted_route"))
    );

    // Reassigned attempt: new identity starts unresolved.
    let proofs = [
        "proof-admission-s5e",
        "proof-fence-s5e",
        "proof-reassign-s5e",
        "proof-result-s5e-new",
    ];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "s5e",
        &[LaneSpec {
            work: "work-s5e",
            role: "reader-s5e",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    coordinator.mark_worker_lost(
        context.clone(),
        worker_fence(&lane, "s5e", "proof-fence-s5e")?,
    )?;
    let new_attempt = AttemptId::new("attempt-s5e-new")?;
    let new_lease = serde_json::from_value::<WorkLeaseId>(
        serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-s5e-new"}),
    )?;
    let new_worker = WorkerId::new("worker-s5e-new")?;
    coordinator.reassign(
        context.clone(),
        ProviderReassignmentReceipt {
            reassignment_id: ReassignmentId::new("reassign-s5e")?,
            provider_identity: provider_identity(),
            g11_receipt_ref: "proof-reassign-s5e".to_owned(),
            old_attempt_id: lane.attempt_id.clone(),
            old_lease_id: lane.lease_id.clone(),
            new_attempt_id: new_attempt.clone(),
            new_lease_id: new_lease.clone(),
            new_worker_id: new_worker.clone(),
            route: lane.route.clone(),
            budget: budget(),
        },
    )?;
    let reassigned = coordinator
        .attempt(&new_attempt)
        .unwrap_or_else(|| panic!("reassigned attempt must exist"))
        .clone();
    assert_eq!(reassigned.admitted_route, None);
    coordinator.start_attempt(context.clone(), new_attempt.clone())?;
    // Build a submission naming the new identity; the embedded binding and
    // digest are well-formed for the new identity but no stored decision
    // exists, so intake names the admission owner.
    let fake_lane = AdmittedLaneReceipt {
        work_unit_id: reassigned.work_unit_id.clone(),
        role_id: reassigned.role_id.clone(),
        role_revision: reassigned.role_revision.clone(),
        attempt_id: new_attempt.clone(),
        lease_id: new_lease.clone(),
        worker_id: new_worker.clone(),
        work_class: reassigned.work_class.clone(),
        route: reassigned.route.clone(),
        routing_receipt_digest: lane.routing_receipt_digest.clone(),
        budget: reassigned.budget.clone(),
        priority: reassigned.priority,
        mutation_scope: reassigned.mutation_scope.clone(),
        admitted_route: None,
    };
    let mut submission = result_submission("s5e-new", &fake_lane, ResultDisposition::Partial)?;
    submission.provider_result_receipt_ref = "proof-result-s5e-new".to_owned();
    assert_eq!(
        coordinator.submit_result(context, submission).err(),
        Some(CoordinatorError::IdentityConflict("admitted_route"))
    );
    Ok(())
}

#[test]
fn s5_forged_lane_admission_rejects_at_admit() -> TestResult {
    // Forged decisions are rejected at admission, never stored: wrong
    // attempt/route/digest/policy and no-route denials all fail closed, and
    // a tampered self_digest fails as a provider contract (shape) error.
    let mut coord = coordinator(config(4, 4), &["proof-admission-s5f"])?;
    let candidate = coord.plan(request(
        "s5f",
        &[LaneSpec {
            work: "work-s5f",
            role: "reader-s5f",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?)?;
    let good = provider_receipt(&candidate, "s5f")?;
    // Sanity: the good receipt admits.
    let mut sanity = crate::core::AgentCoordinator::with_provider(
        config(4, 4),
        Box::new(verifier(&["proof-admission-s5f"], 0)),
    )?;
    let sanity_candidate = sanity.plan(request(
        "s5f-sanity",
        &[LaneSpec {
            work: "work-s5f",
            role: "reader-s5f",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?)?;
    sanity.admit(provider_receipt(&sanity_candidate, "s5f")?)?;

    // Wrong attempt identity (recomputed digest isolates the linkage failure).
    let mut wrong_attempt = good.clone();
    {
        let lane = &mut wrong_attempt.admitted_lanes[0];
        let admission = lane
            .admitted_route
            .as_mut()
            .unwrap_or_else(|| panic!("lane must carry admission"));
        admission.attempt_id = AttemptId::new("attempt-s5f-foreign")?;
        admission.self_digest = admission.compute_digest()?;
    }
    assert_eq!(
        coord.admit(wrong_attempt).err(),
        Some(CoordinatorError::IdentityConflict("admitted_route"))
    );

    // Wrong route (requested/selected no longer match the lane).
    let mut wrong_route = good.clone();
    {
        let lane = &mut wrong_route.admitted_lanes[0];
        let admission = lane
            .admitted_route
            .as_mut()
            .unwrap_or_else(|| panic!("lane must carry admission"));
        admission.requested_route = route("b");
        admission.selected_route = Some(route("b"));
        admission.self_digest = admission.compute_digest()?;
    }
    assert_eq!(
        coord.admit(wrong_route).err(),
        Some(CoordinatorError::IdentityConflict("admitted_route"))
    );

    // Wrong candidate digest (exact bytes no longer bound).
    let mut wrong_digest = good.clone();
    {
        let lane = &mut wrong_digest.admitted_lanes[0];
        let admission = lane
            .admitted_route
            .as_mut()
            .unwrap_or_else(|| panic!("lane must carry admission"));
        admission.candidate_digest = zero_digest()?;
        admission.self_digest = admission.compute_digest()?;
    }
    assert_eq!(
        coord.admit(wrong_digest).err(),
        Some(CoordinatorError::IdentityConflict("admitted_route"))
    );

    // No-route denial cannot back an attempt (selected absent).
    let mut no_route = good.clone();
    {
        let lane = &mut no_route.admitted_lanes[0];
        let admission = lane
            .admitted_route
            .as_mut()
            .unwrap_or_else(|| panic!("lane must carry admission"));
        admission.selected_route = None;
        admission.no_route = Some(eliot_agent_api::NoRouteDisposition::AdmissionDenied);
        admission.self_digest = admission.compute_digest()?;
    }
    assert_eq!(
        coord.admit(no_route).err(),
        Some(CoordinatorError::IdentityConflict("admitted_route"))
    );

    // Tampered self_digest without recompute fails as a shape/contract error.
    let mut bad_digest = good.clone();
    {
        let lane = &mut bad_digest.admitted_lanes[0];
        let admission = lane
            .admitted_route
            .as_mut()
            .unwrap_or_else(|| panic!("lane must carry admission"));
        admission.self_digest = zero_digest()?;
    }
    assert!(matches!(
        coord.admit(bad_digest).err(),
        Some(CoordinatorError::ProviderContract(_))
    ));
    Ok(())
}

fn host_event_envelope(
    lane: &AdmittedLaneReceipt,
    binding: &ProviderExecutionBinding,
    sequence: u64,
    cursor_tag: &str,
    event_tag: &str,
) -> TestResult<NormalizedHostEventEnvelope> {
    let cursor = EventCursor::new(format!("cursor-{cursor_tag}"))?;
    let raw_bytes = format!("host-event-source-{event_tag}").into_bytes();
    let raw = RawSourceRecord {
        handle: RestrictedRawSourceHandle::new(format!("restricted-test:{event_tag}"))?,
        digest: QualifiedSourceDigest {
            algorithm: HOST_EVENT_DIGEST_ALGORITHM.to_owned(),
            digest: serde_json::from_value(serde_json::json!(sha256_hex(&raw_bytes)))?,
        },
    };
    let stored = lane
        .admitted_route
        .as_ref()
        .ok_or("lane must carry the stored admission")?;
    let mut envelope = NormalizedHostEventEnvelope {
        schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        event_id: EventId::new(format!("evt-{event_tag}"))?,
        cursor: cursor.clone(),
        lineage: ProviderObservationLineage::ExecutionUnitObservation(Box::new(
            ExecutionUnitObservation {
                binding: binding.clone(),
                cursor,
                sequence,
            },
        )),
        producer_adapter_identity: "test-adapter".into(),
        adapter_contract_version: "test-adapter/v1".into(),
        sequence,
        causal_predecessors: Vec::new(),
        payload: NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
            delta_chars: 4,
            truncated: false,
        }),
        admitted_route_digest: Some(stored.self_digest.clone()),
        raw_source: raw.clone(),
        normalization: HostEventNormalizationReceipt {
            normalizer_identity: "test-adapter".into(),
            normalizer_version: "test-adapter/v1".into(),
            input_handle: raw.handle.clone(),
            input_digest: raw.digest.clone(),
            output_schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
            output_digest: zero_digest()?,
            omitted_fields: Vec::new(),
            warnings: Vec::new(),
            unsupported_disposition: UnsupportedDisposition::None,
            privacy_class: HostEventPrivacyClass::RedactedSummary,
            coverage: NormalizationCoverage::Complete,
            proof_ceiling: eliot_receipts::ProofCeiling::Observation,
        },
        observed_at: ClockReading {
            valid_time_ms: Some(1_700_000_000_000),
            known_time_ms: Some(1_700_000_000_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        delivery: HostEventDeliveryDisposition::DurableOrdered,
    };
    envelope
        .seal()
        .map_err(|error| format!("envelope must seal: {error}"))?;
    Ok(envelope)
}

fn bound_observe_setup() -> TestResult<(
    AgentCoordinator,
    ExecutionContext,
    AdmittedLaneReceipt,
    ProviderExecutionBinding,
)> {
    let proofs = ["proof-admission-observe", "proof-bind-observe"];
    let mut coordinator = coordinator(config(4, 4), &proofs)?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "observe",
        &[bind_lane_spec("work-observe", "reader-observe", "a")],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let stored = coordinator.bind_provider_execution(
        context.clone(),
        binding_submission("observe", &lane, "unit-observe", "scope-observe")?,
    )?;
    Ok((coordinator, context, lane, stored))
}

#[test]
fn observe_accepts_exact_binding_and_replays_without_duplicate_effects() -> TestResult {
    let (mut coordinator, context, lane, stored) = bound_observe_setup()?;
    let envelope = host_event_envelope(&lane, &stored, 1, "observe-1", "observe-1")?;
    let receipt = envelope.normalization.clone();
    let events_before = coordinator.events().len();
    coordinator.observe_provider_event(context.clone(), envelope.clone(), receipt.clone())?;
    assert_eq!(coordinator.events().len(), events_before + 1);
    // Exact replay is idempotent: no new event, no duplicate effects.
    coordinator.observe_provider_event(context.clone(), envelope.clone(), receipt.clone())?;
    assert_eq!(coordinator.events().len(), events_before + 1);
    // Conflicting same-identity replay is quarantined with its typed reason
    // (issue #371 S7): a changed payload is `ConflictingPayload`, never a
    // generic conflict, and nothing is mutated.
    let mut conflict = envelope.clone();
    conflict.payload = NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
        delta_chars: 5,
        truncated: false,
    });
    conflict
        .seal()
        .map_err(|error| format!("conflict must seal: {error}"))?;
    let conflict_receipt = conflict.normalization.clone();
    assert_eq!(
        coordinator.observe_provider_event(context, conflict, conflict_receipt),
        Err(CoordinatorError::HostEventQuarantine(
            HostEventQuarantineReason::ConflictingPayload
        ))
    );
    assert_eq!(coordinator.events().len(), events_before + 1);
    Ok(())
}

#[test]
fn observe_rejects_foreign_turn_and_unknown_attempt_before_mutation() -> TestResult {
    let (mut coordinator, context, lane, _stored) = bound_observe_setup()?;
    let events_before = coordinator.events().len();
    // Same thread, different provider turn: the foreign unit cannot enter the
    // recorded attempt even though the attempt identity matches.
    let foreign = binding_submission("observe-f", &lane, "unit-foreign", "scope-observe")?.binding;
    let foreign_event = host_event_envelope(&lane, &foreign, 1, "observe-f-1", "observe-f-1")?;
    let foreign_receipt = foreign_event.normalization.clone();
    assert_eq!(
        coordinator.observe_provider_event(context.clone(), foreign_event, foreign_receipt),
        Err(CoordinatorError::IdentityConflict("execution_binding"))
    );
    assert_eq!(coordinator.events().len(), events_before);
    // A caller-selected identity for an unknown attempt resolves to nothing.
    let mut ghost = host_event_envelope(
        &lane,
        &binding_submission("observe", &lane, "unit-observe", "scope-observe")?.binding,
        1,
        "observe-g-1",
        "observe-g-1",
    )?;
    if let ProviderObservationLineage::ExecutionUnitObservation(observation) = &mut ghost.lineage {
        observation.binding.attempt_id = AttemptId::new("attempt-ghost")?;
    } else {
        panic!("envelope must carry execution-unit lineage");
    }
    ghost
        .seal()
        .map_err(|error| format!("ghost must seal: {error}"))?;
    let ghost_receipt = ghost.normalization.clone();
    assert_eq!(
        coordinator.observe_provider_event(context, ghost, ghost_receipt),
        Err(CoordinatorError::UnknownAttempt)
    );
    assert_eq!(coordinator.events().len(), events_before);
    Ok(())
}

/// Builds a session-only observation envelope through the real S6 api
/// constructors plus `seal()` (adapter-style normalized envelope+receipt, no
/// mock adapter). Session lineage carries no admission reference and the
/// session stays `None`: no session is invented here (T1/T5 own admission).
fn session_event_envelope(
    tag: &str,
    event_tag: &str,
    payload: NormalizedHostEventPayload,
) -> TestResult<NormalizedHostEventEnvelope> {
    let cursor = EventCursor::new(format!("cursor-session-{tag}"))?;
    let raw_bytes = format!("host-event-session-source-{event_tag}").into_bytes();
    let raw = RawSourceRecord {
        handle: RestrictedRawSourceHandle::new(format!("restricted-session-test:{event_tag}"))?,
        digest: QualifiedSourceDigest {
            algorithm: HOST_EVENT_DIGEST_ALGORITHM.to_owned(),
            digest: serde_json::from_value(serde_json::json!(sha256_hex(&raw_bytes)))?,
        },
    };
    let mut envelope = NormalizedHostEventEnvelope {
        schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        event_id: EventId::new(format!("evt-session-{event_tag}"))?,
        cursor: cursor.clone(),
        lineage: ProviderObservationLineage::SessionObservation(SessionObservation {
            session_id: None,
            native: NativeSession::Native(NativeSessionLocator::new(format!("thread-{tag}"))?),
        }),
        producer_adapter_identity: "test-adapter".into(),
        adapter_contract_version: "test-adapter/v1".into(),
        sequence: 1,
        causal_predecessors: Vec::new(),
        payload,
        admitted_route_digest: None,
        raw_source: raw.clone(),
        normalization: HostEventNormalizationReceipt {
            normalizer_identity: "test-adapter".into(),
            normalizer_version: "test-adapter/v1".into(),
            input_handle: raw.handle.clone(),
            input_digest: raw.digest.clone(),
            output_schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
            output_digest: zero_digest()?,
            omitted_fields: Vec::new(),
            warnings: Vec::new(),
            unsupported_disposition: UnsupportedDisposition::None,
            privacy_class: HostEventPrivacyClass::RedactedSummary,
            coverage: NormalizationCoverage::Complete,
            proof_ceiling: eliot_receipts::ProofCeiling::Observation,
        },
        observed_at: ClockReading {
            valid_time_ms: Some(1_700_000_000_000),
            known_time_ms: Some(1_700_000_000_001),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        delivery: HostEventDeliveryDisposition::DurableOrdered,
    };
    envelope
        .seal()
        .map_err(|error| format!("session envelope must seal: {error}"))?;
    Ok(envelope)
}

#[test]
fn observe_changed_duplicate_quarantines_with_typed_reason_per_dimension() -> TestResult {
    let (mut coordinator, context, lane, stored) = bound_observe_setup()?;
    let envelope = host_event_envelope(&lane, &stored, 1, "typed-1", "typed-1")?;
    let receipt = envelope.normalization.clone();
    let events_before = coordinator.events().len();
    coordinator.observe_provider_event(context.clone(), envelope.clone(), receipt.clone())?;

    // Same-turn steer of the lineage binding under the same event identity is
    // a cross-turn replay: quarantined as lineage, never advancing any
    // attempt.
    let cross_turn_binding =
        binding_submission("typed-x", &lane, "unit-typed-x", "scope-observe")?.binding;
    let mut lineage = envelope.clone();
    if let ProviderObservationLineage::ExecutionUnitObservation(observation) = &mut lineage.lineage
    {
        observation.binding = cross_turn_binding;
    } else {
        panic!("envelope must carry execution-unit lineage");
    }
    lineage
        .seal()
        .map_err(|error| format!("lineage conflict must seal: {error}"))?;
    let lineage_receipt = lineage.normalization.clone();
    assert_eq!(
        coordinator.observe_provider_event(context.clone(), lineage, lineage_receipt),
        Err(CoordinatorError::HostEventQuarantine(
            HostEventQuarantineReason::ConflictingLineage
        ))
    );

    // Same identity with different restricted source bytes quarantines as
    // source (first differing dimension wins over the rebound receipt).
    let mut source = envelope.clone();
    let alt_bytes = b"host-event-source-typed-1-alt".to_vec();
    let alt_digest: LowercaseSha256 =
        serde_json::from_value(serde_json::json!(sha256_hex(&alt_bytes)))?;
    source.raw_source.handle = RestrictedRawSourceHandle::new("restricted-test:typed-1-alt")?;
    source.raw_source.digest = QualifiedSourceDigest {
        algorithm: HOST_EVENT_DIGEST_ALGORITHM.to_owned(),
        digest: alt_digest,
    };
    source.normalization.input_handle = source.raw_source.handle.clone();
    source.normalization.input_digest = source.raw_source.digest.clone();
    source
        .seal()
        .map_err(|error| format!("source conflict must seal: {error}"))?;
    let source_receipt = source.normalization.clone();
    assert_eq!(
        coordinator.observe_provider_event(context.clone(), source, source_receipt),
        Err(CoordinatorError::HostEventQuarantine(
            HostEventQuarantineReason::ConflictingSource
        ))
    );

    // Same identity and source bytes with a changed normalization manifest
    // quarantines as normalization.
    let mut normalization = envelope.clone();
    normalization
        .normalization
        .warnings
        .push("test-warning".to_owned());
    normalization
        .seal()
        .map_err(|error| format!("normalization conflict must seal: {error}"))?;
    let normalization_receipt = normalization.normalization.clone();
    assert_eq!(
        coordinator.observe_provider_event(context.clone(), normalization, normalization_receipt),
        Err(CoordinatorError::HostEventQuarantine(
            HostEventQuarantineReason::ConflictingNormalization
        ))
    );

    // A sealed framing-only change (delivery) is bound by the receipt output
    // digest, so it surfaces as a normalization conflict rather than
    // silently; the S6 `ConflictingFraming` bucket remains the defensive
    // fallback for valid-framing duplicates whose compared dimensions all
    // match, and it passes through unchanged.
    let mut framing = envelope.clone();
    framing.delivery = HostEventDeliveryDisposition::Replay;
    framing
        .seal()
        .map_err(|error| format!("framing conflict must seal: {error}"))?;
    let framing_receipt = framing.normalization.clone();
    assert_eq!(
        coordinator.observe_provider_event(context.clone(), framing, framing_receipt),
        Err(CoordinatorError::HostEventQuarantine(
            HostEventQuarantineReason::ConflictingNormalization
        ))
    );

    // No quarantine path mutated durable state: exactly the one observation.
    assert_eq!(coordinator.events().len(), events_before + 1);
    Ok(())
}

#[test]
fn observe_gap_reorder_and_stale_sequence_are_explicit() -> TestResult {
    let (mut coordinator, context, lane, stored) = bound_observe_setup()?;
    let events_before = coordinator.events().len();
    let first = host_event_envelope(&lane, &stored, 1, "seq-1", "seq-1")?;
    coordinator.observe_provider_event(
        context.clone(),
        first.clone(),
        first.normalization.clone(),
    )?;
    // Forward jump records an explicit gap marker before the observation; the
    // marker itself advances no cursor (ordering evidence only).
    let third = host_event_envelope(&lane, &stored, 3, "seq-3", "seq-3")?;
    coordinator.observe_provider_event(
        context.clone(),
        third.clone(),
        third.normalization.clone(),
    )?;
    assert_eq!(coordinator.events().len(), events_before + 3);
    match &coordinator.events()[events_before + 1] {
        CoordinatorEvent::ProviderHostEventGap {
            expected_sequence,
            observed_sequence,
            ..
        } => {
            assert_eq!((*expected_sequence, *observed_sequence), (2, 3));
        }
        other => panic!("expected an explicit gap marker, got {other:?}"),
    }
    // Exact replay of the post-gap event stays idempotent.
    coordinator.observe_provider_event(
        context.clone(),
        third.clone(),
        third.normalization.clone(),
    )?;
    assert_eq!(coordinator.events().len(), events_before + 3);
    // Reordered arrival under a new identity with a nonmonotonic sequence
    // stays stale without mutation.
    let second = host_event_envelope(&lane, &stored, 2, "seq-2", "seq-2")?;
    assert_eq!(
        coordinator.observe_provider_event(
            context.clone(),
            second.clone(),
            second.normalization.clone()
        ),
        Err(CoordinatorError::StaleResult)
    );
    assert_eq!(coordinator.events().len(), events_before + 3);
    // The next in-order event advances with no new gap.
    let fourth = host_event_envelope(&lane, &stored, 4, "seq-4", "seq-4")?;
    coordinator.observe_provider_event(
        context.clone(),
        fourth.clone(),
        fourth.normalization.clone(),
    )?;
    assert_eq!(coordinator.events().len(), events_before + 4);
    match &coordinator.events()[events_before + 3] {
        CoordinatorEvent::ProviderHostEventObserved { .. } => {}
        other => panic!("expected a direct observation without a gap, got {other:?}"),
    }
    Ok(())
}

#[test]
fn observe_session_only_mutates_nothing_and_terminal_never_reaches_intake() -> TestResult {
    let (mut coordinator, context, lane, stored) = bound_observe_setup()?;
    let events_before = coordinator.events().len();
    let binding_before = coordinator
        .attempt(&lane.attempt_id)
        .unwrap_or_else(|| panic!("bound attempt must exist"))
        .provider_binding
        .clone();
    // A valid session-only observation is accepted but mutates no attempt
    // state: no sequencing entry, no cursor advance, no result.
    let session = session_event_envelope(
        "session-1",
        "session-1",
        NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
            transition: SessionLifecycleTransition::Started,
            detail_ref: None,
        }),
    )?;
    coordinator.observe_provider_event(
        context.clone(),
        session.clone(),
        session.normalization.clone(),
    )?;
    assert_eq!(coordinator.events().len(), events_before + 1);
    assert_eq!(
        coordinator
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("bound attempt must exist"))
            .provider_binding,
        binding_before
    );
    // Exact session replay is idempotent.
    coordinator.observe_provider_event(
        context.clone(),
        session.clone(),
        session.normalization.clone(),
    )?;
    assert_eq!(coordinator.events().len(), events_before + 1);
    // Attempt sequencing is untouched: the next execution-unit event continues
    // the attempt stream with no gap.
    let next = host_event_envelope(&lane, &stored, 1, "sess-next-1", "sess-next-1")?;
    coordinator.observe_provider_event(
        context.clone(),
        next.clone(),
        next.normalization.clone(),
    )?;
    assert_eq!(coordinator.events().len(), events_before + 2);
    match &coordinator.events()[events_before + 1] {
        CoordinatorEvent::ProviderHostEventObserved { .. } => {}
        other => panic!("session observation must not emit a gap, got {other:?}"),
    }
    // Session-terminal smuggling: an attempt-usage payload on session lineage
    // cannot validate as a session observation.
    let terminal = session_event_envelope(
        "session-t",
        "session-t",
        NormalizedHostEventPayload::Usage(usage()),
    )?;
    assert_eq!(
        coordinator.observe_provider_event(
            context.clone(),
            terminal.clone(),
            terminal.normalization.clone()
        ),
        Err(CoordinatorError::IdentityConflict("execution_binding"))
    );
    // Session-lifecycle payload on execution-unit lineage is rejected before
    // any mutation.
    let mut misplaced = host_event_envelope(&lane, &stored, 9, "sess-mis-9", "sess-mis-9")?;
    misplaced.payload = NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
        transition: SessionLifecycleTransition::Closed,
        detail_ref: None,
    });
    misplaced
        .seal()
        .map_err(|error| format!("misplaced session payload must seal: {error}"))?;
    assert_eq!(
        coordinator.observe_provider_event(
            context.clone(),
            misplaced.clone(),
            misplaced.normalization.clone()
        ),
        Err(CoordinatorError::IdentityConflict("execution_binding"))
    );
    assert_eq!(coordinator.events().len(), events_before + 2);
    Ok(())
}

#[test]
fn observe_e2e_lost_ack_reconstruct_replay_once_without_duplicate_effects() -> TestResult {
    // Owner-path end to end on real api constructors (no mock adapter):
    // ingest a normalized envelope+receipt, lose the acknowledgement,
    // reconstruct via restore, replay once. Until a real durable
    // Store/Governor edge exists this asserts on the in-memory event-log plus
    // snapshot only; the installed durable commit remains controller track
    // and no `Store` commit is invented here.
    let cfg = config(4, 4);
    let mut coordinator = production_coordinator(cfg.clone())?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "e2e-observe",
        &[bind_lane_spec(
            "work-e2e-observe",
            "reader-e2e-observe",
            "a",
        )],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let stored = coordinator.bind_provider_execution(
        context.clone(),
        binding_submission(
            "e2e-observe",
            &lane,
            "unit-e2e-observe",
            "scope-e2e-observe",
        )?,
    )?;
    // No session is invented at binding time: the projected session stays
    // `None` until T1/T5 supply session admission.
    assert!(stored.session_id.is_none());

    // Durable baseline before the event exists.
    let pre_snapshot = coordinator.snapshot()?;
    let event_count_before = coordinator.events().len();

    // Ingest one real adapter-style normalized envelope+receipt. The
    // acknowledgement is then lost (in-memory state dropped before any
    // further durable commit): reconstruct from the pre-ingest snapshot,
    // which cannot contain the event.
    let envelope = host_event_envelope(&lane, &stored, 1, "e2e-1", "e2e-1")?;
    let receipt = envelope.normalization.clone();
    coordinator.observe_provider_event(context.clone(), envelope.clone(), receipt.clone())?;
    assert_eq!(coordinator.events().len(), event_count_before + 1);
    drop(coordinator);
    let mut coordinator = AgentCoordinator::restore_with_admitted_provider(
        pre_snapshot.clone(),
        cfg.clone(),
        admitted_capability(pre_snapshot.event_sequence)?,
    )?;
    assert_eq!(coordinator.events().len(), event_count_before);
    // Replay once: accepted exactly once, never duplicated.
    coordinator.observe_provider_event(context.clone(), envelope.clone(), receipt.clone())?;
    assert_eq!(coordinator.events().len(), event_count_before + 1);

    // Redelivery after durability is idempotent: snapshot, restore, replay,
    // and prove no duplicate usage/result mutation (event count, event log,
    // and snapshot digest all unchanged).
    let durable = coordinator.snapshot()?;
    let mut restored = AgentCoordinator::restore_with_admitted_provider(
        durable.clone(),
        cfg.clone(),
        admitted_capability(durable.event_sequence)?,
    )?;
    assert_eq!(restored.events(), coordinator.events());
    restored.observe_provider_event(context.clone(), envelope.clone(), receipt.clone())?;
    assert_eq!(restored.events(), coordinator.events());
    assert_eq!(restored.snapshot()?, durable);

    // A session-terminal input on the restored state still cannot reach
    // result intake.
    let terminal = session_event_envelope(
        "e2e-session-t",
        "e2e-session-t",
        NormalizedHostEventPayload::Usage(usage()),
    )?;
    assert_eq!(
        restored.observe_provider_event(
            context.clone(),
            terminal.clone(),
            terminal.normalization.clone()
        ),
        Err(CoordinatorError::IdentityConflict("execution_binding"))
    );
    assert_eq!(restored.events(), coordinator.events());

    // A foreign turn never reaches result intake: the binding gate rejects it
    // even though the attempt identity matches.
    let foreign_binding = binding_submission(
        "e2e-foreign",
        &lane,
        "unit-e2e-foreign",
        "scope-e2e-observe",
    )?
    .binding;
    let mut foreign = result_submission("e2e-foreign", &lane, ResultDisposition::Partial)?;
    foreign.result.actual_route = matched_observation(&lane, &foreign_binding)?;
    assert_eq!(
        restored.submit_result(context.clone(), foreign).err(),
        Some(CoordinatorError::IdentityConflict("execution_binding"))
    );

    // The replays synthesized no usage/result: exact intake still closes
    // exactly once, and a second intake is a duplicate.
    let mut submission = result_submission("e2e-observe", &lane, ResultDisposition::Partial)?;
    submission.result.actual_route = matched_observation(&lane, &stored)?;
    let intake = restored.submit_result(context.clone(), submission)?;
    assert_eq!(
        intake.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    let mut again = result_submission("e2e-observe-again", &lane, ResultDisposition::Partial)?;
    again.result.actual_route = matched_observation(&lane, &stored)?;
    assert_eq!(
        restored.submit_result(context, again).err(),
        Some(CoordinatorError::DuplicateResult)
    );
    Ok(())
}

#[test]
fn production_verifier_admits_binds_and_accepts_result() -> TestResult {
    let mut coordinator = production_coordinator(config(4, 4))?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "prod-abr",
        &[bind_lane_spec("work-prod-abr", "reader-prod-abr", "a")],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let binding = coordinator.bind_provider_execution(
        context.clone(),
        binding_submission("prod-abr", &lane, "unit-prod-abr", "scope-prod-abr")?,
    )?;
    assert_eq!(
        coordinator
            .attempt(&lane.attempt_id)
            .unwrap_or_else(|| panic!("bound attempt must exist"))
            .provider_binding,
        Some(binding.clone())
    );
    // The result closes on the exact stored binding, never a second unit.
    let mut submission = result_submission("prod-abr", &lane, ResultDisposition::Partial)?;
    submission.result.actual_route = matched_observation(&lane, &binding)?;
    let receipt = coordinator.submit_result(context, submission)?;
    assert_eq!(
        receipt.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    Ok(())
}

#[test]
fn production_verifier_reconciles_cancellation() -> TestResult {
    let mut coordinator = production_coordinator(config(2, 2))?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "prod-cancel",
        &[bind_lane_spec(
            "work-prod-cancel",
            "reader-prod-cancel",
            "a",
        )],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let operation_id = OperationId::new("operation-prod-cancel")?;
    coordinator.request_cancellation(
        context.clone(),
        CancelCommand {
            operation_id: operation_id.clone(),
            attempt_id: lane.attempt_id.clone(),
            lease_id: lane.lease_id.clone(),
            worker_id: lane.worker_id.clone(),
            reason: CancelReason::UserRequested,
        },
    )?;
    let final_receipt = coordinator.reconcile_cancellation(
        context,
        ProviderCancellationReconciliation {
            reconciliation_id: CancellationReconciliationId::new("cancel-final-prod")?,
            request_operation_id: operation_id,
            attempt_id: lane.attempt_id.clone(),
            lease_id: lane.lease_id.clone(),
            worker_id: lane.worker_id.clone(),
            provider_identity: provider_identity(),
            no_effect_or_cleanup_receipt_ref: "proof-cancel-prod".to_owned(),
        },
    )?;
    assert_eq!(final_receipt.attempt_id, lane.attempt_id);
    assert_eq!(
        final_receipt.state,
        crate::CoordinatedAttemptState::Cancelled
    );
    Ok(())
}

#[test]
fn production_verifier_fences_and_reassigns() -> TestResult {
    let mut coordinator = production_coordinator(config(4, 4))?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "prod-fence",
        &[bind_lane_spec("work-prod-fence", "reader-prod-fence", "a")],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    coordinator.mark_worker_lost(
        context.clone(),
        worker_fence(&lane, "prod-fence", "proof-fence-prod")?,
    )?;
    let new_attempt = AttemptId::new("attempt-prod-fence-new")?;
    coordinator.reassign(
        context,
        ProviderReassignmentReceipt {
            reassignment_id: ReassignmentId::new("reassign-prod-fence")?,
            provider_identity: provider_identity(),
            g11_receipt_ref: "proof-reassign-prod".to_owned(),
            old_attempt_id: lane.attempt_id.clone(),
            old_lease_id: lane.lease_id.clone(),
            new_attempt_id: new_attempt.clone(),
            new_lease_id: serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-prod-fence-new"}),
            )?,
            new_worker_id: WorkerId::new("worker-prod-fence-new")?,
            route: lane.route.clone(),
            budget: budget(),
        },
    )?;
    assert!(coordinator.attempt(&new_attempt).is_some());
    Ok(())
}

#[test]
fn production_verifier_reconciles_unknown_outcome() -> TestResult {
    let mut coordinator = production_coordinator(config(2, 2))?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "prod-unknown",
        &[bind_lane_spec(
            "work-prod-unknown",
            "reader-prod-unknown",
            "a",
        )],
        None,
    )?;
    let context = ExecutionContext::from(&admitted);
    let lane = admitted.admitted_lanes[0].clone();
    coordinator.start_attempt(context.clone(), lane.attempt_id.clone())?;
    let submission = result_submission("prod-unknown", &lane, ResultDisposition::UnknownOutcome)?;
    let submission_id = submission.submission_id.clone();
    coordinator.submit_result(context.clone(), submission)?;
    let final_receipt = coordinator.reconcile_unknown_outcome(
        context,
        ProviderUnknownOutcomeReconciliation {
            reconciliation_id: OutcomeReconciliationId::new("unknown-final-prod")?,
            submission_id,
            attempt_id: lane.attempt_id.clone(),
            lease_id: lane.lease_id.clone(),
            worker_id: lane.worker_id.clone(),
            provider_identity: provider_identity(),
            resolution: UnknownOutcomeResolution::NoEffect,
            effect_reconciliation_ref: "proof-unknown-prod".to_owned(),
        },
    )?;
    assert_eq!(
        final_receipt.state,
        crate::CoordinatedAttemptState::CandidateResultSubmitted
    );
    Ok(())
}

#[test]
fn production_replay_is_idempotent_and_conflict_fails_closed() -> TestResult {
    let mut coordinator = production_coordinator(config(2, 2))?;
    let candidate = coordinator.plan(request(
        "prod-replay",
        &[bind_lane_spec(
            "work-prod-replay",
            "reader-prod-replay",
            "a",
        )],
        None,
    )?)?;
    let receipt = provider_receipt(&candidate, "prod-replay")?;
    let events_before = coordinator.events().len();
    let first = coordinator.admit(receipt.clone())?;
    assert_eq!(coordinator.events().len(), events_before + 1);
    let replayed = coordinator.admit(receipt.clone())?;
    assert_eq!(replayed, first);
    assert_eq!(coordinator.events().len(), events_before + 1);
    let mut conflict = receipt;
    conflict.durable_job_ref = "durable-job-changed".to_owned();
    assert_eq!(
        coordinator.admit(conflict).err(),
        Some(CoordinatorError::IdentityConflict("admission_id"))
    );
    assert_eq!(coordinator.events().len(), events_before + 1);
    Ok(())
}

#[test]
fn production_revoked_capability_fails_closed_without_mutation() -> TestResult {
    let revoked = admitted_capability_for(
        provider_identity(),
        true,
        "route-rev-7",
        "capacity-rev-3",
        "route-rev-7",
        "capacity-rev-3",
        1,
        1,
        0,
    )?;
    let mut coordinator = AgentCoordinator::new_with_admitted_provider(config(2, 2), revoked)?;
    let candidate = coordinator.plan(request(
        "prod-revoked",
        &[bind_lane_spec(
            "work-prod-revoked",
            "reader-prod-revoked",
            "a",
        )],
        None,
    )?)?;
    let before = coordinator.snapshot_json()?;
    assert_eq!(
        coordinator
            .admit(provider_receipt(&candidate, "prod-revoked")?)
            .err(),
        Some(CoordinatorError::StaleProviderBinding)
    );
    assert_eq!(coordinator.snapshot_json()?, before);
    Ok(())
}

#[test]
fn production_stale_route_capacity_epoch_fail_closed() -> TestResult {
    let stale_capacity = admitted_capability_for(
        provider_identity(),
        false,
        "route-rev-7",
        "capacity-rev-stale",
        "route-rev-7",
        "capacity-rev-3",
        1,
        1,
        0,
    )?;
    let mut coordinator =
        AgentCoordinator::new_with_admitted_provider(config(2, 2), stale_capacity)?;
    let candidate = coordinator.plan(request(
        "prod-stale-cap",
        &[bind_lane_spec(
            "work-prod-stale-cap",
            "reader-prod-stale-cap",
            "a",
        )],
        None,
    )?)?;
    let before = coordinator.snapshot_json()?;
    assert_eq!(
        coordinator
            .admit(provider_receipt(&candidate, "prod-stale-cap")?)
            .err(),
        Some(CoordinatorError::StaleCapacity)
    );
    assert_eq!(coordinator.snapshot_json()?, before);

    let stale_route = admitted_capability_for(
        provider_identity(),
        false,
        "route-rev-stale",
        "capacity-rev-3",
        "route-rev-7",
        "capacity-rev-3",
        1,
        1,
        0,
    )?;
    let mut coordinator = AgentCoordinator::new_with_admitted_provider(config(2, 2), stale_route)?;
    let candidate = coordinator.plan(request(
        "prod-stale-route",
        &[bind_lane_spec(
            "work-prod-stale-route",
            "reader-prod-stale-route",
            "a",
        )],
        None,
    )?)?;
    assert_eq!(
        coordinator
            .admit(provider_receipt(&candidate, "prod-stale-route")?)
            .err(),
        Some(CoordinatorError::RouteEvidence)
    );

    let stale_epoch = admitted_capability_for(
        provider_identity(),
        false,
        "route-rev-7",
        "capacity-rev-3",
        "route-rev-7",
        "capacity-rev-3",
        1,
        2,
        0,
    )?;
    let mut coordinator = AgentCoordinator::new_with_admitted_provider(config(2, 2), stale_epoch)?;
    let candidate = coordinator.plan(request(
        "prod-stale-epoch",
        &[bind_lane_spec(
            "work-prod-stale-epoch",
            "reader-prod-stale-epoch",
            "a",
        )],
        None,
    )?)?;
    assert_eq!(
        coordinator
            .admit(provider_receipt(&candidate, "prod-stale-epoch")?)
            .err(),
        Some(CoordinatorError::StaleController)
    );
    Ok(())
}

#[test]
fn production_foreign_identity_fails_closed() -> TestResult {
    let mut coordinator = production_coordinator(config(2, 2))?;
    let candidate = coordinator.plan(request(
        "prod-foreign",
        &[bind_lane_spec(
            "work-prod-foreign",
            "reader-prod-foreign",
            "a",
        )],
        None,
    )?)?;
    let mut receipt = provider_receipt(&candidate, "prod-foreign")?;
    receipt.provider_identity.verifier_identity = "foreign-verifier".to_owned();
    let before = coordinator.snapshot_json()?;
    assert_eq!(
        coordinator.admit(receipt).err(),
        Some(CoordinatorError::StaleProviderBinding)
    );
    assert_eq!(coordinator.snapshot_json()?, before);
    Ok(())
}

#[test]
fn plan_only_constructor_still_refuses_effects() -> TestResult {
    let cfg = config(2, 2);
    let gap = PlanGap::G11Unavailable {
        reason: "G-11 absent".to_owned(),
    };
    let mut gap_coordinator = AgentCoordinator::new(cfg.clone(), gap)?;
    let candidate = gap_coordinator.plan(request(
        "prod-split",
        &[bind_lane_spec("work-prod-split", "reader-prod-split", "a")],
        None,
    )?)?;
    let receipt = provider_receipt(&candidate, "prod-split")?;
    assert!(matches!(
        gap_coordinator.admit(receipt.clone()),
        Err(CoordinatorError::PlanGap(_))
    ));
    let mut production = production_coordinator(cfg)?;
    production.plan(request(
        "prod-split",
        &[bind_lane_spec("work-prod-split", "reader-prod-split", "a")],
        None,
    )?)?;
    production.admit(receipt)?;
    Ok(())
}

#[test]
fn production_restore_reverifies_against_fresh_kernel_evidence() -> TestResult {
    let cfg = config(4, 4);
    let mut coordinator = production_coordinator(cfg.clone())?;
    let admitted = plan_and_admit(
        &mut coordinator,
        "prod-restore",
        &[bind_lane_spec(
            "work-prod-restore",
            "reader-prod-restore",
            "a",
        )],
        None,
    )?;
    coordinator.start_attempt(
        ExecutionContext::from(&admitted),
        admitted.admitted_lanes[0].attempt_id.clone(),
    )?;
    let snapshot = coordinator.snapshot()?;
    let restored = AgentCoordinator::restore_with_admitted_provider(
        snapshot.clone(),
        cfg.clone(),
        admitted_capability(snapshot.event_sequence)?,
    )?;
    assert_eq!(restored.events(), coordinator.events());
    assert_eq!(
        AgentCoordinator::restore_with_admitted_provider(
            snapshot.clone(),
            cfg.clone(),
            admitted_capability_for(
                provider_identity(),
                true,
                "route-rev-7",
                "capacity-rev-3",
                "route-rev-7",
                "capacity-rev-3",
                1,
                1,
                0,
            )?,
        )
        .err(),
        Some(CoordinatorError::StaleProviderBinding)
    );
    assert_eq!(
        AgentCoordinator::restore_with_admitted_provider(
            snapshot.clone(),
            cfg.clone(),
            admitted_capability(snapshot.event_sequence + 1)?,
        )
        .err(),
        Some(CoordinatorError::SnapshotRollback)
    );
    // A serialized `Verified` label alone never restores authority: a
    // foreign identity fails even though the snapshot claims verification.
    let mut foreign_identity = provider_identity();
    foreign_identity.verifier_identity = "foreign-verifier".to_owned();
    assert_eq!(
        AgentCoordinator::restore_with_admitted_provider(
            snapshot,
            cfg,
            admitted_capability_for(
                foreign_identity,
                false,
                "route-rev-7",
                "capacity-rev-3",
                "route-rev-7",
                "capacity-rev-3",
                1,
                1,
                0,
            )?,
        )
        .err(),
        Some(CoordinatorError::StaleProviderBinding)
    );
    Ok(())
}

#[test]
fn coordinator_case_12_effect_payload_digest_is_canonical() -> TestResult {
    // #228 narrow slice consumer proof: coordinator intake carries the v7
    // canonical `LowercaseSha256` effect digest; legacy placeholders never
    // deserialize as `ProposedEffect`.
    let digest: LowercaseSha256 = serde_json::from_value(serde_json::json!(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ))?;
    let effect = ProposedEffect {
        effect_id: "effect-case-12".to_owned(),
        attempt_id: AttemptId::new("attempt-case-12")?,
        kind: EffectKind::Observe,
        scope_ref: "scope-work-case-12".to_owned(),
        payload_digest: digest,
        rationale_ref: None,
    };
    let ceiling = EffectCeiling {
        scope_ref: "scope-work-case-12".to_owned(),
        allowed: BTreeSet::from([EffectKind::Observe]),
        max_external_effects: 0,
    };
    effect.validate_against(&ceiling)?;
    let legacy = serde_json::json!({
        "effect_id": "effect-case-12",
        "attempt_id": "attempt-case-12",
        "kind": "observe",
        "scope_ref": "scope-work-case-12",
        "payload_digest": "payload-case-12",
        "rationale_ref": null,
    });
    assert!(serde_json::from_value::<ProposedEffect>(legacy).is_err());
    Ok(())
}

// I14.1 work classes (issue #1698): the nine canonical values plan, admit,
// and echo through the receipt and scheduled record; anything else rejects
// before launch with a typed error and consumes no capacity.

fn classified_request(tag: &str, class: &str) -> TestResult<StaffingPlanRequest> {
    let mut req = request(
        tag,
        &[LaneSpec {
            work: "work-wc",
            role: "reader-wc",
            route: "a",
            scope: None,
            write: false,
            priority: 1,
        }],
        None,
    )?;
    req.work_class = class.to_owned();
    for lane in &mut req.lanes {
        lane.work_class = class.to_owned();
    }
    Ok(req)
}

#[test]
fn work_class_all_nine_values_admit_and_echo() -> TestResult {
    let classes = [
        "control",
        "interactive",
        "verification",
        "canonical_write",
        "normal_background",
        "model_jobs",
        "swarm",
        "reporting",
        "maintenance",
    ];
    for (index, class) in classes.iter().enumerate() {
        let tag = format!("wc9-{index}");
        let proof = format!("proof-admission-{tag}");
        let mut coord = coordinator(config(4, 4), &[proof.as_str()])?;
        let candidate = coord.plan(classified_request(&tag, class)?)?;
        assert_eq!(candidate.work_class, *class);
        assert_eq!(candidate.lanes.len(), 1);
        assert_eq!(candidate.lanes[0].work_class, *class);
        let receipt = coord.admit(provider_receipt(&candidate, &tag)?)?;
        assert_eq!(receipt.admitted_lanes.len(), 1);
        assert_eq!(receipt.admitted_lanes[0].work_class, *class);
        let next = coord.next_ready().ok_or("admitted work must be ready")?;
        assert_eq!(next.work_class, *class);
    }
    Ok(())
}

#[test]
fn work_class_unknown_blank_and_mixed_reject_before_capacity() -> TestResult {
    let mut coord = coordinator(config(4, 4), &["proof-admission-wcf"])?;
    // Fill the ready window so a capacity check would fire first if class
    // validation were ordered after it.
    let mut tight = AgentCoordinator::with_provider(
        CoordinatorConfig {
            max_ready_items: 1,
            max_admitted_attempts: 4,
            max_active_per_route: 4,
            capacity_identity: "capacity-a".to_owned(),
            capacity_revision: rev("capacity-rev-1"),
        },
        Box::new(verifier(&[], 0)),
    )?;
    tight.plan(classified_request("wcfill", "swarm")?)?;
    // Unknown rejects with the typed variant even at capacity: no silent
    // downgrade to a less restrictive class, no capacity consumed.
    let unknown = classified_request("wcx", "proton")?;
    assert_eq!(
        tight.plan(unknown.clone()).err(),
        Some(CoordinatorError::UnknownWorkClass("proton".to_owned()))
    );
    let mut blank = classified_request("wcb", "swarm")?;
    blank.work_class = String::new();
    for lane in &mut blank.lanes {
        lane.work_class = String::new();
    }
    assert_eq!(
        tight.plan(blank).err(),
        Some(CoordinatorError::UnknownWorkClass(String::new()))
    );
    // Mixed plan/lane classes reject as an identity conflict.
    let mut mixed = classified_request("wcm", "swarm")?;
    mixed.lanes[0].work_class = "interactive".to_owned();
    assert_eq!(
        coord.plan(mixed).err(),
        Some(CoordinatorError::IdentityConflict("work_class"))
    );
    // A forged receipt class that disagrees with the candidate rejects.
    let candidate = coord.plan(classified_request("wcf", "swarm")?)?;
    let mut forged = provider_receipt(&candidate, "wcf")?;
    forged.admitted_lanes[0].work_class = "control".to_owned();
    assert_eq!(
        coord
            .admit(forged)
            .err()
            .map(|error| matches!(error, CoordinatorError::IdentityConflict("admitted_lane"))),
        Some(true)
    );
    Ok(())
}

#[test]
fn work_class_control_sorts_before_higher_priority_normal() -> TestResult {
    let mut coord = coordinator(
        config(4, 4),
        &["proof-admission-wchi", "proof-admission-wclo"],
    )?;
    let mut hi = classified_request("wchi", "maintenance")?;
    hi.lanes[0].priority = 9;
    let mut lo = classified_request("wclo", "control")?;
    lo.lanes[0].priority = 0;
    let hi_candidate = coord.plan(hi)?;
    let lo_candidate = coord.plan(lo)?;
    coord.admit(provider_receipt(&hi_candidate, "wchi")?)?;
    coord.admit(provider_receipt(&lo_candidate, "wclo")?)?;
    let next = coord.next_ready().ok_or("admitted work must be ready")?;
    assert_eq!(next.work_class, WORK_CLASS_CONTROL);
    Ok(())
}

#[test]
fn work_class_taxonomy_matches_kernel_control_reserve() -> TestResult {
    use eliot_kernel_core::{ControlOperationClass, NormalWorkClass};
    // Every normal Kernel variant maps to exactly one I14.1 wire spelling
    // (no wildcard: a Kernel-side addition fails compilation here).
    fn wire(value: NormalWorkClass) -> &'static str {
        match value {
            NormalWorkClass::Interactive => "interactive",
            NormalWorkClass::Verification => "verification",
            NormalWorkClass::CanonicalWrite => "canonical_write",
            NormalWorkClass::NormalBackground => "normal_background",
            NormalWorkClass::ModelJob => "model_jobs",
            NormalWorkClass::Swarm => "swarm",
            NormalWorkClass::Reporting => "reporting",
            NormalWorkClass::Maintenance => "maintenance",
        }
    }
    let normals = [
        NormalWorkClass::Interactive,
        NormalWorkClass::Verification,
        NormalWorkClass::CanonicalWrite,
        NormalWorkClass::NormalBackground,
        NormalWorkClass::ModelJob,
        NormalWorkClass::Swarm,
        NormalWorkClass::Reporting,
        NormalWorkClass::Maintenance,
    ];
    for variant in normals {
        assert_eq!(normal_work_class_from_wire(wire(variant)), Some(variant));
        assert!(validate_work_class(wire(variant)).is_ok());
    }
    // The protected family (no wildcard: additions fail compilation) carries
    // no ordinary lane work; only the single `control` partition label is
    // wire-admissible, and raw protected spellings reject.
    let protected = [
        ControlOperationClass::CancelOperation,
        ControlOperationClass::FenceStaleOwner,
        ControlOperationClass::RevokeAuthority,
        ControlOperationClass::HealthReadinessControl,
        ControlOperationClass::CriticalTelemetry,
        ControlOperationClass::CriticalAttentionTransition,
        ControlOperationClass::ProblemTransition,
        ControlOperationClass::IncidentTransition,
        ControlOperationClass::PersistentNotificationTransition,
        ControlOperationClass::SafeShutdown,
        ControlOperationClass::Drain,
        ControlOperationClass::Recovery,
        ControlOperationClass::Containment,
        ControlOperationClass::UnknownOutcomeReconciliation,
    ];
    for operation in protected {
        match operation {
            ControlOperationClass::CancelOperation
            | ControlOperationClass::FenceStaleOwner
            | ControlOperationClass::RevokeAuthority
            | ControlOperationClass::HealthReadinessControl
            | ControlOperationClass::CriticalTelemetry
            | ControlOperationClass::CriticalAttentionTransition
            | ControlOperationClass::ProblemTransition
            | ControlOperationClass::IncidentTransition
            | ControlOperationClass::PersistentNotificationTransition
            | ControlOperationClass::SafeShutdown
            | ControlOperationClass::Drain
            | ControlOperationClass::Recovery
            | ControlOperationClass::Containment
            | ControlOperationClass::UnknownOutcomeReconciliation => {}
        }
    }
    assert!(validate_work_class(WORK_CLASS_CONTROL).is_ok());
    assert_eq!(work_class_rank(WORK_CLASS_CONTROL), 0);
    assert!(validate_work_class("CANCEL_OPERATION").is_err());
    assert!(validate_work_class("MODEL_JOB").is_err());
    Ok(())
}
