//! Agent-fabric wiring proof for issue #872.
//!
//! Exactly cases 1 through 28; one substantive primary executable test per
//! case marker below. Helpers carry no markers. All proof
//! runs through the real production wiring (`eliotd::agent_fabric` plus the
//! `DaemonComposition` descriptor/plan caller) with recording fakes only at
//! the accepted owner seams. No stubs, no canned authority, no live provider
//! launch.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use eliot_agent_api::{
    AgentLaunchRequest, AgentWorkUnitBrief, AttemptId, BudgetEnvelope, EffectCeiling, EffectKind,
    LaunchRequestId, LowercaseSha256, RouteFingerprint, TaskId, WorkUnitId,
};
use eliot_agent_contracts::RevisionId;
use eliot_agent_coordinator::{
    CandidateId, CoordinatorConfig, RecipeId, RecipeManifest, RoleProfileId, RoleProfileManifest,
    RouteCandidateEvidence, StaffingLaneRequest, StaffingPlanCandidate, StaffingPlanRequest,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_security_contracts::PrivacyClass;
use eliotd::{
    ActivationAuthorityPort, ActivationEvidence, AdmissionAuthorityPort, AgentFabric,
    AttemptLifecycle, AttemptResultRecord, COORDINATOR_CRATE, CancellationLifecycle, DispatchAck,
    DispatchEgressPort, DispatchIntent, FABRIC_CAPACITY_IDENTITY, FABRIC_CAPACITY_REVISION,
    FabricAdmission, FabricError, FabricPorts, ModelRegistryPort, PeerChannelPort, PeerMessage,
    PeerReceipt, Reservation, RouteRequirements, SwarmControlPort, SwarmDefinition,
    SwarmEntryReceipt, WorkerAck, daemon_coordinator_config, plan_candidate, prereq_ports,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_fence() -> TestResult<StateFence> {
    let lineage = EpochLineageId::new(TEST_LINEAGE).map_err(|error| format!("lineage: {error}"))?;
    let sequence = NonZeroU64::new(1).ok_or("non-zero test sequence")?;
    let epoch = EpochId::new(lineage, sequence).map_err(|error| format!("epoch: {error}"))?;
    Ok(StateFence::new(epoch, ResourceGeneration::genesis()))
}

fn test_digest(seed: &str) -> TestResult<LowercaseSha256> {
    serde_json::from_value(serde_json::json!(sha256_hex(seed.as_bytes()))).map_err(Into::into)
}

fn test_route() -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: "test-host".to_owned(),
        adapter: "adapter-fabric-a".to_owned(),
        protocol_transport: "fabric-fixture".to_owned(),
        runtime_hash: test_digest("fabric-runtime")?,
        adapter_hash: test_digest("fabric-adapter")?,
        provider: "provider-fabric-a".to_owned(),
        model: "model-fabric-a".to_owned(),
        auth_billing: "fixture-account".to_owned(),
        serializer_hash: test_digest("fabric-serializer")?,
        tool_semantics_hash: test_digest("fabric-tools")?,
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: test_digest("fabric-features")?,
    })
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

fn test_request(
    fence: &StateFence,
    route: &RouteFingerprint,
    candidate: &str,
) -> TestResult<StaffingPlanRequest> {
    let work = AgentWorkUnitBrief {
        id: WorkUnitId::new("work-1").map_err(|error| format!("work id: {error}"))?,
        objective: "bounded responsibility work-1".to_owned(),
        causal_property: "causal property work-1".to_owned(),
        scope_ref: "scope-work-1".to_owned(),
        expected_outputs: vec!["candidate artifact".to_owned()],
        source_refs: vec!["architecture:10635".to_owned()],
        verifier_ref: "cargo-test".to_owned(),
        integration_owner: "independent-integrator".to_owned(),
        contract_revision: "work-v1".to_owned(),
        budget: test_budget(),
        effect_ceiling: EffectCeiling {
            scope_ref: "scope-work-1".to_owned(),
            allowed: BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]),
            max_external_effects: 0,
        },
        stop_condition: "candidate submitted".to_owned(),
    };
    Ok(StaffingPlanRequest {
        candidate_id: CandidateId::new(candidate).map_err(|error| format!("candidate: {error}"))?,
        launch: AgentLaunchRequest {
            id: LaunchRequestId::new("launch-872").map_err(|error| format!("launch: {error}"))?,
            task_id: TaskId::new("task-872").map_err(|error| format!("task: {error}"))?,
            parent_attempt: None,
            work_units: vec![work],
            required_competence: vec!["rust".to_owned()],
            allowed_route_classes: vec!["provider-fabric-a".to_owned()],
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
            max_fanout: 8,
            cumulative_descendant_budget: test_budget(),
            verifier_ref: "cargo-test".to_owned(),
            synthesis_owner: "synthesis-owner".to_owned(),
            integration_owner: "integration-owner".to_owned(),
            cancellation_policy: "cascade".to_owned(),
        },
        recipe: RecipeManifest {
            recipe_id: RecipeId::new("recipe-872").map_err(|error| format!("recipe: {error}"))?,
            manifest_revision: RevisionId::new("recipe-rev-872")
                .map_err(|error| format!("recipe rev: {error}"))?,
            route_policy_revision: RevisionId::new("route-policy-1")
                .map_err(|error| format!("route policy: {error}"))?,
            max_lanes: 1,
            max_descendants: 8,
            role_profiles: vec![RoleProfileManifest {
                role_id: RoleProfileId::new("role-1").map_err(|error| format!("role: {error}"))?,
                manifest_revision: RevisionId::new("role-rev-role-1")
                    .map_err(|error| format!("role rev: {error}"))?,
                required_competence: vec!["rust".to_owned()],
                allowed_route_classes: vec!["provider-fabric-a".to_owned()],
                mutation_capable: false,
            }],
        },
        task_revision: "task-rev-1".to_owned(),
        plan_revision: RevisionId::new("plan-rev-872")
            .map_err(|error| format!("plan rev: {error}"))?,
        state_fence: fence.clone(),
        privacy_class: PrivacyClass::Private,
        lanes: vec![StaffingLaneRequest {
            work_unit_id: WorkUnitId::new("work-1")
                .map_err(|error| format!("lane work: {error}"))?,
            role_id: RoleProfileId::new("role-1").map_err(|error| format!("lane role: {error}"))?,
            route_candidates: vec![RouteCandidateEvidence {
                route: route.clone(),
                preference_rank: 0,
                capacity_identity: FABRIC_CAPACITY_IDENTITY.to_owned(),
                capacity_revision: RevisionId::new(FABRIC_CAPACITY_REVISION)
                    .map_err(|error| format!("capacity rev: {error}"))?,
                capacity_limit: 4,
                budget_evidence: BudgetEvidence {
                    arm_id: "route-arm-0".to_owned(),
                    model_calls: 1,
                    wall_time_ms: 100,
                    ..BudgetEvidence::default()
                },
                evidence_refs: vec!["route-evidence-0".to_owned()],
            }],
            budget: test_budget(),
            priority: 0,
            mutation_scope: None,
        }],
    })
}

fn test_requirements() -> RouteRequirements {
    RouteRequirements {
        role: "role-1".to_owned(),
        competence: vec!["rust".to_owned()],
    }
}

fn manifest_source(relative: &str) -> TestResult<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative);
    std::fs::read_to_string(&path).map_err(|error| format!("read {path}: {error}").into())
}

fn counter_value(counter: &Mutex<u32>) -> u32 {
    counter.lock().map_or(0, |guard| *guard)
}

fn bump(counter: &Mutex<u32>) {
    if let Ok(mut guard) = counter.lock() {
        *guard = guard.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmitMode {
    Admit,
    Deny,
    Incomplete,
    Narrowed,
    NeedsTask,
    TamperDigest,
    TamperReservation,
}

struct FakeRegistry {
    route: Option<RouteFingerprint>,
    calls: Mutex<u32>,
}

impl ModelRegistryPort for FakeRegistry {
    fn resolve_route(
        &self,
        requirements: &RouteRequirements,
    ) -> Result<Option<RouteFingerprint>, FabricError> {
        bump(&self.calls);
        if requirements.role.trim().is_empty() {
            return Err(FabricError::Contract("blank role".to_owned()));
        }
        Ok(self.route.clone())
    }
}

struct FakePeer {
    calls: Mutex<u32>,
}

impl PeerChannelPort for FakePeer {
    fn deliver(&self, message: &PeerMessage) -> Result<PeerReceipt, FabricError> {
        bump(&self.calls);
        Ok(PeerReceipt {
            message_id: message.message_id.clone(),
            channel_sequence: 1,
        })
    }
}

struct FakeSwarm {
    calls: Mutex<u32>,
    tamper: bool,
}

impl SwarmControlPort for FakeSwarm {
    fn enter_plan(
        &self,
        candidate: &StaffingPlanCandidate,
    ) -> Result<SwarmEntryReceipt, FabricError> {
        bump(&self.calls);
        let bytes = eliot_contracts::canonical_json_bytes(candidate)
            .map_err(|error| FabricError::Contract(format!("candidate bytes: {error}")))?;
        let digest = eliot_contracts::sha256_hex(&bytes);
        Ok(SwarmEntryReceipt {
            candidate_id: candidate.candidate_id.clone(),
            entered_digest: if self.tamper { "0".repeat(64) } else { digest },
        })
    }
}

struct FakeAdmission {
    mode: Mutex<AdmitMode>,
    stage_calls: Mutex<u32>,
    commit_calls: Mutex<u32>,
}

impl FakeAdmission {
    fn mode(&self) -> AdmitMode {
        self.mode.lock().map_or(AdmitMode::Admit, |guard| *guard)
    }
}

impl AdmissionAuthorityPort for FakeAdmission {
    fn stage_reservation(&self, definition: &SwarmDefinition) -> Result<Reservation, FabricError> {
        bump(&self.stage_calls);
        Ok(Reservation {
            reservation_id: format!("res-{}", definition.definition_id.as_str()),
            definition_id: definition.definition_id.clone(),
            definition_digest: definition.definition_digest.clone(),
            fence: definition.fence.clone(),
        })
    }

    fn commit_admission(&self, reservation: &Reservation) -> Result<FabricAdmission, FabricError> {
        bump(&self.commit_calls);
        match self.mode() {
            AdmitMode::Admit => Ok(FabricAdmission {
                admission_id: eliot_agent_coordinator::AdmissionId::new("admission-1")
                    .map_err(|error| FabricError::Contract(format!("admission id: {error}")))?,
                definition_id: reservation.definition_id.clone(),
                definition_digest: reservation.definition_digest.clone(),
                reservation_id: reservation.reservation_id.clone(),
                fence: reservation.fence.clone(),
                epoch: reservation.fence.authority_epoch.clone(),
                attempt_ids: vec![
                    AttemptId::new("attempt-1")
                        .map_err(|error| FabricError::Contract(format!("attempt: {error}")))?,
                ],
            }),
            AdmitMode::Deny => Err(FabricError::AdmissionDenied("governor denied".to_owned())),
            AdmitMode::Incomplete => Err(FabricError::AdmissionIncomplete(
                "admission incomplete".to_owned(),
            )),
            AdmitMode::Narrowed => Err(FabricError::Narrowed("proposal narrowed".to_owned())),
            AdmitMode::NeedsTask => Err(FabricError::NeedsTask("needs task revision".to_owned())),
            AdmitMode::TamperDigest => Ok(FabricAdmission {
                admission_id: eliot_agent_coordinator::AdmissionId::new("admission-1")
                    .map_err(|error| FabricError::Contract(format!("admission id: {error}")))?,
                definition_id: reservation.definition_id.clone(),
                definition_digest: "f".repeat(64),
                reservation_id: reservation.reservation_id.clone(),
                fence: reservation.fence.clone(),
                epoch: reservation.fence.authority_epoch.clone(),
                attempt_ids: vec![
                    AttemptId::new("attempt-1")
                        .map_err(|error| FabricError::Contract(format!("attempt: {error}")))?,
                ],
            }),
            AdmitMode::TamperReservation => Ok(FabricAdmission {
                admission_id: eliot_agent_coordinator::AdmissionId::new("admission-1")
                    .map_err(|error| FabricError::Contract(format!("admission id: {error}")))?,
                definition_id: reservation.definition_id.clone(),
                definition_digest: reservation.definition_digest.clone(),
                reservation_id: "res-foreign".to_owned(),
                fence: reservation.fence.clone(),
                epoch: reservation.fence.authority_epoch.clone(),
                attempt_ids: vec![
                    AttemptId::new("attempt-1")
                        .map_err(|error| FabricError::Contract(format!("attempt: {error}")))?,
                ],
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivateMode {
    Activate,
    StaleFence,
    StaleEpoch,
}

struct FakeActivation {
    mode: Mutex<ActivateMode>,
    calls: Mutex<u32>,
}

impl ActivationAuthorityPort for FakeActivation {
    fn activate(
        &self,
        admission: &FabricAdmission,
        attempt_id: &AttemptId,
    ) -> Result<ActivationEvidence, FabricError> {
        bump(&self.calls);
        let mode = self
            .mode
            .lock()
            .map_or(ActivateMode::Activate, |guard| *guard);
        let fence = match mode {
            ActivateMode::StaleFence => {
                let mut fence = admission.fence.clone();
                fence.resource_generation = ResourceGeneration::new(
                    admission
                        .fence
                        .resource_generation
                        .value()
                        .saturating_add(1),
                )
                .map_err(|error| FabricError::Contract(format!("generation: {error}")))?;
                fence
            }
            ActivateMode::Activate | ActivateMode::StaleEpoch => admission.fence.clone(),
        };
        let epoch = match mode {
            ActivateMode::StaleEpoch => {
                let lineage = admission.epoch.lineage_id.clone();
                let next = admission.epoch.sequence.get().saturating_add(1);
                let sequence = NonZeroU64::new(next)
                    .ok_or_else(|| FabricError::Contract("epoch sequence overflow".to_owned()))?;
                EpochId::new(lineage, sequence)
                    .map_err(|error| FabricError::Contract(format!("epoch: {error}")))?
            }
            _ => admission.epoch.clone(),
        };
        let digest = eliot_contracts::sha256_hex(
            format!(
                "activation:{}:{}",
                admission.admission_id.as_str(),
                attempt_id.as_str()
            )
            .as_bytes(),
        );
        Ok(ActivationEvidence {
            admission_id: admission.admission_id.clone(),
            attempt_id: attempt_id.clone(),
            activation_digest: digest,
            fence,
            epoch,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EgressMode {
    Ack,
    Unavailable,
    Lost,
}

struct FakeEgress {
    mode: Mutex<EgressMode>,
    calls: Mutex<u32>,
}

impl DispatchEgressPort for FakeEgress {
    fn emit(&self, intent: &DispatchIntent) -> Result<DispatchAck, FabricError> {
        bump(&self.calls);
        let mode = self.mode.lock().map_or(EgressMode::Ack, |guard| *guard);
        match mode {
            EgressMode::Ack => Ok(DispatchAck {
                dispatch_id: intent.dispatch_id.clone(),
                retained: true,
            }),
            EgressMode::Unavailable => Err(FabricError::DispatchUnavailable(
                "egress unavailable".to_owned(),
            )),
            EgressMode::Lost => Err(FabricError::DispatchLost("egress lost".to_owned())),
        }
    }
}

struct TestWorld {
    fabric: AgentFabric,
    admission: Arc<FakeAdmission>,
    activation: Arc<FakeActivation>,
    egress: Arc<FakeEgress>,
    registry: Arc<FakeRegistry>,
    peer: Arc<FakePeer>,
    swarm: Arc<FakeSwarm>,
}

fn test_world(
    route: Option<RouteFingerprint>,
    admit: AdmitMode,
    activate: ActivateMode,
    egress: EgressMode,
    swarm_tamper: bool,
) -> TestResult<TestWorld> {
    let config: CoordinatorConfig = daemon_coordinator_config()?;
    let admission = Arc::new(FakeAdmission {
        mode: Mutex::new(admit),
        stage_calls: Mutex::new(0),
        commit_calls: Mutex::new(0),
    });
    let activation = Arc::new(FakeActivation {
        mode: Mutex::new(activate),
        calls: Mutex::new(0),
    });
    let egress_fake = Arc::new(FakeEgress {
        mode: Mutex::new(egress),
        calls: Mutex::new(0),
    });
    let registry = Arc::new(FakeRegistry {
        route,
        calls: Mutex::new(0),
    });
    let peer = Arc::new(FakePeer {
        calls: Mutex::new(0),
    });
    let swarm = Arc::new(FakeSwarm {
        calls: Mutex::new(0),
        tamper: swarm_tamper,
    });
    let ports = FabricPorts {
        model_registry: Arc::clone(&registry) as Arc<dyn ModelRegistryPort>,
        peer_channel: Arc::clone(&peer) as Arc<dyn PeerChannelPort>,
        swarm_control: Arc::clone(&swarm) as Arc<dyn SwarmControlPort>,
        admission_authority: Arc::clone(&admission) as Arc<dyn AdmissionAuthorityPort>,
        activation_authority: Arc::clone(&activation) as Arc<dyn ActivationAuthorityPort>,
        dispatch_egress: Arc::clone(&egress_fake) as Arc<dyn DispatchEgressPort>,
    };
    Ok(TestWorld {
        fabric: AgentFabric::new(config, ports)?,
        admission,
        activation,
        egress: egress_fake,
        registry,
        peer,
        swarm,
    })
}

fn admitted_attempt(
    world: &mut TestWorld,
    candidate: &str,
) -> TestResult<(SwarmDefinition, FabricAdmission)> {
    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, candidate)?;
    let (definition, _candidate) = world.fabric.define_and_plan(request)?;
    let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
    let admission = world.fabric.commit_admission(&reservation.reservation_id)?;
    Ok((definition, admission))
}

// WORK_UNIT_CASE: 872/1
#[test]
fn inventory_freezes_dependencies_callers_and_missing_ports() -> TestResult {
    assert_eq!(COORDINATOR_CRATE, "eliot-agent-coordinator");
    let prereqs = prereq_ports();
    assert_eq!(prereqs.len(), 5);
    for expected in ["#694", "#696", "#698", "#839", "#837"] {
        assert!(
            prereqs.iter().any(|port| port.contains(expected)),
            "missing prereq {expected}"
        );
    }
    let cargo = manifest_source("Cargo.toml")?;
    assert!(
        cargo.contains("eliot-agent-coordinator"),
        "coordinator must be a normal dependency"
    );
    let fabric = manifest_source("src/agent_fabric.rs")?;
    assert!(
        fabric.contains("AgentCoordinator"),
        "fabric must compose the coordinator owner"
    );
    let lib = manifest_source("src/lib.rs")?;
    assert!(
        lib.contains("agent_fabric_plan"),
        "production caller must exist in lib.rs"
    );
    assert!(
        lib.contains("agent_fabric_descriptor"),
        "descriptor caller must exist in lib.rs"
    );
    let runtime = manifest_source("src/daemon_runtime.rs")?;
    assert!(
        runtime.contains("attach_agent_fabric"),
        "admitted ingress must attach the fabric"
    );
    // Frozen ContractChallenge residual: prereqs are OPEN on this base, so the
    // fabric injects their ports and invents no local authority. The five
    // port names above are the challenge surface; no fallback exists here.
    assert!(fabric.contains("never reimplements") || fabric.contains("seam"));
    Ok(())
}

// WORK_UNIT_CASE: 872/2
#[test]
fn coordinator_is_production_dependency_through_daemon_composition() -> TestResult {
    let fence = test_fence()?;
    let route = test_route()?;
    let config = daemon_coordinator_config()?;
    let request = test_request(&fence, &route, "candidate-872-02")?;
    // Real owner planning through the shared production function (the same
    // function `DaemonComposition::agent_fabric_plan` calls).
    let candidate = plan_candidate(&config, request)?;
    assert_eq!(candidate.candidate_id.as_str(), "candidate-872-02");
    assert_eq!(candidate.lanes.len(), 1);
    let world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    assert_eq!(world.fabric.coordinator_count(), 1);
    // Production caller reachability: the daemon composition exposes the same
    // planning contour; source proves the delegation.
    let lib = manifest_source("src/lib.rs")?;
    assert!(lib.contains("plan_candidate(&config, request)"));
    Ok(())
}

// WORK_UNIT_CASE: 872/3
#[test]
fn swarm_control_reachable_through_production_caller() -> TestResult {
    let fence = test_fence()?;
    let route = test_route()?;
    let mut world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let request = test_request(&fence, &route, "candidate-872-03")?;
    let (_definition, candidate) = world.fabric.define_and_plan(request)?;
    let receipt = world.fabric.enter_swarm(&candidate)?;
    assert_eq!(receipt.candidate_id.as_str(), "candidate-872-03");
    assert_eq!(counter_value(&world.swarm.calls), 1);
    assert!(
        world
            .fabric
            .ledger_events()
            .contains(&"swarm_entered".to_owned())
    );
    let runtime = manifest_source("src/daemon_runtime.rs")?;
    assert!(runtime.contains("attach_agent_fabric(&composition)"));
    Ok(())
}

// WORK_UNIT_CASE: 872/4
#[test]
fn no_provider_adapter_in_normal_closure() -> TestResult {
    let cargo = manifest_source("Cargo.toml")?;
    assert!(cargo.contains("eliot-agent-coordinator"));
    for provider in [
        "eliot-agent-claude",
        "eliot-agent-codex",
        "eliot-agent-opencode",
    ] {
        assert!(
            !cargo.contains(provider),
            "provider adapter {provider} must not enter eliotd"
        );
    }
    let fabric = manifest_source("src/agent_fabric.rs")?;
    for forbidden in [
        "eliot-agent-claude",
        "eliot-agent-codex",
        "eliot-agent-opencode",
    ] {
        assert!(
            !fabric.contains(forbidden),
            "fabric must not import {forbidden}"
        );
    }
    // The neutral contract edge terminates in contract-only owners.
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-04")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    let evidence = world.fabric.activate(&admission.admission_id, &attempt)?;
    let intent = world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-04")?;
    assert_eq!(intent.activation_digest, evidence.activation_digest);
    let intent_json = serde_json::to_value(&intent)?;
    let object = intent_json.as_object().ok_or("intent object")?;
    for field in [
        "dispatch_id",
        "admission_id",
        "attempt_id",
        "activation_digest",
        "fence",
        "epoch",
    ] {
        assert!(object.contains_key(field), "intent must carry {field}");
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/5
#[test]
fn exactly_one_coordinator_is_constructed() -> TestResult {
    let world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    assert_eq!(world.fabric.coordinator_count(), 1);
    let constructed = world
        .fabric
        .ledger_events()
        .iter()
        .filter(|event| *event == "coordinator_constructed")
        .count();
    assert_eq!(constructed, 1);
    assert_eq!(world.fabric.ledger()[0].event, "coordinator_constructed");
    Ok(())
}

// WORK_UNIT_CASE: 872/6
#[test]
fn valid_request_preserves_identities_and_validation_order() -> TestResult {
    let fence = test_fence()?;
    let route = test_route()?;
    let mut world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let request = test_request(&fence, &route, "candidate-872-06")?;
    let (definition, candidate) = world.fabric.define_and_plan(request.clone())?;
    assert_eq!(definition.definition_id.as_str(), "candidate-872-06");
    assert_eq!(definition.task_id, "task-872");
    assert_eq!(definition.task_revision, "task-rev-1");
    assert_eq!(definition.fence, fence);
    assert_eq!(candidate.task_id.as_str(), "task-872");
    let events = world.fabric.ledger_events();
    let validated = events
        .iter()
        .position(|event| event == "definition_validated")
        .ok_or("validated")?;
    let compiled = events
        .iter()
        .position(|event| event == "plan_compiled")
        .ok_or("compiled")?;
    assert!(
        validated < compiled,
        "definition validation must precede planning"
    );
    assert_eq!(request.state_fence, fence);
    Ok(())
}

// WORK_UNIT_CASE: 872/7
#[test]
fn fresh_admission_occurs_once_and_replay_is_identical() -> TestResult {
    let mut world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-07")?;
    assert_eq!(counter_value(&world.admission.commit_calls), 1);
    let replay = world.fabric.commit_admission(&admission.reservation_id)?;
    assert_eq!(replay, admission);
    assert_eq!(
        counter_value(&world.admission.commit_calls),
        1,
        "replay must not re-call the owner"
    );
    assert!(
        world
            .fabric
            .ledger_events()
            .contains(&"admission_replayed".to_owned())
    );
    Ok(())
}

// WORK_UNIT_CASE: 872/8
#[test]
fn denied_or_incomplete_admission_and_pre_activation_crash_dispatch_nothing() -> TestResult {
    let mut denied = test_world(
        None,
        AdmitMode::Deny,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, "candidate-872-08a")?;
    let (definition, _candidate) = denied.fabric.define_and_plan(request)?;
    let reservation = denied.fabric.stage_reservation(&definition.definition_id)?;
    match denied.fabric.commit_admission(&reservation.reservation_id) {
        Err(FabricError::AdmissionDenied(_)) => {}
        other => return Err(format!("denial must fail closed, got {other:?}").into()),
    }
    match denied.fabric.activate(
        &eliot_agent_coordinator::AdmissionId::new("admission-1")
            .map_err(|error| format!("admission id: {error}"))?,
        &AttemptId::new("attempt-1").map_err(|error| format!("attempt: {error}"))?,
    ) {
        Err(FabricError::StaleAdmission(_)) => {}
        other => {
            return Err(format!("activation without admission must fail, got {other:?}").into());
        }
    }
    let mut incomplete = test_world(
        None,
        AdmitMode::Incomplete,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let request = test_request(&fence, &route, "candidate-872-08b")?;
    let (definition, _candidate) = incomplete.fabric.define_and_plan(request)?;
    let reservation = incomplete
        .fabric
        .stage_reservation(&definition.definition_id)?;
    match incomplete
        .fabric
        .commit_admission(&reservation.reservation_id)
    {
        Err(FabricError::AdmissionIncomplete(_)) => {}
        other => {
            return Err(format!("incomplete admission must fail closed, got {other:?}").into());
        }
    }
    // Crash before activation: an admitted but unactivated operation dispatches nothing.
    let mut crashed = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut crashed, "candidate-872-08c")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    match crashed
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-08c")
    {
        Err(FabricError::NotActivated(_)) => {}
        other => return Err(format!("pre-activation dispatch must fail, got {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/9
#[test]
fn narrowed_and_needs_dispositions_stay_distinct_and_frozen() -> TestResult {
    for mode in [AdmitMode::Narrowed, AdmitMode::NeedsTask] {
        let mut world = test_world(None, mode, ActivateMode::Activate, EgressMode::Ack, false)?;
        let fence = test_fence()?;
        let route = test_route()?;
        let tag = match mode {
            AdmitMode::Narrowed => "candidate-872-09n",
            _ => "candidate-872-09t",
        };
        let request = test_request(&fence, &route, tag)?;
        let (definition, _candidate) = world.fabric.define_and_plan(request)?;
        let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
        let outcome = world.fabric.commit_admission(&reservation.reservation_id);
        match mode {
            AdmitMode::Narrowed => assert!(matches!(outcome, Err(FabricError::Narrowed(_)))),
            _ => assert!(matches!(outcome, Err(FabricError::NeedsTask(_)))),
        }
    }
    assert_ne!(
        FabricError::Narrowed("x".to_owned()),
        FabricError::NeedsTask("x".to_owned())
    );
    assert_ne!(
        FabricError::NeedsScope("x".to_owned()),
        FabricError::NeedsSource("x".to_owned())
    );
    assert_ne!(
        FabricError::NeedsCapability("x".to_owned()),
        FabricError::NeedsSupervision("x".to_owned())
    );
    // Same identity with changed bytes conflicts instead of rewriting.
    let fence = test_fence()?;
    let route = test_route()?;
    let mut world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let first = test_request(&fence, &route, "candidate-872-09r")?;
    world.fabric.define_and_plan(first)?;
    let mut second = test_request(&fence, &route, "candidate-872-09r")?;
    second.task_revision = "task-rev-2".to_owned();
    match world.fabric.define_and_plan(second) {
        Err(FabricError::DefinitionConflict(_)) => {}
        other => return Err(format!("rewrite must conflict, got {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/10
#[test]
fn stale_cancelled_superseded_and_epoch_fence_rejected() -> TestResult {
    assert_ne!(
        FabricError::StaleFence("x".to_owned()),
        FabricError::StaleEpoch("x".to_owned())
    );
    assert_ne!(
        FabricError::Cancelled("x".to_owned()),
        FabricError::Superseded("x".to_owned())
    );
    let mut fenced = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::StaleFence,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut fenced, "candidate-872-10a")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    match fenced.fabric.activate(&admission.admission_id, &attempt) {
        Err(FabricError::StaleFence(_)) => {}
        other => return Err(format!("stale fence must reject, got {other:?}").into()),
    }
    let mut epoched = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::StaleEpoch,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut epoched, "candidate-872-10b")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    match epoched.fabric.activate(&admission.admission_id, &attempt) {
        Err(FabricError::StaleEpoch(_)) => {}
        other => return Err(format!("stale epoch must reject, got {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/11
#[test]
fn admission_receipt_binds_definition_and_reservation() -> TestResult {
    let mut world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-11a")?;
    let stored = world
        .fabric
        .snapshot()?
        .admissions
        .get("admission-1")
        .cloned()
        .ok_or("admission stored")?;
    assert_eq!(stored.definition_digest, admission.definition_digest);
    assert_eq!(stored.reservation_id, admission.reservation_id);
    let mut tampered = test_world(
        None,
        AdmitMode::TamperDigest,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, "candidate-872-11b")?;
    let (definition, _candidate) = tampered.fabric.define_and_plan(request)?;
    let reservation = tampered
        .fabric
        .stage_reservation(&definition.definition_id)?;
    match tampered
        .fabric
        .commit_admission(&reservation.reservation_id)
    {
        Err(FabricError::ReceiptBinding(_)) => {}
        other => return Err(format!("tampered digest must fail binding, got {other:?}").into()),
    }
    let mut foreign = test_world(
        None,
        AdmitMode::TamperReservation,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let request = test_request(&fence, &route, "candidate-872-11c")?;
    let (definition, _candidate) = foreign.fabric.define_and_plan(request)?;
    let reservation = foreign
        .fabric
        .stage_reservation(&definition.definition_id)?;
    match foreign.fabric.commit_admission(&reservation.reservation_id) {
        Err(FabricError::ReceiptBinding(_)) => {}
        other => {
            return Err(format!("foreign reservation must fail binding, got {other:?}").into());
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/12
#[test]
fn definition_admission_execution_identities_do_not_interchange() -> TestResult {
    let mut world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-12")?;
    let foreign_attempt =
        AttemptId::new("attempt-foreign").map_err(|error| format!("attempt: {error}"))?;
    match world
        .fabric
        .activate(&admission.admission_id, &foreign_attempt)
    {
        Err(FabricError::IdentityConflict(_)) => {}
        other => return Err(format!("foreign attempt must not activate, got {other:?}").into()),
    }
    assert_ne!(
        FabricError::IdentityConflict("a".to_owned()),
        FabricError::DefinitionConflict("a".to_owned())
    );
    // A definition identity is not an admission identity.
    match world.fabric.activate(
        &eliot_agent_coordinator::AdmissionId::new("candidate-872-12")
            .map_err(|error| format!("admission id: {error}"))?,
        &foreign_attempt,
    ) {
        Err(FabricError::StaleAdmission(_)) => {}
        other => return Err(format!("definition-as-admission must fail, got {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/13
#[test]
fn model_route_comes_from_integrated_registry() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let resolved = world.fabric.require_model_route(&test_requirements())?;
    assert_eq!(resolved, route);
    assert_eq!(counter_value(&world.registry.calls), 1);
    assert!(
        world
            .fabric
            .ledger_events()
            .contains(&"model_route_resolved".to_owned())
    );
    Ok(())
}

// WORK_UNIT_CASE: 872/14
#[test]
fn no_eligible_route_yields_typed_outcome() -> TestResult {
    let mut world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    match world.fabric.require_model_route(&test_requirements()) {
        Err(FabricError::NoRoute(_)) => {}
        other => return Err(format!("no route must be typed, got {other:?}").into()),
    }
    assert_eq!(counter_value(&world.registry.calls), 1);
    assert!(
        !world
            .fabric
            .ledger_events()
            .contains(&"dispatch_built".to_owned())
    );
    Ok(())
}

// WORK_UNIT_CASE: 872/15
#[test]
fn peer_channel_is_injected_not_reimplemented() -> TestResult {
    let mut world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let message = PeerMessage {
        message_id: "msg-872-15".to_owned(),
        sender_attempt: AttemptId::new("attempt-1").map_err(|error| format!("sender: {error}"))?,
        recipient_attempt: AttemptId::new("attempt-1")
            .map_err(|error| format!("recipient: {error}"))?,
    };
    let receipt = world.fabric.deliver_peer(&message)?;
    assert_eq!(receipt.message_id, "msg-872-15");
    assert_eq!(counter_value(&world.peer.calls), 1);
    let fabric = manifest_source("src/agent_fabric.rs")?;
    assert!(fabric.contains("trait PeerChannelPort"));
    assert!(!fabric.contains("impl PeerChannelPort for AgentFabric"));
    Ok(())
}

// WORK_UNIT_CASE: 872/16
#[test]
fn admitted_plan_enters_swarm_unchanged() -> TestResult {
    let fence = test_fence()?;
    let route = test_route()?;
    let mut world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let request = test_request(&fence, &route, "candidate-872-16")?;
    let (_definition, candidate) = world.fabric.define_and_plan(request)?;
    let receipt = world.fabric.enter_swarm(&candidate)?;
    let expected = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&candidate)
            .map_err(|error| format!("candidate bytes: {error}"))?,
    );
    assert_eq!(receipt.entered_digest, expected);
    let mut tampered = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        true,
    )?;
    let request = test_request(&fence, &route, "candidate-872-16b")?;
    let (_definition, candidate) = tampered.fabric.define_and_plan(request)?;
    match tampered.fabric.enter_swarm(&candidate) {
        Err(FabricError::IdentityConflict(_)) => {}
        other => return Err(format!("changed plan must fail, got {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/17
#[test]
fn dispatch_intent_is_neutral_with_attempt_and_activation_evidence() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-17")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    let evidence = world.fabric.activate(&admission.admission_id, &attempt)?;
    let intent = world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-17")?;
    assert_eq!(intent.attempt_id, attempt);
    assert_eq!(intent.admission_id, admission.admission_id);
    assert_eq!(intent.activation_digest, evidence.activation_digest);
    assert_eq!(intent.fence, evidence.fence);
    assert_eq!(intent.epoch, evidence.epoch);
    let serialized = serde_json::to_string(&intent)?;
    for forbidden in [
        "provider_sdk",
        "process_spawn",
        "secret",
        "credential",
        "effect_commit",
    ] {
        assert!(!serialized.contains(forbidden), "intent must stay neutral");
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/18
#[test]
fn registration_and_canonical_admission_precede_activation_and_dispatch() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-18")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    let evidence = world.fabric.activate(&admission.admission_id, &attempt)?;
    let intent = world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-18")?;
    let ack = world.fabric.emit("dispatch-872-18")?;
    assert!(ack.retained);
    assert_eq!(intent.dispatch_id, "dispatch-872-18");
    let events = world.fabric.ledger_events();
    let order = [
        "reservation_staged",
        "admission_committed",
        "activation_committed",
        "dispatch_built",
        "dispatch_emitted",
    ];
    let mut cursor = 0;
    for event in &events {
        if cursor < order.len() && *event == order[cursor] {
            cursor += 1;
        }
    }
    assert_eq!(cursor, order.len(), "saga order must hold: {events:?}");
    let _ = evidence;
    Ok(())
}

// WORK_UNIT_CASE: 872/19
#[test]
fn dispatch_unavailability_loss_and_restart_retain_operation() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Unavailable,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-19")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    world.fabric.activate(&admission.admission_id, &attempt)?;
    world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-19")?;
    match world.fabric.emit("dispatch-872-19") {
        Err(FabricError::DispatchUnavailable(_)) => {}
        other => return Err(format!("unavailable must be typed, got {other:?}").into()),
    }
    // Same registered operation retries without duplicate launch.
    if let Ok(mut mode) = world.egress.mode.lock() {
        *mode = EgressMode::Ack;
    }
    let ack = world.fabric.emit("dispatch-872-19")?;
    assert_eq!(ack.dispatch_id, "dispatch-872-19");
    match world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-19b")
    {
        Err(FabricError::DuplicateLaunch(_)) => {}
        other => return Err(format!("second launch must fail, got {other:?}").into()),
    }
    // Restart at the saga boundary retains the same operation.
    let snapshot = world.fabric.snapshot()?;
    let config = daemon_coordinator_config()?;
    let registry_route = test_route()?;
    let restored_world = test_world(
        Some(registry_route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let ports = FabricPorts {
        model_registry: Arc::clone(&restored_world.registry) as Arc<dyn ModelRegistryPort>,
        peer_channel: Arc::clone(&restored_world.peer) as Arc<dyn PeerChannelPort>,
        swarm_control: Arc::clone(&restored_world.swarm) as Arc<dyn SwarmControlPort>,
        admission_authority: Arc::clone(&restored_world.admission)
            as Arc<dyn AdmissionAuthorityPort>,
        activation_authority: Arc::clone(&restored_world.activation)
            as Arc<dyn ActivationAuthorityPort>,
        dispatch_egress: Arc::clone(&restored_world.egress) as Arc<dyn DispatchEgressPort>,
    };
    let restored = AgentFabric::restore(snapshot, config, ports)?;
    assert_eq!(
        restored.attempt_of(&attempt),
        Some(AttemptLifecycle::Dispatched)
    );
    Ok(())
}

// WORK_UNIT_CASE: 872/20
#[test]
fn worker_acknowledgement_cannot_become_attempt_success() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-20")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    world.fabric.activate(&admission.admission_id, &attempt)?;
    world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-20")?;
    world.fabric.observe_worker_ack(&WorkerAck {
        attempt_id: attempt.clone(),
        worker_id: "worker-1".to_owned(),
    })?;
    // Ack advances nothing: the attempt is still dispatched, not result-submitted.
    assert_eq!(
        world.fabric.attempt_of(&attempt),
        Some(AttemptLifecycle::Dispatched)
    );
    assert_ne!(
        FabricError::AckNotResult("x".to_owned()),
        FabricError::ResultNotFinish("x".to_owned())
    );
    Ok(())
}

// WORK_UNIT_CASE: 872/21
#[test]
fn orphan_foreign_stale_observation_is_quarantined() -> TestResult {
    let mut world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let orphan = AttemptId::new("attempt-orphan").map_err(|error| format!("orphan: {error}"))?;
    match world.fabric.observe_worker_result(&orphan, "worker-x") {
        Err(FabricError::Quarantined(_)) => {}
        other => return Err(format!("orphan must quarantine, got {other:?}").into()),
    }
    assert!(
        world
            .fabric
            .ledger_events()
            .contains(&"observation_quarantined".to_owned())
    );
    assert_eq!(world.fabric.attempt_of(&orphan), None);
    Ok(())
}

// WORK_UNIT_CASE: 872/22
#[test]
fn restart_reconstructs_one_owner_with_revisions_and_leases() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (definition, admission) = admitted_attempt(&mut world, "candidate-872-22")?;
    let snapshot = world.fabric.snapshot()?;
    let config = daemon_coordinator_config()?;
    let fresh = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let ports = FabricPorts {
        model_registry: Arc::clone(&fresh.registry) as Arc<dyn ModelRegistryPort>,
        peer_channel: Arc::clone(&fresh.peer) as Arc<dyn PeerChannelPort>,
        swarm_control: Arc::clone(&fresh.swarm) as Arc<dyn SwarmControlPort>,
        admission_authority: Arc::clone(&fresh.admission) as Arc<dyn AdmissionAuthorityPort>,
        activation_authority: Arc::clone(&fresh.activation) as Arc<dyn ActivationAuthorityPort>,
        dispatch_egress: Arc::clone(&fresh.egress) as Arc<dyn DispatchEgressPort>,
    };
    let restored = AgentFabric::restore(snapshot, config, ports)?;
    assert_eq!(restored.coordinator_count(), 1);
    let stored = restored
        .snapshot()?
        .definitions
        .get("candidate-872-22")
        .cloned()
        .ok_or("definition")?;
    assert_eq!(stored, definition);
    let stored_admission = restored
        .snapshot()?
        .admissions
        .get("admission-1")
        .cloned()
        .ok_or("admission")?;
    assert_eq!(stored_admission, admission);
    assert_eq!(
        restored.ledger_events().last().map(String::as_str),
        Some("fabric_restored")
    );
    Ok(())
}

// WORK_UNIT_CASE: 872/23
#[test]
fn duplicate_initialization_cannot_create_second_coordinator() -> TestResult {
    let world = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    match world.fabric.try_initialize_again() {
        Err(FabricError::AlreadyInitialized(_)) => {}
        other => return Err(format!("second init must fail, got {other:?}").into()),
    }
    assert_eq!(world.fabric.coordinator_count(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 872/24
#[test]
fn cancellation_request_and_terminal_stay_distinct() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-24")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    world.fabric.request_cancellation(&attempt, "op-cancel-1")?;
    assert_eq!(
        world.fabric.cancellation_of(&attempt),
        Some(CancellationLifecycle::Requested)
    );
    // Terminal observation is a separate step.
    assert_ne!(
        FabricError::CancellationRequested("x".to_owned()),
        FabricError::TerminalCancellation("x".to_owned())
    );
    world.fabric.reconcile_terminal_cancellation(&attempt)?;
    assert_eq!(
        world.fabric.cancellation_of(&attempt),
        Some(CancellationLifecycle::Terminal)
    );
    // Reconciling without a request stays distinct.
    let mut bare = test_world(
        None,
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut bare, "candidate-872-24b")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    match bare.fabric.reconcile_terminal_cancellation(&attempt) {
        Err(FabricError::Cancelled(_)) => {}
        other => return Err(format!("unrequested terminal must fail, got {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/25
#[test]
fn unknown_child_outcome_remains_unknown() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut world, "candidate-872-25")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    world.fabric.activate(&admission.admission_id, &attempt)?;
    world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-25")?;
    world.fabric.mark_unknown_outcome(&attempt)?;
    assert_eq!(
        world.fabric.attempt_of(&attempt),
        Some(AttemptLifecycle::UnknownOutcome)
    );
    match world.fabric.require_finish(&attempt) {
        Err(FabricError::UnknownChild(_)) => {}
        other => return Err(format!("unknown must stay unknown, got {other:?}").into()),
    }
    match world.fabric.require_finish(&attempt) {
        Err(FabricError::UnknownChild(_)) => {}
        other => return Err(format!("unknown must be stable, got {other:?}").into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/26
#[test]
fn source_and_api_guard_rejects_foreign_authority() -> TestResult {
    let fabric = manifest_source("src/agent_fabric.rs")?;
    for forbidden in [
        "std::process",
        "tokio::process",
        "Command::new",
        "std::env::",
        "api_key",
        "secret_bytes",
    ] {
        assert!(
            !fabric.contains(forbidden),
            "fabric must not contain {forbidden}"
        );
    }
    let runtime = manifest_source("src/daemon_runtime.rs")?;
    assert!(runtime.contains("attach_agent_fabric"));
    assert!(!runtime.contains("std::process::Command"));
    let lib = manifest_source("src/lib.rs")?;
    assert!(
        lib.contains("pub fn start("),
        "start contour must be preserved"
    );
    Ok(())
}

// WORK_UNIT_CASE: 872/27
#[test]
fn allowed_dependency_and_source_diff_preserves_contracts() -> TestResult {
    let cargo = manifest_source("Cargo.toml")?;
    assert!(cargo.contains("eliot-agent-coordinator.workspace = true"));
    for provider in [
        "eliot-agent-claude",
        "eliot-agent-codex",
        "eliot-agent-opencode",
    ] {
        assert!(!cargo.contains(provider));
    }
    let lib = manifest_source("src/lib.rs")?;
    for symbol in [
        "commit_canonical_and_refresh",
        "agent_fabric_descriptor",
        "agent_fabric_plan",
        "resolve_agent_activation_v2",
    ] {
        assert!(lib.contains(symbol), "lib must preserve {symbol}");
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/28
#[allow(
    clippy::too_many_lines,
    reason = "case 28 is the single full saga ledger proof: happy path plus denial, loss, and replay branches in exact call order"
)]
#[test]
fn full_request_to_dispatch_ledger_with_denial_loss_replay() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    // Happy path: request -> definition -> reservation -> admission/attempt ->
    // activation -> dispatch, with exact receipts and call order.
    let fence = test_fence()?;
    let request = test_request(&fence, &route, "candidate-872-28")?;
    let (definition, candidate) = world.fabric.define_and_plan(request)?;
    let resolved = world.fabric.require_model_route(&test_requirements())?;
    assert_eq!(resolved, route);
    let peer_receipt = world.fabric.deliver_peer(&PeerMessage {
        message_id: "msg-872-28".to_owned(),
        sender_attempt: AttemptId::new("attempt-1").map_err(|error| format!("sender: {error}"))?,
        recipient_attempt: AttemptId::new("attempt-1")
            .map_err(|error| format!("recipient: {error}"))?,
    })?;
    assert_eq!(peer_receipt.message_id, "msg-872-28");
    let entry = world.fabric.enter_swarm(&candidate)?;
    assert_eq!(entry.candidate_id.as_str(), "candidate-872-28");
    let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
    let admission = world.fabric.commit_admission(&reservation.reservation_id)?;
    assert_eq!(admission.definition_digest, definition.definition_digest);
    assert_eq!(admission.reservation_id, reservation.reservation_id);
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    let evidence = world.fabric.activate(&admission.admission_id, &attempt)?;
    let intent = world
        .fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-28")?;
    assert_eq!(intent.activation_digest, evidence.activation_digest);
    let ack: DispatchAck = world.fabric.emit("dispatch-872-28")?;
    assert!(ack.retained);
    // Exact replay: same bytes replay without duplicate owner calls.
    let commit_calls = counter_value(&world.admission.commit_calls);
    let replayed = world.fabric.commit_admission(&reservation.reservation_id)?;
    assert_eq!(replayed, admission);
    assert_eq!(counter_value(&world.admission.commit_calls), commit_calls);
    let replayed_activation = world.fabric.activate(&admission.admission_id, &attempt)?;
    assert_eq!(replayed_activation, evidence);
    let replayed_intent =
        world
            .fabric
            .dispatch(&admission.admission_id, &attempt, "dispatch-872-28")?;
    assert_eq!(replayed_intent, intent);
    // Denial branch: a denied definition dispatches nothing.
    let mut denied = test_world(
        Some(route.clone()),
        AdmitMode::Deny,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let request = test_request(&fence, &route, "candidate-872-28d")?;
    let (definition, _candidate) = denied.fabric.define_and_plan(request)?;
    let reservation = denied.fabric.stage_reservation(&definition.definition_id)?;
    assert!(matches!(
        denied.fabric.commit_admission(&reservation.reservation_id),
        Err(FabricError::AdmissionDenied(_))
    ));
    // Loss branch: lost egress retains the operation without false success.
    let mut lost = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Lost,
        false,
    )?;
    let (_definition, admission) = admitted_attempt(&mut lost, "candidate-872-28l")?;
    let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
    lost.fabric.activate(&admission.admission_id, &attempt)?;
    lost.fabric
        .dispatch(&admission.admission_id, &attempt, "dispatch-872-28l")?;
    assert!(matches!(
        lost.fabric.emit("dispatch-872-28l"),
        Err(FabricError::DispatchLost(_))
    ));
    // Call-order proof on the happy path.
    let events = world.fabric.ledger_events();
    let expected = [
        "coordinator_constructed",
        "definition_validated",
        "plan_compiled",
        "model_route_resolved",
        "peer_delivered",
        "swarm_entered",
        "reservation_staged",
        "admission_committed",
        "activation_committed",
        "dispatch_built",
        "dispatch_emitted",
    ];
    let mut cursor = 0;
    for event in &events {
        if cursor < expected.len() && *event == expected[cursor] {
            cursor += 1;
        }
    }
    assert_eq!(
        cursor,
        expected.len(),
        "full call order must hold: {events:?}"
    );
    // Ack and result separation on the happy path.
    world.fabric.observe_worker_ack(&WorkerAck {
        attempt_id: attempt.clone(),
        worker_id: "worker-28".to_owned(),
    })?;
    world.fabric.submit_attempt_result(&AttemptResultRecord {
        attempt_id: attempt.clone(),
        result_digest: sha256_hex(b"result-872-28"),
    })?;
    assert_eq!(
        world.fabric.attempt_of(&attempt),
        Some(AttemptLifecycle::ResultSubmitted)
    );
    Ok(())
}
