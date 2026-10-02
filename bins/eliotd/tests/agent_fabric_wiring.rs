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
use eliot_agent_contracts::{
    ExecutionUpdateProposal, RevisionId, SemanticCeilings, SwarmAdmissionId, SwarmCoordinatorLease,
    SwarmDefinitionId, SwarmExecutionId, SwarmExecutionRevision, SwarmExecutionState,
    SwarmPlanAdmission, SwarmPlanDefinition, SwarmPlanDefinitionLifecycle, TaskControllerLease,
};
use eliot_agent_coordinator::{
    CandidateId, CoordinatorConfig, LearningRole, RecipeId, RecipeManifest, RoleProfileId,
    RoleProfileManifest, RouteCandidateEvidence, StaffingLaneRequest, StaffingPlanCandidate,
    StaffingPlanRequest, WorkClass,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_governor::{
    CapabilityEvidenceRecord, CapabilitySource, CapabilityStatus, RouteScopeFingerprint,
};
use eliot_security_contracts::PrivacyClass;
use eliot_store_api::{
    CommitId, OperationId, OperationManifestDigest, OrderingHead, Resubmission,
    SwarmOwnerAuthorization, SwarmOwnerRevision, SwarmSemanticOwnerKind, TransitionClass,
    WriteReceipt, WriteReceiptStatus,
};
use eliotd::{
    ActivationAuthorityPort, ActivationEvidence, AdmissionAuthorityPort, AgentFabric,
    AttemptLifecycle, AttemptResultRecord, COORDINATOR_CRATE, CancellationLifecycle, DispatchAck,
    DispatchEgressPort, DispatchIntent, FABRIC_CAPACITY_IDENTITY, FABRIC_CAPACITY_REVISION,
    FabricAdmission, FabricError, FabricPorts, FabricSnapshot, GovernorCapabilityAdmission,
    ModelRegistryPort, PeerChannelPort, PeerMessage, PeerReceipt, Reservation, RouteRequirements,
    SwarmControlPort, SwarmDefinition, SwarmEntryReceipt, WorkerAck, daemon_coordinator_config,
    plan_candidate, prereq_ports, semantic_revision_store::SEMANTIC_REVISION_DIR,
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
    let role_effects = work.effect_ceiling.clone();
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
            schema_identity: fixture_schema_identity("recipe-872")?,
            content_digest: test_digest("recipe-manifest-872")?,
            route_policy_revision: RevisionId::new("route-policy-1")
                .map_err(|error| format!("route policy: {error}"))?,
            max_lanes: 1,
            max_descendants: 8,
            stage_templates: vec![fixture_reference("stage-template")?],
            work_item_templates: vec![fixture_reference("work-item-template")?],
            dependency_templates: vec![fixture_reference("dependency-template")?],
            merge_templates: vec![fixture_reference("merge-template")?],
            eligible_route_classes: vec!["provider-fabric-a".to_owned()],
            expansion_conditions: vec![fixture_reference("expansion-condition")?],
            contraction_conditions: vec![fixture_reference("contraction-condition")?],
            verifier_requirements: vec![fixture_reference("verifier-requirement")?],
            audit_requirements: vec![fixture_reference("audit-requirement")?],
            budget: test_budget(),
            partial_result_behavior: fixture_reference("partial-result-behavior")?,
            failure_behavior: fixture_reference("failure-behavior")?,
            role_profiles: vec![RoleProfileManifest {
                role_id: RoleProfileId::new("role-1").map_err(|error| format!("role: {error}"))?,
                manifest_revision: RevisionId::new("role-rev-role-1")
                    .map_err(|error| format!("role rev: {error}"))?,
                schema_identity: fixture_schema_identity("role-1")?,
                content_digest: test_digest("role-manifest-1")?,
                required_competence: vec!["rust".to_owned()],
                allowed_operations: vec![fixture_reference("role-operation")?],
                allowed_effects: role_effects,
                independence_requirement: fixture_reference("independence-requirement")?,
                input_schemas: vec![fixture_reference("role-input-schema")?],
                output_schemas: vec![fixture_reference("role-output-schema")?],
                visibility_policy: fixture_reference("visibility-policy")?,
                learning_role: LearningRole::NotApplicable,
                stop_condition: fixture_reference("candidate-submitted")?,
                escalation_policy: fixture_reference("integration-owner")?,
                allowed_route_classes: vec!["provider-fabric-a".to_owned()],
                mutation_capable: false,
            }],
        },
        task_revision: "task-rev-1".to_owned(),
        plan_revision: RevisionId::new("plan-rev-872")
            .map_err(|error| format!("plan rev: {error}"))?,
        state_fence: fence.clone(),
        human_staffing_intent: eliot_agent_coordinator::HumanStaffingIntent {
            preset: eliot_agent_coordinator::StaffingPreset::Balanced,
            per_job_budget: test_budget(),
        },
        privacy_class: PrivacyClass::Private,
        work_class: "swarm".parse().map_err(|error| format!("class: {error}"))?,
        lanes: vec![StaffingLaneRequest {
            work_unit_id: WorkUnitId::new("work-1")
                .map_err(|error| format!("lane work: {error}"))?,
            role_id: RoleProfileId::new("role-1").map_err(|error| format!("lane role: {error}"))?,
            work_class: "swarm".parse().map_err(|error| format!("class: {error}"))?,
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
                route_classes: vec!["provider-fabric-a".to_owned()],
                route_class_evidence_refs: vec!["route-class-evidence-0".to_owned()],
                privacy_classes: vec![PrivacyClass::Private],
                privacy_evidence_refs: vec!["privacy-evidence-0".to_owned()],
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

// Issue #1957: the daemon route gate consults the held capability admission
// on the observed scope. Helpers below mint that scope plus an admission
// holding fresh probe evidence for the `rust` competence above.
const EVIDENCE_NOW: u64 = 10;

fn test_evidence_scope() -> RouteScopeFingerprint {
    RouteScopeFingerprint {
        host_family: Some("fabric-host-1".to_owned()),
        adapter_id: Some("fabric-adapter-id-1".to_owned()),
        protocol_transport: Some("app-server|stdio".to_owned()),
        runtime_hash: Some("fabric-runtime-1".to_owned()),
        adapter_hash: Some("fabric-adapter-1".to_owned()),
        os_architecture: Some("x86_64-windows".to_owned()),
        auth_profile_class: Some("user-broker".to_owned()),
        provider_model_route: Some("provider-fabric-a/model-fabric-a/fixture-account".to_owned()),
        tool_call_id_and_role_ordering: Some("fabric-tool-ordering-1".to_owned()),
        reasoning_continuation_and_compaction: Some("fabric-reasoning-compaction-1".to_owned()),
        feature_flags_and_serializer: Some("fabric-serializer-1".to_owned()),
    }
}

/// Deterministic stand-in for a store-issued evidence revision.
fn test_owner_revision(owner_revision: u64) -> TestResult<eliot_governor::OwnerEvidenceRevision> {
    eliot_governor::OwnerEvidenceRevision::issued(
        owner_revision,
        &eliot_store_api::sha256_hex(&owner_revision.to_be_bytes()),
    )
    .map_err(|error| format!("owner revision: {error}").into())
}
fn test_evidence_admitted() -> TestResult<GovernorCapabilityAdmission> {
    let mut admission = GovernorCapabilityAdmission::new();
    admission.insert(
        CapabilityEvidenceRecord::verified(
            "rust",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            test_evidence_scope(),
            1,
        )
        .map_err(|error| format!("probe evidence: {error}"))?,
        test_owner_revision(1)?,
    );
    Ok(admission)
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
            work_class: definition.work_class,
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
                work_class: reservation.work_class,
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
                work_class: reservation.work_class,
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
                work_class: reservation.work_class,
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
    let resolved = world.fabric.require_model_route(
        &test_requirements(),
        &test_evidence_admitted()?,
        &test_evidence_scope(),
        EVIDENCE_NOW,
    )?;
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
    match world.fabric.require_model_route(
        &test_requirements(),
        &GovernorCapabilityAdmission::new(),
        &test_evidence_scope(),
        EVIDENCE_NOW,
    ) {
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

// WORK_UNIT_CASE: 872/14b — issue #1957: a resolved route still requires
// fresh capability evidence for every competence item before it may
// execute. An empty admission and a declared-only (legacy) admission both
// deny with the typed NoRoute outcome; resolution itself still ran first.
#[test]
fn resolved_route_without_capability_evidence_is_denied() -> TestResult {
    use eliot_config::legacy_capability_import::{
        LegacyCapabilityDeclaration, LegacyScopeFingerprint, import_legacy_declaration,
    };
    use eliot_governor::CapabilityRegistry;

    let route = test_route()?;
    let empty = GovernorCapabilityAdmission::new();
    let mut declared_only = GovernorCapabilityAdmission::new();
    let imported = import_legacy_declaration(&LegacyCapabilityDeclaration {
        skill_id: "rust".to_owned(),
        scope: LegacyScopeFingerprint::default(),
    })
    .map_err(|error| format!("legacy import: {error}"))?;
    let mut declared_registry = CapabilityRegistry::new();
    declared_registry.insert(
        CapabilityEvidenceRecord::from(&imported),
        eliot_governor::OwnerEvidenceRevision::legacy_declared(),
    );
    for retained in declared_registry.retained() {
        declared_only.insert(
            retained.record.clone(),
            eliot_governor::OwnerEvidenceRevision::legacy_declared(),
        );
    }
    assert!(!empty.admit_production_route("rust", &test_evidence_scope(), EVIDENCE_NOW));
    assert!(!declared_only.admit_production_route("rust", &test_evidence_scope(), EVIDENCE_NOW));

    for admission in [&empty, &declared_only] {
        let mut world = test_world(
            Some(route.clone()),
            AdmitMode::Admit,
            ActivateMode::Activate,
            EgressMode::Ack,
            false,
        )?;
        match world.fabric.require_model_route(
            &test_requirements(),
            admission,
            &test_evidence_scope(),
            EVIDENCE_NOW,
        ) {
            Err(FabricError::NoRoute(_)) => {}
            other => return Err(format!("unevidenced route must be denied, got {other:?}").into()),
        }
        // Resolution ran (candidate-only); the evidence gate denied the
        // requirement afterwards.
        assert_eq!(counter_value(&world.registry.calls), 1);
        assert!(
            world
                .fabric
                .ledger_events()
                .contains(&"model_route_resolved".to_owned())
        );
    }
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
    // #1702 W2: this is a plan-only restore with no daemon state root, so no
    // durable revision store is supplied. Retained semantic records stay
    // readable history; publishing a NEW one here would be refused typed.
    let restored = AgentFabric::restore(snapshot, config, ports, None)?;
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
    // #1702 W2: plan-only restore with no daemon state root; see the sibling
    // case above. Retained semantic records stay readable as history.
    let restored = AgentFabric::restore(snapshot, config, ports, None)?;
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
    let resolved = world.fabric.require_model_route(
        &test_requirements(),
        &test_evidence_admitted()?,
        &test_evidence_scope(),
        EVIDENCE_NOW,
    )?;
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

// WORK_UNIT_CASE: 872/29 — I14.1 work classes (issue #1698). Each of the nine
// canonical wire spellings threads as the closed `WorkClass` boundary type
// through definition, reservation, admission and dispatch; the observable
// records identify the same class and serialize to the same wire string.
#[test]
fn work_class_threads_through_definition_reservation_admission_and_dispatch() -> TestResult {
    let classes = WorkClass::ALL_WIRE_SPELLINGS;
    for (index, class) in classes.iter().enumerate() {
        let route = test_route()?;
        let mut world = test_world(
            Some(route.clone()),
            AdmitMode::Admit,
            ActivateMode::Activate,
            EgressMode::Ack,
            false,
        )?;
        let fence = test_fence()?;
        let mut request = test_request(&fence, &route, &format!("candidate-1698-{index}"))?;
        let expected: WorkClass = (*class)
            .parse()
            .map_err(|error| format!("canonical class must parse: {error}"))?;
        request.work_class = expected;
        for lane in &mut request.lanes {
            lane.work_class = expected;
        }
        let (definition, _candidate) = world.fabric.define_and_plan(request)?;
        assert_eq!(definition.work_class, expected);
        assert_eq!(definition.work_class.as_wire_str(), *class);
        let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
        assert_eq!(reservation.work_class, expected);
        let admission = world.fabric.commit_admission(&reservation.reservation_id)?;
        assert_eq!(admission.work_class, expected);
        let attempt = admission.attempt_ids.first().ok_or("one attempt")?.clone();
        world.fabric.activate(&admission.admission_id, &attempt)?;
        let intent = world.fabric.dispatch(
            &admission.admission_id,
            &attempt,
            &format!("dispatch-1698-{index}"),
        )?;
        assert_eq!(intent.work_class, expected);
    }
    Ok(())
}

// WORK_UNIT_CASE: 872/30 — I14.1 work classes (issue #1698). An unknown class
// is unrepresentable in the `WorkClass` boundary type: the validated
// constructor rejects with the typed coordinator error at decode ingress
// before any definition is frozen, so no reservation is staged, no launch
// occurs, no capacity is consumed, and no silent default is substituted.
#[test]
fn work_class_unknown_rejects_before_launch_without_capacity() -> TestResult {
    let route = test_route()?;
    let world = test_world(
        Some(route.clone()),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let fence = test_fence()?;
    let request = test_request(&fence, &route, "candidate-1698-unknown")?;
    // The wire `String` converts solely through the validated constructor.
    match WorkClass::parse_wire("proton") {
        Err(eliot_agent_coordinator::CoordinatorError::UnknownWorkClass(value)) => {
            assert_eq!(value, "proton");
        }
        other => return Err(format!("unknown class must reject typed, got {other:?}").into()),
    }
    // The same rejection fires at serde ingress for a request-shaped payload.
    let mut tampered =
        serde_json::to_value(&request).map_err(|error| format!("encode: {error}"))?;
    tampered["work_class"] = serde_json::json!("proton");
    let decoded: Result<StaffingPlanRequest, _> = serde_json::from_value(tampered);
    let message = decoded
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        message.contains("unknown work class: proton"),
        "decode must reject unknown class, got {message:?}"
    );
    assert_eq!(counter_value(&world.admission.stage_calls), 0);
    assert_eq!(counter_value(&world.admission.commit_calls), 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Issue #1702 A1: the acceptance path of the contract refusal, and the
// reachability gap it sits behind.
//
// `AgentFabric::record_semantic_execution` is the ONE path that accepts a
// coordinator `SwarmExecutionRevision` and publishes it through the canonical
// `SemanticRevisionStore::commit`. A second revision presented under an
// execution identity the fabric already holds is an execution UPDATE, so that
// path runs `AgentFabric::check_semantic_execution_update` — which applies the
// old-wave disposition gate and then the contract owner's own
// `check_execution_update` — before the revision can become current. The
// fixtures below build the real records and the real durable Store evidence
// those methods require; no authority is short-circuited.
//
// That path has NO production caller today, and these cases do not make it
// one. No production code mints a `SwarmExecutionRevision` or a
// `SwarmOwnerRevision`, so no binary can present one: the durable owner revision
// it requires is a `NamedMutationOperation::ApplySwarmOwnerRevisions` commit
// and no binary executes that operation. The execution record is owned by the
// AgentCoordinator; the durable owner-revision commit is named by no crate.
// What these tests therefore prove is that the refusal is correct and
// reachable-with-real-evidence WHEN a producer exists — they are not evidence
// that production enforces it today.
// ---------------------------------------------------------------------------

const SWARM_TASK_CONTROLLER: &str = "task-controller-1702";
const SWARM_COORDINATOR: &str = "swarm-coordinator-1702";

fn swarm_ceilings() -> SemanticCeilings {
    SemanticCeilings {
        privacy_class: "privacy-internal".to_owned(),
        budget_ref: "budget-ref-1702".to_owned(),
        route_classes: vec!["route-class-a".to_owned()],
        max_depth: 3,
        max_fanout: 4,
        max_wip: 2,
    }
}

/// A frozen Task-Controller definition whose `definition_digest` really binds
/// its own frozen content, so the contract validator accepts it.
fn frozen_swarm_definition(fence: &StateFence, suffix: &str) -> TestResult<SwarmPlanDefinition> {
    let mut definition = SwarmPlanDefinition {
        definition_id: SwarmDefinitionId::new(format!("definition-1702-{suffix}"))
            .expect("definition id"),
        definition_revision: RevisionId::new("1").expect("definition revision"),
        lifecycle: SwarmPlanDefinitionLifecycle::Frozen,
        task_id: format!("task-1702-{suffix}"),
        task_revision: "1".to_owned(),
        recipe_id: "recipe-1702".to_owned(),
        recipe_revision: RevisionId::new("1").expect("recipe revision"),
        controller: TaskControllerLease {
            holder: SWARM_TASK_CONTROLLER.to_owned(),
            epoch: 1,
        },
        objective_ref: "objective-1702".to_owned(),
        acceptance_refs: vec!["acceptance-1702-a".to_owned()],
        root_context_revision: "root-1702".to_owned(),
        work_graph_digest: sha256_hex(b"work-graph-1702"),
        definition_digest: String::new(),
        ceilings: swarm_ceilings(),
        stop_conditions_digest: sha256_hex(b"stop-conditions-1702"),
        supersedes: None,
        state_fence: fence.clone(),
    };
    definition.definition_digest = definition
        .content_digest()
        .expect("definition content digest");
    Ok(definition)
}

fn admitted_swarm_admission(
    definition: &SwarmPlanDefinition,
    fence: &StateFence,
) -> SwarmPlanAdmission {
    SwarmPlanAdmission::admit_for(
        definition,
        SwarmAdmissionId::new("admission-1702").expect("admission id"),
        definition.ceilings.clone(),
        "governor-receipt-1702".to_owned(),
        fence.clone(),
    )
    .expect("admitted admission")
}

/// The real owner-issued Store evidence one semantic write requires: canonical
/// record bytes, the owner revision that commits exactly those bytes, and a
/// `Committed` task-control receipt carrying that revision's ordering head.
struct DurableSwarmCommit {
    revision: SwarmOwnerRevision,
    receipt: WriteReceipt,
}

fn durable_swarm_commit<T: serde::Serialize>(
    owner_kind: SwarmSemanticOwnerKind,
    owner_id: &str,
    record: &T,
    fence: &StateFence,
    revision: u64,
) -> TestResult<DurableSwarmCommit> {
    let value = serde_json::to_value(record).map_err(|error| format!("encode record: {error}"))?;
    let bytes = eliot_contracts::canonical_json_bytes(&value)?;
    let content_digest = sha256_hex(&bytes);
    let canonical_request_hash = sha256_hex(bytes.as_slice());
    let owner_revision = SwarmOwnerRevision {
        owner_kind,
        authorization: SwarmOwnerAuthorization {
            owner_kind,
            presenter: match owner_kind {
                SwarmSemanticOwnerKind::AgentCoordinator => SWARM_COORDINATOR.to_owned(),
                SwarmSemanticOwnerKind::TaskController => SWARM_TASK_CONTROLLER.to_owned(),
                SwarmSemanticOwnerKind::Governor => "governor-1702".to_owned(),
            },
            epoch: 1,
        },
        owner_id: owner_id.to_owned(),
        revision,
        expected_predecessor: revision
            .checked_sub(1)
            .filter(|predecessor| *predecessor > 0),
        content_digest,
        record_json: String::from_utf8(bytes)
            .map_err(|error| format!("canonical record bytes are not utf-8: {error}"))?,
    };
    owner_revision
        .validate()
        .map_err(|error| format!("owner revision fixture must validate: {error}"))?;
    let scope = owner_revision.ordering_scope()?;
    let receipt = WriteReceipt {
        operation_id: OperationId::new(&format!("operation-1702-{owner_id}-{revision}"))?,
        idempotency_key: format!("idempotency-1702-{owner_id}-{revision}"),
        canonical_request_hash,
        transition_class: TransitionClass::TaskControl,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new(&format!(
            "commit-1702-{owner_id}-{revision}"
        ))?),
        state_fence: fence.clone(),
        ordering_sequences: vec![OrderingHead {
            scope,
            sequence: revision,
            state_fence: fence.clone(),
        }],
        revision_before_after: Vec::new(),
        applied_command_ids: vec![format!("command-1702-{owner_id}")],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: OperationManifestDigest::new(&format!(
            "manifest-1702-{owner_id}"
        ))?,
        admission_digest: sha256_hex(b"admission-digest-1702"),
        mutation_plan_digest: sha256_hex(b"mutation-plan-digest-1702"),
        semantic_source_revisions: Vec::new(),
        policy_config_schema_versions: eliot_store_api::PolicyConfigSchemaVersions {
            policy_revision: fence.policy_revision,
            config_profile: eliot_store_api::OPERATION_CATALOGUE_PROFILE.to_owned(),
            schema_revision: eliot_store_api::CONTRACT_VERSION,
        },
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("2026-01-01T00:00:00Z".to_owned()),
        envelope: None,
    };
    receipt
        .validate()
        .map_err(|error| format!("receipt fixture must validate: {error}"))?;
    Ok(DurableSwarmCommit {
        revision: owner_revision,
        receipt,
    })
}

/// A private protected state root for one test's owner-separated revision
/// envelope. The store writes under a protected runtime path lease whose root
/// is this exact directory, so the test's envelope lands on real durable
/// storage rather than in-memory state, and both are torn down with the value.
struct SwarmStateRoot {
    root: std::path::PathBuf,
    _override: eliot_platform_windows::test_support::ProtectedRootOverride,
}

impl SwarmStateRoot {
    fn new(suffix: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "eliotd-1702-semantic-{suffix}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)
            .map_err(|error| format!("state root {}: {error}", root.display()))?;
        // The guard canonicalizes its own test root through
        // `canonical_windows_path`, which drops the `\\?\` verbatim prefix that
        // `std::fs::canonicalize` hands back. Resolving the root through that
        // same helper keeps the state root and the protected contour in one
        // path form, so the leaf this store owns stays inside the contour
        // instead of being refused as outside it.
        let root = eliot_platform_windows::canonical_windows_path(&root)
            .map_err(|error| format!("canonicalize state root {}: {error}", root.display()))?;
        // The store owns `<state root>/<SEMANTIC_REVISION_DIR>/owner-revisions.json`
        // and does not create that directory itself, while the protected runtime
        // path lease resolves the absent leaf's parent to decide the contour.
        // This fixture owns the root, so it supplies the shape the store expects
        // and the lease has a real parent to resolve. `Drop` removes the whole
        // tree, so the directory is torn down with the root.
        let revision_dir = root.join(SEMANTIC_REVISION_DIR);
        std::fs::create_dir_all(&revision_dir)
            .map_err(|error| format!("revision directory {}: {error}", revision_dir.display()))?;
        let override_root = eliot_platform_windows::test_support::override_protected_root(&root);
        Ok(Self {
            root,
            _override: override_root,
        })
    }

    fn path(&self) -> &std::path::Path {
        &self.root
    }
}

impl Drop for SwarmStateRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Registers, admits and launches one live semantic wave, returning the running
/// execution revision this fabric now holds as current.
fn admitted_running_execution(
    fabric: &mut AgentFabric,
    fence: &StateFence,
    suffix: &str,
    revision: u64,
) -> TestResult<SwarmExecutionRevision> {
    let definition = frozen_swarm_definition(fence, suffix)?;
    let admission = admitted_swarm_admission(&definition, fence);
    let execution = SwarmExecutionRevision::begin(
        &definition,
        &admission,
        SwarmExecutionId::new("execution-1702").expect("execution id"),
        SwarmCoordinatorLease {
            holder: SWARM_COORDINATOR.to_owned(),
            epoch: 1,
        },
        RevisionId::new("1").expect("wave"),
        sha256_hex(b"coverage-1702-empty"),
    )
    .expect("execution begun");
    let running = SwarmExecutionRevision {
        state: SwarmExecutionState::Running,
        ..execution
    };

    let definition_commit = durable_swarm_commit(
        SwarmSemanticOwnerKind::TaskController,
        definition.definition_id.as_str(),
        &definition,
        fence,
        revision,
    )?;
    fabric.register_semantic_definition(
        definition.clone(),
        SWARM_TASK_CONTROLLER,
        1,
        &definition_commit.revision,
        &definition_commit.receipt,
    )?;
    let admission_commit = durable_swarm_commit(
        SwarmSemanticOwnerKind::Governor,
        admission.admission_id.as_str(),
        &admission,
        fence,
        revision,
    )?;
    fabric.bind_semantic_admission(
        admission.clone(),
        &admission_commit.revision,
        &admission_commit.receipt,
    )?;
    let execution_commit = durable_swarm_commit(
        SwarmSemanticOwnerKind::AgentCoordinator,
        running.execution_id.as_str(),
        &running,
        fence,
        revision,
    )?;
    fabric.record_semantic_execution(
        running.clone(),
        SWARM_COORDINATOR,
        1,
        &execution_commit.revision,
        &execution_commit.receipt,
    )?;
    Ok(running)
}

// WORK_UNIT_CASE: 1702/A1 — mechanical execution update is admitted. The
// production caller `AgentFabric::record_semantic_execution` routes a changed
// revision under a held execution identity through the contract refusal before
// accepting it; a coordinator advancing its own running wave — the recorded
// state edge and the coverage handle moving, wave and root unchanged — passes
// that guard and is durably committed, so the update path is reachable rather
// than refused for every input.
#[test]
fn mechanical_semantic_execution_update_is_admitted_and_committed() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let state_root = SwarmStateRoot::new("advance")?;
    world
        .fabric
        .attach_semantic_revision_store(state_root.path());
    let fence = test_fence()?;
    let running = admitted_running_execution(&mut world.fabric, &fence, "advance", 1)?;

    // The mechanical advance: RUNNING -> PAUSED, new coverage, same wave, same
    // root, same frozen definition digest, same admitted ceilings.
    let advanced = SwarmExecutionRevision {
        state: SwarmExecutionState::Paused,
        coverage_digest: sha256_hex(b"coverage-1702-advanced"),
        ..running.clone()
    };
    let commit = durable_swarm_commit(
        SwarmSemanticOwnerKind::AgentCoordinator,
        advanced.execution_id.as_str(),
        &advanced,
        &fence,
        2,
    )?;
    world.fabric.record_semantic_execution(
        advanced.clone(),
        SWARM_COORDINATOR,
        1,
        &commit.revision,
        &commit.receipt,
    )?;

    // The advance is current, durably, under its own execution identity.
    let stored = world.fabric.snapshot()?;
    let current = stored
        .semantic_executions
        .get(advanced.execution_id.as_str())
        .ok_or("advanced execution must be current")?;
    assert_eq!(current, &advanced);
    assert_eq!(
        world
            .fabric
            .ledger_events()
            .into_iter()
            .filter(|event| event == "semantic_execution_updated")
            .count(),
        1,
        "the update must record itself on the ledger"
    );
    Ok(())
}

// WORK_UNIT_CASE: 1702/A1 — a semantic execution update is refused. The same
// production caller refuses an update that moves a frozen dimension: here the
// wave is substituted in place, which is the exact change
// `check_execution_update` reports as `SemanticDrift("update.wave")`. The
// typed refusal reaches the caller — nothing is swallowed, and the previously
// current revision stays current because the guard refuses before the map moves
// or the durable commit runs.
#[test]
fn semantic_execution_update_changing_frozen_wave_is_refused_typed() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let state_root = SwarmStateRoot::new("drift")?;
    world
        .fabric
        .attach_semantic_revision_store(state_root.path());
    let fence = test_fence()?;
    let running = admitted_running_execution(&mut world.fabric, &fence, "drift", 1)?;

    // In-place wave substitution: the wave moves while the definition digest is
    // unchanged, so the frozen root/wave pairing this execution was admitted
    // under is rewritten rather than re-admitted.
    let drifted = SwarmExecutionRevision {
        wave: RevisionId::new("2").expect("drifted wave"),
        state: SwarmExecutionState::Paused,
        coverage_digest: sha256_hex(b"coverage-1702-drifted"),
        ..running.clone()
    };
    let commit = durable_swarm_commit(
        SwarmSemanticOwnerKind::AgentCoordinator,
        drifted.execution_id.as_str(),
        &drifted,
        &fence,
        2,
    )?;
    match world.fabric.record_semantic_execution(
        drifted,
        SWARM_COORDINATOR,
        1,
        &commit.revision,
        &commit.receipt,
    ) {
        Err(FabricError::SemanticDrift(field)) => assert_eq!(field, "update.wave"),
        other => {
            return Err(format!(
                "semantic wave change must refuse typed SemanticDrift, got {other:?}"
            )
            .into());
        }
    }

    // Nothing moved: the previously current revision is still exactly what this
    // fabric holds, and the refused update was never recorded as current.
    let stored = world.fabric.snapshot()?;
    let current = stored
        .semantic_executions
        .get(running.execution_id.as_str())
        .ok_or("execution must remain current")?;
    assert_eq!(current, &running);
    assert!(
        !world
            .fabric
            .ledger_events()
            .into_iter()
            .any(|event| event == "semantic_execution_updated"),
        "a refused update must not record an update"
    );
    Ok(())
}

/// Requires the refusal to be the typed one and to name the exact drifted
/// field. Asserting only "an error came back" would prove nothing about which
/// dimension was refused, so the field name is part of the claim.
fn assert_semantic_drift(result: Result<(), FabricError>, field: &str, case: &str) -> TestResult {
    match result {
        Err(FabricError::SemanticDrift(refused)) => {
            assert_eq!(refused, field, "{case} must refuse the exact drifted field");
            Ok(())
        }
        other => {
            Err(format!("{case} must refuse typed SemanticDrift({field}), got {other:?}").into())
        }
    }
}

/// The frozen content one live execution runs under: the definition's five
/// dimensions plus the wave and root the execution itself carries, so a base
/// proposal restates the exact content a strict caller would claim.
struct FrozenSwarmContent {
    work_graph_digest: String,
    objective_ref: String,
    acceptance_refs: Vec<String>,
    ceilings: SemanticCeilings,
    stop_conditions_digest: String,
    wave: RevisionId,
    root_context_revision: String,
}

/// Reads back the frozen plan content the live definition, admission and
/// execution really carry, from the fabric's own maps rather than from a
/// restated fixture.
fn frozen_swarm_content(snapshot: &FabricSnapshot, suffix: &str) -> TestResult<FrozenSwarmContent> {
    let definition = snapshot
        .semantic_definitions
        .get(&format!("definition-1702-{suffix}"))
        .ok_or("registered definition must be readable back")?;
    let admission = snapshot
        .semantic_admissions
        .get("admission-1702")
        .ok_or("bound admission must be readable back")?;
    let execution = snapshot
        .semantic_executions
        .get("execution-1702")
        .ok_or("recorded execution must be readable back")?;
    Ok(FrozenSwarmContent {
        work_graph_digest: definition.work_graph_digest.clone(),
        objective_ref: definition.objective_ref.clone(),
        acceptance_refs: definition.acceptance_refs.clone(),
        ceilings: admission.admitted_ceilings.clone(),
        stop_conditions_digest: definition.stop_conditions_digest.clone(),
        wave: execution.wave.clone(),
        root_context_revision: execution.root_context_revision.clone(),
    })
}

/// A proposal that CLAIMS every frozen dimension at its exact admitted value:
/// the live execution identity, wave and root, the definition's work graph,
/// objective, acceptance and stop conditions, and the admitted ceilings. The
/// one mutation a caller may apply is the single drifted dimension under test,
/// so a refusal can only be that dimension's.
fn claimed_semantic_proposal(
    frozen: &FrozenSwarmContent,
    drift: impl FnOnce(&mut ExecutionUpdateProposal),
) -> ExecutionUpdateProposal {
    let mut proposal = ExecutionUpdateProposal {
        execution_id: SwarmExecutionId::new("execution-1702").expect("execution id"),
        wave: frozen.wave.clone(),
        work_graph_digest: Some(frozen.work_graph_digest.clone()),
        objective_ref: Some(frozen.objective_ref.clone()),
        acceptance_refs: Some(frozen.acceptance_refs.clone()),
        ceilings: Some(frozen.ceilings.clone()),
        stop_conditions_digest: Some(frozen.stop_conditions_digest.clone()),
        root_context_revision: Some(frozen.root_context_revision.clone()),
    };
    drift(&mut proposal);
    proposal
}

/// Runs one claimed change of exactly one frozen dimension against the same
/// live execution identity and demands the contract's typed refusal of THAT
/// field.
fn assert_claimed_dimension_refused(
    name: &str,
    dimension: &str,
    drift: impl FnOnce(&FrozenSwarmContent) -> ExecutionUpdateProposal,
) -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let state_root = SwarmStateRoot::new(name)?;
    world
        .fabric
        .attach_semantic_revision_store(state_root.path());
    let fence = test_fence()?;
    let running = admitted_running_execution(&mut world.fabric, &fence, name, 1)?;

    // The proposal CLAIMS a changed value for one dimension and restates every
    // other dimension exactly as frozen. `None` means unclaimed, so an absent
    // field would prove nothing: this fixture's whole claim is that `Some(..)`
    // with drifted content is what the guard refuses.
    let frozen = frozen_swarm_content(&world.fabric.snapshot()?, name)?;
    let proposal = drift(&frozen);
    assert_semantic_drift(
        world.fabric.check_semantic_execution_update(
            &running.admission_id,
            &running.execution_id,
            &proposal,
            SWARM_COORDINATOR,
            1,
        ),
        dimension,
        name,
    )?;
    // Refused is refused: the current revision never moved.
    assert_eq!(
        world
            .fabric
            .snapshot()?
            .semantic_executions
            .get(running.execution_id.as_str()),
        Some(&running),
        "{name} must leave the current execution revision untouched"
    );
    Ok(())
}

// WORK_UNIT_CASE: 1702/A1 — a claimed work-graph change is refused. `Some(..)`
// with content other than the frozen `work_graph_digest` is refused with
// `SemanticDrift("update.work_graph_digest")`.
#[test]
fn claimed_work_graph_change_is_refused_typed() -> TestResult {
    assert_claimed_dimension_refused("workgraph", "update.work_graph_digest", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal.work_graph_digest = Some(sha256_hex(b"work-graph-rewritten"));
        })
    })
}

// WORK_UNIT_CASE: 1702/A1 — a claimed objective change is refused with
// `SemanticDrift("update.objective_ref")`.
#[test]
fn claimed_objective_change_is_refused_typed() -> TestResult {
    assert_claimed_dimension_refused("objective", "update.objective_ref", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal.objective_ref = Some("objective-rewritten-1702".to_owned());
        })
    })
}

// WORK_UNIT_CASE: 1702/A1 — a claimed acceptance change is refused with
// `SemanticDrift("update.acceptance_refs")`.
#[test]
fn claimed_acceptance_change_is_refused_typed() -> TestResult {
    assert_claimed_dimension_refused("acceptance", "update.acceptance_refs", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal.acceptance_refs = Some(vec!["acceptance-rewritten-1702".to_owned()]);
        })
    })
}

// WORK_UNIT_CASE: 1702/A1 — a claimed budget/privacy/route-ceiling widening is
// refused with `SemanticDrift("update.ceilings")`. Three separate widenings of
// the one admitted ceiling set are checked, one per sub-dimension, because the
// contract compares the whole `SemanticCeilings` as a set.
#[test]
fn claimed_budget_privacy_route_ceiling_widening_is_refused_typed() -> TestResult {
    // The budget envelope handle the plan was admitted under.
    assert_claimed_dimension_refused("ceilingbudget", "update.ceilings", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal
                .ceilings
                .as_mut()
                .expect("ceilings are claimed")
                .budget_ref = "budget-ref-widened-1702".to_owned();
        })
    })?;

    // The privacy class the plan was admitted under.
    assert_claimed_dimension_refused("ceilingprivacy", "update.ceilings", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal
                .ceilings
                .as_mut()
                .expect("ceilings are claimed")
                .privacy_class = "privacy-widened-1702".to_owned();
        })
    })?;

    // The admissible route classes the plan was admitted under.
    assert_claimed_dimension_refused("ceilingsroute", "update.ceilings", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal
                .ceilings
                .as_mut()
                .expect("ceilings are claimed")
                .route_classes = vec![
                "route-class-a".to_owned(),
                "route-class-widened-1702".to_owned(),
            ];
        })
    })
}

// WORK_UNIT_CASE: 1702/A1 — a claimed stop-conditions change is refused with
// `SemanticDrift("update.stop_conditions_digest")`.
#[test]
fn claimed_stop_conditions_change_is_refused_typed() -> TestResult {
    assert_claimed_dimension_refused(
        "stopconditions",
        "update.stop_conditions_digest",
        |frozen| {
            claimed_semantic_proposal(frozen, |proposal| {
                proposal.stop_conditions_digest = Some(sha256_hex(b"stop-conditions-rewritten"));
            })
        },
    )
}

// WORK_UNIT_CASE: 1702/A1 — a claimed root-context change is refused with
// `SemanticDrift("update.root_context_revision")`.
#[test]
fn claimed_root_context_change_is_refused_typed() -> TestResult {
    assert_claimed_dimension_refused("rootcontext", "update.root_context_revision", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal.root_context_revision = Some("root-rewritten-1702".to_owned());
        })
    })
}

// WORK_UNIT_CASE: 1702/A1 — a claimed foreign-execution change is refused with
// `ForeignOwnerField("update.execution_id")`.
#[test]
fn claimed_foreign_execution_change_is_refused_typed() -> TestResult {
    assert_claimed_dimension_refused("foreignexecution", "update.execution_id", |frozen| {
        claimed_semantic_proposal(frozen, |proposal| {
            proposal.execution_id =
                SwarmExecutionId::new("execution-foreign-1702").expect("foreign execution id");
        })
    })
}

// WORK_UNIT_CASE: 1702/A1 — the FULLY CLAIMED, UNCHANGED proposal is admitted.
// Every frozen dimension is claimed at its exact admitted value, so this is the
// strictest reading of "advance mechanically, change nothing" that a caller can
// express: it proves the guard does not refuse a proposal merely for naming the
// plan it is running under.
#[test]
fn fully_claimed_unchanged_proposal_is_admitted() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let state_root = SwarmStateRoot::new("allclaimed")?;
    world
        .fabric
        .attach_semantic_revision_store(state_root.path());
    let fence = test_fence()?;
    let running = admitted_running_execution(&mut world.fabric, &fence, "allclaimed", 1)?;
    let frozen = frozen_swarm_content(&world.fabric.snapshot()?, "allclaimed")?;

    world.fabric.check_semantic_execution_update(
        &running.admission_id,
        &running.execution_id,
        &claimed_semantic_proposal(&frozen, |_| {}),
        SWARM_COORDINATOR,
        1,
    )?;
    Ok(())
}

// WORK_UNIT_CASE: 1702/A1 — a revision binding a digest that is no longer the
// frozen definition is refused. A coordinator present carries none of the work
// graph, objective, acceptance, ceilings or stop conditions on the execution
// record, so a semantic rewrite can only reach them by re-authoring the
// execution onto a different `definition_digest`. That is refused as a BROKEN
// OWNERSHIP JOIN rather than as a work-graph drift:
// `check_semantic_execution_update` hands `check_execution_update` the STORED
// execution, definition and admission, so the presented revision never enters
// those comparisons and `SemanticDrift("update.work_graph_digest")` cannot be
// the refusal. The guard returns Ok here, and the refusal that actually fires is
// `check_owner_join`'s execution-binding check run against the PRESENTED
// revision — `BrokenOwnershipLink("execution binding")`. The rewrite is
// stopped either way; the assertion pins the refusal that really happens rather
// than the one this path would need a different entry point to produce.
#[test]
fn semantic_execution_update_binding_a_foreign_definition_digest_is_refused_typed() -> TestResult {
    let route = test_route()?;
    let mut world = test_world(
        Some(route),
        AdmitMode::Admit,
        ActivateMode::Activate,
        EgressMode::Ack,
        false,
    )?;
    let state_root = SwarmStateRoot::new("digest")?;
    world
        .fabric
        .attach_semantic_revision_store(state_root.path());
    let fence = test_fence()?;
    let running = admitted_running_execution(&mut world.fabric, &fence, "digest", 1)?;

    // A real re-authored plan — different work graph, objective, acceptance and
    // stop conditions — presented as this execution's own revision, durably
    // committed under this coordinator's own owner stream. Nothing here is a
    // stand-in: the substituted digest really does bind that rewritten content.
    let mut rewritten = frozen_swarm_definition(&fence, "rewritten")?;
    rewritten.work_graph_digest = sha256_hex(b"work-graph-rewritten-1702");
    rewritten.objective_ref = "objective-rewritten-1702".to_owned();
    rewritten.acceptance_refs = vec!["acceptance-rewritten-1702".to_owned()];
    rewritten.stop_conditions_digest = sha256_hex(b"stop-conditions-rewritten-1702");
    rewritten.definition_digest = rewritten
        .content_digest()
        .expect("rewritten definition content digest");
    let rewritten_execution = SwarmExecutionRevision {
        definition_digest: rewritten.definition_digest.clone(),
        state: SwarmExecutionState::Paused,
        coverage_digest: sha256_hex(b"coverage-1702-rewritten"),
        ..running.clone()
    };
    let commit = durable_swarm_commit(
        SwarmSemanticOwnerKind::AgentCoordinator,
        rewritten_execution.execution_id.as_str(),
        &rewritten_execution,
        &fence,
        2,
    )?;

    match world.fabric.record_semantic_execution(
        rewritten_execution,
        SWARM_COORDINATOR,
        1,
        &commit.revision,
        &commit.receipt,
    ) {
        Err(FabricError::BrokenOwnershipLink(refused)) => {
            assert_eq!(
                refused, "execution binding",
                "a foreign digest must refuse as the broken execution binding it is"
            );
        }
        other => {
            return Err(format!(
                "foreign definition digest must refuse the broken execution binding, got {other:?}"
            )
            .into());
        }
    }

    // Refused is refused: the previously current revision is still exactly what
    // this fabric holds, and nothing was recorded as an update.
    let stored = world.fabric.snapshot()?;
    assert_eq!(
        stored
            .semantic_executions
            .get(running.execution_id.as_str()),
        Some(&running),
        "a foreign-digest update must leave the current revision untouched"
    );
    assert!(
        !world
            .fabric
            .ledger_events()
            .into_iter()
            .any(|event| event == "semantic_execution_updated"),
        "a refused update must not record an update"
    );
    Ok(())
}
