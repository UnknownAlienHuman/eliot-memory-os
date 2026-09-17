//! Structured Governor-daemon admission diagnostics proof for issue #740.
//!
//! Exactly cases 1 through 21; one substantive primary executable test per
//! case marker below. Helpers carry no markers. Every case runs through the
//! real production path (`eliotd::diagnostics` plus the exercised owner
//! call sites: the #872 fabric composition, the activation projection
//! vocabulary, the Kernel-client parsers, and the daemon error owners)
//! with recording fakes only at the accepted owner seams. No stubs, no
//! canned authority, no live Kernel/Store/provider execution.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use eliot_agent_api::{
    AgentLaunchRequest, AgentWorkUnitBrief, AttemptId, BudgetEnvelope, EffectCeiling, EffectKind,
    LaunchRequestId, LowercaseSha256, RouteFingerprint, TaskId, WorkUnitId,
};
use eliot_agent_contracts::RevisionId;
use eliot_agent_coordinator::{
    AdmissionId, CandidateId, CoordinatorConfig, RecipeId, RecipeManifest, RoleProfileId,
    RoleProfileManifest, RouteCandidateEvidence, StaffingLaneRequest, StaffingPlanCandidate,
    StaffingPlanRequest, WorkClass,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_protocol::{
    AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
    AgentActivationResultAckOutcome, AgentActivationRetryDirective,
    AgentActivationSelectionDirective,
};
use eliot_security_contracts::PrivacyClass;
use eliotd::diagnostics::{
    AdmissionDisposition, AdmissionRecord, CacheState, CaptureGuard, DiagnosticRecord,
    DrainOutcome, ErrorRecord, HandoffKind, KernelDisconnect, MAX_DETAIL_CHARS,
    MAX_REPEATED_FAILURE_LINES, OwningComponent, RebuildState, RejectionReason,
    RepeatedFailureGuard, RequestReceipt, STATE_UNKNOWN, ScopeIdentities, ShutdownOutcome,
    SinkError, SubscriberInit, ack_is_completed, admission_digest, carries_denied_content,
    disposition_of_admission, disposition_of_reservation, disposition_of_resolution,
    emit_activation_ack, emit_cache_health, emit_daemon_readiness, emit_drain,
    emit_fabric_attached, emit_finish_evaluation, emit_finish_refusal, emit_handoff,
    emit_kernel_handshake, emit_process_exit, emit_rebuild, emit_response_write, emit_shutdown,
    emit_startup, emit_to_writer, emit_worker_ack, fabric_rejection_of, init_daemon_diagnostics,
    install_capture, process_exit_is_completed, response_write_is_completed, sanitize_detail,
    sanitize_identity, strict_finish_completed,
};
use eliotd::{
    ActivationAuthorityPort, ActivationEvidence, AdmissionAuthorityPort, AgentFabric,
    AttemptResultRecord, DispatchAck, DispatchEgressPort, DispatchIntent, FabricAdmission,
    FabricError, FabricPorts, ModelRegistryPort, PeerChannelPort, PeerMessage, PeerReceipt,
    Reservation, RouteRequirements, SwarmControlPort, SwarmDefinition, SwarmEntryReceipt,
    WorkerAck, daemon_coordinator_config, plan_candidate,
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

#[allow(clippy::too_many_lines)]
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
            id: LaunchRequestId::new("launch-740").map_err(|error| format!("launch: {error}"))?,
            task_id: TaskId::new("task-740").map_err(|error| format!("task: {error}"))?,
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
            recipe_id: RecipeId::new("recipe-740").map_err(|error| format!("recipe: {error}"))?,
            manifest_revision: RevisionId::new("recipe-rev-740")
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
        plan_revision: RevisionId::new("plan-rev-740")
            .map_err(|error| format!("plan rev: {error}"))?,
        state_fence: fence.clone(),
        privacy_class: PrivacyClass::Private,
        work_class: WorkClass::parse_wire("swarm").map_err(|error| format!("class: {error}"))?,
        lanes: vec![StaffingLaneRequest {
            work_unit_id: WorkUnitId::new("work-1")
                .map_err(|error| format!("lane work: {error}"))?,
            role_id: RoleProfileId::new("role-1").map_err(|error| format!("lane role: {error}"))?,
            work_class: WorkClass::parse_wire("swarm").map_err(|error| format!("class: {error}"))?,
            route_candidates: vec![RouteCandidateEvidence {
                route: route.clone(),
                preference_rank: 0,
                capacity_identity: eliotd::FABRIC_CAPACITY_IDENTITY.to_owned(),
                capacity_revision: RevisionId::new(eliotd::FABRIC_CAPACITY_REVISION)
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

fn bump(counter: &Mutex<u32>) {
    if let Ok(mut guard) = counter.lock() {
        *guard = guard.saturating_add(1);
    }
}

fn counter_value(counter: &Mutex<u32>) -> u32 {
    counter.lock().map_or(0, |guard| *guard)
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
}

impl SwarmControlPort for FakeSwarm {
    fn enter_plan(
        &self,
        candidate: &StaffingPlanCandidate,
    ) -> Result<SwarmEntryReceipt, FabricError> {
        bump(&self.calls);
        let bytes = eliot_contracts::canonical_json_bytes(candidate)
            .map_err(|error| FabricError::Contract(format!("candidate bytes: {error}")))?;
        Ok(SwarmEntryReceipt {
            candidate_id: candidate.candidate_id.clone(),
            entered_digest: eliot_contracts::sha256_hex(&bytes),
        })
    }
}

struct FakeAdmission {
    deny: bool,
    stage_calls: Mutex<u32>,
    commit_calls: Mutex<u32>,
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
        if self.deny {
            return Err(FabricError::AdmissionDenied("governor denied".to_owned()));
        }
        Ok(FabricAdmission {
            admission_id: AdmissionId::new("admission-1")
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
        })
    }
}

struct FakeActivation {
    calls: Mutex<u32>,
}

impl ActivationAuthorityPort for FakeActivation {
    fn activate(
        &self,
        admission: &FabricAdmission,
        attempt_id: &AttemptId,
    ) -> Result<ActivationEvidence, FabricError> {
        bump(&self.calls);
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
            fence: admission.fence.clone(),
            epoch: admission.epoch.clone(),
        })
    }
}

struct FakeEgress {
    calls: Mutex<u32>,
}

impl DispatchEgressPort for FakeEgress {
    fn emit(&self, intent: &DispatchIntent) -> Result<DispatchAck, FabricError> {
        bump(&self.calls);
        Ok(DispatchAck {
            dispatch_id: intent.dispatch_id.clone(),
            retained: true,
        })
    }
}

struct TestWorld {
    fabric: AgentFabric,
    admission: Arc<FakeAdmission>,
}

fn test_world(deny: bool) -> TestResult<TestWorld> {
    let config: CoordinatorConfig = daemon_coordinator_config()?;
    let admission = Arc::new(FakeAdmission {
        deny,
        stage_calls: Mutex::new(0),
        commit_calls: Mutex::new(0),
    });
    let activation = Arc::new(FakeActivation {
        calls: Mutex::new(0),
    });
    let egress = Arc::new(FakeEgress {
        calls: Mutex::new(0),
    });
    let registry = Arc::new(FakeRegistry {
        route: None,
        calls: Mutex::new(0),
    });
    let peer = Arc::new(FakePeer {
        calls: Mutex::new(0),
    });
    let swarm = Arc::new(FakeSwarm {
        calls: Mutex::new(0),
    });
    let ports = FabricPorts {
        model_registry: Arc::clone(&registry) as Arc<dyn ModelRegistryPort>,
        peer_channel: Arc::clone(&peer) as Arc<dyn PeerChannelPort>,
        swarm_control: Arc::clone(&swarm) as Arc<dyn SwarmControlPort>,
        admission_authority: Arc::clone(&admission) as Arc<dyn AdmissionAuthorityPort>,
        activation_authority: Arc::clone(&activation) as Arc<dyn ActivationAuthorityPort>,
        dispatch_egress: Arc::clone(&egress) as Arc<dyn DispatchEgressPort>,
    };
    Ok(TestWorld {
        fabric: AgentFabric::new(config, ports)?,
        admission,
    })
}

fn admitted_fabric(candidate: &str) -> TestResult<(TestWorld, FabricAdmission)> {
    let mut world = test_world(false)?;
    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, candidate)?;
    let (definition, _candidate) = world.fabric.define_and_plan(request)?;
    let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
    let admission = world.fabric.commit_admission(&reservation.reservation_id)?;
    Ok((world, admission))
}

fn manifest_source(relative: &str) -> TestResult<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative);
    std::fs::read_to_string(&path).map_err(|error| format!("read {path}: {error}").into())
}

struct FailingWriter;

impl std::io::Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "injected diagnostic sink failure",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn assert_canary_absent(lines: &[String], canary: &str) {
    assert!(
        !lines.iter().any(|line| line.contains(canary)),
        "canary leaked into diagnostics sink: {canary}"
    );
}

// WORK_UNIT_CASE: 740/1
#[test]
fn bounded_subscriber_parallel_capture_and_sink_failure_keep_protocol_output() -> TestResult {
    let first_init = init_daemon_diagnostics();
    let second_init = init_daemon_diagnostics();
    assert_eq!(first_init, second_init);
    assert!(matches!(
        second_init,
        SubscriberInit::Initialized | SubscriberInit::AlreadyInitialized
    ));
    let startup = emit_startup();
    assert_eq!(startup.event(), "eliotd.startup");

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker in 0..4_u32 {
            handles.push(scope.spawn(move || {
                let _guard: CaptureGuard = install_capture();
                let identity = format!("req-parallel-{worker}");
                let record = RequestReceipt::of(&identity, "op-parallel-1").emit();
                let lines = eliotd::diagnostics::captured_records();
                assert_eq!(lines.len(), 1);
                assert!(lines[0].contains(&identity));
                for other in 0..4_u32 {
                    if other != worker {
                        assert!(!lines[0].contains(&format!("req-parallel-{other}")));
                    }
                }
                record
            }));
        }
        for handle in handles {
            let record: DiagnosticRecord = handle
                .join()
                .map_err(|_| Box::<dyn std::error::Error>::from("worker panicked"))?;
            assert_eq!(record.event(), "eliotd.request_receipt");
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    let record = RequestReceipt::of("req-sink-1", "op-sink-1").emit();
    let mut fallback = Vec::new();
    emit_to_writer(&mut fallback, &record)?;
    assert_eq!(fallback.last(), Some(&b'\n'));
    assert!(fallback.starts_with(b"event='eliotd.request_receipt'"));
    let sink_error = emit_to_writer(&mut FailingWriter, &record);
    match sink_error {
        Err(SinkError::WriteFailed(_)) => {}
        Ok(()) => return Err("failing sink must not report success".into()),
    }
    Ok(())
}

// WORK_UNIT_CASE: 740/2
#[test]
fn kernel_handshake_and_readiness_are_distinct_states() {
    let _guard = install_capture();
    let handshake = emit_kernel_handshake("conn-740-2", false);
    let validated = emit_kernel_handshake("conn-740-2", true);
    let ready = emit_daemon_readiness(true, false);
    let degraded = emit_daemon_readiness(false, true);
    assert_eq!(handshake.event(), "eliotd.kernel_handshake");
    assert_eq!(ready.event(), "eliotd.daemon_readiness");
    assert_ne!(handshake.event(), ready.event());
    assert!(handshake.contains("state='connected'"));
    assert!(validated.contains("state='validated'"));
    assert!(ready.contains("state='ready'"));
    assert!(degraded.contains("state='degraded'"));
    assert!(!handshake.contains("state='ready'"));
    assert!(!ready.contains("state='connected'"));
}

// WORK_UNIT_CASE: 740/3
#[test]
fn request_receipt_records_identity_without_payload() {
    let _guard = install_capture();
    let receipt = RequestReceipt::of("req-740-3", "op-740-3").emit();
    assert_eq!(receipt.event(), "eliotd.request_receipt");
    assert!(receipt.contains("request='req-740-3'"));
    assert!(receipt.contains("operation='op-740-3'"));
    assert!(!receipt.contains("payload"));
    let missing = RequestReceipt::of("", "").emit();
    assert!(missing.contains("request='unavailable'"));
    assert!(missing.contains("operation='unavailable'"));
    let parsed = eliotd::diagnostics::captured_records();
    assert!(parsed.iter().all(|line| !line.contains("payload")));
}

// WORK_UNIT_CASE: 740/4
#[test]
fn scope_task_and_fence_identities_are_preserved_exactly() {
    let identities = ScopeIdentities::of("scope-740-4", "task-740-4", "epoch:1/gen:1");
    let record = identities.emit();
    assert_eq!(record.event(), "eliotd.scope_resolved");
    assert!(record.contains("scope='scope-740-4'"));
    assert!(record.contains("task='task-740-4'"));
    assert!(record.contains("fence='epoch:1/gen:1'"));
    let absent = ScopeIdentities::of("", "task-740-4", "").emit();
    assert!(absent.contains("scope='unavailable'"));
    assert!(absent.contains("fence='unavailable'"));
    assert!(absent.contains("task='task-740-4'"));
}

// WORK_UNIT_CASE: 740/5
#[test]
fn semantic_admission_emits_admitted_or_rejected_with_digest() {
    let digest_a = admission_digest("740/5", &["req-740-5", "admitted"]);
    let digest_b = admission_digest("740/5", &["req-740-5", "admitted"]);
    assert_eq!(digest_a, digest_b);
    assert_ne!(
        digest_a,
        admission_digest("740/5", &["req-740-5", "rejected"])
    );
    let admitted =
        AdmissionRecord::of(AdmissionDisposition::Admitted, "req-740-5", &digest_a).emit();
    let digest_r = admission_digest("740/5", &["req-740-5", "rejected"]);
    let rejected =
        AdmissionRecord::of(AdmissionDisposition::Rejected, "req-740-5", &digest_r).emit();
    assert!(admitted.contains("disposition='admitted'"));
    assert!(rejected.contains("disposition='rejected'"));
    assert!(admitted.contains(&digest_a));
    assert_ne!(admitted.line(), rejected.line());
    let resolved = AgentActivationResolutionDisposition::Resolved {
        binding: Box::new(eliot_protocol::AgentActivationResolvedBinding {
            principal_id: "principal-1".to_owned(),
            session_id: "session-1".to_owned(),
            task_id: "task-1".to_owned(),
            work_unit_id: "work-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            task_revision: "7".to_owned(),
            plan_id: "plan-1".to_owned(),
            plan_revision: "plan-revision-1".to_owned(),
        }),
    };
    assert_eq!(
        disposition_of_resolution(&resolved),
        AdmissionDisposition::Admitted
    );
    let selection = AgentActivationResolutionDisposition::TaskSelectionRequired {
        selection: AgentActivationSelectionDirective {
            candidate_handles: vec!["candidate-a".to_owned()],
            candidate_coverage: AgentActivationCandidateCoverage::Complete,
            recovery_handle: "recovery-740-5".to_owned(),
        },
    };
    assert_eq!(
        disposition_of_resolution(&selection),
        AdmissionDisposition::Candidate
    );
    let not_ready = AgentActivationResolutionDisposition::NotReady {
        recovery_handle: "recovery-740-5".to_owned(),
        retry: AgentActivationRetryDirective {
            dependency_ref: "governor.session".to_owned(),
            observed_dependency_revision: "rev-1".to_owned(),
            not_before_unix_ms: 60,
        },
    };
    assert_eq!(
        disposition_of_resolution(&not_ready),
        AdmissionDisposition::Unknown
    );
    let failed = AgentActivationResolutionDisposition::FailedInternal {
        failure_handle: "failure-740-5".to_owned(),
    };
    assert_eq!(
        disposition_of_resolution(&failed),
        AdmissionDisposition::Unknown
    );
}

// WORK_UNIT_CASE: 740/6
#[test]
fn prepared_handoff_is_distinguishable_from_committed_transition() -> TestResult {
    let mut world = test_world(false)?;
    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, "candidate-740-6")?;
    let (definition, _planned) = world.fabric.define_and_plan(request)?;
    let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
    assert_eq!(
        disposition_of_reservation(&reservation),
        AdmissionDisposition::Staged
    );
    let admission = world.fabric.commit_admission(&reservation.reservation_id)?;
    assert_eq!(
        disposition_of_admission(&admission),
        AdmissionDisposition::Committed
    );
    let prepared = emit_handoff(HandoffKind::Prepared, "op-740-6", "digest-740-6");
    let committed = emit_handoff(HandoffKind::Committed, "op-740-6", "digest-740-6");
    assert_eq!(prepared.event(), "eliotd.transition_handoff");
    assert_eq!(committed.event(), "eliotd.transition_committed");
    assert_ne!(prepared.event(), committed.event());
    assert!(committed.contains("operation='op-740-6'"));
    Ok(())
}

// WORK_UNIT_CASE: 740/7
#[test]
fn candidate_rejection_emits_typed_reason_and_owning_component() -> TestResult {
    let mut world = test_world(true)?;
    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, "candidate-740-7")?;
    let (definition, _candidate) = world.fabric.define_and_plan(request)?;
    let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
    let Err(error) = world.fabric.commit_admission(&reservation.reservation_id) else {
        return Err("governor deny fixture must reject".into());
    };
    let (reason, owner) = fabric_rejection_of(&error);
    assert_eq!(reason, RejectionReason::AdmissionDenied);
    assert_eq!(owner, OwningComponent::Governor);
    let record = eliotd::diagnostics::RejectionRecord::of_fabric_error(&error).emit();
    assert!(record.contains("reason='admission-denied'"));
    assert!(record.contains("owner='governor'"));
    Ok(())
}

// WORK_UNIT_CASE: 740/8
#[test]
fn rebuild_and_degraded_cache_states_remain_distinct() {
    let requested = emit_rebuild(RebuildState::Requested, "digest-740-8");
    let in_progress = emit_rebuild(RebuildState::InProgress, "digest-740-8");
    let completed = emit_rebuild(RebuildState::Completed, "digest-740-8");
    let healthy = emit_cache_health(CacheState::Healthy, "digest-740-8");
    let degraded = emit_cache_health(CacheState::Degraded, "digest-740-8");
    assert!(requested.contains("state='rebuild-requested'"));
    assert!(in_progress.contains("state='rebuild-in-progress'"));
    assert!(completed.contains("state='rebuild-completed'"));
    assert!(healthy.contains("state='cache-healthy'"));
    assert!(degraded.contains("state='cache-degraded'"));
    assert_eq!(requested.event(), "eliotd.cache_rebuild");
    assert_eq!(healthy.event(), "eliotd.cache_health");
    assert_ne!(requested.event(), healthy.event());
    assert_ne!(requested.line(), in_progress.line());
}

// WORK_UNIT_CASE: 740/9
#[test]
fn strict_finish_evaluation_is_visible_without_finish_claim() -> TestResult {
    assert!(!strict_finish_completed(false));
    let evaluated = emit_finish_evaluation("attempt-740-9", strict_finish_completed(false));
    assert_eq!(evaluated.event(), "eliotd.finish_evaluated");
    assert!(evaluated.contains("completed='false'"));
    assert!(!evaluated.contains("disposition='finished'"));
    let (_world, admission) = admitted_fabric("candidate-740-9")?;
    let attempt = admission
        .attempt_ids
        .first()
        .ok_or("admission must carry one attempt")?;
    let refusal = emit_finish_refusal(
        attempt.as_str(),
        RejectionReason::Refused,
        OwningComponent::AgentFabric,
    );
    assert_eq!(refusal.event(), "eliotd.finish_refused");
    assert!(refusal.contains("completed='false'"));
    Ok(())
}

// WORK_UNIT_CASE: 740/10
#[test]
fn drain_and_shutdown_emit_exact_dispositions() {
    let idle = emit_drain(DrainOutcome::Idle, "", "");
    let unknown = emit_drain(
        DrainOutcome::ActivationUnknown,
        "ticket-740-10",
        "result-740-10",
    );
    assert_eq!(idle.event(), "eliotd.drain");
    assert!(idle.contains("disposition='drain-idle'"));
    assert!(unknown.contains("disposition='drain-activation-unknown'"));
    assert!(unknown.contains("ticket='ticket-740-10'"));
    let clean = emit_shutdown(ShutdownOutcome::Clean, "daemon shutdown completed");
    let with_unknown = emit_shutdown(
        ShutdownOutcome::WithActivationUnknown,
        "retained ticket-740-10",
    );
    let with_error = emit_shutdown(ShutdownOutcome::WithError, "shutdown failed closed");
    assert!(clean.contains("disposition='shutdown-clean'"));
    assert!(with_unknown.contains("disposition='shutdown-activation-unknown'"));
    assert!(with_error.contains("disposition='shutdown-error'"));
    assert_ne!(idle.event(), clean.event());
}

// WORK_UNIT_CASE: 740/11
#[test]
fn eight_admission_states_remain_distinct() {
    let all = AdmissionDisposition::all();
    assert_eq!(all.len(), 8);
    let mut codes = BTreeSet::new();
    for disposition in all {
        assert!(codes.insert(disposition.as_str()), "duplicate code");
    }
    assert!(codes.contains("candidate"));
    assert!(codes.contains("admitted"));
    assert!(codes.contains("rejected"));
    assert!(codes.contains("staged"));
    assert!(codes.contains("committed"));
    assert!(codes.contains(STATE_UNKNOWN));
    assert!(codes.contains("reconciled"));
    assert!(codes.contains("finished"));
}

// WORK_UNIT_CASE: 740/12
#[test]
fn worker_acknowledgement_is_never_completed_work() -> TestResult {
    for outcome in [
        AgentActivationResultAckOutcome::Accepted,
        AgentActivationResultAckOutcome::ExactReplay,
        AgentActivationResultAckOutcome::Reconciled,
        AgentActivationResultAckOutcome::Unknown,
    ] {
        assert!(!ack_is_completed(&outcome));
        let record = emit_activation_ack("ticket-740-12", "result-740-12", &outcome);
        assert_eq!(record.event(), "eliotd.activation_ack");
        assert!(!record.contains("completed='true'"));
    }
    let (mut world, admission) = admitted_fabric("candidate-740-12")?;
    let attempt = admission
        .attempt_ids
        .first()
        .ok_or("admission must carry one attempt")?;
    world.fabric.observe_worker_ack(&WorkerAck {
        attempt_id: attempt.clone(),
        worker_id: "worker-740-12".to_owned(),
    })?;
    // The admitted (undispatched) attempt cannot take a result as Finish:
    // the owner refuses with `ResultNotFinish`, never success.
    let submit_error = match world.fabric.submit_attempt_result(&AttemptResultRecord {
        attempt_id: attempt.clone(),
        result_digest: "digest-740-12".to_owned(),
    }) {
        Ok(()) => return Err("candidate result must never pass as Finish".into()),
        Err(error) => error,
    };
    assert!(matches!(submit_error, FabricError::ResultNotFinish(_)));
    let rejected = eliotd::diagnostics::RejectionRecord::of_fabric_error(&submit_error).emit();
    assert!(rejected.contains("reason='contract'"));
    let ack = emit_worker_ack(attempt.as_str(), "worker-740-12");
    assert!(ack.contains("completed='false'"));
    Ok(())
}

// WORK_UNIT_CASE: 740/13
#[test]
fn process_exit_and_response_write_are_never_completed_work() {
    assert!(!process_exit_is_completed());
    assert!(!response_write_is_completed());
    let exit = emit_process_exit("process-740-13", 0);
    let written = emit_response_write("op-740-13");
    assert_eq!(exit.event(), "eliotd.process_exited");
    assert_eq!(written.event(), "eliotd.response_written");
    assert!(exit.contains("completed='false'"));
    assert!(written.contains("completed='false'"));
}

// WORK_UNIT_CASE: 740/14
#[test]
fn owning_error_records_are_bounded_without_duplicate_inflation() {
    let oversized = "detail-740-14-".to_owned() + &"x".repeat(2_000);
    let record = ErrorRecord::of(OwningComponent::Kernel, "kernel-transport", &oversized).emit();
    assert!(record.line().len() < oversized.len());
    assert!(!record.line().contains(&"x".repeat(600)));
    let daemon_error = eliotd::DaemonError::Kernel("transport refused".to_owned());
    let owned = ErrorRecord::of_daemon_error(&daemon_error).emit();
    assert!(owned.contains("owner='kernel'"));
    let fabric_error = FabricError::DispatchLost("egress lost".to_owned());
    let fabric_owned = ErrorRecord::of_fabric_error(&fabric_error).emit();
    assert!(fabric_owned.contains("owner='dispatch-egress'"));
    let mut guard = RepeatedFailureGuard::new();
    for _ in 0..MAX_REPEATED_FAILURE_LINES {
        assert!(guard.should_emit());
    }
    assert!(!guard.should_emit());
    assert_eq!(guard.emitted(), MAX_REPEATED_FAILURE_LINES);
    assert_eq!(guard.suppressed(), 1);
    let mut owners = BTreeSet::new();
    for owner in [
        OwningComponent::Governor,
        OwningComponent::Kernel,
        OwningComponent::DaemonConfig,
        OwningComponent::DaemonRuntime,
        OwningComponent::ActivationProjection,
        OwningComponent::TransitionPort,
        OwningComponent::RecoveryPort,
        OwningComponent::AgentFabric,
        OwningComponent::Coordinator,
        OwningComponent::DispatchEgress,
        OwningComponent::ModelRegistry,
        OwningComponent::AdmissionAuthority,
    ] {
        assert!(owners.insert(owner.as_str()), "duplicate owner code");
    }
    assert_eq!(owners.len(), 12);
}

// WORK_UNIT_CASE: 740/15
#[test]
fn deterministic_rejection_fixture_emits_expected_bounded_record() -> TestResult {
    let answer = serde_json::json!({ "accepted": false });
    let Err(first_detail) = eliotd::parse_local_read_submit_outcome(&answer) else {
        return Err("fixture without accepted/expired must reject".into());
    };
    let Err(second_detail) = eliotd::parse_local_read_submit_outcome(&answer) else {
        return Err("fixture without accepted/expired must reject".into());
    };
    assert_eq!(first_detail, second_detail);
    let first_record =
        ErrorRecord::of(OwningComponent::Kernel, "local-read-submit", &first_detail).emit();
    let second_record =
        ErrorRecord::of(OwningComponent::Kernel, "local-read-submit", &second_detail).emit();
    assert_eq!(first_record.line(), second_record.line());
    assert!(first_record.line().len() <= MAX_DETAIL_CHARS + 128);

    let mut world = test_world(false)?;
    let Err(first_rejection) = world.fabric.commit_admission("res-unknown-740-15") else {
        return Err("unknown reservation must reject".into());
    };
    let Err(second_rejection) = world.fabric.commit_admission("res-unknown-740-15") else {
        return Err("unknown reservation must reject deterministically".into());
    };
    assert_eq!(first_rejection.to_string(), second_rejection.to_string());
    let rejection = eliotd::diagnostics::RejectionRecord::of_fabric_error(&first_rejection).emit();
    assert!(rejection.contains("reason='stale-reservation'"));
    Ok(())
}

// WORK_UNIT_CASE: 740/16
#[test]
fn stale_fence_emits_stale_not_generic_rejection() {
    let error = FabricError::StaleFence("admission fence does not match".to_owned());
    let (reason, owner) = fabric_rejection_of(&error);
    assert!(reason.is_stale_fence());
    assert_eq!(reason.as_str(), "stale-fence");
    assert_eq!(owner, OwningComponent::Kernel);
    let record = eliotd::diagnostics::RejectionRecord::of_fabric_error(&error).emit();
    assert!(record.contains("reason='stale-fence'"));
    assert!(!record.contains("generic-failure"));
    let stale = AgentActivationResolutionDisposition::StaleFence {
        recovery_handle: "recovery-740-16".to_owned(),
        observed_state_fence: None,
    };
    assert_eq!(
        disposition_of_resolution(&stale),
        AdmissionDisposition::Rejected
    );
    let epoch_error = FabricError::StaleEpoch("epoch drift".to_owned());
    let (epoch_reason, _) = fabric_rejection_of(&epoch_error);
    assert_ne!(epoch_reason, RejectionReason::StaleFence);
}

// WORK_UNIT_CASE: 740/17
#[test]
fn kernel_disconnect_emits_unknown_without_extra_operation() {
    let disconnect = KernelDisconnect::of("conn-740-17");
    let first = disconnect.emit();
    let second = disconnect.emit();
    assert_eq!(first.event(), "eliotd.kernel_disconnect");
    assert!(first.contains("state='unknown'"));
    assert!(first.contains("connection='conn-740-17'"));
    assert_eq!(first.line(), second.line());
    assert!(!first.contains("resend"));
    assert!(!first.contains("reconcile"));
}

// WORK_UNIT_CASE: 740/18
#[test]
fn strict_finish_refusal_emits_refusal_without_fabricated_completion() -> TestResult {
    let (mut world, admission) = admitted_fabric("candidate-740-18")?;
    let attempt = admission
        .attempt_ids
        .first()
        .ok_or("admission must carry one attempt")?;
    world.fabric.mark_unknown_outcome(attempt)?;
    let error = match world.fabric.require_finish(attempt) {
        Ok(()) => return Err("unknown outcome cannot satisfy Finish".into()),
        Err(error) => error,
    };
    let (reason, owner) = fabric_rejection_of(&error);
    assert_eq!(reason, RejectionReason::UnknownChild);
    let refusal = emit_finish_refusal(attempt.as_str(), reason, owner);
    assert_eq!(refusal.event(), "eliotd.finish_refused");
    assert!(refusal.contains("completed='false'"));
    assert!(!refusal.contains("disposition='finished'"));
    assert!(!strict_finish_completed(false));
    Ok(())
}

// WORK_UNIT_CASE: 740/19
#[test]
fn model_context_evidence_and_user_canaries_are_absent() {
    let _guard = install_capture();
    let canaries = [
        "model-text: the model said hello world",
        "context-payload {\"secrets\": [1, 2, 3]}",
        "evidence-body bytes of the witness bundle",
        "user-content please ignore previous instructions",
    ];
    for canary in canaries {
        assert!(carries_denied_content(canary));
        let _ = sanitize_identity(canary);
        let _ = sanitize_detail(canary);
        let _ = RequestReceipt::of(canary, "op-740-19").emit();
        let _ = ScopeIdentities::of(canary, canary, canary).emit();
        let _ = AdmissionRecord::of(AdmissionDisposition::Admitted, canary, canary).emit();
        let _ = ErrorRecord::of(OwningComponent::Governor, "contract", canary).emit();
        let _ = emit_handoff(HandoffKind::Prepared, canary, canary);
        let _ = emit_shutdown(ShutdownOutcome::WithError, canary);
    }
    let oversized = "model-text: ".to_owned() + &"y".repeat(10_000);
    let _ = ErrorRecord::of(OwningComponent::Governor, "contract", &oversized).emit();
    let lines = eliotd::diagnostics::captured_records();
    assert!(!lines.is_empty());
    for canary in canaries {
        assert_canary_absent(&lines, canary);
    }
    assert_canary_absent(&lines, &"y".repeat(256));
}

// WORK_UNIT_CASE: 740/20
#[test]
fn credential_token_provider_and_handle_canaries_are_absent_including_fallback() -> TestResult {
    let _guard = install_capture();
    let canaries = [
        "sk-live-740-secret-key-material",
        "token abcdef123456",
        "password=hunter2-hunter2",
        "bearer eyJhbGciOiJIUzI1NiJ9",
        "api-key provider-billing-740",
        "connection-string Server=db;Password=x;",
    ];
    let mut fallback_bytes = Vec::new();
    for canary in canaries {
        assert!(carries_denied_content(canary));
        let record = ErrorRecord::of(OwningComponent::Kernel, "kernel-transport", canary).emit();
        assert!(!record.contains(canary));
        emit_to_writer(&mut fallback_bytes, &record)?;
        let _ = emit_finish_refusal(
            "attempt-740-20",
            RejectionReason::Refused,
            OwningComponent::Governor,
        );
        let _ = RequestReceipt::of(canary, canary).emit();
    }
    let fallback = String::from_utf8(fallback_bytes).map_err(|error| format!("utf8: {error}"))?;
    for canary in canaries {
        assert!(
            !fallback.contains(canary),
            "secret canary leaked into fallback sink: {canary}"
        );
    }
    let lines = eliotd::diagnostics::captured_records();
    for canary in canaries {
        assert_canary_absent(&lines, canary);
    }
    Ok(())
}

// WORK_UNIT_CASE: 740/21
#[test]
fn source_api_diff_and_call_ledger_guards_cover_daemon_partition() -> TestResult {
    assert_eq!(eliotd::SERVICE_NAME, "eliotd");
    assert_eq!(eliotd::PROTOCOL_VERSION, "eliot.daemon.v1");

    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, "candidate-740-21")?;
    let candidate_id = request.candidate_id.clone();
    let candidate = plan_candidate(&daemon_coordinator_config()?, request)?;
    assert_eq!(candidate.candidate_id, candidate_id);

    let mut world = test_world(false)?;
    let fence = test_fence()?;
    let route = test_route()?;
    let request = test_request(&fence, &route, "candidate-740-21b")?;
    let (definition, planned) = world.fabric.define_and_plan(request)?;
    assert_eq!(definition.definition_id, planned.candidate_id);
    let reservation = world.fabric.stage_reservation(&definition.definition_id)?;
    let admission = world.fabric.commit_admission(&reservation.reservation_id)?;
    let replayed = world.fabric.commit_admission(&reservation.reservation_id)?;
    assert_eq!(admission.admission_id, replayed.admission_id);
    assert_eq!(
        counter_value(&world.admission.commit_calls),
        1,
        "exact replay must not call the owner twice"
    );
    let events = world.fabric.ledger_events();
    let positions: Vec<usize> = [
        "definition_validated",
        "plan_compiled",
        "reservation_staged",
    ]
    .iter()
    .map(|event| {
        events
            .iter()
            .position(|entry| entry == event)
            .ok_or_else(|| format!("ledger misses {event}"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(Box::<dyn std::error::Error>::from)?;
    assert!(positions[0] < positions[1] && positions[1] < positions[2]);
    assert!(events.iter().any(|entry| entry == "admission_committed"));

    let attempt = admission
        .attempt_ids
        .first()
        .ok_or("admission must carry one attempt")?;
    let finish_error = match world.fabric.require_finish(attempt) {
        Ok(()) => return Err("attempt result is never task Finish".into()),
        Err(error) => error,
    };
    assert!(matches!(finish_error, FabricError::ResultNotFinish(_)));

    let runtime = manifest_source("src/daemon_runtime.rs")?;
    assert!(runtime.contains("attach_agent_fabric"));
    let fabric = manifest_source("src/agent_fabric.rs")?;
    assert!(fabric.contains("eliotd.fabric_commit"));
    let projection = manifest_source("src/activation_projection.rs")?;
    assert!(projection.contains("eliotd.activation_projection"));
    let _ = emit_fabric_attached(eliotd::SERVICE_NAME, 1, 1);
    Ok(())
}
