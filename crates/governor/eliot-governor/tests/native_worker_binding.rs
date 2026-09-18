//! Focused T9-01 projection tests: real binding validation plus real
//! `GovernorComposition::publish_native_worker_binding` over a Kernel-backed
//! composition built in-test (FakeKernel pattern, no binding mocks).

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_authority::{EffectAuthorizer, GrantGraph};
use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    canonical_json_bytes, sha256_hex,
};
use eliot_coordination::CoordinationOwner;
use eliot_finish::FinishDecisionReceipt;
use eliot_governor::{
    AuthorityOwnerSnapshot, BudgetOwnerSnapshot, BudgetOwnerState, CanonicalAdmissionSnapshot,
    CanonicalPlanBinding, CompositionError, ConfigOwnerSnapshot, EmptyOwnerSnapshot,
    GovernorComposition, KernelDurableJobPort, KernelGenerationExpectation,
    KernelGenerationSnapshot, KernelGenerationSnapshotProvider, KernelNamedReadReply,
    KernelNamedReadRequest, KernelPortError, KernelPortFuture, KernelRecoveryPort,
    KernelServiceObservationPort, KernelServiceRecovery, KernelTransitionPort,
    NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID, NativeWorkerExecutableBinding, OWNER_SNAPSHOT_SCHEMA,
    ProblemOwnerSnapshot, QueueLimits, ReadOwnerSnapshot, RecoveryOwner,
};
use eliot_module_registry::ModuleCatalog;
use eliot_observation::ObservationJournalEntry;
use eliot_protocol::RequestIdentity;
use eliot_session::{
    RegisterSession, SessionCommand, SessionCommandContext, SessionLifecycleOwner,
};
use eliot_skill::SkillLifecycleView;
use eliot_store_api::{EffectClass, PreparedTransition, ScopeId, ScopeRevisionView, StoreHealth};
use eliot_task::{TaskLifecycleEvent, TaskLifecycleSnapshot, TaskRecord, TaskState};
use eliot_workscope::WorkScopeBindingSnapshot;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

struct TestKernel {
    snapshot: KernelGenerationSnapshot,
    payloads: BTreeMap<RecoveryOwner, Vec<u8>>,
}

impl KernelGenerationSnapshotProvider for TestKernel {
    fn snapshot(&self) -> &KernelGenerationSnapshot {
        &self.snapshot
    }
}

impl KernelTransitionPort for TestKernel {
    fn apply_prepared<'a>(
        &'a self,
        _identity: &RequestIdentity,
        _transition: PreparedTransition,
        _expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, eliot_store_api::WriteReceipt> {
        Box::pin(async move {
            Err(KernelPortError::NotAdmitted(
                "test port never executes transitions".to_owned(),
            ))
        })
    }

    fn receipt(
        &self,
        _operation_id: eliot_contracts::OperationId,
    ) -> KernelPortFuture<'_, Option<eliot_store_api::WriteReceipt>> {
        Box::pin(async move { Ok(None) })
    }

    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        Box::pin(async move { Err(KernelPortError::NotAdmitted("test port".to_owned())) })
    }
}

impl KernelRecoveryPort for TestKernel {
    fn named_read(
        &self,
        request: KernelNamedReadRequest,
    ) -> Result<Option<KernelNamedReadReply>, KernelPortError> {
        let payload = self
            .payloads
            .get(&request.owner)
            .cloned()
            .expect("test payload missing");
        Ok(Some(KernelNamedReadReply {
            owner: request.owner,
            state_fence: request.state_fence,
            revision: 1,
            schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
            value_digest: sha256_hex(&payload),
            payload,
        }))
    }

    fn initialize_governor_genesis(
        &self,
        _request: &eliot_governor::GovernorGenesisRequest,
    ) -> Result<(), KernelPortError> {
        Ok(())
    }

    fn canonical_scope(
        &self,
        state_fence: &StateFence,
        _protected_snapshot_digest: &str,
    ) -> Result<ScopeRevisionView, KernelPortError> {
        Ok(ScopeRevisionView {
            scope_id: ScopeId::new("governor").expect("scope"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: state_fence.clone(),
        })
    }

    fn receipts(
        &self,
        _state_fence: &StateFence,
        _protected_snapshot_digest: &str,
    ) -> Result<Vec<eliot_store_api::WriteReceipt>, KernelPortError> {
        Ok(Vec::new())
    }

    fn durable_jobs(
        &self,
        _state_fence: &StateFence,
        _protected_snapshot_digest: &str,
    ) -> Result<Vec<eliot_maintenance::MaintenanceJob>, KernelPortError> {
        Ok(Vec::new())
    }
}

impl KernelServiceObservationPort for TestKernel {
    fn services(
        &self,
        state_fence: &StateFence,
        _protected_snapshot_digest: &str,
    ) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
        Ok(eliot_governor::STARTUP_ORDER
            .into_iter()
            .map(|service| KernelServiceRecovery {
                service,
                observation: eliot_governor::ServiceObservation {
                    state: eliot_runtime_contracts::ServiceProcessState::Ready,
                    health: eliot_runtime_contracts::HealthVector::healthy(),
                    generation: state_fence.resource_generation,
                    authority_epoch: state_fence.authority_epoch.clone(),
                },
            })
            .collect())
    }
}

impl KernelDurableJobPort for TestKernel {
    fn load_durable_job(
        &self,
        _job_id: &str,
        _state_fence: &StateFence,
    ) -> Result<Option<eliot_maintenance::MaintenanceJob>, KernelPortError> {
        Ok(None)
    }

    fn save_durable_job(
        &self,
        _job: &eliot_maintenance::MaintenanceJob,
    ) -> Result<(), KernelPortError> {
        Ok(())
    }
}

fn test_snapshot() -> KernelGenerationSnapshot {
    KernelGenerationSnapshot {
        service: "eliot-kernel".to_owned(),
        protocol: "eliot.kernel.v1".to_owned(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: test_epoch(TEST_LINEAGE_A, 1),
        artifact_digest: "a".repeat(64),
        protected_snapshot_digest: "b".repeat(64),
        principal: "S-1-5-18".to_owned(),
    }
}

fn activation_task_snapshot(fence: &StateFence) -> TaskLifecycleSnapshot {
    let task_id = TaskId::new("task-1").expect("task id");
    TaskLifecycleSnapshot {
        next_sequence: 2,
        tasks: BTreeMap::from([(
            task_id.clone(),
            TaskRecord {
                task_id: task_id.clone(),
                project_ref: "project-1".to_owned(),
                goal: "activate me".to_owned(),
                state: TaskState::ActionAuthorized,
                revision: 1,
                last_sequence: 1,
                last_event_id: "task-event-1".to_owned(),
                state_fence: fence.clone(),
            },
        )]),
        events: vec![TaskLifecycleEvent {
            sequence: 1,
            event_id: "task-event-1".to_owned(),
            request_id: "task-request-1".to_owned(),
            task_id,
            actor_ref: "agent-1".to_owned(),
            from: None,
            to: TaskState::ActionAuthorized,
            command: None,
            state_fence: fence.clone(),
            authority_epoch: fence.authority_epoch.clone(),
            observed_at: ClockReading::default(),
        }],
    }
}

fn activation_session_snapshot(fence: &StateFence) -> eliot_session::SessionLifecycleSnapshot {
    let mut owner = SessionLifecycleOwner::new(fence.authority_epoch.clone(), fence.clone())
        .expect("session owner");
    let session_id = eliot_contracts::SessionId::new("session-1").expect("session id");
    owner
        .register(RegisterSession {
            request_id: "session-request-1".to_owned(),
            event_id: "session-event-1".to_owned(),
            session_id: session_id.clone(),
            agent_id: "agent-1".to_owned(),
            model_route: "route-1".to_owned(),
            harness: "harness-1".to_owned(),
            role: "worker".to_owned(),
            project_scope: "scope-1".to_owned(),
            task_scope: Some("task-1".to_owned()),
            capability_profile_id: "profile-1".to_owned(),
            parent_session_id: None,
            policy_snapshot_id: "policy-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            now: 1,
            expires_at: 100,
        })
        .expect("session register");
    owner
        .apply(
            session_id,
            SessionCommandContext {
                request_id: "session-activate-request".to_owned(),
                event_id: "session-activate-event".to_owned(),
                actor_ref: "agent-1".to_owned(),
                state_fence: fence.clone(),
                authority_epoch: fence.authority_epoch.clone(),
                observed_at: ClockReading::default(),
                now: 2,
            },
            SessionCommand::Activate,
        )
        .expect("session activate");
    owner.snapshot()
}

fn activation_scope_snapshot(fence: &StateFence) -> WorkScopeBindingSnapshot {
    serde_json::from_value(serde_json::json!({
        "state_fence": fence,
        "owner_revision": 1,
        "binding": {
            "scope": {
                "scope_ref": "scope:work",
                "kind": "git_repo",
                "lineage_ref": "lineage:work",
                "instance_ref": "instance:work",
                "root_identity": "root:work",
                "generation": 1
            },
            "privacy_class": "INTERNAL",
            "governing_source_generation": 1
        },
        "guard_receipt": {
            "expected_scope_ref": "scope:work",
            "observed_scope_ref": "scope:work",
            "expected_lineage_ref": "lineage:work",
            "observed_lineage_ref": "lineage:work",
            "expected_instance_ref": "instance:work",
            "observed_instance_ref": "instance:work",
            "disposition": "MATCHED",
            "source_generation": 1
        }
    }))
    .expect("work scope binding")
}

fn activation_canonical_snapshot(fence: &StateFence) -> CanonicalAdmissionSnapshot {
    CanonicalAdmissionSnapshot {
        state_fence: fence.clone(),
        owner_revision: 1,
        current_plan: Some(CanonicalPlanBinding {
            plan_id: "plan:current".to_owned(),
            plan_revision: "1".to_owned(),
            task_id: TaskId::new("task-1").expect("task id"),
            work_scope_id: "scope:work".to_owned(),
        }),
    }
}

fn build_payloads(fence: &StateFence, protected: &str) -> BTreeMap<RecoveryOwner, Vec<u8>> {
    let mut payloads = BTreeMap::new();
    let put = |map: &mut BTreeMap<RecoveryOwner, Vec<u8>>,
               owner: RecoveryOwner,
               value: serde_json::Value| {
        map.insert(
            owner,
            canonical_json_bytes(&value).expect("canonical payload"),
        );
    };
    put(
        &mut payloads,
        RecoveryOwner::WorkScope,
        serde_json::to_value(activation_scope_snapshot(fence)).expect("scope"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Task,
        serde_json::to_value(activation_task_snapshot(fence)).expect("task"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Session,
        serde_json::to_value(activation_session_snapshot(fence)).expect("session"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Canonical,
        serde_json::to_value(activation_canonical_snapshot(fence)).expect("canonical"),
    );
    let grant_graph = GrantGraph::from_grants(std::iter::empty(), 1)
        .and_then(|graph| graph.recovery_snapshot())
        .expect("empty grant graph");
    let effect_authorizer = EffectAuthorizer::default()
        .snapshot()
        .expect("empty authorizer");
    put(
        &mut payloads,
        RecoveryOwner::Authority,
        serde_json::to_value(
            AuthorityOwnerSnapshot::new(fence.clone(), grant_graph, effect_authorizer)
                .expect("authority snapshot"),
        )
        .expect("authority"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Budget,
        serde_json::to_value(BudgetOwnerSnapshot {
            schema: "eliot.governor.budget-owner.v1".to_owned(),
            version: 1,
            state_fence: fence.clone(),
            revision: 1,
            state: BudgetOwnerState::Unconfigured,
        })
        .expect("budget"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Config,
        serde_json::to_value(ConfigOwnerSnapshot {
            state_fence: fence.clone(),
            revision: 1,
            config_digest: protected.to_owned(),
        })
        .expect("config"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Coordination,
        serde_json::to_value(CoordinationOwner::new()).expect("coordination"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Finish,
        serde_json::to_value(Vec::<FinishDecisionReceipt>::new()).expect("finish"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Problem,
        serde_json::to_value(ProblemOwnerSnapshot {
            state_fence: fence.clone(),
            revisions: BTreeMap::new(),
        })
        .expect("problem"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Observation,
        serde_json::to_value(Vec::<ObservationJournalEntry>::new()).expect("observation"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Read,
        serde_json::to_value(ReadOwnerSnapshot {
            state_fence: fence.clone(),
            revision: 1,
        })
        .expect("read"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Skill,
        serde_json::to_value(Vec::<SkillLifecycleView>::new()).expect("skill"),
    );
    put(
        &mut payloads,
        RecoveryOwner::ModuleRegistry,
        serde_json::to_value(
            ModuleCatalog::new(fence.clone())
                .expect("module")
                .snapshot()
                .expect("module snapshot"),
        )
        .expect("module"),
    );
    put(
        &mut payloads,
        RecoveryOwner::ChangeMonitor,
        serde_json::to_value(eliot_change_monitor::ChangeMonitorSnapshot::default())
            .expect("change monitor"),
    );
    put(
        &mut payloads,
        RecoveryOwner::Maintenance,
        serde_json::to_value(EmptyOwnerSnapshot {
            state_fence: fence.clone(),
            revision: 1,
        })
        .expect("maintenance"),
    );
    payloads
}

fn build_composition() -> GovernorComposition<TestKernel> {
    let snapshot = test_snapshot();
    let fence = snapshot.state_fence();
    let protected = snapshot.protected_snapshot_digest.clone();
    let kernel = TestKernel {
        snapshot: snapshot.clone(),
        payloads: build_payloads(&fence, &protected),
    };
    let expected = KernelGenerationExpectation::from_snapshot(&snapshot).expect("expectation");
    GovernorComposition::new(Arc::new(kernel), None, &expected, QueueLimits::default())
        .expect("composition")
}

fn publish_valid(composition: &GovernorComposition<TestKernel>) -> NativeWorkerExecutableBinding {
    composition
        .publish_native_worker_binding(
            "claim-1",
            "reg-1",
            "install-1",
            "task-1",
            "work-1",
            "scope:work",
            1,
            "lease-1",
            "op-1",
            &"c".repeat(64),
            "principal-1",
            "session-1",
            1,
            "proc-tree-1",
            1,
            "process-fence-1",
            "route-1",
            "adapter-1",
            1,
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
            "cmd-1",
            "facet-1",
            vec!["intro-1".to_owned()],
            vec!["grant-1".to_owned()],
            1,
            EffectClass::ReversibleMutation,
            vec!["cred-1".to_owned()],
            vec!["res-1".to_owned()],
            "stream-1",
            "0123456789abcdef",
            &"1".repeat(64),
            100,
            200,
            "plan:current",
            "1",
            1,
            &"b".repeat(64),
            "adm-1",
        )
        .expect("valid publish")
}

#[test]
fn publish_produces_valid_binding_with_stable_digest() {
    let composition = build_composition();
    let binding = publish_valid(&composition);
    assert_eq!(binding.wire_id, NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID);
    assert_eq!(binding.wire_version, 1);
    binding.validate().expect("valid binding");
    let first = binding.compute_digest().expect("digest");
    let second = binding.compute_digest().expect("digest");
    assert_eq!(first, second);
    assert_eq!(first, binding.binding_digest);
    let bytes_first = binding.unsigned_bytes().expect("unsigned bytes");
    let bytes_second = binding.unsigned_bytes().expect("unsigned bytes");
    assert_eq!(bytes_first, bytes_second);
}

#[test]
fn tampered_digest_fails() {
    let composition = build_composition();
    let binding = publish_valid(&composition);
    let mut tampered = binding.clone();
    let mut digest_chars: Vec<char> = tampered.binding_digest.chars().collect();
    let last = digest_chars[63];
    digest_chars[63] = if last == 'a' { 'b' } else { 'a' };
    tampered.binding_digest = digest_chars.into_iter().collect();
    assert!(tampered.validate().is_err());

    let mut field_tampered = binding.clone();
    field_tampered.adapter_revision += 1;
    assert!(field_tampered.validate().is_err());
}

#[test]
fn wrong_wire_version_fails() {
    let composition = build_composition();
    let binding = publish_valid(&composition);
    let mut wrong = binding.clone();
    wrong.wire_version = 2;
    let recomputed = wrong
        .compute_digest()
        .expect("recompute after version change");
    wrong.binding_digest = recomputed;
    assert!(wrong.validate().is_err());
}

#[test]
fn stale_task_revision_fails_publish() {
    let composition = build_composition();
    let result = composition.publish_native_worker_binding(
        "claim-1",
        "reg-1",
        "install-1",
        "task-1",
        "work-1",
        "scope:work",
        1,
        "lease-1",
        "op-1",
        &"c".repeat(64),
        "principal-1",
        "session-1",
        1,
        "proc-tree-1",
        1,
        "process-fence-1",
        "route-1",
        "adapter-1",
        1,
        &"d".repeat(64),
        &"e".repeat(64),
        &"f".repeat(64),
        "cmd-1",
        "facet-1",
        vec!["intro-1".to_owned()],
        vec!["grant-1".to_owned()],
        1,
        EffectClass::ReversibleMutation,
        vec!["cred-1".to_owned()],
        vec!["res-1".to_owned()],
        "stream-1",
        "0123456789abcdef",
        &"1".repeat(64),
        100,
        200,
        "plan:current",
        "1",
        999,
        &"b".repeat(64),
        "adm-1",
    );
    assert!(matches!(result, Err(CompositionError::Recovery(_))));
}

#[test]
fn foreign_fence_binding_fails_validate() {
    let composition = build_composition();
    let binding = publish_valid(&composition);
    let mut foreign = binding.clone();
    foreign.state_fence = StateFence::new(
        test_epoch(TEST_LINEAGE_A, 1),
        ResourceGeneration::new(2).expect("generation"),
    );
    let recomputed = foreign.compute_digest().expect("recompute foreign fence");
    foreign.binding_digest = recomputed;
    assert!(foreign.validate().is_err());
}
