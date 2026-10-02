//! Issue #1746 acceptance edge: the Governor composition reads the exact
//! cold-start terminal through its bound ORS owner. The fixture is limited to
//! test Kernel owner snapshots and a durable-readiness owner response.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_governor::{
    AuthorityOwnerSnapshot, BudgetOwnerSnapshot, CanonicalAdmissionSnapshot, ConfigOwnerSnapshot,
    EmptyOwnerSnapshot, GovernorComposition, KernelDurableJobPort, KernelGenerationExpectation,
    KernelGenerationSnapshot, KernelGenerationSnapshotProvider, KernelNamedReadReply,
    KernelNamedReadRequest, KernelPortError, KernelPortFuture, KernelRecoveryPort,
    KernelServiceObservationPort, KernelServiceRecovery, KernelTransitionPort, QueueLimits,
    RecoveryOwner, ReadOwnerSnapshot, OWNER_SNAPSHOT_SCHEMA, PolicyOwnerSnapshot,
};
use eliot_ors::{
    ColdStartReadinessClaim, ColdStartReadinessOrsRecord,
    ColdStartReadinessTerminalDisposition, RedbRecoveryStore,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    PreparedTransition, RevisionHeadExpectation, ScopeId, ScopeRevisionView, StoreHealth,
    WriteReceipt,
};
use eliot_workscope::{
    InstallationScanContour, OnboardingLease, OnboardingLeaseState, OnboardingReadinessReceipt,
    ProofReadiness, ReadinessLifecycle, ScopeIdentity, ScopeKind, ScopeResolutionState,
    TaskBindingState,
};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const INSTALLATION: &str = "install-1746";

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            std::num::NonZeroU64::new(1).expect("epoch sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    )
}

struct TestKernel {
    snapshot: KernelGenerationSnapshot,
    payloads: BTreeMap<RecoveryOwner, Vec<u8>>,
    acceptance: Mutex<Option<eliot_store_api::TaskContractAcceptanceSet>>,
}

impl KernelGenerationSnapshotProvider for TestKernel {
    fn snapshot(&self) -> &KernelGenerationSnapshot { &self.snapshot }
}

impl KernelTransitionPort for TestKernel {
    fn apply_prepared<'a>(
        &'a self,
        _identity: &RequestIdentity,
        _transition: PreparedTransition,
        _expected_revision_heads: Vec<RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt> {
        Box::pin(async { Err(KernelPortError::NotAdmitted("readback fixture".to_owned())) })
    }
    fn receipt(&self, _operation_id: eliot_contracts::OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
        Box::pin(async { Ok(None) })
    }
    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        Box::pin(async { Err(KernelPortError::NotAdmitted("readback fixture".to_owned())) })
    }
    fn task_contract_acceptance_set(
        &self,
        task_id: &eliot_contracts::TaskId,
        task_revision: u64,
        state_fence: &StateFence,
    ) -> KernelPortFuture<'_, eliot_store_api::TaskContractAcceptanceSet> {
        let result = self.acceptance.lock().expect("acceptance lock").clone().filter(|set| {
            set.task_id == *task_id && set.task_revision == task_revision && set.read_state_fence == *state_fence
        }).ok_or_else(|| KernelPortError::NotAdmitted("test has no matching task contract acceptance set".to_owned()));
        Box::pin(async move { result })
    }
}

impl KernelRecoveryPort for TestKernel {
    fn named_read(&self, request: KernelNamedReadRequest) -> Result<Option<KernelNamedReadReply>, KernelPortError> {
        let payload = self.payloads.get(&request.owner).cloned().unwrap_or_else(|| owner_payload(request.owner, &request.state_fence, &request.protected_snapshot_digest));
        Ok(Some(KernelNamedReadReply {
            owner: request.owner,
            state_fence: request.state_fence,
            revision: 1,
            schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
            value_digest: sha256_hex(&payload),
            payload,
        }))
    }
    fn initialize_governor_genesis(&self, _request: &eliot_governor::GovernorGenesisRequest) -> Result<(), KernelPortError> { Ok(()) }
    fn canonical_scope(&self, state_fence: &StateFence, _digest: &str) -> Result<ScopeRevisionView, KernelPortError> {
        Ok(ScopeRevisionView { scope_id: ScopeId::new("governor").expect("scope"), revision_heads: Vec::new(), ordering_heads: Vec::new(), state_fence: state_fence.clone() })
    }
    fn receipts(&self, _state_fence: &StateFence, _digest: &str) -> Result<Vec<WriteReceipt>, KernelPortError> { Ok(Vec::new()) }
    fn durable_jobs(&self, _state_fence: &StateFence, _digest: &str) -> Result<Vec<eliot_maintenance::MaintenanceJob>, KernelPortError> { Ok(Vec::new()) }
}

impl KernelServiceObservationPort for TestKernel {
    fn services(&self, state_fence: &StateFence, _digest: &str) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
        Ok(eliot_governor::STARTUP_ORDER.into_iter().map(|service| KernelServiceRecovery {
            service,
            observation: eliot_governor::ServiceObservation {
                state: eliot_runtime_contracts::ServiceProcessState::Ready,
                health: eliot_runtime_contracts::HealthVector::healthy(),
                generation: state_fence.resource_generation,
                authority_epoch: state_fence.authority_epoch.clone(),
            },
        }).collect())
    }
}

impl KernelDurableJobPort for TestKernel {
    fn load_durable_job(&self, _job_id: &str, _fence: &StateFence) -> Result<Option<eliot_maintenance::MaintenanceJob>, KernelPortError> { Ok(None) }
    fn save_durable_job(&self, _job: &eliot_maintenance::MaintenanceJob) -> Result<(), KernelPortError> { Ok(()) }
}

fn snapshot() -> KernelGenerationSnapshot {
    KernelGenerationSnapshot {
        service: "eliot-kernel".to_owned(), protocol: "eliot.kernel.v1".to_owned(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: fence().authority_epoch,
        artifact_digest: "a".repeat(64), protected_snapshot_digest: "b".repeat(64),
        principal: "S-1-5-18".to_owned(),
    }
}

fn kernel_with_current_task(snapshot: KernelGenerationSnapshot) -> TestKernel {
    use eliot_contracts::{TaskId, ClockReading};
    use eliot_governor::{CanonicalPlanBinding, CanonicalVerifierPlanState};
    use eliot_coordination::{RegisterSession as CoordinationRegisterSession, WorkItem, WorkLeaseRequest, WorkState, CoordinationOwner};
    use eliot_session::{RegisterSession, SessionCommand, SessionCommandContext, SessionLifecycleOwner};
    use eliot_session::SessionLifecycleSnapshot;
    use eliot_task::{TaskLifecycleEvent, TaskLifecycleSnapshot, TaskRecord, TaskState};
    let state_fence = snapshot.state_fence();
    let mut payloads = BTreeMap::new();
    let mut task = TaskLifecycleSnapshot { next_sequence: 2, tasks: BTreeMap::new(), events: Vec::new(), professional_execution: BTreeMap::new() };
    let task_id = TaskId::new("task-1746").expect("task id");
    task.tasks.insert(task_id.clone(), TaskRecord {
        task_id: task_id.clone(), project_ref: "project-1746".to_owned(), goal: "prove task-bound dispatch".to_owned(),
        state: TaskState::ActionAuthorized, revision: 1, last_sequence: 1, last_event_id: "task-event-1746".to_owned(), state_fence: state_fence.clone(),
    });
    task.events.push(TaskLifecycleEvent {
        sequence: 1, event_id: "task-event-1746".to_owned(), request_id: "task-request-1746".to_owned(),
        task_id: task_id.clone(), actor_ref: "agent-1746".to_owned(), from: None, to: TaskState::ActionAuthorized,
        command: None, professional_execution: None, state_fence: state_fence.clone(), authority_epoch: state_fence.authority_epoch.clone(), observed_at: ClockReading::default(),
    });
    payloads.insert(RecoveryOwner::Task, canonical_json_bytes(&task).expect("task owner bytes"));

    let session_id = eliot_contracts::SessionId::new("session-1746").expect("session id");
    let mut sessions = SessionLifecycleOwner::new(state_fence.authority_epoch.clone(), state_fence.clone()).expect("session owner");
    sessions.register(RegisterSession {
        request_id: "session-register-1746".to_owned(), event_id: "session-event-1746".to_owned(), session_id: session_id.clone(),
        agent_id: "agent-1746".to_owned(), model_route: "route-1746".to_owned(), harness: "harness-1746".to_owned(), role: "worker".to_owned(),
        project_scope: "scope-1746".to_owned(), task_scope: Some(task_id.as_str().to_owned()), capability_profile_id: "capability-1746".to_owned(),
        parent_session_id: None, policy_snapshot_id: "policy-1".to_owned(), authority_epoch: state_fence.authority_epoch.clone(), state_fence: state_fence.clone(), now: 1, expires_at: 100,
    }).expect("session register");
    sessions.apply(session_id, SessionCommandContext {
        request_id: "session-activate-1746".to_owned(), event_id: "session-activate-event-1746".to_owned(), actor_ref: "agent-1746".to_owned(),
        state_fence: state_fence.clone(), authority_epoch: state_fence.authority_epoch.clone(), observed_at: ClockReading::default(), now: 2,
    }, SessionCommand::Activate).expect("session activation");
    let session_snapshot: SessionLifecycleSnapshot = sessions.snapshot();
    payloads.insert(RecoveryOwner::Session, canonical_json_bytes(&session_snapshot).expect("session owner bytes"));

    let mut coordination = CoordinationOwner::new();
    coordination.register_session(CoordinationRegisterSession {
        request_id: "coord-session-1746".to_owned(), session_id: "session-1746".to_owned(), principal_id: "principal-1746".to_owned(),
        route_ref: "route-1746".to_owned(), authority_epoch: state_fence.authority_epoch.clone(), state_fence: state_fence.clone(), now: 1, heartbeat_deadline: 100,
    }).expect("coordination session");
    coordination.register_work(WorkItem {
        work_item_id: "work-1746".to_owned(), task_id: "task-1746".to_owned(), state: WorkState::Ready, state_fence: state_fence.clone(),
        owner_session_id: None, lease_id: None, attempt: 0, checkpoint_ref: None, result_ref: None,
    }, "work-request-1746", "principal-1746", ClockReading::default()).expect("work item");
    coordination.acquire_work(WorkLeaseRequest {
        request_id: "work-lease-1746".to_owned(), lease_id: "lease-work-1746".to_owned(), work_item_id: "work-1746".to_owned(),
        session_id: "session-1746".to_owned(), authority_epoch: state_fence.authority_epoch.clone(), state_fence: state_fence.clone(), now: 2, lease_duration: 50,
    }).expect("work lease");
    payloads.insert(RecoveryOwner::Coordination, canonical_json_bytes(&coordination).expect("coordination bytes"));

    let work_scope: eliot_workscope::WorkScopeBindingSnapshot = serde_json::from_value(serde_json::json!({
        "state_fence": state_fence, "owner_revision": 1,
        "binding": {"scope": {"scope_ref":"scope-1746", "kind":"git_repo", "lineage_ref":"lineage-1746", "instance_ref":"instance-1746", "root_identity":"root-1746", "generation":1}, "privacy_class":"INTERNAL", "governing_source_generation":1},
        "guard_receipt": {"expected_scope_ref":"scope-1746", "observed_scope_ref":"scope-1746", "expected_lineage_ref":"lineage-1746", "observed_lineage_ref":"lineage-1746", "expected_instance_ref":"instance-1746", "observed_instance_ref":"instance-1746", "disposition":"MATCHED", "source_generation":1}
    })).expect("matched WorkScope snapshot");
    payloads.insert(RecoveryOwner::WorkScope, canonical_json_bytes(&work_scope).expect("scope bytes"));
    let canonical = CanonicalAdmissionSnapshot {
        state_fence: state_fence.clone(), owner_revision: 1,
        current_plan: Some(CanonicalPlanBinding { plan_id: "plan-1746".to_owned(), plan_revision: "1".to_owned(), task_id, work_scope_id: "scope-1746".to_owned(), verifier: CanonicalVerifierPlanState::default() }),
        verifier_execution_fact: None, finish_evidence: None,
    };
    payloads.insert(RecoveryOwner::Canonical, canonical_json_bytes(&canonical).expect("canonical bytes"));
    let acceptance = eliot_store_api::TaskContractAcceptanceSet {
        schema: eliot_store_api::TASK_CONTRACT_ACCEPTANCE_SET_SCHEMA_V1.to_owned(), read_state_fence: state_fence,
        task_id: TaskId::new("task-1746").expect("task id"), task_revision: 1, acceptance_digest: "a".repeat(64),
        items: vec![eliot_store_api::TaskContractAcceptanceItem { item_id: "acceptance-1746".to_owned(), description: "dispatch remains bound to the current task".to_owned(), required_evidence: eliot_store_api::TaskContractAcceptanceEvidence::Observation }],
    };
    TestKernel { snapshot, payloads, acceptance: Mutex::new(Some(acceptance)) }
}

fn owner_payload(owner: RecoveryOwner, state_fence: &StateFence, protected: &str) -> Vec<u8> {
    use eliot_governor::{ProblemOwnerSnapshot, RecoveryOwner as R};
    use eliot_observation::ObservationJournalEntry;
    use eliot_skill::SkillLifecycleView;
    use eliot_finish::FinishDecisionReceipt;
    use eliot_coordination::CoordinationOwner;
    use eliot_module_registry::ModuleCatalog;
    use eliot_session::SessionLifecycleSnapshot;
    use eliot_task::TaskLifecycleSnapshot;
    let value = match owner {
        R::WorkScope | R::Maintenance => serde_json::to_value(EmptyOwnerSnapshot { state_fence: state_fence.clone(), revision: 1 }),
        R::Canonical => serde_json::to_value(CanonicalAdmissionSnapshot { state_fence: state_fence.clone(), owner_revision: 1, current_plan: None, verifier_execution_fact: None, finish_evidence: None }),
        R::Task => serde_json::to_value(TaskLifecycleSnapshot { next_sequence: 1, tasks: BTreeMap::new(), events: Vec::new(), professional_execution: BTreeMap::new() }),
        R::Session => serde_json::to_value(SessionLifecycleSnapshot { next_sequence: 1, sessions: BTreeMap::new(), events: Vec::new() }),
        R::Authority => {
            let grants = eliot_authority::GrantGraph::from_grants(std::iter::empty(), 1).and_then(|value| value.recovery_snapshot()).expect("empty grants");
            let effects = eliot_authority::EffectAuthorizer::default().snapshot().expect("empty effects");
            serde_json::to_value(AuthorityOwnerSnapshot::new(state_fence.clone(), grants, effects).expect("authority snapshot"))
        }
        R::Budget => serde_json::to_value(BudgetOwnerSnapshot::unconfigured(state_fence.clone(), 1)),
        R::Config => serde_json::to_value(ConfigOwnerSnapshot { state_fence: state_fence.clone(), revision: 1, config_digest: protected.to_owned() }),
        R::Coordination => serde_json::to_value(CoordinationOwner::new()),
        R::Finish => serde_json::to_value(Vec::<FinishDecisionReceipt>::new()),
        R::Problem => serde_json::to_value(ProblemOwnerSnapshot { state_fence: state_fence.clone(), revisions: BTreeMap::new() }),
        R::Observation => serde_json::to_value(Vec::<ObservationJournalEntry>::new()),
        R::Read => serde_json::to_value(ReadOwnerSnapshot { state_fence: state_fence.clone(), revision: 1 }),
        R::Skill => serde_json::to_value(Vec::<SkillLifecycleView>::new()),
        R::ModuleRegistry => serde_json::to_value(ModuleCatalog::new(state_fence.clone()).expect("catalog").snapshot().expect("snapshot")),
        R::ChangeMonitor => serde_json::to_value(eliot_change_monitor::ChangeMonitorSnapshot::default()),
        R::Policy => {
            let settings = eliot_config::ConfigPolicySnapshot {
                snapshot_id: "policy-1".to_owned(), machine_id: "machine-1".to_owned(), scope_id: "governor".to_owned(),
                revision: eliot_contracts::PolicyRevision::new(1).expect("policy revision"),
                source_completeness: eliot_config::SourceCompleteness::Complete,
                settings: vec![eliot_config::Setting { key: "mode".to_owned(), value_ref: "mode-ref".to_owned(), owner_ref: "human".to_owned() }],
                policy_owner: eliot_config::HumanOwner { owner_ref: "human".to_owned() },
                policy_fence: eliot_security_contracts::PolicyFence { policy_snapshot_id: "policy-1".to_owned(), state_fence: state_fence.clone() },
                state_fence: state_fence.clone(), parent_snapshot_id: None, rollback_of: None,
            };
            let digest = sha256_hex(&canonical_json_bytes(&settings).expect("policy bytes"));
            serde_json::to_value(PolicyOwnerSnapshot { state_fence: state_fence.clone(), revision: 1, policy_digest: digest, snapshot: settings })
        }
    }.expect("owner payload");
    canonical_json_bytes(&value).expect("canonical owner payload")
}

fn valid_record() -> ColdStartReadinessOrsRecord {
    use eliot_ors::{ColdStartReadinessOwnerKey, ColdStartReadinessTerminalReceipt};
    use eliot_security_contracts::PrivacyClass;
    use eliot_workscope::{MemoryState, RepositoryLineageIdentity, WorkspaceInstanceIdentity};
    let state_fence = fence();
    let lease = OnboardingLease { lease_ref: "lease-1746".to_owned(), lineage_candidate_ref: "lineage-1746".to_owned(), workspace_instance_candidate_ref: "instance-1746".to_owned(), privacy_class: PrivacyClass::Internal, governing_source_generation: 1, compiler_epoch: 1, state: OnboardingLeaseState::Ready, deadline: 100 };
    let lease_bytes = String::from_utf8(canonical_json_bytes(&lease).expect("lease bytes")).expect("UTF-8");
    let key = ColdStartReadinessOwnerKey { installation_id: INSTALLATION.to_owned(), lineage_candidate_ref: lease.lineage_candidate_ref.clone(), workspace_instance_candidate_ref: lease.workspace_instance_candidate_ref.clone(), filesystem_identity_ref: "root-1746".to_owned(), vcs_identity_ref: Some("vcs-1746".to_owned()), privacy_boundary_ref: "boundary-1746".to_owned(), privacy_class: PrivacyClass::Internal, governing_source_set_ref: "sources-1746".to_owned(), governing_source_generation: 1, governing_source_digests: Vec::new(), dirty_summary_ref: None, state_fence: state_fence.clone() };
    let claim = ColdStartReadinessClaim::new(key, lease.lease_ref.clone(), lease.deadline, lease_bytes).expect("claim");
    let receipt = OnboardingReadinessReceipt {
        receipt_ref: "receipt-1746".to_owned(), lease_ref: lease.lease_ref.clone(), principal_ref: "principal-1746".to_owned(), session_ref: "session-1746".to_owned(),
        scope: ScopeIdentity { scope_ref: "scope-1746".to_owned(), kind: ScopeKind::GitRepo, lineage_ref: Some(lease.lineage_candidate_ref.clone()), instance_ref: lease.workspace_instance_candidate_ref.clone(), root_identity: "root-1746".to_owned(), generation: 1 },
        scope_descriptor_revision: 1,
        instance: WorkspaceInstanceIdentity { instance_ref: lease.workspace_instance_candidate_ref.clone(), root_identity: "root-1746".to_owned(), vcs_identity_ref: Some("vcs-1746".to_owned()), generation: 1 },
        lineage: Some(RepositoryLineageIdentity { lineage_ref: lease.lineage_candidate_ref.clone(), object_store_ref: "objects-1746".to_owned(), initial_history_ref: "history-1746".to_owned(), normalized_remote_ref: None, manifest_identity_ref: None }),
        scope_resolution: ScopeResolutionState::Provisional, task_binding: TaskBindingState::None_, state_fence: state_fence.clone(),
        governing_source_set_ref: "sources-1746".to_owned(), governing_source_generation: 1, governance_profile_ref: "governance-1746".to_owned(), limiting_integration_evidence: vec!["coverage-unknown".to_owned()], route_profile_ref: "route-1746".to_owned(),
        serializer_id: "serializer".to_owned(), serializer_version: "1".to_owned(), serializer_options_digest: "c".repeat(64), tokenizer_id: "tokenizer".to_owned(), tokenizer_version: "1".to_owned(), tokenizer_hash: "d".repeat(64), projection_source_ref: "projection-1746".to_owned(), projection_generation: 1,
        readiness: ReadinessLifecycle::NeedsTask, memory_state: MemoryState::Empty, missing_inputs: vec!["task".to_owned()], next_safe_action: "select_task".to_owned(), receipt_revision: 1, discovered_source_refs: Vec::new(), admitted_source_refs: Vec::new(), conflicting_source_refs: Vec::new(), unavailable_source_refs: Vec::new(), store_identity_ref: None, proof_readiness: ProofReadiness::NoProofSurface, minimum_understanding_seed: vec!["scope-1746".to_owned()], maintenance_recommendations: Vec::new(), expiry_tick: lease.deadline, scan_receipt_ref: None,
    };
    receipt.validate().expect("valid readiness receipt");
    let receipt_bytes = String::from_utf8(canonical_json_bytes(&receipt).expect("receipt bytes")).expect("UTF-8");
    let receipt_digest = sha256_hex(receipt_bytes.as_bytes());
    let terminal = ColdStartReadinessTerminalReceipt { disposition: ColdStartReadinessTerminalDisposition::Failed, receipt_ref: receipt.receipt_ref.clone(), receipt_revision: 1, receipt_digest, receipt_bytes };
    let record_key = format!("cold-start-readiness:{}:{:020}", claim.base_identity_digest, 1);
    let record = ColdStartReadinessOrsRecord { contract_version: eliot_ors::CONTRACT_VERSION, record_key, record_revision: 1, claim, terminal: Some(terminal) };
    record.validate().expect("valid ORS readiness record");
    record
}

fn current_task_record() -> ColdStartReadinessOrsRecord {
    let mut record = valid_record();
    let terminal = record.terminal.as_mut().expect("terminal receipt");
    let mut receipt: eliot_workscope::OnboardingReadinessReceipt =
        serde_json::from_str(&terminal.receipt_bytes).expect("receipt bytes");
    receipt.scope_resolution = eliot_workscope::ScopeResolutionState::Authenticated;
    receipt.task_binding = eliot_workscope::TaskBindingState::CurrentTaskContract {
        task_ref: "task-1746".to_owned(),
        task_revision: 1,
        acceptance_digest: "a".repeat(64),
        selection_source_ref: "selection-source-1746".to_owned(),
        evidence_ref: "selection-evidence-1746".to_owned(),
    };
    receipt.readiness = eliot_workscope::ReadinessLifecycle::ReadyMaterial;
    receipt.missing_inputs.clear();
    receipt.validate().expect("current material receipt");
    terminal.receipt_bytes = String::from_utf8(canonical_json_bytes(&receipt).expect("receipt bytes")).expect("UTF-8");
    terminal.receipt_ref = receipt.receipt_ref;
    terminal.receipt_digest = sha256_hex(terminal.receipt_bytes.as_bytes());
    terminal.disposition = ColdStartReadinessTerminalDisposition::Ready;
    record.validate().expect("ready owner terminal");
    record
}

fn persist_and_bind_readiness_record(
    composition: &mut GovernorComposition<TestKernel>,
    record: &ColdStartReadinessOrsRecord,
) -> (Arc<RedbRecoveryStore>, std::path::PathBuf) {
    let scratch = std::path::PathBuf::from(r"C:\Development\Rust\projects\eliot-swarm\control-20260923-impl\v2\workers\CS1\scratch\1746");
    std::fs::create_dir_all(&scratch).expect("approved task scratch exists");
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_nanos();
    let database_path = scratch.join(format!("session-scope-readback-{nonce}.redb"));
    let (store, identity) = RedbRecoveryStore::open_for_installation(&database_path, INSTALLATION).expect("bound ORS test store");
    let claim = &record.claim;
    let row = match store.claim_cold_start_readiness(claim, 10).expect("persist original lease") {
        eliot_ors::ColdStartReadinessStageOutcome::Stored { record } => *record,
        eliot_ors::ColdStartReadinessStageOutcome::AlreadyBound { .. } => panic!("fresh fixture key"),
    };
    let terminal = record.terminal.as_ref().expect("terminal receipt");
    store.publish_cold_start_readiness(&row.record_key, &claim.binding_digest, &claim.lease_ref, terminal.disposition, &terminal.receipt_ref, &terminal.receipt_bytes).expect("persist immutable terminal");
    let owner_record = store.load_cold_start_readiness_for_binding(&claim.binding_digest).expect("read ORS row").expect("stored row");
    assert_eq!(&owner_record, record);
    let owner = Arc::new(store);
    let contour = InstallationScanContour::bind(INSTALLATION, database_path.to_string_lossy(), identity.ors_generation()).expect("contour");
    composition.bind_cold_start_readiness_owner(&contour, owner.clone()).expect("bind readiness ORS owner");
    (owner, database_path)
}

#[test]
fn governor_composition_reads_the_full_bound_ors_readiness_record() {
    let observed = snapshot();
    let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
    let kernel = Arc::new(TestKernel { snapshot: observed, payloads: BTreeMap::new(), acceptance: Mutex::new(None) });
    let mut composition = GovernorComposition::new(kernel, None, &expected, QueueLimits::default()).expect("Governor composition");
    let record = valid_record();
    let claim = record.claim.clone();
    let (owner, database_path) = persist_and_bind_readiness_record(&mut composition, &record);

    let readback = composition.cold_start_owner_readback_with_delta_for_claim(&claim, None, 10).expect("exact raw ORS row and terminal readback");
    assert_eq!(readback.readback.record, record, "composition returns the owner's original durable record");
    assert_eq!(readback.readback.receipt.receipt_ref, "receipt-1746");
    assert_eq!(readback.readback.lease.lease_ref, "lease-1746");
    assert_eq!(readback.readback.surface.readiness, "NEEDS_TASK");

    let mut foreign_key = claim.key.clone();
    foreign_key.workspace_instance_candidate_ref = "instance-other".to_owned();
    let mut foreign_lease: OnboardingLease = serde_json::from_str(&claim.lease_bytes).expect("stored lease bytes");
    foreign_lease.workspace_instance_candidate_ref = "instance-other".to_owned();
    let foreign = ColdStartReadinessClaim::new(
        foreign_key,
        claim.lease_ref.clone(),
        claim.lease_deadline,
        String::from_utf8(canonical_json_bytes(&foreign_lease).expect("foreign lease bytes")).expect("UTF-8"),
    ).expect("valid but foreign full claim");
    assert!(composition.cold_start_owner_readback_with_delta_for_claim(&foreign, None, 10).is_err(), "a caller claim that does not name the stored full owner key cannot recover its row");
    drop(composition);
    drop(owner);
    std::fs::remove_file(database_path).expect("remove approved test store");
}

#[test]
fn governor_rechecks_current_task_contract_acceptance_at_the_live_fence() {
    use eliot_observation::TaskSelectionEvidence;
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWake;
    impl Wake for NoopWake { fn wake(self: Arc<Self>) {} }
    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    let observed = snapshot();
    let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
    let kernel = Arc::new(kernel_with_current_task(observed));
    let mut composition = GovernorComposition::new(kernel.clone(), None, &expected, QueueLimits::default()).expect("Governor composition");
    let record = current_task_record();
    let claim = record.claim.clone();
    let (owner, database_path) = persist_and_bind_readiness_record(&mut composition, &record);
    let raw_readback = composition
        .cold_start_owner_readback_with_delta_for_claim(&claim, None, 10)
        .expect("current task terminal comes from the exact bound ORS owner");
    assert_eq!(raw_readback.readback.record, record);
    assert!(matches!(
        raw_readback.readback.receipt.task_binding,
        TaskBindingState::CurrentTaskContract { ref task_ref, task_revision: 1, ref acceptance_digest, .. }
            if task_ref == "task-1746" && acceptance_digest == &"a".repeat(64)
    ));
    let activation = composition.read_unique_agent_activation(10).expect("actual Governor current activation from session, coordination, task, scope and canonical owners");
    assert_eq!(activation.task_id.as_str(), "task-1746");

    let selection = TaskSelectionEvidence {
        task_ref: "task-1746".to_owned(), task_revision: 1, acceptance_digest: "a".repeat(64),
        work_scope_ref: "scope-1746".to_owned(), selection_source_ref: "selection-source-1746".to_owned(),
        evidence_ref: "selection-evidence-1746".to_owned(), contamination_flags: Vec::new(),
    };
    let current = block_on(composition.recheck_task_selection_for_claim(10, &claim, &selection))
        .expect("Governor reads current TaskContract acceptance set at its live fence");
    assert_eq!(current.task_ref, "task-1746");
    assert_eq!(current.acceptance_digest, "a".repeat(64));
    assert_eq!(current.state_fence, fence());

    let mut changed = kernel.acceptance.lock().expect("acceptance lock").clone().expect("owner set");
    changed.acceptance_digest = "b".repeat(64);
    *kernel.acceptance.lock().expect("acceptance lock") = Some(changed);
    let moved = block_on(composition.recheck_task_selection_for_claim(10, &claim, &selection));
    assert!(moved.is_err(), "a live TaskContract acceptance revision/digest change refuses the original selection instead of rebinding it");

    drop(composition);
    drop(owner);
    std::fs::remove_file(database_path).expect("remove approved test store");
}
