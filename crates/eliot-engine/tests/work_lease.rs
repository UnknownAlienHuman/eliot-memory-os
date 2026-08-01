use eliot_engine::{
    ActionLeaseEvaluation, ActionLeaseService, CompletionGate, PatchRunner, PatchRunnerInput,
    WorkClaimRequest, WorkLeaseService, WorkQueueService, WorkState, codecortex_report_ref,
    default_lease_ttl_minutes, default_work_scope,
};
use eliot_types::{
    ActionKind, ActionLease, ActionRequest, ActionScope, AgentId, AgentRole, AgentSessionId,
    AgentSessionStatus, AgentTransport, BlastRadiusView, ChangePlan, CodeCortexReport,
    CodeEvidenceSource, CognitiveGateDecision, CognitiveGateOutcome, CognitiveGateReason,
    CompletionAcceptanceItem, CompletionProof, CompletionStatus, DiagnosticEvidence,
    FileChangeIntent, FileChangeKind, FileEvidence, InvariantCard, LeaseDecision, LeaseDenyReason,
    LeaseStatus, OperationStatus, PatchRequest, PatchRequestId, PatchRunStatus, ProjectId,
    ReceiptId, SymbolChangeIntent, SymbolEvidence, TaskId, UnderstandingProof,
    UnderstandingProofReceipt, UnifiedDiff, VerifierCommandKind, VerifierEvidence, VerifierPlan,
    VerifierRequirement, VerifierRun, VerifierRunId, VerifierStatus, WorkItemId, WorkItemStatus,
    WorkLease, WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId,
    WorkLeaseState, WriteId, WriteReceiptRef,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn agent_session_create_controller() {
    let mut state = WorkState::default();
    let session =
        eliot_engine::AgentSessionService.create_controller(&mut state, ProjectId::new_v7());

    assert_eq!(session.role, AgentRole::Controller);
    assert_eq!(session.status, AgentSessionStatus::Active);
    assert_eq!(state.sessions.len(), 1);
}

#[test]
fn agent_session_create_for_role_persists_requested_role() {
    let mut state = WorkState::default();
    let session = eliot_engine::AgentSessionService.create_for_role(
        &mut state,
        ProjectId::new_v7(),
        AgentRole::Implementer,
    );

    assert_eq!(session.role, AgentRole::Implementer);
    assert_eq!(state.sessions[0].role, AgentRole::Implementer);
    assert_eq!(state.sessions[0].agent_session_id, session.agent_session_id);
}

#[test]
fn agent_session_subagent_hook_smoke_or_unavailable_honestly() {
    let mut state = WorkState::default();
    let controller =
        eliot_engine::AgentSessionService.create_controller(&mut state, ProjectId::new_v7());
    let subagent = eliot_engine::AgentSessionService.create_subagent_unavailable(
        &mut state,
        controller.project_id,
        controller.agent_session_id,
        "subagent adapter unavailable in unit test",
    );

    assert_eq!(subagent.transport, AgentTransport::Unavailable);
    assert!(subagent.unavailable_reason.is_some());
}

#[test]
fn work_item_create_and_claim() {
    let mut fixture = WorkFixture::new("src/lib.rs");
    let decision = fixture.claim(AgentRole::Implementer);

    assert_eq!(decision.kind, WorkLeaseDecisionKind::Granted);
    assert_eq!(fixture.state.work_items[0].status, WorkItemStatus::Active);
}

#[test]
fn work_lease_blocks_overlapping_write_scope() {
    let mut fixture = WorkFixture::new("src/lib.rs");
    let first = fixture.claim(AgentRole::Implementer);
    assert_eq!(first.kind, WorkLeaseDecisionKind::Granted);
    let second_item = fixture.create_item("src/lib.rs");
    let second = WorkLeaseService.claim(
        &mut fixture.state,
        WorkClaimRequest {
            work_item_id: second_item,
            agent_session_id: fixture.session_id,
            role: AgentRole::Implementer,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );

    assert_eq!(second.kind, WorkLeaseDecisionKind::Denied);
    assert_eq!(
        second.reason,
        WorkLeaseDecisionReason::OverlappingWriteScope
    );
}

#[test]
fn work_lease_conflicts_are_scoped_to_one_project() {
    let mut fixture = WorkFixture::new("src/lib.rs");
    assert_eq!(
        fixture.claim(AgentRole::Implementer).kind,
        WorkLeaseDecisionKind::Granted
    );

    let same_project_item = fixture.create_item("src/lib.rs");
    let same_project = WorkLeaseService.claim(
        &mut fixture.state,
        WorkClaimRequest {
            work_item_id: same_project_item,
            agent_session_id: fixture.session_id,
            role: AgentRole::Implementer,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    assert_eq!(same_project.kind, WorkLeaseDecisionKind::Denied);
    assert_eq!(
        same_project.reason,
        WorkLeaseDecisionReason::OverlappingWriteScope
    );

    let other_project = ProjectId::new_v7();
    let other_session =
        eliot_engine::AgentSessionService.create_controller(&mut fixture.state, other_project);
    let other_item = WorkQueueService.create_work_item(
        &mut fixture.state,
        eliot_engine::WorkCreateRequest {
            project_id: other_project,
            task_id: TaskId::new_v7(),
            project: "other-project".to_owned(),
            task: "task".to_owned(),
            goal: "independent project edits the same relative path".to_owned(),
            scope: default_work_scope(
                "D:/other-repo",
                vec!["src/lib.rs".to_owned()],
                vec!["src/lib.rs".to_owned()],
                vec!["cargo check".to_owned()],
            ),
            required: true,
            created_by: other_session.agent_session_id,
            required_verifiers: verifier_plan().required,
        },
    );
    let other_project_decision = WorkLeaseService.claim(
        &mut fixture.state,
        WorkClaimRequest {
            work_item_id: other_item.work_item_id,
            agent_session_id: other_session.agent_session_id,
            role: AgentRole::Implementer,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    assert_eq!(other_project_decision.kind, WorkLeaseDecisionKind::Granted);
}

#[test]
fn work_lease_allows_non_overlapping_scope() {
    let mut fixture = WorkFixture::new("src/lib.rs");
    assert_eq!(
        fixture.claim(AgentRole::Implementer).kind,
        WorkLeaseDecisionKind::Granted
    );
    let second_item = fixture.create_item("src/other.rs");
    let second = WorkLeaseService.claim(
        &mut fixture.state,
        WorkClaimRequest {
            work_item_id: second_item,
            agent_session_id: fixture.session_id,
            role: AgentRole::Implementer,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );

    assert_eq!(second.kind, WorkLeaseDecisionKind::Granted);
}

#[test]
fn work_lease_allows_read_only_auditor_overlap() {
    let mut fixture = WorkFixture::new("src/lib.rs");
    assert_eq!(
        fixture.claim(AgentRole::Implementer).kind,
        WorkLeaseDecisionKind::Granted
    );
    let audit_item = WorkQueueService.create_work_item(
        &mut fixture.state,
        eliot_engine::WorkCreateRequest {
            project_id: fixture.project_id,
            task_id: TaskId::new_v7(),
            project: "fixture".to_owned(),
            task: "audit".to_owned(),
            goal: "audit".to_owned(),
            scope: default_work_scope(
                "C:/repo",
                vec!["src/lib.rs".to_owned()],
                Vec::new(),
                Vec::new(),
            ),
            required: false,
            created_by: fixture.session_id,
            required_verifiers: Vec::new(),
        },
    );
    let audit = WorkLeaseService.claim(
        &mut fixture.state,
        WorkClaimRequest {
            work_item_id: audit_item.work_item_id,
            agent_session_id: fixture.session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );

    assert_eq!(audit.kind, WorkLeaseDecisionKind::Granted);
    assert_eq!(
        audit.reason,
        WorkLeaseDecisionReason::ReadOnlyOverlapAllowed
    );
}

#[test]
fn work_lease_renew_release_revoke() -> TestResult {
    let mut fixture = WorkFixture::new("src/lib.rs");
    let lease_id = granted_lease_id(&fixture.claim(AgentRole::Implementer))?;
    assert_eq!(
        WorkLeaseService
            .renew(&mut fixture.state, lease_id, 10)
            .kind,
        WorkLeaseDecisionKind::Renewed
    );
    assert_eq!(
        WorkLeaseService.release(&mut fixture.state, lease_id).kind,
        WorkLeaseDecisionKind::Released
    );
    let other_item = fixture.create_item("src/other.rs");
    let other = granted_lease_id(&WorkLeaseService.claim(
        &mut fixture.state,
        WorkClaimRequest {
            work_item_id: other_item,
            agent_session_id: fixture.session_id,
            role: AgentRole::Implementer,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    ))?;
    assert_eq!(
        WorkLeaseService.revoke(&mut fixture.state, other).kind,
        WorkLeaseDecisionKind::Revoked
    );
    Ok(())
}

#[test]
fn action_lease_requires_active_work_lease() {
    let fixture = ActionFixture::new();
    let lease = fixture.evaluate(None);

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::MissingWorkLease)
    );
}

#[test]
fn expired_work_lease_cannot_request_action() {
    let fixture = ActionFixture::new();
    let mut work_lease = fixture.work_lease.clone();
    work_lease.expires_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let lease = fixture.evaluate(Some(&work_lease));

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::WorkLeaseInactive)
    );
}

#[test]
fn action_lease_denies_file_outside_work_lease() {
    let fixture = ActionFixture::new();
    let mut work_lease = fixture.work_lease.clone();
    work_lease.scope.write_set = vec!["src/other.rs".to_owned()];
    let lease = fixture.evaluate(Some(&work_lease));

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::FileOutsideWorkLease)
    );
}

#[tokio::test]
async fn patch_runner_requires_active_work_lease() -> TestResult {
    let bundle = PatchBundle::new("work-lease-missing-work-lease", value_diff("2"))?;
    let run = bundle
        .runner()
        .preflight(&bundle.input(Some(&bundle.action_lease), None))
        .await?;

    assert_eq!(run.status, PatchRunStatus::Denied);
    assert!(
        run.failure_reasons
            .contains(&"missing_work_lease".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn patch_runner_denies_file_outside_work_lease() -> TestResult {
    let mut bundle = PatchBundle::new("work-lease-outside", value_diff("2"))?;
    bundle.work_lease.scope.write_set = vec!["src/other.rs".to_owned()];
    let run = bundle
        .runner()
        .preflight(&bundle.input(Some(&bundle.action_lease), Some(&bundle.work_lease)))
        .await?;

    assert_eq!(run.status, PatchRunStatus::Denied);
    assert!(
        run.failure_reasons
            .contains(&"file_outside_work_lease".to_owned())
    );
    Ok(())
}

#[test]
fn completion_requires_work_item_satisfied() -> TestResult {
    let mut fixture = WorkFixture::new("src/lib.rs");
    let lease_id = granted_lease_id(&fixture.claim(AgentRole::Implementer))?;
    let lease = find_lease(&fixture.state, lease_id)?;
    let item = &fixture.state.work_items[0];
    let proof = completion_proof(item);
    let decision = CompletionGate::decide_with_work_context(&proof, Some(item), Some(lease));

    assert_eq!(decision.final_status, CompletionStatus::PartialProgress);
    Ok(())
}

#[test]
fn work_item_completion_requires_receipted_required_verifier() {
    let mut fixture = WorkFixture::new("src/lib.rs");
    let _ = fixture.claim(AgentRole::Implementer);

    let missing = WorkQueueService.complete_verified(&mut fixture.state, fixture.item_id, &[]);
    assert!(missing.is_err());
    assert_ne!(
        fixture.state.work_items[0].status,
        WorkItemStatus::Completed
    );

    let mut unreceipted = passed_verifier_run(&fixture.state.work_items[0]);
    unreceipted.write_receipt = None;
    let invalid =
        WorkQueueService.complete_verified(&mut fixture.state, fixture.item_id, &[unreceipted]);
    assert!(invalid.is_err());
    assert_ne!(
        fixture.state.work_items[0].status,
        WorkItemStatus::Completed
    );
}

#[test]
fn revoked_work_lease_cannot_complete() -> TestResult {
    let mut fixture = WorkFixture::new("src/lib.rs");
    let lease_id = granted_lease_id(&fixture.claim(AgentRole::Implementer))?;
    let verifier = passed_verifier_run(&fixture.state.work_items[0]);
    WorkQueueService.complete_verified(&mut fixture.state, fixture.item_id, &[verifier])?;
    let mut lease = find_lease(&fixture.state, lease_id)?.clone();
    lease.state = WorkLeaseState::Revoked;
    let item = &fixture.state.work_items[0];
    let proof = completion_proof(item);
    let decision = CompletionGate::decide_with_work_context(&proof, Some(item), Some(&lease));

    assert_eq!(decision.final_status, CompletionStatus::PartialProgress);
    Ok(())
}

#[test]
fn work_status_reports_active_blocked_completed() -> TestResult {
    let empty = WorkQueueService.status_report(&WorkState::default(), "fixture", "task");
    assert_eq!(empty.operation_status, OperationStatus::OperationCompleted);

    let active = WorkFixture::new("src/active.rs");
    let active_report = WorkQueueService.status_report(&active.state, "fixture", "task");
    assert_eq!(active_report.operation_status, OperationStatus::Active);

    let mut completed = WorkFixture::new("src/completed.rs");
    let verifier = passed_verifier_run(&completed.state.work_items[0]);
    WorkQueueService.complete_verified(&mut completed.state, completed.item_id, &[verifier])?;
    let completed_report = WorkQueueService.status_report(&completed.state, "fixture", "task");
    assert_eq!(
        completed_report.operation_status,
        OperationStatus::OperationCompleted
    );

    let mut fixture = WorkFixture::new("src/lib.rs");
    let _ = fixture.claim(AgentRole::Implementer);
    let blocked_item = fixture.create_item("src/lib.rs");
    let _ = WorkLeaseService.claim(
        &mut fixture.state,
        WorkClaimRequest {
            work_item_id: blocked_item,
            agent_session_id: fixture.session_id,
            role: AgentRole::Implementer,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let verifier = passed_verifier_run(&fixture.state.work_items[0]);
    WorkQueueService.complete_verified(&mut fixture.state, fixture.item_id, &[verifier])?;
    let report = WorkQueueService.status_report(&fixture.state, "fixture", "task");

    assert_eq!(report.operation_status, OperationStatus::Blocked);
    let serialized = serde_json::to_value(&report)?;
    assert_eq!(serialized["final_status"], "BLOCKED");
    assert!(serialized.get("operation_status").is_none());
    assert!(!serialized.to_string().contains("DONE_VERIFIED"));

    assert!(
        report
            .work_items
            .iter()
            .any(|item| item.status == WorkItemStatus::Completed)
    );
    assert!(
        fixture
            .state
            .work_items
            .iter()
            .any(|item| item.status == WorkItemStatus::Blocked)
    );
    Ok(())
}

#[test]
fn the_mcp_surface_exposes_no_raw_execution_tool() -> TestResult {
    let repo = repo_root();
    let mcp = fs::read_to_string(repo.join("crates/eliot-app/src/mcp_stdio.rs"))?;
    for forbidden in [
        "eliot_shell",
        "eliot_git",
        "eliot_raw",
        "eliot_external_agent",
    ] {
        assert!(
            !mcp.contains(forbidden),
            "forbidden MCP tool marker {forbidden}"
        );
    }
    Ok(())
}

fn granted_lease_id(decision: &WorkLeaseDecision) -> TestResult<WorkLeaseId> {
    decision
        .work_lease_id
        .ok_or_else(|| std::io::Error::other("work lease was not granted").into())
}

fn find_lease(state: &WorkState, lease_id: WorkLeaseId) -> TestResult<&WorkLease> {
    state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .ok_or_else(|| std::io::Error::other("work lease not found").into())
}

struct WorkFixture {
    state: WorkState,
    project_id: ProjectId,
    session_id: AgentSessionId,
    item_id: WorkItemId,
}

impl WorkFixture {
    fn new(path: &str) -> Self {
        let mut state = WorkState::default();
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let session = eliot_engine::AgentSessionService.create_controller(&mut state, project_id);
        let item = WorkQueueService.create_work_item(
            &mut state,
            eliot_engine::WorkCreateRequest {
                project_id,
                task_id,
                project: "fixture".to_owned(),
                task: "task".to_owned(),
                goal: "work fixture".to_owned(),
                scope: default_work_scope(
                    "C:/repo",
                    vec![path.to_owned()],
                    vec![path.to_owned()],
                    vec!["cargo check".to_owned()],
                ),
                required: true,
                created_by: session.agent_session_id,
                required_verifiers: verifier_plan().required,
            },
        );
        Self {
            state,
            project_id,
            session_id: session.agent_session_id,
            item_id: item.work_item_id,
        }
    }

    fn create_item(&mut self, path: &str) -> WorkItemId {
        let item = WorkQueueService.create_work_item(
            &mut self.state,
            eliot_engine::WorkCreateRequest {
                project_id: self.project_id,
                task_id: TaskId::new_v7(),
                project: "fixture".to_owned(),
                task: "task".to_owned(),
                goal: "work fixture".to_owned(),
                scope: default_work_scope(
                    "C:/repo",
                    vec![path.to_owned()],
                    vec![path.to_owned()],
                    vec!["cargo check".to_owned()],
                ),
                required: false,
                created_by: self.session_id,
                required_verifiers: verifier_plan().required,
            },
        );
        item.work_item_id
    }

    fn claim(&mut self, role: AgentRole) -> WorkLeaseDecision {
        WorkLeaseService.claim(
            &mut self.state,
            WorkClaimRequest {
                work_item_id: self.item_id,
                agent_session_id: self.session_id,
                role,
                ttl_minutes: default_lease_ttl_minutes(),
            },
        )
    }
}

struct ActionFixture {
    request: ActionRequest,
    proof: UnderstandingProof,
    receipt: UnderstandingProofReceipt,
    gate: CognitiveGateDecision,
    report: CodeCortexReport,
    work_lease: WorkLease,
}

impl ActionFixture {
    fn new() -> Self {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let agent_id = AgentId::new_v7();
        let report = report("C:/repo", Some("head".to_owned()));
        let report_ref = codecortex_report_ref(&report);
        let proof = UnderstandingProof {
            task_id: task_id.to_string(),
            project_id,
            goal: "change src/lib.rs".to_owned(),
            code_task: true,
            current_truth_refs: Vec::new(),
            evidence_refs: Vec::new(),
            codecortex_report_refs: vec![report_ref.clone()],
            files_to_change: vec!["src/lib.rs".to_owned()],
            files_to_inspect: Vec::new(),
            causal_bridge: "goal maps to file".to_owned(),
            causal_bridge_from_goal_to_code: "change target is src/lib.rs".to_owned(),
            invariants: vec!["bounded".to_owned()],
            negative_memory_checked: true,
            unknowns: Vec::new(),
            planned_action: "plan".to_owned(),
            expected_verifiers: vec!["cargo check".to_owned()],
            blast_radius_acknowledged: true,
            skill_refs: Vec::new(),
            skill_application_rationales: Vec::new(),
            skill_anti_scope_acknowledgements: Vec::new(),
            skill_required_inputs: Vec::new(),
            skill_verifier_plan_refs: Vec::new(),
            risk_level: "low".to_owned(),
        };
        let receipt = UnderstandingProofReceipt {
            task_id: task_id.to_string(),
            project_id,
            accepted: true,
            validation_errors: Vec::new(),
            checked_refs: vec![report_ref.clone()],
            code_task: true,
            codecortex_report_refs: vec![report_ref.clone()],
            files_to_change: vec!["src/lib.rs".to_owned()],
            files_to_inspect: Vec::new(),
        };
        let gate = CognitiveGateDecision {
            task_id: task_id.to_string(),
            project_id,
            decision: CognitiveGateOutcome::AllowReadOnly,
            reasons: vec![CognitiveGateReason::Allowed],
        };
        let request = ActionRequest {
            request_id: eliot_types::ActionRequestId::new_v7(),
            project_id,
            task_id,
            agent_id,
            goal: "change src/lib.rs".to_owned(),
            requested_action_kind: ActionKind::ChangePlanOnly,
            understanding_proof_ref: "proof".to_owned(),
            cognitive_gate_ref: "gate".to_owned(),
            codecortex_report_refs: vec![report_ref],
            skill_refs: Vec::new(),
            skill_activation_decisions: Vec::new(),
            proposed_change_plan: change_plan("src/lib.rs"),
            proposed_verifier_plan: verifier_plan(),
            created_at: time::OffsetDateTime::now_utc(),
        };
        let work_lease = active_work_lease(project_id, task_id, agent_id, "C:/repo", "src/lib.rs");
        Self {
            request,
            proof,
            receipt,
            gate,
            report,
            work_lease,
        }
    }

    fn evaluate(&self, work_lease: Option<&WorkLease>) -> ActionLease {
        ActionLeaseService.evaluate(&ActionLeaseEvaluation {
            request: &self.request,
            understanding_proof: Some(&self.proof),
            understanding_receipt: &self.receipt,
            cognitive_gate_decision: &self.gate,
            codecortex_reports: std::slice::from_ref(&self.report),
            current_git_head: Some("head"),
            work_lease,
            incident_lockdown_active: false,
        })
    }
}

struct PatchBundle {
    repo_root: PathBuf,
    action_lease: ActionLease,
    work_lease: WorkLease,
    request: PatchRequest,
    report: CodeCortexReport,
    verifier_plan: VerifierPlan,
}

impl PatchBundle {
    fn new(name: &str, diff_text: String) -> TestResult<Self> {
        let repo_root = fixture_repo(name)?;
        let git_head = git_head(&repo_root)?;
        let report = report(&repo_root.display().to_string(), Some(git_head.clone()));
        let verifier_plan = verifier_plan();
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let agent_id = AgentId::new_v7();
        let action_lease = ActionLease {
            lease_id: eliot_types::ActionLeaseId::new_v7(),
            request_id: eliot_types::ActionRequestId::new_v7(),
            project_id,
            task_id,
            agent_id,
            decision: LeaseDecision::AllowPatchExecution,
            status: LeaseStatus::ApprovedForExecution,
            allowed_scope: Some(ActionScope {
                repo_root: repo_root.display().to_string(),
                git_head: Some(git_head),
                allowed_files: vec!["src/lib.rs".to_owned()],
                allowed_symbols: Vec::new(),
                forbidden_files: Vec::new(),
                max_files: 1,
                max_diff_bytes: 2048,
                max_runtime_seconds: 60,
            }),
            change_plan: None,
            verifier_plan: Some(verifier_plan.clone()),
            skill_refs: Vec::new(),
            denial_reasons: Vec::new(),
            expires_at: Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
            created_at: time::OffsetDateTime::now_utc(),
        };
        let work_lease = active_work_lease(
            project_id,
            task_id,
            agent_id,
            &repo_root.display().to_string(),
            "src/lib.rs",
        );
        let request = PatchRequest {
            patch_request_id: PatchRequestId::new_v7(),
            project_id,
            task_id,
            agent_id,
            action_lease_id: action_lease.lease_id,
            repo_root: repo_root.display().to_string(),
            git_head_before: report.git_head.clone(),
            codecortex_report_refs: vec![codecortex_report_ref(&report)],
            verifier_plan_ref: format!("verifier_plan:{}", action_lease.lease_id),
            diff: UnifiedDiff {
                byte_len: diff_text.len(),
                text: diff_text,
            },
            created_at: time::OffsetDateTime::now_utc(),
        };
        Ok(Self {
            repo_root,
            action_lease,
            work_lease,
            request,
            report,
            verifier_plan,
        })
    }

    fn runner(&self) -> PatchRunner<'_> {
        PatchRunner::new(&self.repo_root, None)
    }

    fn input<'a>(
        &'a self,
        action_lease: Option<&'a ActionLease>,
        work_lease: Option<&'a WorkLease>,
    ) -> PatchRunnerInput<'a> {
        PatchRunnerInput {
            request: &self.request,
            lease: action_lease,
            work_lease,
            codecortex_reports: std::slice::from_ref(&self.report),
            verifier_plan: Some(&self.verifier_plan),
            incident_lockdown_active: false,
        }
    }
}

fn active_work_lease(
    project_id: ProjectId,
    task_id: TaskId,
    agent_id: AgentId,
    repo_root: &str,
    path: &str,
) -> WorkLease {
    let now = time::OffsetDateTime::now_utc();
    let work_lease_id = WorkLeaseId::new_v7();
    WorkLease {
        work_lease_id,
        work_item_id: WorkItemId::new_v7(),
        agent_session_id: AgentSessionId::new_v7(),
        agent_id,
        project_id,
        task_id,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: default_work_scope(
            repo_root.to_owned(),
            vec![path.to_owned()],
            vec![path.to_owned()],
            vec!["cargo check".to_owned()],
        ),
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "fixture work lease".to_owned(),
            work_lease_id: Some(work_lease_id),
            conflicting_lease_ids: Vec::new(),
            expires_at: Some(now + time::Duration::hours(1)),
        },
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at: now + time::Duration::hours(1),
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    }
}

fn change_plan(path: &str) -> ChangePlan {
    ChangePlan {
        summary: "bounded change".to_owned(),
        files: vec![FileChangeIntent {
            path: path.to_owned(),
            reason: "fixture".to_owned(),
            expected_change_kind: FileChangeKind::Modify,
            code_evidence_refs: vec![format!("file:{path}")],
        }],
        symbols: vec![SymbolChangeIntent {
            symbol: "value".to_owned(),
            reason: "fixture".to_owned(),
            expected_change_kind: FileChangeKind::Modify,
            code_evidence_refs: vec!["symbol:value".to_owned()],
        }],
        invariants_to_preserve: vec!["bounded".to_owned()],
        risks: Vec::new(),
        rollback_plan: Some("discard".to_owned()),
    }
}

fn verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "cargo-check".to_owned(),
            command_kind: VerifierCommandKind::CargoCheck,
            command_display: "cargo check".to_owned(),
            scope: vec!["src/lib.rs".to_owned()],
            required_for_done: true,
            expected_signal: "pass".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["bounded".to_owned()],
    }
}

fn passed_verifier_run(item: &eliot_types::WorkItem) -> VerifierRun {
    let Some(requirement) = item
        .required_verifiers
        .iter()
        .find(|requirement| requirement.required_for_done)
    else {
        panic!("fixture has a required verifier");
    };
    let now = time::OffsetDateTime::now_utc();
    VerifierRun {
        verifier_run_id: VerifierRunId::new_v7(),
        project_id: item.project_id,
        task_id: item.task_id,
        agent_id: AgentId::new_v7(),
        name: requirement.name.clone(),
        command_kind: requirement.command_kind,
        command_display: requirement.command_display.clone(),
        status: VerifierStatus::Passed,
        exit_code: Some(0),
        duration_ms: 1,
        stdout_blob: None,
        stderr_blob: None,
        summary: "fixture verifier passed".to_owned(),
        required_for_done: true,
        write_receipt: Some(WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id: WriteId::new_v7(),
        }),
        started_at: now,
        finished_at: now,
    }
}

fn report(repo_root: &str, git_head: Option<String>) -> CodeCortexReport {
    let file = FileEvidence {
        path: "src/lib.rs".to_owned(),
        content_hash: Some("hash".to_owned()),
        line_start: Some(1),
        line_end: Some(1),
        excerpt: "pub fn value() -> u32 { 1 }".to_owned(),
        source: CodeEvidenceSource::Rg,
    };
    CodeCortexReport {
        project: "fixture".to_owned(),
        task: "fixture".to_owned(),
        goal: "fixture".to_owned(),
        generated_at: time::OffsetDateTime::now_utc(),
        repo_root: repo_root.to_owned(),
        git_head,
        dirty: false,
        scope_binding: eliot_types::CodeCortexScopeBinding::default(),
        tracked_files: vec![file.clone()],
        workspace_members: vec![repo_root.to_owned()],
        crates: vec!["fixture".to_owned()],
        targets: vec!["fixture".to_owned()],
        file_evidence: vec![file],
        symbol_evidence: vec![SymbolEvidence {
            name: "value".to_owned(),
            kind: "fn".to_owned(),
            path: "src/lib.rs".to_owned(),
            line: Some(1),
            source: CodeEvidenceSource::Rg,
        }],
        diagnostic_evidence: vec![DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "clean".to_owned(),
            path: None,
            line: None,
            severity: "info".to_owned(),
            message: "clean".to_owned(),
        }],
        verifier_evidence: vec![VerifierEvidence {
            name: "cargo-check".to_owned(),
            command: "cargo check".to_owned(),
            status: "pass".to_owned(),
            summary: "pass".to_owned(),
            source: CodeEvidenceSource::Diagnostics,
        }],
        blast_radius: BlastRadiusView {
            files: vec!["src/lib.rs".to_owned()],
            crates: vec!["fixture".to_owned()],
            reasons: vec!["fixture".to_owned()],
        },
        invariant_cards: vec![InvariantCard {
            name: "bounded".to_owned(),
            status: "enforced".to_owned(),
            evidence: "fixture".to_owned(),
        }],
        evidence_sources: vec![CodeEvidenceSource::Rg],
        adapter_notes: Vec::new(),
        memory_receipt: None,
        operation_status: OperationStatus::OperationCompleted,
    }
}

fn completion_proof(item: &eliot_types::WorkItem) -> CompletionProof {
    let evidence = std::iter::once(format!("work_item:{}", item.work_item_id))
        .chain(
            item.verifier_run_refs
                .iter()
                .map(|reference| format!("verifier_run:{}", reference.verifier_run_id)),
        )
        .collect::<Vec<_>>();
    CompletionProof {
        task_id: item.task_id.to_string(),
        project_id: item.project_id,
        goal: item.goal.clone(),
        changed_files: item.scope.write_set.clone(),
        memory_refs_used: vec![format!("work_item:{}", item.work_item_id)],
        checks_run: vec!["cargo-check".to_owned()],
        checks_not_run: Vec::new(),
        acceptance_items: vec![CompletionAcceptanceItem {
            item: "work complete".to_owned(),
            status: "verified".to_owned(),
            evidence: format!("work_item:{}", item.work_item_id),
            verifier: "cargo-check".to_owned(),
            residual_uncertainty: "none".to_owned(),
        }],
        evidence,
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: "none".to_owned(),
        known_risks: Vec::new(),
    }
}

fn fixture_repo(name: &str) -> TestResult<PathBuf> {
    let target = repo_root().join("target");
    fs::create_dir_all(&target)?;
    let repo = target.join(name);
    if repo.exists() {
        fs::remove_dir_all(&repo)?;
    }
    fs::create_dir_all(repo.join("src"))?;
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname=\"work-lease-fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n\n[workspace]\n",
    )?;
    fs::write(repo.join("src/lib.rs"), "pub fn value() -> u32 { 1 }\n")?;
    run_process(&repo, "git", &["init"])?;
    run_process(
        &repo,
        "git",
        &["config", "user.email", "eliot@example.invalid"],
    )?;
    run_process(&repo, "git", &["config", "user.name", "Eliot Governor"])?;
    run_process(&repo, "git", &["add", "."])?;
    run_process(&repo, "git", &["commit", "-m", "init"])?;
    Ok(repo)
}

fn git_head(repo_root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string().into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_process(cwd: &Path, program: &str, args: &[&str]) -> TestResult {
    let output = Command::new(program).args(args).current_dir(cwd).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string().into());
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn value_diff(new_value: &str) -> String {
    format!(
        concat!(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -1 +1 @@\n",
            "-pub fn value() -> u32 {{ 1 }}\n",
            "+pub fn value() -> u32 {{ {} }}\n"
        ),
        new_value
    )
}
