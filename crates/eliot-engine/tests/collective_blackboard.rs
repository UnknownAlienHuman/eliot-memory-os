use eliot_engine::{
    BlackboardAddInput, BlackboardService, CollectiveTraceService, LostAgentRecoveryService,
    MailboxSendInput, MailboxService, StopCoordinationGate, WorkClaimRequest, WorkCreateRequest,
    WorkLeaseService, WorkQueueService, WorkState, default_lease_ttl_minutes, default_work_scope,
};
use eliot_types::{
    ActionLease, ActionRequestId, ActionScope, AgentRole, AgentSessionId, AgentSessionStatus,
    BlackboardItemKind, BlackboardItemStatus, BlackboardScope, CandidateDiff, CandidateDiffId,
    CandidateDiffStatus, CandidateReview, CandidateReviewDecision, ConfidenceLevel,
    ContributionEffect, LeaseDecision, LeaseStatus, MailboxMessageId, MailboxMessageKind,
    MailboxMessageStatus, MailboxRecipient, ProjectId, RecoveryAction, TaskId, VerifierCommandKind,
    VerifierRequirement, WorkItemId, WorkLeaseId, WorkLeaseState, WorktreeLease, WorktreeLeaseId,
    WorktreeLeaseState,
};
use std::fs;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn blackboard_typed_items_created() {
    let mut fixture = Fixture::new("blackboard-typed");
    let item = fixture.add_blackboard(BlackboardItemKind::FindingCandidate, "payload:finding");

    assert_eq!(item.kind, BlackboardItemKind::FindingCandidate);
    assert_eq!(item.status, BlackboardItemStatus::Open);
    assert_eq!(item.payload_ref, "payload:finding");
    assert!(item.confidence.is_some());
}

#[test]
fn blackboard_candidate_not_promoted_to_truth() {
    let mut fixture = Fixture::new("blackboard-candidate-not-truth");
    let item = fixture.add_blackboard(BlackboardItemKind::FindingCandidate, "payload:candidate");

    assert_eq!(fixture.state.blackboard_items.len(), 1);
    assert_eq!(
        fixture.state.blackboard_items[0].blackboard_item_id,
        item.blackboard_item_id
    );
    assert!(fixture.state.candidate_diffs.is_empty());
    assert!(fixture.state.candidate_reviews.is_empty());
}

#[test]
fn blackboard_ack_resolve_reject() -> TestResult {
    let mut fixture = Fixture::new("blackboard-status");
    let finding = fixture.add_blackboard(BlackboardItemKind::FindingCandidate, "payload:finding");
    let hypothesis = fixture.add_blackboard(
        BlackboardItemKind::HypothesisCandidate,
        "payload:hypothesis",
    );

    let acknowledged = BlackboardService.acknowledge(
        &mut fixture.state,
        finding.blackboard_item_id,
        fixture.controller_id,
    )?;
    let resolved = BlackboardService.resolve(&mut fixture.state, finding.blackboard_item_id)?;
    let rejected = BlackboardService.reject(&mut fixture.state, hypothesis.blackboard_item_id)?;

    assert_eq!(acknowledged.status, BlackboardItemStatus::Acknowledged);
    assert_eq!(resolved.status, BlackboardItemStatus::Resolved);
    assert_eq!(rejected.status, BlackboardItemStatus::Rejected);
    assert!(resolved.acknowledged_by.contains(&fixture.controller_id));
    Ok(())
}

#[test]
fn blackboard_large_payload_by_ref() -> TestResult {
    let mut fixture = Fixture::new("blackboard-large-ref");
    let large_payload = "x".repeat(4096);
    let item = fixture.add_blackboard(
        BlackboardItemKind::EvidenceHandle,
        "blob:collective-work-large",
    );

    assert_ne!(item.payload_ref, large_payload);
    assert_eq!(item.payload_ref, "blob:collective-work-large");
    assert!(!serde_json::to_string(&item)?.contains(&large_payload));
    Ok(())
}

#[test]
fn mailbox_send_inbox_ack() -> TestResult {
    let mut fixture = Fixture::new("mailbox-send-inbox-ack");
    let message = fixture.send_message(None, MailboxMessageKind::AckRequired);
    let inbox = MailboxService.inbox(
        &fixture.state,
        fixture.project_id,
        fixture.task_id,
        Some(&MailboxRecipient::Controller),
    );
    let acknowledged = MailboxService.acknowledge(&mut fixture.state, message.message_id)?;

    assert_eq!(inbox.len(), 1);
    assert_eq!(acknowledged.status, MailboxMessageStatus::Acknowledged);
    assert!(acknowledged.acknowledged_at.is_some());
    Ok(())
}

#[test]
fn mailbox_idempotent_message_id() {
    let mut fixture = Fixture::new("mailbox-idempotent");
    let id = MailboxMessageId::new_v7();
    let first = fixture.send_message(Some(id), MailboxMessageKind::ReviewRequested);
    let second = fixture.send_message(Some(id), MailboxMessageKind::ReviewRequested);

    assert_eq!(first.message_id, second.message_id);
    assert_eq!(
        fixture
            .state
            .mailbox_messages
            .iter()
            .filter(|message| message.message_id == id)
            .count(),
        1
    );
}

#[test]
fn mailbox_sequence_per_recipient_task() {
    let mut fixture = Fixture::new("mailbox-sequence");
    let first = fixture.send_message(None, MailboxMessageKind::CandidateReady);
    let second = fixture.send_message(None, MailboxMessageKind::CandidateReady);

    assert_eq!(second.sequence, first.sequence + 1);
}

#[test]
fn mailbox_control_message_requires_ack() {
    let mut fixture = Fixture::new("mailbox-control-ack");
    let message = fixture.send_message(None, MailboxMessageKind::CompletionBlocked);

    assert!(message.requires_ack);
}

#[test]
fn lost_agent_recovery_expires_session() {
    let mut fixture = Fixture::new("recovery-expire-session");
    let records = fixture.recover();

    assert_eq!(records.len(), 1);
    assert!(fixture.state.sessions.iter().any(|session| {
        session.agent_session_id == fixture.worker_id
            && session.status == AgentSessionStatus::Expired
    }));
}

#[test]
fn lost_agent_recovery_revokes_action_lease() {
    let mut fixture = Fixture::new("recovery-action-lease");
    let records = fixture.recover();

    assert!(
        records[0]
            .active_action_leases
            .contains(&fixture.action_lease_id)
    );
    assert!(
        records[0]
            .actions_taken
            .contains(&RecoveryAction::RevokeActionLease)
    );
    assert!(
        fixture
            .state
            .action_leases
            .iter()
            .any(|lease| lease.status == LeaseStatus::Revoked)
    );
}

#[test]
fn lost_agent_recovery_advances_work_lease_epoch() {
    let mut fixture = Fixture::new("recovery-work-lease-epoch");
    let records = fixture.recover();

    assert!(
        records[0]
            .active_work_leases
            .contains(&fixture.work_lease_id)
    );
    assert!(fixture.state.leases.iter().any(|lease| {
        lease.work_lease_id == fixture.work_lease_id
            && lease.state == WorkLeaseState::Revoked
            && lease.epoch == 1
    }));
}

#[test]
fn lost_agent_recovery_retains_worktree_for_inspection() {
    let mut fixture = Fixture::new("recovery-retain-worktree");
    let records = fixture.recover();

    assert!(
        records[0]
            .active_worktree_leases
            .contains(&fixture.worktree_lease_id)
    );
    assert!(fixture.state.worktree_leases.iter().any(|lease| {
        lease.worktree_lease_id == fixture.worktree_lease_id
            && lease.state == WorktreeLeaseState::Expired
            && Path::new(&lease.worktree_path).is_dir()
    }));
}

#[test]
fn lost_agent_recovery_notifies_controller() {
    let mut fixture = Fixture::new("recovery-notify");
    let records = fixture.recover();

    assert!(
        records[0]
            .actions_taken
            .contains(&RecoveryAction::NotifyController)
    );
    assert!(records[0].mailbox_messages.iter().any(|message_id| {
        fixture.state.mailbox_messages.iter().any(|message| {
            message.message_id == *message_id && message.kind == MailboxMessageKind::AgentExpired
        })
    }));
}

#[test]
fn collective_trace_records_changed_action() -> TestResult {
    let mut fixture = Fixture::new("trace-changed-action");
    let finding = fixture.add_blackboard(BlackboardItemKind::FindingCandidate, "payload:finding");
    let _ = BlackboardService.resolve(&mut fixture.state, finding.blackboard_item_id)?;
    let trace =
        CollectiveTraceService.trace_task(&mut fixture.state, fixture.project_id, fixture.task_id);

    assert!(
        trace
            .agent_contributions
            .iter()
            .any(|item| item.effect == ContributionEffect::ChangedAction)
    );
    Ok(())
}

#[test]
fn collective_trace_records_rejected_candidate() {
    let mut fixture = Fixture::new("trace-rejected-candidate");
    fixture.add_rejected_candidate();
    let trace =
        CollectiveTraceService.trace_task(&mut fixture.state, fixture.project_id, fixture.task_id);

    assert_eq!(trace.rejected_candidates.len(), 1);
}

#[test]
fn collective_trace_records_verifier_killed_hypothesis() -> TestResult {
    let mut fixture = Fixture::new("trace-verifier-kills");
    let verifier =
        fixture.add_blackboard(BlackboardItemKind::VerifierResult, "verifier:cargo-check");
    if let Some(item) = fixture
        .state
        .blackboard_items
        .iter_mut()
        .find(|item| item.blackboard_item_id == verifier.blackboard_item_id)
    {
        item.evidence_refs.push("hypothesis:bad-path".to_owned());
    }
    let _ = BlackboardService.reject(&mut fixture.state, verifier.blackboard_item_id)?;
    let trace =
        CollectiveTraceService.trace_task(&mut fixture.state, fixture.project_id, fixture.task_id);

    assert!(trace.verifier_effects.iter().any(|effect| {
        effect.effect == ContributionEffect::KilledHypothesis
            && effect.killed_hypothesis_ref.is_some()
    }));
    Ok(())
}

#[test]
fn stop_blocks_unresolved_control_messages() {
    let mut fixture = Fixture::new("stop-blocks-control");
    let _ = fixture.send_message(None, MailboxMessageKind::CompletionBlocked);
    let decision = StopCoordinationGate.evaluate(
        &fixture.state,
        Some(fixture.project_id),
        Some(fixture.task_id),
    );

    assert!(!decision.allow);
    assert_eq!(decision.unacknowledged_control_messages.len(), 1);
}

#[test]
fn mcp_exposes_only_governed_collective_tools() -> TestResult {
    let mcp = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;
    for tool in [
        "eliot_blackboard_add",
        "eliot_blackboard_list",
        "eliot_blackboard_ack",
        "eliot_mailbox_send",
        "eliot_mailbox_inbox",
        "eliot_mailbox_ack",
        "eliot_recovery_scan",
        "eliot_collective_trace",
    ] {
        assert!(
            mcp.contains(tool),
            "{tool} missing from governed MCP surface"
        );
    }
    for forbidden in [
        "eliot_raw",
        "eliot_shell",
        "eliot_git",
        "eliot_rg",
        "eliot_astgrep",
        "eliot_file_read",
        "eliot_file_write",
    ] {
        assert!(!mcp.contains(forbidden), "forbidden MCP marker {forbidden}");
    }
    Ok(())
}

#[test]
fn mcp_exposes_no_external_agent_tools() -> TestResult {
    let mcp = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;
    let allowed_antigravity_tools = [
        "eliot_antigravity_visibility",
        "eliot_antigravity_mcp_status",
        "eliot_antigravity_plugin_status",
        "eliot_antigravity_live_smoke_status",
        "eliot_antigravity_real_report",
    ];
    for tool in allowed_antigravity_tools {
        assert!(
            mcp.contains(tool),
            "{tool} missing from governed MCP surface"
        );
    }
    for forbidden in [
        "eliot_external_agent",
        "eliot_run_antigravity",
        "eliot_raw_antigravity",
        "eliot_agy",
        "eliot_agy_mcp",
        "eliot_gemini",
        "eliot_qdrant",
        "eliot_graphiti",
        "eliot_zep",
    ] {
        assert!(!mcp.contains(forbidden), "forbidden MCP marker {forbidden}");
    }
    Ok(())
}

#[test]
fn the_blackboard_surface_stays_governed() -> TestResult {
    let repo = repo_root();
    let mcp = fs::read_to_string(repo.join("crates/eliot-app/src/mcp_stdio.rs"))?;
    assert!(mcp.contains("eliot_blackboard_add"));
    for forbidden in ["eliot_blackboard_raw", "eliot_blackboard_delete_all"] {
        assert!(
            !mcp.contains(forbidden),
            "{forbidden} leaked into the MCP surface"
        );
    }
    Ok(())
}

struct Fixture {
    state: WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    controller_id: AgentSessionId,
    worker_id: AgentSessionId,
    work_item_id: WorkItemId,
    work_lease_id: WorkLeaseId,
    action_lease_id: eliot_types::ActionLeaseId,
    worktree_lease_id: WorktreeLeaseId,
}

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new(name: &str) -> Self {
        let mut state = WorkState::default();
        let now = OffsetDateTime::now_utc();
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let controller =
            eliot_engine::AgentSessionService.create_controller(&mut state, project_id);
        let worker = eliot_engine::AgentSessionService.create_controller(&mut state, project_id);
        if let Some(session) = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == worker.agent_session_id)
        {
            session.role = AgentRole::Implementer;
            session.parent_session_id = Some(controller.agent_session_id);
        }
        let verifier = verifier();
        let repo = repo_root();
        let item = WorkQueueService.create_work_item(
            &mut state,
            WorkCreateRequest {
                project_id,
                task_id,
                project: "eliot-governor".to_owned(),
                task: name.to_owned(),
                goal: "collective-work fixture".to_owned(),
                scope: default_work_scope(
                    repo.display().to_string(),
                    vec!["crates/eliot-engine/src/collective.rs".to_owned()],
                    vec!["crates/eliot-engine/src/collective.rs".to_owned()],
                    vec!["cargo check --workspace --all-targets --all-features".to_owned()],
                ),
                required: true,
                created_by: controller.agent_session_id,
                required_verifiers: verifier.clone(),
            },
        );
        let decision = WorkLeaseService.claim(
            &mut state,
            WorkClaimRequest {
                work_item_id: item.work_item_id,
                agent_session_id: worker.agent_session_id,
                role: AgentRole::Implementer,
                ttl_minutes: default_lease_ttl_minutes(),
            },
        );
        assert!(decision.work_lease_id.is_some());
        let work_lease_id = decision.work_lease_id.unwrap_or_else(WorkLeaseId::new_v7);
        if let Some(session) = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == worker.agent_session_id)
        {
            session.last_heartbeat_at = now - Duration::hours(2);
        }
        let action_lease_id = eliot_types::ActionLeaseId::new_v7();
        state.action_leases.push(ActionLease {
            lease_id: action_lease_id,
            request_id: ActionRequestId::new_v7(),
            project_id,
            task_id,
            agent_id: worker.agent_id,
            decision: LeaseDecision::AllowPatchExecution,
            status: LeaseStatus::ApprovedForExecution,
            allowed_scope: Some(ActionScope {
                repo_root: repo.display().to_string(),
                git_head: None,
                allowed_files: vec!["crates/eliot-engine/src/collective.rs".to_owned()],
                allowed_symbols: Vec::new(),
                forbidden_files: Vec::new(),
                max_files: 1,
                max_diff_bytes: 4096,
                max_runtime_seconds: 60,
            }),
            change_plan: None,
            verifier_plan: None,
            skill_refs: Vec::new(),
            denial_reasons: Vec::new(),
            expires_at: Some(now + Duration::hours(1)),
            created_at: now,
        });
        let worktree_lease_id = WorktreeLeaseId::new_v7();
        let worktree_path = repo
            .join("target")
            .join("collective-work-tests")
            .join(name.replace('\\', "-"));
        assert!(fs::create_dir_all(&worktree_path).is_ok());
        state.worktree_leases.push(WorktreeLease {
            worktree_lease_id,
            project_id,
            task_id,
            work_item_id: item.work_item_id,
            work_lease_id,
            holder_session_id: worker.agent_session_id,
            repo_root: repo.display().to_string(),
            worktree_path: worktree_path.display().to_string(),
            branch_name: format!("collective-work-{name}"),
            base_commit: "collective-work-fixture".to_owned(),
            allowed_read_set: vec!["crates/eliot-engine/src/collective.rs".to_owned()],
            allowed_write_set: vec!["crates/eliot-engine/src/collective.rs".to_owned()],
            state: WorktreeLeaseState::Active,
            issued_at: now,
            expires_at: now + Duration::hours(1),
            cleaned_at: None,
            write_receipt: None,
        });
        Self {
            state,
            project_id,
            task_id,
            controller_id: controller.agent_session_id,
            worker_id: worker.agent_session_id,
            work_item_id: item.work_item_id,
            work_lease_id,
            action_lease_id,
            worktree_lease_id,
        }
    }

    fn add_blackboard(
        &mut self,
        kind: BlackboardItemKind,
        payload_ref: &str,
    ) -> eliot_types::BlackboardItem {
        BlackboardService.create_item(
            &mut self.state,
            BlackboardAddInput {
                project_id: self.project_id,
                task_id: self.task_id,
                owner_session_id: self.worker_id,
                work_item_id: Some(self.work_item_id),
                lease_id: Some(self.work_lease_id),
                kind,
                scope: BlackboardScope {
                    memory_scope: vec!["collective-work".to_owned()],
                    files: vec!["crates/eliot-engine/src/collective.rs".to_owned()],
                    symbols: vec!["BlackboardService".to_owned()],
                    work_items: vec![self.work_item_id],
                },
                payload_ref: payload_ref.to_owned(),
                evidence_refs: vec!["evidence:collective-work".to_owned()],
                confidence: Some(ConfidenceLevel::High),
                expires_at: None,
            },
        )
    }

    fn send_message(
        &mut self,
        message_id: Option<MailboxMessageId>,
        kind: MailboxMessageKind,
    ) -> eliot_types::MailboxMessage {
        MailboxService.send(
            &mut self.state,
            MailboxSendInput {
                message_id,
                project_id: self.project_id,
                task_id: self.task_id,
                sender_session_id: self.worker_id,
                recipient: MailboxRecipient::Controller,
                kind,
                payload_ref: "mailbox:collective-work".to_owned(),
                requires_ack: None,
                expires_at: None,
            },
        )
    }

    fn recover(&mut self) -> Vec<eliot_types::LostAgentRecoveryRecord> {
        LostAgentRecoveryService.scan(
            &mut self.state,
            self.project_id,
            self.task_id,
            Duration::minutes(30),
        )
    }

    fn add_rejected_candidate(&mut self) {
        let now = OffsetDateTime::now_utc();
        let diff = CandidateDiff {
            candidate_diff_id: CandidateDiffId::new_v7(),
            worktree_lease_id: self.worktree_lease_id,
            project_id: self.project_id,
            task_id: self.task_id,
            work_item_id: self.work_item_id,
            base_commit: "collective-work-fixture".to_owned(),
            worktree_head: None,
            diff_hash: "collective-work-rejected".to_owned(),
            diff_ref: "candidate-diff:collective-work-rejected".to_owned(),
            changed_files: vec!["crates/eliot-engine/src/collective.rs".to_owned()],
            added_files: Vec::new(),
            modified_files: vec!["crates/eliot-engine/src/collective.rs".to_owned()],
            deleted_files: Vec::new(),
            byte_len: 1,
            file_count: 1,
            capture_status: CandidateDiffStatus::Rejected,
            created_at: now,
            write_receipt: None,
        };
        state_push_candidate_review(&mut self.state, &diff, self.controller_id, now);
        self.state.candidate_diffs.push(diff);
    }
}

fn state_push_candidate_review(
    state: &mut WorkState,
    diff: &CandidateDiff,
    reviewer_session_id: AgentSessionId,
    now: OffsetDateTime,
) {
    state.candidate_reviews.push(CandidateReview {
        review_id: format!("review:{}", diff.candidate_diff_id),
        candidate_diff_id: diff.candidate_diff_id,
        reviewer_session_id,
        decision: CandidateReviewDecision::Reject,
        reasons: vec!["candidate rejected for F3 learning trace".to_owned()],
        created_at: now,
        patch_request_id: None,
        write_receipt: None,
    });
}

fn verifier() -> Vec<VerifierRequirement> {
    vec![VerifierRequirement {
        name: "cargo-check".to_owned(),
        command_kind: VerifierCommandKind::CargoCheck,
        command_display: "cargo check --workspace --all-targets --all-features".to_owned(),
        scope: vec!["crates/eliot-engine/src/collective.rs".to_owned()],
        required_for_done: true,
        expected_signal: "workspace type-checks".to_owned(),
    }]
}

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
