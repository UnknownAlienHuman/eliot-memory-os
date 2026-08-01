use eliot_engine::{CompletionGate, WorkState, default_work_scope};
use eliot_types::{
    AgentRole, AgentSessionId, BlackboardItem, BlackboardItemId, BlackboardItemKind,
    BlackboardItemStatus, BlackboardScope, CandidateDiff, CandidateDiffId, CandidateDiffStatus,
    CandidateReview, CandidateReviewDecision, CompletionAcceptanceItem, CompletionGateDecision,
    CompletionProof, CompletionStatus, MailboxMessage, MailboxMessageId, MailboxMessageKind,
    MailboxMessageStatus, MailboxRecipient, ProjectId, ReceiptId, TaskId, VerifierCommandKind,
    VerifierRequirement, VerifierRunId, VerifierRunRef, VerifierStatus, WorkConflict,
    WorkConflictKind, WorkItem, WorkItemId, WorkItemStatus, WorkLeaseId, WorktreeLeaseId, WriteId,
    WriteReceiptRef,
};
use time::OffsetDateTime;

#[test]
fn empty_acceptance_proof_cannot_finish_task() {
    let mut fixture = CompletionFixture::complete();
    fixture.proof.acceptance_items.clear();

    assert_not_done(&fixture.decide(), "missing_acceptance_items");
}

#[test]
fn pending_controller_message_cannot_finish_task() {
    let mut fixture = CompletionFixture::complete();
    fixture.state.mailbox_messages.push(MailboxMessage {
        message_id: MailboxMessageId::new_v7(),
        project_id: fixture.project_id,
        task_id: fixture.task_id,
        sender_session_id: AgentSessionId::new_v7(),
        recipient: MailboxRecipient::Controller,
        sequence: 1,
        kind: MailboxMessageKind::CompletionBlocked,
        payload_ref: "mailbox:completion-blocked".to_owned(),
        requires_ack: true,
        created_at: OffsetDateTime::now_utc(),
        expires_at: None,
        acknowledged_at: None,
        status: MailboxMessageStatus::Pending,
        write_receipt: None,
    });

    assert_not_done(
        &fixture.decide(),
        "stop_coordination:unacknowledged_control_messages",
    );
}

#[test]
fn open_blackboard_blocker_cannot_finish_task() {
    let mut fixture = CompletionFixture::complete();
    fixture.state.blackboard_items.push(BlackboardItem {
        blackboard_item_id: BlackboardItemId::new_v7(),
        project_id: fixture.project_id,
        task_id: fixture.task_id,
        owner_session_id: AgentSessionId::new_v7(),
        work_item_id: Some(fixture.work_item_id),
        lease_id: None,
        kind: BlackboardItemKind::Blocker,
        scope: BlackboardScope {
            work_items: vec![fixture.work_item_id],
            ..BlackboardScope::default()
        },
        payload_ref: "blackboard:completion-blocker".to_owned(),
        evidence_refs: vec!["evidence:blocker".to_owned()],
        status: BlackboardItemStatus::Open,
        confidence: None,
        created_at: OffsetDateTime::now_utc(),
        expires_at: None,
        acknowledged_by: Vec::new(),
        write_receipt: None,
    });

    assert_not_done(
        &fixture.decide(),
        "stop_coordination:unresolved_blackboard_items",
    );
}

#[test]
fn unresolved_work_conflict_cannot_finish_task() {
    let mut fixture = CompletionFixture::complete();
    fixture.state.conflicts.push(WorkConflict {
        conflict_id: "conflict:phase0-completion".to_owned(),
        work_item_id: fixture.work_item_id,
        work_lease_id: WorkLeaseId::new_v7(),
        conflicting_work_lease_id: None,
        kind: WorkConflictKind::OverlappingWriteScope,
        paths: vec!["crates/eliot-engine/src/context.rs".to_owned()],
        resolution: None,
        detail: "unresolved completion-scope conflict".to_owned(),
        detected_at: OffsetDateTime::now_utc(),
    });

    assert_not_done(
        &fixture.decide(),
        "stop_coordination:unresolved_work_conflicts",
    );
}

#[test]
fn completed_required_work_item_without_verifier_evidence_cannot_finish_task() {
    let mut fixture = CompletionFixture::complete();
    fixture.state.work_items[0].verifier_run_refs.clear();

    assert_not_done(&fixture.decide(), "required_work_item_verifier_missing:");
}

#[test]
fn latest_candidate_requires_accepted_receipted_review() {
    let fixture = CompletionFixture::complete();

    let mut missing = fixture.state.clone();
    missing.candidate_reviews.clear();
    assert_not_done(
        &CompletionGate::decide_for_task(
            &fixture.proof,
            fixture.project_id,
            fixture.task_id,
            &missing,
            false,
        ),
        "missing_candidate_review:",
    );

    let mut rejected = fixture.state.clone();
    rejected.candidate_reviews[0].decision = CandidateReviewDecision::Reject;
    assert_not_done(
        &CompletionGate::decide_for_task(
            &fixture.proof,
            fixture.project_id,
            fixture.task_id,
            &rejected,
            false,
        ),
        "candidate_review_not_accepted:",
    );

    let mut unreceipted = fixture.state.clone();
    unreceipted.candidate_reviews[0].write_receipt = None;
    assert_not_done(
        &CompletionGate::decide_for_task(
            &fixture.proof,
            fixture.project_id,
            fixture.task_id,
            &unreceipted,
            false,
        ),
        "candidate_review_not_accepted:",
    );
}

#[test]
fn complete_runtime_evidence_finishes_task() {
    let fixture = CompletionFixture::complete();
    let decision = fixture.decide();

    assert_eq!(decision.final_status, CompletionStatus::DoneVerified);
    assert!(
        decision.reasons.is_empty(),
        "unexpected reasons: {:?}",
        decision.reasons
    );
}

struct CompletionFixture {
    project_id: ProjectId,
    task_id: TaskId,
    work_item_id: WorkItemId,
    state: WorkState,
    proof: CompletionProof,
}

impl CompletionFixture {
    fn complete() -> Self {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let work_item_id = WorkItemId::new_v7();
        let verifier_run_id = VerifierRunId::new_v7();
        let candidate_diff_id = CandidateDiffId::new_v7();
        let review_id = format!("candidate-review:{candidate_diff_id}");
        let now = OffsetDateTime::now_utc();
        let changed_file = "crates/eliot-engine/src/context.rs".to_owned();

        let work_item = completed_work_item(
            project_id,
            task_id,
            work_item_id,
            verifier_run_id,
            &review_id,
            now,
            &changed_file,
        );
        let (candidate_diff, candidate_review) = accepted_candidate_evidence(
            project_id,
            task_id,
            work_item_id,
            candidate_diff_id,
            &review_id,
            now,
            &changed_file,
        );
        let proof = CompletionProof {
            task_id: task_id.to_string(),
            project_id,
            goal: "prove task completion is evidence-bound".to_owned(),
            changed_files: vec![changed_file],
            memory_refs_used: Vec::new(),
            checks_run: vec!["cargo check -p eliot-engine".to_owned()],
            checks_not_run: Vec::new(),
            acceptance_items: vec![CompletionAcceptanceItem {
                item: "runtime completion evidence is complete".to_owned(),
                status: "verified".to_owned(),
                evidence: format!("verifier-run:{verifier_run_id}"),
                verifier: "cargo-check".to_owned(),
                residual_uncertainty: String::new(),
            }],
            evidence: vec![
                format!("work-item:{work_item_id}"),
                format!("verifier-run:{verifier_run_id}"),
                format!("candidate-diff:{candidate_diff_id}"),
                format!("candidate-review:{review_id}"),
            ],
            skill_refs: Vec::new(),
            skill_execution_proof_refs: Vec::new(),
            residual_uncertainty: String::new(),
            known_risks: Vec::new(),
        };
        let state = WorkState {
            work_items: vec![work_item],
            candidate_diffs: vec![candidate_diff],
            candidate_reviews: vec![candidate_review],
            ..WorkState::default()
        };

        Self {
            project_id,
            task_id,
            work_item_id,
            state,
            proof,
        }
    }

    fn decide(&self) -> CompletionGateDecision {
        CompletionGate::decide_for_task(
            &self.proof,
            self.project_id,
            self.task_id,
            &self.state,
            false,
        )
    }
}

fn completed_work_item(
    project_id: ProjectId,
    task_id: TaskId,
    work_item_id: WorkItemId,
    verifier_run_id: VerifierRunId,
    review_id: &str,
    now: OffsetDateTime,
    changed_file: &str,
) -> WorkItem {
    WorkItem {
        work_item_id,
        project_id,
        task_id,
        project: "eliot-memory-os".to_owned(),
        task: "phase0-completion-truth".to_owned(),
        goal: "prove task completion is evidence-bound".to_owned(),
        scope: default_work_scope(
            "C:\\repo",
            vec![changed_file.to_owned()],
            vec![changed_file.to_owned()],
            vec!["cargo-check".to_owned()],
        ),
        status: WorkItemStatus::Completed,
        required: true,
        allowed_roles: vec![AgentRole::Implementer],
        required_verifiers: vec![VerifierRequirement {
            name: "cargo-check".to_owned(),
            command_kind: VerifierCommandKind::CargoCheck,
            command_display: "cargo check -p eliot-engine".to_owned(),
            scope: vec![changed_file.to_owned()],
            required_for_done: true,
            expected_signal: "engine type-checks".to_owned(),
        }],
        verifier_run_refs: vec![VerifierRunRef {
            verifier_run_id,
            name: "cargo-check".to_owned(),
            status: VerifierStatus::Passed,
        }],
        candidate_review_refs: vec![review_id.to_owned()],
        created_by: AgentSessionId::new_v7(),
        active_lease_id: None,
        lease_refs: Vec::new(),
        conflict_refs: Vec::new(),
        created_at: now,
        updated_at: now,
        completed_at: Some(now),
        write_receipt: Some(receipt()),
    }
}

fn accepted_candidate_evidence(
    project_id: ProjectId,
    task_id: TaskId,
    work_item_id: WorkItemId,
    candidate_diff_id: CandidateDiffId,
    review_id: &str,
    now: OffsetDateTime,
    changed_file: &str,
) -> (CandidateDiff, CandidateReview) {
    let candidate_diff = CandidateDiff {
        candidate_diff_id,
        worktree_lease_id: WorktreeLeaseId::new_v7(),
        project_id,
        task_id,
        work_item_id,
        base_commit: "phase0-base".to_owned(),
        worktree_head: Some("phase0-head".to_owned()),
        diff_hash: "phase0-diff-hash".to_owned(),
        diff_ref: format!("candidate-diff:{candidate_diff_id}"),
        changed_files: vec![changed_file.to_owned()],
        added_files: Vec::new(),
        modified_files: vec![changed_file.to_owned()],
        deleted_files: Vec::new(),
        byte_len: 1,
        file_count: 1,
        capture_status: CandidateDiffStatus::AcceptedForPatchRunner,
        created_at: now,
        write_receipt: Some(receipt()),
    };
    let candidate_review = CandidateReview {
        review_id: review_id.to_owned(),
        candidate_diff_id,
        reviewer_session_id: AgentSessionId::new_v7(),
        decision: CandidateReviewDecision::AcceptForPatchRunner,
        reasons: vec!["candidate matches the bounded work item".to_owned()],
        created_at: now,
        patch_request_id: None,
        write_receipt: Some(receipt()),
    };
    (candidate_diff, candidate_review)
}

fn receipt() -> WriteReceiptRef {
    WriteReceiptRef {
        receipt_id: ReceiptId::new_v7(),
        write_id: WriteId::new_v7(),
    }
}

fn assert_not_done(decision: &CompletionGateDecision, expected_reason: &str) {
    assert_ne!(decision.final_status, CompletionStatus::DoneVerified);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.starts_with(expected_reason)),
        "missing reason {expected_reason:?}; actual reasons: {:?}",
        decision.reasons
    );
}
