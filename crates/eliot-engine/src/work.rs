use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_types::{
    ActionLease, AgentId, AgentRole, AgentRun, AgentSession, AgentSessionId, AgentSessionStatus,
    AgentTransport, AuthorityProfile, BlackboardItem, CandidateDiff, CandidateReview,
    CollectiveTrace, CommandContext, LifecycleStatus, LostAgentRecoveryRecord, MailboxMessage,
    ProjectId, RiskTier, SemanticCommand, TaintClass, TaskId, ToolObservationRecordCommand,
    VerifierRequirement, Visibility, WorkConflict, WorkConflictKind, WorkConflictResolution,
    WorkItem, WorkItemId, WorkItemStatus, WorkLease, WorkLeaseDecision, WorkLeaseDecisionKind,
    WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState, WorkScope, WorktreeLease, WriteId,
    WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

const DEFAULT_LEASE_TTL_MINUTES: i64 = 45;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkState {
    pub sessions: Vec<AgentSession>,
    pub work_items: Vec<WorkItem>,
    pub leases: Vec<WorkLease>,
    pub conflicts: Vec<WorkConflict>,
    pub agent_runs: Vec<AgentRun>,
    pub decisions: Vec<WorkLeaseDecision>,
    #[serde(default)]
    pub worktree_leases: Vec<WorktreeLease>,
    #[serde(default)]
    pub candidate_diffs: Vec<CandidateDiff>,
    #[serde(default)]
    pub candidate_reviews: Vec<CandidateReview>,
    #[serde(default)]
    pub action_leases: Vec<ActionLease>,
    #[serde(default)]
    pub blackboard_items: Vec<BlackboardItem>,
    #[serde(default)]
    pub mailbox_messages: Vec<MailboxMessage>,
    #[serde(default)]
    pub recovery_records: Vec<LostAgentRecoveryRecord>,
    #[serde(default)]
    pub collective_traces: Vec<CollectiveTrace>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkStatusReport {
    pub component: String,
    pub project: String,
    pub task: String,
    pub sessions: Vec<AgentSession>,
    pub work_items: Vec<WorkItem>,
    pub active_leases: Vec<WorkLease>,
    pub conflicts: Vec<WorkConflict>,
    pub decisions: Vec<WorkLeaseDecision>,
    pub worktree_leases: Vec<WorktreeLease>,
    pub candidate_diffs: Vec<CandidateDiff>,
    pub candidate_reviews: Vec<CandidateReview>,
    pub final_status: String,
}

#[derive(Clone, Debug)]
pub struct WorkCreateRequest {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub project: String,
    pub task: String,
    pub goal: String,
    pub scope: WorkScope,
    pub required: bool,
    pub created_by: AgentSessionId,
    pub required_verifiers: Vec<VerifierRequirement>,
}

#[derive(Clone, Copy, Debug)]
pub struct WorkClaimRequest {
    pub work_item_id: WorkItemId,
    pub agent_session_id: AgentSessionId,
    pub role: AgentRole,
    pub ttl_minutes: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkSessionEvent {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub role: AgentRole,
    pub transport: AgentTransport,
    pub status: AgentSessionStatus,
    pub summary: String,
}

#[derive(Clone, Copy, Debug)]
struct ClaimSession {
    agent_session_id: AgentSessionId,
    agent_id: AgentId,
    status: AgentSessionStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkLeaseGuardError {
    Missing,
    Inactive,
    Mismatch,
    FileOutsideScope,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AgentSessionService;

#[derive(Clone, Copy, Debug, Default)]
pub struct WorkQueueService;

#[derive(Clone, Copy, Debug, Default)]
pub struct WorkLeaseService;

#[derive(Clone, Copy, Debug, Default)]
pub struct WorkConflictService;

pub struct WorkMemoryWriter;

impl AgentSessionService {
    #[must_use]
    pub fn create_controller(&self, state: &mut WorkState, project_id: ProjectId) -> AgentSession {
        self.create_for_role(state, project_id, AgentRole::Controller)
    }

    #[must_use]
    pub fn create_for_role(
        &self,
        state: &mut WorkState,
        project_id: ProjectId,
        role: AgentRole,
    ) -> AgentSession {
        let now = OffsetDateTime::now_utc();
        let session = AgentSession {
            agent_session_id: AgentSessionId::new_v7(),
            agent_id: AgentId::new_v7(),
            project_id,
            role,
            transport: AgentTransport::LocalCli,
            status: AgentSessionStatus::Active,
            parent_session_id: None,
            current_work_item_id: None,
            started_at: now,
            last_heartbeat_at: now,
            stopped_at: None,
            unavailable_reason: None,
            write_receipt: None,
        };
        state.sessions.push(session.clone());
        session
    }

    #[must_use]
    pub fn create_subagent_unavailable(
        &self,
        state: &mut WorkState,
        project_id: ProjectId,
        parent_session_id: AgentSessionId,
        reason: impl Into<String>,
    ) -> AgentSession {
        let now = OffsetDateTime::now_utc();
        let session = AgentSession {
            agent_session_id: AgentSessionId::new_v7(),
            agent_id: AgentId::new_v7(),
            project_id,
            role: AgentRole::Reviewer,
            transport: AgentTransport::Unavailable,
            status: AgentSessionStatus::Unavailable,
            parent_session_id: Some(parent_session_id),
            current_work_item_id: None,
            started_at: now,
            last_heartbeat_at: now,
            stopped_at: Some(now),
            unavailable_reason: Some(reason.into()),
            write_receipt: None,
        };
        state.sessions.push(session.clone());
        session
    }

    pub fn heartbeat(
        &self,
        state: &mut WorkState,
        session_id: AgentSessionId,
    ) -> Option<AgentSession> {
        let session = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)?;
        session.last_heartbeat_at = OffsetDateTime::now_utc();
        Some(session.clone())
    }

    pub fn stop(&self, state: &mut WorkState, session_id: AgentSessionId) -> Option<AgentSession> {
        let now = OffsetDateTime::now_utc();
        let session = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)?;
        session.status = AgentSessionStatus::Stopped;
        session.stopped_at = Some(now);
        session.last_heartbeat_at = now;
        Some(session.clone())
    }
}

impl WorkQueueService {
    #[must_use]
    pub fn create_work_item(&self, state: &mut WorkState, request: WorkCreateRequest) -> WorkItem {
        let now = OffsetDateTime::now_utc();
        let item = WorkItem {
            work_item_id: WorkItemId::new_v7(),
            project_id: request.project_id,
            task_id: request.task_id,
            project: request.project,
            task: request.task,
            goal: request.goal,
            scope: request.scope,
            status: WorkItemStatus::Open,
            required: request.required,
            allowed_roles: vec![
                AgentRole::Controller,
                AgentRole::Implementer,
                AgentRole::Reviewer,
                AgentRole::Auditor,
                AgentRole::Verifier,
            ],
            required_verifiers: request.required_verifiers,
            created_by: request.created_by,
            active_lease_id: None,
            lease_refs: Vec::new(),
            conflict_refs: Vec::new(),
            created_at: now,
            updated_at: now,
            completed_at: None,
            write_receipt: None,
        };
        state.work_items.push(item.clone());
        item
    }

    pub fn complete(&self, state: &mut WorkState, work_item_id: WorkItemId) -> Option<WorkItem> {
        let now = OffsetDateTime::now_utc();
        let item = state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == work_item_id)?;
        item.status = WorkItemStatus::Completed;
        item.updated_at = now;
        item.completed_at = Some(now);
        Some(item.clone())
    }

    #[must_use]
    pub fn status_report(&self, state: &WorkState, project: &str, task: &str) -> WorkStatusReport {
        let sessions = state
            .sessions
            .iter()
            .filter(|session| {
                state
                    .work_items
                    .iter()
                    .any(|item| item.project_id == session.project_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let work_items = state
            .work_items
            .iter()
            .filter(|item| labels_match(item, project, task))
            .cloned()
            .collect::<Vec<_>>();
        let item_ids = work_items
            .iter()
            .map(|item| item.work_item_id)
            .collect::<BTreeSet<_>>();
        let active_leases = state
            .leases
            .iter()
            .filter(|lease| item_ids.contains(&lease.work_item_id) && work_lease_is_active(lease))
            .cloned()
            .collect::<Vec<_>>();
        let conflicts = state
            .conflicts
            .iter()
            .filter(|conflict| item_ids.contains(&conflict.work_item_id))
            .cloned()
            .collect::<Vec<_>>();
        let final_status = if work_items.is_empty() {
            "NO_WORK"
        } else if work_items.iter().any(|item| {
            matches!(
                item.status,
                WorkItemStatus::Blocked | WorkItemStatus::Expired
            )
        }) {
            "PARTIAL_PROGRESS"
        } else if work_items
            .iter()
            .all(|item| !item.required || item.status == WorkItemStatus::Completed)
        {
            "DONE_VERIFIED"
        } else {
            "ACTIVE"
        }
        .to_owned();
        WorkStatusReport {
            component: "work".to_owned(),
            project: project.to_owned(),
            task: task.to_owned(),
            sessions,
            work_items,
            active_leases,
            conflicts,
            decisions: state.decisions.clone(),
            worktree_leases: state
                .worktree_leases
                .iter()
                .filter(|lease| item_ids.contains(&lease.work_item_id))
                .cloned()
                .collect(),
            candidate_diffs: state
                .candidate_diffs
                .iter()
                .filter(|diff| item_ids.contains(&diff.work_item_id))
                .cloned()
                .collect(),
            candidate_reviews: state
                .candidate_reviews
                .iter()
                .filter(|review| {
                    state.candidate_diffs.iter().any(|diff| {
                        item_ids.contains(&diff.work_item_id)
                            && diff.candidate_diff_id == review.candidate_diff_id
                    })
                })
                .cloned()
                .collect(),
            final_status,
        }
    }
}

impl WorkLeaseService {
    #[must_use]
    pub fn claim(&self, state: &mut WorkState, request: WorkClaimRequest) -> WorkLeaseDecision {
        let now = OffsetDateTime::now_utc();
        let Some(session) = active_session_for_claim(state, request) else {
            return push_decision(state, denied_inactive_session("agent session is missing"));
        };
        if session.status != AgentSessionStatus::Active {
            return push_decision(
                state,
                denied_inactive_session("agent session is not active"),
            );
        }
        let Some(item) = work_item_for_claim(state, request) else {
            return push_decision(state, denied_unknown_work_item());
        };
        if item.status == WorkItemStatus::Completed {
            return push_decision(state, denied_completed_work_item());
        }
        if let Some(denial) = deny_missing_verifier(state, &item) {
            return push_decision(state, denial);
        }
        if let Some(denial) = deny_write_conflicts(state, &item, request.role) {
            return push_decision(state, denial);
        }
        grant_work_lease(state, request, session, item, now)
    }

    pub fn renew(
        &self,
        state: &mut WorkState,
        lease_id: WorkLeaseId,
        ttl_minutes: i64,
    ) -> WorkLeaseDecision {
        let now = OffsetDateTime::now_utc();
        let Some(lease_index) = state
            .leases
            .iter()
            .position(|lease| lease.work_lease_id == lease_id)
        else {
            return push_decision(
                state,
                decision(
                    WorkLeaseDecisionKind::Denied,
                    WorkLeaseDecisionReason::LeaseNotFound,
                    "work lease is missing",
                    Some(lease_id),
                    Vec::new(),
                    None,
                ),
            );
        };
        let lease = &mut state.leases[lease_index];
        if !work_lease_is_active(lease) {
            let reason = inactive_reason(lease);
            let expires_at = lease.expires_at;
            return push_decision(
                state,
                decision(
                    WorkLeaseDecisionKind::Denied,
                    reason,
                    "work lease is not active",
                    Some(lease_id),
                    Vec::new(),
                    Some(expires_at),
                ),
            );
        }
        let expires_at = now + Duration::minutes(ttl_minutes.max(1));
        lease.state = WorkLeaseState::Renewed;
        lease.renewed_at = Some(now);
        lease.expires_at = expires_at;
        let renewed = decision(
            WorkLeaseDecisionKind::Renewed,
            WorkLeaseDecisionReason::NoConflict,
            "work lease renewed",
            Some(lease_id),
            Vec::new(),
            Some(expires_at),
        );
        lease.decision = renewed.clone();
        push_decision(state, renewed)
    }

    pub fn release(&self, state: &mut WorkState, lease_id: WorkLeaseId) -> WorkLeaseDecision {
        Self::finish_lease(
            state,
            lease_id,
            WorkLeaseState::Released,
            WorkLeaseDecisionKind::Released,
            WorkLeaseDecisionReason::ReleasedLease,
            "work lease released",
        )
    }

    pub fn revoke(&self, state: &mut WorkState, lease_id: WorkLeaseId) -> WorkLeaseDecision {
        Self::finish_lease(
            state,
            lease_id,
            WorkLeaseState::Revoked,
            WorkLeaseDecisionKind::Revoked,
            WorkLeaseDecisionReason::RevokedLease,
            "work lease revoked",
        )
    }

    pub fn active_lease_for_item<'a>(
        &self,
        state: &'a WorkState,
        work_item_id: WorkItemId,
    ) -> Option<&'a WorkLease> {
        state
            .leases
            .iter()
            .find(|lease| lease.work_item_id == work_item_id && work_lease_is_active(lease))
    }

    fn finish_lease(
        state: &mut WorkState,
        lease_id: WorkLeaseId,
        next_state: WorkLeaseState,
        kind: WorkLeaseDecisionKind,
        reason: WorkLeaseDecisionReason,
        message: &'static str,
    ) -> WorkLeaseDecision {
        let now = OffsetDateTime::now_utc();
        let Some(lease) = state
            .leases
            .iter_mut()
            .find(|lease| lease.work_lease_id == lease_id)
        else {
            return push_decision(
                state,
                decision(
                    WorkLeaseDecisionKind::Denied,
                    WorkLeaseDecisionReason::LeaseNotFound,
                    "work lease is missing",
                    Some(lease_id),
                    Vec::new(),
                    None,
                ),
            );
        };
        lease.state = next_state;
        match next_state {
            WorkLeaseState::Released => lease.released_at = Some(now),
            WorkLeaseState::Revoked => lease.revoked_at = Some(now),
            WorkLeaseState::Granted
            | WorkLeaseState::Renewed
            | WorkLeaseState::Expired
            | WorkLeaseState::Denied => {}
        }
        let work_item_id = lease.work_item_id;
        let result = decision(
            kind,
            reason,
            message,
            Some(lease_id),
            Vec::new(),
            Some(lease.expires_at),
        );
        lease.decision = result.clone();
        if let Some(item) = state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == work_item_id)
        {
            item.active_lease_id = None;
            item.updated_at = now;
            if item.status != WorkItemStatus::Completed {
                item.status = WorkItemStatus::Open;
            }
        }
        push_decision(state, result)
    }
}

fn active_session_for_claim(state: &WorkState, request: WorkClaimRequest) -> Option<ClaimSession> {
    state
        .sessions
        .iter()
        .find(|session| session.agent_session_id == request.agent_session_id)
        .map(|session| ClaimSession {
            agent_session_id: session.agent_session_id,
            agent_id: session.agent_id,
            status: session.status,
        })
}

fn work_item_for_claim(state: &WorkState, request: WorkClaimRequest) -> Option<WorkItem> {
    state
        .work_items
        .iter()
        .find(|item| item.work_item_id == request.work_item_id)
        .cloned()
}

fn denied_inactive_session(message: &'static str) -> WorkLeaseDecision {
    decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::InactiveSession,
        message,
        None,
        Vec::new(),
        None,
    )
}

fn denied_unknown_work_item() -> WorkLeaseDecision {
    decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::UnknownWorkItem,
        "work item is missing",
        None,
        Vec::new(),
        None,
    )
}

fn denied_completed_work_item() -> WorkLeaseDecision {
    decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::AlreadyCompleted,
        "work item is already completed",
        None,
        Vec::new(),
        None,
    )
}

fn deny_missing_verifier(state: &mut WorkState, item: &WorkItem) -> Option<WorkLeaseDecision> {
    if !item.scope.authority.allows_write() || !item.required_verifiers.is_empty() {
        return None;
    }
    let conflict = conflict(
        item.work_item_id,
        WorkLeaseId::new_v7(),
        None,
        WorkConflictKind::MissingVerifier,
        item.scope.write_set.clone(),
        "mutating work item has no required verifier",
    );
    state.conflicts.push(conflict.clone());
    mark_item_blocked(state, item.work_item_id, &conflict.conflict_id);
    Some(decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::MissingVerifier,
        "mutating work item requires verifier evidence",
        None,
        Vec::new(),
        None,
    ))
}

fn deny_write_conflicts(
    state: &mut WorkState,
    item: &WorkItem,
    role: AgentRole,
) -> Option<WorkLeaseDecision> {
    let conflicts = WorkConflictService::active_write_conflicts(state, item, role);
    if conflicts.is_empty() {
        return None;
    }
    for conflict in &conflicts {
        state.conflicts.push(conflict.clone());
        mark_item_blocked(state, item.work_item_id, &conflict.conflict_id);
    }
    let conflicting_lease_ids = conflicts
        .iter()
        .filter_map(|conflict| conflict.conflicting_work_lease_id)
        .collect();
    Some(decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::OverlappingWriteScope,
        "overlapping active write scope",
        None,
        conflicting_lease_ids,
        None,
    ))
}

fn grant_work_lease(
    state: &mut WorkState,
    request: WorkClaimRequest,
    session: ClaimSession,
    item: WorkItem,
    now: OffsetDateTime,
) -> WorkLeaseDecision {
    let lease_id = WorkLeaseId::new_v7();
    let expires_at = now + Duration::minutes(request.ttl_minutes.max(1));
    let grant = decision(
        WorkLeaseDecisionKind::Granted,
        grant_reason(&item, request.role),
        "work lease granted",
        Some(lease_id),
        Vec::new(),
        Some(expires_at),
    );
    state.leases.push(WorkLease {
        work_lease_id: lease_id,
        work_item_id: item.work_item_id,
        agent_session_id: session.agent_session_id,
        agent_id: session.agent_id,
        project_id: item.project_id,
        task_id: item.task_id,
        role: request.role,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: item.scope,
        decision: grant.clone(),
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at,
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    });
    mark_claim_active(state, request, lease_id, now);
    push_decision(state, grant)
}

fn grant_reason(item: &WorkItem, role: AgentRole) -> WorkLeaseDecisionReason {
    if item.scope.write_set.is_empty() && role == AgentRole::Auditor {
        WorkLeaseDecisionReason::ReadOnlyOverlapAllowed
    } else {
        WorkLeaseDecisionReason::NoConflict
    }
}

fn mark_claim_active(
    state: &mut WorkState,
    request: WorkClaimRequest,
    lease_id: WorkLeaseId,
    now: OffsetDateTime,
) {
    if let Some(item) = state
        .work_items
        .iter_mut()
        .find(|item| item.work_item_id == request.work_item_id)
    {
        item.status = WorkItemStatus::Active;
        item.active_lease_id = Some(lease_id);
        item.lease_refs.push(lease_id);
        item.updated_at = now;
    }
    if let Some(session) = state
        .sessions
        .iter_mut()
        .find(|session| session.agent_session_id == request.agent_session_id)
    {
        session.current_work_item_id = Some(request.work_item_id);
        session.last_heartbeat_at = now;
    }
}

impl WorkConflictService {
    #[must_use]
    pub fn active_write_conflicts(
        state: &WorkState,
        item: &WorkItem,
        role: AgentRole,
    ) -> Vec<WorkConflict> {
        if item.scope.write_set.is_empty() && role == AgentRole::Auditor {
            return Vec::new();
        }
        state
            .leases
            .iter()
            .filter(|lease| work_lease_is_active(lease))
            .filter(|lease| lease.project_id == item.project_id)
            .filter(|lease| !lease.scope.write_set.is_empty() || !item.scope.write_set.is_empty())
            .filter_map(|lease| {
                let paths = overlapping_paths(&lease.scope.write_set, &item.scope.write_set);
                (!paths.is_empty()).then(|| {
                    conflict(
                        item.work_item_id,
                        WorkLeaseId::new_v7(),
                        Some(lease.work_lease_id),
                        WorkConflictKind::OverlappingWriteScope,
                        paths,
                        "active work lease overlaps requested write scope",
                    )
                })
            })
            .collect()
    }
}

impl WorkMemoryWriter {
    pub async fn write_session(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        session: &mut AgentSession,
    ) -> Result<(), EngineError> {
        let receipt = write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: session.project_id,
                task_id: None,
                agent_id: session.agent_id,
                scope: "agent-session",
                observation: format!(
                    "AgentSession {} status {:?}",
                    session.agent_session_id, session.status
                ),
                payload: serde_json::json!({ "agent_session": session }),
            },
        )
        .await?;
        session.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_work_item(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        item: &mut WorkItem,
    ) -> Result<(), EngineError> {
        let receipt = write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: item.project_id,
                task_id: Some(item.task_id),
                agent_id: AgentId::from_uuid(item.created_by.as_uuid()),
                scope: "work-item",
                observation: format!("WorkItem {} status {:?}", item.work_item_id, item.status),
                payload: serde_json::json!({ "work_item": item }),
            },
        )
        .await?;
        item.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_work_lease(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        lease: &mut WorkLease,
    ) -> Result<(), EngineError> {
        let receipt = write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: lease.project_id,
                task_id: Some(lease.task_id),
                agent_id: lease.agent_id,
                scope: "work-lease",
                observation: format!("WorkLease {} state {:?}", lease.work_lease_id, lease.state),
                payload: serde_json::json!({ "work_lease": lease }),
            },
        )
        .await?;
        lease.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_conflict(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        task_id: TaskId,
        agent_id: AgentId,
        conflict: &WorkConflict,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id,
                task_id: Some(task_id),
                agent_id,
                scope: "work-conflict",
                observation: format!(
                    "WorkConflict {} kind {:?}",
                    conflict.conflict_id, conflict.kind
                ),
                payload: serde_json::json!({ "work_conflict": conflict }),
            },
        )
        .await
    }

    pub async fn write_event(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        event: &WorkSessionEvent,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: event.project_id,
                task_id: None,
                agent_id: event.agent_id,
                scope: "agent-session-event",
                observation: event.summary.clone(),
                payload: serde_json::json!({ "agent_session_event": event }),
            },
        )
        .await
    }
}

#[must_use]
pub fn default_work_scope(
    repo_root: impl Into<String>,
    read_set: Vec<String>,
    write_set: Vec<String>,
    verifier_set: Vec<String>,
) -> WorkScope {
    let authority = if write_set.is_empty() {
        AuthorityProfile::read_only()
    } else {
        AuthorityProfile::bounded_write()
    };
    WorkScope {
        repo_root: repo_root.into(),
        read_set,
        write_set,
        verifier_set,
        authority,
        risk_tier: RiskTier::Low,
        max_files: 12,
        requires_active_work_lease: true,
    }
}

#[must_use]
pub fn work_lease_is_active(lease: &WorkLease) -> bool {
    matches!(
        lease.state,
        WorkLeaseState::Granted | WorkLeaseState::Renewed
    ) && lease.expires_at > OffsetDateTime::now_utc()
}

pub fn guard_work_lease_for_files(
    work_lease: Option<&WorkLease>,
    project_id: ProjectId,
    task_id: TaskId,
    agent_id: AgentId,
    files: &[String],
) -> Result<(), WorkLeaseGuardError> {
    let Some(lease) = work_lease else {
        return Err(WorkLeaseGuardError::Missing);
    };
    if !work_lease_is_active(lease) {
        return Err(WorkLeaseGuardError::Inactive);
    }
    if lease.project_id != project_id || lease.task_id != task_id || lease.agent_id != agent_id {
        return Err(WorkLeaseGuardError::Mismatch);
    }
    if files
        .iter()
        .any(|file| !path_in_scope(file, &lease.scope.write_set))
    {
        return Err(WorkLeaseGuardError::FileOutsideScope);
    }
    Ok(())
}

#[must_use]
pub fn path_in_scope(path: &str, scope_paths: &[String]) -> bool {
    let path = normalize_path(path);
    scope_paths.iter().any(|scope_path| {
        let scope_path = normalize_path(scope_path);
        path == scope_path || path.starts_with(&format!("{scope_path}/"))
    })
}

#[must_use]
pub fn work_completion_satisfied(item: Option<&WorkItem>, lease: Option<&WorkLease>) -> bool {
    let Some(item) = item else {
        return false;
    };
    let Some(lease) = lease else {
        return false;
    };
    item.status == WorkItemStatus::Completed
        && !matches!(
            lease.state,
            WorkLeaseState::Revoked | WorkLeaseState::Expired | WorkLeaseState::Denied
        )
}

struct WorkPayloadInput {
    project_id: ProjectId,
    task_id: Option<TaskId>,
    agent_id: AgentId,
    scope: &'static str,
    observation: String,
    payload: serde_json::Value,
}

async fn write_work_payload(
    writer: &WriterHandle,
    admission: &WriteAdmissionService,
    input: WorkPayloadInput,
) -> Result<WriteReceiptRef, EngineError> {
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: input.agent_id,
            session_id: None,
            project_id: input.project_id,
            task_id: input.task_id,
            scope: format!("work/{}", input.scope),
            authority: "eliot-work-coordination-service".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot_work_coordination".to_owned(),
        observation: input.observation,
        payload: input.payload,
    });
    let receipt = writer.submit(admission.admit(&command)?).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

fn labels_match(item: &WorkItem, project: &str, task: &str) -> bool {
    (project.is_empty() || item.project == project) && (task.is_empty() || item.task == task)
}

fn decision(
    kind: WorkLeaseDecisionKind,
    reason: WorkLeaseDecisionReason,
    message: impl Into<String>,
    work_lease_id: Option<WorkLeaseId>,
    conflicting_lease_ids: Vec<WorkLeaseId>,
    expires_at: Option<OffsetDateTime>,
) -> WorkLeaseDecision {
    WorkLeaseDecision {
        kind,
        reason,
        message: message.into(),
        work_lease_id,
        conflicting_lease_ids,
        expires_at,
    }
}

fn push_decision(state: &mut WorkState, decision: WorkLeaseDecision) -> WorkLeaseDecision {
    state.decisions.push(decision.clone());
    decision
}

fn conflict(
    work_item_id: WorkItemId,
    work_lease_id: WorkLeaseId,
    conflicting_work_lease_id: Option<WorkLeaseId>,
    kind: WorkConflictKind,
    paths: Vec<String>,
    detail: impl Into<String>,
) -> WorkConflict {
    let raw = format!(
        "{}:{}:{}:{kind:?}",
        work_item_id,
        work_lease_id,
        conflicting_work_lease_id.map_or_else(String::new, |id| id.to_string())
    );
    let conflict_id = blake3::hash(raw.as_bytes())
        .to_hex()
        .chars()
        .take(24)
        .collect::<String>();
    WorkConflict {
        conflict_id,
        work_item_id,
        work_lease_id,
        conflicting_work_lease_id,
        kind,
        paths,
        resolution: Some(WorkConflictResolution::Denied),
        detail: detail.into(),
        detected_at: OffsetDateTime::now_utc(),
    }
}

fn mark_item_blocked(state: &mut WorkState, work_item_id: WorkItemId, conflict_id: &str) {
    if let Some(item) = state
        .work_items
        .iter_mut()
        .find(|item| item.work_item_id == work_item_id)
    {
        item.status = WorkItemStatus::Blocked;
        item.conflict_refs.push(conflict_id.to_owned());
        item.updated_at = OffsetDateTime::now_utc();
    }
}

fn inactive_reason(lease: &WorkLease) -> WorkLeaseDecisionReason {
    match lease.state {
        WorkLeaseState::Revoked => WorkLeaseDecisionReason::RevokedLease,
        WorkLeaseState::Released => WorkLeaseDecisionReason::ReleasedLease,
        WorkLeaseState::Denied => WorkLeaseDecisionReason::LeaseNotFound,
        WorkLeaseState::Expired | WorkLeaseState::Granted | WorkLeaseState::Renewed
            if lease.expires_at <= OffsetDateTime::now_utc() =>
        {
            WorkLeaseDecisionReason::ExpiredLease
        }
        WorkLeaseState::Granted | WorkLeaseState::Renewed => WorkLeaseDecisionReason::NoConflict,
        WorkLeaseState::Expired => WorkLeaseDecisionReason::ExpiredLease,
    }
}

fn overlapping_paths(left: &[String], right: &[String]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for left in left {
        for right in right {
            let left = normalize_path(left);
            let right = normalize_path(right);
            if left == right
                || left.starts_with(&format!("{right}/"))
                || right.starts_with(&format!("{left}/"))
            {
                paths.insert(if left.len() >= right.len() {
                    left
                } else {
                    right
                });
            }
        }
    }
    paths.into_iter().collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_matches('/')
        .to_ascii_lowercase()
}

#[must_use]
pub fn default_lease_ttl_minutes() -> i64 {
    DEFAULT_LEASE_TTL_MINUTES
}
