use crate::{EngineError, WorkState, WriteAdmissionService, WriterHandle};
use eliot_types::{
    ActionLeaseId, AgentContributionTrace, AgentId, AgentRole, AgentSessionId, AgentSessionStatus,
    BlackboardItem, BlackboardItemId, BlackboardItemKind, BlackboardItemStatus, BlackboardScope,
    CollectiveTrace, CommandContext, ConfidenceLevel, ContributionEffect, LeaseDecision,
    LeaseStatus, LifecycleStatus, LostAgentRecoveryRecord, MailboxMessage, MailboxMessageId,
    MailboxMessageKind, MailboxMessageStatus, MailboxRecipient, ProjectId, RecoveryAction,
    RejectedCandidateTrace, SemanticCommand, TaintClass, TaskId, ToolObservationRecordCommand,
    VerifierEffectTrace, Visibility, WorkItemId, WorkItemStatus, WorkLeaseDecision,
    WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState, WorktreeLeaseId,
    WorktreeLeaseState, WriteId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug)]
pub struct BlackboardAddInput {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub owner_session_id: AgentSessionId,
    pub work_item_id: Option<WorkItemId>,
    pub lease_id: Option<WorkLeaseId>,
    pub kind: BlackboardItemKind,
    pub scope: BlackboardScope,
    pub payload_ref: String,
    pub evidence_refs: Vec<String>,
    pub confidence: Option<ConfidenceLevel>,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct MailboxSendInput {
    pub message_id: Option<MailboxMessageId>,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub sender_session_id: AgentSessionId,
    pub recipient: MailboxRecipient,
    pub kind: MailboxMessageKind,
    pub payload_ref: String,
    pub requires_ack: Option<bool>,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StopCoordinationDecision {
    pub allow: bool,
    pub reasons: Vec<String>,
    pub unacknowledged_control_messages: Vec<MailboxMessageId>,
    pub unresolved_blackboard_items: Vec<BlackboardItemId>,
    pub unresolved_work_conflicts: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlackboardService;

#[derive(Clone, Copy, Debug, Default)]
pub struct MailboxService;

#[derive(Clone, Copy, Debug, Default)]
pub struct LostAgentRecoveryService;

#[derive(Clone, Copy, Debug, Default)]
pub struct CollectiveTraceService;

#[derive(Clone, Copy, Debug, Default)]
pub struct StopCoordinationGate;

pub struct CollectiveMemoryWriter;

impl BlackboardService {
    #[must_use]
    pub fn create_item(&self, state: &mut WorkState, input: BlackboardAddInput) -> BlackboardItem {
        let item = BlackboardItem {
            blackboard_item_id: BlackboardItemId::new_v7(),
            project_id: input.project_id,
            task_id: input.task_id,
            owner_session_id: input.owner_session_id,
            work_item_id: input.work_item_id,
            lease_id: input.lease_id,
            kind: input.kind,
            scope: input.scope,
            payload_ref: input.payload_ref,
            evidence_refs: input.evidence_refs,
            status: BlackboardItemStatus::Open,
            confidence: input.confidence,
            created_at: OffsetDateTime::now_utc(),
            expires_at: input.expires_at,
            acknowledged_by: Vec::new(),
            write_receipt: None,
        };
        state.blackboard_items.push(item.clone());
        item
    }

    #[must_use]
    pub fn list(
        &self,
        state: &WorkState,
        project_id: ProjectId,
        task_id: TaskId,
    ) -> Vec<BlackboardItem> {
        state
            .blackboard_items
            .iter()
            .filter(|item| item.project_id == project_id && item.task_id == task_id)
            .cloned()
            .collect()
    }

    pub fn acknowledge(
        &self,
        state: &mut WorkState,
        item_id: BlackboardItemId,
        session_id: AgentSessionId,
    ) -> Result<BlackboardItem, EngineError> {
        let item = blackboard_item_mut(state, item_id)?;
        if !item.acknowledged_by.contains(&session_id) {
            item.acknowledged_by.push(session_id);
        }
        if item.status == BlackboardItemStatus::Open {
            item.status = BlackboardItemStatus::Acknowledged;
        }
        Ok(item.clone())
    }

    pub fn resolve(
        &self,
        state: &mut WorkState,
        item_id: BlackboardItemId,
    ) -> Result<BlackboardItem, EngineError> {
        let item = blackboard_item_mut(state, item_id)?;
        item.status = BlackboardItemStatus::Resolved;
        Ok(item.clone())
    }

    pub fn reject(
        &self,
        state: &mut WorkState,
        item_id: BlackboardItemId,
    ) -> Result<BlackboardItem, EngineError> {
        let item = blackboard_item_mut(state, item_id)?;
        item.status = BlackboardItemStatus::Rejected;
        Ok(item.clone())
    }

    pub fn supersede(
        &self,
        state: &mut WorkState,
        item_id: BlackboardItemId,
    ) -> Result<BlackboardItem, EngineError> {
        let item = blackboard_item_mut(state, item_id)?;
        item.status = BlackboardItemStatus::Superseded;
        Ok(item.clone())
    }

    #[must_use]
    pub fn expire_old(&self, state: &mut WorkState, now: OffsetDateTime) -> Vec<BlackboardItem> {
        let mut expired = Vec::new();
        for item in &mut state.blackboard_items {
            if matches!(
                item.status,
                BlackboardItemStatus::Open | BlackboardItemStatus::Acknowledged
            ) && item.expires_at.is_some_and(|expires_at| expires_at <= now)
            {
                item.status = BlackboardItemStatus::Expired;
                expired.push(item.clone());
            }
        }
        expired
    }
}

impl MailboxService {
    #[must_use]
    pub fn send(&self, state: &mut WorkState, input: MailboxSendInput) -> MailboxMessage {
        if let Some(message_id) = input.message_id
            && let Some(existing) = state
                .mailbox_messages
                .iter()
                .find(|message| message.message_id == message_id)
        {
            return existing.clone();
        }

        let recipient = input.recipient;
        let sequence = next_sequence(state, input.project_id, input.task_id, &recipient);
        let message = MailboxMessage {
            message_id: input.message_id.unwrap_or_else(MailboxMessageId::new_v7),
            project_id: input.project_id,
            task_id: input.task_id,
            sender_session_id: input.sender_session_id,
            recipient,
            sequence,
            kind: input.kind,
            payload_ref: input.payload_ref,
            requires_ack: input
                .requires_ack
                .unwrap_or_else(|| message_kind_requires_ack(input.kind)),
            created_at: OffsetDateTime::now_utc(),
            expires_at: input.expires_at,
            acknowledged_at: None,
            status: MailboxMessageStatus::Pending,
            write_receipt: None,
        };
        state.mailbox_messages.push(message.clone());
        message
    }

    #[must_use]
    pub fn inbox(
        &self,
        state: &WorkState,
        project_id: ProjectId,
        task_id: TaskId,
        recipient: Option<&MailboxRecipient>,
    ) -> Vec<MailboxMessage> {
        state
            .mailbox_messages
            .iter()
            .filter(|message| message.project_id == project_id && message.task_id == task_id)
            .filter(|message| recipient.is_none_or(|recipient| &message.recipient == recipient))
            .cloned()
            .collect()
    }

    pub fn acknowledge(
        &self,
        state: &mut WorkState,
        message_id: MailboxMessageId,
    ) -> Result<MailboxMessage, EngineError> {
        let message = mailbox_message_mut(state, message_id)?;
        message.status = MailboxMessageStatus::Acknowledged;
        message.acknowledged_at = Some(OffsetDateTime::now_utc());
        Ok(message.clone())
    }

    #[must_use]
    pub fn expire_stale(&self, state: &mut WorkState, now: OffsetDateTime) -> Vec<MailboxMessage> {
        let mut expired = Vec::new();
        for message in &mut state.mailbox_messages {
            if matches!(
                message.status,
                MailboxMessageStatus::Pending | MailboxMessageStatus::Delivered
            ) && message
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                message.status = MailboxMessageStatus::Expired;
                expired.push(message.clone());
            }
        }
        expired
    }
}

impl LostAgentRecoveryService {
    #[must_use]
    pub fn scan(
        &self,
        state: &mut WorkState,
        project_id: ProjectId,
        task_id: TaskId,
        heartbeat_timeout: Duration,
    ) -> Vec<LostAgentRecoveryRecord> {
        let now = OffsetDateTime::now_utc();
        let lost_sessions = state
            .sessions
            .iter()
            .filter(|session| {
                session.project_id == project_id
                    && session.status == AgentSessionStatus::Active
                    && now - session.last_heartbeat_at > heartbeat_timeout
            })
            .map(|session| {
                (
                    session.agent_session_id,
                    session.agent_id,
                    session.last_heartbeat_at,
                )
            })
            .collect::<Vec<_>>();

        let mut records = Vec::new();
        for (session_id, agent_id, last_heartbeat_at) in lost_sessions {
            let mut actions = BTreeSet::new();
            expire_session(state, session_id, now, &mut actions);
            let active_action_leases =
                revoke_action_leases(state, project_id, task_id, agent_id, &mut actions);
            let active_work_leases = revoke_work_leases(state, session_id, now, &mut actions);
            let active_worktree_leases = retain_worktrees(state, session_id, &mut actions);
            let resulting_work_status =
                mark_work_items_resumable(state, &active_work_leases, &mut actions);
            let mailbox_message = notify_controller(
                state,
                project_id,
                task_id,
                session_id,
                &format!("recovery:{task_id}:{session_id}"),
            );
            actions.insert(RecoveryAction::NotifyController);
            let record = LostAgentRecoveryRecord {
                recovery_id: format!("recovery:{}", MailboxMessageId::new_v7()),
                project_id,
                task_id,
                agent_session_id: session_id,
                detected_at: now,
                last_heartbeat_at: Some(last_heartbeat_at),
                active_work_leases,
                active_action_leases,
                active_worktree_leases,
                actions_taken: actions.into_iter().collect(),
                mailbox_messages: vec![mailbox_message.message_id],
                resulting_work_status,
                write_receipt: None,
            };
            state.recovery_records.push(record.clone());
            records.push(record);
        }
        records
    }
}

impl CollectiveTraceService {
    #[must_use]
    pub fn trace_task(
        &self,
        state: &mut WorkState,
        project_id: ProjectId,
        task_id: TaskId,
    ) -> CollectiveTrace {
        let mut agent_contributions = Vec::new();
        for item in state
            .blackboard_items
            .iter()
            .filter(|item| item.project_id == project_id && item.task_id == task_id)
        {
            let role = state
                .sessions
                .iter()
                .find(|session| session.agent_session_id == item.owner_session_id)
                .map_or(AgentRole::Reviewer, |session| session.role);
            agent_contributions.push(AgentContributionTrace {
                agent_session_id: item.owner_session_id,
                role,
                work_item_id: item.work_item_id,
                contribution_refs: vec![format!("blackboard:{}", item.blackboard_item_id)],
                effect: contribution_effect_for_item(item),
                evidence_refs: item.evidence_refs.clone(),
            });
        }

        let mut rejected_candidates = Vec::new();
        for review in &state.candidate_reviews {
            if !matches!(
                review.decision,
                eliot_types::CandidateReviewDecision::Reject
                    | eliot_types::CandidateReviewDecision::RequireRevision
            ) {
                continue;
            }
            if let Some(diff) = state
                .candidate_diffs
                .iter()
                .find(|diff| diff.candidate_diff_id == review.candidate_diff_id)
                && diff.project_id == project_id
                && diff.task_id == task_id
            {
                rejected_candidates.push(RejectedCandidateTrace {
                    candidate_ref: format!("candidate_diff:{}", diff.candidate_diff_id),
                    reviewer_session_id: Some(review.reviewer_session_id),
                    reason: review.reasons.join("; "),
                    evidence_refs: vec![diff.diff_ref.clone()],
                });
            }
        }

        let verifier_effects = state
            .blackboard_items
            .iter()
            .filter(|item| {
                item.project_id == project_id
                    && item.task_id == task_id
                    && item.kind == BlackboardItemKind::VerifierResult
            })
            .map(|item| VerifierEffectTrace {
                verifier_ref: item.payload_ref.clone(),
                effect: if item.status == BlackboardItemStatus::Rejected {
                    ContributionEffect::KilledHypothesis
                } else {
                    ContributionEffect::ConfirmedVerifier
                },
                killed_hypothesis_ref: item
                    .evidence_refs
                    .iter()
                    .find(|reference| reference.contains("hypothesis"))
                    .cloned(),
                evidence_refs: item.evidence_refs.clone(),
            })
            .collect::<Vec<_>>();

        let unused_context_items = state
            .blackboard_items
            .iter()
            .filter(|item| {
                item.project_id == project_id
                    && item.task_id == task_id
                    && matches!(
                        contribution_effect_for_item(item),
                        ContributionEffect::ProducedUnusedCandidate
                            | ContributionEffect::NoObservableEffect
                    )
            })
            .map(|item| format!("blackboard:{}", item.blackboard_item_id))
            .collect::<Vec<_>>();

        let trace = CollectiveTrace {
            collective_trace_id: format!("collective:{}:{}", task_id, MailboxMessageId::new_v7()),
            project_id,
            task_id,
            closed_at: OffsetDateTime::now_utc(),
            agent_contributions,
            rejected_candidates,
            verifier_effects,
            unused_context_items,
            candidate_learning_refs: Vec::new(),
            write_receipt: None,
        };
        state.collective_traces.push(trace.clone());
        trace
    }
}

impl StopCoordinationGate {
    #[must_use]
    pub fn evaluate(
        &self,
        state: &WorkState,
        project_id: Option<ProjectId>,
        task_id: Option<TaskId>,
    ) -> StopCoordinationDecision {
        let unacknowledged_control_messages = state
            .mailbox_messages
            .iter()
            .filter(|message| {
                project_id.is_none_or(|project_id| message.project_id == project_id)
                    && task_id.is_none_or(|task_id| message.task_id == task_id)
                    && message.requires_ack
                    && matches!(
                        message.status,
                        MailboxMessageStatus::Pending | MailboxMessageStatus::Delivered
                    )
            })
            .map(|message| message.message_id)
            .collect::<Vec<_>>();
        let unresolved_blackboard_items = state
            .blackboard_items
            .iter()
            .filter(|item| {
                project_id.is_none_or(|project_id| item.project_id == project_id)
                    && task_id.is_none_or(|task_id| item.task_id == task_id)
                    && matches!(
                        item.kind,
                        BlackboardItemKind::Blocker
                            | BlackboardItemKind::ConflictNotice
                            | BlackboardItemKind::DecisionRequest
                    )
                    && matches!(
                        item.status,
                        BlackboardItemStatus::Open | BlackboardItemStatus::Acknowledged
                    )
            })
            .map(|item| item.blackboard_item_id)
            .collect::<Vec<_>>();
        let unresolved_work_conflicts = state
            .conflicts
            .iter()
            .filter(|conflict| {
                conflict.resolution.is_none()
                    && state.work_items.iter().any(|item| {
                        item.work_item_id == conflict.work_item_id
                            && project_id.is_none_or(|project_id| item.project_id == project_id)
                            && task_id.is_none_or(|task_id| item.task_id == task_id)
                    })
            })
            .map(|conflict| conflict.conflict_id.clone())
            .collect::<Vec<_>>();
        let allow = unacknowledged_control_messages.is_empty()
            && unresolved_blackboard_items.is_empty()
            && unresolved_work_conflicts.is_empty();
        let mut reasons = Vec::new();
        if !unacknowledged_control_messages.is_empty() {
            reasons.push("unacknowledged_control_messages".to_owned());
        }
        if !unresolved_blackboard_items.is_empty() {
            reasons.push("unresolved_blackboard_items".to_owned());
        }
        if !unresolved_work_conflicts.is_empty() {
            reasons.push("unresolved_work_conflicts".to_owned());
        }
        if allow {
            reasons.push("collective_coordination_clear".to_owned());
        }
        StopCoordinationDecision {
            allow,
            reasons,
            unacknowledged_control_messages,
            unresolved_blackboard_items,
            unresolved_work_conflicts,
        }
    }
}

impl CollectiveMemoryWriter {
    pub async fn write_blackboard_item(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        item: &mut BlackboardItem,
    ) -> Result<(), EngineError> {
        let receipt = write_collective_payload(
            writer,
            admission,
            CollectivePayloadInput {
                project_id: item.project_id,
                task_id: item.task_id,
                agent_id: AgentId::from_uuid(item.owner_session_id.as_uuid()),
                scope: "blackboard-item",
                observation: format!(
                    "BlackboardItem {} kind {:?} status {:?}",
                    item.blackboard_item_id, item.kind, item.status
                ),
                payload: serde_json::json!({ "blackboard_item": item }),
            },
        )
        .await?;
        item.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_mailbox_message(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        message: &mut MailboxMessage,
    ) -> Result<(), EngineError> {
        let receipt = write_collective_payload(
            writer,
            admission,
            CollectivePayloadInput {
                project_id: message.project_id,
                task_id: message.task_id,
                agent_id: AgentId::from_uuid(message.sender_session_id.as_uuid()),
                scope: "mailbox-message",
                observation: format!(
                    "MailboxMessage {} kind {:?} status {:?}",
                    message.message_id, message.kind, message.status
                ),
                payload: serde_json::json!({ "mailbox_message": message }),
            },
        )
        .await?;
        message.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_recovery_record(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        record: &mut LostAgentRecoveryRecord,
    ) -> Result<(), EngineError> {
        let receipt = write_collective_payload(
            writer,
            admission,
            CollectivePayloadInput {
                project_id: record.project_id,
                task_id: record.task_id,
                agent_id: AgentId::from_uuid(record.agent_session_id.as_uuid()),
                scope: "lost-agent-recovery",
                observation: format!(
                    "LostAgentRecoveryRecord {} actions {}",
                    record.recovery_id,
                    record.actions_taken.len()
                ),
                payload: serde_json::json!({ "lost_agent_recovery": record }),
            },
        )
        .await?;
        record.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_collective_trace(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        trace: &mut CollectiveTrace,
    ) -> Result<(), EngineError> {
        let receipt = write_collective_payload(
            writer,
            admission,
            CollectivePayloadInput {
                project_id: trace.project_id,
                task_id: trace.task_id,
                agent_id: AgentId::new_v7(),
                scope: "collective-trace",
                observation: format!(
                    "CollectiveTrace {} contributions {}",
                    trace.collective_trace_id,
                    trace.agent_contributions.len()
                ),
                payload: serde_json::json!({ "collective_trace": trace }),
            },
        )
        .await?;
        trace.write_receipt = Some(receipt);
        Ok(())
    }
}

#[derive(Clone)]
struct CollectivePayloadInput {
    project_id: ProjectId,
    task_id: TaskId,
    agent_id: AgentId,
    scope: &'static str,
    observation: String,
    payload: serde_json::Value,
}

async fn write_collective_payload(
    writer: &WriterHandle,
    admission: &WriteAdmissionService,
    input: CollectivePayloadInput,
) -> Result<WriteReceiptRef, EngineError> {
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: input.agent_id,
            session_id: None,
            project_id: input.project_id,
            task_id: Some(input.task_id),
            scope: format!("collective/{}", input.scope),
            authority: "eliot-collective-coordination-service".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot_collective_governor".to_owned(),
        observation: input.observation,
        payload: input.payload,
    });
    let receipt = writer.submit(admission.admit(&command)?).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

fn blackboard_item_mut(
    state: &mut WorkState,
    item_id: BlackboardItemId,
) -> Result<&mut BlackboardItem, EngineError> {
    state
        .blackboard_items
        .iter_mut()
        .find(|item| item.blackboard_item_id == item_id)
        .ok_or_else(|| EngineError::WriteRejected("blackboard_item_not_found".to_owned()))
}

fn mailbox_message_mut(
    state: &mut WorkState,
    message_id: MailboxMessageId,
) -> Result<&mut MailboxMessage, EngineError> {
    state
        .mailbox_messages
        .iter_mut()
        .find(|message| message.message_id == message_id)
        .ok_or_else(|| EngineError::WriteRejected("mailbox_message_not_found".to_owned()))
}

fn next_sequence(
    state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    recipient: &MailboxRecipient,
) -> u64 {
    state
        .mailbox_messages
        .iter()
        .filter(|message| {
            message.project_id == project_id
                && message.task_id == task_id
                && &message.recipient == recipient
        })
        .map(|message| message.sequence)
        .max()
        .unwrap_or(0)
        + 1
}

fn message_kind_requires_ack(kind: MailboxMessageKind) -> bool {
    matches!(
        kind,
        MailboxMessageKind::WorkBlocked
            | MailboxMessageKind::LeaseExpiring
            | MailboxMessageKind::LeaseRevoked
            | MailboxMessageKind::ReviewRequested
            | MailboxMessageKind::ConflictRaised
            | MailboxMessageKind::VerifierFailed
            | MailboxMessageKind::CompletionBlocked
            | MailboxMessageKind::AgentExpired
            | MailboxMessageKind::AckRequired
    )
}

fn expire_session(
    state: &mut WorkState,
    session_id: AgentSessionId,
    now: OffsetDateTime,
    actions: &mut BTreeSet<RecoveryAction>,
) {
    if let Some(session) = state
        .sessions
        .iter_mut()
        .find(|session| session.agent_session_id == session_id)
    {
        session.status = AgentSessionStatus::Expired;
        session.stopped_at = Some(now);
        session.unavailable_reason = Some("lost-agent recovery heartbeat timeout".to_owned());
        actions.insert(RecoveryAction::MarkAgentExpired);
    }
}

fn revoke_action_leases(
    state: &mut WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    agent_id: AgentId,
    actions: &mut BTreeSet<RecoveryAction>,
) -> Vec<ActionLeaseId> {
    let mut ids = Vec::new();
    for lease in &mut state.action_leases {
        if lease.project_id == project_id
            && lease.task_id == task_id
            && lease.agent_id == agent_id
            && matches!(
                lease.status,
                LeaseStatus::PlannedOnly
                    | LeaseStatus::ApprovedForExecution
                    | LeaseStatus::ReadOnly
                    | LeaseStatus::ProbeOnly
            )
        {
            lease.status = LeaseStatus::Revoked;
            lease.decision = LeaseDecision::Deny;
            ids.push(lease.lease_id);
            actions.insert(RecoveryAction::RevokeActionLease);
        }
    }
    ids
}

fn revoke_work_leases(
    state: &mut WorkState,
    session_id: AgentSessionId,
    now: OffsetDateTime,
    actions: &mut BTreeSet<RecoveryAction>,
) -> Vec<WorkLeaseId> {
    let mut ids = Vec::new();
    for lease in &mut state.leases {
        if lease.agent_session_id == session_id
            && matches!(
                lease.state,
                WorkLeaseState::Granted | WorkLeaseState::Renewed
            )
            && lease.expires_at > now
        {
            lease.state = WorkLeaseState::Revoked;
            lease.revoked_at = Some(now);
            lease.expires_at = now;
            lease.epoch += 1;
            lease.decision = WorkLeaseDecision {
                kind: WorkLeaseDecisionKind::Revoked,
                reason: WorkLeaseDecisionReason::ExpiredLease,
                message: "lost-agent recovery revoked active work lease".to_owned(),
                work_lease_id: Some(lease.work_lease_id),
                conflicting_lease_ids: Vec::new(),
                expires_at: Some(now),
            };
            ids.push(lease.work_lease_id);
            actions.insert(RecoveryAction::RevokeOrExpireWorkLease);
            actions.insert(RecoveryAction::AdvanceLeaseEpoch);
        }
    }
    ids
}

fn retain_worktrees(
    state: &mut WorkState,
    session_id: AgentSessionId,
    actions: &mut BTreeSet<RecoveryAction>,
) -> Vec<WorktreeLeaseId> {
    let mut ids = Vec::new();
    for lease in &mut state.worktree_leases {
        if lease.holder_session_id == session_id
            && matches!(
                lease.state,
                WorktreeLeaseState::Created
                    | WorktreeLeaseState::Active
                    | WorktreeLeaseState::Captured
            )
        {
            lease.state = WorktreeLeaseState::Expired;
            ids.push(lease.worktree_lease_id);
            actions.insert(RecoveryAction::RetainWorktreeForInspection);
        }
    }
    ids
}

fn mark_work_items_resumable(
    state: &mut WorkState,
    work_lease_ids: &[WorkLeaseId],
    actions: &mut BTreeSet<RecoveryAction>,
) -> Vec<WorkItemStatus> {
    let mut statuses = Vec::new();
    for lease_id in work_lease_ids {
        let Some(work_item_id) = state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == *lease_id)
            .map(|lease| lease.work_item_id)
        else {
            continue;
        };
        if let Some(item) = state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == work_item_id)
        {
            item.active_lease_id = None;
            if item.status != WorkItemStatus::Completed {
                item.status = WorkItemStatus::Open;
                actions.insert(RecoveryAction::MarkWorkItemResumable);
            }
            statuses.push(item.status);
        }
    }
    statuses
}

fn notify_controller(
    state: &mut WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    expired_session_id: AgentSessionId,
    payload_ref: &str,
) -> MailboxMessage {
    let sender_session_id = state
        .sessions
        .iter()
        .find(|session| session.agent_session_id == expired_session_id)
        .map_or(expired_session_id, |session| session.agent_session_id);
    MailboxService.send(
        state,
        MailboxSendInput {
            message_id: None,
            project_id,
            task_id,
            sender_session_id,
            recipient: MailboxRecipient::Controller,
            kind: MailboxMessageKind::AgentExpired,
            payload_ref: payload_ref.to_owned(),
            requires_ack: Some(true),
            expires_at: None,
        },
    )
}

fn contribution_effect_for_item(item: &BlackboardItem) -> ContributionEffect {
    match (item.kind, item.status) {
        (BlackboardItemKind::FindingCandidate, BlackboardItemStatus::Resolved) => {
            ContributionEffect::ChangedAction
        }
        (BlackboardItemKind::DecisionRequest, BlackboardItemStatus::Resolved) => {
            ContributionEffect::ChangedDecision
        }
        (BlackboardItemKind::HypothesisCandidate, BlackboardItemStatus::Rejected) => {
            ContributionEffect::KilledHypothesis
        }
        (BlackboardItemKind::VerifierResult, BlackboardItemStatus::Resolved) => {
            ContributionEffect::ConfirmedVerifier
        }
        (BlackboardItemKind::FindingCandidate | BlackboardItemKind::HypothesisCandidate, _) => {
            ContributionEffect::ProducedUnusedCandidate
        }
        _ => ContributionEffect::NoObservableEffect,
    }
}
