//! Read-only collective stop-coordination gate projection.
//!
//! Architecture anchors: `A10.5` (localized conflict), `A10.6` (bounded swarm
//! pipeline), and `A10.7` (reconciliation before a safe next action).
//! Implementation anchor: `I10.18` (Mailbox, Blackboard, control-message
//! acknowledgement, and anchored review).
//!
//! This child owns only the read-only coordination decision projection over
//! existing mailbox/blackboard/conflict state. It owns no
//! provider/Dreamer/canonical-write/semantic/write authority and performs no
//! mutable state, recovery, or trace mutation.

use crate::WorkState;
use eliot_types::{
    BlackboardItemId, BlackboardItemKind, BlackboardItemStatus, MailboxMessageId,
    MailboxMessageStatus, ProjectId, TaskId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StopCoordinationDecision {
    pub allow: bool,
    pub reasons: Vec<String>,
    pub unacknowledged_control_messages: Vec<MailboxMessageId>,
    pub unresolved_blackboard_items: Vec<BlackboardItemId>,
    pub unresolved_work_conflicts: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StopCoordinationGate;

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
