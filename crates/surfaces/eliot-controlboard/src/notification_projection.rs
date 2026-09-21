//! Canonical notification projection for the ControlBoard (issue #1780).
//!
//! Pure read-model projection over the Kernel-owned canonical record. This
//! module owns no state, authority, or delivery decisions: it only derives
//! the inbox, unresolved-critical, failed-delivery, and metrics views that
//! the board renders. Acknowledged records stay in the inbox while
//! unresolved, failed deliveries stay visible with their failure state, and
//! critical records persist until an authorized evidence-backed disposition
//! clears them at the owner.

use super::ControlBoardError;
use eliot_contracts::StateFence;
use eliot_kernel_core::{
    DeadlineOrReview, DeliveryChannel, DeliveryState, Notification, NotificationSeverity,
};
use serde::{Deserialize, Serialize};

/// Severity projected from the canonical Kernel record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectedSeverity {
    #[serde(rename = "INFO")]
    Information,
    ActionRequired,
    Warning,
    Critical,
}

/// Minimal board-visible shape of one canonical notification.
///
/// The board never reinterprets delivery, acknowledgement, or resolution;
/// it only projects the owner-supplied flags. Quiet hours do not filter
/// this shape: canonical creation and board visibility are never
/// suppressed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRow {
    pub notification_id: String,
    pub dedup_key: String,
    pub severity: ProjectedSeverity,
    pub subject: String,
    pub summary: String,
    pub evidence_handles: Vec<String>,
    pub affected_scope: String,
    pub owner: String,
    pub required_action: String,
    pub deadline_or_review: Option<DeadlineOrReview>,
    pub delivery_channels: Vec<DeliveryChannel>,
    pub occurrences: u64,
    pub delivery_failed: bool,
    pub failure_reason: Option<String>,
    pub acknowledged: bool,
    pub resolved: bool,
    pub revision: u64,
}

impl NotificationRow {
    /// Returns true while the owner still reports the record unresolved.
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        !self.resolved
    }

    /// Projects one owner-validated canonical record without changing its
    /// lifecycle meaning or applying popup/quiet-hours policy.
    #[must_use]
    pub fn from_notification(notification: &Notification) -> Self {
        let failure_reason = match &notification.delivery {
            DeliveryState::Failed { reason }
            | DeliveryState::Partial { reason }
            | DeliveryState::Unknown { reason } => Some(reason.clone()),
            DeliveryState::Pending | DeliveryState::Delivered => None,
        };
        Self {
            notification_id: notification.notification_id.as_str().to_owned(),
            dedup_key: notification.dedup_key.clone(),
            severity: match notification.severity {
                NotificationSeverity::Critical => ProjectedSeverity::Critical,
                NotificationSeverity::ActionRequired => ProjectedSeverity::ActionRequired,
                NotificationSeverity::Warning => ProjectedSeverity::Warning,
                NotificationSeverity::Information => ProjectedSeverity::Information,
            },
            subject: notification.subject.clone(),
            summary: notification.summary.clone(),
            evidence_handles: notification.evidence_handles.clone(),
            affected_scope: notification.affected_scope.clone(),
            owner: notification.owner.clone(),
            required_action: notification.required_action.clone(),
            deadline_or_review: notification.deadline_or_review.clone(),
            delivery_channels: notification.delivery_channels.clone(),
            occurrences: notification.occurrences,
            delivery_failed: notification.is_failed_delivery(),
            failure_reason,
            acknowledged: notification.acknowledgement.is_some(),
            resolved: !notification.is_unresolved(),
            revision: notification.revision,
        }
    }
}

/// Projects a canonical read response into the rebuildable board rows.
#[must_use]
pub fn project(records: &[Notification]) -> Vec<NotificationRow> {
    records
        .iter()
        .map(NotificationRow::from_notification)
        .collect()
}

/// Exact metrics returned by the authenticated `GetNotificationState` owner.
///
/// These counts may cover the selected scope rather than only the current
/// page, so the board preserves them instead of recomputing them from a
/// truncated row slice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalNotificationMetrics {
    pub unresolved_total: u64,
    pub critical_unresolved: u64,
    pub action_required_unresolved: u64,
    pub failed_delivery_unresolved: u64,
    pub acknowledged_unresolved: u64,
    pub resolved_total: u64,
}

/// Rebuildable ControlBoard notification projection returned by the canonical
/// read consumer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationReadProjection {
    pub rows: Vec<NotificationRow>,
    pub metrics: CanonicalNotificationMetrics,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Consumes one authenticated canonical notification read response.
///
/// The caller must provide the fence it admitted. Records are validated as
/// Kernel-owned canonical records before projection; no board row can create
/// currentness, authority, or a replacement store.
pub fn project_read_page(
    records: &[Notification],
    metrics: CanonicalNotificationMetrics,
    state_fence: StateFence,
    expected_fence: &StateFence,
    revision: u64,
) -> Result<NotificationReadProjection, ControlBoardError> {
    if revision == 0 || state_fence != *expected_fence {
        return Err(ControlBoardError::FenceMismatch);
    }
    state_fence
        .validate()
        .map_err(|error| ControlBoardError::Provider(error.to_string()))?;
    for record in records {
        record
            .validate()
            .map_err(|error| ControlBoardError::Provider(error.to_string()))?;
        if record.state_fence != state_fence {
            return Err(ControlBoardError::FenceMismatch);
        }
    }
    Ok(NotificationReadProjection {
        rows: project(records),
        metrics,
        state_fence,
        revision,
    })
}

/// Board metrics projected from canonical notification rows.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationMetrics {
    pub total: usize,
    pub unresolved: usize,
    pub critical_unresolved: usize,
    pub action_required_unresolved: usize,
    pub failed_delivery: usize,
    pub acknowledged_unresolved: usize,
}

/// Returns every unresolved row. Acknowledged and failed-delivery rows stay
/// in the inbox until the owner reports an authorized disposition.
#[must_use]
pub fn inbox<'a>(rows: &'a [NotificationRow]) -> Vec<&'a NotificationRow> {
    rows.iter().filter(|row| row.is_unresolved()).collect()
}

/// Returns unresolved critical rows. Critical records persist here until
/// the authorized evidence-backed disposition arrives.
#[must_use]
pub fn unresolved_critical<'a>(rows: &'a [NotificationRow]) -> Vec<&'a NotificationRow> {
    rows.iter()
        .filter(|row| row.is_unresolved() && row.severity == ProjectedSeverity::Critical)
        .collect()
}

/// Returns unresolved rows whose latest delivery failed, with the failure
/// state preserved for board visibility.
#[must_use]
pub fn failed_delivery<'a>(rows: &'a [NotificationRow]) -> Vec<&'a NotificationRow> {
    rows.iter()
        .filter(|row| row.is_unresolved() && row.delivery_failed)
        .collect()
}

/// Projects board metrics from canonical rows.
#[must_use]
pub fn metrics(rows: &[NotificationRow]) -> NotificationMetrics {
    let mut output = NotificationMetrics {
        total: rows.len(),
        ..NotificationMetrics::default()
    };
    for row in rows {
        if row.is_unresolved() {
            output.unresolved += 1;
            if row.severity == ProjectedSeverity::Critical {
                output.critical_unresolved += 1;
            }
            if row.severity == ProjectedSeverity::ActionRequired {
                output.action_required_unresolved += 1;
            }
            if row.delivery_failed {
                output.failed_delivery += 1;
            }
            if row.acknowledged {
                output.acknowledged_unresolved += 1;
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        key: &str,
        severity: ProjectedSeverity,
        failed: bool,
        acknowledged: bool,
        resolved: bool,
    ) -> NotificationRow {
        NotificationRow {
            notification_id: format!("notification-{key}"),
            dedup_key: key.to_owned(),
            severity,
            subject: "subject".to_owned(),
            summary: "summary".to_owned(),
            evidence_handles: vec!["evidence-1".to_owned()],
            affected_scope: "scope-1".to_owned(),
            owner: "owner-1".to_owned(),
            required_action: "review".to_owned(),
            deadline_or_review: None,
            delivery_channels: vec![DeliveryChannel::ControlBoard],
            occurrences: 1,
            delivery_failed: failed,
            failure_reason: failed.then(|| "write failed".to_owned()),
            acknowledged,
            resolved,
            revision: 1,
        }
    }

    #[test]
    fn ack_keeps_unresolved_visible_and_failed_delivery_persists() {
        let rows = vec![
            row(
                "backup-failed",
                ProjectedSeverity::Critical,
                true,
                true,
                false,
            ),
            row(
                "routine-sync",
                ProjectedSeverity::Information,
                false,
                false,
                false,
            ),
            row("old-news", ProjectedSeverity::Warning, false, false, true),
        ];
        assert_eq!(inbox(&rows).len(), 2);
        assert_eq!(unresolved_critical(&rows).len(), 1);
        assert_eq!(failed_delivery(&rows).len(), 1);
        assert_eq!(
            failed_delivery(&rows)[0].failure_reason.as_deref(),
            Some("write failed")
        );
        let projected = metrics(&rows);
        assert_eq!(
            projected,
            NotificationMetrics {
                total: 3,
                unresolved: 2,
                critical_unresolved: 1,
                action_required_unresolved: 0,
                failed_delivery: 1,
                acknowledged_unresolved: 1,
            }
        );
    }

    #[test]
    fn resolved_critical_leaves_every_projection() {
        let rows = vec![row(
            "disk-critical",
            ProjectedSeverity::Critical,
            true,
            false,
            true,
        )];
        assert!(inbox(&rows).is_empty());
        assert!(unresolved_critical(&rows).is_empty());
        assert!(failed_delivery(&rows).is_empty());
        let projected = metrics(&rows);
        assert_eq!(projected.total, 1);
        assert_eq!(projected.unresolved, 0);
    }

    #[test]
    fn canonical_unknown_delivery_and_ack_remain_visible_and_unresolved() {
        let notification = Notification {
            notification_id: serde_json::from_value(serde_json::json!("notification-1")).unwrap(),
            severity: NotificationSeverity::Critical,
            subject: "subject".to_owned(),
            summary: "summary".to_owned(),
            evidence_handles: vec!["evidence-1".to_owned()],
            affected_scope: "scope-1".to_owned(),
            owner: "owner-1".to_owned(),
            required_action: "review".to_owned(),
            deadline_or_review: None,
            dedup_key: "dedup-1".to_owned(),
            delivery_channels: vec![DeliveryChannel::ControlBoard],
            occurrences: 2,
            delivery: DeliveryState::Unknown {
                reason: "delivery receipt is unavailable".to_owned(),
            },
            acknowledgement: Some(eliot_kernel_core::Acknowledgement {
                principal: "operator-1".to_owned(),
                sequence: 1,
            }),
            resolution_ref: None,
            state_fence: serde_json::from_value(serde_json::json!({
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 1
                },
                "resource_generation": 1,
                "task_revision": 1,
                "policy_revision": 1,
                "integration_revision": 1
            }))
            .unwrap(),
            revision: 2,
        };

        let rows = project(std::slice::from_ref(&notification));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].acknowledged);
        assert!(rows[0].is_unresolved());
        assert!(rows[0].delivery_failed);
        assert_eq!(
            rows[0].failure_reason.as_deref(),
            Some("delivery receipt is unavailable")
        );
        assert_eq!(inbox(&rows).len(), 1);
        assert_eq!(unresolved_critical(&rows).len(), 1);
        assert_eq!(failed_delivery(&rows).len(), 1);
        assert_eq!(metrics(&rows).acknowledged_unresolved, 1);

        let fence = rows
            .first()
            .and_then(|_| {
                serde_json::from_value::<StateFence>(serde_json::json!({
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": 1
                    },
                    "resource_generation": 1,
                    "task_revision": 1,
                    "policy_revision": 1,
                    "integration_revision": 1
                }))
                .ok()
            })
            .expect("test fence");
        let read = project_read_page(
            &[notification],
            CanonicalNotificationMetrics {
                unresolved_total: 1,
                critical_unresolved: 1,
                action_required_unresolved: 0,
                failed_delivery_unresolved: 1,
                acknowledged_unresolved: 1,
                resolved_total: 0,
            },
            fence.clone(),
            &fence,
            2,
        )
        .expect("canonical read projects");
        assert_eq!(read.rows.len(), 1);
        assert_eq!(read.metrics.acknowledged_unresolved, 1);
        assert_eq!(read.revision, 2);
    }
}
