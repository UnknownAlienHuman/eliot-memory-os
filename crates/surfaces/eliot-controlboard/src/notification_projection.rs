//! Canonical notification projection for the ControlBoard (issue #1780).
//!
//! Pure read-model projection over the Kernel-owned canonical record. This
//! module owns no state, authority, or delivery decisions: it only derives
//! the inbox, unresolved-critical, failed-delivery, and metrics views that
//! the board renders. Acknowledged records stay in the inbox while
//! unresolved, failed deliveries stay visible with their failure state, and
//! critical records persist until an authorized evidence-backed disposition
//! clears them at the owner.

use serde::{Deserialize, Serialize};

/// Severity projected from the canonical Kernel record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectedSeverity {
    Information,
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
    pub dedup_key: String,
    pub severity: ProjectedSeverity,
    pub delivery_failed: bool,
    pub failure_reason: Option<String>,
    pub acknowledged: bool,
    pub resolved: bool,
}

impl NotificationRow {
    /// Returns true while the owner still reports the record unresolved.
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        !self.resolved
    }
}

/// Board metrics projected from canonical notification rows.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationMetrics {
    pub total: usize,
    pub unresolved: usize,
    pub critical_unresolved: usize,
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
            dedup_key: key.to_owned(),
            severity,
            delivery_failed: failed,
            failure_reason: failed.then(|| "write failed".to_owned()),
            acknowledged,
            resolved,
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
}
