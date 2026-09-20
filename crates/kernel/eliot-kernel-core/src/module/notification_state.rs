//! Canonical persistent notification state (issue #1780, go23 slice).
//!
//! Kernel-owned decision state for one durable [`Notification`] record.
//! The Kernel is the single writer: repeat failures keyed by `dedup_key`
//! update exactly one record, delivery observations never resolve the
//! record, acknowledgement only suppresses toast repeats, and resolution
//! requires an authorized evidence-backed disposition. Critical records
//! therefore persist until that disposition is recorded.
//!
//! Quiet hours are explicitly out of scope here: they constrain only popup
//! selection in `bins/eliot-notify` and never suppress canonical creation
//! or board visibility. This module performs no I/O, clock reads, or popup
//! decisions beyond the pure [`Notification::should_popup`] predicate used
//! by the delivery selector.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Severity carried on the canonical record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationSeverity {
    Information,
    Warning,
    Critical,
}

/// Delivery observation for the latest attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum DeliveryState {
    Pending,
    Delivered,
    Failed { reason: String },
}

/// Toast-suppression acknowledgement. It never resolves the record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub principal: String,
    pub sequence: u64,
}

/// Authorized evidence-backed disposition. The only terminal state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub authorized_by: String,
    pub evidence_refs: Vec<String>,
    pub disposition: String,
}

/// Canonical persistent notification record owned by the Kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    pub dedup_key: String,
    pub severity: NotificationSeverity,
    pub summary: String,
    pub occurrences: u64,
    pub delivery: DeliveryState,
    pub acknowledgement: Option<Acknowledgement>,
    pub resolution: Option<Resolution>,
}

impl Notification {
    /// Returns true while the record still needs operator attention.
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        self.resolution.is_none()
    }

    /// Returns true when the latest delivery attempt failed.
    #[must_use]
    pub const fn is_failed_delivery(&self) -> bool {
        matches!(self.delivery, DeliveryState::Failed { .. })
    }

    /// Pure popup predicate shared with the delivery selector.
    ///
    /// Acknowledgement stops toast repeats and resolution stops all popups,
    /// but neither hides the record from the ControlBoard inbox. Quiet hours
    /// suppress only non-critical popups; critical records still pop up.
    #[must_use]
    pub fn should_popup(&self, quiet_hours_active: bool) -> bool {
        if self.resolution.is_some() || self.acknowledgement.is_some() {
            return false;
        }
        if quiet_hours_active && self.severity != NotificationSeverity::Critical {
            return false;
        }
        true
    }
}

/// Fail-closed errors for the notification lifecycle.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NotificationError {
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("unknown notification")]
    UnknownNotification,
    #[error("resolution requires evidence")]
    ResolutionRequiresEvidence,
    #[error("resolution requires authorization")]
    ResolutionRequiresAuthorization,
    #[error("record is already resolved")]
    AlreadyResolved,
}

fn text(value: &str, field: &'static str) -> Result<(), NotificationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NotificationError::InvalidField(field));
    }
    Ok(())
}

fn validate_dedup_key(value: &str) -> Result<(), NotificationError> {
    text(value, "dedup_key")?;
    if value.len() > 256 {
        return Err(NotificationError::InvalidField("dedup_key"));
    }
    Ok(())
}

fn validate_evidence_refs(values: &[String]) -> Result<(), NotificationError> {
    if values.is_empty() {
        return Err(NotificationError::ResolutionRequiresEvidence);
    }
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, "evidence_ref")?;
        if !seen.insert(value) {
            return Err(NotificationError::InvalidField("evidence_ref"));
        }
    }
    Ok(())
}

/// Canonical store keyed by `dedup_key`. One key owns exactly one record.
#[derive(Clone, Debug, Default)]
pub struct NotificationStore {
    records: BTreeMap<String, Notification>,
    sequence: u64,
}

impl NotificationStore {
    /// Creates an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            sequence: 0,
        }
    }

    /// Returns the number of canonical records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true when no canonical record exists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Reads one canonical record by its dedup key.
    #[must_use]
    pub fn get(&self, dedup_key: &str) -> Option<&Notification> {
        self.records.get(dedup_key)
    }

    /// Iterates over canonical records in key order.
    pub fn iter(&self) -> impl Iterator<Item = &Notification> {
        self.records.values()
    }

    /// Records one failure. Repeat failures with the same `dedup_key`
    /// update the single canonical record and increment `occurrences`.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::InvalidField`] for a malformed key,
    /// summary, or reason, and [`NotificationError::AlreadyResolved`] when
    /// the record already carries an authorized disposition.
    pub fn report_failure(
        &mut self,
        dedup_key: &str,
        severity: NotificationSeverity,
        summary: &str,
        reason: &str,
    ) -> Result<&Notification, NotificationError> {
        validate_dedup_key(dedup_key)?;
        text(summary, "summary")?;
        text(reason, "reason")?;
        if let Some(existing) = self.records.get(dedup_key) {
            if existing.resolution.is_some() {
                return Err(NotificationError::AlreadyResolved);
            }
        }
        self.sequence = self.sequence.saturating_add(1);
        let occurrences = self
            .records
            .get(dedup_key)
            .map_or(1, |existing| existing.occurrences.saturating_add(1));
        let acknowledgement = self
            .records
            .get(dedup_key)
            .and_then(|existing| existing.acknowledgement.clone());
        let record = Notification {
            dedup_key: dedup_key.to_owned(),
            severity,
            summary: summary.to_owned(),
            occurrences,
            delivery: DeliveryState::Failed {
                reason: reason.to_owned(),
            },
            acknowledgement,
            resolution: None,
        };
        self.records.insert(dedup_key.to_owned(), record);
        self.records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }

    /// Records one successful delivery without resolving the record.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::UnknownNotification`] for an absent key
    /// and [`NotificationError::AlreadyResolved`] for a resolved record.
    pub fn record_delivery(&mut self, dedup_key: &str) -> Result<&Notification, NotificationError> {
        let existing = self
            .records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)?;
        if existing.resolution.is_some() {
            return Err(NotificationError::AlreadyResolved);
        }
        let mut updated = existing.clone();
        updated.delivery = DeliveryState::Delivered;
        self.records.insert(dedup_key.to_owned(), updated);
        self.records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }

    /// Acknowledges one record. This stops toast repeats but leaves the
    /// record unresolved (and critical records visible in the inbox).
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::UnknownNotification`] for an absent key
    /// and [`NotificationError::InvalidField`] for a malformed principal.
    pub fn acknowledge(
        &mut self,
        dedup_key: &str,
        principal: &str,
    ) -> Result<&Notification, NotificationError> {
        text(principal, "principal")?;
        let existing = self
            .records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)?;
        if existing.resolution.is_some() {
            return Err(NotificationError::AlreadyResolved);
        }
        self.sequence = self.sequence.saturating_add(1);
        let sequence = self.sequence;
        let mut updated = existing.clone();
        updated.acknowledgement = Some(Acknowledgement {
            principal: principal.to_owned(),
            sequence,
        });
        self.records.insert(dedup_key.to_owned(), updated);
        self.records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }

    /// Records an authorized evidence-backed disposition. This is the only
    /// transition that clears `is_unresolved`, including for critical
    /// records.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationError::ResolutionRequiresEvidence`] for empty
    /// or malformed evidence, [`NotificationError::ResolutionRequiresAuthorization`]
    /// when `authorized` is false or the authorizer is malformed, and
    /// [`NotificationError::AlreadyResolved`] for a resolved record.
    pub fn resolve(
        &mut self,
        dedup_key: &str,
        authorized_by: &str,
        evidence_refs: Vec<String>,
        disposition: &str,
        authorized: bool,
    ) -> Result<&Notification, NotificationError> {
        text(authorized_by, "authorized_by")?;
        text(disposition, "disposition")?;
        validate_evidence_refs(&evidence_refs)?;
        if !authorized {
            return Err(NotificationError::ResolutionRequiresAuthorization);
        }
        let existing = self
            .records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)?;
        if existing.resolution.is_some() {
            return Err(NotificationError::AlreadyResolved);
        }
        let mut updated = existing.clone();
        updated.resolution = Some(Resolution {
            authorized_by: authorized_by.to_owned(),
            evidence_refs,
            disposition: disposition.to_owned(),
        });
        self.records.insert(dedup_key.to_owned(), updated);
        self.records
            .get(dedup_key)
            .ok_or(NotificationError::UnknownNotification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_failure_updates_one_record_via_dedup_key() {
        let mut store = NotificationStore::new();
        store
            .report_failure(
                "disk-full",
                NotificationSeverity::Warning,
                "disk full",
                "write failed",
            )
            .expect("first failure creates the record");
        store
            .report_failure(
                "disk-full",
                NotificationSeverity::Warning,
                "disk still full",
                "write failed again",
            )
            .expect("repeat failure updates the record");
        assert_eq!(store.len(), 1);
        let record = store.get("disk-full").expect("record exists");
        assert_eq!(record.occurrences, 2);
        assert_eq!(record.summary, "disk still full");
        assert!(record.is_failed_delivery());
        assert!(record.is_unresolved());
    }

    #[test]
    fn ack_stops_toast_repeats_but_leaves_record_unresolved() {
        let mut store = NotificationStore::new();
        store
            .report_failure(
                "backup-failed",
                NotificationSeverity::Critical,
                "backup failed",
                "snapshot error",
            )
            .expect("create");
        let before = store.get("backup-failed").expect("record exists").clone();
        assert!(before.should_popup(false));
        store
            .acknowledge("backup-failed", "operator-1")
            .expect("ack records");
        let after = store.get("backup-failed").expect("record exists");
        assert!(!after.should_popup(false));
        assert!(!after.should_popup(true));
        assert!(after.is_unresolved());
        assert_eq!(after.severity, NotificationSeverity::Critical);
        assert!(after.is_failed_delivery());
    }

    #[test]
    fn critical_persists_until_authorized_evidence_backed_disposition() {
        let mut store = NotificationStore::new();
        store
            .report_failure(
                "kernel-fence",
                NotificationSeverity::Critical,
                "fence lost",
                "epoch mismatch",
            )
            .expect("create");
        assert!(store
            .resolve("kernel-fence", "owner", Vec::new(), "fixed", true)
            .is_err());
        assert!(store
            .resolve(
                "kernel-fence",
                "owner",
                vec!["evidence-1".to_owned()],
                "fixed",
                false
            )
            .is_err());
        assert!(store.get("kernel-fence").expect("record").is_unresolved());
        store
            .resolve(
                "kernel-fence",
                "owner",
                vec!["evidence-1".to_owned()],
                "rotated and verified",
                true,
            )
            .expect("authorized evidence-backed resolution");
        let resolved = store.get("kernel-fence").expect("record");
        assert!(!resolved.is_unresolved());
        assert!(!resolved.should_popup(false));
    }

    #[test]
    fn quiet_hours_suppress_only_noncritical_popups() {
        let mut store = NotificationStore::new();
        store
            .report_failure(
                "routine-sync",
                NotificationSeverity::Information,
                "sync slow",
                "retryable",
            )
            .expect("create info");
        store
            .report_failure(
                "disk-critical",
                NotificationSeverity::Critical,
                "disk critical",
                "write failed",
            )
            .expect("create critical");
        let info = store.get("routine-sync").expect("info");
        let critical = store.get("disk-critical").expect("critical");
        assert!(info.should_popup(false));
        assert!(!info.should_popup(true));
        assert!(critical.should_popup(false));
        assert!(critical.should_popup(true));
    }
}
