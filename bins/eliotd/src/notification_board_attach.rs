//! Canonical notification reads for the daemon board (#1780).
//!
//! Attach-site wiring mirroring the owner-session pattern in
//! `daemon_runtime::run`: the single place holding both the concrete
//! [`DaemonKernelClient`] and the [`DaemonComposition`] fetches the complete
//! canonical set through the retained [`KernelContextReadClient`] and notes
//! verified records into the composition. The read stays outside the
//! composition lock, and the observed fence is checked again before
//! attachment. No new thread, no new handshake, no stored client.
//!
//! Cold or unbound state stays a typed unavailable gap: transport
//! `Unknown`/`Unavailable`, fence mismatch, decode failure, or a missing
//! fence all report [`NotificationBoardAttach::Unavailable`] with a reason.
//! An unavailable attach never reports success-empty and never fails daemon
//! readiness; the caller degrades to the empty inbox exactly like the
//! skill-tool-source attach path.

use std::sync::Arc;

use eliot_contracts::StateFence;
use eliot_governor::KernelGenerationSnapshotProvider;
use eliot_kernel_core::Notification;
use eliot_store_api::{
    CanonicalReadClient, MAX_NOTIFICATION_PAGE_LIMIT, NOTIFY_PAGE_METRICS, NOTIFY_PAGE_RECORDS,
    NOTIFY_PAGE_REVISION, NOTIFY_PAGE_STATE_FENCE, NamedReadRequest, StoreError,
    notification_read_request,
};

use super::DaemonComposition;
use super::daemon_kernel_client::DaemonKernelClient;
use super::kernel_context_read_client::KernelContextReadClient;

/// Exact metrics returned by the authenticated `GetNotificationState` owner.
///
/// Migrated verbatim from the removed `eliot-controlboard` package (#1213):
/// same fields, same `deny_unknown_fields` wire shape. These counts may cover
/// the selected scope rather than only the current page, so the attach
/// preserves them instead of recomputing them from a truncated row slice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalNotificationMetrics {
    pub unresolved_total: u64,
    pub critical_unresolved: u64,
    pub action_required_unresolved: u64,
    pub failed_delivery_unresolved: u64,
    pub acknowledged_unresolved: u64,
    pub resolved_total: u64,
}

/// Typed outcome of the startup notification attach.
pub enum NotificationBoardAttach {
    /// Verified canonical records at the admitted fence, ready to note.
    Ready(NotificationBoardSnapshot),
    /// Cold/unbound/failed read: explicit gap, never success-empty.
    Unavailable { reason: String },
}

/// Complete verified canonical inbox and the fence it was read against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationBoardSnapshot {
    /// Every canonical record returned across the owner's cursor pages.
    pub records: Vec<Notification>,
    /// Fence echoed consistently by the owner and observed before/after fetch.
    pub state_fence: StateFence,
}

/// One authenticated canonical page and its owner-supplied read metadata.
struct NotificationBoardPage {
    records: Vec<Notification>,
    metrics: CanonicalNotificationMetrics,
    revision: u64,
}

/// Builds the closed board read: every scope, resolved records included
/// (closure evidence stays visible), one bounded page at the contract max.
pub fn build_closed_board_read(state_fence: StateFence) -> Result<NamedReadRequest, StoreError> {
    build_closed_board_page_read(state_fence, None)
}

/// Builds one bounded page at the exact admitted fence and optional opaque
/// dedup-key continuation cursor.
fn build_closed_board_page_read(
    state_fence: StateFence,
    cursor: Option<String>,
) -> Result<NamedReadRequest, StoreError> {
    notification_read_request(
        None,
        None,
        None,
        true,
        MAX_NOTIFICATION_PAGE_LIMIT,
        cursor,
        state_fence,
    )
}

/// Decodes backend payload records with per-record fence checks.
///
/// Mirrors the service decoder shape (`records` array of canonical
/// notifications) using only daemon-available types: no `KernelService` or
/// `CanonicalStore` import. A missing array, an undecodable record, or a
/// record from another fence fails closed; an empty array is a valid empty
/// page only when the backend said so.
pub fn decode_board_records(
    payload: &serde_json::Value,
    fence: &StateFence,
) -> Result<Vec<Notification>, StoreError> {
    let records = payload
        .get(NOTIFY_PAGE_RECORDS)
        .and_then(serde_json::Value::as_array)
        .ok_or(StoreError::InvalidField {
            field: "notification.records",
            reason: "read payload must carry records",
        })?;
    let mut decoded = Vec::with_capacity(records.len());
    for value in records {
        let record: Notification =
            serde_json::from_value(value.clone()).map_err(|_| StoreError::InvalidField {
                field: "notification.records",
                reason: "record payload is not a canonical notification",
            })?;
        record.validate().map_err(|_| StoreError::InvalidField {
            field: "notification.records",
            reason: "record payload fails canonical notification validation",
        })?;
        if record.state_fence != *fence {
            return Err(StoreError::FenceMismatch);
        }
        decoded.push(record);
    }
    Ok(decoded)
}

/// Decodes one page and its metadata without promoting an empty or partial
/// response to a complete inbox.
fn decode_board_page(
    payload: &serde_json::Value,
    expected_fence: &StateFence,
) -> Result<NotificationBoardPage, StoreError> {
    let field = |name: &'static str| {
        payload.get(name).cloned().ok_or(StoreError::InvalidField {
            field: name,
            reason: "canonical notification read metadata is missing",
        })
    };
    let state_fence: StateFence =
        serde_json::from_value(field(NOTIFY_PAGE_STATE_FENCE)?).map_err(|_| {
            StoreError::InvalidField {
                field: NOTIFY_PAGE_STATE_FENCE,
                reason: "canonical notification read fence is invalid",
            }
        })?;
    if state_fence != *expected_fence {
        return Err(StoreError::FenceMismatch);
    }
    let revision = payload
        .get(NOTIFY_PAGE_REVISION)
        .and_then(serde_json::Value::as_u64)
        .ok_or(StoreError::InvalidField {
            field: NOTIFY_PAGE_REVISION,
            reason: "canonical notification read revision is invalid",
        })?;
    let metrics: CanonicalNotificationMetrics = serde_json::from_value(field(NOTIFY_PAGE_METRICS)?)
        .map_err(|_| StoreError::InvalidField {
            field: NOTIFY_PAGE_METRICS,
            reason: "canonical notification read metrics are invalid",
        })?;
    let records = decode_board_records(payload, expected_fence)?;
    Ok(NotificationBoardPage {
        records,
        metrics,
        revision,
    })
}

/// Fetches every bounded canonical page through the retained read client.
///
/// The capability gate inside `execute_named` admits only the closed
/// `GetNotificationState` selector set; operation/fence echo is enforced by
/// the shared response check. The backend's opaque cursor is the last returned
/// dedup key. Pages must advance strictly and retain identical revision and
/// fence. The owner metrics can be partial on a full intermediate page; the
/// terminal page scans the complete selected set, so its metrics are reconciled
/// with all collected records before the inbox is accepted.
pub async fn fetch_board_records(
    reads: &KernelContextReadClient,
    fence: StateFence,
) -> Result<Vec<Notification>, StoreError> {
    let page_limit = usize::from(MAX_NOTIFICATION_PAGE_LIMIT);
    let mut cursor: Option<String> = None;
    let mut previous_key: Option<String> = None;
    let mut expected_revision: Option<u64> = None;
    let mut records = Vec::new();

    loop {
        let request = build_closed_board_page_read(fence.clone(), cursor.clone())?;
        let response = reads.execute_named(request).await?;
        let page = decode_board_page(&response.payload, &fence)?;
        if page.records.len() > page_limit {
            return Err(StoreError::InvalidField {
                field: "notification.records",
                reason: "canonical notification page exceeds its requested limit",
            });
        }
        match expected_revision {
            Some(revision) if revision != page.revision => {
                return Err(StoreError::InvalidField {
                    field: "notification.page",
                    reason: "canonical notification revision changed during pagination",
                });
            }
            Some(_) => {}
            None => expected_revision = Some(page.revision),
        }

        let page_len = page.records.len();
        for record in &page.records {
            if previous_key
                .as_deref()
                .is_some_and(|previous| record.dedup_key.as_str() <= previous)
            {
                return Err(StoreError::InvalidField {
                    field: "notification.cursor",
                    reason: "canonical notification page did not advance its dedup-key cursor",
                });
            }
            previous_key = Some(record.dedup_key.clone());
        }
        records.extend(page.records);
        if page_len < page_limit {
            validate_complete_notification_metrics(&records, page.metrics)?;
            return Ok(records);
        }

        let next_cursor = previous_key.clone().ok_or(StoreError::InvalidField {
            field: "notification.cursor",
            reason: "full canonical notification page has no continuation key",
        })?;
        if cursor
            .as_deref()
            .is_some_and(|previous| next_cursor.as_str() <= previous)
        {
            return Err(StoreError::InvalidField {
                field: "notification.cursor",
                reason: "canonical notification continuation cursor did not advance",
            });
        }
        cursor = Some(next_cursor);
    }
}

/// Verifies that the terminal page's full-scope owner metrics reconcile with
/// every fetched record, including resolved records.
fn validate_complete_notification_metrics(
    records: &[Notification],
    owner_metrics: CanonicalNotificationMetrics,
) -> Result<(), StoreError> {
    let count = |predicate: fn(&&Notification) -> bool| {
        checked_notification_count(records.iter().filter(predicate).count())
    };
    let observed = CanonicalNotificationMetrics {
        unresolved_total: count(|record| record.is_unresolved())?,
        critical_unresolved: count(|record| {
            record.is_unresolved()
                && record.severity == eliot_kernel_core::NotificationSeverity::Critical
        })?,
        action_required_unresolved: count(|record| {
            record.is_unresolved()
                && record.severity == eliot_kernel_core::NotificationSeverity::ActionRequired
        })?,
        failed_delivery_unresolved: count(|record| {
            record.is_unresolved() && record.is_failed_delivery()
        })?,
        acknowledged_unresolved: count(|record| {
            record.is_unresolved() && record.acknowledgement.is_some()
        })?,
        resolved_total: count(|record| !record.is_unresolved())?,
    };
    let owner_total = owner_metrics
        .unresolved_total
        .checked_add(owner_metrics.resolved_total)
        .ok_or(StoreError::InvalidField {
            field: "notification.metrics",
            reason: "canonical notification metric total overflows",
        })?;
    let record_total = u64::try_from(records.len()).map_err(|_| StoreError::InvalidField {
        field: "notification.records",
        reason: "canonical notification record count exceeds metric range",
    })?;
    if owner_total != record_total || owner_metrics != observed {
        return Err(StoreError::InvalidField {
            field: "notification.metrics",
            reason: "terminal canonical notification metrics do not match the complete record set",
        });
    }
    Ok(())
}

/// Converts a complete fetched-row count to the owner's metric width.
fn checked_notification_count(count: usize) -> Result<u64, StoreError> {
    u64::try_from(count).map_err(|_| StoreError::InvalidField {
        field: "notification.metrics",
        reason: "canonical notification record count exceeds metric range",
    })
}

/// Fetches a fresh canonical inbox at the daemon's admitted fence.
///
/// The caller performs this before acquiring the composition lock, then notes
/// the completed snapshot only after every page and metadata check succeeds.
pub async fn fetch_notification_snapshot(
    kernel: &Arc<DaemonKernelClient>,
) -> Result<NotificationBoardSnapshot, String> {
    let fence = kernel.snapshot().state_fence();
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let records = fetch_board_records(&reads, fence.clone())
        .await
        .map_err(|error| format!("notification attach read failed: {error}"))?;
    if kernel.snapshot().state_fence() != fence {
        return Err("Kernel state fence rotated during canonical notification read".to_owned());
    }
    Ok(NotificationBoardSnapshot {
        records,
        state_fence: fence,
    })
}

/// Attaches canonical notification records into the board composition.
///
/// Runs at the daemon startup attach site where the concrete client and the
/// composition meet. Blocking follows the established
/// `DaemonKernelClient::blocking` template (Windows-only; elsewhere the
/// attach reports unavailable). Any gap — unconnected client, fence drift,
/// decode failure — returns [`NotificationBoardAttach::Unavailable`] so the
/// caller degrades to the empty inbox without failing readiness.
pub fn attach_notification_snapshot(
    kernel: &Arc<DaemonKernelClient>,
    composition: &mut DaemonComposition,
) -> NotificationBoardAttach {
    let outcome = block_on_fetch(kernel);
    match outcome {
        Ok(snapshot) => {
            let kernel_fence = kernel.snapshot().state_fence();
            let composition_fence = composition.kernel_snapshot().state_fence();
            if snapshot.state_fence != kernel_fence || snapshot.state_fence != composition_fence {
                return NotificationBoardAttach::Unavailable {
                    reason: "Kernel or composition state fence changed before notification attach"
                        .to_owned(),
                };
            }
            composition.note_notification_snapshot(snapshot.records.clone());
            NotificationBoardAttach::Ready(snapshot)
        }
        Err(reason) => NotificationBoardAttach::Unavailable { reason },
    }
}

#[cfg(windows)]
fn block_on_fetch(kernel: &Arc<DaemonKernelClient>) -> Result<NotificationBoardSnapshot, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("notification attach runtime unavailable: {error}"))?;
    runtime.block_on(fetch_notification_snapshot(kernel))
}

#[cfg(not(windows))]
fn block_on_fetch(_kernel: &Arc<DaemonKernelClient>) -> Result<NotificationBoardSnapshot, String> {
    Err("notification attach is not admitted off Windows".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(7).expect("generation"),
        )
    }

    fn record_json(fence_value: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "notification_id": "notification-1",
            "severity": "CRITICAL",
            "subject": "subject",
            "summary": "summary",
            "evidence_handles": ["evidence-1"],
            "affected_scope": "scope-1",
            "owner": "owner-1",
            "required_action": "review",
            "deadline_or_review": null,
            "dedup_key": "disk-critical",
            "delivery_channels": ["CONTROL_BOARD"],
            "occurrences": 1,
            "delivery": {"kind": "PENDING"},
            "acknowledgement": null,
            "resolution_ref": null,
            "state_fence": fence_value,
            "revision": 1
        })
    }

    fn live_fence_value() -> serde_json::Value {
        serde_json::to_value(fence()).expect("fence serializes")
    }

    #[test]
    fn closed_board_read_uses_bounded_page_and_exact_fence() {
        let fence = fence();
        let request = build_closed_board_read(fence.clone()).expect("closed read builds");
        assert_eq!(
            request.operation,
            eliot_store_api::NamedReadOperation::GetNotificationState
        );
        assert_eq!(request.state_fence, fence);
        // The read passes the daemon capability gate it will face at runtime.
        KernelContextReadClient::check_board_read_for_test(&request).expect("gate admits");
    }

    #[test]
    fn decode_accepts_same_fence_records_and_rejects_foreign_fence() {
        let fence = fence();
        let payload = serde_json::json!({"records": [record_json(&live_fence_value())]});
        let decoded = decode_board_records(&payload, &fence).expect("same fence decodes");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].dedup_key, "disk-critical");

        let foreign = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(6).expect("generation"),
        );
        let payload = serde_json::json!({"records": [record_json(&live_fence_value())]});
        assert!(matches!(
            decode_board_records(&payload, &foreign),
            Err(StoreError::FenceMismatch)
        ));
        let missing = serde_json::json!({"metrics": {}});
        assert!(decode_board_records(&missing, &fence).is_err());
    }
}
