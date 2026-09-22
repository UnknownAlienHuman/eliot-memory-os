//! Startup attach of canonical notification records into the daemon board (#1780).
//!
//! Attach-site wiring mirroring the owner-session pattern in
//! `daemon_runtime::run`: the single place holding both the concrete
//! [`DaemonKernelClient`] and the [`DaemonComposition`] fetches one bounded
//! canonical page through the retained [`KernelContextReadClient`] and notes
//! the verified records into the composition. No new thread, no new
//! handshake, no stored client.
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
    CanonicalReadClient, MAX_NOTIFICATION_PAGE_LIMIT, NOTIFY_PAGE_RECORDS, NamedReadRequest,
    StoreError, notification_read_request,
};

use super::DaemonComposition;
use super::daemon_kernel_client::DaemonKernelClient;
use super::kernel_context_read_client::KernelContextReadClient;

/// Typed outcome of the startup notification attach.
pub enum NotificationBoardAttach {
    /// Verified canonical records at the admitted fence, ready to note.
    Ready(Vec<Notification>),
    /// Cold/unbound/failed read: explicit gap, never success-empty.
    Unavailable { reason: String },
}

/// Startup board-inbox evidence published to diagnostics after attach.
///
/// Pure projection over noted records using the canonical board helpers:
/// unresolved rows stay visible (acknowledged included), critical and
/// failed-delivery rows stay counted, resolved rows count separately.
/// Emitted once at startup so the populated path is observable in the
/// production diagnostics sink without inventing a dispatch loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoardInboxEvidence {
    pub total: usize,
    pub unresolved: usize,
    pub critical_unresolved: usize,
    pub failed_delivery_unresolved: usize,
    pub acknowledged_unresolved: usize,
    pub resolved: usize,
}

/// Projects inbox evidence for diagnostics from noted canonical records.
#[must_use]
pub fn board_inbox_evidence(records: &[Notification]) -> BoardInboxEvidence {
    let rows = eliot_controlboard::project(records);
    let metrics = eliot_controlboard::metrics(&rows);
    let resolved = metrics.total.saturating_sub(metrics.unresolved);
    BoardInboxEvidence {
        total: metrics.total,
        unresolved: metrics.unresolved,
        critical_unresolved: metrics.critical_unresolved,
        failed_delivery_unresolved: metrics.failed_delivery,
        acknowledged_unresolved: metrics.acknowledged_unresolved,
        resolved,
    }
}

/// Builds the closed board read: every scope, resolved records included
/// (closure evidence stays visible), one bounded page at the contract max.
pub fn build_closed_board_read(state_fence: StateFence) -> Result<NamedReadRequest, StoreError> {
    notification_read_request(
        None,
        None,
        None,
        true,
        MAX_NOTIFICATION_PAGE_LIMIT,
        None,
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
        if record.state_fence != *fence {
            return Err(StoreError::FenceMismatch);
        }
        decoded.push(record);
    }
    Ok(decoded)
}

/// Fetches one bounded canonical page through the retained read client.
///
/// The capability gate inside `execute_named` admits only the closed
/// `GetNotificationState` selector set; operation/fence echo is enforced by
/// the shared response check. Transport failures surface as
/// [`StoreError::Unavailable`], never as success-empty.
pub async fn fetch_board_records(
    reads: &KernelContextReadClient,
    fence: StateFence,
) -> Result<Vec<Notification>, StoreError> {
    let request = build_closed_board_read(fence.clone())?;
    let response = reads.execute_named(request).await?;
    decode_board_records(&response.payload, &fence)
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
    let fence = kernel.snapshot().state_fence();
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let outcome = block_on_fetch(&reads, fence);
    match outcome {
        Ok(records) => {
            composition.note_notification_snapshot(records.clone());
            NotificationBoardAttach::Ready(records)
        }
        Err(reason) => NotificationBoardAttach::Unavailable { reason },
    }
}

#[cfg(windows)]
fn block_on_fetch(
    reads: &KernelContextReadClient,
    fence: StateFence,
) -> Result<Vec<Notification>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("notification attach runtime unavailable: {error}"))?;
    runtime
        .block_on(fetch_board_records(reads, fence))
        .map_err(|error| format!("notification attach read failed: {error}"))
}

#[cfg(not(windows))]
fn block_on_fetch(
    _reads: &KernelContextReadClient,
    _fence: StateFence,
) -> Result<Vec<Notification>, String> {
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

    #[test]
    fn board_inbox_evidence_keeps_ack_critical_failed_and_resolved() {
        use eliot_kernel_core::{
            DeliveryChannel, DeliveryState, Notification, NotificationSeverity,
        };
        use eliot_platform::PlatformHandle;

        fn record(
            key: &str,
            severity: NotificationSeverity,
            failed: bool,
            acknowledged: bool,
            resolved: bool,
        ) -> Notification {
            Notification {
                notification_id: PlatformHandle::new(format!("notification-{key}"))
                    .expect("notification id"),
                severity,
                subject: "subject".to_owned(),
                summary: "summary".to_owned(),
                evidence_handles: vec!["evidence-1".to_owned()],
                affected_scope: "scope-1".to_owned(),
                owner: "owner-1".to_owned(),
                required_action: "review".to_owned(),
                deadline_or_review: None,
                dedup_key: key.to_owned(),
                delivery_channels: vec![DeliveryChannel::ControlBoard],
                occurrences: 1,
                delivery: if failed {
                    DeliveryState::Failed {
                        reason: "toast provider failed".to_owned(),
                    }
                } else {
                    DeliveryState::Delivered
                },
                acknowledgement: acknowledged.then(|| eliot_kernel_core::Acknowledgement {
                    principal: "operator-1".to_owned(),
                    sequence: 1,
                }),
                resolution_ref: resolved.then(|| eliot_kernel_core::ResolutionRef {
                    receipt_id: "receipt-1".to_owned(),
                    authority_id: "authority-1".to_owned(),
                    authority_owner: "owner-1".to_owned(),
                    evidence_handles: vec!["evidence-1".to_owned()],
                    disposition: "fixed".to_owned(),
                }),
                state_fence: fence(),
                revision: 1,
            }
        }

        use NotificationSeverity::{Critical, Information};
        let evidence = board_inbox_evidence(&[
            record("backup-failed", Critical, true, true, false),
            record("routine-sync", Information, false, false, false),
            record("old-news", Critical, false, false, true),
        ]);
        assert_eq!(
            evidence,
            BoardInboxEvidence {
                total: 3,
                unresolved: 2,
                critical_unresolved: 1,
                failed_delivery_unresolved: 1,
                acknowledged_unresolved: 1,
                resolved: 1,
            }
        );
        assert_eq!(
            board_inbox_evidence(&[]),
            BoardInboxEvidence {
                total: 0,
                unresolved: 0,
                critical_unresolved: 0,
                failed_delivery_unresolved: 0,
                acknowledged_unresolved: 0,
                resolved: 0,
            }
        );
    }
}
