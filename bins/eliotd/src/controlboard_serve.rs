//! Dedicated daemon `ControlBoard` serve path (#1780).
//!
//! Server side of the daemon board: builds on the already-noted canonical
//! notification snapshot (see [`crate::notification_board_attach`]) and serves
//! one exact-revision [`ControlBoard`](eliot_controlboard::ControlBoard) view
//! for the single live Kernel-issued owner session threaded by the daemon
//! runtime. The caller side lives in `daemon_runtime::run` at the same attach
//! site as the owner-session facts and the notification snapshot attach: it
//! serves the inbox once the composition is live and publishes the served
//! counts to diagnostics.
//!
//! Data flow (nothing invented, nothing guessed):
//!
//! ```text
//! KernelNotificationClient (Beauvoir-owned kernel composition hook,
//!   installer path from B2) → eliot-notify stdin route
//! → NotifyCore deliver → kernel persist (fenced, idempotent)
//! → daemon startup GetNotificationState read (notification_board_attach)
//! → DaemonComposition.notification_snapshot
//! → DaemonComposition::serve_controlboard_inbox (this module's server)
//! → daemon_runtime caller → diagnostics evidence
//! ```
//!
//! Serve rules:
//!
//! - the read request carries the live session id parsed from the held
//!   Kernel-issued owner facts (never a literal) with inert diagnostic
//!   transport labels. Authority comes only from the admitted owner facts
//!   pinned to the live snapshot fence/revision by the access resolver.
//! - no owner session → typed [`ControlBoardError::PlanGap`], never an
//!   empty fabrication. Malformed held facts stay fail-closed through the
//!   admission error, exactly like [`DaemonComposition::controlboard`].
//! - foreign-fence noted records fail closed through the existing
//!   `CanonicalState::validate` at view time.
//! - pure in-memory reads over one immutable board snapshot: no I/O, no new
//!   thread, no new handshake, no stored client, no run-loop change.

use eliot_contracts::StateFence;
use eliot_controlboard::{
    ControlBoard, ControlBoardError, NotificationInbox, PortError, ReadRequest, RequiredProvider,
    ViewRevision,
};

use super::DaemonError;
use super::controlboard_adapters::AdmittedSessionAccess;
use super::daemon_kernel_client::OwnerSessionFacts;
use super::notification_board_attach::BoardInboxEvidence;

/// Inert transport labels for the daemon serve request.
///
/// These carry no authority: the access resolver echoes them into the binding
/// and `seal_for` re-checks the echo, so they only identify the serve call in
/// diagnostics. The session id is the one live owner-issued value.
const SERVE_CONNECTION_ID: &str = "eliotd-controlboard-serve";
const SERVE_CREDENTIAL_BINDING: &str = "eliotd-controlboard-serve";
const SERVE_CHALLENGE: &str = "eliotd-controlboard-serve";
const SERVE_REQUEST_ID: &str = "eliotd-controlboard-serve";
const SERVE_GENERATION: u64 = 1;

/// One served board inbox pinned to its exact revision and fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServedBoardInbox {
    pub revision: ViewRevision,
    pub fence: StateFence,
    pub inbox: NotificationInbox,
}

/// Typed serve outcome: composition failure, admission failure, board gap.
///
/// Every arm preserves its owner type: a not-ready Governor stays a
/// [`DaemonError`], malformed owner facts stay a [`PortError`], and view
/// refusals stay a [`ControlBoardError`]. Nothing is flattened into an
/// untyped string before the runtime caller renders it into diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum ControlboardServeError {
    #[error("controlboard serve composition: {0}")]
    Composition(DaemonError),
    #[error("controlboard serve admission: {0}")]
    Admission(PortError),
    #[error("controlboard serve board: {0}")]
    Board(ControlBoardError),
}

/// Mints the serve read request for the single live owner session.
///
/// Parses the session id from the already-validated Kernel-issued owner facts
/// through the one admission constructor (full validation: shape, binding
/// digest, lifetime window). Malformed facts fail closed as [`PortError`],
/// never as a defaulted session.
pub(crate) fn owner_serve_request(
    facts: &OwnerSessionFacts,
) -> Result<ReadRequest, ControlboardServeError> {
    let binding = AdmittedSessionAccess::from_kernel_owner_facts(facts)
        .map_err(ControlboardServeError::Admission)?;
    ReadRequest::new(
        binding.session_id(),
        SERVE_CONNECTION_ID,
        SERVE_CREDENTIAL_BINDING,
        SERVE_CHALLENGE,
        SERVE_REQUEST_ID,
        SERVE_GENERATION,
    )
    .map_err(ControlboardServeError::Board)
}

/// Serves one exact-revision inbox section from an already-built board.
///
/// The view enforces the admitted-session binding, the live fence/revision
/// pins, and the noted-records fence through the existing board checks; every
/// refusal propagates as its typed [`ControlBoardError`]. The inbox section
/// itself is never filtered here: projection semantics stay in
/// `eliot-controlboard` (`filter_view` projects every owner record).
pub(crate) fn serve_board_inbox(
    board: &mut ControlBoard,
    request: &ReadRequest,
) -> Result<ServedBoardInbox, ControlboardServeError> {
    let view = board.view(request).map_err(ControlboardServeError::Board)?;
    Ok(ServedBoardInbox {
        revision: view.revision,
        fence: view.fence,
        inbox: view.notifications,
    })
}

/// Projects diagnostics evidence from a served inbox section.
///
/// Same no-filter counting as
/// [`board_inbox_evidence`](super::notification_board_attach::board_inbox_evidence):
/// unresolved rows stay counted (acknowledged included), critical and
/// failed-delivery rows stay counted, resolved rows count separately.
#[must_use]
pub fn served_inbox_evidence(served: &ServedBoardInbox) -> BoardInboxEvidence {
    let metrics = served.inbox.metrics;
    BoardInboxEvidence {
        total: metrics.total,
        unresolved: metrics.unresolved,
        critical_unresolved: metrics.critical_unresolved,
        failed_delivery_unresolved: metrics.failed_delivery,
        acknowledged_unresolved: metrics.acknowledged_unresolved,
        resolved: metrics.total.saturating_sub(metrics.unresolved),
    }
}

/// Serves one live inbox through a board built by the caller-provided
/// factory.
///
/// Thin composition seam used by [`DaemonComposition::serve_controlboard_inbox`]:
/// admits the serve request from the held owner facts (unadmitted when
/// absent), builds one board, and serves the pinned inbox. Kept as a free
/// function so the request/build/serve sequencing is unit-covered without a
/// full composition fixture.
pub(crate) fn serve_live_inbox(
    owner_session: Option<&OwnerSessionFacts>,
    build_board: impl FnOnce() -> Result<ControlBoard, DaemonError>,
) -> Result<ServedBoardInbox, ControlboardServeError> {
    let facts = owner_session.ok_or(ControlboardServeError::Board(ControlBoardError::PlanGap(
        RequiredProvider::AccessResolver,
    )))?;
    let request = owner_serve_request(facts)?;
    let mut board = build_board().map_err(ControlboardServeError::Composition)?;
    serve_board_inbox(&mut board, &request)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use super::super::controlboard_adapters::{SharedOperatorReplay, controlboard_over_snapshot};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_controlboard::{ControlBoardError, RequiredProvider};
    use eliot_governor::{ControlBoardGovernorSnapshot, ControlBoardOwnerBinding};
    use eliot_kernel_core::{
        Acknowledgement, DeliveryChannel, DeliveryState, Notification, NotificationSeverity,
        ResolutionRef,
    };
    use eliot_platform::PlatformHandle;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence_at(generation: u64) -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(generation).expect("generation"),
        )
    }

    fn snapshot() -> ControlBoardGovernorSnapshot {
        ControlBoardGovernorSnapshot {
            fence: fence_at(7),
            read_revision: 7,
            coordination_sequence: 3,
            g11_coordination: ControlBoardOwnerBinding {
                binding_id: "governor-owner:coordination".to_owned(),
                binding_digest: "c".repeat(64),
                receipt_ref: "a".repeat(64),
            },
            i12_report: ControlBoardOwnerBinding {
                binding_id: "governor-owner:observation".to_owned(),
                binding_digest: "d".repeat(64),
                receipt_ref: "b".repeat(64),
            },
        }
    }

    fn admitted_owner_session() -> super::super::controlboard_adapters::AdmittedSessionAccess {
        AdmittedSessionAccess::from_kernel_owner_facts(&OwnerSessionFacts {
            session_binding: "sid=S-1-5-18;session=0".to_owned(),
            kernel_principal: "local-service".to_owned(),
            connection_id: "eliotd:test-instance:1:550e8400-e29b-41d4-a716-446655440000:1"
                .to_owned(),
            launch_nonce: "eliotd:0123456789abcdef0123456789abcdef".to_owned(),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
        })
        .expect("owner admission from Kernel facts")
    }

    fn record(
        key: &str,
        severity: NotificationSeverity,
        failed: bool,
        acknowledged: bool,
        resolved: bool,
        fence: &StateFence,
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
            acknowledgement: acknowledged.then(|| Acknowledgement {
                principal: "operator-1".to_owned(),
                sequence: 1,
            }),
            resolution_ref: resolved.then(|| ResolutionRef {
                receipt_id: "receipt-1".to_owned(),
                authority_id: "authority-1".to_owned(),
                authority_owner: "owner-1".to_owned(),
                evidence_handles: vec!["evidence-1".to_owned()],
                disposition: "fixed".to_owned(),
            }),
            state_fence: fence.clone(),
            revision: 1,
        }
    }

    fn owner_facts(binding: &str) -> OwnerSessionFacts {
        OwnerSessionFacts {
            session_binding: binding.to_owned(),
            kernel_principal: "local-service".to_owned(),
            connection_id: "eliotd:test-instance:1:550e8400-e29b-41d4-a716-446655440000:1"
                .to_owned(),
            launch_nonce: "eliotd:0123456789abcdef0123456789abcdef".to_owned(),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
        }
    }

    #[test]
    fn serve_returns_pinned_inbox_with_board_evidence() {
        use NotificationSeverity::{Critical, Information};
        let fence = fence_at(7);
        let mut board = controlboard_over_snapshot(
            snapshot(),
            &SharedOperatorReplay::new(),
            vec![admitted_owner_session()],
            vec![
                record("backup-failed", Critical, true, true, false, &fence),
                record("routine-sync", Information, false, false, false, &fence),
                record("old-news", Critical, false, false, true, &fence),
            ],
        );
        let request = owner_serve_request(&owner_facts("sid=S-1-5-18;session=0"))
            .expect("serve request for live session");
        assert_eq!(request.session_id, "0");
        let served = serve_board_inbox(&mut board, &request).expect("served inbox");
        assert_eq!(served.revision.get(), 7);
        assert_eq!(served.fence, fence);
        assert_eq!(served.inbox.rows.len(), 3);
        assert_eq!(
            served_inbox_evidence(&served),
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
            served_inbox_evidence(&ServedBoardInbox {
                revision: served.revision,
                fence: served.fence.clone(),
                inbox: NotificationInbox {
                    rows: Vec::new(),
                    metrics: eliot_controlboard::NotificationMetrics::default(),
                },
            }),
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

    #[test]
    fn serve_without_admission_is_a_typed_gap_not_an_empty_inbox() {
        let mut board = controlboard_over_snapshot(
            snapshot(),
            &SharedOperatorReplay::new(),
            Vec::new(),
            Vec::new(),
        );
        let request = owner_serve_request(&owner_facts("sid=S-1-5-18;session=0"))
            .expect("request mints without board admission");
        assert!(matches!(
            serve_board_inbox(&mut board, &request),
            Err(ControlboardServeError::Board(ControlBoardError::PlanGap(
                RequiredProvider::AccessResolver
            )))
        ));
        assert!(matches!(
            serve_live_inbox(None, || Ok(board)),
            Err(ControlboardServeError::Board(ControlBoardError::PlanGap(
                RequiredProvider::AccessResolver
            )))
        ));
    }

    #[test]
    fn serve_rejects_foreign_fence_records_and_malformed_facts() {
        use NotificationSeverity::Critical;
        let mut board = controlboard_over_snapshot(
            snapshot(),
            &SharedOperatorReplay::new(),
            vec![admitted_owner_session()],
            vec![record(
                "drifted",
                Critical,
                false,
                false,
                false,
                &fence_at(6),
            )],
        );
        let request = owner_serve_request(&owner_facts("sid=S-1-5-18;session=0"))
            .expect("serve request for live session");
        assert!(matches!(
            serve_board_inbox(&mut board, &request),
            Err(ControlboardServeError::Board(_))
        ));
        assert!(matches!(
            owner_serve_request(&owner_facts("local-user")),
            Err(ControlboardServeError::Admission(_))
        ));
    }

    #[test]
    fn serve_live_inbox_sequences_request_build_and_serve() {
        use NotificationSeverity::Information;
        let fence = fence_at(7);
        let served = serve_live_inbox(Some(&owner_facts("sid=S-1-5-18;session=0")), || {
            Ok(controlboard_over_snapshot(
                snapshot(),
                &SharedOperatorReplay::new(),
                vec![admitted_owner_session()],
                vec![record(
                    "routine-sync",
                    Information,
                    false,
                    false,
                    false,
                    &fence,
                )],
            ))
        })
        .expect("live inbox serves");
        assert_eq!(served.revision.get(), 7);
        assert_eq!(served.inbox.rows.len(), 1);
        let composition_failure =
            serve_live_inbox(Some(&owner_facts("sid=S-1-5-18;session=0")), || {
                Err(super::super::DaemonError::Lifecycle(
                    "governor not ready".to_owned(),
                ))
            });
        assert!(matches!(
            composition_failure,
            Err(ControlboardServeError::Composition(_))
        ));
    }

    #[test]
    fn serve_error_renders_typed_gaps_for_diagnostics() {
        let gap = ControlboardServeError::Board(ControlBoardError::PlanGap(
            RequiredProvider::AccessResolver,
        ));
        assert!(gap.to_string().contains("AccessResolver"));
        let admission = ControlboardServeError::Admission(PortError::Unavailable);
        assert!(admission.to_string().contains("unavailable"));
    }
}
