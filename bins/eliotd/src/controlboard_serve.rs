//! Dedicated daemon `ControlBoard` serve path (#1780).
//!
//! Per-request server side of the daemon board: builds on the already-noted
//! canonical notification snapshot (see
//! [`crate::notification_board_attach`]) and serves one exact-revision
//! [`ControlBoard`](eliot_controlboard::ControlBoard) view per observed
//! Kernel-admitted request. The caller side is the local-read poll step in
//! `daemon_runtime::run_local_read_poll`: every claimed
//! [`HostRequestEnvelope`](eliot_protocol::HostRequestEnvelope) carrying the
//! live owner session claim gets its board inbox served with that envelope's
//! observed fields, and the served counts publish to diagnostics.
//!
//! Data flow (nothing invented, nothing guessed):
//!
//! ```text
//! KernelNotificationClient (Beauvoir-owned kernel composition hook,
//!   installer path from B2 `resolve_notify_binary`) → eliot-notify stdin
//! → NotifyCore deliver → kernel persist (fenced, idempotent)
//! → daemon startup GetNotificationState read (notification_board_attach)
//! → DaemonComposition.notification_snapshot
//! → local-read poll claims envelope (observed session/connection/request
//!   fields, Kernel admission receipts, transport fence)
//! → DaemonComposition::serve_board_for_envelope (this module's server)
//! → diagnostics evidence per served request
//! ```
//!
//! Serve rules:
//!
//! - every request field is observed: the session id is the envelope's
//!   session claim verified equal to the held Kernel-issued owner session
//!   (never a literal, never a default); connection, credential binding,
//!   challenge, request id, generation correlation, and the fence pin all
//!   come from the same envelope. Authority comes only from the admitted
//!   owner facts pinned to the live snapshot fence/revision by the access
//!   resolver; the envelope fields are per-request correlation the seal
//!   re-checks, so no two requests share a binding.
//! - an envelope with no session claim, or a claim for another principal,
//!   is explicitly skipped ([`BoardServeDispatch::SkippedForeignSession`]):
//!   not our principal to serve, pair handling continues untouched. This is
//!   the privacy posture, not a gap.
//! - no owner session → typed [`ControlBoardError::PlanGap`], never an
//!   empty fabrication. Malformed held facts stay fail-closed through the
//!   admission error, exactly like [`DaemonComposition::controlboard`].
//! - foreign-fence noted records fail closed through the existing
//!   `CanonicalState::validate` at view time; a drifted envelope fence
//!   fails closed as `StaleView` through the request pin.
//! - pure in-memory reads over one immutable board snapshot: no I/O, no new
//!   thread, no new handshake, no stored client, no new scheduler — the
//!   existing local-read poller is the only driver.

use eliot_contracts::StateFence;
use eliot_controlboard::{
    ControlBoard, ControlBoardError, NotificationInbox, PortError, ReadRequest, RequiredProvider,
    ViewRevision,
};
use eliot_protocol::HostRequestEnvelope;

use super::DaemonError;
use super::controlboard_adapters::AdmittedSessionAccess;
use super::daemon_kernel_client::OwnerSessionFacts;
use super::notification_board_attach::BoardInboxEvidence;

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

/// Per-request board serve dispatch outcome.
///
/// `Served` carries the pinned inbox for a request whose observed session
/// claim is the live owner session. `SkippedForeignSession` is the explicit
/// privacy posture for an envelope with no session claim or a claim for
/// another principal: not ours to serve, pair handling continues untouched.
/// A skip is never an error and never an empty fabrication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoardServeDispatch {
    Served(ServedBoardInbox),
    SkippedForeignSession,
}

/// Builds the serve read request for one observed envelope.
///
/// Every field is the envelope's own: `session_id` is the caller-verified
/// live owner session (verified by [`serve_board_for_envelope`], never a
/// literal); `connection_id` is the Kernel-created transport identity;
/// `credential_binding` is the Kernel-produced transport admission receipt
/// digest; `challenge` is the exact envelope digest (unique per request);
/// `request_id` is the envelope's exact request identity; `generation`
/// carries the envelope's Kernel-owned absolute deadline as per-request
/// correlation echoed by the resolver (not authority — a zero deadline
/// fails closed here); the expected fence pins the transport-admission
/// fence so a drifted snapshot fails closed as `StaleView` at view time.
pub(crate) fn board_request_for_envelope(
    session_id: &str,
    envelope: &HostRequestEnvelope,
) -> Result<ReadRequest, ControlBoardError> {
    let mut request = ReadRequest::new(
        session_id,
        envelope.connection_id.clone(),
        envelope.peer_admission_receipt_sha256.clone(),
        envelope.envelope_sha256.clone(),
        envelope.identity.request_id.as_str(),
        envelope.identity.deadline_unix_ms,
    )?;
    request.expected_fence = Some(envelope.state_fence.clone());
    Ok(request)
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

/// Serves one live inbox for one observed envelope through a board built by
/// the caller-provided factory.
///
/// Thin composition seam used by
/// [`DaemonComposition::serve_board_for_envelope`]: admits the live owner
/// session from the held facts (unadmitted when absent), verifies the
/// envelope's session claim against it (foreign or absent claim skips
/// explicitly), builds one board, and serves the fence-pinned inbox from
/// the envelope's observed fields. Kept as a free function so the
/// verify/build/serve sequencing is unit-covered without a full composition
/// fixture.
pub(crate) fn serve_board_for_envelope(
    owner_session: Option<&OwnerSessionFacts>,
    build_board: impl FnOnce() -> Result<ControlBoard, DaemonError>,
    envelope: &HostRequestEnvelope,
) -> Result<BoardServeDispatch, ControlboardServeError> {
    let facts = owner_session.ok_or(ControlboardServeError::Board(ControlBoardError::PlanGap(
        RequiredProvider::AccessResolver,
    )))?;
    let binding = AdmittedSessionAccess::from_kernel_owner_facts(facts)
        .map_err(ControlboardServeError::Admission)?;
    if envelope.identity.session_id.as_deref() != Some(binding.session_id()) {
        return Ok(BoardServeDispatch::SkippedForeignSession);
    }
    let request = board_request_for_envelope(binding.session_id(), envelope)
        .map_err(ControlboardServeError::Board)?;
    let mut board = build_board().map_err(ControlboardServeError::Composition)?;
    serve_board_inbox(&mut board, &request).map(BoardServeDispatch::Served)
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

    use eliot_contracts::RequestId;
    use eliot_protocol::{HostRequestEnvelope, HostRequestIdentity, HostRequestKind};

    fn envelope(session: Option<&str>, fence: &StateFence) -> HostRequestEnvelope {
        HostRequestEnvelope {
            wire_id: "wire-7".to_owned(),
            wire_version: 1,
            kind: HostRequestKind::Invocation,
            connection_id: "kernel-conn-7".to_owned(),
            identity: HostRequestIdentity {
                request_id: RequestId::new("req-7").expect("request id"),
                idempotency_key: "idem-7".to_owned(),
                cancellation_id: "cancel-7".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 1_700_000_007,
                capability: "eliot.query".to_owned(),
                session_id: session.map(str::to_owned),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "schema-1".to_owned(),
                payload_sha256: "p".repeat(64),
            },
            state_fence: fence.clone(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "c".repeat(64),
            activation_binding: None,
            envelope_sha256: "e".repeat(64),
        }
    }

    fn board_with(records: Vec<Notification>) -> ControlBoard {
        controlboard_over_snapshot(
            snapshot(),
            &SharedOperatorReplay::new(),
            vec![admitted_owner_session()],
            records,
        )
    }

    fn serve(
        owner: Option<&OwnerSessionFacts>,
        records: Vec<Notification>,
        envelope: &HostRequestEnvelope,
    ) -> Result<BoardServeDispatch, ControlboardServeError> {
        serve_board_for_envelope(owner, || Ok(board_with(records)), envelope)
    }

    #[test]
    fn serve_dispatch_serves_matching_session_claim_with_observed_fields() {
        use NotificationSeverity::{Critical, Information};
        let fence = fence_at(7);
        let dispatch = serve(
            Some(&owner_facts("sid=S-1-5-18;session=0")),
            vec![
                record("backup-failed", Critical, true, true, false, &fence),
                record("routine-sync", Information, false, false, false, &fence),
                record("old-news", Critical, false, false, true, &fence),
            ],
            &envelope(Some("0"), &fence),
        )
        .expect("matching claim serves");
        let served = match dispatch {
            BoardServeDispatch::Served(served) => served,
            BoardServeDispatch::SkippedForeignSession => panic!("owner claim must serve"),
        };
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
    fn serve_dispatch_skips_foreign_and_absent_session_claims_before_any_build() {
        let fence = fence_at(7);
        // The factory must never run for a skip: a build error here would
        // surface as Err, so Ok(Skipped) proves the short-circuit.
        let never_build = || {
            Err(super::super::DaemonError::Lifecycle(
                "board must not build for a foreign claim".to_owned(),
            ))
        };
        assert!(matches!(
            serve_board_for_envelope(
                Some(&owner_facts("sid=S-1-5-18;session=0")),
                never_build,
                &envelope(None, &fence),
            ),
            Ok(BoardServeDispatch::SkippedForeignSession)
        ));
        let never_build = || {
            Err(super::super::DaemonError::Lifecycle(
                "board must not build for a foreign claim".to_owned(),
            ))
        };
        assert!(matches!(
            serve_board_for_envelope(
                Some(&owner_facts("sid=S-1-5-18;session=0")),
                never_build,
                &envelope(Some("9"), &fence),
            ),
            Ok(BoardServeDispatch::SkippedForeignSession)
        ));
    }

    #[test]
    fn serve_dispatch_fails_closed_on_drift_records_and_admission() {
        use NotificationSeverity::Critical;
        let fence = fence_at(7);
        // Drifted envelope fence against the live snapshot: the resolver
        // denies the pin before any read.
        assert!(matches!(
            serve(
                Some(&owner_facts("sid=S-1-5-18;session=0")),
                vec![record(
                    "routine-sync",
                    Critical,
                    false,
                    false,
                    false,
                    &fence,
                )],
                &envelope(Some("0"), &fence_at(6)),
            ),
            Err(ControlboardServeError::Board(
                ControlBoardError::Unauthorized
            ))
        ));
        // Foreign-fence noted records fail closed at view time even when the
        // envelope pin matches the snapshot.
        assert!(matches!(
            serve(
                Some(&owner_facts("sid=S-1-5-18;session=0")),
                vec![record(
                    "drifted",
                    Critical,
                    false,
                    false,
                    false,
                    &fence_at(6),
                )],
                &envelope(Some("0"), &fence),
            ),
            Err(ControlboardServeError::Board(_))
        ));
        // Malformed held facts fail closed as admission, never a default.
        assert!(matches!(
            serve(
                Some(&owner_facts("local-user")),
                Vec::new(),
                &envelope(Some("0"), &fence),
            ),
            Err(ControlboardServeError::Admission(_))
        ));
        // No held owner session: typed gap, never an empty fabrication.
        assert!(matches!(
            serve(None, Vec::new(), &envelope(Some("0"), &fence)),
            Err(ControlboardServeError::Board(ControlBoardError::PlanGap(
                RequiredProvider::AccessResolver
            )))
        ));
    }

    #[test]
    fn board_request_uses_only_observed_envelope_fields() {
        let fence = fence_at(7);
        let request = board_request_for_envelope("0", &envelope(Some("0"), &fence))
            .expect("observed request builds");
        assert_eq!(request.session_id, "0");
        assert_eq!(request.connection_id, "kernel-conn-7");
        assert_eq!(request.credential_binding, "c".repeat(64));
        assert_eq!(request.challenge, "e".repeat(64));
        assert_eq!(request.request_id, "req-7");
        assert_eq!(request.generation, 1_700_000_007);
        assert_eq!(request.expected_fence, Some(fence));
        // A zero deadline is not a generation: fails closed, never defaulted.
        let mut timeless = envelope(Some("0"), &fence_at(7));
        timeless.identity.deadline_unix_ms = 0;
        assert!(matches!(
            board_request_for_envelope("0", &timeless),
            Err(ControlBoardError::InvalidField("generation"))
        ));
        // A blank admission receipt is not a credential binding.
        let mut bare = envelope(Some("0"), &fence_at(7));
        bare.peer_admission_receipt_sha256 = String::new();
        assert!(matches!(
            board_request_for_envelope("0", &bare),
            Err(ControlBoardError::InvalidField(_))
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
