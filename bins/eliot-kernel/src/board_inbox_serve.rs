//! Operator board-inbox read serving over canonical notification state (#1780).
//!
//! Server side of the `controlboard.inbox` front-door operation: reads one
//! bounded canonical notification page through the retained store gateway
//! at the admitted session fence and answers with inbox response bytes in
//! the shared inbox envelope shape (the notify `ReadInbox` route serves
//! the same envelope over stdio, so one operator consumer decodes both
//! producers). It mints no authority: the session comes from the admitted
//! frame (a request naming any other session refuses before any Store
//! I/O), the fence is re-checked against live service authority inside,
//! generation comes from the bound session admission facts (never from a
//! deadline), and bytes travel opaquely (canonical record JSON verbatim).
//!
//! Wiring (central dispatch owner): the `controlboard.inbox` arm admits the
//! frame through the closed gateway matrix and returns
//! [`KernelFrameAction::BoardInbox`](super::KernelFrameAction::BoardInbox);
//! the front-door driver awaits
//! [`KernelComposition::execute_board_inbox_request`] with the retained
//! store gateway. This file declares the operation predicate, the execute
//! entry, and the serving core. No process is spawned here, no new
//! transport/pipe/listener is opened, and no health synthesis occurs.

use std::sync::Arc;

use eliot_contracts::StateFence;
use eliot_ipc::PeerIdentity;
use eliot_kernel_core::Notification;
use eliot_kernel_service::{
    AuthenticatedNotificationSession, NotificationMetrics, NotificationStateReadResponse,
};
use eliot_protocol::{BOARD_INBOX_OPERATION, Frame, FrameKind, MessageType, ProtocolPayload};
use eliot_store_api::{
    MAX_NOTIFICATION_PAGE_LIMIT, NamedReadRequest, NamedReadResponse, notification_read_request,
};

use super::{
    KernelComposition, KernelFrameAction, KernelServiceState, Session, TransportError, status_frame,
};
use crate::{PROTOCOL_VERSION, SERVICE_NAME};

/// Returns whether the operation string selects the board-inbox read.
///
/// The operation string is the stable wire identity itself
/// (`BOARD_INBOX_OPERATION`); there is no second dispatch vocabulary and
/// no generic JSON command routing. Callers must still prove the admitted
/// session, peer, fence, and payload shape through
/// [`KernelComposition::dispatch_board_inbox_frame`] below.
pub(crate) fn is_board_inbox_operation(operation: &str) -> bool {
    operation == BOARD_INBOX_OPERATION
}

/// Narrow read port for the closed board-inbox query.
///
/// The retained store gateway implements this port; tests substitute a
/// scripted fake. Only the fixed closed read travels here — selectors stay
/// server-determined in [`board_inbox_query`], never caller-supplied.
#[allow(async_fn_in_trait)]
pub(crate) trait BoardInboxReadPort {
    async fn read_board_inbox(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, TransportError>;
}

impl BoardInboxReadPort for Arc<super::KernelStoreGateway> {
    async fn read_board_inbox(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, TransportError> {
        self.execute_named(query)
            .await
            .map_err(|_| TransportError::SessionFenced)
    }
}

/// Builds the fixed closed board-inbox read: every scope, resolved records
/// included (closure evidence stays visible), one bounded page at the
/// contract max, under the admitted session fence.
pub(crate) fn board_inbox_query(fence: &StateFence) -> Result<NamedReadRequest, TransportError> {
    notification_read_request(
        None,
        None,
        None,
        true,
        MAX_NOTIFICATION_PAGE_LIMIT,
        None,
        fence.clone(),
    )
    .map_err(|_| TransportError::SessionFenced)
}

/// Decodes one store read payload into the canonical inbox read.
///
/// Mirrors the kernel-service read decoder field-for-field (`records`
/// array of canonical notifications with per-record fence equality, owner
/// `metrics`, payload `state_fence` equality, non-zero `revision`): a
/// missing array, an undecodable record or metrics, a foreign fence, a
/// zero revision, or an over-page record count fails closed. Page bound
/// and generation come from the admitted read facts, never from a
/// deadline.
pub(crate) fn decode_board_inbox_read(
    payload: &serde_json::Value,
    fence: &StateFence,
) -> Result<NotificationStateReadResponse, TransportError> {
    let records = payload
        .get("records")
        .and_then(serde_json::Value::as_array)
        .ok_or(TransportError::SessionFenced)?;
    let mut decoded = Vec::with_capacity(records.len());
    for value in records {
        let record: Notification =
            serde_json::from_value(value.clone()).map_err(|_| TransportError::SessionFenced)?;
        if record.state_fence != *fence {
            return Err(TransportError::SessionFenced);
        }
        decoded.push(record);
    }
    if decoded.len() > usize::from(MAX_NOTIFICATION_PAGE_LIMIT) {
        return Err(TransportError::SessionFenced);
    }
    let metrics: NotificationMetrics = serde_json::from_value(
        payload
            .get("metrics")
            .cloned()
            .ok_or(TransportError::SessionFenced)?,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let state_fence: StateFence = serde_json::from_value(
        payload
            .get("state_fence")
            .cloned()
            .ok_or(TransportError::SessionFenced)?,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    if state_fence != *fence {
        return Err(TransportError::SessionFenced);
    }
    let revision: u64 = payload
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or(TransportError::SessionFenced)?;
    if revision == 0 {
        return Err(TransportError::SessionFenced);
    }
    Ok(NotificationStateReadResponse {
        records: decoded,
        metrics,
        state_fence,
        revision,
    })
}

/// Builds the inbox response envelope for one served read.
///
/// The envelope reuses the notify `ReadInbox` response shape (`status`,
/// `service`, `protocol`, `read`) so one operator consumer decodes both
/// producers; `service`/`protocol` name this producer and are
/// correlation-only. Records travel as canonical owner JSON, verbatim.
pub(crate) fn board_inbox_envelope(read: &NotificationStateReadResponse) -> serde_json::Value {
    serde_json::json!({
        "status": "inbox",
        "service": SERVICE_NAME,
        "protocol": PROTOCOL_VERSION,
        "read": read,
    })
}

/// Serves one authenticated board-inbox read against canonical projections.
///
/// `session` is already bound from live service authority by the caller
/// (generation, Ready state, candidate/activation agreement — never
/// transport assertion alone); `fence` is the admitted session fence the
/// closed read runs under, re-checked here against the bound session's
/// authority epoch and generation. Generation comes from those bound
/// admission facts. Returns the validated canonical read; the caller
/// frames it.
pub(crate) async fn serve_board_inbox(
    store: &impl BoardInboxReadPort,
    session: &AuthenticatedNotificationSession,
    fence: &StateFence,
) -> Result<NotificationStateReadResponse, TransportError> {
    if !fence
        .authority_epoch
        .is_same_authority(session.authority_epoch())
    {
        return Err(TransportError::SessionFenced);
    }
    if fence.resource_generation.value() != session.generation() {
        return Err(TransportError::SessionFenced);
    }
    fence
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    let query = board_inbox_query(fence)?;
    let response = store.read_board_inbox(query).await?;
    if response.operation != eliot_store_api::NamedReadOperation::GetNotificationState {
        return Err(TransportError::SessionFenced);
    }
    decode_board_inbox_read(&response.payload, fence)
}

impl KernelComposition {
    /// Dispatches one board-inbox frame from an admitted session.
    ///
    /// The caller ([`KernelComposition::dispatch_frame`]) has already run
    /// the closed-gateway gates (generation poison, session/frame
    /// identity, daemon-session currency); those joins plus the
    /// Ready gate, peer authentication, and correlation joins are
    /// re-checked here so direct callers cannot bypass them. The
    /// operation string must be the exact board-inbox wire identity and
    /// the payload must be the empty board-inbox request; the canonical
    /// read itself runs in [`KernelComposition::execute_board_inbox_request`].
    pub(crate) fn dispatch_board_inbox_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if !is_board_inbox_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        if payload.as_object().is_none_or(|object| object.len() != 1) {
            return Err(TransportError::SessionFenced);
        }
        Ok(KernelFrameAction::BoardInbox {
            request_id,
            operation: operation.to_owned(),
            payload,
        })
    }

    /// Executes one admitted board-inbox request and frames its reply.
    ///
    /// Re-checks the dispatch gates (Ready, peer, correlation, operation,
    /// empty payload), binds the notification session from live service
    /// authority under the admitted peer principal, serves the closed
    /// read through the retained store gateway, and answers with the
    /// correlated inbox envelope. Any failure fences the session instead
    /// of silently dropping the read. No process is spawned here.
    pub async fn execute_board_inbox_request(
        &self,
        session: &Session,
        request_id: super::RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        if !is_board_inbox_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        if payload.as_object().is_none_or(|object| object.len() != 1) {
            return Err(TransportError::SessionFenced);
        }
        let principal = match &session.peer {
            PeerIdentity::Authenticated { user_identity, .. } => user_identity.clone(),
            PeerIdentity::Unavailable { .. } => {
                return Err(TransportError::PeerIdentityUnavailable);
            }
        };
        let fence = session.module_generation.state_fence.clone();
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        // Bind under a scoped service lock that ends before any await:
        // the bound session carries owned authority facts, and the
        // gateway path locks service internally, so holding this guard
        // across the read would self-deadlock.
        let bound = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            AuthenticatedNotificationSession::bind(&service, &principal)
                .map_err(|_| TransportError::SessionFenced)?
        };
        let read = serve_board_inbox(&gateway, &bound, &fence).await?;
        let mut reply = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            board_inbox_envelope(&read),
        )?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(reply)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use std::sync::Mutex;

    use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration};
    use eliot_kernel_service::{
        HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
        HostProcessBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
        KernelService, KernelServiceState, ProcessObservation, RestartBudget,
    };
    use eliot_platform::PlatformHandle;
    use eliot_runtime_contracts::{
        HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
        SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
    };
    use eliot_store_api::NamedReadOperation;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const EPOCH_SEQUENCE: u64 = 4;
    const GENERATION: u64 = 7;

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn live_generation() -> ResourceGeneration {
        ResourceGeneration::new(GENERATION).expect("generation")
    }

    fn test_fence() -> StateFence {
        StateFence::new(test_epoch(EPOCH_SEQUENCE), live_generation())
    }

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).expect("handle")
    }

    fn candidate_binding() -> HostKernelCandidateBinding {
        HostKernelCandidateBinding {
            installation_id: handle("installation-1"),
            host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: test_epoch(EPOCH_SEQUENCE),
            activation_id: handle("activation-1"),
            artifact_hash: handle("artifact-1"),
            config_hash: handle("config-1"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
            pipe_identity: handle("\\\\.\\pipe\\eliot-kernel-test"),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\eliot\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: SupervisionLeaseIncarnationBinding {
                supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
                supervision_lease_id: String::new(),
                scope_ref_digest: String::new(),
                installation_id: "installation-1".to_owned(),
                host_epoch: SupervisionJournalEpoch {
                    lineage_id: "host-lineage-1".to_owned(),
                    sequence: 1,
                },
                activation_id: "activation-1".to_owned(),
                activation_generation: SupervisionJournalEpoch {
                    lineage_id: "activation-lineage-1".to_owned(),
                    sequence: 1,
                },
                kernel_generation: SupervisionJournalEpoch {
                    lineage_id: "kernel-lineage-1".to_owned(),
                    sequence: 1,
                },
                watchdog_epoch: SupervisionJournalEpoch {
                    lineage_id: "watchdog-epoch-1".to_owned(),
                    sequence: 1,
                },
                observation_scope: SupervisionObservationScope {
                    targets: vec!["eliot-kernel".to_owned()],
                    sensor_profile: "eliot-runtime-live-v3".to_owned(),
                    claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                    governance_axis: "runtime-live-v3".to_owned(),
                },
                wake_policy: RegisteredActivityWakePolicy::Disabled,
                predecessor: None,
            }
            .with_derived_ids()
            .expect("incarnation"),
            restart_budget: RestartBudget::new(1, 1).expect("budget"),
            agent_bridge_admission: None,
            containment_action: None,
        }
    }

    fn ready_service() -> KernelService {
        let mut service = KernelService::new([7; 32], 2, 4).expect("service");
        let candidate = candidate_binding();
        service.reconcile(candidate.clone()).expect("reconcile");
        service.apply(KernelControlCommand::Shadow).expect("shadow");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("handoff");
        let permit = KernelActivationPermit {
            operation_id: handle("op-serve-1"),
            candidate_binding_digest: candidate.compute_digest().expect("digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle("txn-serve-1"),
            journal_sequence: 7,
            generation: live_generation(),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
                .expect("nonce"),
        };
        let activation = service
            .activate_permit(&permit, live_generation(), "c".repeat(64))
            .expect("activate");
        let ready = KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process: ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("ev-serve-1")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ev-serve-1")],
        };
        service.publish_ready(ready).expect("ready");
        assert_eq!(service.state(), KernelServiceState::Ready);
        service
    }

    fn record(
        key: &str,
        severity: eliot_kernel_core::NotificationSeverity,
        failed: bool,
        acknowledged: bool,
        resolved: bool,
        fence: &StateFence,
    ) -> eliot_kernel_core::Notification {
        use eliot_kernel_core::{Acknowledgement, DeliveryChannel, DeliveryState, ResolutionRef};
        eliot_kernel_core::Notification {
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

    fn read_payload() -> serde_json::Value {
        use eliot_kernel_core::NotificationSeverity::{Critical, Information};
        let fence = test_fence();
        let records = vec![
            record("backup-failed", Critical, true, true, false, &fence),
            record("routine-sync", Information, false, false, false, &fence),
            record("old-news", Critical, false, false, true, &fence),
        ];
        serde_json::json!({
            "records": records
                .iter()
                .map(|item| serde_json::to_value(item).expect("record encodes"))
                .collect::<Vec<_>>(),
            "metrics": {
                "unresolved_total": 2,
                "critical_unresolved": 1,
                "action_required_unresolved": 0,
                "failed_delivery_unresolved": 1,
                "acknowledged_unresolved": 1,
                "resolved_total": 1
            },
            "state_fence": serde_json::to_value(test_fence()).expect("fence encodes"),
            "revision": 2
        })
    }

    /// Scripted store: serves one fixed canonical inbox payload. Bytes are
    /// opaque to the serve path except through the decode checks; any other
    /// operation fails closed as unknown.
    struct FakeBoardStore {
        payload: Mutex<serde_json::Value>,
    }

    impl FakeBoardStore {
        fn new(payload: serde_json::Value) -> Self {
            Self {
                payload: Mutex::new(payload),
            }
        }
    }

    impl BoardInboxReadPort for FakeBoardStore {
        async fn read_board_inbox(
            &self,
            query: NamedReadRequest,
        ) -> Result<NamedReadResponse, TransportError> {
            if query.operation != NamedReadOperation::GetNotificationState {
                return Err(TransportError::SessionFenced);
            }
            Ok(NamedReadResponse {
                operation: query.operation,
                state_fence: query.state_fence.clone(),
                revision_heads: Vec::new(),
                payload: self.payload.lock().expect("fake").clone(),
            })
        }
    }

    #[test]
    fn predicate_matches_only_the_board_operation() {
        assert!(is_board_inbox_operation("controlboard.inbox"));
        assert!(is_board_inbox_operation(
            eliot_protocol::BOARD_INBOX_OPERATION
        ));
        assert!(!is_board_inbox_operation("controlboard.status"));
        assert!(!is_board_inbox_operation("local_read"));
        assert!(!is_board_inbox_operation(""));
    }

    #[test]
    fn closed_query_uses_fixed_board_selectors() {
        let query = board_inbox_query(&test_fence()).expect("closed query builds");
        assert_eq!(query.operation, NamedReadOperation::GetNotificationState);
        assert_eq!(query.state_fence, test_fence());
    }

    #[tokio::test]
    async fn serve_traces_request_to_row_bytes() {
        use eliot_contracts::canonical_json_bytes;
        let service = ready_service();
        let store = FakeBoardStore::new(read_payload());
        let read = serve_board_inbox(&store, &bound_session(&service), &test_fence())
            .await
            .expect("board serves");
        assert_eq!(read.revision, 2);
        assert_eq!(read.state_fence, test_fence());
        assert_eq!(read.records.len(), 3);
        assert_eq!(read.records[0].dedup_key, "backup-failed");
        assert!(read.records[0].acknowledgement.is_some());
        assert_eq!(read.metrics.critical_unresolved, 1);
        assert_eq!(read.metrics.failed_delivery_unresolved, 1);
        assert_eq!(read.metrics.acknowledged_unresolved, 1);
        // Served rows re-encode byte-equal to the canonical payload
        // records: the serve path drops, reorders, or alters nothing.
        let returned = canonical_json_bytes(&read.records).expect("returned encodes");
        let wire = read_payload()["records"].clone();
        let expected = canonical_json_bytes(&wire).expect("wire encodes");
        assert_eq!(returned, expected);
        assert!(!returned.is_empty());
        // The response envelope carries the rows under the shared inbox
        // shape with this producer's origin marks.
        let envelope = board_inbox_envelope(&read);
        assert_eq!(envelope["status"], "inbox");
        assert_eq!(envelope["service"], "eliot-kernel");
        assert_eq!(envelope["protocol"], "eliot.kernel.v1");
        assert_eq!(envelope["read"]["records"][0]["dedup_key"], "backup-failed");
        assert_eq!(
            envelope["read"]["records"][0]["acknowledgement"]["principal"],
            "operator-1"
        );
        assert_eq!(
            envelope["read"]["records"][0]["delivery"]["reason"],
            "toast provider failed"
        );
        assert_eq!(envelope["read"]["metrics"]["critical_unresolved"], 1);
    }

    #[tokio::test]
    async fn foreign_fence_records_and_shapes_fail_closed() {
        let service = ready_service();
        // Records from another fence fail closed even when the payload
        // fence matches.
        let mut drifted = read_payload();
        drifted["records"] = serde_json::json!([serde_json::to_value(record(
            "drifted",
            eliot_kernel_core::NotificationSeverity::Critical,
            false,
            false,
            false,
            &fence_at_generation(6),
        ))
        .expect("record encodes")]);
        let store = FakeBoardStore::new(drifted);
        assert!(matches!(
            serve_board_inbox(&store, &bound_session(&service), &test_fence()).await,
            Err(TransportError::SessionFenced)
        ));
        // Missing records array, zero revision, and over-page counts fail.
        for payload in [
            serde_json::json!({"metrics": {}}),
            serde_json::json!({
                "records": [],
                "metrics": read_payload()["metrics"].clone(),
                "state_fence": serde_json::to_value(test_fence()).expect("fence encodes"),
                "revision": 0
            }),
        ] {
            let store = FakeBoardStore::new(payload);
            assert!(matches!(
                serve_board_inbox(&store, &bound_session(&service), &test_fence()).await,
                Err(TransportError::SessionFenced)
            ));
        }
        // A drifted request fence against live authority fails closed.
        let store = FakeBoardStore::new(read_payload());
        assert!(matches!(
            serve_board_inbox(&store, &bound_session(&service), &fence_at_generation(6)).await,
            Err(TransportError::SessionFenced)
        ));
    }

    fn bound_session(service: &KernelService) -> AuthenticatedNotificationSession {
        AuthenticatedNotificationSession::bind(service, "peer-board-1").expect("session binds")
    }

    fn fence_at_generation(generation: u64) -> StateFence {
        StateFence::new(
            test_epoch(EPOCH_SEQUENCE),
            ResourceGeneration::new(generation).expect("generation"),
        )
    }
}
