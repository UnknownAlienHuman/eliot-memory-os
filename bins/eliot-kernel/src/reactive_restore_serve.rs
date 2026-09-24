//! Reactive restore serving over canonical Store projections.
//!
//! This module orchestrates the existing [`AuthenticatedReactiveSession`]
//! binding plus the existing `handle_reactive_ledger_read` /
//! `handle_resource_snapshot_read` projections into one
//! [`ReactiveRestoreReply`](eliot_protocol::ReactiveRestoreReply).
//! It mints no authority: the session comes from the admitted envelope (a
//! query naming any other session refuses before any Store I/O), the fence
//! is re-checked against live service authority inside the projections,
//! and bytes travel opaquely (ledger JSON verbatim, snapshot bytes decoded
//! by the Store contract helpers).
//!
//! Wiring (central dispatch owner, requested — never taken here): the
//! `agent_host_request_reactive_restore` arm admits the envelope, decodes
//! the query, and calls [`serve_reactive_restore`] with the retained store
//! gateway client, the live service, and the envelope-admitted session.
//! This file declares no `mod`, op constant, or dispatch arm.

use eliot_kernel_service::{
    AuthenticatedReactiveSession, KernelService, ReactiveLedgerReadRequest, ReactiveServiceError,
    ResourceSnapshotReadRequest, handle_reactive_ledger_read, handle_resource_snapshot_read,
};
use eliot_protocol::{ReactiveRestoreQuery, ReactiveRestoreReply, RestoredSnapshot};
use eliot_store_api::{CanonicalStoreClient, RequestMetadata};

/// Serve one authenticated restore query against canonical projections.
///
/// `admitted_session` is the session from the admitted envelope (never the
/// query's copy): a query naming any other session refuses before any Store
/// I/O. `context` is the route-bound request metadata the arm derives from
/// the same admitted envelope. Ledger absence projects explicit absence;
/// unserved URIs are omitted (never fabricated); any Store failure aborts
/// with the runner-bound state untouched upstream.
pub async fn serve_reactive_restore(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedReactiveSession,
    admitted_session: &str,
    context: &RequestMetadata,
    query: &ReactiveRestoreQuery,
) -> Result<ReactiveRestoreReply, ReactiveServiceError> {
    query
        .validate()
        .map_err(|_| ReactiveServiceError::InvalidField {
            field: "restore.query",
            reason: "query shape invalid",
        })?;
    if query.session_id != admitted_session {
        return Err(ReactiveServiceError::InvalidField {
            field: "restore.session_id",
            reason: "query session does not match the admitted envelope session",
        });
    }
    let ledger = handle_reactive_ledger_read(
        client,
        service,
        session,
        &ReactiveLedgerReadRequest {
            context: context.clone(),
            state_fence: query.state_fence.clone(),
            session_id: query.session_id.clone(),
        },
    )
    .await?;
    let mut snapshots = Vec::with_capacity(query.uris.len());
    let mut revision = ledger.revision;
    for uri in &query.uris {
        let read = handle_resource_snapshot_read(
            client,
            service,
            session,
            &ResourceSnapshotReadRequest {
                context: context.clone(),
                state_fence: query.state_fence.clone(),
                uri: uri.clone(),
            },
        )
        .await?;
        revision = revision.max(read.revision);
        if let Some(content) = read.content {
            snapshots.push(RestoredSnapshot {
                uri: uri.clone(),
                content,
            });
        }
    }
    Ok(ReactiveRestoreReply {
        session_id: query.session_id.clone(),
        state_fence: query.state_fence.clone(),
        ledger_json: ledger.ledger_json,
        snapshots,
        revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        AuthorityEpoch, ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_kernel_service::{
        HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
        HostProcessBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
        KernelServiceState, ProcessObservation, RestartBudget,
    };
    use eliot_runtime_contracts::{
        HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
        SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
    };
    use eliot_store_api::StoreError;
    use eliot_store_api::{
        NamedReadOperation, NamedReadRequest, NamedReadResponse, OrderingHead, RevisionHead,
        StoreHealth,
    };
    use std::num::NonZeroU64;
    use std::sync::Mutex;

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

    fn handle(value: &str) -> eliot_platform::PlatformHandle {
        eliot_platform::PlatformHandle::new(value).expect("handle")
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

    fn context() -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("request-serve-1").expect("request"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-serve").expect("product"),
            source_id: SourceId::new("owner-serve").expect("source"),
            state_fence: test_fence(),
            clock: ClockReading::default(),
        }
    }

    fn live_session(service: &KernelService) -> AuthenticatedReactiveSession {
        AuthenticatedReactiveSession::bind(service, "peer-serve-1").expect("session binds")
    }

    /// Scripted store: serves fixed projection payloads. Bytes are opaque to
    /// the serve path (verbatim pass-through is exactly its contract); the
    /// ledger JSON below is the minimal valid shape the bridge decoder
    /// accepts, produced here as data, never as authority.
    struct FakeStore {
        ledger_payload: Mutex<serde_json::Value>,
        snapshot_payload: Mutex<serde_json::Value>,
    }

    impl FakeStore {
        fn new(ledger_payload: serde_json::Value, snapshot_payload: serde_json::Value) -> Self {
            Self {
                ledger_payload: Mutex::new(ledger_payload),
                snapshot_payload: Mutex::new(snapshot_payload),
            }
        }
    }

    impl CanonicalStoreClient for FakeStore {
        async fn apply_prepared(
            &self,
            _ctx: &RequestMetadata,
            _transition: eliot_store_api::PreparedTransition,
            _expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
            _expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
        ) -> Result<eliot_store_api::WriteReceipt, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn receipt(
            &self,
            _operation_id: OperationId,
        ) -> Result<Option<eliot_store_api::WriteReceipt>, StoreError> {
            Ok(None)
        }

        async fn revision_heads(
            &self,
            _keys: Vec<eliot_store_api::RevisionKey>,
        ) -> Result<Vec<RevisionHead>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn validation_snapshot(
            &self,
        ) -> Result<eliot_store_api::CanonicalValidationSnapshot, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn scope_revision_view(
            &self,
            _scope_id: eliot_store_api::ScopeId,
        ) -> Result<eliot_store_api::ScopeRevisionView, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn ordering_heads(
            &self,
            _scopes: Vec<eliot_store_api::OrderingScopeId>,
        ) -> Result<Vec<OrderingHead>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn execute_named(
            &self,
            query: NamedReadRequest,
        ) -> Result<NamedReadResponse, StoreError> {
            let payload = match query.operation {
                NamedReadOperation::GetReactiveInjectionState => {
                    self.ledger_payload.lock().expect("fake").clone()
                }
                NamedReadOperation::GetResourceSnapshot => {
                    self.snapshot_payload.lock().expect("fake").clone()
                }
                _ => return Err(StoreError::UnknownOperation),
            };
            Ok(NamedReadResponse {
                operation: query.operation,
                state_fence: query.state_fence.clone(),
                revision_heads: Vec::new(),
                payload,
            })
        }

        async fn health(&self) -> Result<StoreHealth, StoreError> {
            Err(StoreError::Unavailable)
        }
    }

    fn ledger_payload() -> serde_json::Value {
        serde_json::json!({
            "revision": 4,
            "ledger_json": "{\"contract\":\"eliot.agent-bridge.reactive-injection-receipts/v1\",\"next_item_seq\":0,\"next_receipt_seq\":0,\"items\":{},\"receipts\":{}}"
        })
    }

    fn snapshot_payload() -> serde_json::Value {
        serde_json::json!({
            "revision": 6,
            "content_base64": "c25hcHNob3QtYnl0ZXMtOQ==",
            "content_sha256": eliot_contracts::sha256_hex(b"snapshot-bytes-9")
        })
    }

    fn query() -> ReactiveRestoreQuery {
        ReactiveRestoreQuery {
            session_id: "session-live-1".to_owned(),
            state_fence: test_fence(),
            uris: vec!["eliot://evidence/source-9".to_owned()],
        }
    }

    #[tokio::test]
    async fn foreign_session_refuses_before_store_io() {
        let service = ready_service();
        let session = live_session(&service);
        let store = FakeStore::new(ledger_payload(), snapshot_payload());
        let mut foreign = query();
        foreign.session_id = "session-foreign-9".to_owned();
        let result = serve_reactive_restore(
            &store,
            &service,
            &session,
            "session-live-1",
            &context(),
            &foreign,
        )
        .await;
        assert!(matches!(
            result,
            Err(ReactiveServiceError::InvalidField { .. })
        ));
    }

    #[tokio::test]
    async fn foreign_fence_refuses_at_live_authority() {
        let service = ready_service();
        let session = live_session(&service);
        let store = FakeStore::new(ledger_payload(), snapshot_payload());
        let mut rotated = query();
        rotated.state_fence = StateFence::new(
            test_epoch(9),
            ResourceGeneration::new(7).expect("generation"),
        );
        let result = serve_reactive_restore(
            &store,
            &service,
            &session,
            "session-live-1",
            &context(),
            &rotated,
        )
        .await;
        assert!(matches!(result, Err(ReactiveServiceError::FenceMismatch)));
    }

    #[tokio::test]
    async fn served_bytes_echo_binding_verbatim() {
        let service = ready_service();
        let session = live_session(&service);
        let store = FakeStore::new(ledger_payload(), snapshot_payload());
        let reply = serve_reactive_restore(
            &store,
            &service,
            &session,
            "session-live-1",
            &context(),
            &query(),
        )
        .await
        .expect("serve");
        assert_eq!(reply.session_id, "session-live-1");
        assert_eq!(reply.state_fence, test_fence());
        assert!(
            reply
                .ledger_json
                .as_deref()
                .expect("ledger served")
                .contains("reactive-injection-receipts/v1")
        );
        assert_eq!(reply.snapshots.len(), 1);
        assert_eq!(reply.snapshots[0].uri, "eliot://evidence/source-9");
        assert_eq!(reply.snapshots[0].content, b"snapshot-bytes-9");
        assert_eq!(reply.revision, 6);
    }

    #[tokio::test]
    async fn store_failure_aborts_before_any_served_state() {
        struct FailingStore;
        impl CanonicalStoreClient for FailingStore {
            async fn apply_prepared(
                &self,
                _ctx: &RequestMetadata,
                _transition: eliot_store_api::PreparedTransition,
                _expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
                _expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
            ) -> Result<eliot_store_api::WriteReceipt, StoreError> {
                Err(StoreError::Unavailable)
            }
            async fn receipt(
                &self,
                _operation_id: OperationId,
            ) -> Result<Option<eliot_store_api::WriteReceipt>, StoreError> {
                Err(StoreError::Unavailable)
            }
            async fn revision_heads(
                &self,
                _keys: Vec<eliot_store_api::RevisionKey>,
            ) -> Result<Vec<RevisionHead>, StoreError> {
                Err(StoreError::Unavailable)
            }
            async fn validation_snapshot(
                &self,
            ) -> Result<eliot_store_api::CanonicalValidationSnapshot, StoreError> {
                Err(StoreError::Unavailable)
            }
            async fn scope_revision_view(
                &self,
                _scope_id: eliot_store_api::ScopeId,
            ) -> Result<eliot_store_api::ScopeRevisionView, StoreError> {
                Err(StoreError::Unavailable)
            }
            async fn ordering_heads(
                &self,
                _scopes: Vec<eliot_store_api::OrderingScopeId>,
            ) -> Result<Vec<OrderingHead>, StoreError> {
                Err(StoreError::Unavailable)
            }
            async fn execute_named(
                &self,
                _query: NamedReadRequest,
            ) -> Result<NamedReadResponse, StoreError> {
                Err(StoreError::Unavailable)
            }

            async fn health(&self) -> Result<StoreHealth, StoreError> {
                Err(StoreError::Unavailable)
            }
        }
        let service = ready_service();
        let session = live_session(&service);
        let result = serve_reactive_restore(
            &FailingStore,
            &service,
            &session,
            "session-live-1",
            &context(),
            &query(),
        )
        .await;
        assert!(matches!(result, Err(ReactiveServiceError::Store(_))));
    }
}
