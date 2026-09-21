//! S-CONC-ACCEPT #994 follow-up bindings to the Kernel-route fixture (issue #2031).
//!
//! Cases `994/15` (migration drain) and `994/19` (Product Pulse route) could
//! not run the real Kernel to ORS to Store path in the #994 suite: no
//! constructible Kernel runtime / ORS gateway handle existed in scope, so
//! `store_concurrency_product.rs` drives case 19 through a hand-rolled
//! `LoopbackTransport` straight into the adapter with no ORS staging at all.
//! These two edge tests bind the same scenario essences to the vended
//! production seams instead:
//!
//! - `eliot_ors::test_support::KernelRouteStoreFixture`: the real ORS
//!   `RedbRecoveryStore` bound with the single `KernelRouteEvidence`
//!   binding (test-support feature; never production);
//! - `KernelStoreGateway::apply_reserved`: the real gateway admission,
//!   fence, lease, ORS reservation/eligibility, `ReservedSubmission`
//!   projection carrying `CAPABILITY_RESERVED_WRITE`, single send,
//!   receipt reconciliation and finalization;
//! - `KernelStoreGateway::{project_reserved_submission, drain_reserved,
//!   cancel_reserved}`: the Kernel-visible reserved-submission API and the
//!   migration-drain accounting seam.
//!
//! The wire far end is a frame responder answering `ReservedWrite` with
//! exactly enveloped committed receipts bound to the admitted request
//! (precedent: the `gateway_cases` responder in
//! `store_write_reservation_tests.rs` and the `reserved_write_client.rs`
//! fake). It manufactures responses, never admission authority: every
//! reservation, eligibility verdict, capability selection and reconciliation
//! runs through the real ORS store and the real gateway state machine over a
//! real named-pipe EBP connection. The ordinary-`Apply` route panics, so any
//! unreserved fallback fails outright. Discriminator versus the old path: the
//! `LoopbackTransport` shape never creates ORS reservations — both tests
//! assert durable reservation records (`Finalized`/`Released`) in the
//! fixture store, which only the Kernel to ORS to Store route can produce.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::large_futures)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_string_new)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use eliot_contracts::{
    AuthorityEpoch, ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_ipc::{NamedPipeServer, NamedPipeTransport, PeerIdentity, TransportLimits};
use eliot_kernel_core::{GenerationRoute, RouteScope};
use eliot_kernel_service::{
    CompositionReservation, EbpCanonicalStoreClient, HostFileIdentity, HostJobBinding,
    HostJobIdentity, HostJobRoot, HostKernelCandidateBinding, HostProcessBinding,
    HostStoreBootstrapRequirement, KernelActivationPermit, KernelControlCommand,
    KernelReadyReceipt, KernelService, KernelServiceState, KernelStoreGateway, ObservedHead,
    ProcessObservation, ReservationSeed, RestartBudget,
};
use eliot_ors::{ReservationState, test_support::KernelRouteStoreFixture};
use eliot_platform::{KernelActivationNonce, PlatformHandle};
use eliot_protocol::{FrameKind, ProtocolVersion, ServerHello};
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};
use eliot_store_api::{
    CAPABILITY_RESERVED_WRITE, CanonicalRequestView, CommitId, EffectClass,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OperationManifestDigest, OrderingHead, OrderingHeadExpectation,
    OrderingScopeId, PreparedTransition, ReadinessReceipt, RequestMeta, ReservedWriteRequest,
    Resubmission, RevisionHeadExpectation, RevisionKey, ScopeId, SecurityContext, StoreRequest,
    StoreResponse, TransitionClass, WriteReceipt, WriteReceiptStatus, canonical_request_hash,
    decode_request_frame, response_frame,
};
use serde_json::json;

const LINEAGE_994: &str = "550e8400-e29b-41d4-a716-446655440000";
const EPOCH_SEQUENCE: u64 = 1;
const EXPECTED_REVISION: u64 = 3;

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).expect("994-kr handle builds")
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_994).expect("994-kr lineage parses"),
        NonZeroU64::new(sequence).expect("994-kr nonzero sequence"),
    )
    .expect("994-kr epoch builds")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(EPOCH_SEQUENCE), ResourceGeneration::genesis())
}

fn head_digest(scope: &str) -> String {
    let byte = match scope {
        "scope-994-pulse-a" | "scope-994-drain" => b'a',
        "scope-994-pulse-b" | "scope-994-stuck" => b'b',
        _ => b'c',
    };
    std::iter::repeat_n(byte as char, 64).collect()
}

fn context_for(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-994-kr-{tag}")).expect("994-kr request id"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-994-kr").expect("994-kr product"),
        // The gateway admits only the active daemon caller (production rule
        // `apply_reserved_admission`); any other source is refused before
        // any ORS or Store work.
        source_id: SourceId::new("eliotd").expect("994-kr daemon caller"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn transition_for(tag: &str, scopes: &[&str]) -> PreparedTransition {
    let operation_id = format!("op-994-kr-{tag}");
    PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(operation_id.clone()).expect("994-kr operation id"),
            idempotency_key: format!("idem-994-kr-{tag}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(format!("scope-994-kr-{tag}")).expect("994-kr scope id"),
        task_id: None,
        ordering_scopes: scopes
            .iter()
            .map(|scope| OrderingScopeId::new((*scope).to_owned()).expect("994-kr order scope"))
            .collect(),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new(format!("manifest-994-kr-{tag}"))
            .expect("994-kr manifest digest"),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([(
                "subject".to_owned(),
                json!(format!("observation-994-kr-{tag}")),
            )]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    }
}

/// Seals the canonical request hash over the exact values about to be bound,
/// exactly as the gateway admission does before any ORS or Store work.
fn seal(
    context: &RequestMeta,
    transition: &mut PreparedTransition,
    revision: &[RevisionHeadExpectation],
    ordering: &[OrderingHeadExpectation],
) {
    let view = CanonicalRequestView::from_apply(context, transition, revision, ordering);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&view).expect("994-kr request hashes");
}

fn heads_for(
    scopes: &[(&str, u64)],
) -> (Vec<RevisionHeadExpectation>, Vec<OrderingHeadExpectation>) {
    let revision = vec![RevisionHeadExpectation {
        key: RevisionKey::new("rev-994-kr").expect("994-kr revision key"),
        expected_revision: EXPECTED_REVISION,
        state_fence: fence(),
    }];
    let ordering = scopes
        .iter()
        .map(|(scope, sequence)| OrderingHeadExpectation {
            scope: OrderingScopeId::new((*scope).to_owned()).expect("994-kr order scope"),
            expected_sequence: *sequence,
            state_fence: fence(),
        })
        .collect();
    (revision, ordering)
}

fn seed_for(tag: &str, op: &str, scopes: &[(&str, u64)]) -> ReservationSeed {
    let heads = scopes
        .iter()
        .map(|(scope, sequence)| ObservedHead {
            scope: (*scope).to_owned(),
            expected_sequence: *sequence,
            expected_head_digest: head_digest(scope),
            revision_head: None,
        })
        .collect();
    ReservationSeed {
        reservation_id: format!("reservation-994-kr-{tag}"),
        operation_id: op.to_owned(),
        recovery_owner: "recovery-owner-994-kr".to_owned(),
        payload_bytes: format!("payload-994-kr-{tag}").into_bytes(),
        key_provider: eliot_kernel_service::RESERVATION_KEY_PROVIDER.to_owned(),
        key_name: eliot_kernel_service::RESERVATION_KEY_NAME.to_owned(),
        visibility: eliot_kernel_service::RESERVATION_VISIBILITY.to_owned(),
        created_at_ms: 1_700_000_000_000,
        known_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        heads,
    }
}

fn apply_inputs(
    tag: &str,
    scopes: &[(&str, u64)],
) -> (
    RequestMeta,
    PreparedTransition,
    Vec<RevisionHeadExpectation>,
    Vec<OrderingHeadExpectation>,
    ReservationSeed,
) {
    let context = context_for(tag);
    let names: Vec<&str> = scopes.iter().map(|(scope, _)| *scope).collect();
    let mut transition = transition_for(tag, &names);
    let (revision, ordering) = heads_for(scopes);
    seal(&context, &mut transition, &revision, &ordering);
    let seed = seed_for(tag, transition.identity.operation_id.as_str(), scopes);
    (context, transition, revision, ordering, seed)
}

/// Issues the exact receipt envelope the responder binds to one admitted
/// request: same operation identity, same fence everywhere, authority epoch
/// bound to the fence tuple, and the causal chain carrying the real
/// reserved sequence from the admission. The single-scope causal sequence
/// must equal the reserved sequence (`check_receipt_token_binding`), so the
/// envelope is built explicitly like the `gateway_cases` responder does —
/// `issue_store_receipt_envelope` always issues a genesis causal chain and
/// can never satisfy reconciliation. String values below mirror the
/// production mappings (`operation_kind(CaptureCandidate)`,
/// `proof_ceiling_for(Candidate)`) read from `eliot-store-api`.
fn envelope_for(
    context: &RequestMeta,
    transition: &PreparedTransition,
    reserved_sequence: u64,
) -> eliot_receipts::ReceiptEnvelope {
    use eliot_receipts::{EffectClass, ProofCeiling, ReceiptCore, ReceiptEnvelope};
    let fence = serde_json::to_value(&context.state_fence).expect("994-kr fence json");
    let epoch =
        serde_json::to_value(&context.state_fence.authority_epoch).expect("994-kr epoch json");
    let metadata = serde_json::to_value(context).expect("994-kr context json");
    let contract =
        serde_json::to_value(eliot_receipts::contract_identity().expect("994-kr contract"))
            .expect("994-kr contract json");
    let scope = transition.ordering_scopes[0].as_str().to_owned();
    let proof = serde_json::to_value(ProofCeiling::CandidateArtifact).expect("994-kr proof json");
    // Receipt-domain effect vocabulary (`CANDIDATE`); the store-api ceiling
    // `EffectClass::Candidate` maps to this proof ceiling in production
    // (`proof_ceiling_for`), verified against live source.
    let effect = serde_json::to_value(EffectClass::Candidate).expect("994-kr effect json");
    let parent = format!(
        "parent-994-kr-{}",
        transition.identity.operation_id.as_str()
    );
    let core: ReceiptCore = serde_json::from_value(json!({
        "contract": contract,
        "kind": "OPERATION",
        "work_scope": {
            "scope_id": scope,
            "product_id": context.product_id.as_str(),
            "resource_generation": context.state_fence.resource_generation.value(),
            "state_fence": fence,
        },
        "task": null,
        "session": null,
        "causal": {
            "state_fence": fence,
            "transaction_sequence": reserved_sequence,
            "parent_receipt_id": parent,
            "predecessor_receipt_ids": [parent],
        },
        "request": {
            "metadata": metadata,
            "state_fence": fence,
        },
        "operation": {
            "operation_id": transition.identity.operation_id.as_str(),
            "request_id": context.request_id.as_str(),
            "idempotency_key": transition.identity.idempotency_key,
            "operation_kind": "store.apply.capture_candidate",
            "effect": effect.clone(),
            "state_fence": fence,
        },
        "authority": {
            "authority_id": format!("eliot-store-manifest:{}", transition.operation_manifest_digest),
            "authority_owner": context.source_id.as_str(),
            "authority_epoch": epoch,
            "state_fence": fence,
            "allowed_effect": effect,
            "proof_ceiling": proof,
        },
        "artifacts": [],
        "verifier": null,
        "problem": null,
        "coordination": null,
        "disposition": {"kind": "SUCCESS", "proof": proof},
    }))
    .expect("994-kr receipt core decodes");
    ReceiptEnvelope::issue(core).expect("994-kr envelope issues")
}
/// Builds the exact Store receipt answering one projected request: identity,
/// class, fence, and every reserved scope sequence mirror the admission, and
/// the envelope carries the real reserved sequence as its causal chain.
fn receipt_for(request: &ReservedWriteRequest) -> WriteReceipt {
    let transition = &request.transition;
    let scope = request.admission.scopes[0].clone();
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-994-kr").expect("994-kr commit id")),
        state_fence: request.context.state_fence.clone(),
        ordering_sequences: vec![OrderingHead {
            scope: scope.scope,
            sequence: scope.reserved_sequence,
            state_fence: fence(),
        }],
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["capture-observation".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    };
    receipt.envelope = Some(envelope_for(
        &request.context,
        transition,
        scope.reserved_sequence,
    ));
    receipt.validate().expect("994-kr receipt validates");
    receipt
}

fn supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:994kr".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-994kr".to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: "host-lineage-994kr".to_owned(),
            sequence: 1,
        },
        activation_id: "activation-994kr".to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: "activation-lineage-994kr".to_owned(),
            sequence: 1,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-994kr".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-994kr".to_owned(),
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
    .expect("994-kr incarnation derives")
}

fn candidate_binding() -> HostKernelCandidateBinding {
    HostKernelCandidateBinding {
        installation_id: handle("installation-994kr"),
        host_epoch: AuthorityEpoch::new(1).expect("994-kr host epoch"),
        kernel_epoch: test_epoch(EPOCH_SEQUENCE),
        activation_id: handle("activation-994kr"),
        artifact_hash: handle("artifact-994kr"),
        config_hash: handle("config-994kr"),
        job_object_id: handle("Local\\Eliot-Host-Kernel-994kr"),
        pipe_identity: handle(eliot_kernel_service::KERNEL_CONTROL_PIPE),
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-994kr".to_owned(),
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
        supervision_incarnation: supervision_incarnation(),
        restart_budget: RestartBudget::new(1, 1).expect("994-kr restart budget"),
        agent_bridge_admission: None,
        containment_action: None,
    }
}

/// Drives a real `KernelService` to `Ready` on the test lineage, so the
/// gateway binds live authority (precedent: `doctor-front-door.rs`). The
/// widened front-door capacities mirror the 994 lanes profile: two
/// independent scopes need parallel bounded send windows.
fn ready_service() -> KernelService {
    let mut service = KernelService::new([3; 32], 8, 16).expect("994-kr service builds");
    let candidate = candidate_binding();
    let permit = KernelActivationPermit {
        operation_id: handle("activation-operation-994kr"),
        candidate_binding_digest: candidate.compute_digest().expect("994-kr candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("journal-transaction-994kr"),
        journal_sequence: 7,
        generation: ResourceGeneration::genesis(),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64)))
            .expect("994-kr activation nonce"),
    };
    service
        .reconcile(candidate.clone())
        .expect("994-kr reconcile");
    service
        .apply(KernelControlCommand::Shadow)
        .expect("994-kr shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("994-kr handoff");
    let activation = service
        .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
        .expect("994-kr activation");
    let ready = KernelReadyReceipt {
        activation_id: candidate.activation_id.clone(),
        activation_operation_id: activation.operation_id.clone(),
        activation_nonce_digest: activation.activation_nonce_digest.clone(),
        process: ProcessObservation {
            process_id: handle("pid:42:start:10"),
            job_object_id: candidate.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("process-evidence-994kr")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![handle("ready-994kr")],
    };
    service.publish_ready(ready).expect("994-kr ready");
    assert_eq!(service.state(), KernelServiceState::Ready);
    service
}

#[derive(Default)]
struct ServerLog {
    reserved: AtomicUsize,
    apply: AtomicUsize,
}

/// Frame responder answering the production EBP exchange over the real
/// named-pipe connection. `ReservedWrite` answers with the exactly enveloped
/// committed receipt for the admitted request; `Apply` panics so any
/// unreserved fallback fails outright; `Receipt` answers empty (the gateway
/// reconciles from the send response, never by polling here).
async fn serve(
    mut server: NamedPipeServer,
    connection_id: String,
    artifact_hash: String,
    config_hash: String,
    log: Arc<ServerLog>,
) {
    let limits = TransportLimits::default();
    let frame = server
        .receive_frame(limits)
        .await
        .expect("994-kr hello arrives");
    assert_eq!(frame.kind, FrameKind::Control, "994-kr expects EBP hello");
    let hello = ServerHello {
        selected_protocol: ProtocolVersion::CURRENT,
        session_principal_binding: "sconc994-kr-store-session".to_owned(),
        allowed_capabilities: eliot_store_api::CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        allowed_effects: eliot_store_api::EFFECTS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        config_snapshot: serde_json::json!({
            "config_hash": config_hash,
            "artifact_hash": artifact_hash,
        }),
        heartbeat_ms: 1_000,
        control_channel: "sconc994-kr-control".to_owned(),
        rejection_reason: None,
        authority_epoch: test_epoch(EPOCH_SEQUENCE),
    };
    server
        .send_frame(
            &eliot_ipc::server_hello_frame(&connection_id, &hello).expect("994-kr hello encodes"),
            limits,
        )
        .await
        .expect("994-kr hello sends");
    let frame = server
        .receive_frame(limits)
        .await
        .expect("994-kr readiness arrives");
    let (request_id, _, store_request) =
        decode_request_frame(&frame).expect("994-kr readiness decodes");
    assert!(
        matches!(store_request, StoreRequest::Readiness),
        "994-kr expects readiness"
    );
    server
        .send_frame(
            &response_frame(
                connection_id.clone(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                StoreResponse::Readiness {
                    receipt: ReadinessReceipt::ready("kernel-route-994kr".to_owned()),
                },
            )
            .expect("994-kr readiness encodes"),
            limits,
        )
        .await
        .expect("994-kr readiness sends");
    loop {
        let next =
            tokio::time::timeout(Duration::from_secs(10), server.receive_frame(limits)).await;
        let Ok(Ok(frame)) = next else {
            break;
        };
        let Ok((request_id, _, store_request)) = decode_request_frame(&frame) else {
            break;
        };
        let answer = match store_request {
            StoreRequest::ReservedWrite { request } => {
                log.reserved.fetch_add(1, Ordering::SeqCst);
                StoreResponse::Transaction {
                    receipt: receipt_for(&request),
                }
            }
            StoreRequest::Receipt { .. } => StoreResponse::Receipt { receipt: None },
            StoreRequest::Apply { .. } => {
                log.apply.fetch_add(1, Ordering::SeqCst);
                panic!("994-kr reserved route must never fall back to ordinary Apply");
            }
            _ => break,
        };
        let Ok(frame) = response_frame(
            connection_id.clone(),
            ProtocolVersion::CURRENT,
            Some(request_id),
            answer,
        ) else {
            break;
        };
        if server.send_frame(&frame, limits).await.is_err() {
            break;
        }
    }
}

struct Route {
    gateway: Arc<KernelStoreGateway>,
    service: Arc<Mutex<KernelService>>,
    client: Arc<EbpCanonicalStoreClient<NamedPipeTransport>>,
    generation_route: GenerationRoute,
    fixture: KernelRouteStoreFixture,
    log: Arc<ServerLog>,
    server_task: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

/// Composes the real Kernel to ORS to Store route: a `Ready` KernelService,
/// a real named-pipe EBP connection to the frame responder, and the
/// `KernelRouteStoreFixture` ORS bound into the gateway — the constructible
/// runtime + gateway handle #2031 vended so #994 cases bind them instead of
/// `LoopbackTransport`.
async fn route(tag: &str) -> Route {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("994-kr clock")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("eliot-994-kr-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("994-kr temp root");
    let pipe = format!(
        r"\\.\pipe\eliot\store-994-kr-{tag}-{}-{nanos}",
        std::process::id()
    );
    let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
        .expect("994-kr loopback expectation");
    let mut server = NamedPipeServer::create(&pipe, &expectation).expect("994-kr server");
    let client_pipe = pipe.clone();
    let client_expectation = expectation.clone();
    let client_task = tokio::spawn(async move {
        eliot_ipc::NamedPipeTransport::connect_authenticated(
            &client_pipe,
            Duration::from_secs(10),
            &client_expectation,
        )
        .await
        .expect("994-kr loopback connects")
    });
    server
        .wait_for_authenticated_client(Duration::from_secs(10), &expectation)
        .await
        .expect("994-kr loopback admits its own process");
    let transport = client_task.await.expect("994-kr client task");
    let (peer_sid, peer_session) = match transport.peer_identity() {
        PeerIdentity::Authenticated {
            user_identity,
            session_identity,
            ..
        } => (user_identity.clone(), session_identity.clone()),
        PeerIdentity::Unavailable { .. } => {
            panic!("994-kr loopback peer is not authenticated")
        }
    };
    let requirement = HostStoreBootstrapRequirement {
        route_identity: handle("store_bridge"),
        canonical_pipe_identity: handle(&pipe),
        store_generation: ResourceGeneration::genesis(),
        state_fence: fence(),
        launch_nonce: handle("launch-994-kr"),
        connection_id: handle(&format!("conn-994-kr-{tag}")),
        expected_peer_sid: handle(&peer_sid),
        expected_peer_session_id: peer_session.parse().expect("994-kr session"),
        approved_artifact_hash: handle(&"a".repeat(64)),
        approved_config_hash: handle(&"b".repeat(64)),
        timeout_ms: 30_000,
    };
    let artifact = requirement.approved_artifact_hash.as_str().to_owned();
    let config = requirement.approved_config_hash.as_str().to_owned();
    let connection_id = requirement.connection_id.as_str().to_owned();
    let log = Arc::new(ServerLog::default());
    let server_task = tokio::spawn(serve(
        server,
        connection_id,
        artifact,
        config,
        Arc::clone(&log),
    ));
    let client = EbpCanonicalStoreClient::connect(transport, requirement)
        .await
        .expect("994-kr EBP handshake");
    let fixture =
        KernelRouteStoreFixture::open(&format!("994-kr-{tag}")).expect("994-kr fixture opens");
    let service = Arc::new(Mutex::new(ready_service()));
    let generation_route = GenerationRoute::new(
        RouteScope::new("store_bridge").expect("994-kr scope"),
        ResourceGeneration::genesis(),
        AuthorityEpoch::new(1).expect("994-kr route epoch"),
    )
    .expect("994-kr route");
    let client = Arc::new(client);
    let gateway = Arc::new(KernelStoreGateway::new(
        Arc::clone(&service),
        Arc::clone(&client),
        generation_route.clone(),
        Some(Arc::clone(fixture.store())),
    ));
    Route {
        gateway,
        service,
        client,
        generation_route,
        fixture,
        log,
        server_task,
        dir,
    }
}

/// Binds a second gateway handle to the same service authority, store
/// client and ORS: the fence is a per-handle flight guard while the ORS
/// is the shared durable authority, so cancellation and the final drain
/// proceed through a fresh handle after the first handle fenced itself
/// on the honestly blocked drain.
fn second_gateway(route: &Route) -> Arc<KernelStoreGateway> {
    Arc::new(KernelStoreGateway::new(
        Arc::clone(&route.service),
        Arc::clone(&route.client),
        route.generation_route.clone(),
        Some(Arc::clone(route.fixture.store())),
    ))
}

async fn finish(route: Route) {
    let Route {
        gateway,
        server_task,
        dir,
        ..
    } = route;
    drop(gateway);
    if tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .is_err()
    {
        panic!("994-kr responder did not join");
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn owner_for(fixture: &KernelRouteStoreFixture, context: &RequestMeta) -> CompositionReservation {
    CompositionReservation::bind(
        Arc::clone(fixture.store()),
        eliot_kernel_service::writer_epoch_for_fence(context).expect("994-kr writer epoch"),
    )
    .expect("994-kr owner binds")
}

// WORK_UNIT_CASE: 994/19
#[tokio::test]
async fn kernel_route_pulse_progress_two_scopes() {
    // Case-19 essence (`product_pulse_kernel_route_progress`): two
    // independent pulse scopes advance concurrently with valid committed
    // receipts through the admitted route — here the real Kernel to ORS to
    // Store route (gateway + fixture + reserved submission) instead of the
    // hand-rolled `LoopbackTransport` that stages nothing in ORS.
    let route = route("19").await;
    let (a_context, a_transition, a_revision, a_ordering, a_seed) =
        apply_inputs("19a", &[("scope-994-pulse-a", 6)]);
    let (b_context, b_transition, b_revision, b_ordering, b_seed) =
        // Independent scopes carry independent head histories: distinct
        // declared heads reserve distinct sequences, so the two receipts
        // must show distinct nonzero reservation orders.
        apply_inputs("19b", &[("scope-994-pulse-b", 7)]);
    let op_a = a_transition.identity.operation_id.as_str().to_owned();
    let op_b = b_transition.identity.operation_id.as_str().to_owned();
    let (receipt_a, receipt_b) = tokio::join!(
        route
            .gateway
            .apply_reserved(&a_context, a_transition, a_revision, a_ordering, a_seed),
        route
            .gateway
            .apply_reserved(&b_context, b_transition, b_revision, b_ordering, b_seed),
    );
    let receipt_a = receipt_a.unwrap_or_else(|error| {
        panic!("994/19 pulse scope A failed through the Kernel route: {error}")
    });
    let receipt_b = receipt_b.unwrap_or_else(|error| {
        panic!("994/19 pulse scope B failed through the Kernel route: {error}")
    });
    assert_eq!(receipt_a.operation_id.as_str(), op_a);
    assert_eq!(receipt_b.operation_id.as_str(), op_b);
    assert_eq!(receipt_a.status, WriteReceiptStatus::Committed);
    assert_eq!(receipt_b.status, WriteReceiptStatus::Committed);
    // The receipts carry the real ORS-assigned reservation orders: distinct
    // nonzero orders prove the single ORS coordinator staged both writes —
    // the `LoopbackTransport` shape assigns no reservation order at all.
    let order_a = receipt_a.ordering_sequences[0].sequence;
    let order_b = receipt_b.ordering_sequences[0].sequence;
    assert!(order_a > 0 && order_b > 0, "994/19 real reservation orders");
    assert_ne!(
        order_a, order_b,
        "994/19 parallel scopes hold distinct reservation orders"
    );
    // Nothing is left pending: the recovery projection (which surfaces only
    // non-terminal records) scans complete and empty.
    let owner = owner_for(&route.fixture, &a_context);
    let page = eliot_kernel_service::recovery_page(&owner, 64).expect("994/19 recovery scans");
    assert!(
        page.next_after_order.is_none(),
        "994/19 recovery scan is complete"
    );
    assert!(
        page.records.is_empty(),
        "994/19 no pulse reservation is left staged"
    );
    let unresolved =
        eliot_kernel_service::unresolved_reservations(&owner, 64).expect("994/19 unresolved scans");
    assert!(
        unresolved.is_empty(),
        "994/19 no pulse reservation is left unresolved"
    );
    assert_eq!(
        route.log.reserved.load(Ordering::SeqCst),
        2,
        "994/19 exactly two Store sends"
    );
    assert_eq!(
        route.log.apply.load(Ordering::SeqCst),
        0,
        "994/19 never falls back to unreserved Apply"
    );
    // The submission on the wire carries the reserved capability: project one
    // sealed reservation without sending, check the Store declaration itself,
    // then release the untouched token so the fixture stays drain-clean.
    let (c_context, c_transition, c_revision, c_ordering) = {
        let context = context_for("19c");
        let mut transition = transition_for("19c", &["scope-994-pulse-c"]);
        let (revision, ordering) = heads_for(&[("scope-994-pulse-c", 6)]);
        seal(&context, &mut transition, &revision, &ordering);
        (context, transition, revision, ordering)
    };
    let c_op = c_transition.identity.operation_id.as_str().to_owned();
    let c_seed = seed_for("19c", &c_op, &[("scope-994-pulse-c", 6)]);
    let sealed = eliot_kernel_service::reserve_for_transition(
        &owner,
        &c_seed,
        &c_context,
        &c_transition,
        &c_revision,
        &c_ordering,
    )
    .expect("994/19 capability probe reserves");
    // Staged-but-unsent work is visible in the recovery projection with its
    // exact operation identity — the same projection that shows nothing
    // pending after the two commits above.
    let staged = eliot_kernel_service::recovery_page(&owner, 64).expect("994/19 probe scans");
    assert_eq!(staged.records.len(), 1, "994/19 probe reservation staged");
    assert_eq!(staged.records[0].token.operation_id.as_str(), c_op);
    assert!(
        !staged.records[0].state.is_terminal(),
        "994/19 probe reservation is still live"
    );
    let submission = route
        .gateway
        .project_reserved_submission(&sealed, &c_context, &c_transition, c_revision, c_ordering)
        .expect("994/19 capability probe projects");
    assert_eq!(
        submission.capability(),
        CAPABILITY_RESERVED_WRITE,
        "994/19 submission selects the Store reserved-write capability"
    );
    let released = route
        .gateway
        .cancel_reserved(&sealed.token)
        .expect("994/19 capability probe releases");
    assert_eq!(released.state, ReservationState::Released);
    finish(route).await;
}

// WORK_UNIT_CASE: 994/15
#[tokio::test]
async fn kernel_route_migration_drain_accounts_everything() {
    // Case-15 essence (`migration_drain_accounts_every_operation`): the
    // quiesced generation drains through the gateway, which accounts for
    // every unresolved reservation in the bound ORS before exclusivity, and
    // new writes are refused once migration exclusivity holds.
    let route = route("15").await;
    // Live history first on the real route: the drain operation commits.
    let (d_context, d_transition, d_revision, d_ordering, d_seed) =
        apply_inputs("15drain", &[("scope-994-drain", 6)]);
    let drain_op = d_transition.identity.operation_id.as_str().to_owned();
    let drain_receipt = route
        .gateway
        .apply_reserved(&d_context, d_transition, d_revision, d_ordering, d_seed)
        .await
        .unwrap_or_else(|error| {
            panic!("994/15 drain operation failed through the Kernel route: {error}")
        });
    assert_eq!(drain_receipt.operation_id.as_str(), drain_op);
    assert_eq!(drain_receipt.status, WriteReceiptStatus::Committed);
    // One operation is reserved but never sent: in-flight work the drain
    // must account for instead of force-releasing.
    let owner = owner_for(&route.fixture, &d_context);
    let (s_context, s_transition, s_revision, s_ordering) = {
        let context = context_for("15stuck");
        let mut transition = transition_for("15stuck", &["scope-994-stuck"]);
        let (revision, ordering) = heads_for(&[("scope-994-stuck", 6)]);
        seal(&context, &mut transition, &revision, &ordering);
        (context, transition, revision, ordering)
    };
    let stuck_op = s_transition.identity.operation_id.as_str().to_owned();
    let s_seed = seed_for("15stuck", &stuck_op, &[("scope-994-stuck", 6)]);
    let stuck = eliot_kernel_service::reserve_for_transition(
        &owner,
        &s_seed,
        &s_context,
        &s_transition,
        &s_revision,
        &s_ordering,
    )
    .expect("994/15 stuck operation reserves");
    // The staged-but-unsent token is visible in the recovery projection
    // with its exact identity — the scan the drain accounts.
    let staged = eliot_kernel_service::recovery_page(&owner, 64).expect("994/15 probe scans");
    assert_eq!(staged.records.len(), 1, "994/15 stuck token staged");
    assert_eq!(staged.records[0].token.operation_id.as_str(), stuck_op);
    // Drain with unreconciled work outstanding: the gateway refuses
    // exclusivity with the honest pending count — no forced release.
    let blocked = route
        .gateway
        .drain_reserved(Duration::from_secs(5))
        .await
        .expect_err("994/15 drain blocks on the unreconciled reservation");
    assert!(
        blocked.contains("1 unresolved"),
        "994/15 drain names the pending count, got {blocked}"
    );
    // The honestly blocked drain fenced the first handle: exclusivity starts
    // here, and the fenced handle stays inert.
    assert!(
        route.gateway.is_fenced(),
        "994/15 blocked drain fences its own handle"
    );
    let pending =
        eliot_kernel_service::unresolved_reservations(&owner, 64).expect("994/15 unresolved scans");
    assert_eq!(
        pending.len(),
        1,
        "994/15 exactly the stuck token is pending"
    );
    assert_eq!(pending[0].token.operation_id.as_str(), stuck_op);
    // The proven-no-effect reservation releases cleanly through a second
    // handle bound to the same authority and ORS; the drain then accounts
    // for everything and grants exclusivity on that handle.
    let drainer = second_gateway(&route);
    let released = drainer
        .cancel_reserved(&stuck.token)
        .expect("994/15 stuck reservation releases");
    assert_eq!(released.state, ReservationState::Released);
    drainer
        .drain_reserved(Duration::from_secs(5))
        .await
        .expect("994/15 drain completes once everything reconciles");
    // Migration exclusivity: new writes are refused at the fenced handle.
    drainer.fence();
    assert!(drainer.is_fenced(), "994/15 drain handle holds the fence");
    let (x_context, x_transition, x_revision, x_ordering, x_seed) =
        apply_inputs("15excluded", &[("scope-994-excluded", 6)]);
    let excluded = drainer
        .apply_reserved(&x_context, x_transition, x_revision, x_ordering, x_seed)
        .await
        .expect_err("994/15 fenced gateway refuses new writes");
    assert!(
        excluded.contains("fenced"),
        "994/15 refusal names the fence, got {excluded}"
    );
    // Accounting: the committed drain receipt carries the real reservation
    // order, the stuck token released cleanly, and the excluded write never
    // touched ORS or the Store. The recovery projection surfaces only
    // non-terminal records, so a complete empty scan plus the terminal
    // receipts is the drain's exact accounting (the blocked drain above
    // proved the scan is honest: it refused while work was outstanding).
    assert!(drain_receipt.ordering_sequences[0].sequence > 0);
    let page = eliot_kernel_service::recovery_page(&owner, 64).expect("994/15 recovery scans");
    assert!(
        page.next_after_order.is_none(),
        "994/15 recovery scan is complete"
    );
    assert!(
        page.records.is_empty(),
        "994/15 drain leaves no staged reservation behind"
    );
    let unresolved = eliot_kernel_service::unresolved_reservations(&owner, 64)
        .expect("994/15 final unresolved scans");
    assert!(
        unresolved.is_empty(),
        "994/15 nothing remains unresolved after drain"
    );
    assert_eq!(
        route.log.reserved.load(Ordering::SeqCst),
        1,
        "994/15 exactly one Store send"
    );
    assert_eq!(
        route.log.apply.load(Ordering::SeqCst),
        0,
        "994/15 never falls back to unreserved Apply"
    );
    finish(route).await;
}
