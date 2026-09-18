//! Process session-identity tests (issue #79) — test-oracle only.
//!
//! Proves the Kernel stopped treating the transport `connection_id` as
//! process session identity: the durable caller session is resolved
//! server-side, `ProcessIntent.session_id` validates against that admitted
//! binding (never against the pipe), reconnect rebinds transport through an
//! explicit receipt without rewriting intent identity, and every stale or
//! foreign binding fails with its own distinct typed error. No test doubles
//! in the production path: every assertion drives the real resolver,
//! validator, frame gateway, and execution seam.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use super::*;
use eliot_contracts::{EpochId, EpochLineageId};
use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};
use eliot_runtime_contracts::HealthVector;

const BROKER_MODULE: &str = "eliot-user-broker";
const BROKER_SID: &str = "S-1-5-21-100";
const BROKER_PEER_SESSION: &str = "7";

fn temp_root(slug: &str) -> std::path::PathBuf {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-t79-session-{slug}-{}-{ms}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    root
}

fn open_kernel(root: &std::path::Path) -> KernelComposition {
    KernelComposition::new(KernelConfig::new(root)).expect("kernel composition")
}

fn broker_session(kernel: &KernelComposition, connection_id: &str, session_epoch: u64) -> Session {
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let mut module_generation = policy.module_generation.clone();
    module_generation.module_id = ContractId::new(BROKER_MODULE).expect("broker module identity");
    let peer = PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
            .expect("process binding"),
        BROKER_SID.to_owned(),
        BROKER_PEER_SESSION.to_owned(),
    )
    .expect("peer");
    Session {
        connection_id: connection_id.to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer,
        authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        module_generation,
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch,
        state: eliot_ipc::SessionState::Open,
    }
}

fn broker_admission(
    session: &Session,
    operation: &str,
    session_id: SessionId,
) -> ProcessExecutionAdmissionRequest {
    let generation =
        Generation::new(session.module_generation.generation.value()).expect("session generation");
    let intent = ProcessIntent::new(
        OperationId::new(operation).expect("operation"),
        ProcessTreeId::new(format!("t79-tree-{operation}")).expect("tree"),
        JobId::new(format!("t79-job-{operation}")).expect("job"),
        ImageId::new(format!("t79-image-{operation}")).expect("image"),
        session_id,
        generation,
        r"C:\eliot\seed-worker.exe",
        "c".repeat(64),
        vec!["--seed".to_owned()],
        r"C:\eliot",
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .expect("environment"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4).expect("limits"),
    )
    .expect("intent");
    let deadline = 4_000_000_000_000u64;
    ProcessExecutionAdmissionRequest::new(
        session.module_generation.module_id.as_str(),
        intent,
        ActionLeaseRef::new(format!("t79-lease-{operation}")).expect("lease"),
        FencingToken::new(
            session.authority_epoch.clone(),
            generation,
            format!("t79-fence-{operation}"),
        )
        .expect("fence"),
        deadline,
    )
    .expect("admission")
}

fn start_frame(session: &Session, admission: &ProcessExecutionAdmissionRequest) -> Frame {
    let operation = admission.intent().operation_id().as_str().to_owned();
    let fence_value =
        serde_json::to_value(&session.module_generation.state_fence).expect("fence JSON");
    let clock_value =
        serde_json::to_value(eliot_contracts::ClockReading::default()).expect("clock JSON");
    let request_id = format!("t79-frame-{operation}");
    let identity_value = serde_json::json!({
        "request": {
            "metadata": {
                "request_id": request_id,
                "session_id": null,
                "task_id": null,
                "product_id": BROKER_MODULE,
                "source_id": "broker-transport",
                "state_fence": fence_value,
                "clock": clock_value,
            },
            "state_fence": fence_value,
        },
        "idempotency_key": operation,
        "deadline_unix_ms": admission.deadline_unix_ms(),
        "cancellation_id": format!("t79-cancel-{operation}"),
    });
    let identity: eliot_protocol::RequestIdentity =
        serde_json::from_value(identity_value).expect("request identity");
    let payload =
        serde_json::to_value(ProcessExecutionRequest::Start(admission.clone())).expect("payload");
    let frame_request_id =
        serde_json::from_value::<eliot_contracts::RequestId>(serde_json::json!(request_id))
            .expect("frame request id");
    Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: session.connection_id.clone(),
        request_id: Some(frame_request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity),
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    }
}

fn supervision_binding() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-1".to_owned(),
        host_epoch: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "host-lineage-1".to_owned(),
            sequence: 1,
        },
        activation_id: "activation-1".to_owned(),
        activation_generation: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "activation-lineage-1".to_owned(),
            sequence: 1,
        },
        kernel_generation: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-1".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-1".to_owned(),
            sequence: 1,
        },
        observation_scope: eliot_runtime_contracts::SupervisionObservationScope {
            targets: vec!["eliot-kernel".to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: eliot_runtime_contracts::RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .expect("sealed supervision incarnation")
}

/// Drives one composition to `Ready` through the production Host handoff
/// (candidate -> shadow -> prepare -> permit -> ready), mirroring the proven
/// dispatch-gate harness. No gates are weakened.
fn drive_ready(kernel: &KernelComposition) {
    use eliot_kernel_service::{
        HostJobBinding, HostKernelCandidateBinding, KernelActivationPermit, KernelControlCommand,
        KernelReadyReceipt, RestartBudget,
    };
    let candidate = HostKernelCandidateBinding {
        installation_id: PlatformHandle::new("installation-1").expect("installation"),
        host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            std::num::NonZeroU64::new(1).expect("sequence"),
        )
        .expect("kernel epoch"),
        activation_id: PlatformHandle::new("activation-1").expect("activation"),
        artifact_hash: PlatformHandle::new("artifact-1").expect("artifact"),
        config_hash: PlatformHandle::new("config-1").expect("config"),
        job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").expect("job"),
        pipe_identity: PlatformHandle::new(crate::KERNEL_CONTROL_PIPE).expect("pipe"),
        host_process: eliot_kernel_service::HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: r"C:\eliot\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: eliot_kernel_service::HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
            },
            root: eliot_kernel_service::HostJobRoot {
                process: eliot_kernel_service::HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: r"C:\eliot\kernel.exe".to_owned(),
                },
                executable: eliot_kernel_service::HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_binding(),
        restart_budget: RestartBudget::new(1, 1).expect("restart budget"),
        agent_bridge_admission: None,
        containment_action: None,
    };
    let mut service = kernel.service.lock().expect("service lock");
    service.reconcile(candidate.clone()).expect("reconcile");
    service.apply(KernelControlCommand::Shadow).expect("shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("prepare");
    let permit = KernelActivationPermit {
        operation_id: PlatformHandle::new("op-t79-session").expect("operation"),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: PlatformHandle::new("txn-1").expect("transaction"),
        journal_sequence: 1,
        generation: ResourceGeneration::genesis(),
        authority_epoch: candidate.kernel_epoch,
        activation_nonce: eliot_platform::KernelActivationNonce::new(
            PlatformHandle::new("a".repeat(64)).expect("activation nonce"),
        )
        .expect("activation nonce"),
    };
    service
        .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
        .expect("activate");
    let ready = KernelReadyReceipt {
        activation_id: candidate.activation_id.clone(),
        activation_operation_id: permit.operation_id.clone(),
        activation_nonce_digest: service
            .activation_receipt()
            .expect("activation receipt")
            .activation_nonce_digest
            .clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: PlatformHandle::new("pid:42:start:10").expect("process"),
            job_object_id: candidate.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").expect("evidence")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![PlatformHandle::new("ev1").expect("evidence")],
    };
    service.publish_ready(ready).expect("publish ready");
}

#[test]
fn connection_id_alone_never_yields_process_ownership() {
    let root = temp_root("conn-never-owns");
    let kernel = open_kernel(&root);
    let session = broker_session(&kernel, "t79-conn-a", 1);
    let (owner, ephemeral) = crate::caller_binding(&session).expect("caller binding");
    assert_eq!(ephemeral.connection_id(), "t79-conn-a");
    let caller = kernel
        .admitted_process_caller_session(&session)
        .expect("admitted caller session");
    assert_eq!(caller.class(), ProcessSessionClass::UserBrokerSession);
    assert_eq!(caller.owner(), &owner);
    // The durable session is never the transport connection.
    assert_ne!(caller.session_id().as_str(), session.connection_id);
    // An intent that merely copies the connection ID fails closed with the
    // distinct stale-session error: the pipe proves nothing.
    let forged = broker_admission(
        &session,
        "t79-forged",
        SessionId::new(session.connection_id.clone()).expect("forged session"),
    );
    assert!(matches!(
        eliot_process::validate_process_intent_session(
            forged.intent(),
            &caller,
            &owner,
            forged.state_fence(),
        ),
        Err(eliot_process::ContractError::StaleProcessSession)
    ));
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn reconnect_preserves_durable_session_with_distinct_transport() {
    let root = temp_root("reconnect");
    let kernel = open_kernel(&root);
    let first = broker_session(&kernel, "t79-conn-a", 1);
    let second = broker_session(&kernel, "t79-conn-b", 2);
    let (_, first_ephemeral) = crate::caller_binding(&first).expect("first binding");
    let (_, second_ephemeral) = crate::caller_binding(&second).expect("second binding");
    // Replaceable transport: distinct pipes, distinct ephemeral bindings.
    assert_ne!(first_ephemeral, second_ephemeral);
    let first_caller = kernel
        .admitted_process_caller_session(&first)
        .expect("first caller");
    let second_caller = kernel
        .admitted_process_caller_session(&second)
        .expect("second caller");
    // Durable identity: one admitted session across both pipes.
    assert_eq!(first_caller, second_caller);
    // The explicit rebind receipt binds the new pipe without touching the
    // admitted session; the sealed intent digest is unchanged by construction.
    let receipt = kernel
        .rebind_process_transport(&second)
        .expect("rebind receipt");
    receipt.validate().expect("receipt validates");
    assert!(receipt.rebinds(&second_caller));
    assert_eq!(receipt.session_id(), second_caller.session_id());
    assert_eq!(receipt.connection_id(), "t79-conn-b");
    assert_eq!(receipt.session_epoch(), 2);
    let admission = broker_admission(
        &first,
        "t79-reconnect-op",
        second_caller.session_id().clone(),
    );
    assert_eq!(
        admission.intent().session_id(),
        receipt.session_id(),
        "reconnect must not rewrite the admitted effect identity"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn foreign_and_stale_bindings_fail_with_distinct_errors() {
    let root = temp_root("distinct-errors");
    let kernel = open_kernel(&root);
    let session = broker_session(&kernel, "t79-conn-a", 1);
    let caller = kernel
        .admitted_process_caller_session(&session)
        .expect("admitted caller session");
    let admission = broker_admission(&session, "t79-distinct-op", caller.session_id().clone());
    let owner = caller.owner().clone();
    // Exact binding validates.
    eliot_process::validate_process_intent_session(
        admission.intent(),
        &caller,
        &owner,
        admission.state_fence(),
    )
    .expect("exact binding validates");
    // Foreign session: stale session, not a fence or owner failure.
    let foreign_session = SessionId::new("t79-foreign-session").expect("foreign session");
    let foreign = broker_admission(&session, "t79-distinct-op", foreign_session);
    assert!(matches!(
        eliot_process::validate_process_intent_session(
            foreign.intent(),
            &caller,
            &owner,
            foreign.state_fence(),
        ),
        Err(eliot_process::ContractError::StaleProcessSession)
    ));
    // Wrong owner module: binding mismatch, distinct from stale session.
    let wrong_module = ProcessOwnerBinding::new(
        "eliot-testd",
        owner.principal_digest(),
        owner.authority_epoch().clone(),
        owner.generation(),
    )
    .expect("wrong module owner");
    assert!(matches!(
        eliot_process::validate_process_intent_session(
            admission.intent(),
            &caller,
            &wrong_module,
            admission.state_fence(),
        ),
        Err(eliot_process::ContractError::DispatchBindingMismatch)
    ));
    // Stale admission fence epoch: stale epoch, even for the right owner.
    let stale_fence = FencingToken::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            std::num::NonZeroU64::new(9).expect("sequence"),
        )
        .expect("stale epoch"),
        owner.generation(),
        "t79-stale-fence",
    )
    .expect("stale fence");
    assert!(matches!(
        eliot_process::validate_process_intent_session(
            admission.intent(),
            &caller,
            &owner,
            &stale_fence,
        ),
        Err(eliot_process::ContractError::StaleAuthorityEpoch)
    ));
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn admitted_start_crosses_frame_gateway() {
    let root = temp_root("gate-crosses");
    let kernel = open_kernel(&root);
    drive_ready(&kernel);
    let session = broker_session(&kernel, "t79-conn-a", 1);
    let caller = kernel
        .admitted_process_caller_session(&session)
        .expect("admitted caller session");
    let admission = broker_admission(&session, "t79-gate-op", caller.session_id().clone());
    let frame = start_frame(&session, &admission);
    match kernel.dispatch_frame(&session, &frame) {
        Ok(KernelFrameAction::Process {
            request_id,
            request,
            session_binding,
        }) => {
            assert_eq!(request_id, frame.request_id.expect("frame request id"));
            assert_eq!(
                request.operation_id(),
                Some(admission.intent().operation_id())
            );
            let (_, expected_binding) = crate::caller_binding(&session).expect("caller binding");
            assert_eq!(session_binding, expected_binding);
        }
        other => panic!("admitted Start must cross the gateway, got {other:?}"),
    }
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn copied_connection_id_start_fences_at_frame_gateway() {
    let root = temp_root("gate-copied-conn");
    let kernel = open_kernel(&root);
    drive_ready(&kernel);
    let session = broker_session(&kernel, "t79-conn-a", 1);
    let forged = broker_admission(
        &session,
        "t79-gate-forged",
        SessionId::new(session.connection_id.clone()).expect("forged session"),
    );
    let frame = start_frame(&session, &forged);
    assert!(
        matches!(
            kernel.dispatch_frame(&session, &frame),
            Err(TransportError::SessionFenced)
        ),
        "a connection ID copied into the intent must never authorize launch"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn foreign_session_start_fences_at_frame_gateway() {
    let root = temp_root("gate-foreign");
    let kernel = open_kernel(&root);
    drive_ready(&kernel);
    let session = broker_session(&kernel, "t79-conn-a", 1);
    // A session value with no admitted binding behind it fences, even though
    // its shape is well-formed and the pipe itself is authenticated.
    let foreign = broker_admission(
        &session,
        "t79-gate-foreign",
        SessionId::new("t79-foreign-session").expect("foreign session"),
    );
    let frame = start_frame(&session, &foreign);
    assert!(
        matches!(
            kernel.dispatch_frame(&session, &frame),
            Err(TransportError::SessionFenced)
        ),
        "a foreign session must fence at the gateway"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn operation_identity_and_deadline_joins_stay_closed() {
    let root = temp_root("gate-joins");
    let kernel = open_kernel(&root);
    drive_ready(&kernel);
    let session = broker_session(&kernel, "t79-conn-a", 1);
    let caller = kernel
        .admitted_process_caller_session(&session)
        .expect("admitted caller session");
    let admission = broker_admission(&session, "t79-gate-joins", caller.session_id().clone());
    // Mismatched idempotency key (#74 join) still fences after the flip.
    let mut mismatched = start_frame(&session, &admission);
    if let Some(identity) = mismatched.request_identity.as_mut() {
        identity.idempotency_key = "t79-some-other-operation".to_owned();
    }
    assert!(matches!(
        kernel.dispatch_frame(&session, &mismatched),
        Err(TransportError::SessionFenced)
    ));
    // Mismatched deadline join still fences after the flip.
    let mut stale_deadline = start_frame(&session, &admission);
    if let Some(identity) = stale_deadline.request_identity.as_mut() {
        identity.deadline_unix_ms = admission.deadline_unix_ms() - 1;
    }
    assert!(matches!(
        kernel.dispatch_frame(&session, &stale_deadline),
        Err(TransportError::SessionFenced)
    ));
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn doctor_module_admits_no_process_session() {
    let root = temp_root("doctor-fenced");
    let kernel = open_kernel(&root);
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let mut module_generation = policy.module_generation.clone();
    module_generation.module_id =
        ContractId::new(crate::front_door_session::DOCTOR_MODULE_ID).expect("doctor module");
    let peer = PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
            .expect("process binding"),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .expect("peer");
    let session = Session {
        connection_id: "t79-doctor-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer,
        authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        module_generation,
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    };
    assert!(
        kernel.admitted_process_caller_session(&session).is_err(),
        "the Doctor contour has no durable process session on this base"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn session_rejection_codes_stay_distinct() {
    use eliot_process::ContractError;
    let code_of =
        |error: ContractError| crate::process_execution::process_session_rejection(error).code;
    assert_eq!(
        code_of(ContractError::StaleProcessSession),
        "STALE_PROCESS_SESSION"
    );
    assert_eq!(
        code_of(ContractError::StaleTransportBinding),
        "STALE_TRANSPORT_BINDING"
    );
    assert_eq!(
        code_of(ContractError::StaleAuthorityEpoch),
        "STALE_AUTHORITY_EPOCH"
    );
    assert_eq!(
        code_of(ContractError::StaleStateFence),
        "STALE_PROCESS_FENCE"
    );
    assert_eq!(code_of(ContractError::FenceMismatch), "STALE_PROCESS_FENCE");
    assert_eq!(
        code_of(ContractError::DispatchBindingMismatch),
        "PROCESS_OWNER_MISMATCH"
    );
}

#[test]
fn process_owner_authorization_stays_exact() {
    let owner = ProcessOwnerBinding::new(
        BROKER_MODULE,
        "a".repeat(64),
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            std::num::NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch"),
        Generation::new(1).expect("generation"),
    )
    .expect("owner");
    authorize_process_owner(&owner, &owner).expect("exact owner authorizes");
    let foreign = ProcessOwnerBinding::new(
        BROKER_MODULE,
        "b".repeat(64),
        owner.authority_epoch().clone(),
        owner.generation(),
    )
    .expect("foreign owner");
    assert!(matches!(
        authorize_process_owner(&owner, &foreign),
        Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::DispatchBindingMismatch
        ))
    ));
}

#[tokio::test]
async fn execute_seam_rejects_without_admitted_binding() {
    let root = temp_root("execute-seam");
    let kernel = open_kernel(&root);
    // Stale pipe: the ephemeral transport check fires first with the
    // long-standing mismatch code.
    let session = broker_session(&kernel, "t79-conn-a", 1);
    let (_, expected) = crate::caller_binding(&session).expect("caller binding");
    let admitted_id = kernel
        .admitted_process_caller_session(&session)
        .expect("caller")
        .session_id()
        .clone();
    let stale_pipe = ProcessSessionBinding::new("t79-conn-stale", 1).expect("stale pipe");
    let admission = broker_admission(&session, "t79-exec-op", admitted_id);
    let response = kernel
        .execute_process_request(
            &session,
            stale_pipe,
            ProcessExecutionRequest::Start(admission),
        )
        .await;
    assert!(
        matches!(response, ProcessExecutionResponse::Rejected(ref rejection) if rejection.code == "SESSION_BINDING_MISMATCH"),
        "stale pipe must keep the ephemeral mismatch code, got {response:?}"
    );
    // Doctor contour: no admitted durable session, so Start cannot reach the
    // gateway even with a matching ephemeral binding.
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let mut doctor_generation = policy.module_generation.clone();
    doctor_generation.module_id =
        ContractId::new(crate::front_door_session::DOCTOR_MODULE_ID).expect("doctor module");
    let peer = PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
            .expect("process binding"),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .expect("peer");
    let doctor = Session {
        connection_id: "t79-doctor-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer,
        authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        module_generation: doctor_generation,
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    };
    let (_, doctor_binding) = crate::caller_binding(&doctor).expect("doctor binding");
    let doctor_admission = broker_admission(
        &doctor,
        "t79-exec-doctor",
        SessionId::new("t79-doctor-session").expect("doctor session"),
    );
    let response = kernel
        .execute_process_request(
            &doctor,
            doctor_binding,
            ProcessExecutionRequest::Start(doctor_admission),
        )
        .await;
    assert!(
        matches!(response, ProcessExecutionResponse::Rejected(ref rejection) if rejection.code == "ADMITTED_CALLER_SESSION_REQUIRED"),
        "no admitted binding must fence before authority, got {response:?}"
    );
    // Copied connection ID on a live broker pipe: the typed session check
    // fires with its distinct code (no process gateway is configured in this
    // composition, so only the pre-gateway rejections are reachable here).
    let forged = broker_admission(
        &session,
        "t79-exec-forged",
        SessionId::new(session.connection_id.clone()).expect("forged session"),
    );
    let response = kernel
        .execute_process_request(&session, expected, ProcessExecutionRequest::Start(forged))
        .await;
    assert!(
        matches!(response, ProcessExecutionResponse::Rejected(ref rejection) if rejection.code == "STALE_PROCESS_SESSION"),
        "copied connection ID must carry the stale-session code, got {response:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(windows)]
#[test]
fn eliotd_generation_start_crosses_frame_gateway() {
    let root = temp_root("gate-eliotd");
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = open_kernel(&root);
    drive_ready(&kernel);
    let launch = super::test_daemon_launch(&root);
    *kernel
        .daemon_active_launch
        .lock()
        .expect("daemon launch lock") = Some(launch.clone());
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    assert_eq!(
        policy.module_generation.module_id.as_str(),
        crate::ACTIVE_DAEMON_CALLER,
        "test composition serves the daemon caller"
    );
    let peer = PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
            .expect("process binding"),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .expect("peer");
    let session = Session {
        connection_id: "t79-eliotd-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer,
        authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        module_generation: policy.module_generation.clone(),
        launch_nonce: launch.launch_nonce.as_str().to_owned(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    };
    let caller = kernel
        .admitted_process_caller_session(&session)
        .expect("admitted daemon caller");
    assert_eq!(caller.class(), ProcessSessionClass::EliotdGeneration);
    let generation =
        Generation::new(session.module_generation.generation.value()).expect("generation");
    let intent = ProcessIntent::new(
        OperationId::new("t79-eliotd-op").expect("operation"),
        ProcessTreeId::new("t79-eliotd-tree").expect("tree"),
        JobId::new("t79-eliotd-job").expect("job"),
        ImageId::new("t79-eliotd-image").expect("image"),
        caller.session_id().clone(),
        generation,
        r"C:\eliot\seed-worker.exe",
        "c".repeat(64),
        vec!["--seed".to_owned()],
        r"C:\eliot",
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .expect("environment"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4).expect("limits"),
    )
    .expect("intent");
    let admission = ProcessExecutionAdmissionRequest::new(
        crate::ACTIVE_DAEMON_CALLER,
        intent,
        ActionLeaseRef::new("t79-eliotd-lease").expect("lease"),
        FencingToken::new(
            session.authority_epoch.clone(),
            generation,
            "t79-eliotd-fence",
        )
        .expect("fence"),
        4_000_000_000_000u64,
    )
    .expect("admission");
    let frame = start_frame(&session, &admission);
    match kernel.dispatch_frame(&session, &frame) {
        Ok(KernelFrameAction::Process { request, .. }) => {
            assert_eq!(
                request.operation_id().expect("operation").as_str(),
                "t79-eliotd-op"
            );
        }
        other => panic!("admitted daemon Start must cross the gateway, got {other:?}"),
    }
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}
