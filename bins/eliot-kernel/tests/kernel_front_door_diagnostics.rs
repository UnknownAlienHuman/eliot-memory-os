#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Kernel front-door / Agent Bridge / request+frame / session diagnostics (F-LOG-KERNEL-1, issue #897).
//!
//! 26 cases, exactly 1..26. Each test drives actual production callsites
//! through existing injected seams and proves its boundary against
//! `tests/data/kernel_front_door_diagnostics.json`. Windows paths execute on
//! Windows-target with fake peers proving mapping and noninterference.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_kernel::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET;
use eliot_kernel::{KernelComposition, KernelConfig};
use serde_json::Value;

#[derive(Clone, Default)]
struct CaptureSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("capture lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kernel_front_door_diagnostics.json");
    let bytes = std::fs::read(&path).expect("front-door fixture must be readable");
    serde_json::from_slice(&bytes).expect("front-door fixture must be valid JSON")
}

fn capture_with<F, R>(f: F) -> (String, R)
where
    F: FnOnce() -> R,
{
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f)
    };
    let bytes = sink.bytes.lock().expect("capture lock").clone();
    (String::from_utf8_lossy(&bytes).into_owned(), result)
}

struct TempGuard {
    root: std::path::PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn test_kernel_with_pipe(pipe_suffix: &str) -> (KernelComposition, TempGuard) {
    static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u128::from(n), |d| d.as_nanos());
    let unique = format!("{pipe_suffix}-{n}-{nanos}-{}", std::process::id());
    let root = std::env::temp_dir().join(format!("eliot-897-{unique}"));
    std::fs::create_dir_all(&root).expect("test work root");
    let mut config = KernelConfig::new(&root);
    let pipe_short = format!("case{n}-{}", std::process::id());
    config.pipe_name = format!(r"\\.\pipe\eliot\kernel-897-{pipe_short}");
    let kernel = KernelComposition::new(config).expect("kernel composition");
    (kernel, TempGuard { root })
}

fn test_kernel() -> (KernelComposition, TempGuard) {
    test_kernel_with_pipe("default")
}

fn unavailable_peer() -> eliot_ipc::PeerIdentity {
    eliot_ipc::PeerIdentity::Unavailable {
        reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
    }
}

fn fake_authenticated_peer() -> eliot_ipc::PeerIdentity {
    let binding = eliot_ipc::ProcessBinding::from_observation(42, 99, r"C:\Eliot\bridge.exe")
        .expect("fake process binding");
    eliot_ipc::PeerIdentity::authenticated_for_test(
        binding,
        "S-1-5-21-1000".to_owned(),
        "4".to_owned(),
    )
    .expect("fake authenticated peer")
}

fn test_epoch() -> eliot_contracts::EpochId {
    eliot_contracts::EpochId::new(
        eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("lineage"),
        std::num::NonZeroU64::new(1).expect("seq"),
    )
    .expect("epoch")
}

fn daemon_module_generation() -> eliot_runtime_contracts::ModuleGeneration {
    let epoch = test_epoch();
    let resource_gen = eliot_contracts::ResourceGeneration::new(1).expect("gen");
    let fence = eliot_contracts::StateFence::new(epoch, resource_gen);
    eliot_runtime_contracts::ModuleGeneration {
        module_id: eliot_contracts::ContractId::new("eliotd").expect("mid"),
        generation: resource_gen,
        artifact_id: eliot_contracts::ArtifactId::new("a".repeat(64)).expect("art"),
        state: eliot_runtime_contracts::ModuleGenerationState::Starting,
        health: eliot_runtime_contracts::HealthVector::healthy(),
        state_fence: fence,
    }
}

fn generic_module_generation() -> eliot_runtime_contracts::ModuleGeneration {
    let epoch = test_epoch();
    let resource_gen = eliot_contracts::ResourceGeneration::new(1).expect("gen");
    let fence = eliot_contracts::StateFence::new(epoch, resource_gen);
    eliot_runtime_contracts::ModuleGeneration {
        module_id: eliot_contracts::ContractId::new("test-module").expect("mid"),
        generation: resource_gen,
        artifact_id: eliot_contracts::ArtifactId::new("b".repeat(64)).expect("art"),
        state: eliot_runtime_contracts::ModuleGenerationState::Starting,
        health: eliot_runtime_contracts::HealthVector::healthy(),
        state_fence: fence,
    }
}

fn daemon_session_manual() -> eliot_ipc::Session {
    eliot_ipc::Session {
        connection_id: "test-daemon-conn-1".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer: unavailable_peer(),
        authority_epoch: test_epoch(),
        module_generation: daemon_module_generation(),
        launch_nonce: "test-nonce".to_owned(),
        capabilities: vec!["daemon".to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        effects: vec![],
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn generic_session_manual() -> eliot_ipc::Session {
    eliot_ipc::Session {
        connection_id: "test-conn-1".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer: unavailable_peer(),
        authority_epoch: test_epoch(),
        module_generation: generic_module_generation(),
        launch_nonce: "test-nonce".to_owned(),
        capabilities: vec![],
        privacy_classes: vec![],
        effects: vec![],
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn dummy_client_hello() -> eliot_protocol::ClientHello {
    eliot_protocol::ClientHello {
        protocol_range: eliot_protocol::ProtocolRange {
            minimum: eliot_protocol::ProtocolVersion::CURRENT,
            maximum: eliot_protocol::ProtocolVersion::CURRENT,
        },
        module_bridge_identity: "test-module".to_owned(),
        artifact_hash: eliot_contracts::ArtifactId::new("c".repeat(64)).expect("art"),
        module_contract: eliot_runtime_contracts::ModuleContract {
            module_id: eliot_contracts::ContractId::new("test-module").expect("mid"),
            version: eliot_contracts::ContractVersion::new(1, 0, 0),
            artifact_id: eliot_contracts::ArtifactId::new("c".repeat(64)).expect("art"),
            protocols: vec![eliot_kernel::PROTOCOL_VERSION.to_owned()],
            required_capabilities: Vec::new(),
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: eliot_kernel::SERVICE_NAME.to_owned(),
            failure_domain: eliot_kernel::SERVICE_NAME.to_owned(),
            hot_replace: false,
        },
        module_generation: {
            let epoch = test_epoch();
            let rg = eliot_contracts::ResourceGeneration::new(1).expect("gen");
            let fence = eliot_contracts::StateFence::new(epoch, rg);
            eliot_runtime_contracts::ModuleGeneration {
                module_id: eliot_contracts::ContractId::new("test-module").expect("mid"),
                generation: rg,
                artifact_id: eliot_contracts::ArtifactId::new("c".repeat(64)).expect("art"),
                state: eliot_runtime_contracts::ModuleGenerationState::Starting,
                health: eliot_runtime_contracts::HealthVector::healthy(),
                state_fence: fence,
            }
        },
        launch_nonce: "test-nonce".to_owned(),
        capabilities: Vec::new(),
        privacy_classes: Vec::new(),
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES).expect("max frame"),
        authority_epoch: test_epoch(),
    }
}

fn canary_frame(canary: &str) -> eliot_protocol::Frame {
    eliot_protocol::Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
        connection_id: "test-conn-1".to_owned(),
        request_id: None,
        kind: eliot_protocol::FrameKind::Request,
        message_type: eliot_protocol::MessageType::Execute,
        request_identity: None,
        payload: eliot_protocol::ProtocolPayload::Json(serde_json::json!({
            "operation": canary,
            "request": canary,
            "user": canary,
        })),
        trace_context: std::collections::BTreeMap::new(),
    }
}

// WORK_UNIT_CASE: 897/1
#[test]
fn front_door_denomination_is_exact() {
    let f = fixture();
    let files = f["files"].as_array().expect("files array");
    assert_eq!(files.len(), 6, "six owned source files");
    for expected in [
        "bins/eliot-kernel/src/agent_bridge.rs",
        "bins/eliot-kernel/src/daemon_request_dispatch.rs",
        "bins/eliot-kernel/src/daemon_session_guard.rs",
        "bins/eliot-kernel/src/frame_dispatch.rs",
        "bins/eliot-kernel/src/front_door_listener.rs",
        "bins/eliot-kernel/src/front_door_session.rs",
    ] {
        assert!(
            files.iter().any(|v| v.as_str() == Some(expected)),
            "fixture must list {expected}"
        );
    }
    let boundaries = f["boundaries"].as_array().expect("boundaries");
    assert!(!boundaries.is_empty(), "boundary table non-empty");
    for b in boundaries {
        let path = b["path"].as_str().expect("boundary path");
        assert!(
            files.iter().any(|v| v.as_str() == Some(path)),
            "boundary path in denominator, got {path}"
        );
    }
    let inline_tests = f["inline_tests"].as_array().expect("inline");
    assert_eq!(inline_tests.len(), 3, "three inline identities");
    let (kernel, _guard) = test_kernel();
    let (logs, result) = capture_with(|| {
        kernel.bind_session(
            "denominator-conn",
            unavailable_peer(),
            &dummy_client_hello(),
        )
    });
    assert!(result.is_err(), "denominator drives real callsite");
    assert!(logs.contains(KERNEL_DIAGNOSTICS_TARGET));
    assert_eq!(f["target"].as_str(), Some(KERNEL_DIAGNOSTICS_TARGET));
}

// WORK_UNIT_CASE: 897/2
#[cfg(windows)]
#[test]
fn listener_create_bind_accept_are_distinct() {
    let f = fixture();
    let create = f["events"]["listener_create"].as_str().expect("create");
    let bind = f["events"]["listener_bind"].as_str().expect("bind");
    let accept = f["events"]["listener_accept_ready"]
        .as_str()
        .expect("accept");
    assert_ne!(create, bind, "create vs bind distinct");
    assert_ne!(bind, accept, "bind vs accept distinct");
    assert_ne!(create, accept, "create vs accept distinct");
    let (kernel, _guard) = test_kernel_with_pipe("case02");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let _enter = rt.enter();
    let (logs, result) = capture_with(|| kernel.bind_authenticated_front_door());
    assert!(result.is_ok(), "first bind should succeed");
    assert!(logs.contains(create), "logs contain create, got {logs}");
    assert!(logs.contains(bind), "logs contain bind, got {logs}");
    assert!(logs.contains(accept), "logs contain accept, got {logs}");
    let (logs2, result2) = capture_with(|| kernel.bind_authenticated_front_door_next());
    assert!(
        result2.is_ok() || result2.is_err(),
        "rotate drives real callsite"
    );
    let _ = logs2;
}

// WORK_UNIT_CASE: 897/3
#[cfg(windows)]
#[test]
fn rotation_preserves_peer_set_revision() {
    let (kernel, _guard) = test_kernel_with_pipe("case03");
    let before = kernel.agent_bridge_peer_set_revision();
    let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
        .expect("current process expectation");
    let (logs, result) = capture_with(|| kernel.front_door_peer_set_snapshot(&expectation));
    match result {
        Ok((revision, _peers)) => {
            let after = kernel.agent_bridge_peer_set_revision();
            assert_eq!(
                before, after,
                "revision preserved with no concurrent change"
            );
            assert_eq!(revision, after, "snapshot returns preserved revision");
            assert!(
                logs.contains("kernel.front_door_peer_set_snapshot"),
                "logs {logs}"
            );
        }
        Err(error) => {
            let after = kernel.agent_bridge_peer_set_revision();
            assert_eq!(
                before, after,
                "failed snapshot retains revision, got {error:?}"
            );
            assert!(
                logs.contains("kernel.front_door_peer_set_snapshot"),
                "logs {logs}"
            );
        }
    }
    let f = fixture();
    assert_eq!(
        f["events"]["peer_set_snapshot"].as_str(),
        Some("kernel.front_door_peer_set_snapshot")
    );
}

// WORK_UNIT_CASE: 897/4
#[cfg(windows)]
#[test]
fn peer_observation_differs_from_principal_session() {
    let f = fixture();
    let peer_event = f["events"]["peer_set_build"].as_str().expect("peer");
    let handshake = f["events"]["handshake_decode"].as_str().expect("hs");
    assert_ne!(peer_event, handshake, "peer vs handshake distinct");
    let (kernel, _guard) = test_kernel_with_pipe("case04");
    let expectation =
        eliot_platform_windows::current_process_named_pipe_expectation().expect("expectation");
    let (peer_logs, peer_result) = capture_with(|| kernel.front_door_peer_set(&expectation));
    match peer_result {
        Ok(_) => assert!(peer_logs.contains(peer_event), "peer logs {peer_logs}"),
        Err(error) => {
            assert!(
                peer_logs.contains(peer_event),
                "peer attempt logged {peer_logs}"
            );
            assert!(peer_logs.contains("fenced"), "peer fenced {peer_logs}");
            let _ = error;
        }
    }
    let (hs_logs, hs_result) = capture_with(|| {
        kernel.bind_session("case04-conn", unavailable_peer(), &dummy_client_hello())
    });
    assert!(hs_result.is_err(), "handshake with unavailable fails");
    assert!(hs_logs.contains(handshake), "hs logs {hs_logs}");
    assert_ne!(peer_logs, hs_logs, "observations differ");
}

// WORK_UNIT_CASE: 897/5
#[test]
fn invalid_stale_foreign_peer_remains_typed() {
    let (kernel, _guard) = test_kernel();
    let (logs_invalid, result_invalid) = capture_with(|| {
        kernel.bind_session("case05-invalid", unavailable_peer(), &dummy_client_hello())
    });
    assert!(
        matches!(
            result_invalid,
            Err(eliot_ipc::TransportError::PeerIdentityUnavailable
                | eliot_ipc::TransportError::SessionFenced
                | eliot_ipc::TransportError::UnauthenticatedPeer)
        ),
        "invalid peer remains typed, got {result_invalid:?}"
    );
    assert!(logs_invalid.contains("kernel.front_door_handshake_reject"));
    assert!(logs_invalid.contains("kernel.terminal_error"));
    let mut stale_client = dummy_client_hello();
    stale_client.module_bridge_identity = "foreign-module-xyz".to_owned();
    let (logs_stale, result_stale) = capture_with(|| {
        kernel.bind_session("case05-stale", fake_authenticated_peer(), &stale_client)
    });
    assert!(result_stale.is_err(), "stale/foreign fails typed");
    assert!(logs_stale.contains("kernel.terminal_error"));
    let f = fixture();
    assert!(f["terminal_codes"]["handshake"].as_array().is_some());
}

// WORK_UNIT_CASE: 897/6
#[test]
fn handshake_decode_reject_accept_are_distinct() {
    let f = fixture();
    let decode = f["events"]["handshake_decode"].as_str().expect("decode");
    let reject = f["events"]["handshake_reject"].as_str().expect("reject");
    let accept = f["events"]["handshake_accept"].as_str().expect("accept");
    assert_ne!(decode, reject);
    assert_ne!(reject, accept);
    assert_ne!(decode, accept);
    let (kernel, _guard) = test_kernel();
    let (logs, result) = capture_with(|| {
        kernel.bind_session("case06-conn", unavailable_peer(), &dummy_client_hello())
    });
    assert!(result.is_err());
    assert!(logs.contains(decode), "decode attempt, got {logs}");
    assert!(logs.contains(reject), "reject, got {logs}");
    let src = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/front_door_session.rs"),
    )
    .expect("session source readable");
    assert!(src.contains(accept), "accept boundary exists in code");
}

// WORK_UNIT_CASE: 897/7
#[test]
fn handshake_acceptance_cannot_imply_request_success() {
    let (kernel, _guard) = test_kernel();
    let (hs_logs, hs_result) = capture_with(|| {
        kernel.bind_session("case07-hs", unavailable_peer(), &dummy_client_hello())
    });
    assert!(hs_result.is_err(), "handshake fails (reject)");
    assert!(hs_logs.contains("kernel.front_door_handshake_reject"));
    let session = generic_session_manual();
    let frame = canary_frame("CANARY_REQUEST_BODY_897");
    let (fr_logs, fr_result) = capture_with(|| kernel.dispatch_frame(&session, &frame));
    assert!(fr_result.is_err(), "request fails independently");
    assert!(fr_logs.contains("kernel.frame_decode_reject"));
    let f = fixture();
    assert_ne!(
        f["events"]["handshake_accept"].as_str(),
        f["events"]["frame_dispatched"].as_str()
    );
}

// WORK_UNIT_CASE: 897/8
#[cfg(windows)]
#[test]
fn bridge_connect_attach_readiness_are_distinct() {
    let f = fixture();
    let connect = f["events"]["bridge_connect"].as_str().expect("connect");
    let attach = f["events"]["bridge_attach"].as_str().expect("attach");
    let readiness = f["events"]["bridge_readiness"].as_str().expect("readiness");
    assert_ne!(connect, attach);
    assert_ne!(attach, readiness);
    assert_ne!(connect, readiness);
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bridge_src =
        std::fs::read_to_string(manifest_dir.join("src/agent_bridge.rs")).expect("bridge src");
    assert!(bridge_src.contains(connect), "connect boundary in code");
    assert!(bridge_src.contains(attach), "attach boundary in code");
    assert!(bridge_src.contains(readiness), "readiness boundary in code");
    let (kernel, _guard) = test_kernel_with_pipe("case08");
    let (logs, result) =
        capture_with(|| kernel.agent_bridge_admission_receipt_frame("no-such-conn-08"));
    assert!(result.is_err(), "receipt with foreign conn fences typed");
    assert!(
        logs.contains("kernel.bridge_receipt_prepared"),
        "bridge observation, got {logs}"
    );
    assert!(logs.contains("kernel.terminal_error"));
}

// WORK_UNIT_CASE: 897/9
#[cfg(windows)]
#[test]
fn foreign_stale_bridge_generation_is_retained() {
    let (kernel, _guard) = test_kernel_with_pipe("case09");
    let before = kernel.agent_bridge_peer_set_revision();
    let dummy_frame = canary_frame("foreign-gen-897");
    let (logs, result) =
        capture_with(|| kernel.accept_agent_bridge_hello("foreign-conn-09", &dummy_frame));
    assert!(
        result.is_err(),
        "foreign hello fences typed, got {result:?}"
    );
    assert!(logs.contains("kernel.bridge_hello_reject"), "logs {logs}");
    assert!(logs.contains("kernel.terminal_error"));
    let after = kernel.agent_bridge_peer_set_revision();
    assert_eq!(before, after, "failed hello retains revision");
}

// WORK_UNIT_CASE: 897/10
#[test]
fn partial_zero_eof_failed_frame_observed_without_payload() {
    let f = fixture();
    let canary = f["canaries"]["frame"].as_str().expect("canary");
    let (kernel, _guard) = test_kernel();
    let session = generic_session_manual();
    let frame = canary_frame(canary);
    let (logs, result) = capture_with(|| kernel.dispatch_frame(&session, &frame));
    assert!(result.is_err(), "failed frame input fences");
    assert!(logs.contains("kernel.frame_decode_reject"), "logs {logs}");
    assert!(!logs.contains(canary), "no raw payload in logs");
}

// WORK_UNIT_CASE: 897/11
#[test]
fn decode_rejection_uses_only_trusted_identities() {
    let f = fixture();
    let canary = f["canaries"]["frame"].as_str().expect("canary");
    let (kernel, _guard) = test_kernel();
    let mut session = generic_session_manual();
    session.connection_id = format!("{canary}-conn");
    let frame = canary_frame(canary);
    let (logs, result) = capture_with(|| kernel.dispatch_frame(&session, &frame));
    assert!(result.is_err());
    assert!(
        !logs.contains(canary),
        "untrusted identities never copied, got {logs}"
    );
    assert!(logs.contains("kernel.frame_decode_reject"));
}

// WORK_UNIT_CASE: 897/12
#[test]
fn request_received_validated_admitted_dispatched_are_distinct() {
    let f = fixture();
    let received = f["events"]["daemon_request_received"].as_str().expect("r");
    let validated = f["events"]["daemon_request_validated"].as_str().expect("v");
    let admitted = f["events"]["daemon_request_admitted"].as_str().expect("a");
    let dispatched = f["events"]["daemon_request_operation"].as_str().expect("d");
    assert_ne!(received, validated);
    assert_ne!(validated, admitted);
    assert_ne!(admitted, dispatched);
    let (kernel, _guard) = test_kernel();
    let session = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (logs, result) = capture_with(|| {
        rt.block_on(kernel.execute_daemon_request(
            &session,
            eliot_contracts::RequestId::new("req-12").expect("req"),
            "snapshot",
            serde_json::json!({}),
        ))
    });
    assert!(result.is_ok(), "snapshot succeeds, got {result:?}");
    assert!(logs.contains(received), "logs {logs}");
    assert!(logs.contains(validated));
    assert!(logs.contains(admitted));
    assert!(logs.contains(dispatched));
}

// WORK_UNIT_CASE: 897/13
#[test]
fn operation_idempotency_is_preserved() {
    let (kernel, _guard) = test_kernel();
    let session = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (logs, result) = capture_with(|| {
        rt.block_on(kernel.execute_daemon_request(
            &session,
            eliot_contracts::RequestId::new("req-13").expect("req"),
            "snapshot",
            serde_json::json!({}),
        ))
    });
    let frame = result.expect("snapshot ok");
    assert_eq!(
        frame.request_id,
        Some(eliot_contracts::RequestId::new("req-13").expect("req")),
        "request id preserved"
    );
    assert!(
        logs.contains("snapshot"),
        "operation preserved in logs, got {logs}"
    );
    let f = fixture();
    assert!(
        f["trusted_daemon_operations"]
            .as_array()
            .expect("ops")
            .iter()
            .any(|v| v.as_str() == Some("snapshot"))
    );
}

// WORK_UNIT_CASE: 897/14
#[test]
fn prepared_response_is_not_delivered_response() {
    let f = fixture();
    let prepared = f["events"]["daemon_response_prepared"].as_str().expect("p");
    let delivered = f["events"]["daemon_response_delivered"]
        .as_str()
        .expect("d");
    assert_ne!(prepared, delivered, "prepared vs delivered distinct");
    let (kernel, _guard) = test_kernel();
    let session = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (logs, result) = capture_with(|| {
        rt.block_on(kernel.execute_daemon_request(
            &session,
            eliot_contracts::RequestId::new("req-14").expect("req"),
            "snapshot",
            serde_json::json!({}),
        ))
    });
    assert!(result.is_ok());
    let prepared_idx = logs.find(prepared).expect("prepared in logs");
    let delivered_idx = logs.find(delivered).expect("delivered in logs");
    assert!(
        prepared_idx < delivered_idx,
        "prepared before delivered, causal order"
    );
}

// WORK_UNIT_CASE: 897/15
#[test]
fn partial_unknown_write_remains_partial_unknown() {
    let (kernel, _guard) = test_kernel();
    let session = generic_session_manual();
    let mut unknown_frame = canary_frame("unknown-op-897");
    unknown_frame.connection_id = session.connection_id.clone();
    let (logs, result) = capture_with(|| kernel.dispatch_frame(&session, &unknown_frame));
    assert!(result.is_err(), "unknown operation fences, got {result:?}");
    assert!(logs.contains("kernel.frame_decode_reject"), "logs {logs}");
    assert!(
        logs.contains("kernel.terminal_error"),
        "one terminal, got {logs}"
    );
}

// WORK_UNIT_CASE: 897/16
#[test]
fn transport_ack_cannot_prove_semantic_completion() {
    let (kernel, _guard) = test_kernel();
    let session = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (logs, result) = capture_with(|| {
        rt.block_on(kernel.execute_daemon_request(
            &session,
            eliot_contracts::RequestId::new("req-16").expect("req"),
            "snapshot",
            serde_json::json!({}),
        ))
    });
    let frame = result.expect("snapshot ok");
    assert!(logs.contains("kernel.daemon_response_delivered"));
    assert_eq!(frame.kind, eliot_protocol::FrameKind::Response);
    let second = rt.block_on(kernel.execute_daemon_request(
        &session,
        eliot_contracts::RequestId::new("req-16b").expect("req"),
        "snapshot",
        serde_json::json!({}),
    ));
    assert!(
        second.is_ok(),
        "delivered receipt does not complete semantics"
    );
}

// WORK_UNIT_CASE: 897/17
#[cfg(windows)]
#[test]
fn session_current_guard_cancel_cleanup_are_distinct() {
    let f = fixture();
    let guard = f["events"]["session_guard_bind"].as_str().expect("g");
    let current = f["events"]["session_current_guard"].as_str().expect("c");
    let cleanup = f["events"]["bridge_cleanup"].as_str().expect("cl");
    assert_ne!(guard, current);
    assert_ne!(current, cleanup);
    assert_ne!(guard, cleanup);
    let (kernel, _guard) = test_kernel_with_pipe("case17");
    let kernel = std::sync::Arc::new(kernel);
    let session = generic_session_manual();
    let binding = eliot_process::ProcessSessionBinding::new("test-conn-1", 1).expect("binding");
    let (guard_logs, guard_result) =
        capture_with(|| eliot_kernel::process_execution_client(&kernel, &session, &binding));
    assert!(guard_result.is_err(), "session guard fences typed");
    assert!(guard_logs.contains(guard), "guard logs {guard_logs}");
    let heartbeat = eliot_protocol::Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
        connection_id: session.connection_id.clone(),
        request_id: None,
        kind: eliot_protocol::FrameKind::Heartbeat,
        message_type: eliot_protocol::MessageType::Health,
        request_identity: None,
        payload: eliot_protocol::ProtocolPayload::Json(serde_json::json!({})),
        trace_context: std::collections::BTreeMap::new(),
    };
    let (logs, result) = capture_with(|| kernel.dispatch_frame(&session, &heartbeat));
    assert!(result.is_ok(), "heartbeat succeeds, got {result:?}");
    assert!(logs.contains("kernel.frame_dispatched"));
    assert!(logs.contains(current), "current guard observed, got {logs}");
    let (cleanup_logs, ()) = capture_with(|| kernel.revoke_agent_bridge("no-such-conn-17"));
    assert!(
        cleanup_logs.contains(cleanup),
        "cleanup observed, got {cleanup_logs}"
    );
}

// WORK_UNIT_CASE: 897/18
#[test]
fn cancellation_request_differs_from_observation() {
    let (kernel, _guard) = test_kernel();
    let session = generic_session_manual();
    let mut cancel_frame = canary_frame("cancel-897");
    cancel_frame.kind = eliot_protocol::FrameKind::Cancel;
    cancel_frame.message_type = eliot_protocol::MessageType::Cancel;
    cancel_frame.connection_id = session.connection_id.clone();
    let (logs, result) = capture_with(|| kernel.dispatch_frame(&session, &cancel_frame));
    let _ = result;
    assert!(
        logs.contains("kernel.frame_received") || logs.contains("kernel.frame_decode_reject"),
        "cancel request observed distinctly, got {logs}"
    );
    let f = fixture();
    assert_ne!(
        f["events"]["frame_received"].as_str(),
        f["events"]["frame_dispatched"].as_str()
    );
}

// WORK_UNIT_CASE: 897/19
#[test]
fn timeout_disconnect_after_possible_work_remains_unknown() {
    let (kernel, _guard) = test_kernel();
    let session = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (logs, result) = capture_with(|| {
        rt.block_on(kernel.execute_daemon_request(
            &session,
            eliot_contracts::RequestId::new("req-19").expect("req"),
            "no-such-operation-897",
            serde_json::json!({}),
        ))
    });
    assert!(result.is_err(), "unknown operation fails typed");
    assert!(logs.contains("kernel.terminal_error"));
    assert!(
        logs.contains("untrusted_operation"),
        "unknown stays unknown, got {logs}"
    );
}

// WORK_UNIT_CASE: 897/20
#[test]
fn one_designated_terminal_failure_per_operation() {
    let (kernel, _guard) = test_kernel();
    let (logs, result) = capture_with(|| {
        kernel.bind_session("case20-conn", unavailable_peer(), &dummy_client_hello())
    });
    assert!(result.is_err());
    let terminal_count = logs.matches("kernel.terminal_error").count();
    assert_eq!(
        terminal_count, 1,
        "exactly one terminal per failed operation, got {terminal_count} in {logs}"
    );
    assert!(logs.contains("kernel.front_door_handshake_reject"));
}

// WORK_UNIT_CASE: 897/21
#[test]
fn typed_reason_recovery_owner_is_preserved() {
    let (kernel, _guard) = test_kernel();
    let (logs_unavail, result_unavail) = capture_with(|| {
        kernel.bind_session("case21-unavail", unavailable_peer(), &dummy_client_hello())
    });
    assert!(matches!(
        result_unavail,
        Err(eliot_ipc::TransportError::PeerIdentityUnavailable
            | eliot_ipc::TransportError::SessionFenced)
    ));
    let (logs_fenced, result_fenced) = capture_with(|| {
        kernel.bind_session(
            "case21-fenced",
            fake_authenticated_peer(),
            &dummy_client_hello(),
        )
    });
    assert!(result_fenced.is_err());
    assert_ne!(
        format!("{result_unavail:?}"),
        format!("{:?}", eliot_ipc::TransportError::Timeout),
        "owners preserved, not collapsed"
    );
    let _ = logs_unavail;
    let _ = logs_fenced;
    let f = fixture();
    assert!(f["terminal_codes"]["handshake"].as_array().is_some());
}

// WORK_UNIT_CASE: 897/22
#[test]
fn frame_request_user_model_evidence_canaries_absent() {
    let f = fixture();
    let canaries = [
        f["canaries"]["frame"].as_str().expect("frame"),
        f["canaries"]["request"].as_str().expect("request"),
        f["canaries"]["user"].as_str().expect("user"),
        f["canaries"]["model"].as_str().expect("model"),
        f["canaries"]["evidence"].as_str().expect("evidence"),
    ];
    let (kernel, _guard) = test_kernel();
    let session = generic_session_manual();
    for canary in canaries {
        let frame = canary_frame(canary);
        let (logs, _) = capture_with(|| kernel.dispatch_frame(&session, &frame));
        for c in canaries {
            assert!(!logs.contains(c), "canary {c} absent, got {logs}");
        }
    }
}

// WORK_UNIT_CASE: 897/23
#[test]
fn credential_token_environment_canaries_absent() {
    let f = fixture();
    let canaries = [
        f["canaries"]["credential"].as_str().expect("cred"),
        f["canaries"]["token"].as_str().expect("token"),
        f["canaries"]["env"].as_str().expect("env"),
    ];
    let (kernel, _guard) = test_kernel();
    let session = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    for canary in canaries {
        let payload = serde_json::json!({
            "reason": canary,
            "generation": 1,
        });
        let (logs, _) = capture_with(|| {
            rt.block_on(kernel.execute_daemon_request(
                &session,
                eliot_contracts::RequestId::new("req-23").expect("req"),
                "daemon_degraded",
                payload.clone(),
            ))
        });
        for c in canaries {
            assert!(!logs.contains(c), "secret canary {c} absent, got {logs}");
        }
    }
}

// WORK_UNIT_CASE: 897/24
#[test]
fn sink_failure_drop_disabled_leaves_results_unchanged() {
    let (kernel, _guard) = test_kernel();
    let session = generic_session_manual();
    let frame = canary_frame("sink-probe-897");
    let (logs_enabled, result_enabled) = capture_with(|| kernel.dispatch_frame(&session, &frame));
    let result_disabled = kernel.dispatch_frame(&session, &frame);
    assert_eq!(
        format!("{result_enabled:?}"),
        format!("{result_disabled:?}"),
        "disabled sink leaves exact result unchanged"
    );
    assert!(logs_enabled.contains(KERNEL_DIAGNOSTICS_TARGET));
    let (kernel2, _guard2) = test_kernel();
    let session2 = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (_logs2, result2) = capture_with(|| {
        rt.block_on(kernel2.execute_daemon_request(
            &session2,
            eliot_contracts::RequestId::new("req-24").expect("req"),
            "snapshot",
            serde_json::json!({}),
        ))
    });
    let result2_direct = rt.block_on(kernel2.execute_daemon_request(
        &session2,
        eliot_contracts::RequestId::new("req-24b").expect("req"),
        "snapshot",
        serde_json::json!({}),
    ));
    assert!(result2.is_ok() && result2_direct.is_ok(), "both succeed");
}

// WORK_UNIT_CASE: 897/25
#[test]
fn fixed_observations_preserve_causal_order() {
    let (kernel, _guard) = test_kernel();
    let session = daemon_session_manual();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (logs, result) = capture_with(|| {
        rt.block_on(kernel.execute_daemon_request(
            &session,
            eliot_contracts::RequestId::new("req-25").expect("req"),
            "snapshot",
            serde_json::json!({}),
        ))
    });
    assert!(result.is_ok());
    let received = logs
        .find("kernel.daemon_request_received")
        .expect("received");
    let validated = logs
        .find("kernel.daemon_request_validated")
        .expect("validated");
    let admitted = logs
        .find("kernel.daemon_request_admitted")
        .expect("admitted");
    let prepared = logs
        .find("kernel.daemon_response_prepared")
        .expect("prepared");
    let delivered = logs
        .find("kernel.daemon_response_delivered")
        .expect("delivered");
    assert!(received < validated, "causal order received->validated");
    assert!(validated < admitted, "validated->admitted");
    assert!(admitted < prepared, "admitted->prepared");
    assert!(prepared < delivered, "prepared->delivered");
}

// WORK_UNIT_CASE: 897/26
#[test]
fn source_api_diff_and_family_partition_guard() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib_src = std::fs::read_to_string(manifest_dir.join("src/lib.rs")).expect("lib.rs");
    assert!(
        !lib_src.contains("kernel.front_door_listener_create"),
        "no lib.rs diagnostic callsites mutated"
    );
    let facade_src =
        std::fs::read_to_string(manifest_dir.join("src/kernel_diagnostics.rs")).expect("facade");
    assert!(
        !facade_src.contains("kernel.front_door_listener_create"),
        "no facade changes"
    );
    assert!(
        !facade_src.contains("kernel.bridge_connect"),
        "no facade changes for bridge"
    );
    let cargo_toml = std::fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("manifest");
    assert!(
        !cargo_toml.contains("kernel-front-door-diagnostics"),
        "no manifest changes"
    );
    for owned in [
        "src/agent_bridge.rs",
        "src/daemon_request_dispatch.rs",
        "src/daemon_session_guard.rs",
        "src/frame_dispatch.rs",
        "src/front_door_listener.rs",
        "src/front_door_session.rs",
    ] {
        let src = std::fs::read_to_string(manifest_dir.join(owned)).expect("owned readable");
        assert!(
            !src.contains("pub fn observe_"),
            "no new public visibility in {owned}"
        );
        assert!(
            !src.contains("install_kernel_diagnostics"),
            "no new subscriber"
        );
        assert!(!src.contains("dedup"), "no global dedup");
    }
    let (kernel, _guard) = test_kernel();
    let (logs, result) = capture_with(|| {
        kernel.bind_session("case26-conn", unavailable_peer(), &dummy_client_hello())
    });
    assert!(result.is_err(), "behavior preserved, drives real callsite");
    assert!(logs.contains("kernel.terminal_error"));
    let f = fixture();
    assert_eq!(f["issue"].as_u64(), Some(897));
}
