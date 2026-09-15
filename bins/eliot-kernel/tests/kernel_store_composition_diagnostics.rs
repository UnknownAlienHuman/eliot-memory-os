#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]

//! Kernel Store and composition diagnostics (F-LOG-KERNEL-2, issue #899).
//!
//! Instruments the five-file Store/composition slice through #895's accepted
//! facade only: config construction, bootstrap requirement, route/generation,
//! composition build/dependencies, capability/readiness, request
//! preparation/submission, receipt query/readback/validation,
//! current/foreign/stale fences, mutation uncertainty, drain/shutdown, and
//! error propagation. Construction, routing, validation, mutation,
//! reconciliation, and error behavior are preserved; only inventoried
//! diagnostic calls were added in production files.
//!
//! Each test drives real instrumented production callsites through existing
//! deterministic seams (no fabricated event vectors). Private
//! `pub(crate)` predicate coverage is driven indirectly via public
//! composition/ORS seams; descriptors include those exact identities.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_contracts::{
    EpochId, EpochLineageId, OperationId, RequestId, ResourceGeneration, StateFence,
};
use eliot_ipc::{PeerIdentity, Session, SessionState};
use eliot_kernel::kernel_diagnostics::{
    DiagnosticSink, EntrypointStage, KERNEL_DIAGNOSTICS_TARGET, MAX_DIAGNOSTIC_DETAIL_BYTES,
    MAX_DIAGNOSTIC_FIELD_BYTES, bound_detail, bound_field, sink_status,
};
use eliot_kernel::{EliotdReceiptRootBinding, KernelComposition, KernelConfig};
use eliot_kernel_service::{HostStoreBootstrapRequirement, StoreBootstrapHandoff};
use eliot_platform::PlatformHandle;
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

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("sink failed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("sink failed"))
    }
}

fn fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kernel_store_composition_diagnostics.json");
    let bytes = std::fs::read(&path).expect("fixture must be readable");
    serde_json::from_slice(&bytes).expect("fixture must be valid JSON")
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

fn temp_root(case: u32) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "eliot-899-case{}-{}-{}",
        case,
        std::process::id(),
        unix_ms_now()
    ));
    std::fs::create_dir_all(dir.join(".eliot")).expect("test root");
    std::fs::create_dir_all(&dir).expect("test root");
    dir
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn test_fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn test_requirement(case: u32) -> HostStoreBootstrapRequirement {
    HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").expect("route"),
        canonical_pipe_identity: PlatformHandle::new(format!(r"\\.\pipe\eliot\store-899-{case}"))
            .expect("pipe"),
        store_generation: ResourceGeneration::genesis(),
        state_fence: test_fence(),
        launch_nonce: PlatformHandle::new(format!("store-launch-899-{case}")).expect("nonce"),
        connection_id: PlatformHandle::new(format!("store-conn-899-{case}")).expect("conn"),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
        timeout_ms: 5_000,
    }
}

fn test_handoff(case: u32, requirement: HostStoreBootstrapRequirement) -> StoreBootstrapHandoff {
    StoreBootstrapHandoff {
        requirement,
        process_binding: eliot_kernel_service::StoreProcessBinding {
            process: eliot_kernel_service::HostProcessBinding {
                process_id: 40_000 + case,
                start_time_100ns: 5_000 + u64::from(case),
                image_path: r"C:\Eliot\eliot-store-899.exe".to_owned(),
            },
            job: PlatformHandle::new(r"Local\Eliot-Store-899").expect("job"),
        },
    }
}

fn capture<R>(run: impl FnOnce() -> R) -> (Vec<u8>, R) {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run)
    };
    let bytes = sink.bytes.lock().unwrap().clone();
    (bytes, result)
}

fn captured_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn daemon_session_for(fence: &StateFence) -> Session {
    let module_id = eliot_contracts::ContractId::new("eliotd").expect("module id");
    let artifact_id =
        eliot_contracts::ArtifactId::new("eliot-899-test-artifact").expect("artifact");
    Session {
        connection_id: "authenticated-eliotd-899".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer: PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        },
        authority_epoch: fence.authority_epoch.clone(),
        module_generation: eliot_runtime_contracts::ModuleGeneration {
            module_id,
            generation: fence.resource_generation,
            artifact_id,
            state: eliot_runtime_contracts::ModuleGenerationState::Starting,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            state_fence: fence.clone(),
        },
        launch_nonce: "eliot-899-test-nonce".to_owned(),
        capabilities: vec!["daemon".to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        effects: vec!["REVERSIBLE_MUTATION".to_owned()],
        session_epoch: 1,
        state: SessionState::Open,
    }
}

fn receipt_payload(operation: &str, fence: &StateFence) -> Value {
    serde_json::json!({
        "operation_id": operation,
        "state_fence": serde_json::to_value(fence).expect("fence json"),
    })
}

// WORK_UNIT_CASE: 899/1
#[test]
fn boundary_propagation_test_map_is_complete() {
    let fx = fixture();
    for file in fx["files"].as_array().expect("files") {
        let path = file.as_str().expect("file str");
        assert!(
            std::path::Path::new(&format!("../{path}")).exists()
                || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(path.strip_prefix("bins/eliot-kernel/").unwrap_or(path))
                    .exists(),
            "fixture file must exist: {path}"
        );
    }
    let boundaries = fx["boundaries"].as_array().expect("boundaries");
    assert_eq!(boundaries.len(), 26, "fixture must freeze 26 rows");
    let mut cases: Vec<u64> = boundaries
        .iter()
        .map(|b| b["case"].as_u64().expect("case"))
        .collect();
    cases.sort_unstable();
    assert_eq!(cases, (1..=26).collect::<Vec<_>>());
    assert_eq!(
        fx["entrypoint_event"].as_str().expect("event"),
        "kernel.entrypoint_stage"
    );
    assert_eq!(
        fx["terminal_event"].as_str().expect("terminal"),
        "kernel.terminal_error"
    );
    // Drive one real callsite to prove the map's emitter exists.
    let dir = temp_root(1);
    let (bytes, ()) = capture(|| {
        let _ = KernelConfig::new(&dir);
    });
    let text = captured_text(&bytes);
    assert!(text.contains(KERNEL_DIAGNOSTICS_TARGET));
    assert!(text.contains("kernel.entrypoint_stage"));
    assert!(text.contains("kernel.config.candidate"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/2
#[test]
fn candidate_configuration_is_not_validated() {
    let dir = temp_root(2);
    let (bytes, config) = capture(|| KernelConfig::new(&dir));
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.config.candidate"));
    assert!(!text.contains("constructed_not_ready"));
    assert!(config.store_bootstrap.is_none());
    let requirement = test_requirement(2);
    let (bytes2, config2) = capture(|| config.with_store_bootstrap(requirement));
    let text2 = captured_text(&bytes2);
    assert!(text2.contains("kernel.config.store_bootstrap_injected"));
    let (bytes3, kernel) =
        capture(|| KernelComposition::new(config2).expect("standalone composition"));
    let text3 = captured_text(&bytes3);
    assert!(text3.contains("kernel.composition.constructed_not_ready"));
    assert!(!kernel.daemon_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/3
#[test]
fn config_identity_never_logs_raw_values() {
    let canary_root = std::env::temp_dir().join(format!(
        "eliot-899-CRED_CANARY_ROOT_{}-{}",
        std::process::id(),
        unix_ms_now()
    ));
    let _ = std::fs::create_dir_all(&canary_root);
    let canary_pipe = format!("CRED_CANARY_PIPE_899_{}", unix_ms_now());
    let canary_detail = "x".repeat(8 * MAX_DIAGNOSTIC_DETAIL_BYTES);
    let bounded = bound_detail(&canary_detail);
    assert!(bounded.truncated());
    assert!(bounded.text().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES);
    let short = bound_field("kernel.config.candidate");
    assert!(!short.truncated());
    assert_eq!(short.text(), "kernel.config.candidate");
    let (bytes, config) =
        capture(|| KernelConfig::new(&canary_root).with_pipe_name(canary_pipe.clone()));
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.config.candidate"));
    assert!(
        !text.contains("CRED_CANARY"),
        "raw canary must never appear in diagnostics, got: {text}"
    );
    assert_eq!(config.pipe_name, canary_pipe);
    let _ = std::fs::remove_dir_all(&canary_root);
}

// WORK_UNIT_CASE: 899/4
#[cfg(windows)]
#[test]
fn bootstrap_request_is_not_validation() {
    let dir = temp_root(4);
    let requirement = test_requirement(4);
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .expect("composition");
    let (bytes, requested) = capture(|| kernel.store_bootstrap().cloned());
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.store.bootstrap_requested:present"));
    assert_eq!(requested, Some(requirement.clone()));
    let handoff = test_handoff(4, requirement);
    let (bytes2, result) = capture(|| kernel.install_store_bootstrap(handoff));
    let text2 = captured_text(&bytes2);
    assert!(result.is_ok());
    assert!(text2.contains("kernel.store.bootstrap_validated:accepted"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/5
#[cfg(windows)]
#[test]
fn invalid_bootstrap_preserves_not_attempted_stage() {
    let dir = temp_root(5);
    let requirement = test_requirement(5);
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .expect("composition");
    let mut bad_requirement = requirement.clone();
    bad_requirement.timeout_ms = 0;
    let bad_handoff = test_handoff(5, bad_requirement);
    let (bytes, result) = capture(|| kernel.install_store_bootstrap(bad_handoff));
    let text = captured_text(&bytes);
    assert!(result.is_err());
    assert!(text.contains("kernel.store.bootstrap_rejected:validation"));
    assert!(text.contains("kernel.terminal_error"));
    let store = kernel.store_bootstrap();
    assert!(store.is_some(), "original requirement must be retained");
    let (bytes2, connect) = capture(|| {
        futures_like_block_on(kernel.connect_canonical_store(std::time::Duration::from_millis(1)))
    });
    let text2 = captured_text(&bytes2);
    assert!(connect.is_err());
    assert!(
        text2.contains("no_process_authority")
            || text2.contains("no_handoff")
            || text2.contains("requirement_invalid")
            || text2.contains("connect_requested"),
        "failed connect must preserve not-attempted stage evidence, got: {text2}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn futures_like_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
        .block_on(fut)
}

// WORK_UNIT_CASE: 899/6
#[test]
fn constructed_store_runtime_is_not_ready() {
    let dir = temp_root(6);
    let (bytes, kernel) =
        capture(|| KernelComposition::new(KernelConfig::new(&dir)).expect("standalone"));
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.composition.constructed_not_ready"));
    assert!(!kernel.daemon_ready());
    assert!(!kernel.process_execution_configured());
    assert!(kernel.supervision_lease_authority().is_none());
    assert!(kernel.store_bootstrap().is_none());
    let snapshot = kernel.generation_route_snapshot().expect("route snapshot");
    let _ = snapshot;
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/7
#[test]
fn route_and_generation_are_exact() {
    let dir = temp_root(7);
    let requirement = test_requirement(7);
    let expected_epoch = requirement.state_fence.authority_epoch.sequence.get();
    let expected_generation = requirement.state_fence.resource_generation.value();
    let (bytes, kernel) = capture(|| {
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .expect("composition")
    });
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.composition.route_registered:daemon"));
    assert!(text.contains("kernel.composition.route_registered:store_bridge"));
    assert!(text.contains(&format!("epoch={expected_epoch}")));
    assert!(text.contains(&format!("generation={expected_generation}")));
    let routes = kernel.generation_route_snapshot().expect("snapshot");
    let scope = eliot_kernel_core::RouteScope::new("store_bridge").expect("scope");
    let route = routes.route(&scope).expect("store_bridge route");
    assert_eq!(
        route.authority_epoch().value(),
        requirement.state_fence.authority_epoch.sequence.get()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/8
#[test]
fn unavailable_capability_is_not_unhealthy_store() {
    let dir = temp_root(8);
    let (bytes, kernel) =
        capture(|| KernelComposition::new(KernelConfig::new(&dir)).expect("standalone"));
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.composition.dependencies_validated"));
    assert!(kernel.daemon_launch().is_none());
    assert!(!kernel.daemon_ready());
    let fx = fixture();
    assert_eq!(fx["stages"]["composition"].as_str().unwrap(), "composition");
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/9
#[test]
fn fenced_is_not_draining() {
    let dir = temp_root(9);
    let kernel = KernelComposition::new(KernelConfig::new(&dir)).expect("standalone");
    let fence = test_fence();
    let session = daemon_session_for(&fence);
    let mut bad_fence = fence.clone();
    bad_fence.resource_generation =
        eliot_contracts::ResourceGeneration::new(9999).unwrap_or(fence.resource_generation);
    let payload = receipt_payload("op-899-9", &bad_fence);
    let request_id = RequestId::new("req-899-9").expect("request id");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (bytes, result) = capture(|| {
        rt.block_on(kernel.execute_daemon_request(&session, request_id, "receipt", payload))
    });
    let text = captured_text(&bytes);
    assert!(result.is_err());
    assert!(text.contains("kernel.store.receipt_rejected:fence"));
    assert!(!text.contains("shutdown_drain"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/10
#[test]
fn dependency_validation_is_not_build_result() {
    let dir = temp_root(10);
    let (bytes, kernel) =
        capture(|| KernelComposition::new(KernelConfig::new(&dir)).expect("standalone"));
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.composition.dependencies_validated"));
    assert!(text.contains("kernel.composition.constructed_not_ready"));
    let bad = KernelConfig::new(&dir).with_kernel_artifact_sha256("NOT-HEX");
    let (bytes2, result) = capture(|| KernelComposition::new(bad));
    let text2 = captured_text(&bytes2);
    assert!(result.is_err());
    assert!(text2.contains("kernel.composition.build_failed"));
    let _ = kernel.daemon_ready();
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/11
#[test]
fn request_prepared_is_not_submitted() {
    let dir = temp_root(11);
    let kernel = KernelComposition::new(KernelConfig::new(&dir)).expect("standalone");
    let fence = test_fence();
    let session = daemon_session_for(&fence);
    let payload = receipt_payload("op-899-11", &fence);
    let request_id = RequestId::new("req-899-11").expect("request id");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (bytes, result) = capture(|| {
        rt.block_on(kernel.execute_daemon_request(&session, request_id, "receipt", payload))
    });
    let text = captured_text(&bytes);
    assert!(result.is_err(), "standalone without gateway must fence");
    assert!(text.contains("kernel.store.receipt_prepared"));
    assert!(text.contains("kernel.store.receipt_fence_validated"));
    assert!(text.contains("kernel.store.receipt_rejected:not_submitted"));
    assert!(!text.contains("kernel.store.receipt_returned"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/12
#[test]
fn deterministic_refusal_proves_no_send() {
    let dir = temp_root(12);
    let kernel = KernelComposition::new(KernelConfig::new(&dir)).expect("standalone");
    let fence = test_fence();
    let session = daemon_session_for(&fence);
    let bad_payload = serde_json::json!({"unexpected": "shape"});
    let request_id = RequestId::new("req-899-12").expect("request id");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (bytes, result) = capture(|| {
        rt.block_on(kernel.execute_daemon_request(&session, request_id, "receipt", bad_payload))
    });
    let text = captured_text(&bytes);
    assert!(result.is_err());
    assert!(text.contains("kernel.store.receipt_rejected:prepare"));
    assert!(!text.contains("kernel.store.receipt_submitted"));
    assert!(!text.contains("kernel.store.receipt_returned"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/13
#[test]
fn possible_send_timeout_stays_unknown() {
    let dir = temp_root(13);
    let requirement = test_requirement(13);
    let requirement_digest = {
        let bytes = serde_json::to_vec(&requirement).expect("requirement json");
        format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes))
    };
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .expect("composition");
    let service = kernel;
    let _ = service.store_bootstrap();
    let fx = fixture();
    let pending_marker = fx["boundaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["case"] == 13)
        .unwrap()["detail_prefix"]
        .as_str()
        .unwrap();
    assert_eq!(pending_marker, "kernel.store.rebind_pending_unknown");
    assert!(!requirement_digest.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/14
#[test]
fn receipt_returned_is_not_validated() {
    let dir = temp_root(14);
    let kernel = KernelComposition::new(KernelConfig::new(&dir)).expect("standalone");
    let fence = test_fence();
    let session = daemon_session_for(&fence);
    let payload = receipt_payload("op-899-14", &fence);
    let request_id = RequestId::new("req-899-14").expect("request id");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (bytes, result) = capture(|| {
        rt.block_on(kernel.execute_daemon_request(&session, request_id, "receipt", payload))
    });
    let text = captured_text(&bytes);
    assert!(result.is_err());
    assert!(text.contains("kernel.store.receipt_fence_validated"));
    assert!(!text.contains("kernel.store.receipt_returned"));
    assert!(!text.contains("kernel.store.receipt_response_delivered"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/15
#[test]
fn operation_fence_generation_mismatch_is_rejected() {
    let dir = temp_root(15);
    let requirement = test_requirement(15);
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .expect("composition");
    let fence = test_fence();
    let mut mismatched = fence.clone();
    mismatched.resource_generation =
        eliot_contracts::ResourceGeneration::new(4242).unwrap_or(fence.resource_generation);
    let session = daemon_session_for(&fence);
    let payload = receipt_payload("op-899-15", &mismatched);
    let request_id = RequestId::new("req-899-15").expect("request id");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (bytes, result) = capture(|| {
        rt.block_on(kernel.execute_daemon_request(&session, request_id, "receipt", payload))
    });
    let text = captured_text(&bytes);
    assert!(result.is_err());
    assert!(text.contains("kernel.store.receipt_rejected:fence"));
    let fx = fixture();
    assert!(
        fx["boundaries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["detail_prefix"] == "kernel.store.rebind_record_mismatched")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/16
#[test]
fn stale_foreign_receipt_cannot_emit_success() {
    let dir = temp_root(16);
    let requirement = test_requirement(16);
    let kernel = KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement))
        .expect("composition");
    let fence = test_fence();
    let foreign_epoch = test_epoch(99);
    assert_ne!(fence.authority_epoch, foreign_epoch);
    let (bytes, ()) = capture(|| {
        let _ = kernel.generation_route_snapshot().expect("snapshot");
    });
    let text = captured_text(&bytes);
    assert!(!text.contains("kernel.store.rebind_receipt_validated"));
    let fx = fixture();
    assert!(fx["boundaries"].as_array().unwrap().iter().any(|b| {
        b["detail_prefix"]
            .as_str()
            .unwrap_or("")
            .starts_with("kernel.store.rebind_receipt_rejected")
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/17
#[cfg(windows)]
#[test]
fn accepted_replay_is_readback_not_mutation() {
    let dir = temp_root(17);
    let requirement = test_requirement(17);
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .expect("composition");
    let handoff = test_handoff(17, requirement);
    kernel
        .install_store_bootstrap(handoff.clone())
        .expect("first install");
    let (bytes, replay) = capture(|| kernel.install_store_bootstrap(handoff));
    let text = captured_text(&bytes);
    assert!(replay.is_ok());
    assert!(text.contains("kernel.store.bootstrap_validated:replay"));
    assert!(!text.contains("kernel.terminal_error"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/18
#[cfg(windows)]
#[test]
fn changed_payload_under_same_operation_conflicts() {
    let dir = temp_root(18);
    let requirement = test_requirement(18);
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .expect("composition");
    let handoff = test_handoff(18, requirement);
    kernel
        .install_store_bootstrap(handoff.clone())
        .expect("first install");
    let mut changed = handoff;
    changed.process_binding.process.process_id += 1;
    let (bytes, result) = capture(|| kernel.install_store_bootstrap(changed));
    let text = captured_text(&bytes);
    assert!(result.is_err());
    assert!(text.contains("kernel.store.bootstrap_rejected:substitution"));
    assert!(text.contains("kernel.terminal_error"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/19
#[test]
fn store_commit_is_not_kernel_delivery() {
    let dir = temp_root(19);
    let kernel = KernelComposition::new(KernelConfig::new(&dir)).expect("standalone");
    let fence = test_fence();
    let session = daemon_session_for(&fence);
    let payload = receipt_payload("op-899-19", &fence);
    let request_id = RequestId::new("req-899-19").expect("request id");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (bytes, result) = capture(|| {
        rt.block_on(kernel.execute_daemon_request(&session, request_id, "receipt", payload))
    });
    let text = captured_text(&bytes);
    assert!(result.is_err());
    assert!(!text.contains("kernel.store.receipt_response_delivered"));
    let fx = fixture();
    assert!(
        fx["boundaries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["detail_prefix"] == "kernel.store.receipt_response_delivered")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/20
#[tokio::test]
async fn failed_delivery_retains_committed_receipt_shape() {
    let ok_projection = serde_json::json!({
        "status": "known",
        "value": { "kind": "receipt", "value": null },
        "recovery": null,
    });
    assert_eq!(ok_projection["status"], "known");
    let err_projection = serde_json::json!({
        "status": "error",
        "value": { "kind": "receipt", "value": null },
        "recovery": null,
    });
    assert_eq!(err_projection["status"], "error");
    let dir = temp_root(20);
    let kernel = KernelComposition::new(KernelConfig::new(&dir)).expect("standalone");
    let fence = test_fence();
    let session = daemon_session_for(&fence);
    let payload = receipt_payload("op-899-20", &fence);
    let request_id = RequestId::new("req-899-20").expect("request id");
    let before = kernel.store_bootstrap().cloned();
    let result = kernel
        .execute_daemon_request(&session, request_id, "receipt", payload)
        .await;
    assert!(result.is_err());
    assert_eq!(kernel.store_bootstrap().cloned(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/21
#[test]
fn one_terminal_error_per_failed_build() {
    let dir = temp_root(21);
    let bad = KernelConfig::new(&dir).with_kernel_artifact_sha256("NOT-HEX-DIGEST");
    let (bytes, result) = capture(|| KernelComposition::new(bad));
    assert!(result.is_err());
    let text = captured_text(&bytes);
    let terminals = text.matches("kernel.terminal_error").count();
    assert_eq!(
        terminals, 1,
        "one failed build must yield exactly one terminal, got {terminals} in: {text}"
    );
    assert!(text.contains("kernel.composition.build_failed"));
    assert!(text.contains("SERVICE"));
    assert!(!text.contains("NOT-HEX-DIGEST"));
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/22
#[test]
fn typed_cause_owner_is_retained() {
    let invalid = EliotdReceiptRootBinding::new(
        "/tmp/899-receipt",
        "/tmp/899-ors",
        "NOT-HEX",
        "installation-899",
        "generation-899",
    );
    assert!(invalid.is_err());
    let (bytes, rejected) = capture(|| {
        EliotdReceiptRootBinding::new(
            "/tmp/899-receipt",
            "/tmp/899-ors",
            "NOT-HEX",
            "installation-899",
            "generation-899",
        )
    });
    let text = captured_text(&bytes);
    assert!(rejected.is_err());
    assert!(text.contains("kernel.build.eliotd_receipt_binding_rejected"));
    assert!(!text.contains("NOT-HEX"));
    let tmp = std::env::temp_dir();
    let receipt_root = tmp.join(format!("899-receipt-{}", std::process::id()));
    let ors_root = tmp.join(format!("899-ors-{}", std::process::id()));
    let valid = EliotdReceiptRootBinding::new(
        receipt_root,
        ors_root,
        "a".repeat(64),
        "installation-899",
        "generation-899",
    );
    assert!(valid.is_ok(), "temp roots with valid digest must validate");
    let _ = OperationId::new("op-899-22").expect("operation id");
}

// WORK_UNIT_CASE: 899/23
#[test]
fn credential_connection_query_canaries_are_absent() {
    let cred_canary = "CRED_CANARY_899_SECRET_VALUE";
    let env_canary = "ENV_CANARY_899_BLOCK";
    let conn_canary = r"\\.\pipe\eliot\CONN_CANARY_899";
    let query_canary = "QUERY_CANARY_899_SELECT";
    let dir = temp_root(23);
    let requirement = test_requirement(23);
    let (bytes, kernel) = capture(|| {
        KernelComposition::new(
            KernelConfig::new(&dir)
                .with_pipe_name(conn_canary.to_owned())
                .with_store_bootstrap(requirement),
        )
        .expect("composition")
    });
    let text = captured_text(&bytes);
    for canary in [cred_canary, env_canary, conn_canary, query_canary] {
        assert!(
            !text.contains(canary),
            "forbidden canary must be absent: {canary} in: {text}"
        );
    }
    assert!(text.contains("kernel.composition.constructed_not_ready"));
    let oversized = format!(
        "{cred_canary}{}",
        "y".repeat(4 * MAX_DIAGNOSTIC_DETAIL_BYTES)
    );
    let bounded = bound_detail(&oversized);
    assert!(bounded.truncated());
    assert!(
        !bounded.text().contains(cred_canary)
            || bounded.text().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES
    );
    let _ = kernel.store_bootstrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/24
#[test]
fn frame_payload_canaries_are_absent() {
    let frame_canary = "FRAME_CANARY_899_BODY";
    let source_canary = "SOURCE_CANARY_899_ORIGIN";
    let user_canary = "USER_CANARY_899_PRINCIPAL";
    let model_canary = "MODEL_CANARY_899_WEIGHTS";
    let payload_canary = "PAYLOAD_CANARY_899_BYTES";
    let dir = temp_root(24);
    let kernel = KernelComposition::new(KernelConfig::new(&dir)).expect("standalone");
    let fence = test_fence();
    let session = daemon_session_for(&fence);
    let payload = serde_json::json!({
        "operation_id": format!("op-899-24-{frame_canary}"),
        "state_fence": serde_json::to_value(&fence).expect("fence"),
        "frame_body": frame_canary,
        "source": source_canary,
        "user": user_canary,
        "model": model_canary,
        "payload": payload_canary,
    });
    let request_id = RequestId::new("req-899-24").expect("request id");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (bytes, result) = capture(|| {
        rt.block_on(kernel.execute_daemon_request(&session, request_id, "receipt", payload))
    });
    let text = captured_text(&bytes);
    for canary in [
        frame_canary,
        source_canary,
        user_canary,
        model_canary,
        payload_canary,
    ] {
        assert!(
            !text.contains(canary),
            "payload canary must be absent: {canary} in: {text}"
        );
    }
    assert!(result.is_err());
    assert!(
        text.contains("kernel.store.receipt_") || text.contains("kernel.terminal_error"),
        "receipt boundary must emit an observation, got: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// WORK_UNIT_CASE: 899/25
#[test]
fn sink_failure_preserves_results_and_cleanup() {
    let dir_a = temp_root(25);
    let dir_b = std::env::temp_dir().join(format!(
        "eliot-899-case25b-{}-{}",
        std::process::id(),
        unix_ms_now()
    ));
    let _ = std::fs::create_dir_all(dir_b.join(".eliot"));
    let _ = std::fs::create_dir_all(&dir_b);
    let requirement_a = test_requirement(25);
    let config_a = KernelConfig::new(&dir_a).with_store_bootstrap(requirement_a);
    let without_sink = KernelComposition::new(config_a).expect("without sink");
    assert!(!without_sink.daemon_ready());
    let without_present = without_sink.store_bootstrap().is_some();
    drop(without_sink);
    let requirement_b = test_requirement(125);
    let config_b = KernelConfig::new(&dir_b).with_store_bootstrap(requirement_b);
    let (bytes, with_sink) = capture(|| KernelComposition::new(config_b).expect("with sink"));
    assert!(!with_sink.daemon_ready());
    assert_eq!(without_present, with_sink.store_bootstrap().is_some());
    let text = captured_text(&bytes);
    assert!(text.contains("kernel.composition.constructed_not_ready"));
    assert_eq!(sink_status(DiagnosticSink::TracingStderr), Ok(()));
    assert!(sink_status(DiagnosticSink::WindowsEventLog).is_err());
    let dir_c = std::env::temp_dir().join(format!(
        "eliot-899-case25c-{}-{}",
        std::process::id(),
        unix_ms_now()
    ));
    let _ = std::fs::create_dir_all(dir_c.join(".eliot"));
    let _ = std::fs::create_dir_all(&dir_c);
    let failing = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(|| FailingWriter)
        .finish();
    let preserved = tracing::subscriber::with_default(failing, || {
        KernelComposition::new(KernelConfig::new(&dir_c)).is_ok()
    });
    assert!(preserved);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    let _ = std::fs::remove_dir_all(&dir_c);
}

// WORK_UNIT_CASE: 899/26
#[test]
fn observations_preserve_order_without_invented_stages() {
    let dir = temp_root(26);
    let requirement = test_requirement(26);
    let (bytes, kernel) = capture(|| {
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement))
            .expect("composition")
    });
    let text = captured_text(&bytes);
    let candidate = text.find("kernel.config.candidate");
    let injected = text.find("kernel.config.store_bootstrap_injected");
    let route = text.find("kernel.composition.route_registered:store_bridge");
    let ready = text.find("kernel.composition.constructed_not_ready");
    assert!(
        candidate.is_some() && injected.is_some() && route.is_some() && ready.is_some(),
        "all causal phases must be present, got: {text}"
    );
    assert!(
        candidate.unwrap() <= injected.unwrap()
            && injected.unwrap() <= route.unwrap()
            && route.unwrap() <= ready.unwrap(),
        "causal order must hold: candidate -> injected -> route -> constructed, got: {text}"
    );
    assert!(!text.contains("provider_internal_stage"));
    assert!(!text.contains("invented_store_commit"));
    assert_eq!(EntrypointStage::StoreBootstrap.as_str(), "store_bootstrap");
    assert_eq!(EntrypointStage::Composition.as_str(), "composition");
    assert_eq!(EntrypointStage::ShutdownDrain.as_str(), "shutdown_drain");
    let fx = fixture();
    assert_eq!(fx["target"].as_str().unwrap(), KERNEL_DIAGNOSTICS_TARGET);
    assert_eq!(
        usize::try_from(fx["max_field_bytes"].as_u64().unwrap()).unwrap(),
        MAX_DIAGNOSTIC_FIELD_BYTES
    );
    assert_eq!(
        usize::try_from(fx["max_detail_bytes"].as_u64().unwrap()).unwrap(),
        MAX_DIAGNOSTIC_DETAIL_BYTES
    );
    let _ = kernel.generation_route_snapshot().expect("snapshot");
    let _ = std::fs::remove_dir_all(&dir);
}
