//! Slice A claim+readiness admission plumbing proofs (issue #22, T5-02).
//!
//! Focused acceptance proofs only. Pure cross-binding and fail-closed gates
//! run on every invocation; full admit/advance flows that require the ORS
//! `advance_native_worker_claim` state commit are marked `ignored` with the
//! exact blocker: at base `store.rs` validates the transition but never
//! applies `next.state = target`, so every non-idempotent advance fails
//! (`Requested` + receipt) or silently no-ops. That file is outside this
//! slice's owned paths (non-goal, S-ORS), so the blocked proofs are deferred
//! to the ORS owner instead of being weakened here.
//!
//! All durability uses the real ORS `redb` store (`RedbRecoveryStore::open`);
//! no fakes, no stubs, no canned receipt identities. Digests are recomputed
//! through the real canonical procedures.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex,
};
use eliot_ipc::TransportError;
use eliot_kernel_service::{
    HostKernelCandidateBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
    KernelService, KernelServiceState, NATIVE_WORKER_CLAIM_WIRE_ID,
    NATIVE_WORKER_CLAIM_WIRE_VERSION, NATIVE_WORKER_CLAIM_WIRE_VERSION_V1,
    NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
    NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION, NATIVE_WORKER_PROTOCOL_VERSION,
    NativeWorkerClaimBudget, NativeWorkerClaimRequest, NativeWorkerClaimResponse,
    NativeWorkerExecutableBinding, NativeWorkerExecutableExpectation,
};
use eliot_ors::{NativeWorkerClaimState, RedbRecoveryStore};
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};

use crate::KernelComposition;

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).expect("test handle")
}

fn live_fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn candidate_binding() -> HostKernelCandidateBinding {
    use eliot_kernel_service::{HostFileIdentity, HostJobIdentity, HostJobRoot, RestartBudget};
    HostKernelCandidateBinding {
        installation_id: handle("installation-1"),
        host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: test_epoch(1),
        activation_id: handle("activation-1"),
        artifact_hash: handle("artifact-1"),
        config_hash: handle("config-1"),
        job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
        pipe_identity: handle(eliot_kernel_service::KERNEL_CONTROL_PIPE),
        host_process: eliot_kernel_service::HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\host.exe".to_owned(),
        },
        job_binding: eliot_kernel_service::HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
            },
            root: HostJobRoot {
                process: eliot_kernel_service::HostProcessBinding {
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
                lineage_id: "watchdog-lineage-1".to_owned(),
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
        .expect("supervision incarnation"),
        restart_budget: RestartBudget::new(1, 1).expect("restart budget"),
        agent_bridge_admission: None,
        containment_action: None,
    }
}

fn ready_service() -> KernelService {
    let mut svc = KernelService::new([7; 32], 4, 8).expect("kernel service");
    let cand = candidate_binding();
    svc.reconcile(cand.clone()).expect("reconcile");
    svc.apply(KernelControlCommand::Shadow).expect("shadow");
    svc.apply(KernelControlCommand::PrepareHandoff)
        .expect("handoff");
    let permit = KernelActivationPermit {
        operation_id: handle("op-t5-02-a-1"),
        candidate_binding_digest: cand.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("txn-t5-02-a-1"),
        journal_sequence: 1,
        generation: ResourceGeneration::genesis(),
        authority_epoch: cand.kernel_epoch,
        activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
            .expect("activation nonce"),
    };
    svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
        .expect("activate");
    let ready = KernelReadyReceipt {
        activation_id: cand.activation_id.clone(),
        activation_operation_id: permit.operation_id.clone(),
        activation_nonce_digest: svc
            .activation_receipt()
            .expect("activation receipt")
            .activation_nonce_digest
            .clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: handle("pid:42:start:10"),
            job_object_id: cand.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ev-t5-02-a")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![handle("ev-t5-02-a")],
    };
    svc.publish_ready(ready).expect("publish ready");
    assert_eq!(svc.state(), KernelServiceState::Ready);
    svc
}

/// Owner-issued executable digest stand-in for these proofs.
///
/// Deterministic SHA-256 over stable seed bytes through the real hash
/// procedure — never hardcoded. Opaque to the route join, which carries it
/// and compares it for equality only; the true digest is published by the
/// Governor T9-01 owner.
fn test_owner_digest() -> String {
    sha256_hex(b"t9-02 w-b route owner-issued executable digest stand-in")
}

/// Builds one well-formed owner-produced executable join (T9-02 wire v2).
///
/// The `config_digest` is pinned to the presenting registration's
/// `worker_config_digest` (`"b".repeat(64)` in these proofs): the route
/// builds its expectation from the live registration record, so a join
/// carrying any other config is stale by construction.
fn test_executable_join() -> NativeWorkerExecutableBinding {
    let now = now_ms();
    NativeWorkerExecutableBinding {
        route_ref: "route://test/full-canonical-route".to_owned(),
        adapter_id: "adapter-test".to_owned(),
        adapter_revision: 3,
        config_digest: "b".repeat(64),
        facet_manifest_ref: "facet-manifest-7".to_owned(),
        grant_graph_revision: 5,
        replay_stream_id: "stream-claim-t9-02-1/gen-1".to_owned(),
        launch_nonce: "launch-nonce-0123456789abcdef".to_owned(),
        process_invocation_digest: "d".repeat(64),
        authority_epoch: test_epoch(1),
        generation: ResourceGeneration::genesis(),
        state_fence: live_fence(),
        deadline_unix_ms: now.saturating_add(100_000),
        expires_at_unix_ms: now.saturating_add(200_000),
        executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
        executable_binding_digest: test_owner_digest(),
    }
}

/// Builds the route's executable expectation exactly the way
/// `handle_native_worker_claim` does: owner-produced fields from the
/// presented v2 join, currentness anchors from the live registration fence,
/// the registration's worker-configuration identity, and the live epoch.
fn route_expectation(request: &NativeWorkerClaimRequest) -> NativeWorkerExecutableExpectation {
    let registration = serde_json::json!({
        "worker_config_digest": "b".repeat(64),
    });
    KernelComposition::build_executable_expectation(
        request.executable_binding.as_ref(),
        &registration,
        &live_fence(),
        &test_epoch(1),
    )
    .expect("route expectation builds")
}

/// Recomputes both claim digests after a presented-field mutation so the
/// executable gate reaches its typed currentness arm instead of stopping at
/// a stale envelope digest.
fn rebind_claim(claim: &mut NativeWorkerClaimRequest) {
    claim.binding_digest = claim.compute_binding_digest().expect("rebind binding");
    claim.request_digest = claim.canonical_request_digest().expect("rebind envelope");
}

/// Downgrades one valid v2 request to wire v1 (no join), recomputing both
/// digests so the envelope stays shape-valid: old-wire refusal must come
/// from the executable gate's typed disposition, never from a stale digest.
fn test_v1_claim_request(
    claim_id: &str,
    registration_id: &str,
    attempt_id: &str,
    operation_id: &str,
    deadline_unix_ms: u64,
) -> NativeWorkerClaimRequest {
    let mut request = test_claim_request(
        claim_id,
        registration_id,
        attempt_id,
        operation_id,
        deadline_unix_ms,
    );
    request.wire_version = NATIVE_WORKER_CLAIM_WIRE_VERSION_V1;
    request.executable_binding = None;
    rebind_claim(&mut request);
    request.validate().expect("v1 shape validates");
    request
        .validate_canonical_digest()
        .expect("v1 canonical digest validates");
    request
}

/// Builds one fully valid claim request with real computed digests.
///
/// Every bound field is filled; the binding digest is recomputed over the
/// exact presented bytes and the request digest over the envelope, so no
/// receipt identity is canned.
fn test_claim_request(
    claim_id: &str,
    registration_id: &str,
    attempt_id: &str,
    operation_id: &str,
    deadline_unix_ms: u64,
) -> NativeWorkerClaimRequest {
    let fence = live_fence();
    let mut request = NativeWorkerClaimRequest {
        wire_id: NATIVE_WORKER_CLAIM_WIRE_ID.to_owned(),
        wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
        claim_id: claim_id.to_owned(),
        registration_id: registration_id.to_owned(),
        worker_generation: 1,
        installation_id: "installation-1".to_owned(),
        worker_artifact_digest: "a".repeat(64),
        worker_config_digest: "b".repeat(64),
        protocol_version: NATIVE_WORKER_PROTOCOL_VERSION.to_owned(),
        execution_unit_schema_version: NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION,
        parent_job_id: "parent-job-1".to_owned(),
        task_id: "task-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        decision_id: "decision-1".to_owned(),
        attempt_id: attempt_id.to_owned(),
        operation_id: operation_id.to_owned(),
        route_class: "test-route".to_owned(),
        budget: NativeWorkerClaimBudget {
            context_tokens: 8,
            wall_time_ms: 1_000,
            output_bytes: 1_024,
            cost_microunits: 10,
            max_depth: 2,
            max_descendants: 4,
        },
        deadline_unix_ms,
        cancellation_policy_id: "cancel-1".to_owned(),
        expected_result_schema: "result-schema".to_owned(),
        expected_result_schema_version: 1,
        predecessor_revision: "rev-1".to_owned(),
        authority_epoch: test_epoch(1),
        state_fence: fence,
        executable_binding: Some(test_executable_join()),
        binding_digest: String::new(),
        request_digest: String::new(),
    };
    request.binding_digest = request.compute_binding_digest().expect("binding digest");
    request.request_digest = request.canonical_request_digest().expect("request digest");
    request.validate().expect("claim validates");
    request
        .validate_canonical_digest()
        .expect("canonical digest validates");
    request
}

fn temp_ors_path(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "eliot-t5-02-a-{tag}-{}-{}",
        std::process::id(),
        now_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let path = root.join("kernel-ors.redb");
    (root, path)
}

fn admitted_receipt(
    response: &NativeWorkerClaimResponse,
) -> eliot_kernel_service::NativeWorkerClaimReceipt {
    match response {
        NativeWorkerClaimResponse::Admitted(receipt) => receipt.clone(),
        other => panic!("expected Admitted, got {other:?}"),
    }
}

/// Resource envelope mirrored from the service owner for the staged-record
/// test: installation plus artifact/configuration identity, canonicalized
/// the same way before hashing.
#[derive(serde::Serialize)]
struct TestResourceEnvelope<'a> {
    installation_id: &'a str,
    worker_artifact_digest: &'a str,
    worker_config_digest: &'a str,
}

#[test]
fn typed_cross_binding_and_fail_closed_gates() {
    let now = now_ms();
    let request = test_claim_request(
        "claim-gate-1",
        "reg-gate-1",
        "attempt-1",
        "op-gate-1",
        now.saturating_add(120_000),
    );
    // Exact registration binds; foreign identity/generation/epoch/fence fail.
    request
        .validate_presented_under_registration("reg-gate-1", 1, test_epoch(1), &live_fence())
        .expect("exact registration binds");
    assert!(
        request
            .validate_presented_under_registration("reg-foreign", 1, test_epoch(1), &live_fence(),)
            .is_err(),
        "foreign registration must not bind"
    );
    assert!(
        request
            .validate_presented_under_registration("reg-gate-1", 2, test_epoch(1), &live_fence(),)
            .is_err(),
        "foreign generation must not bind"
    );
    // T9-02 executable binding: the v2 owner record passes against the live
    // registration/admission/activation/epoch records the route supplies...
    let expectation = route_expectation(&request);
    request
        .require_executable_binding(&expectation, now)
        .expect("v2 owner join passes");
    // ...while wire v1 is refused with its typed disposition, never promoted.
    let v1 = test_v1_claim_request(
        "claim-gate-v1",
        "reg-gate-1",
        "attempt-1",
        "op-gate-v1",
        now.saturating_add(120_000),
    );
    let old = v1
        .require_executable_binding(&route_expectation(&v1), now)
        .expect_err("v1 must fail closed");
    assert!(
        format!("{old:?}").contains("u1_old_wire_without_executable_binding"),
        "explicit old-wire disposition, got {old:?}"
    );
    // Claim admission never implies launch (stop S-X2).
    let receipt = eliot_kernel_service::NativeWorkerClaimReceipt {
        wire_id: NATIVE_WORKER_CLAIM_WIRE_ID.to_owned(),
        wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
        claim_id: request.claim_id.clone(),
        registration_id: request.registration_id.clone(),
        attempt_id: request.attempt_id.clone(),
        operation_id: request.operation_id.clone(),
        worker_generation: request.worker_generation,
        authority_epoch: request.authority_epoch,
        state_fence: request.state_fence.clone(),
        binding_digest: request.binding_digest.clone(),
        admitted_at_unix_ms: now,
        receipt_digest: String::new(),
    }
    .with_computed_digest()
    .expect("receipt digest");
    let admitted = NativeWorkerClaimResponse::Admitted(receipt);
    let x2 = admitted
        .require_canonical_activation()
        .expect_err("X2 must fail closed");
    assert!(
        format!("{x2:?}").contains("missing_canonical_activation"),
        "explicit X2 disposition, got {x2:?}"
    );
}

#[test]
fn route_resource_fence_and_credential_shape() {
    // Resource identity must match the presenting registration.
    let claim_json = serde_json::json!({
        "registration_id": "reg-1",
        "installation_id": "installation-1",
        "worker_artifact_digest": "a".repeat(64),
        "worker_config_digest": "b".repeat(64),
    });
    let same_reg = serde_json::json!({
        "registration_id": "reg-1",
        "installation_id": "installation-1",
        "worker_artifact_digest": "a".repeat(64),
        "worker_config_digest": "b".repeat(64),
    });
    KernelComposition::require_claim_registration_resource_binding(&claim_json, &same_reg)
        .expect("matching resource identity binds");
    let foreign_reg = serde_json::json!({
        "registration_id": "reg-1",
        "installation_id": "installation-1",
        "worker_artifact_digest": "f".repeat(64),
        "worker_config_digest": "b".repeat(64),
    });
    assert!(
        KernelComposition::require_claim_registration_resource_binding(&claim_json, &foreign_reg)
            .is_err(),
        "foreign artifact must not bind"
    );
    // Presenting fence digest matches itself and differs on a changed fence.
    let digest = KernelComposition::presenting_fence_digest(&live_fence()).expect("fence digest");
    assert_eq!(digest.len(), 64);
    let other_fence = StateFence::new(test_epoch(2), ResourceGeneration::genesis());
    let other = KernelComposition::presenting_fence_digest(&other_fence).expect("other digest");
    assert_ne!(digest, other, "changed fence must change its digest");
    // Credential references carry only provider/key; secret smuggling fails.
    let good = vec![
        serde_json::json!({"provider": "prov-a", "key": "key-a"}),
        serde_json::json!({"provider": "prov-b", "key": "key-b"}),
    ];
    KernelComposition::validate_credential_refs_shape(&good).expect("references pass");
    let smuggled = vec![serde_json::json!({
        "provider": "prov-a",
        "key": "key-a",
        "secret": "TOP-SECRET-MATERIAL",
    })];
    assert!(
        KernelComposition::validate_credential_refs_shape(&smuggled).is_err(),
        "secret material must never pass as a credential reference"
    );
}

#[test]
fn stage_persists_requested_row_with_real_store() {
    use eliot_contracts::{canonical_json_bytes, sha256_hex};
    let now = now_ms();
    let request = test_claim_request(
        "claim-stage-1",
        "reg-stage-1",
        "attempt-1",
        "op-stage-1",
        now.saturating_add(120_000),
    );
    let budget_digest = sha256_hex(&canonical_json_bytes(&request.budget).expect("budget"));
    let fence_digest = sha256_hex(&canonical_json_bytes(&request.state_fence).expect("fence"));
    let resource_envelope_digest = sha256_hex(
        &canonical_json_bytes(&TestResourceEnvelope {
            installation_id: &request.installation_id,
            worker_artifact_digest: &request.worker_artifact_digest,
            worker_config_digest: &request.worker_config_digest,
        })
        .expect("resource envelope"),
    );
    let record = eliot_ors::NativeWorkerClaimRecord {
        contract_version: eliot_ors::CONTRACT_VERSION,
        claim_id: eliot_ors::OperationIdentity::new(request.claim_id.as_str()).expect("claim"),
        registration_id: eliot_ors::OpaqueLabel::new(request.registration_id.as_str())
            .expect("reg"),
        worker_generation: request.worker_generation,
        parent_job_id: eliot_ors::OpaqueLabel::new(request.parent_job_id.as_str()).expect("parent"),
        task_id: eliot_ors::OpaqueLabel::new(request.task_id.as_str()).expect("task"),
        work_scope_id: eliot_ors::OpaqueLabel::new(request.work_scope_id.as_str()).expect("scope"),
        decision_id: eliot_ors::OpaqueLabel::new(request.decision_id.as_str()).expect("decision"),
        attempt_id: eliot_ors::OpaqueLabel::new(request.attempt_id.as_str()).expect("attempt"),
        operation_id: eliot_ors::OpaqueLabel::new(request.operation_id.as_str()).expect("op"),
        route_class: eliot_ors::OpaqueLabel::new(request.route_class.as_str()).expect("route"),
        budget_digest,
        deadline_unix_ms: request.deadline_unix_ms,
        fence_digest,
        authority_epoch: request.authority_epoch.sequence.get(),
        binding_digest: request.binding_digest.clone(),
        request_digest: request.request_digest.clone(),
        execution_unit_schema_version: request.execution_unit_schema_version,
        predecessor_revision: eliot_ors::OpaqueLabel::new(request.predecessor_revision.as_str())
            .expect("pred"),
        resource_envelope_digest,
        state: NativeWorkerClaimState::Requested,
        receipt_digest: None,
        admitted_at_unix_ms: None,
        commit_order: 0,
    };
    record.validate().expect("staged record validates");
    let (root, path) = temp_ors_path("stage");
    let store = RedbRecoveryStore::open(&path).expect("open ORS");
    let stored = store
        .stage_native_worker_claim(&record)
        .expect("stage persists");
    assert_eq!(stored.record().state, NativeWorkerClaimState::Requested);
    drop(store);
    // Close and reopen the real store: the staged row survives (persist-before-ack half).
    let reopened = RedbRecoveryStore::open(&path).expect("reopen ORS");
    let loaded = reopened
        .load_native_worker_claim(&eliot_ors::OperationIdentity::new("claim-stage-1").expect("id"))
        .expect("load")
        .expect("durable row");
    assert!(
        loaded.same_binding(&record),
        "durable row keeps exact binding"
    );
    assert_eq!(loaded.state, NativeWorkerClaimState::Requested);
    assert_eq!(loaded.receipt_digest, None);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn unknown_never_becomes_unclaimed_and_terminal_never_regresses() {
    // Mechanical transition table: Unknown only becomes Reconciling, Terminal absorbs.
    assert!(
        NativeWorkerClaimState::Unknown
            .transition_to(NativeWorkerClaimState::Requested)
            .is_err(),
        "Unknown must never become unclaimed"
    );
    assert!(
        NativeWorkerClaimState::Unknown
            .transition_to(NativeWorkerClaimState::Reconciling)
            .is_ok(),
        "Unknown reconciles only"
    );
    for target in [
        NativeWorkerClaimState::Requested,
        NativeWorkerClaimState::Admitted,
        NativeWorkerClaimState::Ready,
        NativeWorkerClaimState::Active,
        NativeWorkerClaimState::Cancelling,
        NativeWorkerClaimState::Submitted,
        NativeWorkerClaimState::Unknown,
        NativeWorkerClaimState::Reconciling,
    ] {
        assert!(
            NativeWorkerClaimState::Terminal
                .transition_to(target)
                .is_err(),
            "Terminal must never regress"
        );
    }
    // Unknown identities stay unknown at the store boundary: advance invents nothing.
    let (root, path) = temp_ors_path("unknown-terminal");
    let store = RedbRecoveryStore::open(&path).expect("open ORS");
    let unknown = store
        .advance_native_worker_claim(
            &eliot_ors::OperationIdentity::new("claim-absent-1").expect("identity"),
            NativeWorkerClaimState::Reconciling,
            None,
        )
        .expect("advance unknown");
    assert!(
        unknown.is_none(),
        "unknown claim must stay unknown, never invented"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn claim_join_mints_no_process_request_or_permit() {
    // Source-level proof: the lifecycle route mints no process request outside
    // the pre-existing #100 Cancel path. Minting patterns use `::`, `{`, or
    // `(` after the type name; bare mentions in docs do not count.
    let route_src = include_str!("../native_worker_lifecycle_route.rs");
    for pattern in [
        "ProcessRequest::",
        "ProcessRequest {",
        "ProcessRequest(",
        "ProcessRequest::new",
    ] {
        assert!(
            !route_src.contains(pattern),
            "lifecycle route must not mint process requests ({pattern})"
        );
    }
    assert!(
        !route_src.contains("DispatchPermit"),
        "claim plumbing must not mint dispatch permits"
    );
    assert!(
        !route_src.contains("CapabilityGrant"),
        "claim plumbing must not mint capability grants"
    );
    assert!(
        !route_src.contains("activate_permit"),
        "claim plumbing must not consume activation permits"
    );
    assert!(
        route_src.contains("ProcessExecutionRequest::Cancel"),
        "only the pre-existing #100 Cancel path may reference process execution"
    );
    // Typed proof: the claim response exposes no launch authority constructor.
    let now = now_ms();
    let request = test_claim_request(
        "claim-nomint-1",
        "reg-nomint-1",
        "attempt-1",
        "op-nomint-1",
        now.saturating_add(60_000),
    );
    let receipt = eliot_kernel_service::NativeWorkerClaimReceipt {
        wire_id: NATIVE_WORKER_CLAIM_WIRE_ID.to_owned(),
        wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
        claim_id: request.claim_id.clone(),
        registration_id: request.registration_id.clone(),
        attempt_id: request.attempt_id.clone(),
        operation_id: request.operation_id.clone(),
        worker_generation: request.worker_generation,
        authority_epoch: request.authority_epoch,
        state_fence: request.state_fence.clone(),
        binding_digest: request.binding_digest.clone(),
        admitted_at_unix_ms: now,
        receipt_digest: String::new(),
    }
    .with_computed_digest()
    .expect("receipt digest");
    let response = NativeWorkerClaimResponse::Admitted(receipt);
    assert!(response.require_canonical_activation().is_err());
}

// --- Full-flow proofs (ORS owner fix S-ORS has landed) ---
//
// These proofs once stayed `ignored` because at their base
// `crates/kernel/eliot-ors/src/store.rs` `advance_native_worker_claim`
// validated the transition but never applied `next.state = target`. The
// owner has since landed the one-line commit, so they run on every
// invocation against the real store.

#[test]
fn identical_claim_replays_same_receipt_across_close_reopen() {
    let (root, path) = temp_ors_path("replay");
    let now = now_ms();
    let deadline = now.saturating_add(120_000);
    let request = test_claim_request(
        "claim-replay-1",
        "reg-replay-1",
        "attempt-1",
        "op-replay-1",
        deadline,
    );

    let svc = ready_service();
    let first = {
        let store = RedbRecoveryStore::open(&path).expect("open ORS");
        let response = svc
            .admit_native_worker_claim(&store, &request, now)
            .expect("first admit");
        let receipt = admitted_receipt(&response);
        receipt.validate().expect("receipt validates");
        receipt.receipt_digest.clone()
    };
    let second = {
        let reopened = RedbRecoveryStore::open(&path).expect("reopen ORS");
        let response = svc
            .admit_native_worker_claim(&reopened, &request, now.saturating_add(1_000))
            .expect("replay admit");
        let receipt = admitted_receipt(&response);
        receipt.validate().expect("replayed receipt validates");
        receipt.receipt_digest.clone()
    };
    assert_eq!(
        first, second,
        "identical claim must return the same logical receipt identity"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn changed_input_conflicts_with_no_effect() {
    let (root, path) = temp_ors_path("conflict");
    let now = now_ms();
    let deadline = now.saturating_add(120_000);
    let original = test_claim_request(
        "claim-conflict-1",
        "reg-conflict-1",
        "attempt-1",
        "op-a",
        deadline,
    );
    let svc = ready_service();
    let store = RedbRecoveryStore::open(&path).expect("open ORS");
    let first = admitted_receipt(
        &svc.admit_native_worker_claim(&store, &original, now)
            .expect("admit original"),
    );
    let changed = test_claim_request(
        "claim-conflict-1",
        "reg-conflict-1",
        "attempt-1",
        "op-changed",
        deadline,
    );
    assert_ne!(
        original.binding_digest, changed.binding_digest,
        "test setup must change the binding"
    );
    let response = svc
        .admit_native_worker_claim(&store, &changed, now.saturating_add(500))
        .expect("changed admit");
    match &response {
        NativeWorkerClaimResponse::Conflict(conflict) => {
            conflict.validate().expect("conflict validates");
            assert_eq!(conflict.claim_id, "claim-conflict-1");
            assert_eq!(conflict.expected_digest, first.binding_digest);
            assert_eq!(conflict.observed_digest, changed.binding_digest);
            assert!(
                !conflict.changed_fields.is_empty(),
                "conflict must name changed dimensions"
            );
            assert!(conflict.changed_fields.contains(&"operation_id".to_owned()));
        }
        other => panic!("changed input must conflict, got {other:?}"),
    }
    let durable = store
        .load_native_worker_claim(
            &eliot_ors::OperationIdentity::new("claim-conflict-1").expect("identity"),
        )
        .expect("load")
        .expect("durable row");
    assert_eq!(durable.binding_digest, first.binding_digest);
    assert_eq!(durable.operation_id.as_str(), "op-a");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn lost_acknowledgement_reconciles_original_operation() {
    let (root, path) = temp_ors_path("lost-ack");
    let now = now_ms();
    let deadline = now.saturating_add(120_000);
    let request = test_claim_request(
        "claim-lostack-1",
        "reg-lostack-1",
        "attempt-1",
        "op-orig",
        deadline,
    );
    let svc = ready_service();
    let store = RedbRecoveryStore::open(&path).expect("open ORS");
    let receipt = admitted_receipt(
        &svc.admit_native_worker_claim(&store, &request, now)
            .expect("admit"),
    );
    assert!(
        svc.reconcile_native_worker_claim_admission(&receipt, &request)
            .expect("reconcile binds"),
        "retained receipt must reconcile the original operation"
    );
    let replay = admitted_receipt(
        &svc.admit_native_worker_claim(&store, &request, now.saturating_add(700))
            .expect("replay"),
    );
    assert_eq!(receipt.receipt_digest, replay.receipt_digest);
    let retry_new = test_claim_request(
        "claim-lostack-1",
        "reg-lostack-1",
        "attempt-1",
        "op-retry-new",
        deadline,
    );
    match svc
        .admit_native_worker_claim(&store, &retry_new, now.saturating_add(800))
        .expect("retry")
    {
        NativeWorkerClaimResponse::Conflict(_) => {}
        other => panic!("retry-as-new must conflict, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stale_foreign_registration_cannot_use_retained_receipts() {
    let now = now_ms();
    let deadline = now.saturating_add(120_000);
    let request = test_claim_request(
        "claim-fence-1",
        "reg-fence-1",
        "attempt-1",
        "op-fence-1",
        deadline,
    );
    let mut stale_svc = ready_service();
    stale_svc
        .advance_authority_epoch()
        .expect("advance live epoch");
    let (root, path) = temp_ors_path("stale-epoch");
    let store = RedbRecoveryStore::open(&path).expect("open ORS");
    match stale_svc
        .admit_native_worker_claim(&store, &request, now.saturating_add(100))
        .expect("stale admit")
    {
        NativeWorkerClaimResponse::Rejected(rejection) => {
            assert_eq!(
                rejection.reason,
                eliot_kernel_service::NativeWorkerClaimRejectionReason::StaleRegistration
            );
        }
        other => panic!("stale epoch must be rejected, got {other:?}"),
    }
    let (root2, path2) = temp_ors_path("foreign-ready");
    let store2 = RedbRecoveryStore::open(&path2).expect("open ORS");
    let svc = ready_service();
    let live_request = test_claim_request(
        "claim-ready-1",
        "reg-ready-1",
        "attempt-1",
        "op-ready-1",
        deadline,
    );
    let admit = svc
        .admit_native_worker_claim(&store2, &live_request, now)
        .expect("admit");
    assert!(matches!(admit, NativeWorkerClaimResponse::Admitted(_)));
    match svc
        .mark_native_worker_ready(
            &store2,
            &live_request,
            "ready-foreign-1",
            "reg-ready-1",
            99,
            "registry-rev-1",
            &[("prov", "key")],
            now.saturating_add(10),
            now.saturating_add(20),
        )
        .expect("foreign ready")
    {
        NativeWorkerClaimResponse::Rejected(rejection) => {
            assert_eq!(
                rejection.reason,
                eliot_kernel_service::NativeWorkerClaimRejectionReason::StaleRegistration
            );
        }
        other => panic!("foreign generation readiness must be rejected, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(root2);
}

#[test]
fn absent_canonical_activation_performs_no_launch() {
    let now = now_ms();
    let deadline = now.saturating_add(120_000);
    let request = test_claim_request(
        "claim-nolaunch-1",
        "reg-nolaunch-1",
        "attempt-1",
        "op-no",
        deadline,
    );
    let (root, path) = temp_ors_path("no-launch");
    let store = RedbRecoveryStore::open(&path).expect("open ORS");
    let svc = ready_service();
    let response = svc
        .admit_native_worker_claim(&store, &request, now)
        .expect("admit");
    assert!(
        response.require_canonical_activation().is_err(),
        "admission must never imply launch"
    );
    let err = response
        .require_canonical_activation()
        .expect_err("must fail closed");
    assert!(
        format!("{err:?}").contains("missing_canonical_activation"),
        "explicit missing-activation disposition, got {err:?}"
    );
    request
        .require_executable_binding(&route_expectation(&request), now)
        .expect("v2 owner join passes before activation check");
    assert!(
        svc.activation_receipt().is_some(),
        "test setup keeps the Host activation receipt, but the claim join itself mints none"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn credentials_stay_references_with_no_secrets_in_receipts() {
    let now = now_ms();
    let request = test_claim_request(
        "claim-cred-1",
        "reg-cred-1",
        "attempt-1",
        "op-cred-1",
        now.saturating_add(60_000),
    );
    let (root, path) = temp_ors_path("creds");
    let store = RedbRecoveryStore::open(&path).expect("open ORS");
    let svc = ready_service();
    let receipt = admitted_receipt(
        &svc.admit_native_worker_claim(&store, &request, now)
            .expect("admit"),
    );
    let receipt_json = serde_json::to_value(&receipt).expect("receipt JSON");
    let encoded = serde_json::to_string(&receipt_json).expect("encode");
    for needle in ["secret", "SECRET", "token", "password", "material"] {
        assert!(
            !encoded.contains(needle),
            "receipt must not carry credential material ({needle})"
        );
    }
    let ready_once = svc
        .mark_native_worker_ready(
            &store,
            &request,
            "ready-cred-1",
            "reg-cred-1",
            1,
            "registry-rev-1",
            &[("prov-a", "key-a")],
            now.saturating_add(10),
            now.saturating_add(20),
        )
        .expect("ready");
    let ready_receipt = admitted_receipt(&ready_once);
    let ready_twice = admitted_receipt(
        &svc.mark_native_worker_ready(
            &store,
            &request,
            "ready-cred-2",
            "reg-cred-1",
            1,
            "registry-rev-1",
            &[("prov-a", "key-a")],
            now.saturating_add(11),
            now.saturating_add(21),
        )
        .expect("ready replay"),
    );
    assert_eq!(
        ready_receipt.receipt_digest, ready_twice.receipt_digest,
        "exact READY replay must keep one receipt identity"
    );
    let _ = std::fs::remove_dir_all(root);
}

struct ExecutableFixture {
    claim: NativeWorkerClaimRequest,
    expectation: NativeWorkerExecutableExpectation,
    now: u64,
}

fn executable_fixture(tag: &str) -> ExecutableFixture {
    let now = now_ms();
    let claim = test_claim_request(
        &format!("claim-t902-{tag}"),
        &format!("reg-t902-{tag}"),
        "attempt-1",
        &format!("op-t902-{tag}"),
        now.saturating_add(120_000),
    );
    let expectation = route_expectation(&claim);
    ExecutableFixture {
        claim,
        expectation,
        now,
    }
}

fn join_of(fixture: &mut ExecutableFixture) -> &mut NativeWorkerExecutableBinding {
    fixture
        .claim
        .executable_binding
        .as_mut()
        .expect("v2 fixture carries the join")
}

struct StaleCase {
    name: &'static str,
    mutate: fn(&mut ExecutableFixture),
    rebind: bool,
    service_field: &'static str,
    transport: TransportError,
}

fn stale_cases() -> Vec<StaleCase> {
    vec![
        StaleCase {
            name: "changed route",
            mutate: |fixture| {
                join_of(fixture).route_ref = "route://test/changed".to_owned();
            },
            rebind: true,
            service_field: "native_worker_claim.executable_binding.route_ref",
            transport: TransportError::IdentityConflict,
        },
        StaleCase {
            name: "changed config",
            mutate: |fixture| {
                join_of(fixture).config_digest = "e".repeat(64);
            },
            rebind: true,
            service_field: "native_worker_claim.executable_binding.config_digest",
            transport: TransportError::IdentityConflict,
        },
        StaleCase {
            name: "changed facet",
            mutate: |fixture| {
                join_of(fixture).facet_manifest_ref = "facet-manifest-9".to_owned();
            },
            rebind: true,
            service_field: "native_worker_claim.executable_binding.facet_manifest_ref",
            transport: TransportError::IdentityConflict,
        },
        StaleCase {
            name: "changed owner digest",
            mutate: |fixture| {
                join_of(fixture).executable_binding_digest = "e".repeat(64);
            },
            rebind: true,
            service_field: "native_worker_claim.executable_binding.executable_binding_digest",
            transport: TransportError::IdentityConflict,
        },
        StaleCase {
            name: "stale epoch while owner advanced",
            mutate: |fixture| {
                let advanced = test_epoch(2);
                fixture.expectation.current.authority_epoch = advanced.clone();
                fixture.expectation.current.state_fence =
                    StateFence::new(advanced, ResourceGeneration::genesis());
            },
            rebind: false,
            service_field: "native_worker_claim.executable_binding.authority_epoch",
            transport: TransportError::SessionFenced,
        },
        StaleCase {
            name: "expired binding window",
            mutate: |fixture| {
                fixture.now = fixture
                    .claim
                    .executable_binding
                    .as_ref()
                    .expect("v2 carries the join")
                    .expires_at_unix_ms;
            },
            rebind: false,
            service_field: "native_worker_claim.executable_binding.expired",
            transport: TransportError::Timeout,
        },
        StaleCase {
            name: "revoked authority",
            mutate: |fixture| {
                fixture.expectation.revoked = true;
            },
            rebind: false,
            service_field: "native_worker_claim.executable_binding_revoked",
            transport: TransportError::IdentityConflict,
        },
        StaleCase {
            name: "old wire v1 without join",
            mutate: |fixture| {
                fixture.claim.wire_version = NATIVE_WORKER_CLAIM_WIRE_VERSION_V1;
                fixture.claim.executable_binding = None;
            },
            rebind: true,
            service_field: "native_worker_claim.u1_old_wire_without_executable_binding",
            transport: TransportError::SessionFenced,
        },
    ]
}

/// T9-02 W-B stale-binding enforcement (Implements #22): one table-driven
/// set proving the route gate refuses every stale dimension with its typed
/// service reason and maps it into the existing `TransportError` vocabulary —
/// changed owner dimensions conflict (`IdentityConflict`), epoch/fence and
/// old-wire failures fence (`SessionFenced`), an elapsed binding window
/// times out (`Timeout`). No new stage is invented; `ADMITTED` is never
/// emitted for any of these (the route returns before sealing).
#[test]
fn executable_binding_stale_inputs_reject_typed() {
    let valid = executable_fixture("valid");
    valid
        .claim
        .require_executable_binding(&valid.expectation, valid.now)
        .expect("valid owner join passes the gate");
    KernelComposition::enforce_claim_executable_binding(
        &valid.claim,
        &valid.expectation,
        valid.now,
    )
    .expect("route enforces the valid join");
    for case in stale_cases() {
        let mut fixture = executable_fixture(case.name);
        (case.mutate)(&mut fixture);
        if case.rebind {
            rebind_claim(&mut fixture.claim);
        }
        let service_error = fixture
            .claim
            .require_executable_binding(&fixture.expectation, fixture.now)
            .expect_err("stale binding must fail closed");
        assert!(
            format!("{service_error:?}").contains(case.service_field),
            "{}: expected typed reason {}, got {service_error:?}",
            case.name,
            case.service_field
        );
        let route_error = KernelComposition::enforce_claim_executable_binding(
            &fixture.claim,
            &fixture.expectation,
            fixture.now,
        )
        .expect_err("route must reject the stale binding");
        assert_eq!(
            route_error.into_transport(),
            case.transport,
            "{}: wrong transport mapping",
            case.name
        );
    }
}

/// Route v2 carry (Implements #22): `build_claim_request` populates the
/// executable join from the presented claim, fails closed when v2 omits it,
/// parses v1 without a join, and refuses a v1 payload smuggling one.
#[test]
fn route_build_claim_request_carries_v2_join() {
    let now = now_ms();
    let request = test_claim_request(
        "claim-carry-1",
        "reg-carry-1",
        "attempt-1",
        "op-carry-1",
        now.saturating_add(120_000),
    );
    let mut json = serde_json::to_value(&request).expect("claim JSON");
    // Wire contour (Implements #64): the top-level `authority_epoch` travels
    // as the scalar sequence, while the fence keeps the full `EpochId`.
    json["authority_epoch"] = serde_json::json!(request.authority_epoch.sequence.get());
    let rebuilt = KernelComposition::build_claim_request(&json).expect("v2 rebuilds");
    assert!(
        rebuilt.executable_binding.is_some(),
        "v2 join must be carried"
    );
    assert_eq!(rebuilt.binding_digest, request.binding_digest);
    rebuilt.validate().expect("rebuilt claim validates");
    let mut no_join = json.clone();
    no_join
        .as_object_mut()
        .expect("claim is an object")
        .remove("executable_binding");
    assert!(
        KernelComposition::build_claim_request(&no_join).is_err(),
        "v2 without join must fail closed"
    );
    let mut v1_value = json.clone();
    let v1_object = v1_value.as_object_mut().expect("claim is an object");
    v1_object.remove("executable_binding");
    v1_object.insert(
        "wire_version".to_owned(),
        serde_json::json!(NATIVE_WORKER_CLAIM_WIRE_VERSION_V1),
    );
    let v1 = KernelComposition::build_claim_request(&v1_value).expect("v1 parses");
    assert!(
        v1.executable_binding.is_none(),
        "v1 carries no join by construction"
    );
    let mut smuggled = json.clone();
    smuggled
        .as_object_mut()
        .expect("claim is an object")
        .insert(
            "wire_version".to_owned(),
            serde_json::json!(NATIVE_WORKER_CLAIM_WIRE_VERSION_V1),
        );
    assert!(
        KernelComposition::build_claim_request(&smuggled).is_err(),
        "v1 must not smuggle a join"
    );
}

/// Source-level proof: the claim handler runs the real executable gate after
/// admission and before any `ADMITTED` receipt is sealed, and seals the
/// executable digest with `native_worker_claim` decisions so later reconcile
/// observes it. The `EpochId` lineage bridge stays intact.
#[test]
fn claim_route_gates_executable_binding_after_admit_before_seal() {
    let route_src = include_str!("../native_worker_lifecycle_route.rs");
    for needle in [
        "build_executable_expectation(",
        "enforce_claim_executable_binding(&request, &expectation, now)",
        "executable_binding_digest",
    ] {
        assert!(
            route_src.contains(needle),
            "lifecycle route must enforce the executable join ({needle})"
        );
    }
    let admit = route_src
        .find("admit_native_worker_claim(self.generation_gateway")
        .expect("admission call");
    let gate = route_src
        .find("enforce_claim_executable_binding(&request, &expectation, now)")
        .expect("gate call");
    let seal = route_src
        .find("\"native_worker_claim\",\n            &claim_id,")
        .expect("claim seal");
    assert!(
        admit < gate && gate < seal,
        "gate must run after admit and before the ADMITTED seal"
    );
    assert!(
        route_src.contains("Implements #64"),
        "EpochId lineage-bridge comments must be preserved"
    );
}
