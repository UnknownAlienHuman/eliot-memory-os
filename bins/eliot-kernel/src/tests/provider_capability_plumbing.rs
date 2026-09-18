//! T9-04 provider-capability composition proofs (issue #1108, Slice B).
//!
//! Focused wiring proofs only: an authenticated session builds a capability
//! context, an unauthenticated session cannot, a durable ORS row bound to
//! the exact attempt/operation verifies, a foreign attempt mismatches before
//! any owner mutation, and a stale-epoch row fails. All durability uses the
//! real ORS `redb` store (`RedbRecoveryStore::open` through the production
//! composition); no fakes, no stubs, no cached verification.
//!
//! The accept/reject verdicts for the coherent and stale-epoch cases are
//! produced by the real capability owner
//! (`eliot_kernel_service::protocol::provider_capability::verify_provider_capability`,
//! parallel Writer-A slice of the same issue): the route only
//! authenticates, loads the exact row, re-queries the live epoch, and
//! delegates. If the owner's comparison semantics drift from the coherence
//! assumed here (row digests presented verbatim, live-epoch agreement,
//! `revoked == false`), the integrator reconciles these two proofs first.
//!
//! Wiring note: this file is compiled as a `#[cfg(test)]` child of
//! `super::provider_capability_route` (see the `#[path]` declaration at the
//! bottom of that owned module), so it exercises the route directly while
//! keeping `bins/eliot-kernel/src/tests.rs` untouched.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use super::ProviderCapabilityRouteError;
use crate::{KernelComposition, KernelConfig};
use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration};
use eliot_ipc::{PeerIdentity, Session};
use eliot_kernel_service::{
    HostKernelCandidateBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
    KernelServiceState, ProviderProofKind,
};
use eliot_ors::{NativeWorkerClaimRecord, NativeWorkerClaimState, OpaqueLabel, OperationIdentity};
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn temp_root(slug: &str) -> std::path::PathBuf {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-t904-capability-{slug}-{}-{ms}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    root
}

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).expect("test handle")
}

fn label(value: &str) -> OpaqueLabel {
    OpaqueLabel::new(value).expect("opaque label")
}

fn identity(value: &str) -> OperationIdentity {
    OperationIdentity::new(value).expect("operation identity")
}

fn candidate_binding(sequence: u64) -> HostKernelCandidateBinding {
    use eliot_kernel_service::{HostFileIdentity, HostJobIdentity, HostJobRoot, RestartBudget};
    HostKernelCandidateBinding {
        installation_id: handle("installation-1"),
        host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: test_epoch(sequence),
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

/// Drives one production composition to `Ready` at the given epoch
/// sequence through the exact Host candidate lifecycle.
fn ready_kernel(root: &std::path::Path, sequence: u64) -> KernelComposition {
    let kernel = KernelComposition::new(KernelConfig::new(root)).expect("kernel composition");
    let candidate = candidate_binding(sequence);
    let mut service = kernel.service.lock().expect("service lock");
    service.reconcile(candidate.clone()).expect("reconcile");
    service.apply(KernelControlCommand::Shadow).expect("shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("handoff");
    let permit = KernelActivationPermit {
        operation_id: handle(&format!("op-t904-capability-{sequence}")),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle(&format!("txn-t904-capability-{sequence}")),
        journal_sequence: 1,
        generation: ResourceGeneration::genesis(),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
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
            process_id: handle("pid:42:start:10"),
            job_object_id: candidate.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ev-t904-capability")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![handle("ev-t904-capability")],
    };
    service.publish_ready(ready).expect("publish ready");
    assert_eq!(service.state(), KernelServiceState::Ready);
    drop(service);
    kernel
}

fn test_session(kernel: &KernelComposition) -> Session {
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let peer = PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
            .expect("process binding"),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .expect("peer");
    Session {
        connection_id: "t904-capability-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer,
        authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
        module_generation: policy.module_generation.clone(),
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn unauthenticated_session(kernel: &KernelComposition) -> Session {
    let mut session = test_session(kernel);
    session.peer = PeerIdentity::Unavailable {
        reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
    };
    session
}

/// Stages one admitted claim row bound to the exact attempt/operation.
fn stage_row(
    kernel: &KernelComposition,
    claim: &str,
    attempt: &str,
    operation: &str,
    binding_digest: &str,
    epoch: u64,
) -> NativeWorkerClaimRecord {
    let record = NativeWorkerClaimRecord {
        contract_version: eliot_ors::CONTRACT_VERSION,
        claim_id: identity(claim),
        registration_id: label("registration-t904"),
        worker_generation: 1,
        parent_job_id: label("parent-t904"),
        task_id: label("task-t904"),
        work_scope_id: label("scope-t904"),
        decision_id: label("decision-t904"),
        attempt_id: label(attempt),
        operation_id: label(operation),
        route_class: label("route-t904"),
        budget_digest: "a".repeat(64),
        deadline_unix_ms: 4_000_000_000_000,
        fence_digest: "b".repeat(64),
        authority_epoch: epoch,
        binding_digest: binding_digest.to_owned(),
        request_digest: "e".repeat(64),
        execution_unit_schema_version: 1,
        predecessor_revision: label("predecessor-t904"),
        resource_envelope_digest: "f".repeat(63) + "0",
        state: NativeWorkerClaimState::Admitted,
        receipt_digest: Some("d".repeat(64)),
        admitted_at_unix_ms: Some(1_700_000_000_000),
        commit_order: 0,
    };
    kernel
        .generation_gateway
        .ors
        .stage_native_worker_claim(&record)
        .expect("stage claim")
        .record()
        .clone()
}

fn cleanup(root: &std::path::Path) {
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn authenticated_session_builds_capability_context() {
    let root = temp_root("context-ok");
    let kernel = ready_kernel(&root, 1);
    let session = test_session(&kernel);
    let context = kernel
        .provider_capability_for_session(&session)
        .expect("authenticated session builds a capability context");
    assert!(
        context.session_principal_binding().starts_with("module="),
        "context must carry the authenticated principal binding"
    );
    let live = kernel
        .service
        .lock()
        .expect("service lock")
        .authority_epoch();
    assert_eq!(*context.live_authority_epoch(), live);
    drop(kernel);
    cleanup(&root);
}

#[test]
fn unauthenticated_session_cannot_build_capability_context() {
    let root = temp_root("context-denied");
    let kernel = ready_kernel(&root, 1);
    let session = unauthenticated_session(&kernel);
    let result = kernel.provider_capability_for_session(&session);
    assert!(
        matches!(result, Err(ProviderCapabilityRouteError::Session(_))),
        "an unauthenticated session must never yield a capability context"
    );
    drop(kernel);
    cleanup(&root);
}

#[test]
fn verify_accepts_durable_row_bound_to_exact_attempt_and_operation() {
    let root = temp_root("verify-ok");
    let kernel = ready_kernel(&root, 1);
    let binding_digest = "9".repeat(64);
    stage_row(
        &kernel,
        "claim-t904-ok",
        "attempt-t904-ok",
        "operation-t904-ok",
        &binding_digest,
        1,
    );
    let session = test_session(&kernel);
    let context = kernel
        .provider_capability_for_session(&session)
        .expect("context");
    // Presented proof material mirrors the durable row exactly; the owner
    // verifies currentness (live epoch agreement, no revocation) and the
    // presented route/capacity revision binding.
    context
        .verify(
            ProviderProofKind::Admission,
            "attempt-t904-ok",
            "operation-t904-ok",
            "claim-t904-ok",
            "proof-ref-t904-ok",
            &"c".repeat(64),
            &binding_digest,
            &"8".repeat(64),
            "route-rev-t904-7",
            "capacity-rev-t904-3",
        )
        .expect("exact attempt/operation proof verifies against the durable row");
    drop(kernel);
    cleanup(&root);
}

#[test]
fn verify_rejects_foreign_attempt_under_known_claim() {
    let root = temp_root("verify-foreign");
    let kernel = ready_kernel(&root, 1);
    let binding_digest = "9".repeat(64);
    stage_row(
        &kernel,
        "claim-t904-foreign",
        "attempt-t904-real",
        "operation-t904-real",
        &binding_digest,
        1,
    );
    let session = test_session(&kernel);
    let context = kernel
        .provider_capability_for_session(&session)
        .expect("context");
    let result = context.verify(
        ProviderProofKind::Admission,
        "attempt-t904-foreign",
        "operation-t904-real",
        "claim-t904-foreign",
        "proof-ref-t904-foreign",
        &"c".repeat(64),
        &binding_digest,
        &"8".repeat(64),
        "route-rev-t904-7",
        "capacity-rev-t904-3",
    );
    let error = result.expect_err("a foreign attempt must mismatch before any owner mutation");
    assert!(
        matches!(error, ProviderCapabilityRouteError::BindingMismatch(_)),
        "foreign attempt must report a binding mismatch"
    );
    let rendered = format!("{error}");
    assert!(
        rendered.contains("provider capability"),
        "typed error must stay in capability vocabulary"
    );
    assert!(
        !rendered.contains("attempt-t904-foreign"),
        "typed error must not echo presenter-controlled proof material"
    );
    drop(kernel);
    cleanup(&root);
}

#[test]
fn verify_rejects_stale_epoch_row() {
    let root = temp_root("verify-stale");
    let kernel = ready_kernel(&root, 2);
    let binding_digest = "9".repeat(64);
    // The row was admitted under epoch 1 while the live authority epoch is
    // already 2: restore must observe fresh owner evidence, never a stale
    // admission.
    stage_row(
        &kernel,
        "claim-t904-stale",
        "attempt-t904-stale",
        "operation-t904-stale",
        &binding_digest,
        1,
    );
    let session = test_session(&kernel);
    let context = kernel
        .provider_capability_for_session(&session)
        .expect("context");
    let result = context.verify(
        ProviderProofKind::Result,
        "attempt-t904-stale",
        "operation-t904-stale",
        "claim-t904-stale",
        "proof-ref-t904-stale",
        &"c".repeat(64),
        &binding_digest,
        &"8".repeat(64),
        "route-rev-t904-7",
        "capacity-rev-t904-3",
    );
    assert!(
        result.is_err(),
        "a stale-epoch row must fail against the fresh live epoch"
    );
    drop(kernel);
    cleanup(&root);
}
