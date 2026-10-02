//! Unit proof for the current P-07 owner guard before Resolved publication.
//!
//! This exercises the private guard and binding validator, not the full live
//! bridge handshake or Session publication edge.

use super::*;

use crate::KernelConfig;
use eliot_contracts::{
    ContractId, EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence,
};
use eliot_protocol::{
    AgentActivationOwnerEvidence, AgentActivationOwnerReadback,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResolvedBinding, AgentBridgeActivationRequest,
    AgentBridgePeerAdmissionReceipt,
};
use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OWNER_TEST_REVISION: u64 = 5;
const OWNER_TEST_ROOT: &str = "root-owner-guard-test";

fn owner_test_fence() -> TestResult<StateFence> {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
    let sequence = std::num::NonZeroU64::new(7)
        .ok_or_else(|| std::io::Error::other("fixture epoch must be nonzero"))?;
    let epoch = EpochId::new(lineage, sequence)?;
    let generation = ResourceGeneration::new(1)?;
    Ok(StateFence::new(epoch, generation))
}

fn owner_test_binding(fence: &StateFence) -> TestResult<AuthorityBinding> {
    Ok(AuthorityBinding {
        authority_id: ContractId::new("authority:owner-guard-test")?,
        authority_owner: "owner-guard-test".to_owned(),
        authority_epoch: fence.authority_epoch.clone(),
        state_fence: fence.clone(),
        allowed_effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::ScopedVerification,
    })
}

fn owner_test_restore(fence: &StateFence) -> TestResult<eliot_kernel_core::GovernorClosureRestore> {
    use eliot_authority::{GrantGraphRecoverySnapshot, GrantRecoveryRecord, GrantStatus};
    Ok(eliot_kernel_core::GovernorClosureRestore {
        graph_snapshot: GrantGraphRecoverySnapshot {
            schema: eliot_authority::GRANT_GRAPH_RECOVERY_SCHEMA.to_owned(),
            version: eliot_authority::GRANT_GRAPH_RECOVERY_VERSION,
            revision: OWNER_TEST_REVISION,
            grants: vec![GrantRecoveryRecord {
                grant_id: "grant-expired-owner-guard-test".to_owned(),
                parent_grant_id: None,
                authority_root_ref: OWNER_TEST_ROOT.to_owned(),
                issuer: "owner-guard-fixture".to_owned(),
                holder: "owner-guard-fixture".to_owned(),
                allowed_operations: vec!["op.read".to_owned()],
                allowed_resources: vec!["res:owner-guard-test".to_owned()],
                max_effect: EffectClass::Read,
                inherited_source_ceiling: None,
                binding: owner_test_binding(fence)?,
                issued_at: 1,
                expires_at: 2,
                max_uses: 1,
                status: GrantStatus::Expired,
            }],
            revoked: Vec::new(),
            admitted_root_transitions: Vec::new(),
            quarantined_cross_root: Vec::new(),
        },
        revocation_history: Some(eliot_authority::RevocationHistoryEvidence {
            state_fence: fence.clone(),
            source_revision: OWNER_TEST_REVISION,
            closures: Vec::new(),
        }),
        members: Vec::new(),
        roots: Vec::new(),
        introductions: Vec::new(),
        declarations: Vec::new(),
        preserved: Vec::new(),
        canonical_receipts: BTreeMap::new(),
        quarantine_evidence: BTreeMap::new(),
        retained_quarantine_decisions: BTreeMap::new(),
        retained_transition_decisions: BTreeMap::new(),
        retained_quarantine_enforcements: BTreeMap::new(),
    })
}

fn owner_test_kernel() -> TestResult<(std::path::PathBuf, KernelComposition, StateFence)> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "eliot-1115-owner-guard-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root)?;
    let fence = owner_test_fence()?;
    let kernel = KernelComposition::new(KernelConfig::new(&root))?;
    kernel.initialize_p07_owner_revision(OWNER_TEST_ROOT, OWNER_TEST_REVISION, &fence)?;
    kernel.bind_p07_owner(owner_test_restore(&fence)?, OWNER_TEST_REVISION)?;
    Ok((root, kernel, fence))
}

fn owner_test_receipt(
    fence: &StateFence,
    connection_id: &str,
    deadline: u64,
) -> TestResult<AgentBridgePeerAdmissionReceipt> {
    Ok(AgentBridgePeerAdmissionReceipt {
        wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
        wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
        module_id: eliot_protocol::AGENT_BRIDGE_MODULE_ID.to_owned(),
        connection_id: connection_id.to_owned(),
        profile_id: "profile-owner-guard-test".to_owned(),
        descriptor_sha256: "a".repeat(64),
        client_declaration_sha256: "b".repeat(64),
        bridge_generation: fence.resource_generation,
        state_fence: fence.clone(),
        activation_deadline_unix_ms: deadline,
        challenge_nonce: "owner-guard-test-nonce".to_owned(),
        challenge_sha256: "c".repeat(64),
        client_hello_sha256: "d".repeat(64),
        observed_sid: "S-1-5-21-1-2-3-1000".to_owned(),
        observed_session_id: 1,
        observed_process_id: 2,
        observed_process_start_time_100ns: 3,
        observed_image_path: r"C:\eliot\agent-bridge.exe".to_owned(),
        observed_image_volume_serial: 1,
        observed_image_file_index: 1,
        receipt_sha256: String::new(),
    }
    .with_computed_digest()?)
}

fn owner_test_request(
    fence: &StateFence,
    receipt: &AgentBridgePeerAdmissionReceipt,
    connection_id: &str,
    deadline: u64,
) -> TestResult<AgentBridgeActivationRequest> {
    let request_id = RequestId::new("activation-request-owner-guard-test")?;
    let request = serde_json::from_value::<AgentBridgeActivationRequest>(serde_json::json!({
    "wire_id": eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_ID,
    "wire_version": eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_VERSION,
    "operation": eliot_protocol::AGENT_BRIDGE_ACTIVATION_OPERATION,
    "demand_id": "activation-demand-owner-guard-test",
    "connection_id": connection_id,
    "attach_kind": "MANAGED",
    "pre_attach_blind_interval": null,
    "request_identity": {
        "request": {
            "metadata": {
                "request_id": request_id.as_str(),
                "session_id": null,
                "task_id": null,
                "product_id": "eliot-agent-bridge",
                "source_id": "agent-bridge-owner-guard-test",
                "state_fence": fence,
                "clock": {
                    "valid_time_ms": null,
                    "known_time_ms": null,
                    "transaction_sequence": null,
                    "monotonic_ns": null
                }
            },
            "state_fence": fence
        },
        "idempotency_key": "activation-idempotency-owner-guard-test",
        "deadline_unix_ms": deadline,
        "cancellation_id": "activation-cancellation-owner-guard-test"
    },
    "peer_admission_receipt_sha256": receipt.receipt_sha256,
    "request_sha256": "e".repeat(64)
    }))?;
    Ok(request.with_computed_digest()?)
}

fn owner_test_ticket(
    request: &AgentBridgeActivationRequest,
    receipt: &AgentBridgePeerAdmissionReceipt,
    fence: &StateFence,
    connection_id: &str,
    deadline: u64,
) -> TestResult<AgentActivationResolutionTicket> {
    Ok(AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: AgentActivationResolutionTicket::CONTRACT_VERSION,
        ticket_id: "activation-ticket-owner-guard-test".to_owned(),
        activation_request_id: request.request_identity.request.metadata.request_id.clone(),
        demand_id: request.demand_id.clone(),
        activation_request_sha256: request.request_sha256.clone(),
        peer_admission_receipt_sha256: receipt.receipt_sha256.clone(),
        connection_id: connection_id.to_owned(),
        workspace_selector: None,
        cancellation_id: request.request_identity.cancellation_id.clone(),
        state_fence: fence.clone(),
        kernel_deadline_unix_ms: deadline,
        successor_of: None,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()?)
}

fn owner_test_pending_and_result(
    fence: &StateFence,
    bundle_sha256: &str,
) -> TestResult<(
    AgentActivationPending,
    AgentActivationResolutionResult,
    AgentActivationResolvedBinding,
    AgentBridgePeerAdmissionReceipt,
)> {
    let connection_id = "activation-connection-owner-guard-test";
    let deadline = 10_000;
    let receipt = owner_test_receipt(fence, connection_id, deadline)?;
    let request = owner_test_request(fence, &receipt, connection_id, deadline)?;
    let ticket = owner_test_ticket(&request, &receipt, fence, connection_id, deadline)?;
    let binding = AgentActivationResolvedBinding {
        principal_id: "principal-owner-guard-test".to_owned(),
        session_id: "session-owner-guard-test".to_owned(),
        task_id: "task-owner-guard-test".to_owned(),
        work_unit_id: "work-unit-owner-guard-test".to_owned(),
        work_scope_id: "scope-owner-guard-test".to_owned(),
        task_revision: "1".to_owned(),
        plan_id: "plan-owner-guard-test".to_owned(),
        plan_revision: "plan-revision-owner-guard-test".to_owned(),
    };
    let result = AgentActivationResolutionResult::new_with_owner_evidence(
        &ticket,
        1_000,
        AgentActivationResolutionDisposition::Resolved {
            binding: Box::new(binding.clone()),
        },
        OWNER_TEST_REVISION,
    )?;
    let evidence =
        AgentActivationOwnerEvidence::for_binding(&binding, OWNER_TEST_REVISION, fence.clone())?;
    let readback = AgentActivationOwnerReadback::from_evidence(evidence, 1_001)?
        .with_kernel_owner_readback(eliot_protocol::AgentActivationKernelOwnerReadback::new(
            OWNER_TEST_REVISION,
            bundle_sha256.to_owned(),
        )?)?;
    Ok((
        AgentActivationPending {
            ticket,
            request,
            claim_lease_until_unix_ms: None,
            claim_dependency_ref: None,
            claim_dependency_revision: None,
            successor_of: None,
            owner_readback: Some(readback),
        },
        result,
        binding,
        receipt,
    ))
}

#[test]
fn exact_retained_owner_runs_resolved_publication_guard() -> TestResult {
    let (root, kernel, fence) = owner_test_kernel()?;
    let (_, revision, digest) = kernel.p07_owner_readback();
    assert_eq!(revision, Some(OWNER_TEST_REVISION));
    let digest = digest.ok_or_else(|| std::io::Error::other("bound owner digest is present"))?;
    let (pending, result, binding, receipt) = owner_test_pending_and_result(&fence, &digest)?;
    let observed = AtomicBool::new(false);
    drop(
        kernel.with_current_activation_owner(&pending, &result, &binding, || {
            KernelComposition::activated_application_binding(
                &binding,
                &pending,
                &result,
                &receipt,
                &pending.ticket.connection_id,
            )
            .inspect(|_| {
                observed.store(true, Ordering::SeqCst);
            })
        })?,
    );
    assert!(observed.load(Ordering::SeqCst));
    drop(kernel);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn changed_or_missing_current_owner_refuses_before_publication_closure() -> TestResult {
    let (root, kernel, fence) = owner_test_kernel()?;
    let (_, _, digest) = kernel.p07_owner_readback();
    let digest = digest.ok_or_else(|| std::io::Error::other("bound owner digest is present"))?;
    let (pending, result, binding, _) = owner_test_pending_and_result(&fence, &digest)?;
    let observed = AtomicBool::new(false);
    *kernel
        .p07_owner_digest
        .lock()
        .map_err(|_| std::io::Error::other("owner digest lock poisoned"))? = Some("f".repeat(64));
    assert!(matches!(
        kernel.with_current_activation_owner(&pending, &result, &binding, || {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        }),
        Err(TransportError::SessionFenced)
    ));
    assert!(!observed.load(Ordering::SeqCst));
    *kernel
        .p07_owner
        .lock()
        .map_err(|_| std::io::Error::other("owner lock poisoned"))? = None;
    *kernel
        .p07_owner_digest
        .lock()
        .map_err(|_| std::io::Error::other("owner digest lock poisoned"))? = None;
    assert!(matches!(
        kernel.with_current_activation_owner(&pending, &result, &binding, || {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        }),
        Err(TransportError::SessionFenced)
    ));
    assert!(!observed.load(Ordering::SeqCst));
    drop(kernel);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
