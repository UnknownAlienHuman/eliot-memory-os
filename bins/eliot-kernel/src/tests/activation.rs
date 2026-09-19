//! Kernel activation claim tests — acceptance-only scope.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md` :: A2.3 and `ARCH-MOD-01` — modular architecture, ordinary module boundary.
//! - `ELIOT_IMPLEMENTATION.md` :: I2.2 and `I2.16` — crate capability extraction and crate-size/Agent Context Envelope.
//!
//! This module owns no runtime authority and exercises only the Kernel composition
//! boundary via `super::*`. It is an ordinary module kept under 10k LOC.

use super::*;
use eliot_contracts::{EpochId, EpochLineageId};

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

#[cfg(windows)]
fn activation_test_entry(deadline: u64) -> (String, AgentActivationPending) {
    let state_fence = StateFence::new(
        test_epoch(1),
        ResourceGeneration::new(1).expect("resource generation"),
    );
    let request_id = RequestId::new("activation-request-test").expect("request id");
    let request: AgentBridgeActivationRequest = serde_json::from_value(serde_json::json!({
        "wire_id": eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_ID,
        "wire_version": eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_VERSION,
        "operation": AGENT_BRIDGE_ACTIVATION_OPERATION,
        "demand_id": "activation-demand-test",
        "connection_id": "activation-connection-test",
        "attach_kind": "MANAGED",
        "pre_attach_blind_interval": null,
        "request_identity": {
            "request": {
                "metadata": {
                    "request_id": request_id.as_str(),
                    "session_id": null,
                    "task_id": null,
                    "product_id": "eliot-agent-bridge",
                    "source_id": "agent-bridge-test",
                    "state_fence": state_fence.clone(),
                    "clock": {
                        "valid_time_ms": null,
                        "known_time_ms": null,
                        "transaction_sequence": null,
                        "monotonic_ns": null
                    }
                },
                "state_fence": state_fence.clone()
            },
            "idempotency_key": "activation-idempotency-test",
            "deadline_unix_ms": deadline,
            "cancellation_id": "activation-cancellation-test"
        },
        "peer_admission_receipt_sha256": "b".repeat(64),
        "request_sha256": "a".repeat(64)
    }))
    .expect("activation request");
    let ticket_id = "activation-ticket-test".to_owned();
    let ticket = AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: ticket_id.clone(),
        activation_request_id: request_id,
        activation_request_sha256: request.request_sha256.clone(),
        peer_admission_receipt_sha256: request.peer_admission_receipt_sha256.clone(),
        connection_id: request.connection_id.clone(),
        state_fence,
        kernel_deadline_unix_ms: deadline,
        ticket_sha256: "c".repeat(64),
    };
    (
        ticket_id,
        AgentActivationPending {
            ticket,
            request,
            decision: None,
            claim_lease_until_unix_ms: None,
        },
    )
}

#[cfg(windows)]
fn activation_test_decision(ticket_id: &str) -> AgentActivationResolutionDecision {
    AgentActivationResolutionDecision {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_ID.to_owned(),
        wire_version: AgentActivationResolutionDecision::CONTRACT_VERSION,
        ticket_id: ticket_id.to_owned(),
        ticket_sha256: "c".repeat(64),
        state_fence: StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("resource generation"),
        ),
        principal_id: "principal-test".to_owned(),
        session_id: "session-test".to_owned(),
        task_id: "task-test".to_owned(),
        work_unit_id: "work-unit-test".to_owned(),
        work_scope_id: "scope-test".to_owned(),
        task_revision: "task-revision-test".to_owned(),
        plan_id: "plan-test".to_owned(),
        plan_revision: "plan-revision-test".to_owned(),
        decision_sha256: "d".repeat(64),
    }
}

#[cfg(windows)]
#[test]
fn activation_claim_lease_retries_transient_resolution_without_duplicate_claim() {
    let (ticket_id, entry) = activation_test_entry(2_000);
    let mut pending = AgentActivationPendingState::default();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id, entry);

    let first = pending.claim_at(1).expect("first claim");
    assert_eq!(first.ticket_id, "activation-ticket-test");
    assert!(pending.claim_at(AGENT_ACTIVATION_CLAIM_LEASE_MS).is_none());
    let retry = pending
        .claim_at(AGENT_ACTIVATION_CLAIM_LEASE_MS + 1)
        .expect("claim after lease expiry");
    assert_eq!(retry, first, "retry reuses the exact Kernel ticket");
}

#[cfg(windows)]
#[test]
fn activation_claim_expires_at_deadline_and_decided_ticket_is_not_reclaimed() {
    let (ticket_id, mut entry) = activation_test_entry(2_000);
    let mut pending = AgentActivationPendingState::default();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id.clone(), entry.clone());
    assert!(pending.claim_at(2_000).is_none(), "deadline is inclusive");

    entry.decision = Some(activation_test_decision(&ticket_id));
    pending.fifo.clear();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id, entry);
    assert!(
        pending.claim_at(1).is_none(),
        "decided tickets are terminal"
    );
}

#[cfg(windows)]
#[test]
fn activation_denial_codes_map_each_non_resolved_disposition_distinctly() {
    use eliot_protocol::{
        AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
        AgentActivationResolvedBinding, AgentActivationRetryDirective,
        AgentActivationSelectionDirective, AgentBridgeActivationDenialCode,
    };

    let selection = AgentActivationSelectionDirective {
        candidate_handles: vec!["candidate-1".to_owned(), "candidate-2".to_owned()],
        candidate_coverage: AgentActivationCandidateCoverage::Complete,
        recovery_handle: "recovery-1".to_owned(),
    };
    let retry = AgentActivationRetryDirective {
        dependency_ref: "owner-dependency-1".to_owned(),
        observed_dependency_revision: "revision-1".to_owned(),
        not_before_unix_ms: 2_001,
    };
    let fence = StateFence::new(
        test_epoch(1),
        ResourceGeneration::new(1).expect("resource generation"),
    );
    let cases: [(
        AgentActivationResolutionDisposition,
        AgentBridgeActivationDenialCode,
    ); 6] = [
        (
            AgentActivationResolutionDisposition::TaskSelectionRequired {
                selection: selection.clone(),
            },
            AgentBridgeActivationDenialCode::TaskSelectionRequired,
        ),
        (
            AgentActivationResolutionDisposition::ScopeSelectionRequired {
                selection: selection.clone(),
            },
            AgentBridgeActivationDenialCode::ScopeSelectionRequired,
        ),
        (
            AgentActivationResolutionDisposition::ScopeAmbiguous {
                selection: selection.clone(),
            },
            AgentBridgeActivationDenialCode::ScopeAmbiguous,
        ),
        (
            AgentActivationResolutionDisposition::NotReady {
                recovery_handle: "recovery-1".to_owned(),
                retry,
            },
            AgentBridgeActivationDenialCode::NotReady,
        ),
        (
            AgentActivationResolutionDisposition::StaleFence {
                recovery_handle: "recovery-1".to_owned(),
                observed_state_fence: Some(fence),
            },
            AgentBridgeActivationDenialCode::StaleFence,
        ),
        (
            AgentActivationResolutionDisposition::FailedInternal {
                failure_handle: "failure-1".to_owned(),
            },
            AgentBridgeActivationDenialCode::FailedInternal,
        ),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (disposition, expected) in &cases {
        let code = KernelComposition::activation_denial_code_for_disposition(disposition);
        assert_eq!(code, Some(*expected));
        assert!(
            seen.insert(expected.as_str()),
            "each disposition must project a distinct denial code"
        );
    }
    assert_eq!(seen.len(), cases.len());

    let resolved = AgentActivationResolutionDisposition::Resolved {
        binding: Box::new(AgentActivationResolvedBinding {
            principal_id: "principal-test".to_owned(),
            session_id: "session-test".to_owned(),
            task_id: "task-test".to_owned(),
            work_unit_id: "work-unit-test".to_owned(),
            work_scope_id: "scope-test".to_owned(),
            task_revision: "task-revision-test".to_owned(),
            plan_id: "plan-test".to_owned(),
            plan_revision: "plan-revision-test".to_owned(),
        }),
    };
    assert_eq!(
        KernelComposition::activation_denial_code_for_disposition(&resolved),
        None,
        "a resolved disposition never projects a denial"
    );
}

#[cfg(windows)]
#[test]
fn activation_decision_replay_is_exact_and_conflicts_are_rejected() {
    let first = activation_test_decision("activation-ticket-test");
    assert_eq!(
        classify_activation_decision(None, &first),
        ActivationDecisionDisposition::Commit
    );
    assert_eq!(
        classify_activation_decision(Some(&first), &first),
        ActivationDecisionDisposition::ExactReplay
    );
    let mut conflicting = first.clone();
    conflicting.plan_id = "different-plan".to_owned();
    assert_eq!(
        classify_activation_decision(Some(&first), &conflicting),
        ActivationDecisionDisposition::Conflict
    );
}

// ---------------------------------------------------------------------------
// #203 / #1115: one canonical terminal result identity per ticket across the
// daemon and host-request legs.
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn activation_v2_ticket(ticket_id: &str, deadline: u64) -> AgentActivationResolutionTicket {
    AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: ticket_id.to_owned(),
        activation_request_id: RequestId::new("activation-request-test").expect("request id"),
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: "activation-connection-test".to_owned(),
        state_fence: StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("resource generation"),
        ),
        kernel_deadline_unix_ms: deadline,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("ticket digest")
}

#[cfg(windows)]
fn activation_v2_entry(ticket: &AgentActivationResolutionTicket) -> AgentActivationPending {
    let (_, template) = activation_test_entry(ticket.kernel_deadline_unix_ms);
    AgentActivationPending {
        ticket: ticket.clone(),
        request: template.request,
        decision: None,
        claim_lease_until_unix_ms: None,
    }
}

#[cfg(windows)]
fn activation_v2_resolved(
    ticket: &AgentActivationResolutionTicket,
    resolved_at: u64,
) -> eliot_protocol::AgentActivationResolutionResult {
    use eliot_protocol::{
        AgentActivationResolutionDisposition, AgentActivationResolutionResult,
        AgentActivationResolvedBinding,
    };
    AgentActivationResolutionResult::new(
        ticket,
        resolved_at,
        AgentActivationResolutionDisposition::Resolved {
            binding: Box::new(AgentActivationResolvedBinding {
                principal_id: "principal-test".to_owned(),
                session_id: "session-test".to_owned(),
                task_id: "task-test".to_owned(),
                work_unit_id: "work-unit-test".to_owned(),
                work_scope_id: "scope-test".to_owned(),
                task_revision: "task-revision-test".to_owned(),
                plan_id: "plan-test".to_owned(),
                plan_revision: "plan-revision-test".to_owned(),
            }),
        },
    )
    .expect("resolved result")
}

#[cfg(windows)]
fn activation_v2_failed(
    ticket: &AgentActivationResolutionTicket,
    resolved_at: u64,
) -> eliot_protocol::AgentActivationResolutionResult {
    use eliot_protocol::{AgentActivationResolutionDisposition, AgentActivationResolutionResult};
    AgentActivationResolutionResult::new(
        ticket,
        resolved_at,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "failure-test".to_owned(),
        },
    )
    .expect("failed result")
}

#[cfg(windows)]
fn activation_host_envelope(
    ticket: &AgentActivationResolutionTicket,
    result_sha256: &str,
    connection_id: &str,
) -> eliot_protocol::HostRequestEnvelope {
    use eliot_protocol::{
        HostRequestActivationBinding, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
    };
    HostRequestEnvelope {
        wire_id: eliot_protocol::HOST_REQUEST_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::HOST_REQUEST_WIRE_VERSION,
        kind: HostRequestKind::Activation,
        connection_id: connection_id.to_owned(),
        identity: HostRequestIdentity {
            request_id: RequestId::new("host-request-activation-test").expect("request id"),
            idempotency_key: "host-request-idempotency-test".to_owned(),
            cancellation_id: "host-request-cancellation-test".to_owned(),
            parent_operation_id: None,
            deadline_unix_ms: 9_000,
            capability: "activation-test-capability".to_owned(),
            session_id: None,
            task_id: None,
            work_scope_id: None,
            payload_schema_id: "activation-test-schema".to_owned(),
            payload_sha256: "e".repeat(64),
        },
        state_fence: ticket.state_fence.clone(),
        descriptor_sha256: "f".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        activation_binding: Some(HostRequestActivationBinding {
            ticket_id: ticket.ticket_id.clone(),
            ticket_sha256: ticket.ticket_sha256.clone(),
            resolution_result_sha256: result_sha256.to_owned(),
        }),
        envelope_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("envelope digest")
}

#[cfg(windows)]
fn activation_kernel_with_ticket(
    name: &str,
    ticket: &AgentActivationResolutionTicket,
    canonical: Option<eliot_protocol::AgentActivationResolutionResult>,
    raw: Option<eliot_protocol::AgentActivationResolutionResult>,
) -> (std::path::PathBuf, KernelComposition) {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-v2-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    {
        let mut pending = kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock");
        pending
            .entries
            .insert(ticket.ticket_id.clone(), activation_v2_entry(ticket));
        if let Some(result) = canonical {
            pending.retain_activation_result(AgentActivationResultRecord {
                result,
                phase: AgentActivationResultPhase::AcceptedTerminal,
                ticket_connection: ticket.connection_id.clone(),
                retention_order: 0,
            });
        }
    }
    if let Some(result) = raw {
        kernel
            .agent_activation_results
            .lock()
            .expect("raw result lock")
            .insert(
                ticket.ticket_id.clone(),
                AgentActivationResultRecord {
                    result,
                    phase: AgentActivationResultPhase::AcceptedTerminal,
                    ticket_connection: ticket.connection_id.clone(),
                    retention_order: 0,
                },
            );
    }
    (root, kernel)
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the live bridge fixture keeps the production admission lifecycle in one test helper"
)]
fn activation_kernel_with_live_bridge_ticket(
    name: &str,
) -> (
    std::path::PathBuf,
    KernelComposition,
    AgentActivationResolutionTicket,
) {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-v2-live-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel_artifact_sha256 = "a".repeat(64);
    let kernel = KernelComposition::new(
        KernelConfig::new(&root).with_kernel_artifact_sha256(kernel_artifact_sha256.clone()),
    )
    .expect("kernel composition");
    let kernel_policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let kernel_config_snapshot_sha256 =
        sha256_json(&kernel_policy.config_snapshot).expect("config snapshot digest");
    let bridge_generation = ResourceGeneration::new(1).expect("bridge generation");
    let bridge_authority_epoch = test_epoch(1);
    let bridge_state_fence = StateFence::new(bridge_authority_epoch.clone(), bridge_generation);
    let profile_id = "f".repeat(64);
    let executable = eliot_platform_windows::observe_named_pipe_peer_process(std::process::id())
        .expect("current process binding");
    let executable_identity = executable
        .executable_file_identity()
        .expect("current process executable identity");
    let bridge_sid = eliot_platform_windows::current_process_named_pipe_expectation()
        .expect("current process expectation")
        .expected_sid()
        .to_owned();
    let executable_sha256 = "b".repeat(64);
    let capabilities = vec!["agent.bridge.activate".to_owned()];
    let privacy_classes = vec!["PUBLIC".to_owned()];
    let module_id = ContractId::new(AGENT_BRIDGE_MODULE_ID).expect("bridge module id");
    let artifact_id = ArtifactId::new(executable_sha256.clone()).expect("bridge artifact id");
    let declaration = AgentBridgeClientDeclaration {
        wire_id: eliot_protocol::AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
        module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
        profile_id: profile_id.clone(),
        protocol_range: eliot_protocol::ProtocolRange {
            minimum: eliot_protocol::ProtocolVersion::CURRENT,
            maximum: eliot_protocol::ProtocolVersion::CURRENT,
        },
        module_contract: ModuleContract {
            module_id: module_id.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact_id.clone(),
            protocols: vec!["eliot.agent-bridge.v1".to_owned()],
            required_capabilities: capabilities.clone(),
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-host".to_owned(),
            failure_domain: "agent-bridge".to_owned(),
            hot_replace: false,
        },
        module_generation: ModuleGeneration {
            module_id,
            generation: bridge_generation,
            artifact_id,
            state: ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence: bridge_state_fence.clone(),
        },
        capabilities: capabilities.clone(),
        privacy_classes: privacy_classes.clone(),
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES).expect("frame ceiling"),
        expected_kernel_sid: bridge_sid.clone(),
        expected_kernel_session_id: 0,
        expected_kernel_principal_binding: kernel_policy.session_principal_binding.clone(),
        expected_kernel_authority_epoch: kernel_policy
            .module_generation
            .state_fence
            .authority_epoch
            .clone(),
        expected_kernel_generation: kernel_policy.module_generation.generation,
        expected_kernel_artifact_sha256: kernel_artifact_sha256,
        expected_kernel_config_snapshot_sha256: kernel_config_snapshot_sha256.clone(),
        declaration_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("declaration digest");
    let admission = AgentBridgeAdmissionDescriptor {
        wire_id: eliot_kernel_service::AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_VERSION,
        module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
        profile_id: PlatformHandle::new(profile_id.clone()).expect("profile handle"),
        profile_sha256: "c".repeat(64),
        executable: PlatformHandle::new(executable.image_path()).expect("executable path"),
        executable_sha256,
        executable_identity: eliot_kernel_service::HostFileIdentity {
            volume_serial_number: executable_identity.volume_serial_number,
            file_index: executable_identity.file_index,
        },
        generation: bridge_generation,
        authority_epoch: bridge_authority_epoch.clone(),
        state_fence: bridge_state_fence.clone(),
        approved_user_sid: bridge_sid.clone(),
        caller_session_policy:
            eliot_kernel_service::AgentBridgeCallerSessionPolicy::AnyInteractiveSessionForApprovedSid,
        process_policy: eliot_kernel_service::AgentBridgeProcessPolicy::ExactProcessPerConnection,
        allowed_capabilities: capabilities,
        allowed_privacy_classes: privacy_classes,
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES).expect("frame ceiling"),
        allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
        expected_kernel_principal_binding: kernel_policy.session_principal_binding,
        expected_kernel_config_snapshot_sha256: kernel_config_snapshot_sha256,
        client_declaration_path: PlatformHandle::new(
            r"C:\eliot\agent-bridge\client-declaration.json",
        )
        .expect("declaration path"),
        client_declaration_sha256: declaration.declaration_sha256.clone(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("admission descriptor digest");
    admission.validate().expect("admission descriptor");
    admission
        .validate_client_declaration(&declaration)
        .expect("descriptor/declaration binding");

    let candidate = HostKernelCandidateBinding {
        installation_id: PlatformHandle::new("installation-1").expect("installation"),
        host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: bridge_authority_epoch,
        activation_id: PlatformHandle::new("activation-1").expect("activation"),
        artifact_hash: PlatformHandle::new("artifact-1").expect("artifact"),
        config_hash: PlatformHandle::new("config-1").expect("config"),
        job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").expect("job"),
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).expect("pipe"),
        host_process: eliot_kernel_service::HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: r"C:\eliot\host.exe".to_owned(),
        },
        job_binding: eliot_kernel_service::HostJobBinding {
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
        supervision_incarnation: supervision_incarnation(),
        restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).expect("restart budget"),
        agent_bridge_admission: Some(admission.clone()),
        containment_action: None,
    };
    {
        let mut service = kernel.service.lock().expect("service lock");
        service
            .reconcile(candidate.clone())
            .expect("candidate reconcile");
        service
            .apply(KernelControlCommand::Shadow)
            .expect("shadow transition");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("handoff transition");
        let permit = KernelActivationPermit {
            operation_id: PlatformHandle::new("activation-operation-test").expect("operation"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "d".repeat(64),
            journal_transaction_id: PlatformHandle::new("activation-transaction-test")
                .expect("transaction"),
            journal_sequence: 1,
            generation: bridge_generation,
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("e".repeat(64)).expect("activation nonce"),
            )
            .expect("activation nonce"),
        };
        service
            .activate_permit(&permit, bridge_generation, "e".repeat(64))
            .expect("activate candidate");
        let activation_nonce_digest = service
            .activation_receipt()
            .expect("activation receipt")
            .activation_nonce_digest
            .clone();
        service
            .publish_ready(KernelReadyReceipt {
                activation_id: candidate.activation_id.clone(),
                activation_operation_id: permit.operation_id,
                activation_nonce_digest,
                process: eliot_kernel_service::ProcessObservation {
                    process_id: PlatformHandle::new("pid:42:start:10").expect("process"),
                    job_object_id: candidate.job_object_id.clone(),
                    state: eliot_runtime_contracts::ServiceProcessState::Ready,
                    health: HealthVector::healthy(),
                    evidence_refs: vec![
                        PlatformHandle::new("ev-activation-test").expect("evidence"),
                    ],
                },
                health: HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("ev-activation-test").expect("evidence")],
            })
            .expect("publish Ready state");
    }
    *kernel
        .agent_bridge_profile
        .lock()
        .expect("bridge profile lock") = Some(AgentBridgeProfile {
        admission: admission.clone(),
        declaration: declaration.clone(),
    });

    let deadline = unix_ms().saturating_add(60_000);
    let pipe_name = format!(r"\\.\pipe\eliot\activation-v2-live-{}", std::process::id());
    let (receipt_sha256, connection_id) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bridge fixture runtime")
        .block_on(async {
            let bridge_expectation =
                eliot_platform_windows::NamedPipePeerExpectation::new_for_dynamic_process(
                    bridge_sid,
                    executable.image_path().to_owned(),
                    executable_identity,
                )
                .expect("bridge expectation");
            let peers = eliot_platform_windows::NamedPipePeerSet::new(vec![
                eliot_platform_windows::NamedPipePeerProfile::new(
                    eliot_platform_windows::NamedPipePeerKind::AgentBridge,
                    bridge_expectation,
                    Some(admission.profile_id.as_str().to_owned()),
                )
                .expect("bridge peer profile"),
            ])
            .expect("bridge peer set");
            let mut server = eliot_ipc::NamedPipeServer::create_with_peer_set(&pipe_name, &peers)
                .expect("bridge fixture server");
            let (selection, (mut client, client_selection)) = tokio::try_join!(
                server.wait_for_authenticated_client_with_peer_set(
                    std::time::Duration::from_secs(5),
                    &peers,
                ),
                eliot_ipc::NamedPipeTransport::connect_authenticated_with_peer_set(
                    &pipe_name,
                    std::time::Duration::from_secs(5),
                    &peers,
                ),
            )
            .expect("bridge fixture connection");
            assert_eq!(selection, client_selection);
            let handshake = kernel
                .begin_agent_bridge(&selection, server.peer_identity().clone())
                .expect("server-first bridge challenge");
            server
                .send_frame(&handshake.challenge_frame, kernel.ipc_limits())
                .await
                .expect("send bridge challenge");
            let challenge = client
                .receive_frame(kernel.ipc_limits())
                .await
                .expect("receive bridge challenge");
            let hello = declaration
                .client_hello(handshake.challenge.challenge_nonce.clone())
                .expect("bridge hello");
            let hello_frame = eliot_ipc::client_hello_frame(&handshake.connection_id, &hello)
                .expect("bridge hello frame");
            assert_eq!(challenge, handshake.challenge_frame);
            client
                .send_frame(&hello_frame, kernel.ipc_limits())
                .await
                .expect("send bridge hello");
            let received_hello = server
                .receive_frame(kernel.ipc_limits())
                .await
                .expect("receive bridge hello");
            let receipt = kernel
                .accept_agent_bridge_hello(&handshake.connection_id, &received_hello)
                .expect("accept bridge hello");
            (receipt.receipt_sha256, handshake.connection_id)
        });

    let mut ticket = activation_v2_ticket(name, deadline);
    ticket.connection_id = connection_id;
    ticket.peer_admission_receipt_sha256 = receipt_sha256;
    let ticket = ticket
        .with_computed_digest()
        .expect("live bridge ticket digest");
    kernel
        .agent_activation_pending
        .lock()
        .expect("pending lock")
        .entries
        .insert(ticket.ticket_id.clone(), activation_v2_entry(&ticket));
    (root, kernel, ticket)
}

#[cfg(windows)]
fn activation_retention_record(
    ticket: &AgentActivationResolutionTicket,
    result: &eliot_protocol::AgentActivationResolutionResult,
) -> eliot_ors::ActivationResultRetentionRecord {
    eliot_ors::ActivationResultRetentionRecord {
        ticket_id: ticket.ticket_id.clone(),
        ticket_sha256: ticket.ticket_sha256.clone(),
        ticket_payload: serde_json::to_string(ticket).expect("ticket payload"),
        result_sha256: result.result_sha256.clone(),
        result_payload: serde_json::to_string(result).expect("result payload"),
        connection_id: ticket.connection_id.clone(),
        state_fence: sha256_json(&ticket.state_fence).expect("fence digest"),
        phase: eliot_ors::ActivationResultRetentionPhase::AcceptedTerminal,
        retention_order: 0,
    }
}

#[cfg(windows)]
#[test]
fn activation_result_ledger_rehydrates_without_bridge_state_or_session() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-rehydrate-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(root.join(".eliot")).expect("test ORS directory");
    let ticket = activation_v2_ticket("activation-ticket-rehydrate", 2_000);
    let result = activation_v2_resolved(&ticket, 1_000);
    let ors_path = root.join(".eliot").join("kernel-ors.redb");
    let ors = eliot_ors::RedbRecoveryStore::open(&ors_path).expect("open ORS");
    ors.retain_activation_result(&activation_retention_record(&ticket, &result))
        .expect("retain activation result");
    drop(ors);

    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("rehydrate kernel");
    let ledger = kernel
        .agent_activation_results
        .lock()
        .expect("result ledger lock");
    assert_eq!(ledger.len(), 1);
    assert_eq!(
        ledger
            .get(&ticket.ticket_id)
            .expect("rehydrated ticket")
            .result,
        result
    );
    drop(ledger);
    assert!(
        kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock")
            .entries
            .is_empty()
    );
    assert!(
        kernel
            .agent_bridge_connections
            .lock()
            .expect("connection lock")
            .is_empty()
    );
    let query =
        AgentActivationResultReconcile::new(ticket.ticket_id.clone(), result.result_sha256.clone())
            .expect("reconcile query");
    let ack = kernel
        .reconcile_agent_activation_result(&query)
        .expect("rehydrated result reconciles");
    assert_eq!(
        ack.outcome,
        eliot_protocol::AgentActivationResultAckOutcome::Reconciled
    );
    let missing =
        AgentActivationResultReconcile::new("activation-ticket-missing".to_owned(), "f".repeat(64))
            .expect("missing reconcile query");
    let missing_ack = kernel
        .reconcile_agent_activation_result(&missing)
        .expect("missing result reconciles as unknown");
    assert_eq!(
        missing_ack.outcome,
        eliot_protocol::AgentActivationResultAckOutcome::Unknown
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_result_ledger_typed_corruption_fences_startup() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-corrupt-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(root.join(".eliot")).expect("test ORS directory");
    let ticket = activation_v2_ticket("activation-ticket-corrupt", 2_000);
    let mut result = activation_v2_resolved(&ticket, 1_000);
    result.ticket_sha256 = "e".repeat(64);
    let ors_path = root.join(".eliot").join("kernel-ors.redb");
    let ors = eliot_ors::RedbRecoveryStore::open(&ors_path).expect("open ORS");
    ors.retain_activation_result(&activation_retention_record(&ticket, &result))
        .expect("retain typed-corrupt result");
    drop(ors);

    let Err(error) = KernelComposition::new(KernelConfig::new(&root)) else {
        panic!("typed-corrupt retention must fence startup");
    };
    assert!(matches!(error, KernelBuildError::Ors(_)));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_resolves_canonical_v2_envelope_result() {
    let ticket = activation_v2_ticket("activation-ticket-v2", 2_000);
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("canonical", &ticket, Some(result.clone()), None);
    let envelope = activation_host_envelope(&ticket, &result.result_sha256, &ticket.connection_id);
    let resolved = kernel
        .host_request_activation_resolution(&envelope)
        .expect("canonical v2 result must be addressable");
    assert_eq!(resolved.result_sha256, result.result_sha256);
    assert!(resolved.resolved_binding().is_some());
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_falls_back_to_raw_result_map() {
    let ticket = activation_v2_ticket("activation-ticket-raw", 2_000);
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("raw-fallback", &ticket, None, Some(result.clone()));
    let envelope = activation_host_envelope(&ticket, &result.result_sha256, &ticket.connection_id);
    let resolved = kernel
        .host_request_activation_resolution(&envelope)
        .expect("raw P-04 result must stay addressable");
    assert_eq!(resolved.result_sha256, result.result_sha256);
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_conflicting_ledgers_fail_closed() {
    let ticket = activation_v2_ticket("activation-ticket-priority", 2_000);
    let canonical = activation_v2_resolved(&ticket, 1_000);
    let raw = activation_v2_resolved(&ticket, 1_001);
    assert_ne!(
        canonical.result_sha256, raw.result_sha256,
        "fixture requires two distinct result identities"
    );
    let (root, kernel) =
        activation_kernel_with_ticket("priority", &ticket, Some(canonical.clone()), Some(raw));
    let envelope =
        activation_host_envelope(&ticket, &canonical.result_sha256, &ticket.connection_id);
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("conflicting ledger entries for one ticket must conflict");
    assert!(
        matches!(error, TransportError::IdentityConflict),
        "unexpected error: {error:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_matching_ledgers_stay_idempotent() {
    let ticket = activation_v2_ticket("activation-ticket-dual-match", 2_000);
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) = activation_kernel_with_ticket(
        "dual-match",
        &ticket,
        Some(result.clone()),
        Some(result.clone()),
    );
    let envelope = activation_host_envelope(&ticket, &result.result_sha256, &ticket.connection_id);
    let resolved = kernel
        .host_request_activation_resolution(&envelope)
        .expect("exact digest match across both ledgers stays idempotent");
    assert_eq!(resolved.result_sha256, result.result_sha256);
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_without_any_result_is_unknown() {
    let ticket = activation_v2_ticket("activation-ticket-unknown", 2_000);
    let probe = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) = activation_kernel_with_ticket("unknown", &ticket, None, None);
    let envelope = activation_host_envelope(&ticket, &probe.result_sha256, &ticket.connection_id);
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("result-less ticket must not resolve");
    assert!(
        matches!(error, TransportError::UnknownRequest),
        "unexpected error: {error:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_non_resolved_v2_fails_closed() {
    let ticket = activation_v2_ticket("activation-ticket-negative", 2_000);
    let failed = activation_v2_failed(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("negative", &ticket, Some(failed.clone()), None);
    let envelope = activation_host_envelope(&ticket, &failed.result_sha256, &ticket.connection_id);
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("a negative disposition must never yield a binding");
    assert!(
        matches!(error, TransportError::SessionFenced),
        "unexpected error: {error:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_wrong_connection_fails_closed() {
    let ticket = activation_v2_ticket("activation-ticket-conn", 2_000);
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("connection", &ticket, Some(result.clone()), None);
    let envelope = activation_host_envelope(&ticket, &result.result_sha256, "other-connection");
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("cross-connection resolution must fail closed");
    assert!(
        matches!(error, TransportError::SessionFenced),
        "unexpected error: {error:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

// ---------------------------------------------------------------------------
// #203 smallest slice: the legacy raw P-04 projection leg re-validates the
// retained result against its exact pending ticket before mutating anything.
// A tampered negative result is rejected with the pending evidence preserved.
// ---------------------------------------------------------------------------
// #203 slice 2: a projected-then-retried ticket answers from the known
// retained result instead of falling back, fail-closed on any mismatch.
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[test]
fn activation_host_request_projected_retry_answers_from_retained_result() {
    let ticket = activation_v2_ticket("activation-ticket-projected-retry-203", 2_000);
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("projected-retry-203", &ticket, Some(result.clone()), None);
    // Project the bridge leg: the pending entry is consumed but the exact
    // v2 record stays retained for replay/reconcile.
    {
        let mut pending = kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock");
        pending.entries.remove(&ticket.ticket_id);
        assert!(
            pending.results.contains_key(&ticket.ticket_id),
            "projected result must stay retained"
        );
    }
    {
        let pending = kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock");
        assert!(
            !pending.entries.contains_key(&ticket.ticket_id),
            "projected entry must be consumed"
        );
        assert!(
            pending.results.contains_key(&ticket.ticket_id),
            "projected result must stay retained"
        );
    }
    let envelope = activation_host_envelope(&ticket, &result.result_sha256, &ticket.connection_id);
    let resolved = kernel
        .host_request_activation_resolution(&envelope)
        .expect("projected-then-retried ticket must answer from the known result");
    assert_eq!(resolved.result_sha256, result.result_sha256);
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_projected_retry_wrong_connection_fails_closed() {
    let ticket = activation_v2_ticket("activation-ticket-projected-conn-203", 2_000);
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("projected-conn-203", &ticket, Some(result.clone()), None);
    {
        let mut pending = kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock");
        pending.entries.remove(&ticket.ticket_id);
    }
    let envelope = activation_host_envelope(&ticket, &result.result_sha256, "other-connection");
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("cross-connection retry after projection must fail closed");
    assert!(
        matches!(error, TransportError::SessionFenced),
        "unexpected error: {error:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_raw_negative_projection_rejects_tampered_result_with_pending_preserved() {
    use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};

    let ticket = activation_v2_ticket("activation-ticket-raw-tamper-203", 2_000);
    let valid = activation_v2_failed(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("raw-tamper-203", &ticket, None, Some(valid.clone()));
    let mut tampered = valid.clone();
    tampered.ticket_sha256 = "0".repeat(64);
    let frame = Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: ticket.connection_id.clone(),
        request_id: None,
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: None,
        payload: ProtocolPayload::Json(serde_json::Value::Null),
        trace_context: std::collections::BTreeMap::new(),
    };
    let error = kernel
        .activation_result_response(&ticket.connection_id, &frame, &ticket.ticket_id, &tampered)
        .expect_err("tampered negative result must be rejected before mutation");
    assert!(
        matches!(error, TransportError::SessionFenced),
        "unexpected error: {error:?}"
    );
    // Pending evidence is preserved: the exact ticket entry and the retained
    // raw result survive the rejected projection verbatim.
    {
        let pending = kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock");
        assert!(
            pending.entries.contains_key(&ticket.ticket_id),
            "rejected projection must preserve the pending entry"
        );
    }
    {
        let results = kernel
            .agent_activation_results
            .lock()
            .expect("raw result lock");
        let retained = results
            .get(&ticket.ticket_id)
            .expect("rejected projection must preserve the retained result");
        assert_eq!(retained.result.result_sha256, valid.result_sha256);
    }
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the restart test keeps direct-seed and live-bridge routes side by side"
)]
fn activation_terminal_negative_replay_survives_restart_without_pending_entry() {
    let no_result_ticket = activation_v2_ticket("activation-ticket-no-result-deadline", 2_000);
    let no_result = activation_v2_failed(&no_result_ticket, 1_000);
    let (no_result_root, no_result_kernel) =
        activation_kernel_with_ticket("no-result-deadline", &no_result_ticket, None, None);

    let timeout = no_result_kernel
        .submit_agent_activation_resolution_result(no_result.clone())
        .expect_err("a result-less expired ticket must return Timeout");
    assert!(
        matches!(timeout, TransportError::Timeout),
        "unexpected no-result deadline error: {timeout:?}"
    );
    drop(no_result_kernel);
    let restarted_no_result = KernelComposition::new(KernelConfig::new(&no_result_root))
        .expect("restart without a retained result");
    let unknown_after_restart = restarted_no_result
        .submit_agent_activation_resolution_result(no_result.clone())
        .expect_err("a result-less ticket is not restored as a pending entry");
    assert!(
        matches!(unknown_after_restart, TransportError::UnknownRequest),
        "unexpected result-less restart error: {unknown_after_restart:?}"
    );
    drop(restarted_no_result);
    let _ = std::fs::remove_dir_all(no_result_root);

    let (commit_root, commit_kernel, commit_ticket) =
        activation_kernel_with_live_bridge_ticket("activation-ticket-negative-commit-restart");
    let commit_failed = activation_v2_failed(&commit_ticket, 1_000);
    let commit_ack = commit_kernel
        .submit_agent_activation_result(
            eliot_protocol::AgentActivationResultSubmit::new(commit_failed.clone())
                .expect("commit-route result submit"),
        )
        .expect("live bridge terminal negative submit");
    assert_eq!(
        commit_ack.outcome,
        eliot_protocol::AgentActivationResultAckOutcome::Accepted
    );
    assert_eq!(commit_ack.result, Some(commit_failed.clone()));
    drop(commit_kernel);

    let restarted_commit = KernelComposition::new(KernelConfig::new(&commit_root))
        .expect("restart after a live bridge terminal negative submit");
    assert!(
        restarted_commit
            .agent_activation_pending
            .lock()
            .expect("pending lock")
            .entries
            .is_empty(),
        "commit-route restart must not restore a live pending entry"
    );
    let commit_replay = restarted_commit
        .submit_agent_activation_result(
            eliot_protocol::AgentActivationResultSubmit::new(commit_failed.clone())
                .expect("exact commit-route replay submit"),
        )
        .expect("exact commit-route terminal negative replay after restart");
    assert_eq!(
        commit_replay.outcome,
        eliot_protocol::AgentActivationResultAckOutcome::ExactReplay
    );
    assert_eq!(commit_replay.result, Some(commit_failed.clone()));

    let commit_changed = eliot_protocol::AgentActivationResolutionResult::new(
        &commit_ticket,
        1_000,
        eliot_protocol::AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "changed-commit-failure".to_owned(),
        },
    )
    .expect("changed commit-route terminal negative");
    let commit_conflict = restarted_commit
        .submit_agent_activation_result(
            eliot_protocol::AgentActivationResultSubmit::new(commit_changed)
                .expect("changed commit-route replay submit"),
        )
        .expect_err("changed commit-route replay after restart must conflict");
    assert!(
        matches!(commit_conflict, TransportError::IdentityConflict),
        "unexpected commit-route changed replay error: {commit_conflict:?}"
    );
    drop(restarted_commit);
    let _ = std::fs::remove_dir_all(commit_root);

    let ticket = activation_v2_ticket("activation-ticket-negative-restart", 2_000);
    let failed = activation_v2_failed(&ticket, 1_000);
    let retained_root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-negative-restart-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(retained_root.join(".eliot")).expect("retained test root");
    let ors_path = retained_root.join(".eliot").join("kernel-ors.redb");
    let ors = eliot_ors::RedbRecoveryStore::open(&ors_path).expect("open retained ORS");
    ors.retain_activation_result(&activation_retention_record(&ticket, &failed))
        .expect("retain terminal negative");
    drop(ors);

    let kernel = KernelComposition::new(KernelConfig::new(&retained_root))
        .expect("rehydrate terminal negative");
    assert!(
        kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock")
            .entries
            .is_empty(),
        "restart must not restore a live pending entry"
    );

    let exact_submit = eliot_protocol::AgentActivationResultSubmit::new(failed.clone())
        .expect("exact result submit");
    let replay = kernel
        .submit_agent_activation_result(exact_submit)
        .expect("exact terminal negative replay after restart");
    assert_eq!(
        replay.outcome,
        eliot_protocol::AgentActivationResultAckOutcome::ExactReplay
    );
    assert_eq!(replay.result, Some(failed.clone()));

    let changed = eliot_protocol::AgentActivationResolutionResult::new(
        &ticket,
        1_000,
        eliot_protocol::AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "changed-failure".to_owned(),
        },
    )
    .expect("changed terminal negative");
    let changed_submit = eliot_protocol::AgentActivationResultSubmit::new(changed.clone())
        .expect("changed result submit");
    let conflict = kernel
        .submit_agent_activation_result(changed_submit)
        .expect_err("changed replay after restart must conflict");
    assert!(
        matches!(conflict, TransportError::IdentityConflict),
        "unexpected changed replay error: {conflict:?}"
    );

    kernel
        .submit_agent_activation_resolution_result(failed)
        .expect("raw exact terminal negative replay after restart");
    let raw_conflict = kernel
        .submit_agent_activation_resolution_result(changed)
        .expect_err("raw changed replay after restart must conflict");
    assert!(
        matches!(raw_conflict, TransportError::IdentityConflict),
        "unexpected raw changed replay error: {raw_conflict:?}"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(retained_root);
}
