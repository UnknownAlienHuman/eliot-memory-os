//! Kernel activation claim tests — acceptance-only scope.
//!
//! Architecture traceability:
//! - `A2.3` (`docs/architecture/A02-03-modular-architecture.md`) and
//!   `ARCH-MOD-01` — modular architecture, ordinary module boundary.
//! - `I2.16`
//!   (`docs/architecture/I02-16-crate-size-and-agent-context-envelope.md`) —
//!   crate-size/Agent Context Envelope.
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
        demand_id: request.demand_id.clone(),
        activation_request_sha256: request.request_sha256.clone(),
        peer_admission_receipt_sha256: request.peer_admission_receipt_sha256.clone(),
        connection_id: request.connection_id.clone(),
        workspace_selector: request.workspace_selector.clone(),
        cancellation_id: request.request_identity.cancellation_id.clone(),
        state_fence,
        kernel_deadline_unix_ms: deadline,
        successor_of: None,
        ticket_sha256: "c".repeat(64),
    };
    (
        ticket_id,
        AgentActivationPending {
            ticket,
            request,
            claim_lease_until_unix_ms: None,
            claim_dependency_ref: None,
            claim_dependency_revision: None,
            successor_of: None,
            owner_readback: None,
        },
    )
}

#[cfg(windows)]
#[test]
fn activation_claim_lease_expiry_never_requeues_the_ticket() {
    let (ticket_id, entry) = activation_test_entry(2_000);
    let mut pending = AgentActivationPendingState::default();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id, entry);

    let first = pending
        .claim_at(1, "governor.readiness", "revision-current")
        .expect("first claim");
    assert_eq!(first.ticket_id, "activation-ticket-test");
    assert!(
        pending
            .claim_at(
                AGENT_ACTIVATION_CLAIM_LEASE_MS,
                "governor.readiness",
                "revision-current"
            )
            .is_none()
    );
    assert!(
        pending
            .claim_at(
                AGENT_ACTIVATION_CLAIM_LEASE_MS + 1,
                "governor.readiness",
                "revision-current"
            )
            .is_none(),
        "claim expiry is reconciliation evidence, not a semantic retry"
    );
    assert!(
        pending
            .claim_at(1_999, "governor.readiness", "revision-current")
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn activation_claim_expires_at_deadline() {
    let (ticket_id, entry) = activation_test_entry(2_000);
    let mut pending = AgentActivationPendingState::default();
    pending.fifo.push_back(ticket_id.clone());
    pending.entries.insert(ticket_id.clone(), entry.clone());
    assert!(
        pending
            .claim_at(2_000, "governor.readiness", "revision-current")
            .is_none(),
        "deadline is inclusive"
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

// ---------------------------------------------------------------------------
// #203 / #1115: one canonical terminal result identity per ticket across the
// daemon and host-request legs.
// ---------------------------------------------------------------------------

/// One directly seeded ticket carrying the production activation window, so a
/// fixture never seeds a deadline below the real wall clock (which would make
/// `store.rs:9401-9404` expire the lifecycle before the result is admitted).
#[cfg(windows)]
fn activation_v2_ticket(ticket_id: &str) -> AgentActivationResolutionTicket {
    activation_v2_ticket_with_deadline(
        ticket_id,
        activation_v2_deadline(AGENT_BRIDGE_ACTIVATION_WINDOW_MS),
    )
}

#[cfg(windows)]
fn activation_v2_ticket_with_deadline(
    ticket_id: &str,
    deadline: u64,
) -> AgentActivationResolutionTicket {
    AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: ticket_id.to_owned(),
        activation_request_id: RequestId::new("activation-request-test").expect("request id"),
        demand_id: "activation-demand-test".to_owned(),
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: "activation-connection-test".to_owned(),
        workspace_selector: None,
        cancellation_id: "activation-cancellation-test".to_owned(),
        state_fence: StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("resource generation"),
        ),
        kernel_deadline_unix_ms: deadline,
        successor_of: None,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("ticket digest")
}

/// Wall-clock-relative ticket deadline, mirroring the production seeding in
/// `agent_bridge.rs::begin_agent_bridge_inner` (`:447-448`):
/// `activation_deadline_unix_ms: unix_ms().saturating_add(AGENT_BRIDGE_ACTIVATION_WINDOW_MS)`.
#[cfg(windows)]
fn activation_v2_deadline(window_ms: u64) -> u64 {
    unix_ms().saturating_add(window_ms)
}

/// The latest instant at which production could still admit this ticket.
///
/// `stage_activation_ticket` refuses a `now` at or past the kernel deadline
/// (`store.rs:9014`) and so does `claim_activation_ticket` (`store.rs:9275`), so
/// a ticket whose deadline is still ahead is seeded at `unix_ms()`, exactly as
/// production does. A ticket whose deadline has already elapsed is seeded at the
/// last instant it was still admissible: that is how an elapsed deadline is
/// reproduced without sleeping and without a sentinel value.
#[cfg(windows)]
fn activation_v2_seed_now(ticket: &AgentActivationResolutionTicket) -> u64 {
    unix_ms().min(ticket.kernel_deadline_unix_ms.saturating_sub(1))
}

/// Stages one ORS activation lifecycle exactly as
/// `begin_agent_bridge_inner` does (`agent_bridge.rs:776` and `:842` pass
/// `let enqueue_now = unix_ms();`), carrying the ticket's own activation
/// request identity (`agent_bridge.rs:818-827`), which is what rehydration
/// compares (`agent_bridge.rs:2691-2692`).
#[cfg(windows)]
fn activation_v2_stage_lifecycle(
    ors: &eliot_ors::RedbRecoveryStore,
    ticket: &AgentActivationResolutionTicket,
) {
    let entry = activation_v2_entry(ticket);
    ors.stage_activation_ticket(
        &eliot_ors::ActivationLifecycleRecord {
            ticket_id: ticket.ticket_id.clone(),
            ticket_sha256: ticket.ticket_sha256.clone(),
            ticket_payload: serde_json::to_string(ticket).expect("ticket payload"),
            activation_request_id: ticket.activation_request_id.as_str().to_owned(),
            activation_request_sha256: ticket.activation_request_sha256.clone(),
            connection_id: ticket.connection_id.clone(),
            state_fence: sha256_json(&ticket.state_fence).expect("fence digest"),
            kernel_deadline_unix_ms: ticket.kernel_deadline_unix_ms,
            cancellation_id: entry.request.request_identity.cancellation_id.clone(),
            state: eliot_ors::ActivationLifecycleState::Pending,
            lifecycle_order: 0,
            result_sha256: None,
            claim_owner: None,
            claim_expires_at_unix_ms: None,
            successor_of: entry.successor_of.clone(),
            successor_ticket_id: None,
            terminal_reason: None,
        },
        activation_v2_seed_now(ticket),
    )
    .expect("stage activation lifecycle");
}

/// Stages and then claims one ORS activation lifecycle with the exact values
/// production writes, so no seeded claim lease is already elapsed by the time
/// the fixture admits a result.
///
/// `claim_agent_activation_ticket` (`:906-917`) claims with:
/// ```text
/// let now = unix_ms();
/// let claim_expires_at = now
///     .saturating_add(AGENT_ACTIVATION_CLAIM_LEASE_MS)
///     .min(ticket.kernel_deadline_unix_ms);
/// ors.claim_activation_ticket(&ticket.ticket_id, "eliotd", now, claim_expires_at)
/// ```
/// Nothing in production is an absolute epoch-ms literal.
#[cfg(windows)]
fn activation_v2_seed_claimed_lifecycle(
    ors: &eliot_ors::RedbRecoveryStore,
    ticket: &AgentActivationResolutionTicket,
) {
    activation_v2_stage_lifecycle(ors, ticket);
    let claim_now = activation_v2_seed_now(ticket);
    let claim_expires_at = claim_now
        .saturating_add(AGENT_ACTIVATION_CLAIM_LEASE_MS)
        .min(ticket.kernel_deadline_unix_ms);
    ors.claim_activation_ticket(&ticket.ticket_id, "eliotd", claim_now, claim_expires_at)
        .expect("claim activation lifecycle")
        .expect("a staged activation lifecycle is claimable");
}

#[cfg(windows)]
fn activation_v2_entry(ticket: &AgentActivationResolutionTicket) -> AgentActivationPending {
    let (_, template) = activation_test_entry(ticket.kernel_deadline_unix_ms);
    AgentActivationPending {
        ticket: ticket.clone(),
        request: template.request,
        claim_lease_until_unix_ms: None,
        claim_dependency_ref: None,
        claim_dependency_revision: None,
        successor_of: ticket.successor_of.as_ref().map(|predecessor| {
            eliot_ors::ActivationSuccessorBinding {
                predecessor_ticket_id: predecessor.predecessor_ticket_id.clone(),
                predecessor_ticket_sha256: predecessor.predecessor_ticket_sha256.clone(),
                predecessor_result_sha256: predecessor.predecessor_result_sha256.clone(),
                dependency_ref: predecessor.dependency_ref.clone(),
                observed_dependency_revision: predecessor.observed_dependency_revision.clone(),
                not_before_unix_ms: predecessor.not_before_unix_ms,
            }
        }),
        owner_readback: None,
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
            correlation_projection: None,
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
    result: Option<eliot_protocol::AgentActivationResolutionResult>,
) -> (std::path::PathBuf, KernelComposition) {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-v2-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let entry = activation_v2_entry(ticket);
    activation_v2_seed_claimed_lifecycle(&kernel.generation_gateway.ors, ticket);
    {
        let mut pending = kernel
            .agent_activation_pending
            .lock()
            .expect("pending lock");
        pending.entries.insert(ticket.ticket_id.clone(), entry);
        if let Some(result) = result {
            kernel
                .retain_activation_result_durably(
                    &mut pending,
                    ticket,
                    &result,
                    AgentActivationResultPhase::AcceptedTerminal,
                )
                .expect("retain activation result");
        }
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
    deadline: u64,
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
            capabilities: Vec::new(),
            required_capabilities: capabilities.clone(),
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-host".to_owned(),
            failure_domain: "agent-bridge".to_owned(),
            owner: AGENT_BRIDGE_MODULE_ID.to_owned(),
            hot_replace: false,
            startup_after: capabilities.clone(),
            drain_before: capabilities.clone(),
            invalidation_triggers: Vec::new(),
            supervision_plan: "one_for_one".to_owned(),
            child_restart: "transient".to_owned(),
            restart_intensity: "3/10m".to_owned(),
            resource_profile: "background-medium".to_owned(),
            privacy_classes: vec!["PUBLIC".to_owned()],
            permissions: Vec::new(),
            health_contract: "health/agent-bridge-v1".to_owned(),
            checkpoint_contract: "checkpoint/bridge-v1".to_owned(),
            compatibility_state: "rebuildable".to_owned(),
            independent_test_profile: "module/agent-bridge".to_owned(),
            contract_fixture_set: "eliot.agent-bridge.v1/agent.bridge.activate".to_owned(),
            affected_test_tags: vec!["agent-bridge".to_owned()],
            architecture: Vec::new(),
            telemetry: "telemetry/agent-bridge-v1".to_owned(),
            removal_boundary: "agent-bridge".to_owned(),
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

    let pipe_name = format!(
        r"\\.\pipe\eliot\activation-v2-live-{name}-{}",
        std::process::id()
    );
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

    let mut ticket = activation_v2_ticket_with_deadline(name, deadline);
    ticket.connection_id = connection_id;
    ticket.peer_admission_receipt_sha256 = receipt_sha256;
    let ticket = ticket
        .with_computed_digest()
        .expect("live bridge ticket digest");
    let entry = activation_v2_entry(&ticket);
    activation_v2_seed_claimed_lifecycle(&kernel.generation_gateway.ors, &ticket);
    kernel
        .agent_activation_pending
        .lock()
        .expect("pending lock")
        .entries
        .insert(ticket.ticket_id.clone(), entry);
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
fn retain_test_activation_result(
    ors: &eliot_ors::RedbRecoveryStore,
    ticket: &AgentActivationResolutionTicket,
    result: &eliot_protocol::AgentActivationResolutionResult,
) {
    // The claim seed and the commit clock move together: the claim is taken
    // from `unix_ms()` with the production lease (see
    // `activation_v2_seed_claimed_lifecycle`), and the commit argument is the
    // fresh `unix_ms()` production passes at `agent_bridge.rs:1179`, so the
    // commit lands inside the live lease and strictly before the deadline.
    activation_v2_seed_claimed_lifecycle(ors, ticket);
    ors.commit_activation_result(
        &activation_retention_record(ticket, result),
        "eliotd",
        None,
        unix_ms(),
    )
    .expect("commit activation result");
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
    let ticket = activation_v2_ticket("activation-ticket-rehydrate");
    let result = activation_v2_resolved(&ticket, 1_000);
    let ors_path = root.join(".eliot").join("kernel-ors.redb");
    let ors = eliot_ors::RedbRecoveryStore::open(&ors_path).expect("open ORS");
    retain_test_activation_result(&ors, &ticket, &result);
    drop(ors);

    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("rehydrate kernel");
    let pending = kernel
        .agent_activation_pending
        .lock()
        .expect("activation state lock");
    assert_eq!(pending.results.len(), 1);
    assert_eq!(
        pending
            .results
            .get(&ticket.ticket_id)
            .expect("rehydrated ticket")
            .result,
        result
    );
    assert_eq!(
        pending.lifecycle(&ticket.ticket_id),
        AgentActivationLifecycle::Accepted
    );
    drop(pending);
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
        eliot_protocol::AgentActivationResultAckOutcome::Accepted
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
    let ticket = activation_v2_ticket("activation-ticket-corrupt");
    let mut result = activation_v2_resolved(&ticket, 1_000);
    result.ticket_sha256 = "e".repeat(64);
    let ors_path = root.join(".eliot").join("kernel-ors.redb");
    let ors = eliot_ors::RedbRecoveryStore::open(&ors_path).expect("open ORS");
    retain_test_activation_result(&ors, &ticket, &result);
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
    let ticket = activation_v2_ticket("activation-ticket-v2");
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) = activation_kernel_with_ticket("canonical", &ticket, Some(result.clone()));
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
fn activation_host_request_without_any_result_is_unknown() {
    let ticket = activation_v2_ticket("activation-ticket-unknown");
    let probe = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) = activation_kernel_with_ticket("unknown", &ticket, None);
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
    let ticket = activation_v2_ticket("activation-ticket-negative");
    let failed = activation_v2_failed(&ticket, 1_000);
    let (root, kernel) = activation_kernel_with_ticket("negative", &ticket, Some(failed.clone()));
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
    let ticket = activation_v2_ticket("activation-ticket-conn");
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) = activation_kernel_with_ticket("connection", &ticket, Some(result.clone()));
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
// #203 identity refusals on the host-request resolution leg. Each case mutates
// exactly one identity field of a fully valid envelope, so the comparison that
// fires is the one the case names. `HostRequestEnvelope::validate()` never runs
// on this path, so every mutated envelope is re-digested: a stale
// `envelope_sha256` would let the case pass for a weaker reason than the
// refusal it is meant to prove.
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[test]
fn activation_host_request_wrong_ticket_digest_fails_closed() {
    let ticket = activation_v2_ticket("activation-ticket-wrong-digest");
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("wrong-digest", &ticket, Some(result.clone()));
    let mut envelope =
        activation_host_envelope(&ticket, &result.result_sha256, &ticket.connection_id);
    envelope
        .activation_binding
        .as_mut()
        .expect("activation binding")
        .ticket_sha256 = "9".repeat(64);
    let envelope = envelope
        .with_computed_digest()
        .expect("wrong-digest envelope digest");
    // The ticket id and the result digest still match, so `validate_resolution`
    // clears `eliot-protocol/src/lib.rs:4344` and `result.result_sha256 !=
    // resolution_result_sha256` (`host_request_route.rs:3148`) and reaches
    // `result.ticket_sha256 != binding.ticket_sha256`
    // (`eliot-protocol/src/lib.rs:4345`).
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("a binding for another ticket digest must never resolve");
    assert!(
        matches!(error, TransportError::IdentityConflict),
        "unexpected error: {error:?}"
    );
    assert!(
        kernel
            .agent_bridge_connections
            .lock()
            .expect("connection lock")
            .is_empty(),
        "the refusal holds no Session authority"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_wrong_state_fence_fails_closed() {
    let ticket = activation_v2_ticket("activation-ticket-wrong-fence");
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("wrong-fence", &ticket, Some(result.clone()));
    let mut envelope =
        activation_host_envelope(&ticket, &result.result_sha256, &ticket.connection_id);
    // A valid but different State Fence: same shape, different epoch and
    // generation, so the refusal cannot be attributed to an unparsable fence.
    envelope.state_fence = StateFence::new(
        test_epoch(2),
        ResourceGeneration::new(2).expect("resource generation"),
    );
    let envelope = envelope
        .with_computed_digest()
        .expect("wrong-fence envelope digest");
    // The ticket id, ticket digest and result digest all still match, so
    // `result.ticket_state_fence != self.state_fence`
    // (`eliot-protocol/src/lib.rs:4347`) is the only clause left to fire, and it
    // is the only State Fence check on this leg.
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("a binding under another State Fence must never resolve");
    assert!(
        matches!(error, TransportError::IdentityConflict),
        "unexpected error: {error:?}"
    );
    assert!(
        kernel
            .agent_bridge_connections
            .lock()
            .expect("connection lock")
            .is_empty(),
        "the refusal holds no Session authority"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_host_request_wrong_ticket_identity_fails_closed() {
    // The card's wrong-ticket clause cannot be reached by mutating the envelope.
    // `host_request_activation_resolution_under_transition` loads the lifecycle
    // BY `activation_binding.ticket_id` (`:3117-3122`) and then compares
    // `result.ticket_id` against that same string (`:3147`), so for any ticket
    // that exists the comparison is self-satisfying, and for a ticket that does
    // not exist the lookup already returned `UnknownRequest` (a duplicate of
    // `activation_host_request_without_any_result_is_unknown`). This case
    // therefore reaches the clause through the only route that is both reachable
    // and honest: ORS keys a retention row by the lifecycle ticket and never
    // inspects the typed payload (`ActivationResultRetentionRecord::validate`),
    // so the bound ticket's row is made to carry a second, real ticket's sealed
    // result. Both identities are seeded, claimed and retained, so the refused
    // pair is not a fabricated string.
    let mut impostor = activation_v2_ticket("activation-ticket-wrong-id-impostor");
    impostor.activation_request_id =
        RequestId::new("activation-request-wrong-id-impostor").expect("request id");
    let impostor = impostor
        .with_computed_digest()
        .expect("impostor ticket digest");
    let impostor_result = activation_v2_resolved(&impostor, 1_000);
    let ticket = activation_v2_ticket("activation-ticket-wrong-id-bound");
    let (root, kernel) = activation_kernel_with_ticket("wrong-ticket", &ticket, None);
    activation_v2_seed_claimed_lifecycle(&kernel.generation_gateway.ors, &impostor);
    kernel
        .generation_gateway
        .ors
        .commit_activation_result(
            &activation_retention_record(&impostor, &impostor_result),
            "eliotd",
            None,
            unix_ms(),
        )
        .expect("retain the impostor result");
    kernel
        .generation_gateway
        .ors
        .commit_activation_result(
            &activation_retention_record(&ticket, &impostor_result),
            "eliotd",
            None,
            unix_ms(),
        )
        .expect("retain the impostor result under the bound ticket");
    let envelope = activation_host_envelope(
        &ticket,
        &impostor_result.result_sha256,
        &ticket.connection_id,
    );
    // The retained payload is internally valid and its digest matches the
    // lifecycle, so `result.validate()` passes and the first clause of the pair
    // at `host_request_route.rs:3147-3150` — `result.ticket_id !=
    // activation_binding.ticket_id` — is the one that fires.
    let error = kernel
        .host_request_activation_resolution(&envelope)
        .expect_err("a result bound to another ticket must never resolve");
    assert!(
        matches!(error, TransportError::IdentityConflict),
        "unexpected error: {error:?}"
    );
    assert!(
        kernel
            .agent_bridge_connections
            .lock()
            .expect("connection lock")
            .is_empty(),
        "the refusal holds no Session authority"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn activation_result_admission_fences_an_elapsed_claim_lease() {
    // The seeded claim in every other fixture is fresh, so nothing else enters
    // the durable claimed-but-elapsed branch (`store.rs:9389-9400`). This case
    // constructs that state directly, without sleeping and without a sentinel:
    // `claim_activation_ticket` refuses only an expiry that is not later than
    // its own `now` (`store.rs:9218-9223`) and a `now` at or past the kernel
    // deadline (`store.rs:9275`), so a claim taken entirely inside its own past
    // lease is admitted and leaves the row durably `Claimed`.
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-elapsed-lease-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(root.join(".eliot")).expect("test ORS directory");
    let ticket = activation_v2_ticket("activation-ticket-elapsed-lease");
    let result = activation_v2_resolved(&ticket, 1_000);
    let ors_path = root.join(".eliot").join("kernel-ors.redb");
    let ors = eliot_ors::RedbRecoveryStore::open(&ors_path).expect("open ORS");
    activation_v2_stage_lifecycle(&ors, &ticket);
    let claim_now = unix_ms().saturating_sub(5_000);
    let claim_expires_at = claim_now.saturating_add(1);
    ors.claim_activation_ticket(&ticket.ticket_id, "eliotd", claim_now, claim_expires_at)
        .expect("claim a lease that has already elapsed")
        .expect("a staged activation lifecycle is claimable");
    let conflict = ors
        .commit_activation_result(
            &activation_retention_record(&ticket, &result),
            "eliotd",
            None,
            unix_ms(),
        )
        .expect_err("an elapsed claim lease must fence durable result admission");
    assert!(
        matches!(
            conflict,
            eliot_ors::OrsError::ActivationLifecycleStateConflict { .. }
        ),
        "unexpected error: {conflict:?}"
    );
    let lifecycle = ors
        .load_activation_lifecycle(&ticket.ticket_id)
        .expect("load activation lifecycle")
        .expect("durable activation lifecycle");
    assert_eq!(
        lifecycle.state,
        eliot_ors::ActivationLifecycleState::Reconciling,
        "an elapsed claim moves the row to Reconciling"
    );
    assert_eq!(
        lifecycle.terminal_reason.as_deref(),
        Some("claim lease elapsed before durable result admission"),
        "the reconciliation reason is the product's own"
    );
    drop(ors);
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
    let ticket = activation_v2_ticket("activation-ticket-projected-retry-203");
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("projected-retry-203", &ticket, Some(result.clone()));
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
    let ticket = activation_v2_ticket("activation-ticket-projected-conn-203");
    let result = activation_v2_resolved(&ticket, 1_000);
    let (root, kernel) =
        activation_kernel_with_ticket("projected-conn-203", &ticket, Some(result.clone()));
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
#[allow(
    clippy::too_many_lines,
    reason = "the restart test keeps direct-seed and live-bridge routes side by side"
)]
fn activation_terminal_negative_replay_survives_restart_without_pending_entry() {
    // The result-less deadline leg runs on the live bridge fixture, because the
    // bridge leg must still validate before `commit_fresh_activation_result`
    // reaches its inclusive deadline gate (`agent_bridge.rs:1432-1434`). The
    // ticket deadline is already in the past when the fixture seeds it: the
    // pending entry's ticket and the ORS lifecycle carry that one deadline, and
    // `activation_v2_seed_now` seeds both clocks at the last instant the ticket
    // was still admissible, so the submit-time `unix_ms()` is past it with no
    // waiting and no sentinel.
    let elapsed_deadline = unix_ms().saturating_sub(1_000);
    let (no_result_root, no_result_kernel, no_result_ticket) =
        activation_kernel_with_live_bridge_ticket(
            "activation-ticket-no-result-deadline",
            elapsed_deadline,
        );
    // `AgentActivationResolutionResult::new` requires a non-zero
    // `resolved_at_unix_ms` strictly earlier than the ticket deadline
    // (`activation_resolution.rs:861-866`), so this result was resolved one
    // millisecond before the deadline it must miss.
    let no_result = activation_v2_failed(
        &no_result_ticket,
        no_result_ticket.kernel_deadline_unix_ms.saturating_sub(1),
    );
    let timeout = no_result_kernel
        .submit_agent_activation_result(
            eliot_protocol::AgentActivationResultSubmit::new(no_result.clone())
                .expect("no-result submit"),
        )
        .expect_err("a result-less expired ticket must return Timeout");
    assert!(
        matches!(timeout, TransportError::Timeout),
        "unexpected no-result deadline error: {timeout:?}"
    );
    drop(no_result_kernel);
    // The refusal admits no durable result, and the still-claimed lifecycle is
    // never rehydrated: `rehydrate_activation_lifecycles` refuses every live
    // `Pending`/`Claimed` row (`agent_bridge.rs:2699-2708`), so the next
    // incarnation fences startup instead of restoring a pending entry.
    {
        let ors = eliot_ors::RedbRecoveryStore::open(
            &no_result_root.join(".eliot").join("kernel-ors.redb"),
        )
        .expect("reopen the no-result ORS");
        let lifecycle = ors
            .load_activation_lifecycle(&no_result_ticket.ticket_id)
            .expect("load the no-result lifecycle")
            .expect("durable no-result lifecycle");
        assert!(
            lifecycle.result_sha256.is_none(),
            "a result-less deadline refusal admits no durable result"
        );
    }
    let Err(no_result_restart) = KernelComposition::new(KernelConfig::new(&no_result_root)) else {
        panic!("a live result-less claim must never be rehydrated");
    };
    assert!(
        matches!(no_result_restart, KernelBuildError::Ors(_)),
        "unexpected result-less restart error: {no_result_restart:?}"
    );
    let _ = std::fs::remove_dir_all(no_result_root);

    let (commit_root, commit_kernel, commit_ticket) = activation_kernel_with_live_bridge_ticket(
        "activation-ticket-negative-commit-restart",
        activation_v2_deadline(AGENT_BRIDGE_ACTIVATION_WINDOW_MS),
    );
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
        eliot_protocol::AgentActivationResultAckOutcome::Accepted
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

    let ticket = activation_v2_ticket("activation-ticket-negative-restart");
    let failed = activation_v2_failed(&ticket, 1_000);
    let retained_root = std::env::temp_dir().join(format!(
        "eliot-kernel-activation-negative-restart-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(retained_root.join(".eliot")).expect("retained test root");
    let ors_path = retained_root.join(".eliot").join("kernel-ors.redb");
    let ors = eliot_ors::RedbRecoveryStore::open(&ors_path).expect("open retained ORS");
    retain_test_activation_result(&ors, &ticket, &failed);
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
        eliot_protocol::AgentActivationResultAckOutcome::Accepted
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

    drop(kernel);
    let _ = std::fs::remove_dir_all(retained_root);
}
