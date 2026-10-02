//! Daemon contract tests — test-oracle only.
//!
//! Architecture traceability: A2.3 (Governor/N4 composition), A13.2 and A13.8
//! (Kernel/Governor boundary and authenticated IPC).
//! Implementation traceability: I1.8 (artifact binding), I2.16 (generation
//! fencing), I2.23 (typed contract payloads).
//! This module is test-oracle only, exercises no transport, and asserts only
//! Governor or Kernel authority — no session, fence, or capability issuance.

use super::*;
use eliot_contracts::{EpochId, EpochLineageId};
use std::num::NonZeroU64;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
    Ok(EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A)?,
        NonZeroU64::new(sequence).ok_or("nonzero test sequence")?,
    )?)
}

fn valid_launch_config() -> Result<GovernorLaunchConfig, Box<dyn std::error::Error>> {
    Ok(GovernorLaunchConfig {
        instance_id: "test-instance".to_owned(),
        kernel: eliot_governor::KernelGenerationExpectation {
            service: "eliot-kernel".to_owned(),
            protocol: "eliot.kernel.v1".to_owned(),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
            principal: "local-service".to_owned(),
            generation: ResourceGeneration::new(1)?,
            authority_epoch: test_epoch(1)?,
        },
        protected_snapshot_digest: "b".repeat(64),
    })
}

fn resolution_ticket() -> Result<AgentActivationResolutionTicket, Box<dyn std::error::Error>> {
    AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: "ticket-1".to_owned(),
        activation_request_id: RequestId::new("activation-request-1")?,
        demand_id: "activation-demand-1".to_owned(),
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: "connection-1".to_owned(),
        workspace_selector: None,
        cancellation_id: "cancellation-1".to_owned(),
        state_fence: StateFence::new(test_epoch(1)?, ResourceGeneration::new(1)?),
        kernel_deadline_unix_ms: 100,
        successor_of: None,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(Into::into)
}

#[test]
fn semantic_resolution_mapping_is_immutable_and_ticket_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let ticket = resolution_ticket()?;
    ticket.validate()?;
    let snapshot = eliot_governor::GovernorActivationSnapshot {
        state_fence: ticket.state_fence.clone(),
        owner_revision: 1,
        principal_id: "principal-1".to_owned(),
        session_id: "session-1".to_owned(),
        task_id: eliot_contracts::TaskId::new("task-1")?,
        work_unit_id: "work-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        task_revision: 7,
        plan_id: "plan-1".to_owned(),
        plan_revision: "plan-revision-1".to_owned(),
    };
    let result = super::activation_projection::map_governor_outcome_to_protocol(
        &ticket,
        eliot_governor::GovernorActivationOutcome::Resolved(snapshot),
        50,
    )?;
    result.validate_against(&ticket)?;
    match &result.disposition {
        eliot_protocol::AgentActivationResolutionDisposition::Resolved { binding } => {
            assert_eq!(binding.principal_id, "principal-1");
            assert_eq!(binding.task_revision, "7");
            assert_eq!(binding.plan_revision, "plan-revision-1");
        }
        _ => panic!("expected Resolved"),
    }

    let mut substituted = ticket.clone();
    substituted.ticket_id = "ticket-other".to_owned();
    substituted.ticket_sha256 = substituted.compute_digest()?;
    assert!(result.validate_against(&substituted).is_err());

    let mut stale = ticket.clone();
    stale.state_fence = StateFence::new(test_epoch(1)?, ResourceGeneration::new(2)?);
    stale.ticket_sha256 = stale.compute_digest()?;
    assert!(result.validate_against(&stale).is_err());
    Ok(())
}

#[test]
fn semantic_resolution_deadline_is_inclusive() {
    assert!(!activation_deadline_expired(99, 100));
    assert!(activation_deadline_expired(100, 100));
    assert!(activation_deadline_expired(101, 100));
}

#[test]
fn production_config_has_no_root_or_environment_override() {
    assert!(!PROTECTED_CONFIG_RELATIVE.contains("ProgramData"));
    assert!(!PROTECTED_CONFIG_RELATIVE.contains(".."));
    assert!(!PROTECTED_STATE_RELATIVE.contains(".."));
}

#[test]
fn application_payload_always_carries_a_closed_operation_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let payload = operation_payload("health", serde_json::json!({}))?;
    assert_eq!(payload["operation"], "health");
    assert!(operation_payload("health", serde_json::json!([])).is_err());
    Ok(())
}

#[test]
fn unknown_kernel_outcome_is_not_treated_as_success() -> Result<(), Box<dyn std::error::Error>> {
    let outcome: WireOutcome = serde_json::from_value(serde_json::json!({
        "status": "unknown",
        "reason": "delivery outcome was not proven"
    }))?;
    assert!(matches!(outcome, WireOutcome::Unknown { .. }));
    Ok(())
}

#[test]
fn snapshot_expectation_rejects_unbound_digest() -> Result<(), Box<dyn std::error::Error>> {
    let mut launch = valid_launch_config()?;
    launch.kernel.principal = "local-user".to_owned();
    launch.protected_snapshot_digest = "c".repeat(64);
    assert!(launch.validate().is_err());
    Ok(())
}

#[test]
fn kernel_and_eliotd_artifact_domains_cannot_rewrite_each_other()
-> Result<(), Box<dyn std::error::Error>> {
    let launch = valid_launch_config()?;
    let kernel_digest = launch.kernel.artifact_digest.clone();
    let child_digest = "c".repeat(64);
    let config_path = PathBuf::from(r"C:\ProgramData\Eliot\runtime\eliotd.json");
    let nonce = "eliotd:0123456789abcdef0123456789abcdef";

    let child_bound = DaemonConfig::from_launch_with_binding(
        launch.clone(),
        config_path.clone(),
        nonce,
        &child_digest,
    )?;
    assert_eq!(child_bound.launch.kernel.artifact_digest, kernel_digest);
    assert_eq!(
        child_bound.kernel_binding.daemon_artifact_sha256,
        child_digest
    );
    assert_eq!(
        child_bound.kernel_binding.kernel_artifact_sha256,
        kernel_digest
    );
    let front_door = KernelFrontDoorServerExpectation::new(
        "S-1-5-19",
        0,
        &kernel_digest,
        KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient,
    )?;
    assert_eq!(front_door.expected_kernel_artifact_sha256(), kernel_digest);
    assert!(matches!(
        front_door.acl_mode(),
        KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient
    ));

    let kernel_digest_substitution =
        DaemonConfig::from_launch_with_binding(launch, config_path, nonce, &kernel_digest)?;
    assert_eq!(
        kernel_digest_substitution.launch.kernel.artifact_digest,
        kernel_digest
    );
    assert_eq!(
        kernel_digest_substitution
            .kernel_binding
            .kernel_artifact_sha256,
        kernel_digest
    );
    assert_ne!(
        child_bound.kernel_binding.daemon_artifact_sha256,
        kernel_digest_substitution
            .kernel_binding
            .daemon_artifact_sha256
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_server_hello_requires_observed_sid_and_session_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let launch = valid_launch_config()?;
    let config = DaemonConfig::from_launch_with_binding(
        launch.clone(),
        PathBuf::from(r"C:\ProgramData\Eliot\governor\eliotd.json"),
        "eliotd:0123456789abcdef0123456789abcdef",
        &"c".repeat(64),
    )?;
    let mut hello = ServerHello {
        selected_protocol: ProtocolVersion::CURRENT,
        session_principal_binding: format!(
            "sid={};session={}",
            config.kernel_binding.expected_kernel_sid,
            config.kernel_binding.expected_kernel_session_id
        ),
        allowed_capabilities: vec!["daemon".to_owned()],
        allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
        config_snapshot: published_kernel_snapshot(&launch)?,
        heartbeat_ms: 1_000,
        control_channel: KERNEL_PIPE_NAME.to_owned(),
        rejection_reason: None,
        authority_epoch: launch.kernel.authority_epoch.clone(),
    };
    validate_server_hello(&launch, &config.kernel_binding, &hello)?;

    let valid_snapshot = hello.config_snapshot.clone();
    let Some(snapshot) = hello.config_snapshot.as_object_mut() else {
        return Err("snapshot object expected".into());
    };
    snapshot.remove("protected_snapshot_digest");
    assert!(validate_server_hello(&launch, &config.kernel_binding, &hello).is_err());

    hello.config_snapshot = valid_snapshot.clone();
    hello.config_snapshot["protected_snapshot_digest"] = serde_json::Value::String("A".repeat(64));
    assert!(validate_server_hello(&launch, &config.kernel_binding, &hello).is_err());

    hello.config_snapshot = valid_snapshot.clone();
    hello.config_snapshot["protected_snapshot_digest"] = serde_json::Value::String("c".repeat(64));
    assert!(validate_server_hello(&launch, &config.kernel_binding, &hello).is_err());

    hello.config_snapshot = valid_snapshot;
    let mut local_mismatch = launch.clone();
    local_mismatch.protected_snapshot_digest = "c".repeat(64);
    assert!(validate_server_hello(&local_mismatch, &config.kernel_binding, &hello).is_err());

    hello.session_principal_binding = "local-user".to_owned();
    assert!(validate_server_hello(&launch, &config.kernel_binding, &hello).is_err());
    Ok(())
}

/// The `ServerHello.config_snapshot` a Kernel peer publishes on this wire: the
/// six generation-snapshot keys plus the five I1.12 compatibility-envelope items.
///
/// The five are built from their OWNERS in `eliot_kernel_core`, never from
/// literals, so a fixture built here keeps asserting that this daemon's OWN
/// identity is what a Kernel presents and is compared against. Writing them as
/// literals would make this a test that a stale constant is accepted.
#[cfg(windows)]
fn published_kernel_snapshot(
    launch: &GovernorLaunchConfig,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let identities = [
        eliot_kernel_core::contract_identity()?,
        eliot_kernel_service::contract_identity()?,
        eliot_protocol::protocol_contract_identity()?,
        eliot_runtime_contracts::contract_identity()?,
    ];
    let architecture_source_digest = eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST;
    let receipt = eliot_kernel_core::NormativePairReceipt::new(
        architecture_source_digest,
        eliot_kernel_core::expected_seal_tag(architecture_source_digest),
    )?;
    Ok(serde_json::json!({
        "service": launch.kernel.service,
        "protocol": launch.kernel.protocol,
        "generation": launch.kernel.generation.value(),
        "authority_epoch": launch.kernel.authority_epoch.clone(),
        "artifact_digest": launch.kernel.artifact_digest,
        "protected_snapshot_digest": launch.protected_snapshot_digest,
        "contract_set_digest": eliot_kernel_core::contract_set_digest(&identities)?,
        "canonical_format_range": eliot_kernel_core::handshake_canonical_format_range()?,
        "architecture_source_digest": architecture_source_digest,
        "normative_pair_receipt": receipt,
        // The class the Kernel's own process boundary declares for a process
        // handshake (`bins/eliot-kernel/src/compatibility_gate.rs`), which is
        // the same class this daemon declares as its receiver-held operand.
        "state_migration_class": eliot_kernel_core::StateMigrationClass::NoMigration,
    }))
}

/// I1.12 (#1968), the fail-closed reading at the PRODUCTION entry point: a
/// Kernel whose `ServerHello` omits any one of the five compatibility-envelope
/// items is refused by `validate_server_hello`, before the validated session
/// binding is retained in `DaemonKernelClient::connect_transport`.
///
/// Every other case in this file varies a presented VALUE. This one removes the
/// KEY, because that is the shape a Kernel which never exchanged the envelope
/// presents, and admitting it would be admitting "the pipe answered".
#[cfg(windows)]
#[test]
fn production_server_hello_refuses_a_snapshot_missing_any_envelope_item()
-> Result<(), Box<dyn std::error::Error>> {
    let launch = valid_launch_config()?;
    let config = DaemonConfig::from_launch_with_binding(
        launch.clone(),
        PathBuf::from(r"C:\ProgramData\Eliot\governor\eliotd.json"),
        "eliotd:0123456789abcdef0123456789abcdef",
        &"c".repeat(64),
    )?;
    let published = published_kernel_snapshot(&launch)?;
    let hello_for = |snapshot: serde_json::Value| ServerHello {
        selected_protocol: ProtocolVersion::CURRENT,
        session_principal_binding: format!(
            "sid={};session={}",
            config.kernel_binding.expected_kernel_sid,
            config.kernel_binding.expected_kernel_session_id
        ),
        allowed_capabilities: vec!["daemon".to_owned()],
        allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
        config_snapshot: snapshot,
        heartbeat_ms: 1_000,
        control_channel: KERNEL_PIPE_NAME.to_owned(),
        rejection_reason: None,
        authority_epoch: launch.kernel.authority_epoch.clone(),
    };

    // The full envelope is admitted, so every refusal below is caused by the
    // removal and by nothing else.
    validate_server_hello(
        &launch,
        &config.kernel_binding,
        &hello_for(published.clone()),
    )?;

    for key in [
        "contract_set_digest",
        "canonical_format_range",
        "architecture_source_digest",
        "normative_pair_receipt",
        "state_migration_class",
    ] {
        let serde_json::Value::Object(mut absent) = published.clone() else {
            return Err("snapshot object expected".into());
        };
        assert!(
            absent.remove(key).is_some(),
            "{key} must be published in the base fixture for this case to mean anything"
        );
        let Err(error) = validate_server_hello(
            &launch,
            &config.kernel_binding,
            &hello_for(serde_json::Value::Object(absent)),
        ) else {
            return Err(
                format!("a snapshot missing {key} was admitted but must be refused").into(),
            );
        };
        assert!(
            error.to_string().contains("compatibility mismatch"),
            "the refusal for {key} must be the structured I1.12 refusal, was: {error}"
        );
    }
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn receipt_publication_race_retries_only_exact_pre_admission_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let connection_id = "eliotd:race:test";
    let pending =
        eliot_ipc::handshake_rejection_frame(connection_id, ELIOTD_RECEIPT_PENDING_REJECTION)?;
    assert!(is_pre_admission_pending_rejection(&pending, connection_id));
    assert!(!is_pre_admission_pending_rejection(
        &pending,
        "eliotd:substituted:connection"
    ));
    let identity_rejection =
        eliot_ipc::handshake_rejection_frame(connection_id, "session is fenced or closed")?;
    assert!(!is_pre_admission_pending_rejection(
        &identity_rejection,
        connection_id
    ));

    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let race_attempts = Arc::clone(&attempts);
    let admitted = retry_pre_admission(
        Duration::from_secs(1),
        move || {
            let attempt = race_attempts.fetch_add(1, Ordering::Relaxed);
            async move {
                if attempt == 0 {
                    Err(KernelClientError::PreAdmissionTransport(
                        "access denied while the Kernel peer set was rebuilding".to_owned(),
                    ))
                } else if attempt == 1 {
                    Err(KernelClientError::PreAdmissionPending)
                } else {
                    Ok("same-bound-peer-admitted")
                }
            }
        },
        "test deadline",
    )
    .await?;
    assert_eq!(admitted, "same-bound-peer-admitted");
    assert_eq!(attempts.load(Ordering::Relaxed), 3);

    let substituted_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_attempts = Arc::clone(&substituted_attempts);
    let rejected = retry_pre_admission(
        Duration::from_secs(1),
        move || {
            observed_attempts.fetch_add(1, Ordering::Relaxed);
            async {
                Err::<(), _>(KernelClientError::Contract(
                    "authenticated peer identity mismatch".to_owned(),
                ))
            }
        },
        "test deadline",
    )
    .await;
    assert!(matches!(rejected, Err(KernelClientError::Contract(_))));
    assert_eq!(substituted_attempts.load(Ordering::Relaxed), 1);
    Ok(())
}
