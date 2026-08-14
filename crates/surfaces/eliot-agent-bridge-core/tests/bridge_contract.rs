use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use eliot_agent_api::{HostEventEnvelope, SessionId};
use eliot_agent_bridge_core::{
    ActivationPortOutcome, ActivationPortResult, AgentBridgeCore, AttachRequest, BridgeError,
    ConnectionId, CursorPolicy, DemandId, EventForwardAck, EventForwardStatus, EventPortOutcome,
    HostActivationPort, McpForwardingPort, PrincipalId, ProofCeiling, ProviderFailure,
    ProviderReadiness, ReconciliationPortOutcome, ReconciliationPortResult,
    ReconciliationReceiptRef, ReconnectRequest, RequiredProvider,
};
use eliot_observation_contracts::{BlindInterval, CoverageGap, CoverageInterval};
use eliot_process::{FencingToken, Generation};
use eliot_protocol::{AckPhase, EventDisposition, EventEnvelope, Frame};
use serde_json::json;

#[derive(Default)]
struct HostState {
    activations: usize,
    demand_ids: BTreeSet<String>,
}

struct CoalescingHost {
    state: Arc<Mutex<HostState>>,
    result: ActivationPortResult,
}

impl HostActivationPort for CoalescingHost {
    fn activate(
        &mut self,
        request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("host", "test lock poisoned"))?;
        if state
            .demand_ids
            .insert(request.demand_id().as_str().to_owned())
        {
            state.activations += 1;
        }
        Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
    }
}

struct SequencedHost {
    outcomes: VecDeque<ActivationPortOutcome>,
}

impl HostActivationPort for SequencedHost {
    fn activate(
        &mut self,
        _request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        self.outcomes
            .pop_front()
            .ok_or_else(|| ProviderFailure::new("host", "missing activation result"))
    }
}

#[derive(Default)]
struct ForwardState {
    frames: usize,
    hooks: usize,
    events: usize,
    gaps: Vec<CoverageGap>,
    outcomes: VecDeque<EventPortOutcome>,
    reconciliations: VecDeque<ReconciliationPortOutcome>,
}

struct FakeForwarder {
    state: Arc<Mutex<ForwardState>>,
}

impl McpForwardingPort for FakeForwarder {
    fn forward_frame(
        &mut self,
        _binding: &eliot_agent_bridge_core::AttachBinding,
        _frame: &Frame,
    ) -> Result<(), ProviderFailure> {
        self.state
            .lock()
            .map_err(|_| ProviderFailure::new("mcp", "test lock poisoned"))?
            .frames += 1;
        Ok(())
    }

    fn forward_hook(
        &mut self,
        _binding: &eliot_agent_bridge_core::AttachBinding,
        _event: &HostEventEnvelope,
    ) -> Result<(), ProviderFailure> {
        self.state
            .lock()
            .map_err(|_| ProviderFailure::new("mcp", "test lock poisoned"))?
            .hooks += 1;
        Ok(())
    }

    fn forward_event(
        &mut self,
        _binding: &eliot_agent_bridge_core::AttachBinding,
        _event: &EventEnvelope,
    ) -> Result<EventPortOutcome, ProviderFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("mcp", "test lock poisoned"))?;
        state.events += 1;
        state
            .outcomes
            .pop_front()
            .ok_or_else(|| ProviderFailure::new("mcp", "missing test outcome"))
    }

    fn forward_gap(
        &mut self,
        _binding: &eliot_agent_bridge_core::AttachBinding,
        gap: &CoverageGap,
    ) -> Result<(), ProviderFailure> {
        self.state
            .lock()
            .map_err(|_| ProviderFailure::new("mcp", "test lock poisoned"))?
            .gaps
            .push(gap.clone());
        Ok(())
    }

    fn reconcile_external(
        &mut self,
        _binding: &eliot_agent_bridge_core::AttachBinding,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        self.state
            .lock()
            .map_err(|_| ProviderFailure::new("mcp", "test lock poisoned"))?
            .reconciliations
            .pop_front()
            .ok_or_else(|| ProviderFailure::new("mcp", "missing reconciliation result"))
    }
}

fn generation(value: u64) -> Result<Generation, Box<dyn std::error::Error>> {
    Ok(Generation::new(value)?)
}

fn fence(value: u64) -> Result<FencingToken, Box<dyn std::error::Error>> {
    Ok(FencingToken::new(
        value,
        generation(value)?,
        format!("fence-{value}"),
    )?)
}

fn activation_result(value: u64) -> Result<ActivationPortResult, Box<dyn std::error::Error>> {
    Ok(ActivationPortResult::authenticated(
        PrincipalId::new("principal-1")?,
        SessionId::new(format!("session-{value}"))?,
        generation(value)?,
        fence(value)?,
    )?)
}

fn managed_request(connection: &str) -> Result<AttachRequest, Box<dyn std::error::Error>> {
    managed_request_with("demand-1", connection)
}

fn managed_request_with(
    demand: &str,
    connection: &str,
) -> Result<AttachRequest, Box<dyn std::error::Error>> {
    Ok(AttachRequest::managed(
        DemandId::new(demand)?,
        ConnectionId::new(connection)?,
    ))
}

fn event(class: &str, event_id: &str, sequence: u64) -> Result<EventEnvelope, serde_json::Error> {
    serde_json::from_value(json!({
        "stream_id": "stream-1",
        "producer_id": "bridge-producer",
        "producer_generation": 1,
        "authority_epoch": 1,
        "event_id": event_id,
        "sequence": sequence,
        "causal_predecessor_refs": [],
        "delivery_class": class,
        "ack_required": class != "best_effort_telemetry",
        "payload_type": "fixture",
        "payload_or_blob_ref": {"inline": {"Json": {"value": 1}}},
        "state_fence": {
            "authority_epoch": 1,
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        },
        "trace_context": {}
    }))
}

fn frame(connection: &str) -> Result<Frame, serde_json::Error> {
    serde_json::from_value(json!({
        "protocol_version": {"major": 1, "minor": 0},
        "encoding_profile": "json-v1",
        "connection_id": connection,
        "request_id": null,
        "kind": "heartbeat",
        "message_type": "Health",
        "request_identity": null,
        "payload": {"Json": {}},
        "trace_context": {}
    }))
}

fn hook() -> Result<HostEventEnvelope, serde_json::Error> {
    serde_json::from_value(json!({
        "event_id": "hook-1",
        "attempt_id": "attempt-1",
        "sequence": 1,
        "cursor": "cursor-1",
        "kind": "tool_result",
        "route": {
            "host_family": "test",
            "adapter": "test",
            "protocol_transport": "stdio",
            "runtime_hash": "runtime",
            "adapter_hash": "adapter",
            "provider": "provider",
            "model": "model",
            "auth_billing": "test",
            "serializer_hash": "serializer",
            "tool_semantics_hash": "tools",
            "reasoning_mode": "test",
            "continuation_behavior": "fresh",
            "feature_flags_hash": "flags"
        },
        "raw_payload_digest": "digest",
        "normalized_payload": {},
        "parent_event_id": null,
        "observed_at": "2026-08-14T00:00:00Z"
    }))
}

fn bridge(
    host_state: Arc<Mutex<HostState>>,
    forward_state: Arc<Mutex<ForwardState>>,
) -> Result<AgentBridgeCore, Box<dyn std::error::Error>> {
    Ok(AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        Some(Box::new(CoalescingHost {
            state: host_state,
            result: activation_result(1)?,
        })),
        Some(Box::new(FakeForwarder {
            state: forward_state,
        })),
        CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)?,
    ))
}

#[test]
fn process_contract_and_port_owned_demand_coalescing() -> Result<(), Box<dyn std::error::Error>> {
    let host_state = Arc::new(Mutex::new(HostState::default()));
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    let mut bridge = bridge(Arc::clone(&host_state), forward_state)?;

    let first = bridge.attach(managed_request("connection-1")?)?;
    let second = bridge.attach(managed_request("connection-1")?)?;

    assert_eq!(first.binding().activation_generation().get(), 1);
    assert_eq!(second.binding().activation_generation().get(), 1);
    assert_eq!(
        host_state
            .lock()
            .map_err(|_| "host state lock poisoned")?
            .activations,
        1
    );
    Ok(())
}

#[test]
fn attach_binds_authenticated_connection_session_generation_and_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bridge = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::new(Mutex::new(ForwardState::default())),
    )?;
    let view = bridge.attach(managed_request("connection-1")?)?;
    let binding = view.binding();

    assert_eq!(binding.principal_id().as_str(), "principal-1");
    assert_eq!(binding.session_id().as_str(), "session-1");
    assert_eq!(binding.connection_id().as_str(), "connection-1");
    assert_eq!(binding.activation_generation().get(), 1);
    assert_eq!(binding.state_fence().authority_epoch(), 1);
    assert_eq!(binding.state_fence().generation().get(), 1);
    Ok(())
}

#[test]
fn reconnect_replaces_transport_but_rejects_stale_generation_and_session()
-> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    let mut bridge = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::clone(&forward_state),
    )?;
    bridge.attach(managed_request("connection-1")?)?;
    assert!(matches!(
        bridge.attach(managed_request("connection-2")?),
        Err(BridgeError::InvalidTransition(_))
    ));

    let stale = ReconnectRequest::new(
        SessionId::new("session-2")?,
        generation(2)?,
        fence(2)?,
        ConnectionId::new("connection-2")?,
    )?;
    assert!(matches!(
        bridge.reconnect(stale),
        Err(BridgeError::StaleAuthority)
    ));

    let current = ReconnectRequest::new(
        SessionId::new("session-1")?,
        generation(1)?,
        fence(1)?,
        ConnectionId::new("connection-2")?,
    )?;
    let view = bridge.reconnect(current)?;
    assert_eq!(view.binding().connection_id().as_str(), "connection-2");
    assert!(matches!(
        bridge.forward_frame(&frame("connection-1")?),
        Err(BridgeError::StaleTransport)
    ));
    bridge.forward_frame(&frame("connection-2")?)?;
    assert_eq!(
        forward_state
            .lock()
            .map_err(|_| "forward state lock poisoned")?
            .frames,
        1
    );
    Ok(())
}

#[test]
fn durable_duplicate_replay_is_idempotent_and_ack_phase_controls_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?
        .outcomes
        .push_back(EventPortOutcome::Acknowledged(EventForwardAck::new(
            "stream-1",
            "event-1",
            AckPhase::Durable,
            EventDisposition::Accepted,
        )?));
    let mut bridge = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::clone(&forward_state),
    )?;
    bridge.attach(managed_request("connection-1")?)?;
    let durable = event("durable_control", "event-1", 1)?;

    let first = bridge.forward_event(&durable)?;
    assert_eq!(
        first,
        EventForwardStatus::Durable {
            phase: AckPhase::Durable,
            disposition: EventDisposition::Accepted,
            cursor_advanced: true,
        }
    );
    assert_eq!(bridge.cursor("stream-1"), Some(1));

    let replay = bridge.forward_event(&durable)?;
    assert_eq!(
        replay,
        EventForwardStatus::Durable {
            phase: AckPhase::Durable,
            disposition: EventDisposition::Duplicate,
            cursor_advanced: false,
        }
    );
    assert_eq!(
        forward_state
            .lock()
            .map_err(|_| "forward state lock poisoned")?
            .events,
        1
    );

    let mut conflicting = durable;
    conflicting.sequence = 2;
    assert!(matches!(
        bridge.forward_event(&conflicting),
        Err(BridgeError::ProviderContract(_))
    ));
    Ok(())
}

#[test]
fn received_ack_is_explicit_but_does_not_advance_durable_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    let mut state = forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?;
    state
        .outcomes
        .push_back(EventPortOutcome::Acknowledged(EventForwardAck::new(
            "stream-1",
            "event-1",
            AckPhase::Received,
            EventDisposition::Accepted,
        )?));
    state
        .outcomes
        .push_back(EventPortOutcome::Acknowledged(EventForwardAck::new(
            "stream-1",
            "event-1",
            AckPhase::Durable,
            EventDisposition::Accepted,
        )?));
    drop(state);
    let mut bridge = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::clone(&forward_state),
    )?;
    bridge.attach(managed_request("connection-1")?)?;
    let durable = event("durable_control", "event-1", 1)?;

    assert_eq!(
        bridge.forward_event(&durable)?,
        EventForwardStatus::Durable {
            phase: AckPhase::Received,
            disposition: EventDisposition::Accepted,
            cursor_advanced: false,
        }
    );
    assert_eq!(bridge.cursor("stream-1"), None);
    assert_eq!(bridge.outstanding_deliveries().len(), 1);
    assert_eq!(
        bridge.forward_event(&durable)?,
        EventForwardStatus::Durable {
            phase: AckPhase::Durable,
            disposition: EventDisposition::Accepted,
            cursor_advanced: true,
        }
    );
    assert!(bridge.outstanding_deliveries().is_empty());
    assert_eq!(bridge.cursor("stream-1"), Some(1));
    assert_eq!(
        forward_state
            .lock()
            .map_err(|_| "forward state lock poisoned")?
            .events,
        2
    );
    Ok(())
}

#[test]
fn received_and_durable_ack_retry_until_required_normalized_phase()
-> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    let mut state = forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?;
    for phase in [AckPhase::Received, AckPhase::Durable, AckPhase::Normalized] {
        state
            .outcomes
            .push_back(EventPortOutcome::Acknowledged(EventForwardAck::new(
                "stream-1",
                "event-2",
                phase,
                EventDisposition::Accepted,
            )?));
    }
    drop(state);
    let mut bridge = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::clone(&forward_state),
    )?;
    bridge.attach(managed_request("connection-1")?)?;
    let durable = event("durable_observation", "event-2", 2)?;

    for phase in [AckPhase::Received, AckPhase::Durable] {
        assert_eq!(
            bridge.forward_event(&durable)?,
            EventForwardStatus::Durable {
                phase,
                disposition: EventDisposition::Accepted,
                cursor_advanced: false,
            }
        );
        assert_eq!(bridge.outstanding_deliveries().len(), 1);
        assert_eq!(bridge.cursor("stream-1"), None);
    }
    assert_eq!(
        bridge.forward_event(&durable)?,
        EventForwardStatus::Durable {
            phase: AckPhase::Normalized,
            disposition: EventDisposition::Accepted,
            cursor_advanced: true,
        }
    );
    assert!(bridge.outstanding_deliveries().is_empty());
    assert_eq!(bridge.cursor("stream-1"), Some(2));
    assert_eq!(
        forward_state
            .lock()
            .map_err(|_| "forward state lock poisoned")?
            .events,
        3
    );
    Ok(())
}

#[test]
fn higher_generation_attach_is_blocked_until_outstanding_delivery_reconciles()
-> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    let mut state = forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?;
    for phase in [AckPhase::Received, AckPhase::Durable] {
        state
            .outcomes
            .push_back(EventPortOutcome::Acknowledged(EventForwardAck::new(
                "stream-1",
                "event-1",
                phase,
                EventDisposition::Accepted,
            )?));
    }
    drop(state);

    let host = SequencedHost {
        outcomes: VecDeque::from([
            ActivationPortOutcome::Authenticated(activation_result(1)?),
            ActivationPortOutcome::Authenticated(activation_result(2)?),
        ]),
    };
    let mut bridge = AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        Some(Box::new(host)),
        Some(Box::new(FakeForwarder {
            state: forward_state,
        })),
        CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)?,
    );
    bridge.attach(managed_request_with("demand-1", "connection-1")?)?;
    let durable = event("durable_control", "event-1", 1)?;
    bridge.forward_event(&durable)?;

    assert!(matches!(
        bridge.attach(managed_request_with("demand-2", "connection-2")?),
        Err(BridgeError::OutstandingDeliveryReconciliationRequired { count: 1 })
    ));
    let outstanding = bridge.outstanding_deliveries();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0].event_id(), "event-1");
    assert_eq!(outstanding[0].highest_phase(), AckPhase::Received);
    assert_eq!(outstanding[0].required_phase(), AckPhase::Durable);
    assert_eq!(
        bridge
            .attach_view()
            .map(|view| view.binding().activation_generation().get()),
        Some(1)
    );

    bridge.forward_event(&durable)?;
    assert!(bridge.outstanding_deliveries().is_empty());
    let next = bridge.attach(managed_request_with("demand-2", "connection-2")?)?;
    assert_eq!(next.binding().activation_generation().get(), 2);
    assert_eq!(next.binding().connection_id().as_str(), "connection-2");
    Ok(())
}

#[test]
fn best_effort_drop_emits_an_explicit_hook_gap_signal() -> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?
        .outcomes
        .push_back(EventPortOutcome::BestEffortDropped {
            reason_ref: "telemetry-buffer-pressure".to_owned(),
        });
    let mut bridge = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::clone(&forward_state),
    )?;
    bridge.attach(managed_request("connection-1")?)?;

    let status = bridge.forward_event(&event("best_effort_telemetry", "telemetry-1", 4)?)?;
    let EventForwardStatus::BestEffortGapSignalled { gap } = status else {
        return Err("expected explicit telemetry gap".into());
    };
    assert_eq!(gap.reason_ref, "telemetry-buffer-pressure");
    assert_eq!(gap.affected_interval, Some(CoverageInterval::new(4, 4)?));
    assert_eq!(
        forward_state
            .lock()
            .map_err(|_| "forward state lock poisoned")?
            .gaps
            .len(),
        1
    );
    Ok(())
}

#[test]
fn external_attach_stays_candidate_until_reconciled_and_never_promotes_history()
-> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?
        .reconciliations
        .push_back(ReconciliationPortOutcome::Reconciled(
            ReconciliationPortResult::reconciled(
                SessionId::new("session-1")?,
                generation(1)?,
                fence(1)?,
                ReconciliationReceiptRef::new("external-attach-reconciliation-receipt-1")?,
            )?,
        ));
    let mut bridge = bridge(Arc::new(Mutex::new(HostState::default())), forward_state)?;
    let request = AttachRequest::external(
        DemandId::new("external-demand")?,
        ConnectionId::new("connection-1")?,
        BlindInterval {
            interval: CoverageInterval::new(1, 9)?,
            reason_ref: "pre-attach-unobserved".to_owned(),
        },
    )?;
    let view = bridge.attach(request)?;
    assert!(view.reconciliation_required());
    assert_eq!(
        view.pre_attach_proof_ceiling(),
        Some(ProofCeiling::CandidateOnly)
    );
    assert!(matches!(
        bridge.forward_hook(&hook()?),
        Err(BridgeError::ExternalAttachReconciliationRequired)
    ));

    let reconciled = bridge.reconcile_external()?;
    assert!(!reconciled.reconciliation_required());
    assert_eq!(
        reconciled.pre_attach_proof_ceiling(),
        Some(ProofCeiling::CandidateOnly)
    );
    bridge.forward_hook(&hook()?)?;
    Ok(())
}

#[test]
fn restart_is_empty_and_cannot_reuse_prior_session_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut first = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::new(Mutex::new(ForwardState::default())),
    )?;
    first.attach(managed_request("connection-1")?)?;
    assert!(first.attach_view().is_some());

    let mut restarted = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::new(Mutex::new(ForwardState::default())),
    )?;
    assert!(restarted.attach_view().is_none());
    assert!(matches!(
        restarted.forward_hook(&hook()?),
        Err(BridgeError::NotAttached)
    ));
    Ok(())
}

#[test]
fn unavailable_admitted_contracts_and_ports_return_typed_plan_gap()
-> Result<(), Box<dyn std::error::Error>> {
    for provider in [
        RequiredProvider::A01AgentApi,
        RequiredProvider::A06McpSurface,
        RequiredProvider::C07Protocol,
        RequiredProvider::C011ObservationContracts,
        RequiredProvider::P03ProcessContracts,
    ] {
        let mut bridge = AgentBridgeCore::new(
            ProviderReadiness::all_admitted().with_unavailable(provider),
            None,
            None,
            CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)?,
        );
        let Err(BridgeError::PlanGap(gap)) = bridge.attach(managed_request("connection-1")?) else {
            return Err(format!("expected PLAN_GAP for {provider:?}").into());
        };
        assert_eq!(gap.reason_code(), "PLAN_GAP");
        assert_eq!(gap.missing_provider(), provider);
        assert!(!gap.required_contract().is_empty());
    }

    let mut missing_host = AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        None,
        None,
        CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)?,
    );
    assert!(matches!(
        missing_host.attach(managed_request("connection-1")?),
        Err(BridgeError::PlanGap(_))
    ));
    Ok(())
}

#[test]
fn trusted_activation_and_reconciliation_ports_return_typed_denial_or_plan_gap()
-> Result<(), Box<dyn std::error::Error>> {
    let denying_host = SequencedHost {
        outcomes: VecDeque::from([ActivationPortOutcome::Denied {
            reason_code: "HOST_AUTHENTICATION_DENIED",
        }]),
    };
    let mut denied = AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        Some(Box::new(denying_host)),
        None,
        CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)?,
    );
    assert!(matches!(
        denied.attach(managed_request("connection-1")?),
        Err(BridgeError::ActivationDenied("HOST_AUTHENTICATION_DENIED"))
    ));

    let host = CoalescingHost {
        state: Arc::new(Mutex::new(HostState::default())),
        result: activation_result(1)?,
    };
    let mut missing_reconciler = AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        Some(Box::new(host)),
        None,
        CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)?,
    );
    missing_reconciler.attach(AttachRequest::external(
        DemandId::new("external-demand")?,
        ConnectionId::new("connection-1")?,
        BlindInterval {
            interval: CoverageInterval::new(1, 2)?,
            reason_ref: "pre-attach-unobserved".to_owned(),
        },
    )?)?;
    let Err(BridgeError::PlanGap(gap)) = missing_reconciler.reconcile_external() else {
        return Err("expected reconciliation PLAN_GAP".into());
    };
    assert_eq!(gap.missing_provider(), RequiredProvider::McpForwardingPort);

    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?
        .reconciliations
        .push_back(ReconciliationPortOutcome::Denied {
            reason_code: "EXTERNAL_ATTACH_NOT_VERIFIED",
        });
    let mut denied_reconciliation =
        bridge(Arc::new(Mutex::new(HostState::default())), forward_state)?;
    denied_reconciliation.attach(AttachRequest::external(
        DemandId::new("external-demand")?,
        ConnectionId::new("connection-1")?,
        BlindInterval {
            interval: CoverageInterval::new(1, 2)?,
            reason_ref: "pre-attach-unobserved".to_owned(),
        },
    )?)?;
    assert!(matches!(
        denied_reconciliation.reconcile_external(),
        Err(BridgeError::ExternalReconciliationDenied(
            "EXTERNAL_ATTACH_NOT_VERIFIED"
        ))
    ));
    Ok(())
}

#[test]
fn serde_and_constructors_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        serde_json::from_value::<AttachRequest>(json!({
            "demand_id": "demand-1",
            "connection_id": "connection-1",
            "attach_kind": "MANAGED",
            "pre_attach_blind_interval": {
                "interval": {"start": 1, "end": 2},
                "reason_ref": "unexpected"
            }
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AttachRequest>(json!({
            "demand_id": "",
            "connection_id": "connection-1",
            "attach_kind": "EXTERNAL",
            "pre_attach_blind_interval": null
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AttachRequest>(json!({
            "demand_id": "demand-1",
            "connection_id": "connection-1",
            "attach_kind": "MANAGED",
            "pre_attach_blind_interval": null,
            "unexpected": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AttachRequest>(json!({
            "demand_id": "demand-1",
            "connection_id": "connection-1",
            "attach_kind": "EXTERNAL",
            "pre_attach_blind_interval": {
                "interval": {"start": 9, "end": 1},
                "reason_ref": "reversed"
            }
        }))
        .is_err()
    );
    assert!(CursorPolicy::new(AckPhase::Received, AckPhase::Normalized).is_err());
    assert!(
        ActivationPortResult::authenticated(
            PrincipalId::new("principal")?,
            SessionId::new("session")?,
            generation(1)?,
            fence(2)?,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn direct_hook_and_frame_contracts_are_validated_before_forwarding()
-> Result<(), Box<dyn std::error::Error>> {
    let forward_state = Arc::new(Mutex::new(ForwardState::default()));
    let mut bridge = bridge(
        Arc::new(Mutex::new(HostState::default())),
        Arc::clone(&forward_state),
    )?;
    bridge.attach(managed_request("connection-1")?)?;
    bridge.forward_hook(&hook()?)?;
    bridge.forward_frame(&frame("connection-1")?)?;
    let state = forward_state
        .lock()
        .map_err(|_| "forward state lock poisoned")?;
    assert_eq!(state.hooks, 1);
    assert_eq!(state.frames, 1);
    Ok(())
}

#[test]
fn bridge_has_no_durable_or_database_state_surface() {
    let debug = format!(
        "{:?}",
        AgentBridgeCore::new(
            ProviderReadiness::all_admitted(),
            None,
            None,
            CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)
                .unwrap_or_else(|error| panic!("valid cursor policy rejected: {error}")),
        )
    );
    assert!(debug.contains("transport-only"));
    assert!(!debug.contains("credential"));
    assert!(!debug.contains("database"));
}

#[test]
fn provider_failure_surface_is_sanitized_and_static() {
    let failure = ProviderFailure::new("mcp", "temporarily unavailable");
    assert_eq!(
        failure.to_string(),
        "provider mcp failed: temporarily unavailable"
    );
}

#[test]
fn attach_request_round_trips_without_widening_fields() -> Result<(), Box<dyn std::error::Error>> {
    let request = managed_request("connection-1")?;
    let encoded = serde_json::to_string(&request)?;
    let decoded: AttachRequest = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, request);
    Ok(())
}

#[test]
fn type_level_port_contract_is_object_safe() {
    fn accepts_ports(
        _host: Option<Box<dyn HostActivationPort>>,
        _mcp: Option<Box<dyn McpForwardingPort>>,
    ) {
    }
    accepts_ports(None, None);
}

#[test]
fn event_fixture_has_only_expected_trace_shape() -> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::to_value(event("durable_observation", "event-2", 2)?)?;
    let trace = value
        .get("trace_context")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    assert!(trace.is_empty());
    Ok(())
}
