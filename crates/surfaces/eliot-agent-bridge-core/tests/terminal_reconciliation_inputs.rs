//! Issue #9 Slice A: bridge-transport terminal reconciliation inputs.
//!
//! The MGR01 half proves the transport carries fingerprint passthrough,
//! raw/normalized host events with sequences/cursors, attempt transitions,
//! and keeps stale-UI/error-event evidence independent of the canonical
//! disposition references until reduction. The terminal reducer itself is
//! MGR02 land and is deliberately not exercised here.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use eliot_agent_bridge_core::{
    ActivationPortOutcome, ActivationPortResult, AgentBridgeCore, AttachBinding, AttachRequest,
    AttemptState, BridgeError, ConnectionId, CoverageGap, CursorPolicy, DemandId, EventEnvelope,
    EventPortOutcome, FencingToken, Generation, HostActivationPort, HostEventEnvelope,
    HostEventKind, McpForwardingPort, PrincipalId, ProviderFailure, ProviderReadiness,
    ReconciliationPortOutcome, RecoveryDirective, RecoveryDirectiveKind, RouteFingerprint,
    SessionId, TaskId, TerminalReductionInputs, WorkUnitId,
};
use eliot_agent_bridge_core::{TransportEdge, TransportEdgeKind};
use eliot_contracts::{EpochId, EpochLineageId};
use serde_json::json;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const RUNTIME_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ADAPTER_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SERIALIZER_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const TOOL_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const FLAGS_HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
    Ok(EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A)?,
        NonZeroU64::new(sequence).ok_or("nonzero test sequence")?,
    )?)
}

fn generation(value: u64) -> Result<Generation, Box<dyn std::error::Error>> {
    Ok(Generation::new(value)?)
}

fn fence(value: u64) -> Result<FencingToken, Box<dyn std::error::Error>> {
    Ok(FencingToken::new(
        test_epoch(value)?,
        generation(value)?,
        format!("fence-{value}"),
    )?)
}

fn activation_result() -> Result<ActivationPortResult, Box<dyn std::error::Error>> {
    Ok(ActivationPortResult::authenticated(
        PrincipalId::new("principal-1")?,
        SessionId::new("session-1")?,
        generation(1)?,
        fence(1)?,
        TaskId::new("task-1")?,
        WorkUnitId::new("work-unit-1")?,
        "scope-1",
        "task-revision-1",
        "plan-1",
        "plan-revision-1",
    )?)
}

struct FixtureHost {
    result: ActivationPortResult,
}

impl HostActivationPort for FixtureHost {
    fn activate(
        &mut self,
        _request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
    }
}

#[derive(Default)]
struct FixtureForwarder {
    hooks: usize,
}

struct ForwardingFixture {
    state: Arc<Mutex<FixtureForwarder>>,
}

impl McpForwardingPort for ForwardingFixture {
    fn forward_hook(
        &mut self,
        _binding: &AttachBinding,
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
        _binding: &AttachBinding,
        _event: &EventEnvelope,
    ) -> Result<EventPortOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "mcp",
            "event forwarding not part of this fixture",
        ))
    }

    fn forward_gap(
        &mut self,
        _binding: &AttachBinding,
        _gap: &CoverageGap,
    ) -> Result<(), ProviderFailure> {
        Ok(())
    }

    fn reconcile_external(
        &mut self,
        _binding: &AttachBinding,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "mcp",
            "reconciliation not part of this fixture",
        ))
    }
}

fn bridge() -> Result<AgentBridgeCore, Box<dyn std::error::Error>> {
    Ok(AgentBridgeCore::new(
        ProviderReadiness::all_admitted(),
        Some(Box::new(FixtureHost {
            result: activation_result()?,
        })),
        Some(Box::new(ForwardingFixture {
            state: Arc::new(Mutex::new(FixtureForwarder::default())),
        })),
        CursorPolicy::new(
            eliot_agent_bridge_core::AckPhase::Durable,
            eliot_agent_bridge_core::AckPhase::Normalized,
        )?,
    ))
}

fn test_route() -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!({
        "host_family": "antigravity",
        "adapter": "antigravity-stream",
        "protocol_transport": "ndjson",
        "runtime_hash": RUNTIME_HASH,
        "adapter_hash": ADAPTER_HASH,
        "provider": "antigravity",
        "model": "antigravity-1",
        "auth_billing": "operator",
        "serializer_hash": SERIALIZER_HASH,
        "tool_semantics_hash": TOOL_HASH,
        "reasoning_mode": "default",
        "continuation_behavior": "fresh",
        "feature_flags_hash": FLAGS_HASH
    }))?)
}

fn host_event(
    event_id: &str,
    sequence: u64,
    kind: &str,
    normalized: &serde_json::Value,
    parent: Option<&str>,
) -> Result<HostEventEnvelope, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!({
        "event_id": event_id,
        "attempt_id": "attempt-1",
        "sequence": sequence,
        "cursor": format!("cursor-{sequence}"),
        "kind": kind,
        "route": {
            "host_family": "antigravity",
            "adapter": "antigravity-stream",
            "protocol_transport": "ndjson",
            "runtime_hash": RUNTIME_HASH,
            "adapter_hash": ADAPTER_HASH,
            "provider": "antigravity",
            "model": "antigravity-1",
            "auth_billing": "operator",
            "serializer_hash": SERIALIZER_HASH,
            "tool_semantics_hash": TOOL_HASH,
            "reasoning_mode": "default",
            "continuation_behavior": "fresh",
            "feature_flags_hash": FLAGS_HASH
        },
        "raw_payload_digest": format!("raw-digest-{event_id}"),
        "normalized_payload": normalized,
        "parent_event_id": parent,
        "observed_at": "2026-09-15T00:00:00Z"
    }))?)
}

fn managed_request() -> Result<AttachRequest, Box<dyn std::error::Error>> {
    Ok(AttachRequest::managed(
        DemandId::new("demand-1")?,
        ConnectionId::new("connection-1")?,
    ))
}

fn seeded_recovery_core()
-> Result<(AgentBridgeCore, TerminalReductionInputs), Box<dyn std::error::Error>> {
    let mut core = bridge()?;
    assert!(core.terminal_reduction_inputs().is_none());
    core.attach(managed_request()?)?;

    // Invalid/recoverable call followed by its typed error event.
    core.forward_hook(&host_event(
        "tool-call-1",
        1,
        "tool_call",
        &json!({"tool": "write", "args_valid": false}),
        None,
    )?)?;
    core.forward_hook(&host_event(
        "tool-result-1",
        2,
        "error",
        &json!({"recoverable": true, "code": "INVALID_ARGUMENTS"}),
        Some("tool-call-1"),
    )?)?;

    // A directive that reuses the failed identity is rejected: the
    // retry/new-identity rule is structural, not conventional.
    assert!(matches!(
        RecoveryDirective::prescribe(
            "tool-result-1",
            "tool-result-1",
            RecoveryDirectiveKind::CorrectAndResubmit,
            "same identity",
        ),
        Err(BridgeError::InvalidContract { .. })
    ));
    // A directive for an unobserved event cannot chain to history.
    assert!(matches!(
        core.prescribe_recovery(RecoveryDirective::prescribe(
            "unobserved-event",
            "tool-call-2",
            RecoveryDirectiveKind::CorrectAndResubmit,
            "no history anchor",
        )?),
        Err(BridgeError::InvalidTransition(_))
    ));

    // Typed recovery directive chaining the error to the corrected call.
    core.prescribe_recovery(RecoveryDirective::prescribe(
        "tool-result-1",
        "tool-call-2",
        RecoveryDirectiveKind::CorrectAndResubmit,
        "INVALID_ARGUMENTS is recoverable by resubmitting corrected args",
    )?)?;

    // Corrected call under the new identity, then its success result.
    core.forward_hook(&host_event(
        "tool-call-2",
        3,
        "tool_call",
        &json!({"tool": "write", "args_valid": true}),
        None,
    )?)?;
    core.forward_hook(&host_event(
        "tool-result-2",
        4,
        "tool_result",
        &json!({"ok": true}),
        Some("tool-call-2"),
    )?)?;

    // Candidate canonical submission/receipt plus the independent exact
    // readback reference.
    core.record_canonical_submission("write-submission-1")?;
    core.record_canonical_receipt("write-receipt-1")?;
    core.record_canonical_readback("readback-1")?;
    // A conflicting receipt identity cannot silently replace the recorded one.
    assert!(matches!(
        core.record_canonical_receipt("write-receipt-2"),
        Err(BridgeError::InvalidTransition(_))
    ));

    core.observe_attempt_transition(AttemptState::Started, AttemptState::Running, 1)?;
    core.observe_attempt_transition(AttemptState::Running, AttemptState::Reconciling, 4)?;

    // The stale UI still displays the earlier error after the later success.
    core.note_stale_ui_disposition("terminal shows INVALID_ARGUMENTS from tool-result-1")?;

    let inputs = core
        .terminal_reduction_inputs()
        .ok_or("missing terminal reduction inputs")?;
    Ok((core, inputs))
}

#[test]
fn recoverable_error_then_corrected_call_yields_independent_terminal_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let (_core, inputs) = seeded_recovery_core()?;

    // Fingerprint passthrough: the exact host route, untouched.
    assert_eq!(inputs.fingerprint(), Some(&test_route()?));

    // History keeps the earlier error: four events in observation order
    // with raw/normalized payloads paired per event.
    assert_eq!(inputs.history().len(), 4);
    assert_eq!(inputs.history()[1].kind, HostEventKind::Error);
    assert_eq!(
        inputs.history()[1].normalized_payload,
        json!({"recoverable": true, "code": "INVALID_ARGUMENTS"})
    );
    assert_eq!(
        inputs.history()[1].raw_payload_digest,
        "raw-digest-tool-result-1"
    );
    let sequences: Vec<u64> = inputs
        .history()
        .iter()
        .map(|event| event.sequence)
        .collect();
    assert_eq!(sequences, vec![1, 2, 3, 4]);

    // The earlier error stays queryable as non-terminal history with its
    // recovery directive pointing at the new corrected identity.
    assert_eq!(inputs.error_event_refs(), &["tool-result-1".to_owned()]);
    assert_eq!(inputs.recovery_directives().len(), 1);
    let directive = &inputs.recovery_directives()[0];
    assert_eq!(directive.for_event(), "tool-result-1");
    assert_eq!(directive.corrected_event(), "tool-call-2");
    assert_eq!(directive.kind(), RecoveryDirectiveKind::CorrectAndResubmit);

    // Stale-UI display and canonical references are independent fields:
    // the stale error text coexists with the success receipt without
    // either deriving from the other.
    assert_eq!(
        inputs.stale_ui_disposition(),
        Some("terminal shows INVALID_ARGUMENTS from tool-result-1")
    );
    assert_eq!(inputs.canonical().receipt_ref(), Some("write-receipt-1"));
    assert_eq!(inputs.canonical().readback_ref(), Some("readback-1"));
    assert!(inputs.canonical().has_complete_canonical_chain());

    // Clean-path coverage: no edges, no blocking flags.
    assert!(inputs.edges().is_empty());
    assert!(!inputs.coverage().unknown_commit());
    assert!(!inputs.coverage().cancel_unconfirmed());
    assert!(!inputs.coverage().incomplete_coverage());

    assert_eq!(inputs.attempt_transitions().len(), 2);
    Ok(())
}

#[test]
fn terminal_edges_stay_independent_without_reduction() -> Result<(), Box<dyn std::error::Error>> {
    let mut core = bridge()?;
    core.attach(managed_request()?)?;
    core.forward_hook(&host_event(
        "tool-call-1",
        1,
        "tool_call",
        &json!({"tool": "write"}),
        None,
    )?)?;

    let edges = [
        (
            TransportEdgeKind::Timeout,
            "tool-call-1",
            2,
            "provider deadline exceeded",
        ),
        (
            TransportEdgeKind::CancelRequested,
            "tool-call-1",
            3,
            "operator cancel observed",
        ),
        (
            TransportEdgeKind::ParseFailure,
            "tool-result-1",
            4,
            "host frame failed strict parse",
        ),
        (
            TransportEdgeKind::LateSuccess,
            "tool-call-1",
            5,
            "success arrived after timeout edge",
        ),
        (
            TransportEdgeKind::DuplicateCorrectedCall,
            "tool-call-2",
            6,
            "corrected call observed twice",
        ),
        (
            TransportEdgeKind::UnknownCommit,
            "tool-call-1",
            7,
            "effect commit state unconfirmed",
        ),
        (
            TransportEdgeKind::Disconnect,
            "tool-call-1",
            8,
            "host process disconnected",
        ),
    ];
    for (kind, event_ref, sequence, detail) in edges {
        core.record_transport_edge(TransportEdge::record(kind, event_ref, sequence, detail)?)?;
    }
    assert!(matches!(
        TransportEdge::record(TransportEdgeKind::Timeout, "tool-call-1", 0, "zero order"),
        Err(BridgeError::InvalidContract { .. })
    ));

    let inputs = core
        .terminal_reduction_inputs()
        .ok_or("missing terminal reduction inputs")?;

    // Every edge is carried independently; the late success does not clear
    // the timeout, and history is untouched by edge recording.
    assert_eq!(inputs.edges().len(), 7);
    let kinds: BTreeSet<String> = inputs
        .edges()
        .iter()
        .map(|edge| edge.kind().to_string())
        .collect();
    assert_eq!(kinds.len(), 7);
    assert!(kinds.contains("LATE_SUCCESS") && kinds.contains("TIMEOUT"));
    assert_eq!(inputs.history().len(), 1);

    // Blocking coverage facts are explicit: unknown commit, unconfirmed
    // cancellation, and incomplete coverage after disconnect.
    assert!(inputs.coverage().unknown_commit());
    assert!(inputs.coverage().cancel_unconfirmed());
    assert!(inputs.coverage().incomplete_coverage());

    // No canonical chain and no stale display were recorded, and no
    // disposition exists anywhere on these inputs for a consumer to mistake
    // for a reduction.
    assert!(!inputs.canonical().has_complete_canonical_chain());
    assert_eq!(inputs.stale_ui_disposition(), None);
    assert!(inputs.error_event_refs().is_empty());
    Ok(())
}
