//! Production-caller proof: the real A4 settled-plan feed drives the real
//! bridge admission path end to end — owner projections → settled plan →
//! batch → live Governor assessment → transport → ledger → hook drain →
//! receipts. No hand-shaped batch, no stub assessor, no direct ledger
//! calls. The negative arm proves a settled no-injection makes zero calls.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../../crates/smart/eliot-reactive-context-plan/tests/support/reactive_plan.rs"]
mod support;

use eliot_agent_bridge::{
    BridgeRunner, FeedAdmissionOutcome, Profile, SettledPlanAdmission, admit_producer_feed,
};
use eliot_agent_bridge_core::{
    ActivationPortOutcome, ActivationPortResult, AttachBinding, AttachRequest, ConnectionId,
    CoverageGap, DemandId, EventEnvelope, EventPortOutcome, FencingToken, Generation,
    HostActivationPort, HostEventEnvelope, McpForwardingPort, PrincipalId, ProviderFailure,
    ProviderReadiness, ReconciliationPortOutcome, SessionId, TaskId, WorkUnitId,
};
use eliot_contracts::{EpochId, EpochLineageId};
use eliot_integration_coverage::{
    ALL_EVENTS, DispatchOrdering, EventCompleteness, EventCoverage, EventDisposition,
    GovernorCoverageDerivation, IntegrationCoverageProfile, LogicalEvent, TraceFreshness,
    WatchdogEvidence,
};
use eliot_reactive_context_plan::{SettledPlanFeedInputs, SettledPlanFeedOutcome};
use std::num::NonZeroU64;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

struct StaticActivation {
    result: ActivationPortResult,
}

impl HostActivationPort for StaticActivation {
    fn activate(
        &mut self,
        _request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
    }
}

struct OkForwarder;

impl McpForwardingPort for OkForwarder {
    fn forward_hook(
        &mut self,
        _binding: &AttachBinding,
        _event: &HostEventEnvelope,
    ) -> Result<(), ProviderFailure> {
        Ok(())
    }
    fn forward_event(
        &mut self,
        _binding: &AttachBinding,
        _event: &EventEnvelope,
    ) -> Result<EventPortOutcome, ProviderFailure> {
        Ok(EventPortOutcome::BestEffortForwarded)
    }
    fn forward_gap(
        &mut self,
        _binding: &AttachBinding,
        _gap: &CoverageGap,
    ) -> Result<(), ProviderFailure> {
        Err(ProviderFailure::new("test-forwarder", "gap not exercised"))
    }
    fn reconcile_external(
        &mut self,
        _binding: &AttachBinding,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "test-forwarder",
            "reconciliation not exercised",
        ))
    }
}

fn attached_runner(session: &str) -> BridgeRunner {
    let generation = Generation::new(7).expect("non-zero test generation");
    let fence = FencingToken::new(
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(2).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        generation,
        "fence-caller-7",
    )
    .expect("valid test fence");
    let result = ActivationPortResult::authenticated(
        PrincipalId::new("principal-caller-1").expect("valid principal"),
        SessionId::new(session).expect("valid session"),
        generation,
        fence,
        TaskId::new("task-caller-1").expect("valid task"),
        WorkUnitId::new("work-unit-caller-1").expect("valid work unit"),
        "scope-caller-1",
        "task-revision-1",
        "plan-caller-1",
        "plan-revision-1",
    )
    .expect("valid activation result");
    let mut runner = BridgeRunner::new(
        Profile::SpineFunctional,
        ProviderReadiness::all_admitted(),
        Some(Box::new(StaticActivation { result })),
        Some(Box::new(OkForwarder)),
    )
    .expect("runner composes");
    runner
        .attach(AttachRequest::managed(
            DemandId::new("demand-caller-1").expect("valid demand"),
            ConnectionId::new("conn-caller-1").expect("valid connection"),
        ))
        .expect("managed attach admits");
    runner
}

fn hook_event(hook_id: &str) -> HostEventEnvelope {
    serde_json::from_value(serde_json::json!({
        "event_id": hook_id,
        "attempt_id": "attempt-caller-1",
        "sequence": 1,
        "cursor": "cursor-caller-1",
        "kind": "tool_result",
        "route": {
            "host_family": "test",
            "adapter": "test",
            "protocol_transport": "stdio",
            "runtime_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "adapter_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "provider": "provider",
            "model": "model",
            "auth_billing": "test",
            "serializer_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "tool_semantics_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "reasoning_mode": "test",
            "continuation_behavior": "fresh",
            "feature_flags_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        },
        "raw_payload_digest": "digest-caller-1",
        "normalized_payload": {},
        "parent_event_id": null,
        "observed_at": "2026-09-21T00:00:00Z"
    }))
    .expect("valid hook fixture")
}

fn live_derivation() -> GovernorCoverageDerivation {
    let events: Vec<EventCoverage> = ALL_EVENTS
        .iter()
        .map(|event| EventCoverage {
            event: *event,
            disposition: if matches!(
                event,
                LogicalEvent::PreToolUse | LogicalEvent::PermissionRequest
            ) {
                EventDisposition::Enforced
            } else {
                EventDisposition::Observed
            },
            ordering: DispatchOrdering::PreDispatch,
            completeness: EventCompleteness::Complete,
            proof_ceiling: "test-ceiling".to_owned(),
            source: "test-source".to_owned(),
            gaps: Vec::new(),
        })
        .collect();
    let coverage = IntegrationCoverageProfile::candidate(
        "fingerprint-1",
        events,
        EventCompleteness::Complete,
        "test-ceiling",
        "test-source",
        Vec::new(),
    )
    .expect("candidate")
    .verify("fingerprint-1", true)
    .expect("verified");
    let mut derivation = GovernorCoverageDerivation::new();
    derivation
        .derive(
            &coverage,
            &WatchdogEvidence {
                supervisor_id: "watchdog-1".to_owned(),
                fresh: true,
                summary: "test supervision".to_owned(),
            },
            TraceFreshness::Fresh,
        )
        .expect("derive");
    derivation
}

#[test]
fn settled_feed_drives_admission_drain_and_receipts() {
    let (view, activation, session, attention, coverage, policy) = support::inputs(false, false);
    let outcome = eliot_reactive_context_plan::produce_settled_plan_feed(SettledPlanFeedInputs {
        view: &view,
        cue_activation: &activation,
        session_snapshot: &session,
        critical_attention: &attention,
        integration_coverage: &coverage,
        policy: &policy,
    })
    .expect("owner projections must feed");
    let (live_session, batch_items, plan_items, activation_digest, policy_digest) = match &outcome {
        SettledPlanFeedOutcome::Ready(feed) => {
            assert!(
                !feed.batch.items.is_empty(),
                "tool-only fixture must yield deliverable items"
            );
            (
                feed.plan.request.session_id.as_str().to_owned(),
                feed.batch.items.len(),
                feed.plan.items.len(),
                feed.plan.activation_digest.clone(),
                feed.plan.policy_digest.clone(),
            )
        }
        SettledPlanFeedOutcome::NoSettledPlan(disposition) => {
            panic!(
                "fixture must settle a plan, got no-injection {}",
                disposition.reason
            )
        }
    };
    // The runner attaches under the plan's own owner session: the session
    // gate compares feed text against the live attach, never mints.
    let mut runner = attached_runner(&live_session);
    let mut admission = SettledPlanAdmission::new();
    let derivation = live_derivation();
    // THE production caller: feed outcome + retained driver + live
    // derivation into the ledger. No batch hand-shaping after this point.
    let outcome = admit_producer_feed(&mut admission, &mut runner, &derivation, outcome);
    let report = match outcome.expect("live chain admits") {
        FeedAdmissionOutcome::Admitted(report) => report,
        FeedAdmissionOutcome::NoPlan => panic!("ready feed must admit"),
    };
    assert_eq!(report.session_id, live_session);
    assert_eq!(
        report.admitted.len(),
        batch_items,
        "every produced instruction reaches the ledger"
    );
    assert!(report.withheld.is_empty());
    assert_eq!(
        report.admitted.len() as u64
            + report.replay_suppressed
            + report.duplicate_suppressed
            + report.skipped_sticky
            + report.skipped_ineligible,
        plan_items as u64,
        "admitted + suppressed + skipped reconciles with the settled plan"
    );
    assert_eq!(runner.reactive_pending_count(), report.admitted.len());
    // Live drain through the real forwarded hook: one receipt per item,
    // each carrying the Governor assessment and the live session.
    runner
        .forward_hook(&hook_event("hook-caller-1"))
        .expect("hook forwards");
    let receipts = runner
        .deliver_reactive_pending_via_hook("hook-caller-1")
        .expect("hook drain issues receipts");
    assert_eq!(receipts.len(), report.admitted.len());
    for receipt in &receipts {
        assert_eq!(receipt.session_id, live_session);
        assert_eq!(
            receipt.firing.rule_id,
            format!("reactive-activation:{activation_digest}")
        );
        assert_eq!(receipt.admission.governance_profile_rev, policy_digest);
    }
    assert_eq!(runner.reactive_pending_count(), 0);
}

#[test]
fn settled_no_injection_makes_zero_calls() {
    let (view, activation, _session, attention, coverage, policy) = support::inputs(false, false);
    let delivered = support::delivered_session(&policy);
    let outcome = eliot_reactive_context_plan::produce_settled_plan_feed(SettledPlanFeedInputs {
        view: &view,
        cue_activation: &activation,
        session_snapshot: &delivered,
        critical_attention: &attention,
        integration_coverage: &coverage,
        policy: &policy,
    })
    .expect("delivered session must feed without error");
    assert!(
        matches!(outcome, SettledPlanFeedOutcome::NoSettledPlan(_)),
        "delivered session must settle no injection"
    );
    let mut runner = attached_runner("session-caller-unused");
    let mut admission = SettledPlanAdmission::new();
    let derivation = live_derivation();
    let outcome = admit_producer_feed(&mut admission, &mut runner, &derivation, outcome)
        .expect("no-plan is honest, not failure");
    assert_eq!(outcome, FeedAdmissionOutcome::NoPlan);
    assert_eq!(runner.reactive_pending_count(), 0);
    assert_eq!(admission.replay_len(), 0);
}
