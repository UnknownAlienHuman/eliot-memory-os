//! Issue #1941 result flow: live holder joining the route owner's measured
//! attestation (observation, count, digest) with the exact result bytes,
//! current admission, and execution binding.
//!
//! The codex adapter measures exact result bytes with the route's actual
//! tokenizer and emits the canonical Matched observation
//! ([`CodexMeasuredToolResult`](eliot_agent_codex::route_tokenizer::CodexMeasuredToolResult)).
//! This bridge crate verifies the attestation and projects the receipt
//! ([`AgentBridgeCore::project_produced_tool_result`]). The bridge runs no
//! tokenizer: the count passes through byte-bound verification unaltered,
//! never estimated, summed, or re-counted. Layering stays one-way — the
//! adapter takes no bridge dependency, the surface takes no adapter
//! dependency, and this crate (which already depends on the core) holds
//! only canonical agent-api types plus primitives. No parallel measurement
//! types, facades, or `From` bridges are introduced.
//!
//! Intake verification (admission linkage, route state, byte binding) stays
//! the single verifier — this module duplicates none of it.
//!
//! The remaining gap is the central hook: calling this join from the live
//! Invoke dispatch with owner-supplied inputs (bytes are present at the
//! dispatch; observation, attested count/digest, admission, binding, and
//! admissible handle arrive from their owners) and attaching the receipt
//! to the response evidence path. That dispatch and response slot are
//! A3-owned; the exact insertion anchor is reserved in CONTROL
//! (`1941-result-flow-delivery.md`), not built here.
//!
//! Call chain (exact):
//!
//! ```text
//! project_measured_tool_result(core, bytes, flow)
//! → TokenMeasurementPayload{contract_version: v1, observation (unmodified),
//!     result_digest: attested digest, tokens: attested count}
//! → core.project_produced_tool_result(bytes, handle, Some(payload),
//!     admission, binding, delivery)
//!   → intake verifies version/shape, validate_against(admission, binding),
//!     Matched + observed route, digest equality with the exact bytes
//!   → ToolResultReceipt::project(bytes, handle, attested tokens, delivery)
//! ```

use eliot_agent_api::{
    AdmittedRouteReceipt, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
};
use eliot_agent_bridge_core::{
    AgentBridgeCore, BridgeError, DeliveryStatus, ResourceUri, TOKEN_MEASUREMENT_VERSION,
    TokenMeasurementPayload, ToolResultReceipt,
};

/// Live holder for one measured tool-result delivery.
///
/// Every field arrives from its owner: the physical observation and the
/// attested count/digest from the route owner's measurement emission, the
/// admission and execution binding from the current admission/binding
/// authorities, the source handle from the C3-recorded view, and delivery
/// from the owner's observed completeness. All references are borrowed —
/// this flow mints nothing, defaults nothing, and runs no tokenizer.
#[derive(Clone, Debug)]
pub struct LiveToolResult<'a> {
    /// Live route observation, passed through unmodified into the payload.
    pub observation: &'a PhysicalRouteObservationReceipt,
    /// Token count the route owner's actual tokenizer reported for the
    /// exact bytes being receipted. Passed through unaltered; never
    /// estimated or recomputed here.
    pub tokens: u64,
    /// Lowercase SHA-256 hex of the exact bytes the count was reported
    /// for, as bound by the measurer. Verified against the bytes at
    /// intake.
    pub result_digest: &'a str,
    /// Current admission the observation must link against.
    pub admission: &'a AdmittedRouteReceipt,
    /// Live execution binding the observation must link against.
    pub binding: &'a ProviderExecutionBinding,
    /// Admissible source handle for the receipt (C3-recorded view handle).
    pub source_handle: ResourceUri,
    /// Owner-observed delivery completeness.
    pub delivery: DeliveryStatus,
}

/// Projects the route owner's measured attestation into its byte-bound
/// delivery receipt.
///
/// The attested count and digest enter the versioned wire payload; the
/// core re-verifies admission linkage, route state, and byte binding at
/// intake and passes the attested count through unaltered. Turn-level
/// usage is never read as a result cost.
///
/// # Errors
///
/// Returns [`BridgeError::UnmeasuredTokens`] when the attestation fails
/// intake verification (unlinked, diverged, unobserved, or misbound
/// evidence); [`BridgeError::InvalidContract`] for malformed
/// payload/admission/binding inputs; [`BridgeError::NotAttached`] while
/// detached.
pub fn project_measured_tool_result(
    core: &AgentBridgeCore,
    result_bytes: &[u8],
    flow: &LiveToolResult<'_>,
) -> Result<ToolResultReceipt, BridgeError> {
    let payload = TokenMeasurementPayload {
        contract_version: TOKEN_MEASUREMENT_VERSION,
        observation: flow.observation.clone(),
        result_digest: flow.result_digest.to_owned(),
        tokens: flow.tokens,
    };
    core.project_produced_tool_result(
        result_bytes,
        flow.source_handle.clone(),
        Some(&payload),
        flow.admission,
        flow.binding,
        flow.delivery,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_agent_api::{
        AgentAttemptId, CONTRACT_VERSION, CandidateSelectionDisposition, ClockReading, EventCursor,
        ExecutionOutcome, ExecutionUnit, NativeSession, NativeSessionLocator, RequestId,
        ResourceGeneration, RouteObservationState, RouteSelectionCandidate, StateFence,
        UsageReceipt, candidate_digest_for, route_divergence_fields,
    };
    use eliot_agent_bridge_core::{
        ActivationPortOutcome, ActivationPortResult, AttachBinding, AttachRequest, ConnectionId,
        CoverageGap, DemandId, EventPortOutcome, Generation, HostActivationPort, HostEventEnvelope,
        McpForwardingPort, PrincipalId, ProviderFailure, ProviderReadiness,
        ReconciliationPortOutcome, RouteFingerprint, SessionId, TaskId, UnmeasuredReason,
        WorkUnitId,
    };
    use eliot_contracts::{EpochId, EpochLineageId};
    use serde_json::json;
    use std::num::NonZeroU64;

    use crate::{BridgeRunner, Profile};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    /// Adapter-proven golden end to end: the codex producer counts
    /// `b"hello world"` as 2 under the owner-mapped tokenizer with this
    /// digest. The bridge never recounts; it passes the attestation
    /// through byte-bound verification.
    const HELLO_DIGEST: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> Result<StateFence, Box<dyn std::error::Error>> {
        Ok(StateFence::new(test_epoch(1), ResourceGeneration::new(1)?))
    }

    fn test_route() -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Ok(serde_json::from_value(json!({
            "host_family": "codex",
            "adapter": "eliot-agent-codex",
            "protocol_transport": "app-server+stdio/jsonl",
            "runtime_hash": hex,
            "adapter_hash": hex,
            "provider": "test-provider",
            "model": "gpt-5-codex",
            "auth_billing": "test-billing",
            "serializer_hash": hex,
            "tool_semantics_hash": hex,
            "reasoning_mode": "test-reasoning",
            "continuation_behavior": "test-continuation",
            "feature_flags_hash": hex,
        }))?)
    }

    fn binding(
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
        Ok(ProviderExecutionBinding {
            attempt_id: AgentAttemptId::new("attempt-1")?,
            lease_id: serde_json::from_value(json!({
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": "lease-1",
            }))?,
            state_fence: fence.clone(),
            runtime_generation: ResourceGeneration::new(1)?,
            route: route.clone(),
            session_id: None,
            provider_scope_ref: "scope:test".to_owned(),
            native_session: NativeSession::Native(NativeSessionLocator::new("thread-1")?),
            execution_unit: ExecutionUnit::new("test-provider", "unit-1")?,
            start_request_id: RequestId::new("req-1")?,
            start_request_sha256: serde_json::from_value(serde_json::Value::String(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
            ))?,
        })
    }

    fn admission(
        decision: &str,
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
        let candidate = RouteSelectionCandidate {
            capability: "test-capability".to_owned(),
            query_intent: "test-intent".to_owned(),
            scope_ref: "scope:test".to_owned(),
            policy_revision: eliot_agent_api::PolicyRevision::new(3)?,
            candidates: vec![route.clone()],
            selected: Some(route.clone()),
            rejected: Vec::new(),
            selection: CandidateSelectionDisposition::Selected,
            evidence_refs: vec!["evidence-1".to_owned()],
        };
        candidate.validate()?;
        let candidate_digest = candidate_digest_for(&candidate)?;
        let route_json = serde_json::to_value(route)?;
        let mut receipt: AdmittedRouteReceipt = serde_json::from_value(json!({
            "schema_version": CONTRACT_VERSION,
            "decision_id": decision,
            "candidate_digest": candidate_digest.as_str(),
            "attempt_id": "attempt-1",
            "lease_id": {"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"},
            "state_fence": {
                "authority_epoch": {"lineage_id": TEST_LINEAGE_A, "sequence": 1},
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null,
            },
            "runtime_generation": 1,
            "policy_revision": 3,
            "requested_route": route_json,
            "selected_route": route_json,
            "no_route": null,
            "evidence_refs": ["evidence-1"],
            "proof_ceiling": "CANDIDATE_ARTIFACT",
            "self_digest": "0000000000000000000000000000000000000000000000000000000000000000",
        }))?;
        receipt.self_digest = receipt.compute_digest()?;
        receipt.validate()?;
        assert_eq!(receipt.state_fence, *fence);
        Ok(receipt)
    }

    fn observation(
        route: &RouteFingerprint,
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        state: RouteObservationState,
        observed: Option<RouteFingerprint>,
    ) -> Result<PhysicalRouteObservationReceipt, Box<dyn std::error::Error>> {
        let (diverged_fields, unobserved_reason, recovery_ref) = match state {
            RouteObservationState::Matched => (Vec::new(), None, None),
            RouteObservationState::Diverged => {
                let seen = observed.clone().expect("diverged needs observed");
                (
                    route_divergence_fields(route, &seen),
                    None,
                    Some("quarantine-diverged".to_owned()),
                )
            }
            RouteObservationState::Unobserved => (
                Vec::new(),
                Some("route not observed on this delivery".to_owned()),
                None,
            ),
        };
        let mut receipt = PhysicalRouteObservationReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            attempt_id: AgentAttemptId::new("attempt-1")?,
            state_fence: fence()?,
            runtime_generation: ResourceGeneration::new(1)?,
            admitted_route_digest: admission.self_digest.clone(),
            binding: binding.clone(),
            requested_route: route.clone(),
            observed_route: observed,
            route_state: state,
            diverged_fields,
            execution_outcome: ExecutionOutcome::Observed,
            request_digest: serde_json::from_value(serde_json::Value::String(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
            ))?,
            translation_digest: None,
            // Adapter-honest: no evidence record exists at emission time, so
            // neither digest nor reference is set here; the counted-bytes
            // binding travels in the attestation digest the bridge verifies.
            raw_evidence_digest: None,
            raw_evidence_ref: None,
            // Turn-level usage is the adapter's own record and is never read
            // as a result cost: the attested count below must not equal it.
            usage: UsageReceipt {
                input_tokens: Some(10),
                output_tokens: Some(99),
                cost_microunits: None,
                quota: eliot_agent_api::QuotaKnowledge::Unknown,
            },
            started: ClockReading {
                valid_time_ms: Some(1_000),
                known_time_ms: Some(1_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            first_byte: ClockReading::default(),
            first_semantic: ClockReading::default(),
            terminal: ClockReading {
                valid_time_ms: Some(2_000),
                known_time_ms: Some(2_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            event_cursor: EventCursor::new("cursor-1")?,
            event_sequence: 1,
            cancellation: None,
            unobserved_reason,
            recovery_ref,
            safe_public_error: None,
            restricted_raw_error_ref: None,
            self_digest: serde_json::from_value(serde_json::Value::String(
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            ))?,
        };
        receipt.self_digest = receipt.compute_digest()?;
        receipt.validate()?;
        receipt.validate_against(binding, admission)?;
        Ok(receipt)
    }

    struct StaticHost {
        result: ActivationPortResult,
    }

    impl HostActivationPort for StaticHost {
        fn activate(
            &mut self,
            _request: &AttachRequest,
        ) -> Result<ActivationPortOutcome, ProviderFailure> {
            Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
        }
    }

    fn core(attached: bool) -> Result<AgentBridgeCore, Box<dyn std::error::Error>> {
        let generation = Generation::new(1)?;
        let fence = eliot_agent_bridge_core::FencingToken::new(
            test_epoch(1),
            Generation::new(1)?,
            "fence-1".to_owned(),
        )?;
        let result = ActivationPortResult::authenticated(
            PrincipalId::new("principal-1")?,
            SessionId::new("session-1")?,
            generation,
            fence,
            TaskId::new("task-1")?,
            WorkUnitId::new("work-unit-1")?,
            "scope-1",
            "task-revision-1",
            "plan-1",
            "plan-revision-1",
        )?;
        let mut core = AgentBridgeCore::new(
            ProviderReadiness::all_admitted(),
            Some(Box::new(StaticHost { result })),
            None,
            eliot_agent_bridge_core::CursorPolicy::new(
                eliot_agent_bridge_core::AckPhase::Durable,
                eliot_agent_bridge_core::AckPhase::Normalized,
            )?,
        );
        if attached {
            core.attach(AttachRequest::managed(
                DemandId::new("demand-1")?,
                ConnectionId::new("connection-1")?,
            ))?;
        }
        Ok(core)
    }

    fn live_set() -> Result<
        (
            RouteFingerprint,
            ProviderExecutionBinding,
            AdmittedRouteReceipt,
            AgentBridgeCore,
        ),
        Box<dyn std::error::Error>,
    > {
        let route = test_route()?;
        let fence = fence()?;
        let bound = binding(&route, &fence)?;
        let admitted = admission("decision-1", &route, &fence)?;
        let core = core(true)?;
        Ok((route, bound, admitted, core))
    }

    fn flow<'a>(
        observation: &'a PhysicalRouteObservationReceipt,
        tokens: u64,
        result_digest: &'a str,
        admission: &'a AdmittedRouteReceipt,
        binding: &'a ProviderExecutionBinding,
    ) -> Result<LiveToolResult<'a>, Box<dyn std::error::Error>> {
        Ok(LiveToolResult {
            observation,
            tokens,
            result_digest,
            admission,
            binding,
            source_handle: ResourceUri::parse("eliot://evidence/source")?,
            delivery: DeliveryStatus::Full,
        })
    }

    #[test]
    fn live_holder_projects_attested_count_unaltered() -> TestResult {
        let (route, bound, admitted, core) = live_set()?;
        let result_bytes = b"hello world";
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Matched,
            Some(route.clone()),
        )?;
        let flow = flow(&seen, 2, HELLO_DIGEST, &admitted, &bound)?;
        let receipt = project_measured_tool_result(&core, result_bytes, &flow)?;
        // Pass-through: the receipt repeats the attested count and digest,
        // never a relabelled turn-level figure.
        assert_eq!(receipt.tokens_rendered(), 2);
        assert_eq!(receipt.result_digest(), HELLO_DIGEST);
        assert_ne!(
            receipt.tokens_rendered(),
            99,
            "turn-level usage must never become the result cost"
        );
        assert!(receipt.check_complete_evidence().is_ok());
        Ok(())
    }

    #[test]
    fn tampered_bytes_withhold_on_digest() -> TestResult {
        let (route, bound, admitted, core) = live_set()?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Matched,
            Some(route.clone()),
        )?;
        let flow = flow(&seen, 2, HELLO_DIGEST, &admitted, &bound)?;
        match project_measured_tool_result(&core, b"hello world?", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::DigestMismatch,
            }) => Ok(()),
            other => panic!("misbound bytes must withhold: {other:?}"),
        }
    }

    #[test]
    fn cross_admission_withholds_on_linkage() -> TestResult {
        let (route, bound, admitted, core) = live_set()?;
        let fence = fence()?;
        let other_admission = admission("decision-2", &route, &fence)?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Matched,
            Some(route.clone()),
        )?;
        let flow = flow(&seen, 2, HELLO_DIGEST, &other_admission, &bound)?;
        match project_measured_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::AdmissionMismatch,
            }) => Ok(()),
            other => panic!("cross-admission evidence must withhold: {other:?}"),
        }
    }

    #[test]
    fn diverged_route_withholds_despite_count() -> TestResult {
        let fence = fence()?;
        let route = test_route()?;
        let mut seen_route = route.clone();
        seen_route.model = "gpt-5-mini".to_owned();
        let bound = binding(&route, &fence)?;
        let admitted = admission("decision-1", &route, &fence)?;
        let core = core(true)?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Diverged,
            Some(seen_route),
        )?;
        let flow = flow(&seen, 2, HELLO_DIGEST, &admitted, &bound)?;
        match project_measured_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::RouteDiverged,
            }) => Ok(()),
            other => panic!("diverged route must withhold: {other:?}"),
        }
    }

    #[test]
    fn unobserved_route_withholds_at_intake() -> TestResult {
        let (route, bound, admitted, core) = live_set()?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Unobserved,
            None,
        )?;
        let flow = flow(&seen, 2, HELLO_DIGEST, &admitted, &bound)?;
        match project_measured_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::RouteUnobserved,
            }) => Ok(()),
            other => panic!("unobserved route must withhold: {other:?}"),
        }
    }

    #[test]
    fn detached_core_fails_closed() -> TestResult {
        let (route, bound, admitted, _attached) = live_set()?;
        let core = core(false)?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Matched,
            Some(route.clone()),
        )?;
        let flow = flow(&seen, 2, HELLO_DIGEST, &admitted, &bound)?;
        match project_measured_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::NotAttached) => Ok(()),
            other => panic!("detached core must fail closed: {other:?}"),
        }
    }

    struct StubForwarder;

    impl McpForwardingPort for StubForwarder {
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
            _event: &eliot_agent_bridge_core::EventEnvelope,
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

    #[test]
    fn runner_projects_measured_attestation() -> TestResult {
        let generation = Generation::new(3).expect("non-zero test generation");
        let fence = eliot_agent_bridge_core::FencingToken::new(
            test_epoch(2),
            generation,
            "fence-runner-3".to_owned(),
        )
        .expect("valid test fence");
        let result = ActivationPortResult::authenticated(
            PrincipalId::new("principal-runner-1").expect("valid principal"),
            SessionId::new("session-runner-1").expect("valid session"),
            generation,
            fence,
            TaskId::new("task-runner-1").expect("valid task"),
            WorkUnitId::new("work-unit-runner-1").expect("valid work unit"),
            "scope-runner-1",
            "task-revision-1",
            "plan-runner-1",
            "plan-revision-1",
        )
        .expect("valid activation result");
        let mut runner = BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::all_admitted(),
            Some(Box::new(StaticHost { result })),
            Some(Box::new(StubForwarder)),
        )
        .expect("runner composes");
        runner
            .attach(AttachRequest::managed(
                DemandId::new("demand-runner-1").expect("valid demand"),
                ConnectionId::new("connection-runner-1").expect("valid connection"),
            ))
            .expect("managed attach admits");
        let (route, bound, admitted, _core) = live_set()?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Matched,
            Some(route.clone()),
        )?;
        let flow = flow(&seen, 2, HELLO_DIGEST, &admitted, &bound)?;
        let receipt = runner.project_measured_tool_result(b"hello world", &flow)?;
        assert_eq!(receipt.result_digest(), HELLO_DIGEST);
        assert_eq!(receipt.tokens_rendered(), 2);
        assert!(receipt.check_complete_evidence().is_ok());
        Ok(())
    }
}
