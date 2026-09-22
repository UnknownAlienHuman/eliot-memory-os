//! Issue #1941 result flow: live holder joining exact result bytes with the
//! admitted route's observed model, physical observation, current admission,
//! and execution binding.
//!
//! The codex adapter measures exact result bytes with the route's actual
//! tokenizer
//! ([`measure_result_tokens`](eliot_agent_codex::route_tokenizer::measure_result_tokens));
//! the bridge core verifies the attestation and projects the receipt
//! ([`AgentBridgeCore::project_produced_tool_result`]). Neither crate may
//! depend on the other — provider-side measurement never depends on surface
//! contracts, and the surface never runs a tokenizer — so the holder lives
//! here: this bridge crate already depends on the core and the adapter and
//! holds the Invoke callsite. All join logic stays in this module; no
//! parallel measurement types, facades, or `From` bridges are introduced —
//! every boundary type is the canonical owner type.
//!
//! The measured model is derived from the observation's observed route
//! ([`LiveToolResult::observed_model`]), never supplied separately: a
//! caller-provided model string next to an observation for another route
//! would attribute one route's tokenizer count to another route's receipt.
//! A missing observed route withholds as
//! [`UnmeasuredReason::RouteUnobserved`]; measurement withhold (unknown or
//! community-only model, non-text bytes, unavailable tokenizer) withholds
//! as [`UnmeasuredReason::NoObservation`]. Intake verification
//! (admission linkage, route state, byte binding) stays the single
//! verifier — this module duplicates none of it.
//!
//! Verified adapter/API/coordinator findings (no changes needed there):
//!
//! - Adapter: `measure_result_tokens` is the complete authentic producer
//!   (owner-gated, real BPE, withhold-honest). `translate_result` keeps its
//!   documented contract — observed route never defaulted from requested,
//!   `UNOBSERVED` with reason — so no Matched observation and no count
//!   channel are invented adapter-side.
//! - API: all linkage types exist (`validate_against` enforced); a second
//!   measurement wire type would duplicate the bridge-core contract.
//! - Coordinator: `AgentResult` carries artifact IDs and evidence refs, not
//!   bytes, so no byte-join belongs there.
//!
//! The remaining gap is the central hook: calling this join from the live
//! Invoke dispatch with the Kernel/admission-side inputs (exact bytes are
//! present; observation, admission, binding, and admissible handle must
//! arrive from their owners) and attaching the receipt to the response
//! evidence path. That dispatch and response slot are A3-owned; the exact
//! insertion anchor is reserved in CONTROL (`1941-result-flow-delivery.md`),
//! not built here.
//!
//! Call chain (exact):
//!
//! ```text
//! project_live_tool_result(core, bytes, flow)
//! → flow.observed_model() else UnmeasuredTokens{RouteUnobserved}
//! → measure_result_tokens(model, bytes)
//!   else UnmeasuredTokens{NoObservation} (withhold, never estimate)
//! → TokenMeasurementPayload{contract_version: v1, observation (unmodified),
//!     result_digest: measured digest, tokens: measured count}
//! → core.project_produced_tool_result(bytes, handle, Some(payload),
//!     admission, binding, delivery)
//!   (NotAttached | InvalidContract | UnmeasuredTokens propagate)
//! ```

use eliot_agent_api::{
    AdmittedRouteReceipt, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
};
use eliot_agent_bridge_core::{
    AgentBridgeCore, BridgeError, DeliveryStatus, ResourceUri, TOKEN_MEASUREMENT_VERSION,
    TokenMeasurementPayload, ToolResultReceipt, UnmeasuredReason,
};
use eliot_agent_codex::route_tokenizer::measure_result_tokens;

/// Live holder for one measured tool-result delivery.
///
/// The bridge cannot source any of these itself: the physical observation
/// from the route owner, the admission and execution binding from the
/// current admission/binding authorities, the source handle from the
/// C3-recorded view, and delivery from the owner's observed completeness.
/// All are borrowed — this flow mints nothing, defaults nothing, and
/// carries no model string of its own.
#[derive(Clone, Debug)]
pub struct LiveToolResult<'a> {
    /// Live route observation, passed through unmodified into the payload.
    pub observation: &'a PhysicalRouteObservationReceipt,
    /// Current admission the observation must link against.
    pub admission: &'a AdmittedRouteReceipt,
    /// Live execution binding the observation must link against.
    pub binding: &'a ProviderExecutionBinding,
    /// Admissible source handle for the receipt (C3-recorded view handle).
    pub source_handle: ResourceUri,
    /// Owner-observed delivery completeness.
    pub delivery: DeliveryStatus,
}

impl LiveToolResult<'_> {
    /// Exact provider model of the observed route, verbatim.
    ///
    /// `None` exactly when no route was observed: absence is never
    /// synthesized from the requested route, so unobserved deliveries
    /// withhold instead of measuring under a guessed model.
    #[must_use]
    pub fn observed_model(&self) -> Option<&str> {
        self.observation
            .observed_route
            .as_ref()
            .map(|route| route.model.as_str())
    }
}

/// Measures exact result bytes with the observed route's actual tokenizer
/// and projects the byte-bound delivery receipt.
///
/// The observed model ([`LiveToolResult::observed_model`]) runs the count;
/// the measured digest and count enter the versioned wire payload; the core
/// re-verifies admission linkage, route state, and byte binding at intake
/// and passes the attested count through unaltered. Turn-level usage is
/// never read as a result cost.
///
/// # Errors
///
/// Returns [`BridgeError::UnmeasuredTokens`] when no route was observed,
/// when the route supports no measurement on this delivery, or when the
/// attestation fails intake verification; [`BridgeError::InvalidContract`]
/// for malformed payload/admission/binding inputs;
/// [`BridgeError::NotAttached`] while detached.
pub fn project_live_tool_result(
    core: &AgentBridgeCore,
    result_bytes: &[u8],
    flow: &LiveToolResult<'_>,
) -> Result<ToolResultReceipt, BridgeError> {
    let model = flow.observed_model().ok_or(BridgeError::UnmeasuredTokens {
        reason: UnmeasuredReason::RouteUnobserved,
    })?;
    let measured =
        measure_result_tokens(model, result_bytes).map_err(|_| BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::NoObservation,
        })?;
    let payload = TokenMeasurementPayload {
        contract_version: TOKEN_MEASUREMENT_VERSION,
        observation: flow.observation.clone(),
        result_digest: measured.result_digest().to_owned(),
        tokens: measured.tokens(),
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
        ReconciliationPortOutcome, RouteFingerprint, SessionId, TaskId, WorkUnitId,
    };
    use eliot_contracts::{EpochId, EpochLineageId};
    use serde_json::json;
    use std::num::NonZeroU64;

    use crate::{BridgeRunner, Profile};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    /// Producer-proven golden: `measure_result_tokens("gpt-5-codex",
    /// b"hello world")` counts 2 under `o200k_base` with this digest
    /// (codex producer lane). Pinned here as the end-to-end expectation,
    /// not recomputed by the unit under test.
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

    fn test_route(model: &str) -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Ok(serde_json::from_value(json!({
            "host_family": "codex",
            "adapter": "eliot-agent-codex",
            "protocol_transport": "app-server+stdio/jsonl",
            "runtime_hash": hex,
            "adapter_hash": hex,
            "provider": "test-provider",
            "model": model,
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

    #[allow(clippy::too_many_arguments)]
    fn observation(
        route: &RouteFingerprint,
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        state: RouteObservationState,
        observed: Option<RouteFingerprint>,
        evidence_digest: Option<&str>,
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
        let (raw_evidence_digest, raw_evidence_ref) = match evidence_digest {
            Some(hex) => (
                Some(serde_json::from_value::<eliot_agent_api::LowercaseSha256>(
                    serde_json::Value::String(hex.to_owned()),
                )?),
                Some("tool-result:invoke-1".to_owned()),
            ),
            None => (None, None),
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
            raw_evidence_digest,
            raw_evidence_ref,
            // Turn-level usage is the adapter's own record and is never read
            // as a result cost: the measured count below must not equal it.
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
        let route = test_route("gpt-5-codex")?;
        let fence = fence()?;
        let bound = binding(&route, &fence)?;
        let admitted = admission("decision-1", &route, &fence)?;
        let core = core(true)?;
        Ok((route, bound, admitted, core))
    }

    fn flow<'a>(
        observation: &'a PhysicalRouteObservationReceipt,
        admission: &'a AdmittedRouteReceipt,
        binding: &'a ProviderExecutionBinding,
    ) -> Result<LiveToolResult<'a>, Box<dyn std::error::Error>> {
        Ok(LiveToolResult {
            observation,
            admission,
            binding,
            source_handle: ResourceUri::parse("eliot://evidence/source")?,
            delivery: DeliveryStatus::Full,
        })
    }

    #[test]
    fn live_holder_projects_measured_count_unaltered() -> TestResult {
        let (route, bound, admitted, core) = live_set()?;
        let result_bytes = b"hello world";
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Matched,
            Some(route.clone()),
            Some(HELLO_DIGEST),
        )?;
        let flow = flow(&seen, &admitted, &bound)?;
        assert_eq!(flow.observed_model(), Some("gpt-5-codex"));
        let receipt = project_live_tool_result(&core, result_bytes, &flow)?;
        // Pass-through: the receipt repeats the producer's real count and
        // digest, never a relabelled turn-level figure.
        let direct =
            measure_result_tokens("gpt-5-codex", result_bytes).expect("direct producer count");
        assert_eq!(receipt.tokens_rendered(), direct.tokens());
        assert_eq!(receipt.result_digest(), HELLO_DIGEST);
        assert_eq!(receipt.result_digest(), direct.result_digest());
        assert_ne!(
            receipt.tokens_rendered(),
            99,
            "turn-level usage must never become the result cost"
        );
        assert!(receipt.check_complete_evidence().is_ok());
        Ok(())
    }

    #[test]
    fn community_only_model_withholds() -> TestResult {
        let fence = fence()?;
        let route = test_route("codex-mini-latest")?;
        let bound = binding(&route, &fence)?;
        let admitted = admission("decision-1", &route, &fence)?;
        let core = core(true)?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Matched,
            Some(route.clone()),
            Some(HELLO_DIGEST),
        )?;
        let flow = flow(&seen, &admitted, &bound)?;
        assert_eq!(flow.observed_model(), Some("codex-mini-latest"));
        match project_live_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::NoObservation,
            }) => Ok(()),
            other => panic!("community-only model must withhold: {other:?}"),
        }
    }

    #[test]
    fn unobserved_route_withholds_before_measuring() -> TestResult {
        let (route, bound, admitted, core) = live_set()?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Unobserved,
            None,
            None,
        )?;
        let flow = flow(&seen, &admitted, &bound)?;
        assert_eq!(flow.observed_model(), None);
        match project_live_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::RouteUnobserved,
            }) => Ok(()),
            other => panic!("unobserved route must withhold: {other:?}"),
        }
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
            Some(HELLO_DIGEST),
        )?;
        let flow = flow(&seen, &admitted, &bound)?;
        match project_live_tool_result(&core, b"hello world?", &flow) {
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
            Some(HELLO_DIGEST),
        )?;
        let flow = flow(&seen, &other_admission, &bound)?;
        match project_live_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::AdmissionMismatch,
            }) => Ok(()),
            other => panic!("cross-admission evidence must withhold: {other:?}"),
        }
    }

    #[test]
    fn diverged_route_withholds_despite_count() -> TestResult {
        let fence = fence()?;
        let route = test_route("gpt-5-codex")?;
        let seen_route = test_route("gpt-5-mini")?;
        let bound = binding(&route, &fence)?;
        let admitted = admission("decision-1", &route, &fence)?;
        let core = core(true)?;
        let seen = observation(
            &route,
            &bound,
            &admitted,
            RouteObservationState::Diverged,
            Some(seen_route),
            Some(HELLO_DIGEST),
        )?;
        let flow = flow(&seen, &admitted, &bound)?;
        // The observed model measures fine; linkage still withholds.
        assert_eq!(flow.observed_model(), Some("gpt-5-mini"));
        match project_live_tool_result(&core, b"hello world", &flow) {
            Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::RouteDiverged,
            }) => Ok(()),
            other => panic!("diverged route must withhold: {other:?}"),
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
            Some(HELLO_DIGEST),
        )?;
        let flow = flow(&seen, &admitted, &bound)?;
        match project_live_tool_result(&core, b"hello world", &flow) {
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
    fn runner_projects_live_tool_result() -> TestResult {
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
            Some(HELLO_DIGEST),
        )?;
        let flow = flow(&seen, &admitted, &bound)?;
        let receipt = runner.project_live_tool_result(b"hello world", &flow)?;
        assert_eq!(receipt.result_digest(), HELLO_DIGEST);
        assert!(receipt.check_complete_evidence().is_ok());
        Ok(())
    }
}
