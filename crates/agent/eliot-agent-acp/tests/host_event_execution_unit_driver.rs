//! Execution-unit ingest driver proof for issue #2645 W1/W3 (audit
//! 5848315622).
//!
//! POSITIVE (`run_produces_and_delivers_execution_unit_events_with_owner_route_evidence`):
//! the production run flow
//! `run_ingest_for_fingerprint` declares one execution-unit event carrying the
//! run owner's own #361 binding, #369 admission and matched #369 physical
//! observation, and drives it through `produce_execution_unit_allowed`. The
//! committed record's retained route evidence is read back and compared with
//! what those owners resolve to; the same event is then delivered downstream and
//! projected to coordinator intake carrying that relation with the `Verified`
//! disposition, and the coverage denominator counts it.
//!
//! Without this change: at base `produce_execution_unit_allowed` has no
//! production caller at all, `run_ingest_for_fingerprint` accepts no events and
//! therefore produces nothing. The whole assertion set below is unreachable — no
//! record exists to read back, nothing is delivered, `intakes` is empty and the
//! denominator counts zero events. The test fails to even name
//! `ExecutionUnitDriverEvent`, which does not exist at base.
//!
//! REFUSAL (`run_refuses_foreign_observation_boundary_before_any_mutation`):
//! the declared observation was minted for another observation boundary of the
//! same attempt, binding, admission, fence and generation (its `event_sequence`
//! is 7 while the event's execution-unit sequence is 1). The producer must
//! reject it typed before any mutation, so nothing is staged or committed and the
//! durable cursor stays unadvanced.
//!
//! Without this change: the event cannot be declared at base (no driver entry
//! point), so the refusal is unobservable; and a hand-rolled
//! `stage_allowed` call would additionally bypass the applicability gate, which
//! only the execution-unit constructor reaches.

use eliot_agent_acp::{
    AcpFrameCodec, CoverageManifestPlan, CoverageManifestRun, DurableHostEventJournal,
    ExecutionUnitDisclosure, ExecutionUnitDriverEvent, ExecutionUnitFrame, ExecutionUnitRunError,
    IngestError, ProducerError, run_ingest_for_fingerprint,
};
use eliot_agent_api::{
    AdmittedRouteReceipt, AssistantDeltaObservation, AttemptId, CONTRACT_VERSION,
    CandidateSelectionDisposition, ClockReading, ContractError, DecisionId, EventCursor, EventId,
    ExecutionOutcome, ExecutionUnit, LowercaseSha256, NativeSession, NativeSessionLocator,
    NormalizedHostEventPayload, PhysicalRouteObservationReceipt, PolicyRevision, ProofCeiling,
    ProviderExecutionBinding, QuotaKnowledge, RequestId, RestrictedRawSourceHandle,
    ResourceGeneration, RouteFingerprint, RouteObservationState, RouteSelectionCandidate, StateFence,
    UsageReceipt, WorkLeaseId, candidate_digest_for, host_event::CommittedRouteBindingDisposition,
    route_fingerprint_digest_for,
};
use eliot_contracts::EpochLineageId;
use eliot_evaluation_contracts::{
    CoverageCompleteness, DenominatorOrigin, MaterialActionCoverage, RunFingerprint,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const STREAM: &str = "host-events:execution-unit-2645";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440264";

fn fixture_digest(value: &str) -> Result<LowercaseSha256, serde_json::Error> {
    serde_json::from_value(serde_json::json!(value))
}

fn zero_digest() -> Result<LowercaseSha256, serde_json::Error> {
    fixture_digest("0000000000000000000000000000000000000000000000000000000000000000")
}

fn clock(valid_ms: i64, known_ms: i64) -> ClockReading {
    ClockReading {
        valid_time_ms: Some(valid_ms),
        known_time_ms: Some(known_ms),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn observed_at() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1_750_000_000_000),
        known_time_ms: Some(1_750_000_000_001),
        transaction_sequence: None,
        monotonic_ns: Some(2645),
    }
}

fn fence() -> Result<StateFence, Box<dyn std::error::Error>> {
    Ok(StateFence::new(
        eliot_contracts::EpochId::new(
            EpochLineageId::new(LINEAGE)?,
            std::num::NonZeroU64::new(1).expect("nonzero epoch sequence"),
        )?,
        ResourceGeneration::new(1)?,
    ))
}

fn lease(value: &str) -> Result<WorkLeaseId, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": value,
    }))
}

fn route() -> Result<RouteFingerprint, serde_json::Error> {
    Ok(RouteFingerprint {
        host_family: "test-host".into(),
        adapter: "test-adapter".into(),
        protocol_transport: "loopback".into(),
        runtime_hash: fixture_digest(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )?,
        adapter_hash: fixture_digest(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )?,
        provider: "provider".into(),
        model: "model".into(),
        auth_billing: "subscription".into(),
        serializer_hash: fixture_digest(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )?,
        tool_semantics_hash: fixture_digest(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )?,
        reasoning_mode: "visible".into(),
        continuation_behavior: "native_resume".into(),
        feature_flags_hash: fixture_digest(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )?,
    })
}

fn binding(
    attempt: &AttemptId,
    lease_id: &WorkLeaseId,
    route: &RouteFingerprint,
    fence: &StateFence,
) -> TestResult<ProviderExecutionBinding> {
    Ok(ProviderExecutionBinding {
        attempt_id: attempt.clone(),
        lease_id: lease_id.clone(),
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::new(1)?,
        route: route.clone(),
        session_id: None,
        provider_scope_ref: "scope:test".into(),
        native_session: NativeSession::Native(NativeSessionLocator::new("thread-2645")?),
        execution_unit: ExecutionUnit::new("test-provider", "unit-2645")?,
        start_request_id: RequestId::new("req-2645")?,
        start_request_sha256: eliot_contracts::sha256_hex(b"req-2645"),
    })
}

fn admission(
    attempt: &AttemptId,
    lease_id: &WorkLeaseId,
    route: &RouteFingerprint,
    fence: &StateFence,
) -> TestResult<AdmittedRouteReceipt> {
    let candidate = RouteSelectionCandidate {
        capability: "test-capability".into(),
        query_intent: "test-intent".into(),
        scope_ref: "scope:test".into(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![route.clone()],
        selected: Some(route.clone()),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-2645".into()],
    };
    candidate.validate()?;
    let mut receipt = AdmittedRouteReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        decision_id: DecisionId::new("decision-2645")?,
        candidate_digest: candidate_digest_for(&candidate)?,
        attempt_id: attempt.clone(),
        lease_id: lease_id.clone(),
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::new(1)?,
        policy_revision: PolicyRevision::new(3)?,
        requested_route: route.clone(),
        selected_route: Some(route.clone()),
        no_route: None,
        evidence_refs: vec!["evidence-2645".into()],
        proof_ceiling: ProofCeiling::CandidateArtifact,
        self_digest: zero_digest()?,
    };
    receipt.self_digest = receipt.compute_digest()?;
    receipt.validate()?;
    Ok(receipt)
}

/// Owner-issued physical observation for one observation boundary. The reported
/// request commitment is the bound start request preserved verbatim.
fn observation(
    attempt: &AttemptId,
    route: &RouteFingerprint,
    fence: &StateFence,
    admission: &AdmittedRouteReceipt,
    binding: &ProviderExecutionBinding,
    event_sequence: u64,
) -> TestResult<PhysicalRouteObservationReceipt> {
    let mut record = PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: attempt.clone(),
        state_fence: fence.clone(),
        runtime_generation: ResourceGeneration::new(1)?,
        admitted_route_digest: admission.self_digest.clone(),
        binding: binding.clone(),
        requested_route: route.clone(),
        observed_route: Some(route.clone()),
        route_state: RouteObservationState::Matched,
        diverged_fields: Vec::new(),
        execution_outcome: ExecutionOutcome::Observed,
        request_digest: fixture_digest(&binding.start_request_sha256)?,
        translation_digest: None,
        raw_evidence_digest: None,
        raw_evidence_ref: None,
        usage: UsageReceipt {
            input_tokens: None,
            output_tokens: None,
            cost_microunits: None,
            quota: QuotaKnowledge::Unknown,
        },
        started: clock(1_000, 1_001),
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: clock(2_000, 2_001),
        event_cursor: EventCursor::new("unit-cursor-2645")?,
        event_sequence,
        cancellation: None,
        unobserved_reason: None,
        recovery_ref: None,
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: zero_digest()?,
    };
    record.self_digest = record.compute_digest()?;
    record.validate()?;
    record.validate_against(binding, admission)?;
    Ok(record)
}

fn frame_bytes() -> TestResult<Vec<u8>> {
    Ok(AcpFrameCodec::encode(
        br#"{"jsonrpc":"2.0","method":"session/update","params":{"update":"agent_message_chunk"}}"#,
    )?)
}

/// The declared coverage content the run may not mint itself.
///
/// [`CoverageManifestPlan`] borrows every collection and the denominator origin
/// rather than owning them, so the declared values are owned here and the plan
/// borrows them for exactly as long as the test holds this fixture.
struct CoveragePlanFixture {
    expected_event_sources_and_event_classes: [String; 1],
    observable_actions: [String; 1],
    unobservable_actions: [String; 1],
    missing_source_reasons: [String; 1],
    coverage_by_material_action_and_effect_route: [MaterialActionCoverage; 1],
    denominator_origin_and_sampling_policy: DenominatorOrigin,
    invalidation_dependencies: [String; 1],
}

fn coverage_plan() -> CoveragePlanFixture {
    CoveragePlanFixture {
        expected_event_sources_and_event_classes: ["acp:execution-unit".to_owned()],
        observable_actions: ["session-update".to_owned()],
        unobservable_actions: ["host-filesystem-access".to_owned()],
        missing_source_reasons: ["host-access-observation-not-exposed".to_owned()],
        coverage_by_material_action_and_effect_route: [MaterialActionCoverage {
            action_or_effect_route: "acp:execution-unit".to_owned(),
            covered: true,
            detail: "one retained committed execution-unit record".to_owned(),
        }],
        denominator_origin_and_sampling_policy: DenominatorOrigin {
            origin: "durable-host-event-journal".to_owned(),
            sampling_policy: "every-committed-record".to_owned(),
        },
        invalidation_dependencies: ["host-event-journal-reset".to_owned()],
    }
}

impl CoveragePlanFixture {
    fn plan<'a>(
        &'a self,
        fingerprint: &'a RunFingerprint,
        allowed_manifest_digest: &'a str,
    ) -> CoverageManifestPlan<'a> {
        CoverageManifestPlan {
            fingerprint,
            allowed_manifest_digest,
            expected_event_sources_and_event_classes: &self.expected_event_sources_and_event_classes,
            observable_actions: &self.observable_actions,
            unobservable_actions: &self.unobservable_actions,
            missing_source_reasons: &self.missing_source_reasons,
            coverage_by_material_action_and_effect_route:
                &self.coverage_by_material_action_and_effect_route,
            denominator_origin_and_sampling_policy: &self.denominator_origin_and_sampling_policy,
            completeness: CoverageCompleteness::Partial,
            invalidation_dependencies: &self.invalidation_dependencies,
        }
    }
}

#[test]
fn run_produces_and_delivers_execution_unit_events_with_owner_route_evidence() -> TestResult {
    let route = route()?;
    let attempt = AttemptId::new("attempt-2645")?;
    let lease_id = lease("lease-2645")?;
    let fence = fence()?;
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let admission = admission(&attempt, &lease_id, &route, &fence)?;
    let observation = observation(&attempt, &route, &fence, &admission, &binding, 1)?;
    let bytes = frame_bytes()?;

    let fingerprint = RunFingerprint {
        product_id: "product-2645".to_owned(),
        session_id: "session-2645".to_owned(),
        attempt_id: "attempt-2645".to_owned(),
        route_fingerprint: route_fingerprint_digest_for(&route)?.to_string(),
    };
    let allowed_manifest_digest = "manifest-2645";
    let events = vec![ExecutionUnitDriverEvent {
        frame: ExecutionUnitFrame {
            stream_id: STREAM,
            stream_sequence: 1,
            event_id: EventId::new("evt-2645-1")?,
            cursor: EventCursor::new("unit-cursor-2645")?,
            unit_cursor: EventCursor::new("unit-cursor-2645")?,
            unit_sequence: 1,
            binding: &binding,
            admission: &admission,
            physical_observation: Some(&observation),
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-source:2645-1")?,
            frame_bytes: &bytes,
            payload: NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
                delta_chars: 12,
                truncated: false,
            }),
            predecessors: Vec::new(),
            warnings: Vec::new(),
            observed_at: observed_at(),
        },
        disclosure: ExecutionUnitDisclosure::Admissible,
    }];

    let mut journal = DurableHostEventJournal::new();
    let coverage = coverage_plan();
    let run = CoverageManifestRun {
        stream_ids: &[STREAM],
        manifest_digest: allowed_manifest_digest,
        manifest_revision: "rev-2645",
        declared_tool_names: &[],
        forbidden_tool_names: &[],
        plan: coverage.plan(&fingerprint, allowed_manifest_digest),
    };

    let outcome = run_ingest_for_fingerprint(&mut journal, &run, &events, |_| true)?;

    // Produced through the execution-unit producer entry point and persisted.
    assert_eq!(outcome.produced.len(), 1);
    let produced = &outcome.produced[0];
    assert!(produced.outcome.fresh);
    assert!(!produced.outcome.redacted);
    assert_eq!(produced.outcome.key.stream_id, STREAM);
    assert_eq!(produced.outcome.key.sequence, 1);
    assert_eq!(produced.outcome.cursor.last_durable_sequence, 1);

    // The retained relation is compared with the owners, not merely present: the
    // requested column binds the admission's requested route, the actual column
    // binds the observation's observed route, and the observation reference is
    // the owner's own self digest.
    assert_eq!(
        produced.route_evidence.requested_route_digest,
        route_fingerprint_digest_for(&admission.requested_route)?
    );
    assert_eq!(
        produced.route_evidence.actual_route_digest,
        Some(route_fingerprint_digest_for(
            observation.observed_route.as_ref().ok_or("matched observation carries a route")?
        )?)
    );
    assert_eq!(
        produced.route_evidence.physical_observation_digest.as_ref(),
        Some(&observation.self_digest)
    );
    assert_eq!(
        produced.route_evidence.admission_digest,
        admission.self_digest
    );
    assert_eq!(
        produced.route_evidence.route_state,
        Some(RouteObservationState::Matched)
    );

    // Consumed by the ordinary path: delivered downstream and projected to
    // coordinator intake carrying the same relation under Verified.
    assert_eq!(outcome.observed.len(), 1);
    let drive = &outcome.observed[0];
    assert_eq!(drive.drive.delivered, vec![1]);
    assert_eq!(drive.intakes.len(), 1);
    assert_eq!(
        drive.intakes[0].route_evidence.as_ref(),
        Some(&produced.route_evidence)
    );
    assert_eq!(
        drive.intakes[0].route_binding_disposition,
        Some(CommittedRouteBindingDisposition::Verified)
    );
    assert!(drive.gaps.is_empty());

    // And counted in the coverage denominator resolved from committed records.
    assert_eq!(outcome.manifest.manifest.counts.received, 1);
    assert_eq!(outcome.manifest.facts.len(), 1);
    assert_eq!(outcome.manifest.facts[0].records.len(), 1);
    assert_eq!(outcome.manifest.facts[0].records[0].sequence, 1);
    Ok(())
}

#[test]
fn run_refuses_foreign_observation_boundary_before_any_mutation() -> TestResult {
    let route = route()?;
    let attempt = AttemptId::new("attempt-2645")?;
    let lease_id = lease("lease-2645")?;
    let fence = fence()?;
    let binding = binding(&attempt, &lease_id, &route, &fence)?;
    let admission = admission(&attempt, &lease_id, &route, &fence)?;
    // Same attempt, binding, admission, fence and generation — but minted for
    // another observation boundary of that execution unit.
    let foreign = observation(&attempt, &route, &fence, &admission, &binding, 7)?;
    let bytes = frame_bytes()?;

    let fingerprint = RunFingerprint {
        product_id: "product-2645".to_owned(),
        session_id: "session-2645".to_owned(),
        attempt_id: "attempt-2645".to_owned(),
        route_fingerprint: route_fingerprint_digest_for(&route)?.to_string(),
    };
    let allowed_manifest_digest = "manifest-2645";
    let events = vec![ExecutionUnitDriverEvent {
        frame: ExecutionUnitFrame {
            stream_id: STREAM,
            stream_sequence: 1,
            event_id: EventId::new("evt-2645-foreign")?,
            cursor: EventCursor::new("unit-cursor-2645")?,
            unit_cursor: EventCursor::new("unit-cursor-2645")?,
            unit_sequence: 1,
            binding: &binding,
            admission: &admission,
            physical_observation: Some(&foreign),
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-source:2645-foreign")?,
            frame_bytes: &bytes,
            payload: NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
                delta_chars: 12,
                truncated: false,
            }),
            predecessors: Vec::new(),
            warnings: Vec::new(),
            observed_at: observed_at(),
        },
        disclosure: ExecutionUnitDisclosure::Admissible,
    }];

    let mut journal = DurableHostEventJournal::new();
    let coverage = coverage_plan();
    let run = CoverageManifestRun {
        stream_ids: &[STREAM],
        manifest_digest: allowed_manifest_digest,
        manifest_revision: "rev-2645",
        declared_tool_names: &[],
        forbidden_tool_names: &[],
        plan: coverage.plan(&fingerprint, allowed_manifest_digest),
    };

    let refused = run_ingest_for_fingerprint(&mut journal, &run, &events, |_| true)
        .expect_err("a receipt from another observation boundary must be refused");
    assert!(
        matches!(
            refused,
            ExecutionUnitRunError::Event(ProducerError::Ingest(IngestError::Contract(
                ContractError::BindingMismatch
            )))
        ),
        "unexpected refusal: {refused:?}"
    );
    // Refused before any mutation: nothing stored, cursor unadvanced, and the
    // denominator therefore never ran.
    assert_eq!(journal.record_count(), 0);
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 0);
    Ok(())
}