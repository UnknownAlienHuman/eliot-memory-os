#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{
    ActiveUnderstandingView, AdmissionDisposition, AdmittedAtom, AdmittedContextSet,
    AtomAvailability, AtomRepresentation, AttentionAcknowledgement, AttentionInfluence,
    AttentionOwnerClosure, AttentionResolution, AuthorityClass, CONTEXT_CONTRACT_VERSION,
    CapacityLimits, ContextBinding, ContextCandidate, ContextEconomyReceipt, CoverageAxis,
    CoverageEvidence, CoverageFreshness, CriticalAttentionMember, DecisionSafetyFloor,
    IntegrationCoverageProfile, LossPolicy, MeasurementRef, MeasurementStatus,
    PriorDeliveryBinding, PrivacyClass, ProofBinding, ProviderDisposition, ProviderId,
    ProviderRole, ProviderRoleDenominator, QualityDimension, QualityDimensionResult,
    QualityScorecard, ReactiveDeliveryMode, SafetyFloorMember, SemanticRole,
    SerializedContextMeasurement, SessionDeliverySnapshot, SnapshotCompleteness,
    SnapshotDenominator, SourceSnapshot,
};
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractIdentity, ContractVersion,
    OperationId, ProductId, RequestId, ResourceGeneration, SessionId, SourceId, StateFence, TaskId,
    TransactionSequence, canonical_json_bytes,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};
use eliot_protocol::reactive_context::{
    ReactiveContextAckDisposition, ReactiveContextAckEvidence, ReactiveContextContentRef,
    ReactiveContextLifecycleEvidence, ReactiveContextPayload, ReactiveContextPrivacy,
    ReactiveContextRecipient, ReactiveContextSafetyFloor, ReactiveContextSequence,
    ReactiveContextStage, ReactiveContextViewBinding, reactive_context_contract_identity,
};
use eliot_protocol::{AckPhase, EventAckReceipt, EventDisposition};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, CoordinationBinding, EffectClass,
    OperationBinding, ProofCeiling, ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind,
    RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding, WorkScopeId,
};

pub fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

pub fn task() -> TaskId {
    TaskId::new("task").expect("fixture task")
}

pub fn scope() -> WorkScopeId {
    WorkScopeId::new("scope").expect("fixture scope")
}

pub fn digest() -> String {
    "a".repeat(64)
}

fn context_binding() -> ContextBinding {
    ContextBinding {
        task_id: task(),
        attempt_id: AgentAttemptId::new("attempt").expect("fixture attempt"),
        scope_id: scope(),
        state_fence: fence(),
        decision_id: eliot_contracts::DecisionId::new("decision").expect("fixture decision"),
        operation_id: None,
    }
}

fn provider_role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("fixture-provider").expect("fixture provider"),
        role: SemanticRole::Goal,
    }
}

fn measurement_ref() -> MeasurementRef {
    MeasurementRef {
        digest: digest(),
        serializer: "fixture-serde-v1".to_owned(),
    }
}

fn candidate() -> ContextCandidate {
    ContextCandidate {
        binding: context_binding(),
        atom_id: id("atom"),
        provider_role: provider_role(),
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new("fixture-source").expect("fixture source"),
            owner: ProviderId::new("fixture-provider").expect("fixture owner"),
            snapshot_id: id("snapshot"),
            revision: "r1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: "complete goal".to_owned(),
        },
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: true,
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: measurement_ref(),
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id("evidence"),
            ceiling: ProofCeiling::Observation,
        },
    }
}

fn quality(binding: &ContextBinding) -> QualityScorecard {
    let dimensions = [
        QualityDimension::AcceptanceDecisionCoverage,
        QualityDimension::CausalOperationalSufficiency,
        QualityDimension::ExactAnchorProvenanceCoverage,
        QualityDimension::FreshnessStateFenceCoherence,
        QualityDimension::RivalsConflictsUnknownsVisibility,
        QualityDimension::NegativeMemoryInvariantCoverage,
        QualityDimension::VerifierActionReadiness,
        QualityDimension::RouteAccessibilityLayoutRisk,
        QualityDimension::InstructionSufficiency,
        QualityDimension::PayloadHandleReconstructionCost,
        QualityDimension::KnownOmissionsExpansionPaths,
        QualityDimension::TelemetryMeasurementCostCoverage,
    ];
    QualityScorecard {
        binding: binding.clone(),
        results: dimensions
            .into_iter()
            .map(|dimension| QualityDimensionResult {
                dimension,
                passed: true,
                evidence: vec![id("quality-evidence")],
                measurements: Vec::new(),
                failed_invariant: None,
                unknown_evidence: Vec::new(),
                proof_ceiling: ProofCeiling::Observation,
                invalidation: None,
                binding: binding.clone(),
            })
            .collect(),
    }
}

fn admitted() -> AdmittedContextSet {
    let candidate = candidate();
    let binding = candidate.binding.clone();
    let atom_id = candidate.atom_id.clone();
    let measurement = candidate.measurement.clone();
    let floor = DecisionSafetyFloor {
        binding: binding.clone(),
        mandatory_atoms: vec![atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: ProviderRoleDenominator {
            requested: vec![provider_role()],
            dispositions: vec![ProviderDisposition {
                slot: provider_role(),
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
        members: vec![SafetyFloorMember {
            atom_id: atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(measurement.clone()),
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: CapacityLimits {
            route_capacity: 100_000,
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
        },
    };
    let mut result = AdmittedContextSet {
        binding: binding.clone(),
        records: vec![AdmittedAtom {
            candidate,
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        admissions: vec![eliot_context_contracts::AdmissionRecord {
            atom_id,
            provider_role: provider_role(),
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        floor,
        economy: ContextEconomyReceipt {
            binding: binding.clone(),
            decision_id: binding.decision_id.clone(),
            measurement: MeasurementRef {
                digest: digest(),
                serializer: "serde-json".to_owned(),
            },
            requested: vec![id("atom")],
            admitted: vec![id("atom")],
            displaced: Vec::new(),
            omissions: Vec::new(),
            applied_rule: id("economy-rule"),
            allocations: eliot_context_contracts::EconomyAllocations {
                fixed_overhead: 2,
                output_reserve: 3,
                review_reserve: 4,
                admitted_required: 1,
                admitted_optional: 0,
                remaining_headroom: 99_990,
                route_capacity: 100_000,
            },
            receipt_digest: digest(),
        },
    };
    let bytes = result
        .canonical_payload_utf8_bytes()
        .expect("admitted bytes");
    result.economy.allocations.admitted_required = bytes;
    result.economy.allocations.remaining_headroom = 100_000 - 2 - 3 - 4 - bytes;
    result.economy.measurement.digest = result.canonical_payload_digest().expect("admitted digest");
    result
}

#[derive(serde::Serialize)]
struct AdmittedCanonical<'a> {
    schema_version: eliot_contracts::ContractVersion,
    binding: &'a ContextBinding,
    records: &'a [AdmittedAtom],
}

#[derive(serde::Serialize)]
struct RenderedCanonical<'a> {
    schema_version: eliot_contracts::ContractVersion,
    binding: &'a ContextBinding,
    recipe_digest: &'a str,
    fence_digest: &'a str,
    rendered: &'a [eliot_context_contracts::RenderedAtom],
}

pub fn fence() -> StateFence {
    StateFence::new(
        AuthorityEpoch::new(1).expect("fixture epoch"),
        ResourceGeneration::new(1).expect("fixture generation"),
    )
}

pub fn contract() -> ContractIdentity {
    ContractIdentity {
        name: ContractId::new("fixture.contract").expect("fixture contract"),
        version: ContractVersion::new(1, 0, 0),
        shape_sha256: digest(),
    }
}

pub fn content_ref() -> ReactiveContextContentRef {
    ReactiveContextContentRef {
        contract: contract(),
        source_revision: "r1".to_owned(),
        content_sha256: digest(),
        byte_length: Some(1),
        artifact_id: Some(id("artifact")),
    }
}

pub fn open_attention() -> CriticalAttentionMember {
    let attention_id = id("attention");
    let mut member = CriticalAttentionMember {
        attention_id: attention_id.clone(),
        claim_artifact_id: id("attention-claim"),
        claim_digest: String::new(),
        kind: "deadline".to_owned(),
        source_revision: "r1".to_owned(),
        source: vec![content_ref()],
        evidence: vec![content_ref()],
        task_id: task(),
        scope_id: scope(),
        owner_id: "owner".to_owned(),
        affected_action_classes: vec!["plan".to_owned()],
        delivery_stage: eliot_protocol::ReactiveContextStage::ValidatedNotEnqueued,
        acknowledgement: AttentionAcknowledgement::Acknowledged,
        influence: AttentionInfluence::Observed,
        resolution: AttentionResolution::Open,
        deadline_unix_ms: Some(1),
        review_ref: None,
        escalation_target: None,
        resolution_condition: "owner review".to_owned(),
        waiver_authority: None,
        superseded_by: None,
        missing_coverage: Vec::new(),
        state_fence: fence(),
        owner_closure: AttentionOwnerClosure {
            owner_id: "owner".to_owned(),
            source_revision: "r1".to_owned(),
            attention_id,
            task_id: task(),
            scope_id: scope(),
            state_fence: fence(),
            source: vec![content_ref()],
            receipts: Vec::new(),
            evidence: Vec::new(),
            resolution_receipt: None,
        },
    };
    member.claim_digest = member
        .canonical_resolution_claim_digest()
        .expect("attention claim digest");
    member
}

pub fn owner_evidence() -> EvidenceEnvelope {
    EvidenceEnvelope {
        authority: EvidenceAuthority::DeterministicRuntimeTest,
        freshness: EvidenceFreshness::ExactCandidate,
        coverage: EvidenceCoverage::CompleteForScope,
        status: EpistemicStatus::Verified,
        assertability: Assertability::Assertable,
        provenance: Provenance {
            source_id: eliot_contracts::SourceId::new("owner-source").expect("fixture source"),
            capture_route: "owner".to_owned(),
            scope: "scope".to_owned(),
            raw_handle: Some("owner-evidence".to_owned()),
            revision: Some("r1".to_owned()),
        },
        verification: Some(eliot_evidence::VerificationBinding {
            contract_id: ContractId::new("fixture.verifier").expect("fixture verifier"),
            run_id: id("verification-run"),
            revision: "r1".to_owned(),
        }),
        state_fence: fence(),
    }
}

pub fn resolved_attention() -> CriticalAttentionMember {
    let mut member = open_attention();
    member.resolution = AttentionResolution::Resolved;
    member.owner_closure.evidence = vec![owner_evidence()];
    if let Some(evidence) = member.owner_closure.evidence.first_mut() {
        evidence.provenance.raw_handle = Some(member.source[0].content_sha256.clone());
    }
    member.claim_digest = member
        .canonical_resolution_claim_digest()
        .expect("resolved attention claim digest");
    member
}

pub fn context_view() -> (
    ActiveUnderstandingView,
    AdmittedContextSet,
    Vec<u8>,
    Vec<u8>,
) {
    let admitted = admitted();
    let binding = admitted.binding.clone();
    let recipe_digest = digest();
    let fence_digest = "b".repeat(64);
    let rendered: Vec<_> = admitted
        .records
        .iter()
        .map(eliot_context_contracts::RenderedAtom::from_admitted)
        .collect();
    let output_digest = ActiveUnderstandingView::canonical_output_digest(
        &binding,
        &recipe_digest,
        &fence_digest,
        &rendered,
    )
    .expect("rendered digest");
    let rendered_bytes = ActiveUnderstandingView::canonical_output_utf8_bytes(
        &binding,
        &recipe_digest,
        &fence_digest,
        &rendered,
    )
    .expect("rendered bytes");
    let measurement = SerializedContextMeasurement {
        measurement_id: id("measurement"),
        context: binding.clone(),
        schema_version: CONTEXT_CONTRACT_VERSION,
        envelope_digest: output_digest.clone(),
        serializer_id: "serde-json".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        rendered_utf8_bytes: rendered_bytes,
        stu_estimate: None,
        tokenizer: None,
        status: MeasurementStatus::ExactUtf8,
        fixed_overhead: 2,
        output_reserve: 3,
        review_reserve: 4,
        false_safe_overflow: None,
        false_rejection_or_decomposition: None,
        valid_until: None,
    };
    let view = ActiveUnderstandingView::assemble(
        &admitted,
        quality(&binding),
        measurement,
        output_digest,
        recipe_digest,
        fence_digest,
    )
    .expect("context view");
    let rendered_bytes = canonical_json_bytes(&RenderedCanonical {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: &view.binding,
        recipe_digest: &view.recipe_digest,
        fence_digest: &view.fence_digest,
        rendered: &view.rendered,
    })
    .expect("rendered canonical bytes");
    let admitted_bytes = canonical_json_bytes(&AdmittedCanonical {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: &admitted.binding,
        records: &admitted.records,
    })
    .expect("admitted canonical bytes");
    (view, admitted, rendered_bytes, admitted_bytes)
}

pub fn coverage_event() -> CoverageEvidence {
    let mut event = CoverageEvidence {
        owner_id: "coverage-owner".to_owned(),
        claim_artifact_id: id("coverage-claim"),
        claim_digest: String::new(),
        event: "PreToolUse".to_owned(),
        host_id: "host".to_owned(),
        runtime_id: "runtime".to_owned(),
        interface_id: "interface".to_owned(),
        contract: contract(),
        recipient_id: "recipient".to_owned(),
        host_generation: ResourceGeneration::new(1).expect("fixture generation"),
        runtime_generation: ResourceGeneration::new(1).expect("fixture generation"),
        recipient_generation: ResourceGeneration::new(1).expect("fixture generation"),
        state_fence: fence(),
        axis: CoverageAxis::Unavailable,
        completeness: SnapshotCompleteness::Partial,
        ordering: "UNKNOWN".to_owned(),
        proof_ceiling: ProofCeiling::Observation,
        freshness: CoverageFreshness::Unknown,
        source: content_ref(),
        gaps: vec!["owner did not expose event".to_owned()],
        receipts: Vec::new(),
        evidence: Vec::new(),
    };
    event.claim_digest = event
        .canonical_claim_digest()
        .expect("coverage claim digest");
    event
}

pub fn profile() -> IntegrationCoverageProfile {
    IntegrationCoverageProfile {
        host_id: "host".to_owned(),
        runtime_id: "runtime".to_owned(),
        interface_id: "interface".to_owned(),
        contract: contract(),
        recipient_id: "recipient".to_owned(),
        host_generation: ResourceGeneration::new(1).expect("fixture generation"),
        runtime_generation: ResourceGeneration::new(1).expect("fixture generation"),
        recipient_generation: ResourceGeneration::new(1).expect("fixture generation"),
        profile_revision: "r1".to_owned(),
        completeness: SnapshotCompleteness::Unknown,
        supported_modes: vec![ReactiveDeliveryMode::ObserveOnly],
        privacy_ceiling: ReactiveContextPrivacy::Public,
        effect_ceiling: EffectClass::Read,
        proof_ceiling: ProofCeiling::Observation,
        state_fence: fence(),
        events: vec![coverage_event()],
        gaps: vec!["historical coverage unavailable".to_owned()],
        profile_digest: String::new(),
    }
}

pub fn empty_snapshot() -> SessionDeliverySnapshot {
    SessionDeliverySnapshot {
        owner_id: "owner".to_owned(),
        source_id: SourceId::new("source").expect("fixture source"),
        source_revision: "r1".to_owned(),
        snapshot_revision: "r1".to_owned(),
        snapshot_digest: String::new(),
        session_id: SessionId::new("session").expect("fixture session"),
        principal_id: "principal".to_owned(),
        recipient_id: "recipient".to_owned(),
        runtime_id: "runtime".to_owned(),
        host_id: "host".to_owned(),
        runtime_generation: ResourceGeneration::new(1).expect("fixture generation"),
        host_generation: ResourceGeneration::new(1).expect("fixture generation"),
        task_id: task(),
        attempt_id: AgentAttemptId::new("attempt").expect("fixture attempt"),
        scope_id: scope(),
        state_fence: fence(),
        denominator: SnapshotDenominator {
            observed: 0,
            expected: None,
            completeness: SnapshotCompleteness::Unknown,
        },
        records: Vec::new(),
    }
}

pub fn unknown_record() -> PriorDeliveryBinding {
    PriorDeliveryBinding {
        record_id: "record-1".to_owned(),
        operation_id: eliot_contracts::OperationId::new("operation-1").expect("fixture operation"),
        request_id: eliot_contracts::RequestId::new("request-1").expect("fixture request"),
        idempotency_key: "idempotency-1".to_owned(),
        item_id: "item-1".to_owned(),
        content: content_ref(),
        source: content_ref(),
        profile: content_ref(),
        validity: eliot_protocol::ReactiveContextValidity::Current,
        lifecycle: eliot_protocol::ReactiveContextLifecycleEvidence {
            stage: eliot_protocol::ReactiveContextStage::UnknownDelivery,
            predecessor: Some(eliot_protocol::ReactiveContextStage::DeliveryAttempted),
            owner_receipt: None,
        },
        stage: eliot_protocol::ReactiveContextStage::UnknownDelivery,
        acknowledgement_phase: None,
        predecessor_ids: Vec::new(),
        replay_identity: "replay-1".to_owned(),
        session_id: SessionId::new("session").expect("fixture session"),
        runtime_id: "runtime".to_owned(),
        runtime_generation: ResourceGeneration::new(1).expect("fixture generation"),
        host_generation: ResourceGeneration::new(1).expect("fixture generation"),
        task_id: task(),
        attempt_id: AgentAttemptId::new("attempt").expect("fixture attempt"),
        scope_id: scope(),
        state_fence: fence(),
        closure: None,
    }
}

fn protocol_content(name: &str) -> ReactiveContextContentRef {
    ReactiveContextContentRef {
        contract: contract(),
        source_revision: "r1".to_owned(),
        content_sha256: digest(),
        byte_length: Some(1),
        artifact_id: Some(id(name)),
    }
}

pub fn delivered_fixture() -> (
    eliot_context_contracts::ContextPlanningView,
    ReactiveContextPayload,
    eliot_protocol::EventEnvelope,
    ReactiveContextAckEvidence,
    ReceiptEnvelope,
    ReceiptEnvelope,
    ReactiveContextContentRef,
) {
    let (view, admitted, rendered_bytes, admitted_bytes) = context_view();
    let retained = eliot_context_contracts::ContextPlanningView::new(
        id("view"),
        view,
        admitted,
        rendered_bytes,
        admitted_bytes,
    )
    .expect("context closure");
    let mut representation = protocol_content("representation");
    representation
        .content_sha256
        .clone_from(&retained.canonical_sha256);
    representation.byte_length = Some(retained.canonical_bytes.len() as u64);
    let mut admitted_ref = protocol_content("admitted");
    admitted_ref
        .content_sha256
        .clone_from(&retained.admitted_canonical_sha256);
    admitted_ref.byte_length = Some(retained.admitted_canonical_bytes.len() as u64);
    let mut recipe = protocol_content("recipe");
    recipe
        .content_sha256
        .clone_from(&retained.view.recipe_digest);
    let assembly = protocol_content("assembly");
    let mut payload = ReactiveContextPayload {
        contract: reactive_context_contract_identity().expect("protocol contract"),
        operation_id: OperationId::new("operation-1").expect("operation"),
        request_id: RequestId::new("request-1").expect("request"),
        idempotency_key: "idempotency-1".to_owned(),
        task_id: task(),
        attempt_id: AgentAttemptId::new("attempt").expect("attempt"),
        producer_generation: ResourceGeneration::new(1).expect("generation"),
        work_scope: WorkScopeBinding {
            scope_id: scope(),
            product_id: ProductId::new("product").expect("product"),
            resource_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence(),
        },
        planner: eliot_protocol::reactive_context::ReactiveContextPlannerBinding {
            request: protocol_content("planner-request"),
            decision: protocol_content("planner-decision"),
            receipt: protocol_content("planner-receipt"),
        },
        recipient: ReactiveContextRecipient {
            session_id: SessionId::new("session").expect("session"),
            runtime_id: "runtime".to_owned(),
            runtime_generation: ResourceGeneration::new(1).expect("generation"),
            route: "route".to_owned(),
        },
        view: ReactiveContextViewBinding {
            view_id: id("view"),
            view_generation: ResourceGeneration::new(1).expect("generation"),
            admitted_set: admitted_ref,
            recipe,
            assembly_receipt: assembly,
            representation,
            measurement: eliot_protocol::reactive_context::ReactiveContextMeasurement {
                serializer: protocol_content("serializer"),
                tokenizer: protocol_content("tokenizer"),
                serialized_byte_length: retained.view.measurement.rendered_utf8_bytes,
                token_count: None,
            },
        },
        safety_floor: ReactiveContextSafetyFloor {
            owner: protocol_content("safety-floor"),
            privacy: ReactiveContextPrivacy::Public,
            disclosure_closure: protocol_content("disclosure"),
            proof_ceiling: ProofCeiling::Observation,
        },
        sequence: ReactiveContextSequence {
            stream_id: "reactive-context/stream".to_owned(),
            sequence: 1,
            predecessor_event_ids: Vec::new(),
            cursor: 1,
        },
        acknowledgement_deadline_unix_ms: 100,
        cancellation_id: "cancel".to_owned(),
        expires_at_unix_ms: Some(200),
        validity: eliot_protocol::reactive_context::ReactiveContextValidity::Current,
    };
    let initial_event = payload.to_event_envelope().expect("event envelope");
    let assembly_receipt = assembly_receipt(&payload, &initial_event, &retained);
    payload
        .view
        .assembly_receipt
        .content_sha256
        .clone_from(&assembly_receipt.identity.canonical_sha256);
    let event = payload.to_event_envelope().expect("event envelope");
    let receipt =
        generic_receipt(&payload, &event, AckPhase::Received, 1, None).expect("ack receipt");
    let ack = ack_evidence(&payload, receipt.clone(), AckPhase::Received).expect("ack evidence");
    let mut delivery_core = receipt.receipt.core;
    delivery_core.artifacts[0]
        .sha256
        .clone_from(&payload.view.representation.content_sha256);
    let receipt_envelope = ReceiptEnvelope::issue(delivery_core).expect("delivery receipt");
    (
        retained,
        payload,
        event,
        ack,
        receipt_envelope,
        assembly_receipt,
        protocol_content("profile"),
    )
}

fn assembly_receipt(
    payload: &ReactiveContextPayload,
    event: &eliot_protocol::EventEnvelope,
    context: &eliot_context_contracts::ContextPlanningView,
) -> ReceiptEnvelope {
    let mut receipt = generic_receipt(payload, event, AckPhase::Received, 1, None)
        .expect("assembly receipt")
        .receipt;
    let mut core = receipt.core;
    core.operation.operation_id = OperationId::new("assembly-operation").expect("operation");
    core.operation.request_id = RequestId::new("assembly-request").expect("request");
    "assembly-idempotency".clone_into(&mut core.operation.idempotency_key);
    core.request.metadata.request_id = core.operation.request_id.clone();
    core.coordination = None;
    core.artifacts.push(ArtifactBinding {
        artifact_id: id("view"),
        sha256: context.canonical_sha256.clone(),
        role: ReceiptKind::Artifact,
        source_revision: Some("r1".to_owned()),
    });
    receipt = ReceiptEnvelope::issue(core).expect("issued assembly receipt");
    receipt
}

fn ack_evidence(
    payload: &ReactiveContextPayload,
    receipt: EventAckReceipt,
    phase: AckPhase,
) -> Result<ReactiveContextAckEvidence, Box<dyn std::error::Error>> {
    Ok(ReactiveContextAckEvidence {
        receipt,
        operation_id: payload.operation_id.clone(),
        task_id: payload.task_id.clone(),
        attempt_id: payload.attempt_id.clone(),
        session_id: payload.recipient.session_id.clone(),
        runtime_id: payload.recipient.runtime_id.clone(),
        runtime_generation: payload.recipient.runtime_generation,
        route: payload.recipient.route.clone(),
        work_scope: payload.work_scope.clone(),
        state_fence: payload.work_scope.state_fence.clone(),
        view_id: payload.view.view_id.clone(),
        view_generation: payload.view.view_generation,
        payload_sha256: payload.payload_sha256()?,
        expected_phase: phase,
        observed_phase: phase,
        owner_ref: protocol_content("ack-owner"),
        issuer_ref: protocol_content("ack-issuer"),
        receive_sequence: payload.sequence.sequence,
        receive_cursor: payload.sequence.cursor,
        observed_at_unix_ms: 50,
        freshness_ref: Some(protocol_content("freshness")),
        disposition: ReactiveContextAckDisposition::Accepted,
        proof_sha256: "2".repeat(64),
        lifecycle: ReactiveContextLifecycleEvidence {
            stage: ReactiveContextStage::RecipientReceived,
            predecessor: None,
            owner_receipt: None,
        },
    })
}

fn generic_receipt(
    payload: &ReactiveContextPayload,
    envelope: &eliot_protocol::EventEnvelope,
    phase: AckPhase,
    receipt_sequence: u64,
    parent_receipt_id: Option<eliot_contracts::ReceiptId>,
) -> Result<EventAckReceipt, Box<dyn std::error::Error>> {
    let fence = payload.work_scope.state_fence.clone();
    let core = ReceiptCore {
        contract: eliot_receipts::contract_identity()?,
        kind: ReceiptKind::Coordination,
        work_scope: payload.work_scope.clone(),
        task: Some(TaskBinding {
            task_id: payload.task_id.clone(),
            task_revision: eliot_contracts::TaskRevision::genesis(),
            state_fence: fence.clone(),
        }),
        session: Some(SessionBinding {
            session_id: payload.recipient.session_id.clone(),
            authority_epoch: fence.authority_epoch,
            state_fence: fence.clone(),
        }),
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::new(receipt_sequence)?,
            parent_receipt_id: parent_receipt_id.clone(),
            predecessor_receipt_ids: parent_receipt_id.into_iter().collect(),
        },
        request: RequestBinding {
            metadata: eliot_contracts::RequestMetadata {
                request_id: payload.request_id.clone(),
                session_id: Some(payload.recipient.session_id.clone()),
                task_id: Some(payload.task_id.clone()),
                product_id: payload.work_scope.product_id.clone(),
                source_id: SourceId::new("source")?,
                state_fence: fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id: payload.operation_id.clone(),
            request_id: payload.request_id.clone(),
            idempotency_key: payload.idempotency_key.clone(),
            operation_kind: "reactive-context".to_owned(),
            effect: EffectClass::Read,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("recipient-authority")?,
            authority_owner: "recipient".to_owned(),
            authority_epoch: fence.authority_epoch,
            state_fence: fence.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::Observation,
        },
        artifacts: vec![
            ArtifactBinding {
                artifact_id: id("representation"),
                sha256: payload.payload_sha256()?,
                role: ReceiptKind::Artifact,
                source_revision: Some("r1".to_owned()),
            },
            ArtifactBinding {
                artifact_id: id("profile"),
                sha256: digest(),
                role: ReceiptKind::Artifact,
                source_revision: Some("r1".to_owned()),
            },
        ],
        verifier: None,
        problem: None,
        coordination: Some(CoordinationBinding {
            event_id: ContractId::new(&envelope.event_id)?,
            idempotency_key: payload.idempotency_key.clone(),
            state_fence: fence.clone(),
        }),
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
    };
    Ok(EventAckReceipt {
        stream_id: envelope.stream_id.clone(),
        event_id: envelope.event_id.clone(),
        phase,
        disposition: EventDisposition::Accepted,
        state_fence: fence,
        receipt: ReceiptEnvelope::issue(core)?,
    })
}
