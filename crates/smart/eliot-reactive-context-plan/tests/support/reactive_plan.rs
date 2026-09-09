#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

#[path = "../../../eliot-context-contracts/tests/support/reactive.rs"]
pub mod a15;

use eliot_context_contracts::{
    AdmissionDisposition, AdmissionRecord, ReactiveDeliveryMode, SemanticRole,
};
use eliot_contracts::{
    AuthorityEpoch, ClockReading, OperationId, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_cue_contracts::{
    ActivationBounds, ActivationBoundsSpec, ActivationRequest, ActivationRequestSpec,
    ActivationResult, ActivationResultSpec, ActivationStrength, ActivationTrace, CONTRACT_REVISION,
    CanonicalCueId, CanonicalCueIdentity, ComparisonForm, ComparisonKey, ComparisonKeyId,
    CueContext, CueKind, DirectActivation, MatchMode, NormalizationOutcome, NormalizationProfile,
    NormalizedCue, ObservedCue, ObservedCueId, SourceHandle, TargetHandle,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_protocol::{ReactiveContextContentRef, ReactiveContextPrivacy};
use eliot_reactive_context_plan::{
    AttentionDisclosureRule, ReactiveCueActivation, ReactiveDeliveryPolicy, ReactiveTargetBinding,
};
use eliot_receipts::ProofCeiling;
use serde::Serialize;

#[derive(Serialize)]
struct RenderedCanonical<'a> {
    schema_version: eliot_contracts::ContractVersion,
    binding: &'a eliot_context_contracts::ContextBinding,
    recipe_digest: &'a str,
    fence_digest: &'a str,
    rendered: &'a [eliot_context_contracts::RenderedAtom],
}

#[derive(Serialize)]
struct AdmittedCanonical<'a> {
    schema_version: eliot_contracts::ContractVersion,
    binding: &'a eliot_context_contracts::ContextBinding,
    records: &'a [eliot_context_contracts::AdmittedAtom],
}

pub fn fence() -> StateFence {
    StateFence::new(
        AuthorityEpoch::new(1).unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
}

fn digest(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn norm_profile() -> NormalizationProfile {
    NormalizationProfile::new(
        "norm-v1".into(),
        1,
        eliot_cue_contracts::Digest::new(digest(1)).unwrap(),
    )
}

fn provenance() -> Provenance {
    Provenance {
        source_id: SourceId::new("activation-source").unwrap(),
        capture_route: "fixture".into(),
        scope: "scope".into(),
        raw_handle: None,
        revision: Some("r1".into()),
    }
}

fn normalized() -> NormalizedCue {
    let profile = norm_profile();
    let kind = CueKind::Concept;
    let observed = ObservedCue::new(
        CONTRACT_REVISION.into(),
        ObservedCueId::new("observed-atom").unwrap(),
        kind,
        "complete goal".into(),
        SourceHandle::new(
            TargetHandle::new("source").unwrap(),
            eliot_cue_contracts::Digest::new(digest(2)).unwrap(),
            provenance(),
        ),
        CueContext::new(
            TaskId::new("task").unwrap(),
            eliot_receipts::WorkScopeId::new("scope").unwrap(),
            fence(),
            EvidenceEnvelope {
                authority: EvidenceAuthority::SourceIdentity,
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
                status: EpistemicStatus::Observed,
                assertability: Assertability::NonAssertableUnverified,
                provenance: provenance(),
                verification: None,
                state_fence: fence(),
            },
            LifecycleState::Active,
            eliot_cue_contracts::PrivacyClass::Public,
            ProofCeiling::Observation,
        ),
    );
    let canonical = CanonicalCueIdentity::new(
        CanonicalCueId::new("canonical-atom").unwrap(),
        kind,
        "complete goal".into(),
        eliot_cue_contracts::Digest::new(digest(3)).unwrap(),
    );
    let key = ComparisonKey::new(
        ComparisonKeyId::new("key-atom").unwrap(),
        profile.clone(),
        "complete goal".into(),
        MatchMode::Exact,
        ComparisonForm::Exact,
    );
    NormalizedCue::new(
        CONTRACT_REVISION.into(),
        observed,
        profile,
        Some(canonical),
        vec![key],
        NormalizationOutcome::Lossless,
        Vec::new(),
    )
}

pub fn activation() -> ReactiveCueActivation {
    let profile = norm_profile();
    let seed = normalized();
    let bounds = ActivationBounds::new(ActivationBoundsSpec {
        max_depth: 0,
        max_fanout: 0,
        max_results: 8,
        max_nodes: 8,
        max_edges: 0,
        max_work: 32,
        max_path_len: 0,
        max_seeds: 4,
        max_direct: 4,
        max_derived: 0,
        max_trace_steps: 8,
        max_output_bytes: 4096,
        activation_threshold: ActivationStrength(1),
    });
    let request = ActivationRequest::new(ActivationRequestSpec {
        schema_revision: CONTRACT_REVISION.into(),
        request_id: eliot_cue_contracts::ActivationRequestId::new("activation-request").unwrap(),
        seeds: vec![seed.clone()],
        snapshot_id: eliot_cue_contracts::SnapshotId::new("snapshot").unwrap(),
        relation_edges: Vec::new(),
        bounds,
        state_fence: fence(),
        normalization_profile: profile.clone(),
        observed_at: ClockReading::default(),
        deadline_ms: None,
        cancelled: false,
    });
    let result = ActivationResult::new(ActivationResultSpec {
        schema_revision: CONTRACT_REVISION.into(),
        request_id: request.request_id.clone(),
        snapshot_id: request.snapshot_id.clone(),
        normalization_profile: profile,
        state_fence: fence(),
        observed_at: request.observed_at,
        deadline_ms: None,
        cancelled: false,
        direct: vec![DirectActivation::new(
            TargetHandle::new("atom").unwrap(),
            seed.comparison_keys[0].clone(),
            ActivationStrength(1),
        )],
        derived: Vec::new(),
        completeness: eliot_cue_contracts::Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    ReactiveCueActivation {
        request,
        result,
        expected_view_id: Some(a15::id("view")),
        expected_admitted_set_digest: None,
        target_bindings: vec![ReactiveTargetBinding {
            target: TargetHandle::new("atom").unwrap(),
            item_id: a15::id("atom"),
            source_revision: Some("r1".into()),
            source_digest: None,
        }],
    }
}

pub fn session() -> eliot_context_contracts::SessionDeliverySnapshot {
    let mut snapshot = a15::empty_snapshot();
    snapshot.snapshot_digest = snapshot.canonical_digest().unwrap();
    snapshot
}

pub fn delivered_session(
    policy: &ReactiveDeliveryPolicy,
) -> eliot_context_contracts::SessionDeliverySnapshot {
    let (view, payload, event, ack, receipt, assembly, _fixture_profile) = a15::delivered_fixture();
    let atom = view.view.rendered[0].clone();
    let contract = eliot_protocol::reactive_context_contract_identity().unwrap();
    let mut content = a15::content_ref();
    content.contract = contract.clone();
    content.artifact_id = Some(atom.atom_id.clone());
    content.source_revision.clone_from(&atom.source_revision);
    content.content_sha256 =
        eliot_context_contracts::canonical_planning_digest(&atom.representation).unwrap();
    content.byte_length = Some(
        eliot_contracts::canonical_json_bytes(&atom.representation)
            .unwrap()
            .len() as u64,
    );
    let mut source = a15::content_ref();
    source.contract = contract;
    source.artifact_id = Some(atom.source_id.clone());
    source.source_revision.clone_from(&atom.source_revision);
    source.content_sha256.clone_from(&atom.source_digest);
    source.byte_length = None;
    let profile = policy.delivery_profile.clone();
    let closure = eliot_context_contracts::DeliveryEvidenceClosure {
        context_view: view,
        profile: profile.clone(),
        delivery_claim: None,
        delivery_owner_id: None,
        assembly_receipt: assembly,
        payload,
        event,
        acknowledgements: vec![ack],
        receipts: vec![receipt],
        evidence: Vec::new(),
    };
    let mut snapshot = session();
    snapshot
        .records
        .push(eliot_context_contracts::PriorDeliveryBinding {
            record_id: "delivered-record".into(),
            operation_id: policy.operation_id.clone(),
            request_id: policy.request_id.clone(),
            idempotency_key: policy.idempotency_key.clone(),
            item_id: atom.atom_id.to_string(),
            content,
            source,
            profile,
            validity: eliot_protocol::ReactiveContextValidity::Current,
            lifecycle: eliot_protocol::ReactiveContextLifecycleEvidence {
                stage: eliot_protocol::ReactiveContextStage::RecipientReceived,
                predecessor: None,
                owner_receipt: None,
            },
            stage: eliot_protocol::ReactiveContextStage::RecipientReceived,
            acknowledgement_phase: Some(eliot_protocol::AckPhase::Received),
            predecessor_ids: Vec::new(),
            replay_identity: "delivered-replay".into(),
            session_id: snapshot.session_id.clone(),
            runtime_id: snapshot.runtime_id.clone(),
            runtime_generation: snapshot.runtime_generation,
            host_generation: snapshot.host_generation,
            task_id: snapshot.task_id.clone(),
            attempt_id: snapshot.attempt_id.clone(),
            scope_id: snapshot.scope_id.clone(),
            state_fence: snapshot.state_fence.clone(),
            closure: Some(closure),
        });
    snapshot.denominator.observed = 1;
    snapshot.denominator.expected = Some(1);
    snapshot.denominator.completeness = eliot_context_contracts::SnapshotCompleteness::Complete;
    snapshot.snapshot_digest = snapshot.canonical_digest().unwrap();
    snapshot
}

pub fn attention(open: bool) -> eliot_context_contracts::CriticalAttentionProjection {
    let members = if open {
        vec![a15::open_attention()]
    } else {
        Vec::new()
    };
    let mut projection = eliot_context_contracts::CriticalAttentionProjection {
        owner_id: "owner".into(),
        source_revision: "r1".into(),
        snapshot_revision: "r1".into(),
        task_id: a15::task(),
        scope_id: a15::scope(),
        state_fence: a15::fence(),
        members,
        missing_coverage: Vec::new(),
        projection_digest: String::new(),
    };
    projection.projection_digest = projection.canonical_digest().unwrap();
    projection
}

pub fn resolved_attention_projection() -> eliot_context_contracts::CriticalAttentionProjection {
    let mut member = a15::resolved_attention();
    let (_, _, _, _, receipt, _, _) = a15::delivered_fixture();
    let mut core = receipt.core;
    core.authority.authority_owner.clone_from(&member.owner_id);
    core.artifacts.push(eliot_receipts::ArtifactBinding {
        artifact_id: member.attention_id.clone(),
        sha256: member.claim_digest.clone(),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some(member.source_revision.clone()),
    });
    core.artifacts.push(eliot_receipts::ArtifactBinding {
        artifact_id: member.claim_artifact_id.clone(),
        sha256: member.claim_digest.clone(),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some(member.source_revision.clone()),
    });
    member.owner_closure.resolution_receipt =
        Some(eliot_receipts::ReceiptEnvelope::issue(core).unwrap());
    let mut projection = attention(false);
    projection.members = vec![member];
    projection.projection_digest = projection.canonical_digest().unwrap();
    projection
}

pub fn coverage(tool: bool) -> eliot_context_contracts::IntegrationCoverageProfile {
    let mut profile = a15::profile();
    profile.supported_modes = if tool {
        vec![ReactiveDeliveryMode::ToolOnly]
    } else {
        vec![ReactiveDeliveryMode::ObserveOnly]
    };
    if tool {
        let (_, _, _, _, receipt, _, _) = a15::delivered_fixture();
        let mut event = a15::coverage_event();
        event.axis = eliot_context_contracts::CoverageAxis::Enforced;
        event.completeness = eliot_context_contracts::SnapshotCompleteness::Complete;
        event.ordering = "PRE_DISPATCH".into();
        event.freshness = eliot_context_contracts::CoverageFreshness::Fresh;
        event.source.artifact_id = Some(a15::id("profile"));
        let mut evidence = a15::owner_evidence();
        evidence.provenance.raw_handle = Some(event.source.content_sha256.clone());
        evidence.provenance.revision = Some(event.source.source_revision.clone());
        event.evidence = vec![evidence];
        event.claim_digest = event.canonical_claim_digest().unwrap();
        let mut receipt_core = receipt.core;
        event
            .owner_id
            .clone_into(&mut receipt_core.authority.authority_owner);
        receipt_core
            .artifacts
            .push(eliot_receipts::ArtifactBinding {
                artifact_id: event.claim_artifact_id.clone(),
                sha256: event.claim_digest.clone(),
                role: eliot_receipts::ReceiptKind::Artifact,
                source_revision: Some(event.source.source_revision.clone()),
            });
        event.receipts = vec![eliot_receipts::ReceiptEnvelope::issue(receipt_core).unwrap()];
        profile.events = vec![event];
        profile.completeness = eliot_context_contracts::SnapshotCompleteness::Partial;
        profile.gaps = vec!["unobserved integration events".into()];
    }
    if !tool {
        profile.completeness = eliot_context_contracts::SnapshotCompleteness::Unknown;
    }
    profile.profile_digest = profile.canonical_digest().unwrap();
    profile
}

pub fn delivery_profile() -> ReactiveContextContentRef {
    let mut profile = a15::content_ref();
    profile.artifact_id = Some(a15::id("profile"));
    profile
}

pub fn policy(attention_rule: Option<AttentionDisclosureRule>) -> ReactiveDeliveryPolicy {
    let mut policy = ReactiveDeliveryPolicy {
        policy_id: a15::id("policy"),
        policy_revision: 1,
        policy_digest: String::new(),
        request_id: eliot_contracts::RequestId::new("request-1").unwrap(),
        operation_id: OperationId::new("operation-1").unwrap(),
        idempotency_key: "idempotency-1".into(),
        plan_id: a15::id("plan"),
        target_event_id: None,
        target_event: "PreToolUse".into(),
        delivery_profile: delivery_profile(),
        delivery_contract: a15::contract(),
        allowed_modes: vec![ReactiveDeliveryMode::ToolOnly],
        max_input_bytes: 256 * 1024,
        max_items: 256,
        max_references: 512,
        max_work: 256,
        max_delivery_bytes: 256 * 1024,
        max_delivery_stu: Some(100_000),
        fixed_reserve: 1,
        protocol_reserve: 1,
        output_reserve: 1,
        review_reserve: 1,
        delivery_reserve: 1,
        priority: vec![SemanticRole::Goal],
        attention_disclosure: attention_rule.into_iter().collect(),
        tie_break_revision: 1,
        observed_at: ClockReading::default(),
        deadline_ms: None,
        cancelled: false,
    };
    policy.policy_digest = policy.canonical_digest().unwrap();
    policy
}

pub fn open_rule() -> AttentionDisclosureRule {
    let member = a15::open_attention();
    AttentionDisclosureRule {
        attention_id: member.attention_id,
        claim_digest: member.claim_digest,
        minimum_privacy: ReactiveContextPrivacy::Public,
    }
}

pub fn inputs(
    open: bool,
    rule: bool,
) -> (
    eliot_context_contracts::ContextPlanningView,
    ReactiveCueActivation,
    eliot_context_contracts::SessionDeliverySnapshot,
    eliot_context_contracts::CriticalAttentionProjection,
    eliot_context_contracts::IntegrationCoverageProfile,
    ReactiveDeliveryPolicy,
) {
    let (view, admitted, rendered, admitted_bytes) = a15::context_view();
    let context = eliot_context_contracts::ContextPlanningView::new(
        a15::id("view"),
        view,
        admitted,
        rendered,
        admitted_bytes,
    )
    .unwrap();
    let mut activation = activation();
    activation.expected_admitted_set_digest = Some(context.admitted_canonical_sha256.clone());
    (
        context,
        activation,
        session(),
        attention(open),
        coverage(true),
        policy(if rule { Some(open_rule()) } else { None }),
    )
}

/// Rebuild all owner-issued canonical projections after a fixture-only change
/// to the admitted records. The active view is reassembled from the exact
/// admitted records, so its rendered projection, digest, and measurement stay
/// joined to the current source identity.
pub fn reseal_context_view(
    view_id: eliot_contracts::ArtifactId,
    active_seed: &eliot_context_contracts::ActiveUnderstandingView,
    mut admitted: eliot_context_contracts::AdmittedContextSet,
    required_bytes: Option<u64>,
) -> eliot_context_contracts::ContextPlanningView {
    let admitted_payload = AdmittedCanonical {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: &admitted.binding,
        records: &admitted.records,
    };
    let admitted_payload_bytes =
        eliot_contracts::canonical_json_bytes(&admitted_payload).expect("admitted bytes");
    let total_admitted_bytes = admitted_payload_bytes.len() as u64;
    let admitted_required = required_bytes.unwrap_or(total_admitted_bytes);
    let admitted_optional = total_admitted_bytes
        .checked_sub(admitted_required)
        .expect("required fixture bytes cannot exceed total bytes");
    admitted.economy.allocations.admitted_required = admitted_required;
    admitted.economy.allocations.admitted_optional = admitted_optional;
    let reserved = admitted
        .economy
        .allocations
        .fixed_overhead
        .checked_add(admitted.economy.allocations.output_reserve)
        .and_then(|value| value.checked_add(admitted.economy.allocations.review_reserve))
        .expect("fixture reserves");
    admitted.economy.allocations.remaining_headroom = admitted
        .economy
        .allocations
        .route_capacity
        .checked_sub(reserved)
        .and_then(|value| value.checked_sub(admitted_required))
        .and_then(|value| value.checked_sub(admitted_optional))
        .expect("fixture admitted bytes fit route");
    admitted.economy.measurement.digest = admitted
        .canonical_payload_digest()
        .expect("admitted digest");

    let rendered: Vec<_> = admitted
        .records
        .iter()
        .map(eliot_context_contracts::RenderedAtom::from_admitted)
        .collect();
    let rendered_digest =
        eliot_context_contracts::ActiveUnderstandingView::canonical_output_digest(
            &active_seed.binding,
            &active_seed.recipe_digest,
            &active_seed.fence_digest,
            &rendered,
        )
        .expect("rendered digest");
    let rendered_payload = RenderedCanonical {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: &active_seed.binding,
        recipe_digest: &active_seed.recipe_digest,
        fence_digest: &active_seed.fence_digest,
        rendered: &rendered,
    };
    let rendered_payload_bytes =
        eliot_contracts::canonical_json_bytes(&rendered_payload).expect("rendered bytes");
    let mut measurement = active_seed.measurement.clone();
    measurement.envelope_digest.clone_from(&rendered_digest);
    measurement.rendered_utf8_bytes = rendered_payload_bytes.len() as u64;
    let active = eliot_context_contracts::ActiveUnderstandingView::assemble(
        &admitted,
        active_seed.quality.clone(),
        measurement,
        rendered_digest,
        active_seed.recipe_digest.clone(),
        active_seed.fence_digest.clone(),
    )
    .expect("resealed active view");
    let rendered_payload = RenderedCanonical {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: &active.binding,
        recipe_digest: &active.recipe_digest,
        fence_digest: &active.fence_digest,
        rendered: &active.rendered,
    };
    let rendered_bytes =
        eliot_contracts::canonical_json_bytes(&rendered_payload).expect("final rendered bytes");
    let admitted_payload = AdmittedCanonical {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: &admitted.binding,
        records: &admitted.records,
    };
    let admitted_bytes =
        eliot_contracts::canonical_json_bytes(&admitted_payload).expect("final admitted bytes");
    eliot_context_contracts::ContextPlanningView::new(
        view_id,
        active,
        admitted,
        rendered_bytes,
        admitted_bytes,
    )
    .expect("resealed context view")
}

pub fn optional_dependency_inputs() -> (
    eliot_context_contracts::ContextPlanningView,
    ReactiveCueActivation,
    eliot_context_contracts::SessionDeliverySnapshot,
    eliot_context_contracts::CriticalAttentionProjection,
    eliot_context_contracts::IntegrationCoverageProfile,
    ReactiveDeliveryPolicy,
) {
    let (active_seed, mut admitted, _, _) = a15::context_view();
    let baseline_required_bytes = admitted
        .canonical_payload_utf8_bytes()
        .expect("baseline admitted bytes");
    let base = admitted.records[0].clone();
    let b_id = a15::id("optional-b");
    for (name, dependencies) in [
        ("optional-a", vec![b_id.clone()]),
        ("optional-b", Vec::new()),
    ] {
        let mut record = base.clone();
        let atom_id = a15::id(name);
        record.candidate.atom_id = atom_id.clone();
        record.candidate.provider_role.role = SemanticRole::Optional;
        record.candidate.protected = false;
        record.candidate.source.snapshot_id = a15::id(&format!("snapshot-{name}"));
        record.candidate.source.source_id =
            SourceId::new(format!("source-{name}")).expect("fixture source");
        record.candidate.representation = eliot_context_contracts::AtomRepresentation::Whole {
            content: format!("{name} content"),
        };
        record.candidate.dependencies = dependencies;
        record.candidate.proof.evidence_id = a15::id(&format!("evidence-{name}"));
        record.rule_evidence = a15::id(&format!("admission-{name}"));
        admitted.admissions.push(AdmissionRecord {
            atom_id: atom_id.clone(),
            provider_role: record.candidate.provider_role.clone(),
            disposition: AdmissionDisposition::Include,
            rule_evidence: record.rule_evidence.clone(),
        });
        admitted.records.push(record);
        admitted.economy.requested.push(atom_id.clone());
        admitted.economy.admitted.push(atom_id);
    }
    let context = reseal_context_view(
        a15::id("view-options"),
        &active_seed,
        admitted,
        Some(baseline_required_bytes),
    );
    let mut activation = activation();
    activation.target_bindings[0].item_id = a15::id("optional-a");
    activation.target_bindings[0].source_digest = Some(
        context
            .view
            .rendered
            .iter()
            .find(|atom| atom.atom_id == a15::id("optional-a"))
            .expect("optional A")
            .source_digest
            .clone(),
    );
    activation.expected_view_id = Some(context.view_id.clone());
    activation.expected_admitted_set_digest = Some(context.admitted_canonical_sha256.clone());
    (
        context,
        activation,
        session(),
        attention(false),
        coverage(true),
        {
            let mut policy = policy(None);
            policy.max_work = 4096;
            policy.policy_digest = policy.canonical_digest().unwrap();
            policy
        },
    )
}
