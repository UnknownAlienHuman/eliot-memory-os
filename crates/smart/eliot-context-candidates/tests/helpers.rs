//! Shared deterministic fixtures for the issue #604 acceptance matrix.
//!
//! Every fixture binds the same task, scope, fence and decision unless a
//! test explicitly varies one axis. Digests and measurements are recomputed
//! from exact bytes, never canned: a tampered fixture fails closed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_candidates::{
    AttentionInput, CANDIDATE_SCHEMA_VERSION, CandidatePolicy, CandidateRequest, CueInput,
    EpistemicInput, EvidenceInput, MemberMeasurement, OpaqueMember, OpaqueProjection,
    PROVIDER_AFFORDANCE, PROVIDER_NEGATIVE_MEMORY, PROVIDER_TASK_FRAME, ProjectionSchema,
    ProjectionState, assurance_member_id, conflict_member_id, derived_member_id, direct_member_id,
    envelope_member_id, epistemic_member_id,
};
use eliot_context_contracts::{
    AtomAvailability, AttentionAcknowledgement, AttentionInfluence, AttentionOwnerClosure,
    AttentionResolution, AuthorityClass, CONTEXT_CONTRACT_VERSION, CapacityLimits, ContextBinding,
    ContextRecipe, CriticalAttentionMember, CriticalAttentionProjection, DecisionRevision,
    LossPolicy, MeasurementRef, PrivacyClass, ProofBinding, ProviderDisposition, ProviderId,
    ProviderRole, ProviderRoleDenominator, RepresentationKind, RoleLossRule, SemanticRole,
    SourceSnapshot,
};
use eliot_contracts::{
    ArtifactId, ContractId, ContractIdentity, ContractVersion, DecisionId, EpochId, EpochLineageId,
    RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision,
    canonical_json_bytes, sha256_hex,
};
use eliot_cue_contracts::{
    ActivationRequestId, ActivationResult, ActivationResultSpec, ActivationStrength,
    ActivationTrace, BoundKind, CONTRACT_REVISION, ComparisonForm, ComparisonKey, ComparisonKeyId,
    Completeness, Digest, DirectActivation, MatchMode, NormalizationProfile, RelationEdgeId,
    SnapshotId, TargetHandle,
};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, ArgumentAcceptability, ClaimId, ConflictKind,
    ConflictLifecycle, ConflictPosition, ConflictSet, ConflictSetParams, CurrentEpistemicPosition,
    Currentness, LineageRootId, PositionId, PositionRevision, SourceRevisionId,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance, VerificationBinding,
};
use eliot_protocol::ReactiveContextStage;
use eliot_protocol::reactive_context::ReactiveContextContentRef;
use eliot_receipts::{ProofCeiling, WorkScopeId};

pub const SERIALIZER: &str = "test-serde-v1";

pub fn digest() -> String {
    "a".repeat(64)
}

pub fn sha(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

pub fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

pub fn task() -> TaskId {
    TaskId::new("task-604").expect("fixture task")
}

pub fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-604").expect("fixture scope")
}

pub fn lineage() -> EpochLineageId {
    EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage")
}

pub fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(lineage(), NonZeroU64::new(1).expect("non-zero")).expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

pub fn fence_rev() -> StateFence {
    let mut fence = fence();
    fence.task_revision = Some(TaskRevision::genesis());
    fence
}

pub fn fence_other() -> StateFence {
    StateFence::new(
        EpochId::new(lineage(), NonZeroU64::new(2).expect("non-zero")).expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

pub fn binding() -> ContextBinding {
    ContextBinding {
        task_id: task(),
        attempt_id: AgentAttemptId::new("attempt-604").expect("fixture attempt"),
        scope_id: scope(),
        state_fence: fence(),
        decision_id: DecisionId::new("decision-604").expect("fixture decision"),
        operation_id: None,
    }
}

pub fn binding_rev() -> ContextBinding {
    let mut binding = binding();
    binding.state_fence = fence_rev();
    binding
}

pub fn request_for(binding: &ContextBinding) -> CandidateRequest {
    CandidateRequest {
        binding: binding.clone(),
        request_id: RequestId::new("request-604").expect("fixture request"),
        idempotency_key: "idem-604".to_owned(),
    }
}

pub fn slots() -> Vec<ProviderRole> {
    eliot_context_candidates::seven_slots().expect("seven slots")
}

fn loss_for(role: SemanticRole) -> (LossPolicy, Vec<RepresentationKind>, bool) {
    match role {
        SemanticRole::Goal
        | SemanticRole::Conflict
        | SemanticRole::Verifier
        | SemanticRole::Negative
        | SemanticRole::Evidence => (
            LossPolicy::NonDroppable,
            vec![RepresentationKind::Whole],
            true,
        ),
        _ => (
            LossPolicy::Extractive,
            vec![RepresentationKind::Whole, RepresentationKind::Extractive],
            false,
        ),
    }
}

pub fn recipe_for(binding: &ContextBinding) -> ContextRecipe {
    let slots = slots();
    let role_policies: Vec<RoleLossRule> = slots
        .iter()
        .map(|slot| {
            let (loss_policy, allowed_representations, required) = loss_for(slot.role);
            RoleLossRule {
                role: slot.role,
                loss_policy,
                required,
                allowed_representations,
            }
        })
        .collect();
    let mandatory_roles: Vec<SemanticRole> = role_policies
        .iter()
        .filter(|rule| rule.required)
        .map(|rule| rule.role)
        .collect();
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: binding.clone(),
        decision: DecisionRevision {
            decision_id: binding.decision_id.clone(),
            recipe_revision: TaskRevision::genesis(),
            policy_sha256: sha("policy-604"),
        },
        recipe_sha256: "0".repeat(64),
        denominator: ProviderRoleDenominator {
            requested: slots.clone(),
            dispositions: slots
                .iter()
                .map(|slot| ProviderDisposition {
                    slot: slot.clone(),
                    state: AtomAvailability::PresentCurrent,
                    evidence: None,
                })
                .collect(),
        },
        mandatory_roles,
        role_policies,
        capacity: CapacityLimits {
            route_capacity: 1_000_000,
            fixed_overhead: 10,
            output_reserve: 20,
            review_reserve: 20,
        },
        predecessor: None,
        invalidation: None,
    };
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
    recipe
}

pub fn policy() -> CandidatePolicy {
    CandidatePolicy {
        bounds: eliot_context_candidates::CandidateBounds::generous(),
        serializer: SERIALIZER.to_owned(),
        cancelled: false,
    }
}

pub fn measurement_for(content: &str) -> MeasurementRef {
    MeasurementRef {
        digest: sha(content),
        serializer: SERIALIZER.to_owned(),
    }
}

pub fn opaque_member(
    id: &str,
    kind: &str,
    content: &str,
    owner: &str,
    protected: bool,
    authority: AuthorityClass,
) -> OpaqueMember {
    let content_sha = sha(content);
    OpaqueMember {
        member_id: aid(id),
        kind: kind.to_owned(),
        content: content.to_owned(),
        source: SourceSnapshot {
            source_id: SourceId::new("fixture-source").expect("fixture source"),
            owner: ProviderId::new(owner).expect("fixture owner"),
            snapshot_id: aid(&format!("{id}-snap")),
            revision: "r1".to_owned(),
            content_sha256: content_sha.clone(),
            predecessor: None,
        },
        measurement: MeasurementRef {
            digest: content_sha,
            serializer: SERIALIZER.to_owned(),
        },
        dependencies: Vec::new(),
        protected,
        privacy: PrivacyClass::Public,
        authority,
        status: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        proof: ProofBinding {
            evidence_id: aid(&format!("{id}-proof")),
            ceiling: ProofCeiling::Observation,
        },
    }
}

pub fn opaque_projection(
    owner: &str,
    binding: &ContextBinding,
    state: ProjectionState,
    members: Vec<OpaqueMember>,
) -> OpaqueProjection {
    OpaqueProjection {
        schema: ProjectionSchema {
            owner: ProviderId::new(owner).expect("fixture owner"),
            schema_version: CANDIDATE_SCHEMA_VERSION,
            source_revision: "r1".to_owned(),
            snapshot_digest: digest(),
        },
        task_id: binding.task_id.clone(),
        scope_id: binding.scope_id.clone(),
        state_fence: binding.state_fence.clone(),
        state,
        members,
        frontier: Vec::new(),
    }
}

pub fn task_frame(binding: &ContextBinding) -> OpaqueProjection {
    opaque_projection(
        PROVIDER_TASK_FRAME,
        binding,
        ProjectionState::Complete,
        vec![opaque_member(
            "task-objective-1",
            "objective",
            "objective: land the probe safely",
            PROVIDER_TASK_FRAME,
            true,
            AuthorityClass::Governing,
        )],
    )
}

pub fn negative_memory(binding: &ContextBinding) -> OpaqueProjection {
    opaque_projection(
        PROVIDER_NEGATIVE_MEMORY,
        binding,
        ProjectionState::Complete,
        vec![opaque_member(
            "negative-trigger-1",
            "trigger",
            "trigger: prior landing burn ran long",
            PROVIDER_NEGATIVE_MEMORY,
            true,
            AuthorityClass::DecisionRelevant,
        )],
    )
}

pub fn affordances(binding: &ContextBinding) -> OpaqueProjection {
    opaque_projection(
        PROVIDER_AFFORDANCE,
        binding,
        ProjectionState::Complete,
        vec![opaque_member(
            "affordance-capability-1",
            "capability",
            "capability: throttle range 10-100",
            PROVIDER_AFFORDANCE,
            false,
            AuthorityClass::Informational,
        )],
    )
}

pub fn content_ref() -> ReactiveContextContentRef {
    ReactiveContextContentRef {
        contract: ContractIdentity {
            name: ContractId::new("fixture.contract").expect("fixture contract"),
            version: ContractVersion::new(1, 0, 0),
            shape_sha256: digest(),
        },
        source_revision: "r1".to_owned(),
        content_sha256: digest(),
        byte_length: Some(1),
        artifact_id: Some(aid("artifact-604")),
    }
}

pub fn attention_member(binding: &ContextBinding) -> CriticalAttentionMember {
    let attention_id = aid("attention-1");
    let mut member = CriticalAttentionMember {
        attention_id: attention_id.clone(),
        claim_artifact_id: aid("attention-claim-1"),
        claim_digest: String::new(),
        kind: "deadline".to_owned(),
        source_revision: "r1".to_owned(),
        source: vec![content_ref()],
        evidence: vec![content_ref()],
        task_id: binding.task_id.clone(),
        scope_id: binding.scope_id.clone(),
        owner_id: "owner-1".to_owned(),
        affected_action_classes: vec!["plan".to_owned()],
        delivery_stage: ReactiveContextStage::ValidatedNotEnqueued,
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
        state_fence: binding.state_fence.clone(),
        owner_closure: AttentionOwnerClosure {
            owner_id: "owner-1".to_owned(),
            source_revision: "r1".to_owned(),
            attention_id,
            task_id: binding.task_id.clone(),
            scope_id: binding.scope_id.clone(),
            state_fence: binding.state_fence.clone(),
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

pub fn attention_input(binding: &ContextBinding) -> AttentionInput {
    attention_input_with(binding, Vec::new())
}

pub fn attention_input_with(
    binding: &ContextBinding,
    conflicts: Vec<ConflictSet>,
) -> AttentionInput {
    let member = attention_member(binding);
    let bytes = canonical_json_bytes(&member).expect("attention bytes");
    AttentionInput {
        projection: {
            let projection = CriticalAttentionProjection {
                owner_id: "owner-1".to_owned(),
                source_revision: "r1".to_owned(),
                snapshot_revision: "snap-1".to_owned(),
                task_id: binding.task_id.clone(),
                scope_id: binding.scope_id.clone(),
                state_fence: binding.state_fence.clone(),
                members: vec![member],
                missing_coverage: Vec::new(),
                projection_digest: String::new(),
            };
            let digest = projection.canonical_digest().expect("projection digest");
            CriticalAttentionProjection {
                projection_digest: digest,
                ..projection
            }
        },
        conflicts,
        measurements: vec![MemberMeasurement {
            member_id: aid("attention-1"),
            measurement: MeasurementRef {
                digest: sha256_hex(&bytes),
                serializer: SERIALIZER.to_owned(),
            },
        }],
    }
}

pub fn source_id(value: &str) -> SourceId {
    SourceId::new(value).expect("fixture source id")
}

pub fn conflict_set(binding: &ContextBinding) -> ConflictSet {
    let first = ConflictPosition::new(
        source_id("source-a"),
        "stance-a",
        BTreeSet::new(),
        BTreeSet::new(),
        false,
    )
    .expect("position");
    let second = ConflictPosition::new(
        source_id("source-b"),
        "stance-b",
        BTreeSet::from(["assumption-1".to_owned()]),
        BTreeSet::from([aid("counter-1")]),
        true,
    )
    .expect("position");
    ConflictSet::new(ConflictSetParams {
        conflict_id: "conflict-1".to_owned(),
        kind: ConflictKind::Epistemic,
        scope: "scope-604".to_owned(),
        task_id: Some(binding.task_id.clone()),
        positions: vec![first, second],
        evidence_refs: BTreeSet::from([aid("evidence-1")]),
        owners: BTreeSet::from([source_id("source-a"), source_id("source-b")]),
        common_lineage: BTreeSet::from([LineageRootId::new("lineage-1").expect("lineage")]),
        resolved_parts: BTreeSet::new(),
        unresolved: BTreeSet::from(["open-question-1".to_owned()]),
        unresolved_owners: BTreeSet::from([source_id("source-b")]),
        acceptability: ArgumentAcceptability::Contested,
        defeated_refs: BTreeSet::new(),
        probe: Some("probe-1".to_owned()),
        decision_owner: source_id("source-a"),
        affected_actions: vec!["action-1".to_owned()],
        lifecycle: ConflictLifecycle::Open,
        receipt_digest: sha("receipt-conflict"),
    })
    .expect("conflict set")
}

pub fn conflict_measurements(conflict: &ConflictSet) -> Vec<MemberMeasurement> {
    conflict
        .positions
        .iter()
        .enumerate()
        .map(|(index, position)| {
            let bytes = canonical_json_bytes(position).expect("position bytes");
            MemberMeasurement {
                member_id: conflict_member_id(&conflict.conflict_id, index)
                    .expect("conflict member id"),
                measurement: MeasurementRef {
                    digest: sha256_hex(&bytes),
                    serializer: SERIALIZER.to_owned(),
                },
            }
        })
        .collect()
}

pub fn epistemic_position(
    binding: &ContextBinding,
    currentness: Currentness,
) -> CurrentEpistemicPosition {
    let admission = AdmittedReceipt::new(AdmittedReceiptParams {
        receipt_id: eliot_contracts::ReceiptId::new("receipt-604").expect("fixture receipt"),
        payload_digest: sha("admission-payload"),
        owner: source_id("owner-1"),
        revision: "r1".to_owned(),
        scope: "scope-604".to_owned(),
        fence: binding.state_fence.clone(),
        evidence_digest: sha("evidence-view"),
        coverage_digest: sha("coverage-view"),
        conflict_digest: sha("conflict-view"),
        proof_digest: sha("proof-view"),
        position: PositionId::new("position-604").expect("fixture position"),
        position_revision: PositionRevision::genesis(),
    })
    .expect("admission");
    let supersession = match currentness {
        Currentness::Current => BTreeSet::new(),
        Currentness::Superseded => BTreeSet::from([aid("successor-1")]),
    };
    CurrentEpistemicPosition::new(
        admission,
        currentness,
        supersession,
        ClaimId::new("claim-604").expect("fixture claim"),
    )
    .expect("position")
}

pub fn epistemic_input(binding: &ContextBinding) -> EpistemicInput {
    epistemic_input_with(binding, Currentness::Current)
}

pub fn epistemic_input_with(binding: &ContextBinding, currentness: Currentness) -> EpistemicInput {
    let position = epistemic_position(binding, currentness);
    let bytes = canonical_json_bytes(&position).expect("position bytes");
    EpistemicInput {
        position,
        measurements: vec![MemberMeasurement {
            member_id: epistemic_member_id(&epistemic_position(binding, currentness))
                .expect("epistemic member id"),
            measurement: MeasurementRef {
                digest: sha256_hex(&bytes),
                serializer: SERIALIZER.to_owned(),
            },
        }],
    }
}

pub fn cue_profile() -> NormalizationProfile {
    NormalizationProfile::new(
        "profile-604".to_owned(),
        1,
        Digest::new(digest()).expect("profile digest"),
    )
}

pub fn direct_activation(profile: &NormalizationProfile) -> DirectActivation {
    DirectActivation::new(
        TargetHandle::new("target-direct-1").expect("fixture target"),
        ComparisonKey::new(
            ComparisonKeyId::new("key-1").expect("fixture key"),
            profile.clone(),
            "folded-value-1".to_owned(),
            MatchMode::Exact,
            ComparisonForm::Exact,
        ),
        ActivationStrength(500),
    )
}

pub fn cue_result(binding: &ContextBinding) -> ActivationResult {
    let profile = cue_profile();
    let result = ActivationResult::new(ActivationResultSpec {
        schema_revision: CONTRACT_REVISION.to_owned(),
        request_id: ActivationRequestId::new("request-604").expect("fixture request"),
        snapshot_id: SnapshotId::new("snapshot-604").expect("fixture snapshot"),
        normalization_profile: profile.clone(),
        state_fence: binding.state_fence.clone(),
        observed_at: eliot_contracts::ClockReading {
            valid_time_ms: Some(100),
            known_time_ms: Some(200),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        deadline_ms: None,
        cancelled: false,
        direct: vec![direct_activation(&profile)],
        derived: Vec::new(),
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    result.validate().expect("cue fixture");
    result
}

pub fn cue_input(binding: &ContextBinding) -> CueInput {
    let result = cue_result(binding);
    let bytes = canonical_json_bytes(&result.direct[0]).expect("direct bytes");
    let member_id = direct_member_id(&result.direct[0].target).expect("direct member id");
    CueInput {
        result,
        measurements: vec![MemberMeasurement {
            member_id,
            measurement: MeasurementRef {
                digest: sha256_hex(&bytes),
                serializer: SERIALIZER.to_owned(),
            },
        }],
    }
}

pub fn derived_cue_input(binding: &ContextBinding) -> CueInput {
    let profile = cue_profile();
    let direct = direct_activation(&profile);
    let derived = eliot_cue_contracts::DerivedActivation::try_new(
        TargetHandle::new("target-derived-1").expect("fixture target"),
        TargetHandle::new("target-direct-1").expect("fixture seed"),
        vec![RelationEdgeId::new("edge-1").expect("fixture edge")],
        ActivationStrength(100),
    )
    .expect("derived");
    let result = ActivationResult::new(ActivationResultSpec {
        schema_revision: CONTRACT_REVISION.to_owned(),
        request_id: ActivationRequestId::new("request-604").expect("fixture request"),
        snapshot_id: SnapshotId::new("snapshot-604").expect("fixture snapshot"),
        normalization_profile: profile,
        state_fence: binding.state_fence.clone(),
        observed_at: eliot_contracts::ClockReading {
            valid_time_ms: Some(100),
            known_time_ms: Some(200),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        deadline_ms: None,
        cancelled: false,
        direct: vec![direct],
        derived: vec![derived],
        completeness: Completeness::Truncated {
            frontier: vec![RelationEdgeId::new("edge-2").expect("fixture edge")],
            bound_hit: BoundKind::Results,
        },
        trace: ActivationTrace::empty(),
    });
    result.validate().expect("derived cue fixture");
    let direct_bytes = canonical_json_bytes(&result.direct[0]).expect("direct bytes");
    let derived_bytes = canonical_json_bytes(&result.derived[0]).expect("derived bytes");
    CueInput {
        result,
        measurements: vec![
            MemberMeasurement {
                member_id: direct_member_id(
                    &TargetHandle::new("target-direct-1").expect("fixture target"),
                )
                .expect("direct member id"),
                measurement: MeasurementRef {
                    digest: sha256_hex(&direct_bytes),
                    serializer: SERIALIZER.to_owned(),
                },
            },
            MemberMeasurement {
                member_id: derived_member_id(
                    &TargetHandle::new("target-derived-1").expect("fixture target"),
                )
                .expect("derived member id"),
                measurement: MeasurementRef {
                    digest: sha256_hex(&derived_bytes),
                    serializer: SERIALIZER.to_owned(),
                },
            },
        ],
    }
}

pub fn envelope(
    binding: &ContextBinding,
    status: EpistemicStatus,
    assertability: Assertability,
) -> EvidenceEnvelope {
    EvidenceEnvelope {
        authority: EvidenceAuthority::DeterministicRuntimeTest,
        freshness: EvidenceFreshness::ExactCandidate,
        coverage: EvidenceCoverage::CompleteForScope,
        status,
        assertability,
        provenance: Provenance {
            source_id: source_id("fixture-source"),
            capture_route: "fixture.route".to_owned(),
            scope: "scope-604".to_owned(),
            raw_handle: Some("eliot://evidence/fixture".to_owned()),
            revision: Some("r1".to_owned()),
        },
        verification: None,
        state_fence: binding.state_fence.clone(),
    }
}

pub fn verified_envelope(binding: &ContextBinding) -> EvidenceEnvelope {
    let mut envelope = envelope(
        binding,
        EpistemicStatus::Verified,
        Assertability::Assertable,
    );
    envelope.verification = Some(VerificationBinding {
        contract_id: ContractId::new("fixture.contract").expect("fixture contract"),
        run_id: aid("run-1"),
        revision: "r1".to_owned(),
    });
    envelope.validate().expect("verified envelope");
    envelope
}

pub fn evidence_input(binding: &ContextBinding) -> EvidenceInput {
    let shown = envelope(
        binding,
        EpistemicStatus::Supported,
        Assertability::NonAssertableUnverified,
    );
    shown.validate().expect("envelope fixture");
    let bytes = canonical_json_bytes(&shown).expect("envelope bytes");
    EvidenceInput {
        envelopes: vec![shown],
        assurances: Vec::new(),
        payloads: Vec::new(),
        measurements: vec![MemberMeasurement {
            member_id: envelope_member_id(&envelope(
                binding,
                EpistemicStatus::Supported,
                Assertability::NonAssertableUnverified,
            ))
            .expect("envelope member id"),
            measurement: MeasurementRef {
                digest: sha256_hex(&bytes),
                serializer: SERIALIZER.to_owned(),
            },
        }],
    }
}

pub fn assurance() -> eliot_epistemic_contracts::SourceAssurance {
    eliot_epistemic_contracts::SourceAssurance::new(
        source_id("assurance-source"),
        SourceRevisionId::new("r1").expect("fixture revision"),
        sha("proof-payload"),
    )
    .expect("assurance")
}

pub fn assurance_measurement(
    item: &eliot_epistemic_contracts::SourceAssurance,
) -> MemberMeasurement {
    let bytes = canonical_json_bytes(item).expect("assurance bytes");
    MemberMeasurement {
        member_id: assurance_member_id(item).expect("assurance member id"),
        measurement: MeasurementRef {
            digest: sha256_hex(&bytes),
            serializer: SERIALIZER.to_owned(),
        },
    }
}

/// One complete default compilation.
pub struct Full {
    pub request: CandidateRequest,
    pub recipe: ContextRecipe,
    pub task: OpaqueProjection,
    pub attention: AttentionInput,
    pub epistemic: EpistemicInput,
    pub cue: CueInput,
    pub negative: OpaqueProjection,
    pub evidence: EvidenceInput,
    pub affordances: OpaqueProjection,
    pub policy: CandidatePolicy,
}

pub fn full(binding: &ContextBinding) -> Full {
    Full {
        request: request_for(binding),
        recipe: recipe_for(binding),
        task: task_frame(binding),
        attention: attention_input(binding),
        epistemic: epistemic_input(binding),
        cue: cue_input(binding),
        negative: negative_memory(binding),
        evidence: evidence_input(binding),
        affordances: affordances(binding),
        policy: policy(),
    }
}

pub fn run(
    fixture: &Full,
) -> Result<
    eliot_context_candidates::ContextCandidateSetResult,
    eliot_context_contracts::ContextError,
> {
    eliot_context_candidates::construct_context_candidates(
        &fixture.request,
        &fixture.recipe,
        &fixture.task,
        Some(&fixture.attention),
        Some(&fixture.epistemic),
        Some(&fixture.cue),
        &fixture.negative,
        Some(&fixture.evidence),
        &fixture.affordances,
        &fixture.policy,
    )
}

pub fn atom_content(
    result: &eliot_context_candidates::ContextCandidateSetResult,
    atom_id: &str,
) -> String {
    match &result
        .set
        .candidates
        .iter()
        .find(|candidate| candidate.atom_id.as_str() == atom_id)
        .expect("atom present")
        .representation
    {
        eliot_context_contracts::AtomRepresentation::Whole { content } => content.clone(),
        other => panic!("expected whole atom, found {other:?}"),
    }
}

/// Exact total content bytes across every supplied member of a fixture:
/// opaque and payload bytes plus canonical bytes of every bound value.
pub fn full_member_bytes(fixture: &Full) -> usize {
    let mut total = 0_usize;
    for member in fixture
        .task
        .members
        .iter()
        .chain(fixture.negative.members.iter())
        .chain(fixture.affordances.members.iter())
        .chain(fixture.evidence.payloads.iter())
    {
        total = total.saturating_add(member.content.len());
    }
    for member in &fixture.attention.projection.members {
        total = total.saturating_add(canonical_json_bytes(member).expect("bytes").len());
    }
    for conflict in &fixture.attention.conflicts {
        for position in &conflict.positions {
            total = total.saturating_add(canonical_json_bytes(position).expect("bytes").len());
        }
    }
    total = total.saturating_add(
        canonical_json_bytes(&fixture.epistemic.position)
            .expect("bytes")
            .len(),
    );
    for direct in &fixture.cue.result.direct {
        total = total.saturating_add(canonical_json_bytes(direct).expect("bytes").len());
    }
    for derived in &fixture.cue.result.derived {
        total = total.saturating_add(canonical_json_bytes(derived).expect("bytes").len());
    }
    for shown in &fixture.evidence.envelopes {
        total = total.saturating_add(canonical_json_bytes(shown).expect("bytes").len());
    }
    for item in &fixture.evidence.assurances {
        total = total.saturating_add(canonical_json_bytes(item).expect("bytes").len());
    }
    total
}
