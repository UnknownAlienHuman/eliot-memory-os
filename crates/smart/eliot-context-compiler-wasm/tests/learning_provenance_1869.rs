//! Learning provenance guest-transport proof for issue #1869 (round 5).
//!
//! I5.26: adapter normalization does not clear lineage. The guest envelope
//! carries exactly the native [`AdmissionInput`] type, so the intrinsic
//! learning mark (`ContextCandidate.learning`) must survive guest
//! encode/decode verbatim, and stripping it must change the envelope
//! identity. The guest does not verify permits (host Governor evidence
//! cannot enter the guest); verification is the native retrieval gate and
//! host preflight. No `eliot-governor` dependency enters this crate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_compiler_wasm::{
    GUEST_ABI_VERSION, GuestRequest, HANDLER_SUBTYPE, WORLD_NAME, decode_request, encode_request,
    request_digest,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest(byte: u8) -> String {
    char::from(byte).to_string().repeat(64)
}

fn fence() -> StateFence {
    let mut fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            std::num::NonZeroU64::new(3).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(7).expect("generation"),
    );
    fence.task_revision = Some(TaskRevision::new(1).expect("task revision"));
    fence
}

fn binding() -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new("task-1869-a").expect("task"),
        attempt_id: AgentAttemptId::new("attempt-1869").expect("attempt"),
        scope_id: WorkScopeId::new("scope-1869").expect("scope"),
        state_fence: fence(),
        decision_id: DecisionId::new("decision-1869").expect("decision"),
        operation_id: None,
    }
}

fn marked_candidate(context: &ContextBinding, permit_digest: &str) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id("learning-1869"),
        provider_role: ProviderRole {
            provider: ProviderId::new("learning-provider").expect("provider"),
            role: SemanticRole::Optional,
        },
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new("source-learning-1869").expect("source"),
            owner: ProviderId::new("owner-learning-1869").expect("owner"),
            snapshot_id: id("snapshot-learning-1869"),
            revision: "r1".to_owned(),
            content_sha256: digest(b'b'),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: "content-learning-1869".to_owned(),
        },
        learning: Some(LearningProvenance {
            campaign_id: "campaign-1869-a".to_string(),
            overlay_id: Some("overlay-1869-live".to_string()),
            candidate_id: None,
            closure_ref: None,
            owner: None,
            draft: false,
            expires_at_unix_secs: Some(1_800_003_600),
            permit_digest: permit_digest.to_string(),
        }),
        loss_policy: LossPolicy::Summarizable,
        availability: AtomAvailability::PresentCurrent,
        protected: false,
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: digest(b'c'),
            serializer: "json-v1".to_owned(),
        },
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id("evidence-learning-1869"),
            ceiling: ProofCeiling::Observation,
        },
    }
}

/// Minimal envelope shell: encode/decode validates the envelope and the
/// byte ceiling only, so structural (non-admission) fields suffice here.
/// Full admission validity is proven natively; this proves transport.
fn envelope(candidate: ContextCandidate) -> GuestRequest {
    let context = binding();
    let role = ProviderRole {
        provider: ProviderId::new("learning-provider").expect("provider"),
        role: SemanticRole::Optional,
    };
    let denominator = ProviderRoleDenominator {
        requested: vec![role.clone()],
        dispositions: vec![ProviderDisposition {
            slot: role,
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        }],
    };
    let capacity = CapacityLimits {
        route_capacity: 100,
        fixed_overhead: 10,
        output_reserve: 10,
        review_reserve: 10,
    };
    let recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: DecisionRevision {
            decision_id: context.decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("revision"),
            policy_sha256: digest(b'a'),
        },
        recipe_sha256: digest(b'd'),
        denominator: denominator.clone(),
        mandatory_roles: Vec::new(),
        role_policies: Vec::new(),
        capacity,
        predecessor: None,
        invalidation: None,
    };
    GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_string(),
        handler_subtype: HANDLER_SUBTYPE.to_string(),
        input: AdmissionInput {
            schema_version: CONTEXT_CONTRACT_VERSION,
            binding: context.clone(),
            recipe,
            candidates: ContextCandidateSet {
                binding: context.clone(),
                candidates: vec![candidate],
                denominator,
            },
            floor: SafetyFloorIdentity {
                floor_id: id("floor"),
                decision: DecisionRevision {
                    decision_id: context.decision_id.clone(),
                    recipe_revision: TaskRevision::new(1).expect("revision"),
                    policy_sha256: digest(b'a'),
                },
                floor: DecisionSafetyFloor {
                    binding: context.clone(),
                    mandatory_atoms: Vec::new(),
                    mandatory_roles: Vec::new(),
                    providers: ProviderRoleDenominator {
                        requested: Vec::new(),
                        dispositions: Vec::new(),
                    },
                    members: Vec::new(),
                    interpretation_dependencies: Vec::new(),
                    rule_evidence: id("floor-rule"),
                    capacity,
                },
            },
            priority: PriorityPolicyIdentity {
                policy_id: id("priority"),
                decision: DecisionRevision {
                    decision_id: context.decision_id.clone(),
                    recipe_revision: TaskRevision::new(1).expect("revision"),
                    policy_sha256: digest(b'a'),
                },
                priorities: Vec::new(),
            },
            rule: AdmissionRuleIdentity {
                rule_id: id("rule"),
                decision: DecisionRevision {
                    decision_id: context.decision_id.clone(),
                    recipe_revision: TaskRevision::new(1).expect("revision"),
                    policy_sha256: digest(b'a'),
                },
                rule_sha256: digest(b'a'),
            },
            measurement_profile: MeasurementCompositionProfile {
                profile_id: id("profile"),
                schema_version: CONTEXT_CONTRACT_VERSION,
                serializer_id: "json-v1".to_owned(),
                serializer_version: "1".to_owned(),
                serializer_options_digest: digest(b'f'),
                route_id: "route".to_owned(),
                model_id: "model".to_owned(),
                unit: MeasurementUnit::Utf8Bytes,
                aggregation: MeasurementAggregationMode::QualifiedUtf8Contribution,
                qualification: id("qualification"),
                capacity,
            },
            supplied_omissions: Vec::new(),
            measurements: Vec::new(),
        },
    }
}

#[test]
fn learning_mark_survives_guest_envelope() {
    let context = binding();
    let permit_digest = digest(b'd');
    let request = envelope(marked_candidate(&context, &permit_digest));
    let bytes = encode_request(&request).expect("envelope encodes");
    let decoded = decode_request(&bytes).expect("envelope decodes");
    let atom = decoded
        .input
        .candidates
        .candidates
        .iter()
        .find(|candidate| candidate.atom_id == id("learning-1869"))
        .expect("marked atom present");
    let mark = atom.learning.as_ref().expect("mark preserved verbatim");
    assert_eq!(mark.campaign_id, "campaign-1869-a");
    assert_eq!(mark.overlay_id.as_deref(), Some("overlay-1869-live"));
    assert_eq!(mark.permit_digest, permit_digest);
    assert_eq!(
        mark.expires_at_unix_secs,
        Some(1_800_003_600),
        "expiry travels with the mark"
    );
}

#[test]
fn stripping_the_mark_changes_envelope_identity() {
    let context = binding();
    let permit_digest = digest(b'd');
    let marked = envelope(marked_candidate(&context, &permit_digest));
    let mut stripped = marked.clone();
    for candidate in &mut stripped.input.candidates.candidates {
        candidate.learning = None;
    }
    assert_ne!(
        request_digest(&marked),
        request_digest(&stripped),
        "a stripped envelope is a different envelope: reclassification is detectable"
    );
    // And the mark is digest-covered at the atom level too.
    let marked_digest =
        canonical_digest(&marked.input.candidates.candidates[0]).expect("marked digest");
    let stripped_digest =
        canonical_digest(&stripped.input.candidates.candidates[0]).expect("stripped digest");
    assert_ne!(
        marked_digest, stripped_digest,
        "stripping changes atom identity and breaks bound measurements"
    );
}
