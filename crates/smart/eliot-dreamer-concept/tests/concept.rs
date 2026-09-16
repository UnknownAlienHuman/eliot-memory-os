#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
    TaskId,
};
use eliot_dreamer_concept::{
    ConceptPolicy, HANDLER_ID, handler_port, propose_concept_or_abstraction,
};
use eliot_dreamer_contracts::{
    AtomicityMode, BudgetUsage, BundleCompleteness, BundleMaterial, CURATION_WIRE_KINDS,
    CandidateDisposition, ClaimResidue, ConceptApplicability, ConceptCase, ConceptCaseKind,
    ConceptCoverage, ConceptCriterion, ConceptCriterionRole, ConceptDependency,
    ConceptDiscriminator, ConceptDisposition, ConceptEvidence, ConceptInput, ConceptMode,
    ConceptNeighborhood, ConceptParameter, ConceptProposal, ConceptSnapshot,
    ConceptSourceDenominator, ConceptSourceRef, ConceptSourceSet, ConceptVerifierRef,
    ContractViolation, CurationAcceptanceCtx, CurationFamily, CurationKind, CurationPayload,
    DreamInputBundle, DreamJobInput, GroundedDreamDraft, JobClass, NamedEvidence,
    RelationPreservation, RelationPreservationDimension, RelationPreservationVerdict, Requester,
    RequesterOrigin, ScreenBinding, ScreenState, SupportState, TargetDenominator,
    TypedCurationHandlerRequest, ValidatedCurationItem, ValidationReceipt, canonical_bytes,
    concept_proposal_digest, digest_hex, family_of, parse_kind,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};
use std::num::NonZeroU64;

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("artifact id")
}

fn preservation() -> RelationPreservation {
    RelationPreservation {
        verdicts: RelationPreservationDimension::all()
            .iter()
            .copied()
            .map(|dimension| RelationPreservationVerdict {
                dimension,
                passed: true,
                known: true,
                note: "fixture".to_owned(),
            })
            .collect(),
    }
}

fn concept_evidence() -> ConceptEvidence {
    ConceptEvidence {
        named: NamedEvidence {
            id: aid("evidence-1"),
            foundation_evidence_envelope: EvidenceEnvelope {
                authority: EvidenceAuthority::DeterministicRuntimeTest,
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
                status: EpistemicStatus::Supported,
                assertability: Assertability::Assertable,
                provenance: Provenance {
                    source_id: SourceId::new("source-1").expect("source id"),
                    capture_route: "fixture".to_owned(),
                    scope: "scope-1".to_owned(),
                    raw_handle: Some("source-1".to_owned()),
                    revision: Some("source-rev".to_owned()),
                },
                verification: None,
                state_fence: fence(),
            },
            source_handles: vec![aid("source-1")],
            dependence_groups: vec!["group-1".to_owned()],
            external_grade: None,
        },
        source_refs: vec![aid("source-1")],
        freshness: EvidenceFreshness::ExactCandidate,
    }
}

fn proposal(mode: ConceptMode, policy_digest: String) -> ConceptProposal {
    let evidence_refs = vec![aid("evidence-1")];
    ConceptProposal {
        schema_version: 1,
        concept_id: aid("concept-1"),
        mode,
        name: "cache".to_owned(),
        definition: "retained result".to_owned(),
        criteria: vec![ConceptCriterion {
            criterion_id: aid("criterion-1"),
            role: ConceptCriterionRole::Necessary,
            applicability: eliot_dreamer_contracts::CriterionApplicability::Required,
            status: eliot_dreamer_contracts::CriterionStatus::Supported,
            statement: "retains a reusable result".to_owned(),
            evidence_refs: evidence_refs.clone(),
            exception_refs: Vec::new(),
        }],
        applicability: ConceptApplicability {
            domain: "software".to_owned(),
            population: "results".to_owned(),
            role: "concept".to_owned(),
            environment: "test".to_owned(),
            time: "current".to_owned(),
            version: "v1".to_owned(),
            parameters: vec![ConceptParameter {
                name: "mode".to_owned(),
                value: "bounded".to_owned(),
            }],
            exclusions: vec!["unbounded state".to_owned()],
            source_refs: vec![aid("source-1")],
        },
        cases: vec![ConceptCase {
            case_id: aid("case-1"),
            kind: ConceptCaseKind::Positive,
            source_ref: aid("source-1"),
            evidence_refs: evidence_refs.clone(),
            note: "retained example".to_owned(),
        }],
        case_expected_total: 1,
        case_omitted_refs: Vec::new(),
        case_coverage: ConceptCoverage::Complete,
        evidence: vec![concept_evidence()],
        rivals: Vec::new(),
        discriminator: ConceptDiscriminator {
            alternative_id: None,
            predicted_distinction: "keeps the boundary".to_owned(),
            falsification_condition: "a retained source violates the boundary".to_owned(),
            evidence_refs,
            verifier: ConceptVerifierRef {
                verifier_id: aid("source-1"),
                revision: "source-rev".to_owned(),
                digest: digest(b's'),
            },
        },
        dependencies: vec![ConceptDependency {
            dependency_id: aid("dependency-1"),
            revision: "dependency-rev".to_owned(),
            content_digest: digest(b'd'),
            source_refs: vec![aid("source-1")],
        }],
        source_refs: vec![aid("source-1")],
        policy_digest,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        preservation: preservation(),
    }
}

struct Fixture {
    input: ConceptInput,
    context: CurationAcceptanceCtx<'static>,
}

fn fixture_job() -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "op-1".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "concept-contract".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: eliot_dreamer_contracts::BudgetLimits {
            input_bytes: Some(1_048_576),
            output_bytes: Some(1_048_576),
            source_width: Some(16),
            reference_width: Some(32),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(10_000),
            work_fan_out: Some(2),
            report_bytes: Some(1_048_576),
            max_stu: Some(10),
        },
        deadline_ms: None,
        frozen_manifest_digest: digest(b'm'),
    }
}

fn fixture_source() -> ConceptSourceRef {
    ConceptSourceRef {
        source_id: aid("source-1"),
        source_revision: "source-rev".to_owned(),
        content_digest: digest(b's'),
        admission: ReceiptIdentity {
            receipt_id: ReceiptId::new("admission-1").expect("receipt"),
            canonical_sha256: digest(b'a'),
        },
        task_id: TaskId::new("task-1").expect("task"),
        scope_id: WorkScopeId::new("scope-1").expect("scope"),
        state_fence: fence(),
        freshness: EvidenceFreshness::ExactCandidate,
    }
}

fn fixture_receipt(job: &DreamJobInput) -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05".to_owned(),
        validator_policy: "policy".to_owned(),
        job_id: "job-1".to_owned(),
        draft_digest: digest(b'g'),
        bundle_digest: digest(b'b'),
        manifest_digest: job.frozen_manifest_digest.clone(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: digest(b'i'),
        output_digest: digest(b'o'),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: digest(b'r'),
        budget_digest: digest(b'u'),
    }
}

fn fixture_bundle(input: &ConceptInput) -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        manifest_digest: input.job.frozen_manifest_digest.clone(),
        materials: vec![
            BundleMaterial {
                handle: "source-1".to_owned(),
                disposition: eliot_dreamer_contracts::SourceDisposition::Required,
                bytes: 1,
                digest: digest(b's'),
            },
            BundleMaterial {
                handle: "evidence-1".to_owned(),
                disposition: eliot_dreamer_contracts::SourceDisposition::Required,
                bytes: 1,
                digest: digest(b'e'),
            },
        ],
        omissions: Vec::new(),
        completeness: BundleCompleteness::CompleteForScope,
        authoritative_denominator: Some("source-1,evidence-1".to_owned()),
    }
}

fn fixture_grounded(receipt: &ValidationReceipt) -> GroundedDreamDraft {
    GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        draft_digest: receipt.draft_digest.clone(),
        residues: vec![ClaimResidue {
            claim: "cache".to_owned(),
            state: SupportState::Partial,
            detail: "bounded".to_owned(),
        }],
        coverage_note: "fixture coverage".to_owned(),
    }
}

fn fixture_payload() -> CurationPayload {
    CurationPayload::Concept(eliot_dreamer_contracts::curation::ConceptPayload {
        concept: "cache".to_owned(),
        definition: "retained result".to_owned(),
        target_evidence: eliot_dreamer_contracts::curation::TargetEvidence {
            targets: vec!["source-1".to_owned()],
            evidence_refs: vec!["evidence-1".to_owned()],
        },
    })
}

fn fixture_denominator() -> TargetDenominator {
    TargetDenominator {
        mode: AtomicityMode::PerMember,
        members: vec!["source-1".to_owned()],
        expected_total: 1,
    }
}

fn fixture_screen(item_digest: String) -> ScreenBinding {
    ScreenBinding {
        request_id: eliot_contracts::RequestId::new("request-1").expect("request"),
        receipt_id: ReceiptId::new("screen-receipt-1").expect("receipt"),
        screened_targets: vec!["source-1".to_owned()],
        source_snapshot: "screen-snapshot".to_owned(),
        source_revision: "screen-rev".to_owned(),
        profile: "concept-profile".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: digest(b'k'),
        item_digest,
    }
}

fn fixture_request(
    payload: CurationPayload,
    denominator: TargetDenominator,
    screen: &ScreenBinding,
) -> TypedCurationHandlerRequest {
    TypedCurationHandlerRequest {
        request_id: "request-1".to_owned(),
        receipt_id: "screen-receipt-1".to_owned(),
        source_snapshot: screen.source_snapshot.clone(),
        source_revision: screen.source_revision.clone(),
        profile: screen.profile.clone(),
        kind: CurationKind::Concept,
        family: CurationFamily::Concept,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        payload,
        denominator,
        screen_binding: Some(screen.clone()),
    }
}

fn fixture_item(
    receipt: &ValidationReceipt,
    grounded: &GroundedDreamDraft,
    job: &DreamJobInput,
    source: &ConceptSourceRef,
    payload: &CurationPayload,
    denominator: &TargetDenominator,
) -> (ValidatedCurationItem, ScreenBinding) {
    let item = ValidatedCurationItem {
        receipt: receipt.clone(),
        kind_spelling: "concept".to_owned(),
        family_spelling: "concept".to_owned(),
        payload: payload.clone(),
        denominator: denominator.clone(),
        source_digest: source.content_digest.clone(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        job_digest: digest_hex(&canonical_bytes(job).expect("job bytes")),
        requester: job.requester.clone(),
        budget_note: "bounded".to_owned(),
    };
    let item_digest = item.item_digest(grounded).expect("item digest");
    (item, fixture_screen(item_digest))
}

fn fixture_neighborhood(proposal: &ConceptProposal) -> ConceptNeighborhood {
    ConceptNeighborhood {
        expected_total: 1,
        concepts: vec![ConceptSnapshot {
            concept_id: proposal.concept_id.clone(),
            proposal: Box::new(proposal.clone()),
            revision: "existing-rev".to_owned(),
            content_digest: concept_proposal_digest(proposal).expect("snapshot digest"),
            scope_id: WorkScopeId::new("scope-1").expect("scope"),
            state_fence: fence(),
            source_refs: vec![aid("source-1")],
            evidence_refs: vec![aid("evidence-1")],
        }],
        omitted_refs: Vec::new(),
        coverage: ConceptCoverage::Complete,
    }
}

fn fixture(policy_digest: String, mode: ConceptMode) -> Fixture {
    let job = fixture_job();
    let source = fixture_source();
    let receipt = fixture_receipt(&job);
    let grounded = fixture_grounded(&receipt);
    let payload = fixture_payload();
    let denominator = fixture_denominator();
    let (item, screen) = fixture_item(&receipt, &grounded, &job, &source, &payload, &denominator);
    let request = fixture_request(payload, denominator, &screen);
    let proposal = proposal(mode, policy_digest.clone());
    let neighborhood = fixture_neighborhood(&proposal);
    let input = ConceptInput {
        schema_version: 1,
        operation_id: aid("op-1"),
        request_id: "request-1".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        policy_digest,
        job,
        item,
        request: request.clone(),
        sources: ConceptSourceSet {
            sources: vec![source],
            denominator: ConceptSourceDenominator {
                expected_total: 1,
                processed: vec![aid("source-1")],
                omitted: Vec::new(),
                coverage: ConceptCoverage::Complete,
            },
        },
        proposal,
        neighborhood,
        screen: screen.clone(),
        preservation: preservation(),
    };
    let bundle = fixture_bundle(&input);
    let usage = BudgetUsage::default();
    let context = CurationAcceptanceCtx {
        job: Box::leak(Box::new(input.job.clone())),
        bundle: Box::leak(Box::new(bundle)),
        receipt: Box::leak(Box::new(receipt)),
        screen: Box::leak(Box::new(screen)),
        grounded: Box::leak(Box::new(grounded)),
        request: Box::leak(Box::new(request)),
        usage: Box::leak(Box::new(usage)),
    };
    Fixture { input, context }
}

#[test]
fn accepted_scoped_concept_and_abstraction_paths_emit_bound_candidates() {
    for mode in [ConceptMode::Concept, ConceptMode::Abstraction] {
        let mut policy = ConceptPolicy::new("policy");
        policy.seal().expect("policy seals");
        let mut fixture = fixture(policy.digest.clone(), mode);
        fixture.input.proposal.concept_id = aid("concept-fresh");
        fixture.input.neighborhood = ConceptNeighborhood {
            expected_total: 0,
            concepts: Vec::new(),
            omitted_refs: Vec::new(),
            coverage: ConceptCoverage::Complete,
        };
        let candidate = propose_concept_or_abstraction(&fixture.input, &fixture.context, &policy)
            .expect("accepted typed closure emits candidate");
        assert_eq!(candidate.mode, mode);
        assert_eq!(candidate.policy_digest, policy.digest);
        assert_eq!(
            candidate.disposition,
            eliot_dreamer_contracts::ConceptDisposition::Hypothesis
        );
        assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
        assert_eq!(candidate.handler_result.kind, CurationKind::Concept);
        assert_eq!(candidate.handler_result.family, CurationFamily::Concept);
        assert!(candidate.validate_against(&fixture.input).is_ok());
    }
}

#[test]
fn exact_duplicate_is_explicit_and_replay_is_deterministic() {
    for mode in [ConceptMode::Concept, ConceptMode::Abstraction] {
        let mut policy = ConceptPolicy::new("policy");
        policy.seal().expect("policy seals");
        let mut base = fixture(policy.digest.clone(), mode);
        base.input.proposal.cases[0].kind = ConceptCaseKind::Counterexample;
        let snapshot = &mut base.input.neighborhood.concepts[0];
        snapshot.proposal.cases[0].kind = ConceptCaseKind::Counterexample;
        snapshot.content_digest =
            concept_proposal_digest(&snapshot.proposal).expect("counterexample snapshot digest");
        let first = propose_concept_or_abstraction(&base.input, &base.context, &policy)
            .expect("first replay succeeds");
        let second = propose_concept_or_abstraction(&base.input, &base.context, &policy)
            .expect("second replay succeeds");
        assert_eq!(first, second);
        assert_eq!(
            first.disposition,
            eliot_dreamer_contracts::ConceptDisposition::Duplicate
        );
        assert_eq!(
            first.common_disposition,
            eliot_dreamer_contracts::CandidateDisposition::Duplicate
        );
        assert_eq!(
            first.proposal.cases[0].kind,
            ConceptCaseKind::Counterexample
        );
    }
}

#[test]
fn partial_neighborhood_stays_a_hypothesis() {
    let mut policy = ConceptPolicy::new("policy");
    policy.seal().expect("policy seals");
    let mut partial = fixture(policy.digest.clone(), ConceptMode::Concept);
    partial.input.proposal.concept_id = aid("concept-2");
    partial.input.proposal.cases[0].kind = ConceptCaseKind::Counterexample;
    partial.input.neighborhood.coverage = ConceptCoverage::Partial;
    let result = propose_concept_or_abstraction(&partial.input, &partial.context, &policy)
        .expect("partial neighborhood remains a candidate assertion");
    assert_eq!(
        result.disposition,
        eliot_dreamer_contracts::ConceptDisposition::Hypothesis
    );
    assert_eq!(
        result.common_disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
    assert_eq!(
        result.proposal.cases[0].kind,
        ConceptCaseKind::Counterexample
    );
}

#[test]
fn safe_narrowing_retains_predecessor_and_scope() {
    let mut policy = ConceptPolicy::new("policy");
    policy.seal().expect("policy seals");
    let mut refinement = fixture(policy.digest.clone(), ConceptMode::Concept);
    refinement.input.proposal.concept_id = aid("concept-2");
    refinement
        .input
        .proposal
        .applicability
        .exclusions
        .push("new boundary excludes unbounded state".to_owned());
    refinement.input.proposal.criteria.push(ConceptCriterion {
        criterion_id: aid("criterion-2"),
        role: ConceptCriterionRole::Exclusion,
        applicability: eliot_dreamer_contracts::CriterionApplicability::Required,
        status: eliot_dreamer_contracts::CriterionStatus::Supported,
        statement: "new boundary excludes unbounded state".to_owned(),
        evidence_refs: vec![aid("evidence-1")],
        exception_refs: Vec::new(),
    });
    refinement
        .input
        .proposal
        .applicability
        .exclusions
        .swap(0, 1);
    let first = propose_concept_or_abstraction(&refinement.input, &refinement.context, &policy)
        .expect("one safe narrowing predecessor remains a hypothesis");
    assert_eq!(
        first.disposition,
        eliot_dreamer_contracts::ConceptDisposition::Hypothesis
    );
    assert_eq!(first.rollback.predecessor, Some(aid("concept-1")));
    let mut second = refinement.input.neighborhood.concepts[0].clone();
    second.concept_id = aid("concept-3");
    second.proposal.concept_id = aid("concept-3");
    second.content_digest =
        concept_proposal_digest(&second.proposal).expect("second predecessor digest");
    refinement.input.neighborhood.expected_total = 2;
    refinement.input.neighborhood.concepts.push(second);
    let result = propose_concept_or_abstraction(&refinement.input, &refinement.context, &policy)
        .expect("ambiguous narrowing remains bounded");
    assert_eq!(
        result.disposition,
        eliot_dreamer_contracts::ConceptDisposition::Ambiguity
    );
    assert_eq!(result.rollback.predecessor, None);
    assert_eq!(result.rollback.history_refs.len(), 2);
    assert_eq!(result.proposal.cases[0].kind, ConceptCaseKind::Positive);
}

#[test]
fn unsupported_criterion_or_budget_is_refused() {
    let mut policy = ConceptPolicy::new("policy");
    policy.seal().expect("policy seals");
    let mut unknown = fixture(policy.digest.clone(), ConceptMode::Concept);
    unknown.input.proposal.concept_id = aid("concept-2");
    unknown.input.proposal.criteria[0].status = eliot_dreamer_contracts::CriterionStatus::Unknown;
    let unknown_result = propose_concept_or_abstraction(&unknown.input, &unknown.context, &policy)
        .expect("unknown evidence remains a candidate assertion");
    assert_eq!(
        unknown_result.disposition,
        eliot_dreamer_contracts::ConceptDisposition::Insufficient
    );

    let mut bounded = ConceptPolicy::new("policy");
    bounded.max_work = 1;
    bounded.seal().expect("bounded policy seals");
    let budgeted = fixture(bounded.digest.clone(), ConceptMode::Concept);
    assert!(propose_concept_or_abstraction(&budgeted.input, &budgeted.context, &bounded).is_err());
}

// ---- 659 proof helpers (additive; the five tests above are unchanged) ----

fn sealed_policy(policy_id: &str) -> ConceptPolicy {
    let mut policy = ConceptPolicy::new(policy_id);
    policy.seal().expect("policy seals");
    policy
}

/// Baseline scoped input: fresh identity with a complete empty neighborhood.
fn scoped(mode: ConceptMode) -> (Fixture, ConceptPolicy) {
    let policy = sealed_policy("policy");
    let mut fx = fixture(policy.digest.clone(), mode);
    fx.input.proposal.concept_id = aid("concept-fresh");
    fx.input.neighborhood = ConceptNeighborhood {
        expected_total: 0,
        concepts: Vec::new(),
        omitted_refs: Vec::new(),
        coverage: ConceptCoverage::Complete,
    };
    (fx, policy)
}

fn second_evidence(id: &str, group: &str) -> ConceptEvidence {
    let mut evidence = concept_evidence();
    evidence.named.id = aid(id);
    evidence.named.dependence_groups = vec![group.to_owned()];
    evidence
}

fn fence_seq2() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
        NonZeroU64::new(2).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn set_payload_definition(input: &mut ConceptInput, definition: &str) {
    for payload in [&mut input.item.payload, &mut input.request.payload] {
        if let CurationPayload::Concept(concept) = payload {
            definition.clone_into(&mut concept.definition);
        }
    }
}

/// Rebuilds the acceptance context after an intentional payload/text edit so
/// the refusal or disposition under test is semantic rather than a stale bind.
fn recontext(fx: &mut Fixture) {
    let job = fx.input.job.clone();
    let receipt = fx.input.item.receipt.clone();
    let grounded = fixture_grounded(&receipt);
    let source = fx.input.sources.sources[0].clone();
    let payload = fx.input.item.payload.clone();
    let denominator = fx.input.item.denominator.clone();
    let (_item, screen) = fixture_item(&receipt, &grounded, &job, &source, &payload, &denominator);
    let request = fixture_request(payload, denominator, &screen);
    let bundle = fixture_bundle(&fx.input);
    fx.input.request = request.clone();
    fx.input.screen = screen.clone();
    fx.context.job = Box::leak(Box::new(job));
    fx.context.bundle = Box::leak(Box::new(bundle));
    fx.context.receipt = Box::leak(Box::new(receipt));
    fx.context.screen = Box::leak(Box::new(screen));
    fx.context.grounded = Box::leak(Box::new(grounded));
    fx.context.request = Box::leak(Box::new(request));
}

fn narrowed(input: &mut ConceptInput) {
    input.proposal.concept_id = aid("concept-2");
    input
        .proposal
        .applicability
        .exclusions
        .push("new boundary excludes unbounded state".to_owned());
    input.proposal.criteria.push(ConceptCriterion {
        criterion_id: aid("criterion-2"),
        role: ConceptCriterionRole::Exclusion,
        applicability: eliot_dreamer_contracts::CriterionApplicability::Required,
        status: eliot_dreamer_contracts::CriterionStatus::Supported,
        statement: "new boundary excludes unbounded state".to_owned(),
        evidence_refs: vec![aid("evidence-1")],
        exception_refs: Vec::new(),
    });
}

// WORK_UNIT_CASE: 659/1
#[test]
fn case_01_valid_concept_candidate() {
    let (fx, policy) = scoped(ConceptMode::Concept);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("valid Concept proposal emits a scoped candidate");
    assert_eq!(candidate.mode, ConceptMode::Concept);
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_eq!(candidate.handler_result.kind, CurationKind::Concept);
    assert_eq!(candidate.handler_result.family, CurationFamily::Concept);
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert_eq!(candidate.policy_digest, policy.digest);
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/2
#[test]
fn case_02_valid_bounded_abstraction_candidate() {
    let (fx, policy) = scoped(ConceptMode::Abstraction);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("valid Abstraction proposal emits a scoped candidate");
    assert_eq!(candidate.mode, ConceptMode::Abstraction);
    assert_eq!(candidate.handler_result.kind, CurationKind::Concept);
    assert_eq!(candidate.handler_result.family, CurationFamily::Concept);
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/3
#[test]
fn case_03_exactly_concept_wire_kind_no_global_abstraction() {
    assert_eq!(CURATION_WIRE_KINDS.len(), 11);
    assert!(CURATION_WIRE_KINDS.contains(&"concept"));
    assert!(!CURATION_WIRE_KINDS.contains(&"abstraction"));
    assert!(parse_kind("concept").is_ok());
    assert!(parse_kind("abstraction").is_err());
    assert_eq!(family_of(CurationKind::Concept), CurationFamily::Concept);
    let port = handler_port();
    assert_eq!(port.descriptor.accepted_kinds, vec![CurationKind::Concept]);
    assert_eq!(port.descriptor.family, CurationFamily::Concept);
    for mode in [ConceptMode::Concept, ConceptMode::Abstraction] {
        let (fx, policy) = scoped(mode);
        let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
            .expect("both modes emit");
        assert_eq!(candidate.handler_result.kind, CurationKind::Concept);
    }
}

// WORK_UNIT_CASE: 659/4
#[test]
fn case_04_wrong_kind_payload_refused() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.request.kind = CurationKind::Relation;
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("wrong request kind must fail");
    assert!(matches!(err, ContractViolation::KindPayload(_)));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    let relation = CurationPayload::Relation(eliot_dreamer_contracts::curation::RelationPayload {
        from_handle: "source-1".to_owned(),
        to_handle: "source-1".to_owned(),
        relation: "related".to_owned(),
        target_evidence: eliot_dreamer_contracts::curation::TargetEvidence {
            targets: vec!["source-1".to_owned()],
            evidence_refs: vec!["evidence-1".to_owned()],
        },
    });
    fx.input.item.payload = relation;
    fx.input.item.kind_spelling = "relation".to_owned();
    fx.input.item.family_spelling = "relation".to_owned();
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());
}

// WORK_UNIT_CASE: 659/5
#[test]
fn case_05_source_identity_revision_scope_fence_mismatch() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.sources.sources[0].task_id = TaskId::new("other-task").expect("task");
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.sources.sources[0].scope_id = WorkScopeId::new("other-scope").expect("scope");
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.sources.sources[0].state_fence = fence_seq2();
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("fence drift must fail");
    assert!(matches!(err, ContractViolation::BindingMismatch { .. }));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.evidence[0]
        .named
        .foundation_evidence_envelope
        .provenance
        .revision = Some("other-rev".to_owned());
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.sources.sources[0].content_digest = digest(b'z');
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());
}

// WORK_UNIT_CASE: 659/6
#[test]
fn case_06_same_id_changed_proposal_refused() {
    let policy = sealed_policy("policy");
    let mut fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    let mut snapshot_proposal = fx.input.neighborhood.concepts[0].proposal.clone();
    snapshot_proposal.definition = "changed definition".to_owned();
    let content_digest =
        concept_proposal_digest(&snapshot_proposal).expect("changed snapshot digest");
    let snapshot = &mut fx.input.neighborhood.concepts[0];
    snapshot.proposal = snapshot_proposal;
    snapshot.content_digest = content_digest;
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("same-ID changed proposal must fail");
    assert!(matches!(
        err,
        ContractViolation::BindingMismatch {
            field: "concept.neighborhood.concept_id",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 659/7
#[test]
fn case_07_grounded_criterion_roles() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    for (id, role) in [
        ("criterion-2", ConceptCriterionRole::Sufficient),
        ("criterion-3", ConceptCriterionRole::Characteristic),
        ("criterion-4", ConceptCriterionRole::Exclusion),
    ] {
        fx.input.proposal.criteria.push(ConceptCriterion {
            criterion_id: aid(id),
            role,
            applicability: eliot_dreamer_contracts::CriterionApplicability::Required,
            status: eliot_dreamer_contracts::CriterionStatus::Supported,
            statement: format!("grounded {id}"),
            evidence_refs: vec![aid("evidence-1")],
            exception_refs: Vec::new(),
        });
    }
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("grounded roles emit");
    let roles: Vec<_> = candidate
        .proposal
        .criteria
        .iter()
        .map(|criterion| criterion.role)
        .collect();
    assert!(roles.contains(&ConceptCriterionRole::Necessary));
    assert!(roles.contains(&ConceptCriterionRole::Sufficient));
    assert!(roles.contains(&ConceptCriterionRole::Characteristic));
    assert!(roles.contains(&ConceptCriterionRole::Exclusion));
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/8
#[test]
fn case_08_unsupported_partial_unknown_criterion_insufficient() {
    for status in [
        eliot_dreamer_contracts::CriterionStatus::Unsupported,
        eliot_dreamer_contracts::CriterionStatus::Partial,
        eliot_dreamer_contracts::CriterionStatus::Unknown,
    ] {
        let (mut fx, policy) = scoped(ConceptMode::Concept);
        fx.input.proposal.criteria[0].status = status;
        let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
            .expect("weak criterion stays a bounded assertion");
        assert_eq!(
            candidate.disposition,
            ConceptDisposition::Insufficient,
            "status {status:?} must be insufficient"
        );
        assert_eq!(candidate.common_disposition, CandidateDisposition::Partial);
    }
}

// WORK_UNIT_CASE: 659/9
#[test]
fn case_09_copied_dependent_sources_not_independent() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input
        .proposal
        .evidence
        .push(second_evidence("evidence-2", "group-1"));
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("copied dependence group stays bounded");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_eq!(candidate.proposal.evidence.len(), 2);
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/10
#[test]
fn case_10_authority_coverage_ceiling() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.evidence[0]
        .named
        .foundation_evidence_envelope
        .authority = EvidenceAuthority::ModelInterpretation;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("model authority stays a bounded assertion");
    assert_eq!(candidate.disposition, ConceptDisposition::Insufficient);

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.evidence[0]
        .named
        .foundation_evidence_envelope
        .coverage = EvidenceCoverage::PartialForScope;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("partial coverage stays a bounded assertion");
    assert_eq!(candidate.disposition, ConceptDisposition::Insufficient);
}

// WORK_UNIT_CASE: 659/11
#[test]
fn case_11_prose_without_grounding_insufficient() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.criteria[0].evidence_refs = Vec::new();
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("ungrounded criterion stays bounded");
    assert_eq!(candidate.disposition, ConceptDisposition::Insufficient);

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.criteria = Vec::new();
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("criterion-free prose stays bounded");
    assert_eq!(candidate.disposition, ConceptDisposition::Insufficient);
}

// WORK_UNIT_CASE: 659/12
#[test]
fn case_12_circular_definition_rejected() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.definition = "cache".to_owned();
    set_payload_definition(&mut fx.input, "cache");
    recontext(&mut fx);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("circular definition stays a bounded assertion");
    assert_eq!(candidate.disposition, ConceptDisposition::Unsupported);
    assert_eq!(
        candidate.common_disposition,
        CandidateDisposition::Unsupported
    );
}

// WORK_UNIT_CASE: 659/13
#[test]
fn case_13_catchall_no_discrimination_rejected() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.discriminator.falsification_condition = fx
        .input
        .proposal
        .discriminator
        .predicted_distinction
        .clone();
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("tautological discriminator stays bounded");
    assert_eq!(candidate.disposition, ConceptDisposition::Unsupported);

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.discriminator.predicted_distinction = String::new();
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("blank discriminator is malformed");
    assert!(matches!(err, ContractViolation::MissingField(_)));
}

// WORK_UNIT_CASE: 659/14
#[test]
fn case_14_positive_example_mapping() {
    let (fx, policy) = scoped(ConceptMode::Concept);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("positive example maps");
    let positives = candidate
        .proposal
        .cases
        .iter()
        .filter(|case| case.kind == ConceptCaseKind::Positive)
        .count();
    assert_eq!(positives, 1);
    assert_eq!(candidate.proposal.cases[0].source_ref, aid("source-1"));
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/15
#[test]
fn case_15_counterexample_mapping() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.cases[0].kind = ConceptCaseKind::Counterexample;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("counterexample maps");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_eq!(
        candidate.proposal.cases[0].kind,
        ConceptCaseKind::Counterexample
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/16
#[test]
fn case_16_borderline_unknown_mapping() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    let mut borderline = fx.input.proposal.cases[0].clone();
    borderline.case_id = aid("case-2");
    borderline.kind = ConceptCaseKind::Borderline;
    let mut unknown = fx.input.proposal.cases[0].clone();
    unknown.case_id = aid("case-3");
    unknown.kind = ConceptCaseKind::Unknown;
    fx.input.proposal.cases.push(borderline);
    fx.input.proposal.cases.push(unknown);
    fx.input.proposal.case_expected_total = 3;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("borderline and unknown map");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert!(
        candidate
            .proposal
            .cases
            .iter()
            .any(|case| case.kind == ConceptCaseKind::Borderline)
    );
    assert!(
        candidate
            .proposal
            .cases
            .iter()
            .any(|case| case.kind == ConceptCaseKind::Unknown)
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/17
#[test]
fn case_17_counterexample_survives_majority() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    for (id, kind) in [
        ("case-2", ConceptCaseKind::Positive),
        ("case-3", ConceptCaseKind::Positive),
        ("case-4", ConceptCaseKind::Counterexample),
    ] {
        let mut case = fx.input.proposal.cases[0].clone();
        case.case_id = aid(id);
        case.kind = kind;
        fx.input.proposal.cases.push(case);
    }
    fx.input.proposal.case_expected_total = 4;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("majority cannot erase a counterexample");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_eq!(candidate.proposal.cases.len(), 4);
    assert!(
        candidate
            .proposal
            .cases
            .iter()
            .any(|case| case.kind == ConceptCaseKind::Counterexample)
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/18
#[test]
fn case_18_partial_coverage_proves_no_counterexample_absence() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.case_expected_total = 2;
    fx.input.proposal.case_omitted_refs = vec![aid("case-omitted")];
    fx.input.proposal.case_coverage = ConceptCoverage::Partial;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("partial coverage stays scoped");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_eq!(candidate.common_disposition, CandidateDisposition::Partial);
    assert_eq!(
        candidate.proposal.case_omitted_refs,
        vec![aid("case-omitted")]
    );
}

// WORK_UNIT_CASE: 659/19
#[test]
fn case_19_single_case_stays_scoped() {
    let (fx, policy) = scoped(ConceptMode::Concept);
    assert!(fx.input.neighborhood.concepts.is_empty());
    let candidate =
        propose_concept_or_abstraction(&fx.input, &fx.context, &policy).expect("single case emits");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_ne!(candidate.disposition, ConceptDisposition::Candidate);
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
}

// WORK_UNIT_CASE: 659/20
#[test]
fn case_20_applicability_boundary_recorded() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.applicability.domain = "restricted-zone".to_owned();
    fx.input.proposal.applicability.population = "admitted members".to_owned();
    fx.input.proposal.applicability.environment = "offline".to_owned();
    fx.input.proposal.applicability.time = "frozen window".to_owned();
    fx.input.proposal.applicability.version = "v2".to_owned();
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("bounded transfer emits");
    assert_eq!(candidate.proposal.applicability.domain, "restricted-zone");
    assert_eq!(
        candidate.proposal.applicability.population,
        "admitted members"
    );
    assert_eq!(candidate.proposal.applicability.environment, "offline");
    assert_eq!(candidate.proposal.applicability.time, "frozen window");
    assert_eq!(candidate.proposal.applicability.version, "v2");
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/21
#[test]
fn case_21_hidden_universal_extrapolation_rejected() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.definition = "always retains every result everywhere".to_owned();
    set_payload_definition(&mut fx.input, "always retains every result everywhere");
    recontext(&mut fx);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("universal wording stays bounded");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_ne!(candidate.disposition, ConceptDisposition::Candidate);
}

// WORK_UNIT_CASE: 659/22
#[test]
fn case_22_narrower_scope_retains_exclusions() {
    let policy = sealed_policy("policy");
    let mut fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    narrowed(&mut fx.input);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("safe narrowing emits");
    assert!(
        candidate
            .proposal
            .applicability
            .exclusions
            .contains(&"unbounded state".to_owned())
    );
    assert!(
        candidate
            .proposal
            .applicability
            .exclusions
            .contains(&"new boundary excludes unbounded state".to_owned())
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/23
#[test]
fn case_23_rival_and_dependency_retained() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    let mut rival = fx.input.proposal.discriminator.clone();
    rival.alternative_id = None;
    rival.predicted_distinction = "rival keeps no boundary".to_owned();
    rival.falsification_condition = "rival source retains the boundary".to_owned();
    fx.input.proposal.rivals.push(rival);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("rival interpretation stays bounded");
    assert_eq!(candidate.proposal.rivals.len(), 1);
    assert_eq!(candidate.proposal.dependencies.len(), 1);
    assert_eq!(
        candidate.proposal.dependencies[0].dependency_id,
        aid("dependency-1")
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/24
#[test]
fn case_24_similarity_not_causal_abstraction() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.evidence[0]
        .named
        .foundation_evidence_envelope
        .authority = EvidenceAuthority::HeuristicStatic;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("heuristic similarity stays bounded");
    assert_eq!(candidate.disposition, ConceptDisposition::Insufficient);
}

// WORK_UNIT_CASE: 659/25
#[test]
fn case_25_discriminator_against_rival() {
    let policy = sealed_policy("policy");
    let mut fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    fx.input.proposal.concept_id = aid("concept-2");
    fx.input.proposal.discriminator.alternative_id = Some(aid("concept-1"));
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("rival discriminator emits");
    assert_eq!(
        candidate.proposal.discriminator.alternative_id,
        Some(aid("concept-1"))
    );
    assert!(
        !candidate
            .proposal
            .discriminator
            .predicted_distinction
            .trim()
            .is_empty()
    );
    assert!(
        !candidate
            .proposal
            .discriminator
            .falsification_condition
            .trim()
            .is_empty()
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/26
#[test]
fn case_26_missing_tautological_discriminator() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.discriminator.evidence_refs = Vec::new();
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.discriminator.alternative_id = Some(aid("ghost-rival"));
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("unretained rival alternative must fail");
    assert!(matches!(err, ContractViolation::BindingMismatch { .. }));
}

// WORK_UNIT_CASE: 659/27
#[test]
fn case_27_exact_duplicate_idempotent_replay() {
    let policy = sealed_policy("policy");
    let fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    let first = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("first replay emits");
    let second = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("second replay emits");
    assert_eq!(first, second);
    assert_eq!(first.disposition, ConceptDisposition::Duplicate);
    assert_eq!(first.common_disposition, CandidateDisposition::Duplicate);
    assert!(first.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/28
#[test]
fn case_28_same_label_different_definition_distinct() {
    let policy = sealed_policy("policy");
    let mut fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    fx.input.proposal.concept_id = aid("concept-2");
    fx.input.proposal.definition = "evicts stale entries".to_owned();
    set_payload_definition(&mut fx.input, "evicts stale entries");
    recontext(&mut fx);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("same label with new definition stays distinct");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    assert_eq!(candidate.rollback.predecessor, None);
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/29
#[test]
fn case_29_refinement_with_predecessor() {
    let policy = sealed_policy("policy");
    let mut fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    narrowed(&mut fx.input);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("narrowing retains predecessor");
    assert_eq!(candidate.rollback.predecessor, Some(aid("concept-1")));
    assert!(candidate.rollback.history_refs.contains(&aid("concept-1")));
    assert!(!candidate.rollback.note.trim().is_empty());
}

// WORK_UNIT_CASE: 659/30
#[test]
fn case_30_contradictory_definition_retains_conflict() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.criteria[0].role = ConceptCriterionRole::Characteristic;
    fx.input.proposal.criteria[0].applicability =
        eliot_dreamer_contracts::CriterionApplicability::Conditional;
    fx.input.proposal.criteria[0].status = eliot_dreamer_contracts::CriterionStatus::Contradicted;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("contradiction stays explicit");
    assert_eq!(candidate.disposition, ConceptDisposition::Conflict);
    assert_eq!(candidate.common_disposition, CandidateDisposition::Conflict);
    assert_eq!(
        candidate.proposal.criteria[0].status,
        eliot_dreamer_contracts::CriterionStatus::Contradicted
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/31
#[test]
fn case_31_taxonomy_conflict_handoff_only() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.criteria[0].status = eliot_dreamer_contracts::CriterionStatus::Contradicted;
    let before = fx.input.neighborhood.clone();
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("conflict never merges taxonomy");
    assert_eq!(candidate.disposition, ConceptDisposition::Conflict);
    assert_eq!(fx.input.neighborhood, before);
    assert_eq!(candidate.proposal.name, fx.input.proposal.name);
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/32
#[test]
fn case_32_seven_dimensions_history_loss_ledger() {
    assert_eq!(RelationPreservationDimension::all().len(), 7);
    let policy = sealed_policy("policy");
    let fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("duplicate retains full ledger");
    assert_eq!(candidate.preservation, fx.input.preservation);
    assert!(candidate.preservation.overall().is_ok());
    assert_eq!(candidate.rollback.history_refs, vec![aid("concept-1")]);
    assert_eq!(candidate.rollback.reversal_refs, vec![aid("source-1")]);
    assert_eq!(
        candidate.rollback.invalidation_refs,
        vec![aid("evidence-1")]
    );
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/33
#[test]
fn case_33_counterevidence_dissent_unknown_provenance_retained() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    for (id, kind) in [
        ("case-2", ConceptCaseKind::Counterexample),
        ("case-3", ConceptCaseKind::Borderline),
        ("case-4", ConceptCaseKind::Unknown),
    ] {
        let mut case = fx.input.proposal.cases[0].clone();
        case.case_id = aid(id);
        case.kind = kind;
        fx.input.proposal.cases.push(case);
    }
    fx.input.proposal.case_expected_total = 4;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("dissent stays addressable");
    assert_eq!(candidate.disposition, ConceptDisposition::Hypothesis);
    for kind in [
        ConceptCaseKind::Positive,
        ConceptCaseKind::Counterexample,
        ConceptCaseKind::Borderline,
        ConceptCaseKind::Unknown,
    ] {
        assert!(
            candidate
                .proposal
                .cases
                .iter()
                .any(|case| case.kind == kind),
            "missing {kind:?}"
        );
    }
    assert!(!candidate.rollback.invalidation_refs.is_empty());
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/34
#[test]
fn case_34_inverse_reversal_invalidation() {
    let policy = sealed_policy("policy");
    let fx = fixture(policy.digest.clone(), ConceptMode::Concept);
    let duplicate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("duplicate carries reversal refs");
    assert_eq!(duplicate.rollback.predecessor, None);
    assert_eq!(duplicate.rollback.reversal_refs, vec![aid("source-1")]);
    assert_eq!(
        duplicate.rollback.invalidation_refs,
        vec![aid("evidence-1")]
    );

    let mut refinement = fixture(policy.digest.clone(), ConceptMode::Concept);
    narrowed(&mut refinement.input);
    let narrowed_candidate =
        propose_concept_or_abstraction(&refinement.input, &refinement.context, &policy)
            .expect("narrowing carries predecessor inverse");
    assert_eq!(
        narrowed_candidate.rollback.predecessor,
        Some(aid("concept-1"))
    );
    assert!(!narrowed_candidate.rollback.note.trim().is_empty());
}

// WORK_UNIT_CASE: 659/35
#[test]
fn case_35_budget_time_cancel_partial() {
    let mut cancelled = ConceptPolicy::new("policy");
    cancelled.cancellation_requested = true;
    cancelled.seal().expect("cancel policy seals");
    let fx = fixture(cancelled.digest.clone(), ConceptMode::Concept);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &cancelled)
        .expect("cancellation stays explicit");
    assert_eq!(candidate.disposition, ConceptDisposition::Cancelled);
    assert_eq!(
        candidate.common_disposition,
        CandidateDisposition::Abstention
    );

    let mut tiny = ConceptPolicy::new("policy");
    tiny.max_output_bytes = 64;
    tiny.seal().expect("tiny policy seals");
    let fx = fixture(tiny.digest.clone(), ConceptMode::Concept);
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &tiny)
        .expect_err("output bound must fail");
    assert!(matches!(err, ContractViolation::Budget { .. }));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.case_expected_total = 2;
    fx.input.proposal.case_omitted_refs = vec![aid("case-omitted")];
    fx.input.proposal.case_coverage = ConceptCoverage::Partial;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("partial work stays partial");
    assert_eq!(candidate.common_disposition, CandidateDisposition::Partial);
}

// WORK_UNIT_CASE: 659/36
#[test]
fn case_36_privacy_authority_effect_proof_escalation() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.proof_ceiling = ProofCeiling::ScopedVerification;
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("proof escalation must fail");
    assert!(matches!(err, ContractViolation::ForbiddenCarry(_)));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.evidence[0]
        .named
        .foundation_evidence_envelope
        .authority = EvidenceAuthority::SourceIdentity;
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("bare source identity grants no authority");
    assert_eq!(candidate.disposition, ConceptDisposition::Insufficient);
}

// WORK_UNIT_CASE: 659/37
#[test]
fn case_37_independent_bounds_and_one_over() {
    let mut exact = ConceptPolicy::new("policy");
    exact.max_evidence = 2;
    exact.seal().expect("exact policy seals");
    let mut fx = fixture(exact.digest.clone(), ConceptMode::Concept);
    fx.input.proposal.concept_id = aid("concept-fresh");
    fx.input.neighborhood = ConceptNeighborhood {
        expected_total: 0,
        concepts: Vec::new(),
        omitted_refs: Vec::new(),
        coverage: ConceptCoverage::Complete,
    };
    fx.input
        .proposal
        .evidence
        .push(second_evidence("evidence-2", "group-2"));
    let candidate =
        propose_concept_or_abstraction(&fx.input, &fx.context, &exact).expect("exact bound admits");
    assert_eq!(candidate.proposal.evidence.len(), 2);

    let mut tight = ConceptPolicy::new("policy");
    tight.max_evidence = 1;
    tight.seal().expect("tight policy seals");
    let mut fx = fixture(tight.digest.clone(), ConceptMode::Concept);
    fx.input.proposal.concept_id = aid("concept-fresh");
    fx.input.neighborhood = ConceptNeighborhood {
        expected_total: 0,
        concepts: Vec::new(),
        omitted_refs: Vec::new(),
        coverage: ConceptCoverage::Complete,
    };
    fx.input
        .proposal
        .evidence
        .push(second_evidence("evidence-2", "group-2"));
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &tight)
        .expect_err("one over bound must fail");
    assert!(matches!(err, ContractViolation::Budget { .. }));
}

// WORK_UNIT_CASE: 659/38
#[test]
fn case_38_set_order_determinism() {
    let policy = sealed_policy("policy");
    let mut first = fixture(policy.digest.clone(), ConceptMode::Concept);
    narrowed(&mut first.input);
    first.input.proposal.concept_id = aid("concept-2");
    let mut second = first.input.clone();
    second.proposal.applicability.exclusions.reverse();
    assert_ne!(
        first.input.proposal.applicability.exclusions,
        second.proposal.applicability.exclusions
    );
    let left = propose_concept_or_abstraction(&first.input, &first.context, &policy)
        .expect("ordered input emits");
    let right = propose_concept_or_abstraction(&second, &first.context, &policy)
        .expect("reordered input emits");
    assert_eq!(left.input_digest, right.input_digest);
    assert_eq!(
        left.handler_result.result_digest,
        right.handler_result.result_digest
    );
    assert_eq!(
        concept_proposal_digest(&left.proposal).expect("left digest"),
        concept_proposal_digest(&right.proposal).expect("right digest")
    );
}

// WORK_UNIT_CASE: 659/39
#[test]
fn case_39_replay_changed_request_policy() {
    let (fx, policy) = scoped(ConceptMode::Concept);
    let first = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("first replay emits");
    let second = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("second replay emits");
    assert_eq!(first, second);

    let mut changed = ConceptPolicy::new("policy");
    changed.max_work = 512;
    changed.seal().expect("changed policy seals");
    assert_ne!(changed.digest, policy.digest);
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &changed)
        .expect_err("changed policy must fail the digest bind");
    assert!(matches!(
        err,
        ContractViolation::BindingMismatch {
            field: "concept.policy_digest",
            ..
        }
    ));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.request_id = "request-2".to_owned();
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());
}

// WORK_UNIT_CASE: 659/40
#[test]
fn case_40_bounded_malformed_input() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.name = String::new();
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("blank name must fail");
    assert!(matches!(err, ContractViolation::MissingField(_)));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.schema_version = 99;
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("wrong schema version must fail");
    assert!(matches!(err, ContractViolation::OutOfBounds { .. }));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.policy_digest = "not-a-digest".to_owned();
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());
}

// WORK_UNIT_CASE: 659/41
#[test]
fn case_41_every_feature_binds_exact_source() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.cases[0].source_ref = aid("ghost-source");
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("unretained case source must fail");
    assert!(matches!(err, ContractViolation::BindingMismatch { .. }));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.criteria[0].evidence_refs = vec![aid("ghost-evidence")];
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.discriminator.evidence_refs = vec![aid("ghost-evidence")];
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());
}

// WORK_UNIT_CASE: 659/42
#[test]
fn case_42_complete_generalization_within_ceilings() {
    let (fx, policy) = scoped(ConceptMode::Concept);
    let candidate = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("complete support stays within ceilings");
    assert_eq!(
        candidate.common_disposition,
        CandidateDisposition::Candidate
    );
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert_eq!(candidate.handler_result.kind, CurationKind::Concept);
    assert_eq!(candidate.handler_result.family, CurationFamily::Concept);
    assert_eq!(candidate.input_digest.len(), 64);
    assert_eq!(candidate.policy_digest, policy.digest);
    assert!(candidate.validate_against(&fx.input).is_ok());
}

// WORK_UNIT_CASE: 659/43
#[test]
fn case_43_counterexample_removal_changes_digest() {
    let (mut with, policy) = scoped(ConceptMode::Concept);
    with.input.proposal.cases[0].kind = ConceptCaseKind::Counterexample;
    let with_digest =
        concept_proposal_digest(&with.input.proposal).expect("digest with counterexample");
    let candidate_with = propose_concept_or_abstraction(&with.input, &with.context, &policy)
        .expect("counterexample input emits");
    assert_eq!(candidate_with.disposition, ConceptDisposition::Hypothesis);

    let (without, _) = scoped(ConceptMode::Concept);
    let without_digest =
        concept_proposal_digest(&without.input.proposal).expect("digest without counterexample");
    assert_ne!(with_digest, without_digest);
    let candidate_without =
        propose_concept_or_abstraction(&without.input, &without.context, &policy)
            .expect("removed-counterexample input emits");
    assert_ne!(
        candidate_with.handler_result.result_digest,
        candidate_without.handler_result.result_digest
    );
}

// WORK_UNIT_CASE: 659/44
#[test]
fn case_44_no_source_provenance_dissent_deletion() {
    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.sources.denominator.expected_total = 2;
    fx.input.sources.denominator.processed = vec![aid("source-1")];
    fx.input.sources.denominator.omitted = vec![aid("source-x")];
    fx.input.sources.denominator.coverage = ConceptCoverage::Partial;
    let err = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect_err("unaccounted omitted source must fail");
    assert!(matches!(err, ContractViolation::BindingMismatch { .. }));

    let (mut fx, policy) = scoped(ConceptMode::Concept);
    fx.input.proposal.evidence = Vec::new();
    assert!(propose_concept_or_abstraction(&fx.input, &fx.context, &policy).is_err());
}

// WORK_UNIT_CASE: 659/45
#[test]
fn case_45_no_model_provider_taxonomy_mutation_or_finish() {
    assert_eq!(HANDLER_ID, "eliot-dreamer-concept");
    let (fx, policy) = scoped(ConceptMode::Concept);
    let before = fx.input.clone();
    let first = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("pure handler emits");
    let second = propose_concept_or_abstraction(&fx.input, &fx.context, &policy)
        .expect("pure handler replays");
    assert_eq!(first, second);
    assert_eq!(fx.input, before);
    assert_eq!(first.handler_result.handler_id, HANDLER_ID);
    assert_eq!(handler_port().descriptor.handler_id, HANDLER_ID);
}
