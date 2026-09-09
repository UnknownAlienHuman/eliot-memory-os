#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ReceiptId, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_dreamer_concept::{ConceptPolicy, propose_concept_or_abstraction};
use eliot_dreamer_contracts::{
    AtomicityMode, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue,
    ConceptApplicability, ConceptCase, ConceptCaseKind, ConceptCoverage, ConceptCriterion,
    ConceptCriterionRole, ConceptDependency, ConceptDiscriminator, ConceptEvidence, ConceptInput,
    ConceptMode, ConceptNeighborhood, ConceptParameter, ConceptProposal, ConceptSnapshot,
    ConceptSourceDenominator, ConceptSourceRef, ConceptSourceSet, ConceptVerifierRef,
    CurationAcceptanceCtx, CurationFamily, CurationKind, CurationPayload, DreamInputBundle,
    DreamJobInput, GroundedDreamDraft, JobClass, NamedEvidence, RelationPreservation,
    RelationPreservationDimension, RelationPreservationVerdict, Requester, RequesterOrigin,
    ScreenBinding, ScreenState, SupportState, TargetDenominator, TypedCurationHandlerRequest,
    ValidatedCurationItem, ValidationReceipt, canonical_bytes, concept_proposal_digest, digest_hex,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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
