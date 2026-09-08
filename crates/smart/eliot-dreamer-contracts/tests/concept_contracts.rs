#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ReceiptId, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_dreamer_contracts::{
    AtomicityMode, BudgetUsage, BundleCompleteness, BundleMaterial, ConceptApplicability,
    ConceptCandidate, ConceptCase, ConceptCaseKind, ConceptCoverage, ConceptCriterion,
    ConceptCriterionRole, ConceptDependency, ConceptDiscriminator, ConceptDisposition,
    ConceptEvidence, ConceptInput, ConceptMode, ConceptNeighborhood, ConceptParameter,
    ConceptProposal, ConceptRollback, ConceptSnapshot, ConceptSourceDenominator, ConceptSourceRef,
    ConceptSourceSet, ConceptVerifierRef, CurationFamily, CurationKind, CurationPayload,
    DreamInputBundle, DreamJobInput, GroundedDreamDraft, JobClass, NamedEvidence,
    RelationPreservation, RelationPreservationDimension, RelationPreservationVerdict, Requester,
    RequesterOrigin, ScreenBinding, ScreenState, SupportState, TargetDenominator,
    TypedCurationHandlerRequest, TypedCurationHandlerResult, ValidatedCurationItem,
    ValidationReceipt, canonical_bytes, digest_hex, validate_concept_acceptance,
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

fn preservation(passing: bool) -> RelationPreservation {
    RelationPreservation {
        verdicts: RelationPreservationDimension::all()
            .iter()
            .copied()
            .map(|dimension| RelationPreservationVerdict {
                dimension,
                passed: passing,
                known: passing,
                note: "structural fixture".to_owned(),
            })
            .collect(),
    }
}

fn job() -> DreamJobInput {
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

fn source_id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("artifact id")
}

fn source_ref() -> ConceptSourceRef {
    ConceptSourceRef {
        source_id: source_id("source-1"),
        source_revision: "source-rev".to_owned(),
        content_digest: digest(b's'),
        admission: ReceiptIdentity {
            receipt_id: ReceiptId::new("admission-1").expect("receipt id"),
            canonical_sha256: digest(b'a'),
        },
        task_id: TaskId::new("task-1").expect("task id"),
        scope_id: WorkScopeId::new("scope-1").expect("scope id"),
        state_fence: fence(),
        freshness: EvidenceFreshness::ExactCandidate,
    }
}

fn evidence(id: &str) -> ConceptEvidence {
    ConceptEvidence {
        named: NamedEvidence {
            id: source_id(id),
            foundation_evidence_envelope: EvidenceEnvelope {
                authority: EvidenceAuthority::SourceIdentity,
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
            source_handles: vec![source_id("source-1")],
            dependence_groups: vec!["group-1".to_owned()],
            external_grade: None,
        },
        source_refs: vec![source_id("source-1")],
        freshness: EvidenceFreshness::ExactCandidate,
    }
}

fn proposal(mode: ConceptMode, passing: bool) -> ConceptProposal {
    let evidence_refs = vec![source_id("evidence-1"), source_id("evidence-2")];
    ConceptProposal {
        schema_version: 1,
        concept_id: source_id("concept-1"),
        mode,
        name: "cache".to_owned(),
        definition: "retained result".to_owned(),
        criteria: vec![ConceptCriterion {
            criterion_id: source_id("criterion-1"),
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
            source_refs: vec![source_id("source-1")],
        },
        cases: vec![ConceptCase {
            case_id: source_id("case-1"),
            kind: ConceptCaseKind::Positive,
            source_ref: source_id("source-1"),
            evidence_refs: evidence_refs.clone(),
            note: "retained example".to_owned(),
        }],
        case_expected_total: 1,
        case_omitted_refs: Vec::new(),
        case_coverage: ConceptCoverage::Complete,
        evidence: vec![evidence("evidence-1"), evidence("evidence-2")],
        rivals: Vec::new(),
        discriminator: ConceptDiscriminator {
            alternative_id: None,
            predicted_distinction: "keeps the boundary".to_owned(),
            falsification_condition: "a retained source would violate the boundary".to_owned(),
            evidence_refs,
            verifier: ConceptVerifierRef {
                verifier_id: source_id("source-1"),
                revision: "source-rev".to_owned(),
                digest: digest(b's'),
            },
        },
        dependencies: vec![ConceptDependency {
            dependency_id: source_id("dependency-1"),
            revision: "dependency-rev".to_owned(),
            content_digest: digest(b'd'),
            source_refs: vec![source_id("source-1")],
        }],
        source_refs: vec![source_id("source-1")],
        policy_digest: digest(b'p'),
        proof_ceiling: ProofCeiling::CandidateArtifact,
        preservation: preservation(passing),
    }
}

struct Fixture {
    input: ConceptInput,
    job: DreamJobInput,
    bundle: DreamInputBundle,
    receipt: ValidationReceipt,
    grounded: GroundedDreamDraft,
    request: TypedCurationHandlerRequest,
    screen: ScreenBinding,
    usage: BudgetUsage,
}

impl Fixture {
    fn context(&self) -> eliot_dreamer_contracts::CurationAcceptanceCtx<'_> {
        eliot_dreamer_contracts::CurationAcceptanceCtx {
            job: &self.job,
            bundle: &self.bundle,
            receipt: &self.receipt,
            screen: &self.screen,
            grounded: &self.grounded,
            request: &self.request,
            usage: &self.usage,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn fixture(mode: ConceptMode, passing: bool) -> Fixture {
    let job = job();
    let source = source_ref();
    let draft_digest = digest(b'g');
    let grounded = GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        draft_digest: draft_digest.clone(),
        residues: vec![eliot_dreamer_contracts::ClaimResidue {
            claim: "cache".to_owned(),
            state: SupportState::Partial,
            detail: "bounded".to_owned(),
        }],
        coverage_note: "fixture coverage".to_owned(),
    };
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05".to_owned(),
        validator_policy: "policy".to_owned(),
        job_id: "job-1".to_owned(),
        draft_digest,
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
    };
    let payload = CurationPayload::Concept(eliot_dreamer_contracts::curation::ConceptPayload {
        concept: "cache".to_owned(),
        definition: "retained result".to_owned(),
        target_evidence: eliot_dreamer_contracts::curation::TargetEvidence {
            targets: vec!["source-1".to_owned()],
            evidence_refs: vec!["evidence-1".to_owned(), "evidence-2".to_owned()],
        },
    });
    let denominator = TargetDenominator {
        mode: AtomicityMode::PerMember,
        members: vec!["source-1".to_owned()],
        expected_total: 1,
    };
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
        job_digest: digest_hex(&canonical_bytes(&job).expect("job bytes")),
        requester: job.requester.clone(),
        budget_note: "bounded".to_owned(),
    };
    let grounded_digest = item.item_digest(&grounded).expect("item digest");
    let screen = ScreenBinding {
        request_id: eliot_contracts::RequestId::new("request-1").expect("request id"),
        receipt_id: ReceiptId::new("screen-receipt-1").expect("receipt id"),
        screened_targets: vec!["source-1".to_owned()],
        source_snapshot: "screen-snapshot".to_owned(),
        source_revision: "screen-rev".to_owned(),
        profile: "concept-profile".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: digest(b'k'),
        item_digest: grounded_digest,
    };
    let request = TypedCurationHandlerRequest {
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
        payload: payload.clone(),
        denominator: denominator.clone(),
        screen_binding: Some(screen.clone()),
    };
    let structured_proposal = proposal(mode, passing);
    let mut snapshot_proposal = proposal(ConceptMode::Concept, true);
    snapshot_proposal.concept_id = source_id("existing-1");
    let snapshot_digest = eliot_dreamer_contracts::concept_proposal_digest(&snapshot_proposal)
        .expect("snapshot proposal digest");
    let neighborhood = ConceptNeighborhood {
        expected_total: 1,
        concepts: vec![ConceptSnapshot {
            concept_id: source_id("existing-1"),
            proposal: Box::new(snapshot_proposal),
            revision: "existing-rev".to_owned(),
            content_digest: snapshot_digest,
            scope_id: WorkScopeId::new("scope-1").expect("scope"),
            state_fence: fence(),
            source_refs: vec![source_id("source-1")],
            evidence_refs: vec![source_id("evidence-1"), source_id("evidence-2")],
        }],
        omitted_refs: Vec::new(),
        coverage: ConceptCoverage::Complete,
    };
    let input = ConceptInput {
        schema_version: 1,
        operation_id: source_id("op-1"),
        request_id: "request-1".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        policy_digest: structured_proposal.policy_digest.clone(),
        job,
        item: { item },
        request: request.clone(),
        sources: ConceptSourceSet {
            sources: vec![source],
            denominator: ConceptSourceDenominator {
                expected_total: 1,
                processed: vec![source_id("source-1")],
                omitted: Vec::new(),
                coverage: ConceptCoverage::Complete,
            },
        },
        proposal: structured_proposal,
        neighborhood,
        screen: screen.clone(),
        preservation: preservation(passing),
    };
    let mut bundle = DreamInputBundle {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        manifest_digest: input.job.frozen_manifest_digest.clone(),
        materials: Vec::new(),
        omissions: Vec::new(),
        completeness: BundleCompleteness::CompleteForScope,
        authoritative_denominator: Some("source-1,evidence-1,evidence-2".to_owned()),
    };
    bundle.materials = vec![
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
        BundleMaterial {
            handle: "evidence-2".to_owned(),
            disposition: eliot_dreamer_contracts::SourceDisposition::Required,
            bytes: 1,
            digest: digest(b'f'),
        },
    ];
    let fixture_job = input.job.clone();
    Fixture {
        input,
        job: fixture_job,
        bundle,
        receipt,
        grounded,
        request,
        screen,
        usage: BudgetUsage::default(),
    }
}

fn candidate(input: &ConceptInput) -> ConceptCandidate {
    ConceptCandidate {
        schema_version: 1,
        candidate_id: source_id("candidate-placeholder"),
        operation_id: input.operation_id.clone(),
        input_digest: eliot_dreamer_contracts::concept_input_digest(input).expect("input digest"),
        policy_digest: input.policy_digest.clone(),
        mode: input.proposal.mode,
        proposal: input.proposal.clone(),
        disposition: ConceptDisposition::Candidate,
        common_disposition: eliot_dreamer_contracts::CandidateDisposition::Candidate,
        preservation: input.preservation.clone(),
        rollback: ConceptRollback {
            predecessor: Some(source_id("existing-1")),
            history_refs: vec![source_id("existing-1")],
            reversal_refs: vec![source_id("evidence-1")],
            invalidation_refs: vec![source_id("source-1")],
            note: "reversible candidate".to_owned(),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
        handler_result: TypedCurationHandlerResult {
            request_id: input.request_id.clone(),
            kind: CurationKind::Concept,
            family: CurationFamily::Concept,
            disposition: eliot_dreamer_contracts::CandidateDisposition::Candidate,
            handler_id: "concept-handler".to_owned(),
            request_digest: {
                let mut request = input.request.clone();
                if let CurationPayload::Concept(payload) = &mut request.payload {
                    payload.target_evidence.targets.sort();
                    payload.target_evidence.evidence_refs.sort();
                }
                digest_hex(&canonical_bytes(&request).expect("request bytes"))
            },
            result_digest: digest(0),
        },
    }
}

#[test]
fn concept_and_abstraction_public_paths_accept_digest_and_seal() {
    for mode in [ConceptMode::Concept, ConceptMode::Abstraction] {
        let fixture = fixture(mode, true);
        let context = fixture.context();
        validate_concept_acceptance(&fixture.input, &context).expect("accepted Concept closure");
        let input_digest =
            eliot_dreamer_contracts::concept_input_digest(&fixture.input).expect("input digest");
        let sealed =
            eliot_dreamer_contracts::seal_concept(candidate(&fixture.input), &fixture.input)
                .expect("sealed candidate");
        assert_eq!(sealed.input_digest, input_digest);
        sealed
            .validate_against(&fixture.input)
            .expect("candidate remains bound");
    }
}

#[test]
fn exact_source_evidence_case_target_and_receipt_joins_fail_closed() {
    let base = fixture(ConceptMode::Concept, true);
    let context = base.context();
    validate_concept_acceptance(&base.input, &context).expect("base accepted");

    let mut source_drift = base.input.clone();
    source_drift.sources.sources[0].content_digest = digest(b'z');
    assert!(validate_concept_acceptance(&source_drift, &context).is_err());

    let mut evidence_drift = base.input.clone();
    evidence_drift.proposal.criteria[0].evidence_refs[0] = source_id("missing-evidence");
    assert!(evidence_drift.validate().is_err());

    let mut case_drift = base.input.clone();
    case_drift.proposal.cases[0].source_ref = source_id("missing-source");
    assert!(case_drift.validate().is_err());

    let mut target_drift = base.input.clone();
    if let CurationPayload::Concept(payload) = &mut target_drift.item.payload {
        payload.target_evidence.targets[0] = "missing-target".to_owned();
    }
    assert!(target_drift.validate().is_err());

    let mut receipt_drift = base.input.clone();
    receipt_drift.item.receipt.validator_policy = "changed-policy".to_owned();
    assert!(validate_concept_acceptance(&receipt_drift, &context).is_err());

    let mut duplicate_snapshot_criterion = base.input.neighborhood.concepts[0].proposal.clone();
    let duplicate_criterion = duplicate_snapshot_criterion.criteria[0].clone();
    duplicate_snapshot_criterion
        .criteria
        .push(duplicate_criterion);
    assert!(duplicate_snapshot_criterion.validate().is_err());
}

#[test]
fn set_canonicalization_preserves_identity_and_unknown_coverage_blocks_promotion() {
    let base = fixture(ConceptMode::Concept, true);
    let first = eliot_dreamer_contracts::concept_input_digest(&base.input).expect("digest");
    let mut permuted = base.input.clone();
    permuted.proposal.criteria[0].evidence_refs.reverse();
    permuted.proposal.cases[0].evidence_refs.reverse();
    permuted.proposal.discriminator.evidence_refs.reverse();
    permuted.proposal.preservation.verdicts.reverse();
    permuted.preservation.verdicts.reverse();
    permuted.item.payload = match permuted.item.payload {
        CurationPayload::Concept(mut payload) => {
            payload.target_evidence.evidence_refs.reverse();
            CurationPayload::Concept(payload)
        }
        other => other,
    };
    permuted.request.payload = permuted.item.payload.clone();
    assert_eq!(
        first,
        eliot_dreamer_contracts::concept_input_digest(&permuted).expect("permuted digest")
    );

    let sealed = eliot_dreamer_contracts::seal_concept(candidate(&base.input), &base.input)
        .expect("base candidate seals");
    let sealed_permuted = eliot_dreamer_contracts::seal_concept(candidate(&permuted), &permuted)
        .expect("permuted candidate seals");
    assert_eq!(sealed.candidate_id, sealed_permuted.candidate_id);
    assert_eq!(
        sealed.handler_result.result_digest,
        sealed_permuted.handler_result.result_digest
    );

    let mut partial = base.input.clone();
    partial.sources.denominator.coverage = ConceptCoverage::Partial;
    partial.proposal.cases.clear();
    partial.proposal.case_expected_total = 0;
    partial.proposal.case_omitted_refs.clear();
    partial.proposal.case_coverage = ConceptCoverage::Unknown;
    partial.neighborhood.concepts.clear();
    partial.neighborhood.omitted_refs.clear();
    partial.neighborhood.expected_total = 0;
    partial.neighborhood.coverage = ConceptCoverage::Unknown;
    partial
        .validate()
        .expect("empty unknown closure remains valid");
    let mut partial_candidate = candidate(&partial);
    partial_candidate.rollback.predecessor = None;
    partial_candidate.rollback.history_refs.clear();
    partial_candidate.disposition = ConceptDisposition::Hypothesis;
    partial_candidate.common_disposition = eliot_dreamer_contracts::CandidateDisposition::Partial;
    partial_candidate.handler_result.disposition =
        eliot_dreamer_contracts::CandidateDisposition::Partial;
    eliot_dreamer_contracts::seal_concept(partial_candidate, &partial)
        .expect("partial hypothesis candidate");
    let mut incomplete_candidate = candidate(&partial);
    incomplete_candidate.rollback.predecessor = None;
    incomplete_candidate.rollback.history_refs.clear();
    assert!(eliot_dreamer_contracts::seal_concept(incomplete_candidate, &partial).is_err());

    let mut promotion = candidate(&base.input);
    promotion.proof_ceiling = ProofCeiling::ScopedVerification;
    assert!(eliot_dreamer_contracts::seal_concept(promotion, &base.input).is_err());
}

#[test]
fn omitted_source_requires_accepted_bundle_omission_and_preserves_unknown() {
    let mut fixture = fixture(ConceptMode::Concept, true);
    fixture.input.sources.denominator.expected_total = 2;
    fixture.input.sources.denominator.coverage = ConceptCoverage::Partial;
    fixture.input.sources.denominator.omitted = vec![source_id("source-omitted")];
    assert!(fixture.input.validate().is_ok());
    let context = fixture.context();
    assert!(validate_concept_acceptance(&fixture.input, &context).is_err());
}
