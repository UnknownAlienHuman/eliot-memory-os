//! Structural proofs for the A03 typed relation closure.
#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ReceiptId, RequestId, ResourceGeneration, SourceId, StateFence,
    TaskId, sha256_hex,
};
use eliot_dreamer_contracts::curation::{RelationPayload, TargetEvidence};
use eliot_dreamer_contracts::encoding::canonical_bytes;
use eliot_dreamer_contracts::*;
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_receipts::{ReceiptIdentity, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("id")
}
fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}
fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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
                note: "checked".to_owned(),
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
        operation_id: "op-relation-1".to_owned(),
        idempotency_key: "idem-relation-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "contract-1".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(1_048_576),
            output_bytes: Some(524_288),
            source_width: Some(32),
            reference_width: Some(32),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(1_000),
            work_fan_out: Some(2),
            report_bytes: Some(1_024),
            max_stu: Some(10),
        },
        deadline_ms: None,
        frozen_manifest_digest: digest("manifest"),
    }
}

fn bundle() -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: "job-relation-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        manifest_digest: digest("manifest"),
        materials: vec![
            BundleMaterial {
                handle: "source-a".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: digest("source-a"),
            },
            BundleMaterial {
                handle: "target-b".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: digest("target-b"),
            },
            BundleMaterial {
                handle: "evidence-1".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: digest("evidence-1"),
            },
            BundleMaterial {
                handle: "evidence-rival".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: digest("evidence-rival"),
            },
            BundleMaterial {
                handle: "evidence-none".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: digest("evidence-none"),
            },
        ],
        omissions: Vec::new(),
        completeness: BundleCompleteness::CompleteForScope,
        authoritative_denominator: Some("relation-scope-1".to_owned()),
    }
}

fn grounded() -> GroundedDreamDraft {
    GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-relation-1".to_owned(),
        draft_digest: digest("draft"),
        residues: vec![ClaimResidue {
            claim: "relation claim".to_owned(),
            state: SupportState::Supported,
            detail: "grounded".to_owned(),
        }],
        coverage_note: "covered".to_owned(),
    }
}

fn receipt() -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".to_owned(),
        validator_policy: "policy-7".to_owned(),
        job_id: "job-relation-1".to_owned(),
        draft_digest: digest("draft"),
        bundle_digest: digest("manifest"),
        manifest_digest: digest("manifest"),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: digest("validator-input"),
        output_digest: digest("validator-output"),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: digest("preservation"),
        budget_digest: digest("budget"),
    }
}

fn payload_for_relation(relation: &str) -> CurationPayload {
    CurationPayload::Relation(RelationPayload {
        from_handle: "source-a".to_owned(),
        to_handle: "target-b".to_owned(),
        relation: relation.to_owned(),
        target_evidence: TargetEvidence {
            targets: vec!["source-a".to_owned(), "target-b".to_owned()],
            evidence_refs: vec!["evidence-1".to_owned()],
        },
    })
}

fn payload() -> CurationPayload {
    payload_for_relation("supports")
}

fn evidence() -> RelationEvidence {
    RelationEvidence {
        named: NamedEvidence {
            id: id("evidence-1"),
            foundation_evidence_envelope: EvidenceEnvelope {
                authority: EvidenceAuthority::DeterministicRuntimeTest,
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
                status: EpistemicStatus::Supported,
                assertability: Assertability::Assertable,
                provenance: Provenance {
                    source_id: SourceId::new("source-proof").expect("source"),
                    capture_route: "route-1".to_owned(),
                    scope: "scope-1".to_owned(),
                    raw_handle: Some("evidence-1".to_owned()),
                    revision: Some("rev-1".to_owned()),
                },
                verification: None,
                state_fence: fence(),
            },
            source_handles: vec![id("source-a")],
            dependence_groups: vec!["group-1".to_owned()],
            external_grade: None,
        },
        predicate: RelationPredicate {
            family: Some(RelationFamily::Supports),
            direction: Some(RelationDirection::Forward),
            source_id: "source-a".to_owned(),
            target_id: "target-b".to_owned(),
            expression: "directly supports".to_owned(),
        },
        polarity: RelationEvidencePolarity::Support,
        relation_role: "source".to_owned(),
    }
}

fn registry() -> RelationRegistrySnapshot {
    let mut value = RelationRegistrySnapshot {
        owner: "relation-owner".to_owned(),
        schema: "i5.18-relation-registry".to_owned(),
        revision: "rev-1".to_owned(),
        digest: "0".repeat(64),
        complete: false,
        denominator: vec![RelationFamily::Supports, RelationFamily::Contradicts],
        allowed_families: vec![RelationFamily::Supports],
        omitted_families: vec![RelationFamily::Contradicts],
        rules: vec![RelationFamilyRule {
            family: RelationFamily::Supports,
            direction: RelationDirection::Forward,
            source_roles: vec!["source".to_owned()],
            target_roles: vec!["target".to_owned()],
            source_record_families: vec![ClassificationRecordFamily::Interpretation],
            target_record_families: vec![ClassificationRecordFamily::Interpretation],
            permits_self_relation: false,
            symmetric: false,
            inverse_family: Some(RelationFamily::Contradicts),
            permits_transitive: false,
            requires_causal_mechanism: false,
            rule_ref: "rule-supports-v1".to_owned(),
        }],
        rule_refs: vec!["rule-supports-v1".to_owned()],
    };
    value.digest = value.computed_digest().expect("registry digest");
    value
}

fn endpoint(target: &str, role: &str, material: &str) -> RelationEndpoint {
    RelationEndpoint {
        admitted: AdmittedTargetRef {
            target_id: id(target),
            target_revision: "rev-1".to_owned(),
            target_digest: digest(material),
            admission: ReceiptIdentity {
                receipt_id: ReceiptId::new(format!("admission-{target}")).expect("receipt"),
                canonical_sha256: digest(&format!("admission-{target}")),
            },
            lifecycle: LifecycleState::Active,
            freshness: EvidenceFreshness::ExactCandidate,
            task_id: TaskId::new("task-1").expect("task"),
            scope_id: WorkScopeId::new("scope-1").expect("scope"),
            state_fence: fence(),
            source_handles: vec![id(material)],
        },
        record_family: ClassificationRecordFamily::Interpretation,
        role: role.to_owned(),
        privacy_class: "internal".to_owned(),
        validity: "valid".to_owned(),
        authority: "admission-owner".to_owned(),
        status: EpistemicStatus::Supported,
    }
}

fn relation_item(
    job_ref: &DreamJobInput,
    receipt_ref: &ValidationReceipt,
) -> ValidatedCurationItem {
    ValidatedCurationItem {
        receipt: receipt_ref.clone(),
        kind_spelling: "relation".to_owned(),
        family_spelling: "relation".to_owned(),
        payload: payload(),
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["source-a".to_owned(), "target-b".to_owned()],
            expected_total: 2,
        },
        source_digest: digest("source-a"),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        job_digest: sha256_hex(&canonical_bytes(job_ref).expect("job JSON")),
        requester: job_ref.requester.clone(),
        budget_note: "within limits".to_owned(),
    }
}

fn relation_screen(item_digest: String) -> ScreenBinding {
    ScreenBinding {
        request_id: RequestId::new("req-relation-1").expect("request"),
        receipt_id: ReceiptId::new("screen-relation-1").expect("receipt"),
        screened_targets: vec!["source-a".to_owned(), "target-b".to_owned()],
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: digest("screen"),
        item_digest,
    }
}

fn relation_request(screen: &ScreenBinding) -> TypedCurationHandlerRequest {
    TypedCurationHandlerRequest {
        request_id: "req-relation-1".to_owned(),
        receipt_id: "screen-relation-1".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        kind: CurationKind::Relation,
        family: CurationFamily::Relation,
        job_id: "job-relation-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        payload: payload(),
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["source-a".to_owned(), "target-b".to_owned()],
            expected_total: 2,
        },
        screen_binding: Some(screen.clone()),
    }
}

fn relation_alternative(
    alternative_id: &str,
    family: Option<RelationFamily>,
    direction: Option<RelationDirection>,
    registry_digest: String,
    evidence_refs: Vec<String>,
) -> RelationAlternative {
    RelationAlternative {
        alternative_id: alternative_id.to_owned(),
        family,
        direction,
        source_id: "source-a".to_owned(),
        target_id: "target-b".to_owned(),
        source_revision: "rev-1".to_owned(),
        target_revision: "rev-1".to_owned(),
        source_material_digest: digest("source-a"),
        target_material_digest: digest("target-b"),
        source_admission_id: "admission-source-a".to_owned(),
        target_admission_id: "admission-target-b".to_owned(),
        source_admission_digest: digest("admission-source-a"),
        target_admission_digest: digest("admission-target-b"),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        registry_digest,
        evidence_refs,
    }
}

fn fixtures() -> (RelationInput, CurationAcceptanceCtx<'static>) {
    let job_ref = Box::leak(Box::new(job()));
    let bundle_ref = Box::leak(Box::new(bundle()));
    let grounded_ref = Box::leak(Box::new(grounded()));
    let receipt_ref = Box::leak(Box::new(receipt()));
    let item = relation_item(job_ref, receipt_ref);
    let item_digest = item.item_digest(grounded_ref).expect("item digest");
    let screen_ref = Box::leak(Box::new(relation_screen(item_digest)));
    let request = Box::leak(Box::new(relation_request(screen_ref)));
    let ctx = CurationAcceptanceCtx {
        job: job_ref,
        bundle: bundle_ref,
        receipt: receipt_ref,
        screen: screen_ref,
        grounded: grounded_ref,
        request,
        usage: Box::leak(Box::new(BudgetUsage::default())),
    };
    let relation_registry = registry();
    let input = RelationInput {
        schema_version: 1,
        operation_id: "op-relation-1".to_owned(),
        request_id: "req-relation-1".to_owned(),
        idempotency_key: "idem-relation-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        policy_digest: digest("policy"),
        item,
        source: endpoint("source-a", "source", "source-a"),
        target: endpoint("target-b", "target", "target-b"),
        family: RelationFamily::Supports,
        direction: RelationDirection::Forward,
        registry: relation_registry.clone(),
        neighborhood: RelationNeighborhood {
            snapshot_id: "neighborhood-1".to_owned(),
            revision: "rev-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: fence(),
            complete: true,
            relations: Vec::new(),
            omitted_refs: Vec::new(),
            coverage_note: "complete".to_owned(),
        },
        screen: (*ctx.screen).clone(),
        evidence: vec![evidence()],
        counterevidence: Vec::new(),
        rivals: vec![relation_alternative(
            "rival-1",
            Some(RelationFamily::Contradicts),
            Some(RelationDirection::Forward),
            relation_registry.digest.clone(),
            Vec::new(),
        )],
        no_relation_alternative: Some(relation_alternative(
            "no-relation-1",
            None,
            None,
            relation_registry.digest,
            Vec::new(),
        )),
        temporal: RelationTemporalEvidence {
            event_time: None,
            effective_time: None,
            observation_time: None,
            ingestion_time: None,
            commit_time: None,
            temporal_status: EpistemicStatus::Observed,
            uncertainty_ref: None,
        },
        verifier: None,
        disclosure_evidence: None,
        preservation: preservation(),
    };
    (input, ctx)
}

use eliot_dreamer_relation::{
    CausalMaterialBinding, CausalPredicateBinding, EvidenceBinding, EvidenceBindingKind,
    EvidenceGradeBinding, RelationPolicy, grade_binding_digest, propose_relation,
};
use eliot_epistemic_contracts::{
    CausalClaim, CausalClaimParams, CausalStatus, EvidenceGrade, GradeAssignment, LineageRootId,
    PropositionId, SourceAssurance, SourceLineage, SourceRevisionId, TemporalRecord,
};

fn relation_grade_binding(evidence_id: &str) -> EvidenceGradeBinding {
    relation_grade_binding_with_grade(evidence_id, EvidenceGrade::Grounded)
}

fn relation_grade_binding_with_grade(
    evidence_id: &str,
    grade: EvidenceGrade,
) -> EvidenceGradeBinding {
    let mut binding = EvidenceGradeBinding {
        evidence_id: evidence_id.to_owned(),
        reference: ExternalGradeRef {
            owner: "grade-owner".to_owned(),
            schema: "c1-grade".to_owned(),
            revision: "rev-1".to_owned(),
            record_id: id(&format!("grade-{evidence_id}")),
            digest: "0".repeat(64),
        },
        assignment: GradeAssignment::known(grade),
    };
    binding.reference.digest = grade_binding_digest(&binding).expect("grade digest");
    binding
}

fn disclosure(input: &RelationInput) -> RelationDisclosureEvidence {
    RelationDisclosureEvidence {
        owner: "owner-1".to_owned(),
        ref_id: "disclosure-1".to_owned(),
        digest: digest("disclosure-1"),
        source_id: input.source.endpoint_id().to_owned(),
        target_id: input.target.endpoint_id().to_owned(),
        source_revision: input.source.admitted.target_revision.clone(),
        target_revision: input.target.admitted.target_revision.clone(),
        source_material_digest: input.source.material_digest().to_owned(),
        target_material_digest: input.target.material_digest().to_owned(),
        source_admission_id: input
            .source
            .admitted
            .admission
            .receipt_id
            .as_str()
            .to_owned(),
        target_admission_id: input
            .target
            .admitted
            .admission
            .receipt_id
            .as_str()
            .to_owned(),
        source_admission_digest: input.source.admitted.admission.canonical_sha256.clone(),
        target_admission_digest: input.target.admitted.admission.canonical_sha256.clone(),
        family: input.family,
        direction: input.direction,
        scope_id: input.scope_id.clone(),
        state_fence: input.state_fence.clone(),
        permitted: Some(true),
        decision: EpistemicStatus::Supported,
    }
}

fn prepared(
    mut input: RelationInput,
) -> (
    RelationInput,
    RelationPolicy,
    CurationAcceptanceCtx<'static>,
) {
    let primary = input.evidence[0].clone();
    input.evidence[0].named.external_grade = Some(relation_grade_binding("evidence-1").reference);
    let mut rival = primary.clone();
    rival.named.id = id("evidence-rival");
    rival.named.external_grade = Some(relation_grade_binding("evidence-rival").reference);
    rival
        .named
        .foundation_evidence_envelope
        .provenance
        .raw_handle = Some("evidence-rival".to_owned());
    rival.predicate.family = Some(RelationFamily::Contradicts);
    rival.polarity = RelationEvidencePolarity::Counter;
    input.counterevidence.push(rival);
    input.rivals[0].evidence_refs = vec!["evidence-rival".to_owned()];
    let mut no_relation = primary;
    no_relation.named.id = id("evidence-none");
    no_relation.named.external_grade = Some(relation_grade_binding("evidence-none").reference);
    no_relation
        .named
        .foundation_evidence_envelope
        .provenance
        .raw_handle = Some("evidence-none".to_owned());
    no_relation.predicate.family = None;
    no_relation.predicate.direction = None;
    no_relation.polarity = RelationEvidencePolarity::Counter;
    input.counterevidence.push(no_relation);
    input
        .no_relation_alternative
        .as_mut()
        .expect("no relation")
        .evidence_refs = vec!["evidence-none".to_owned()];
    let mut policy = RelationPolicy::new("relation-handler-test");
    policy.expected_alternative_refs = vec!["rival-1".to_owned(), "no-relation-1".to_owned()];
    policy.grade_bindings = vec![
        relation_grade_binding("evidence-1"),
        relation_grade_binding("evidence-rival"),
        relation_grade_binding("evidence-none"),
    ];
    input.disclosure_evidence = Some(disclosure(&input));
    policy.seal().expect("policy seal");
    input.policy_digest.clone_from(&policy.digest);
    (input, policy, fixtures().1)
}

fn causal_claim() -> CausalClaim {
    let source = SourceId::new("source-a").expect("source");
    let fact = "causal fact source-a to target-b".to_owned();
    let rival_fact = "rival fact contradicting the causal proposition".to_owned();
    CausalClaim::new(CausalClaimParams {
        subject: PropositionId::new("relation-proposition-causes-1").expect("subject"),
        status: CausalStatus::InterventionSupported,
        mechanism: fact.clone(),
        rivals: [rival_fact].into_iter().collect(),
        confounders: [fact.clone()].into_iter().collect(),
        evidence_refs: ["evidence-1", "evidence-rival"]
            .into_iter()
            .map(id)
            .collect(),
        outcome: fact.clone(),
        control: fact,
        source: source.clone(),
        source_lineage: SourceLineage::new(
            source.clone(),
            SourceRevisionId::new("rev-1").expect("revision"),
            digest("source-a"),
            Some("source-a".to_owned()),
            std::collections::BTreeSet::new(),
            None,
        )
        .expect("lineage"),
        assurance: SourceAssurance::new(
            source,
            SourceRevisionId::new("rev-1").expect("revision"),
            digest("proof-causal"),
        )
        .expect("assurance"),
        lineage: LineageRootId::new("lineage-causes-1").expect("lineage root"),
        fence: fence(),
        temporal: TemporalRecord::new(10, 11, 12, 13, 14).expect("temporal"),
        proof_digest: digest("proof-causal"),
        ceiling: EvidenceGrade::Grounded,
        scope: "scope-1".to_owned(),
    })
    .expect("claim")
}

fn causal_policy() -> RelationPolicy {
    let fact = "causal fact source-a to target-b".to_owned();
    let roles = [
        (
            EvidenceBindingKind::Mechanism,
            "evidence-1",
            fact.clone(),
            None,
        ),
        (
            EvidenceBindingKind::Intervention,
            "evidence-1",
            fact.clone(),
            None,
        ),
        (
            EvidenceBindingKind::Outcome,
            "evidence-1",
            fact.clone(),
            None,
        ),
        (
            EvidenceBindingKind::Control,
            "evidence-1",
            fact.clone(),
            None,
        ),
        (
            EvidenceBindingKind::Rival,
            "evidence-rival",
            "rival fact contradicting the causal proposition".to_owned(),
            Some("rival-1".to_owned()),
        ),
        (
            EvidenceBindingKind::Confounder,
            "evidence-1",
            fact.clone(),
            None,
        ),
        (EvidenceBindingKind::Discriminator, "evidence-1", fact, None),
    ];
    let mut policy = RelationPolicy::new("causal-handler-test");
    policy.expected_alternative_refs = vec!["rival-1".to_owned(), "no-relation-1".to_owned()];
    policy.grade_bindings = vec![
        relation_grade_binding_with_grade("evidence-1", EvidenceGrade::Corroborated),
        relation_grade_binding_with_grade("evidence-rival", EvidenceGrade::Corroborated),
        relation_grade_binding("evidence-none"),
    ];
    policy.causal_claim = Some(causal_claim());
    policy.causal_material = Some(CausalMaterialBinding {
        source_handle: "source-a".to_owned(),
        proof_handle: "proof-causal".to_owned(),
    });
    policy.causal_predicate = Some(CausalPredicateBinding {
        subject: "relation-proposition-causes-1".to_owned(),
        predicate: RelationPredicate {
            family: Some(RelationFamily::Causes),
            direction: Some(RelationDirection::Forward),
            source_id: "source-a".to_owned(),
            target_id: "target-b".to_owned(),
            expression: "causal proposition source-a causes target-b".to_owned(),
        },
    });
    policy.temporal_required = true;
    policy.causal_bindings = roles
        .into_iter()
        .map(
            |(kind, evidence_id, fact, alternative_id)| EvidenceBinding {
                evidence_id: evidence_id.to_owned(),
                kind,
                fact,
                alternative_id,
                grade: GradeAssignment::known(EvidenceGrade::Corroborated),
            },
        )
        .collect();
    policy
}

fn causal_times(input: &mut RelationInput) {
    let points = [10_i64, 11, 12, 13, 14].map(|value| RelationTimePoint {
        reading: eliot_contracts::ClockReading {
            valid_time_ms: Some(value),
            known_time_ms: Some(value),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        clock_ref: "clock-1".to_owned(),
        uncertainty_ms: 0,
        conversion_ref: None,
    });
    input.temporal = RelationTemporalEvidence {
        event_time: Some(points[0].clone()),
        effective_time: Some(points[1].clone()),
        observation_time: Some(points[2].clone()),
        ingestion_time: Some(points[3].clone()),
        commit_time: Some(points[4].clone()),
        temporal_status: EpistemicStatus::Supported,
        uncertainty_ref: None,
    };
}

fn causal_fixtures() -> (
    RelationInput,
    RelationPolicy,
    CurationAcceptanceCtx<'static>,
) {
    let (mut input, base_ctx) = fixtures();
    let manifest = digest("manifest-causal");
    let mut job = (*base_ctx.job).clone();
    job.frozen_manifest_digest.clone_from(&manifest);
    let mut bundle = (*base_ctx.bundle).clone();
    bundle.manifest_digest.clone_from(&manifest);
    bundle.materials.push(BundleMaterial {
        handle: "proof-causal".to_owned(),
        disposition: SourceDisposition::Required,
        bytes: 10,
        digest: digest("proof-causal"),
    });
    let mut receipt = (*base_ctx.receipt).clone();
    receipt.bundle_digest.clone_from(&manifest);
    receipt.manifest_digest = manifest;
    let grounded = (*base_ctx.grounded).clone();
    let mut request = (*base_ctx.request).clone();
    request.payload = payload_for_relation("causes");

    input.family = RelationFamily::Causes;
    input.registry.allowed_families = vec![RelationFamily::Causes];
    input.registry.denominator = vec![RelationFamily::Causes, RelationFamily::Contradicts];
    input.registry.rules[0].family = RelationFamily::Causes;
    input.registry.rules[0].requires_causal_mechanism = true;
    "rule-causes-v1".clone_into(&mut input.registry.rules[0].rule_ref);
    input.registry.rule_refs = vec!["rule-causes-v1".to_owned()];
    input.registry.digest = input.registry.computed_digest().expect("causal registry");
    input.item.payload = payload_for_relation("causes");
    input.item.receipt = receipt.clone();
    input.item.job_digest = sha256_hex(&canonical_bytes(&job).expect("causal job JSON"));
    input.evidence[0]
        .named
        .foundation_evidence_envelope
        .provenance
        .source_id = SourceId::new("source-a").expect("source");
    input.evidence[0]
        .named
        .foundation_evidence_envelope
        .provenance
        .raw_handle = Some("source-a".to_owned());
    input.evidence[0].named.external_grade = Some(
        relation_grade_binding_with_grade("evidence-1", EvidenceGrade::Corroborated).reference,
    );
    input.evidence[0].predicate.family = Some(RelationFamily::Causes);
    "causal fact source-a to target-b".clone_into(&mut input.evidence[0].predicate.expression);
    input.rivals[0] = relation_alternative(
        "rival-1",
        Some(RelationFamily::Contradicts),
        Some(RelationDirection::Forward),
        input.registry.digest.clone(),
        vec!["evidence-rival".to_owned()],
    );
    input.no_relation_alternative = Some(relation_alternative(
        "no-relation-1",
        None,
        None,
        input.registry.digest.clone(),
        vec!["evidence-none".to_owned()],
    ));
    let mut rival = input.evidence[0].clone();
    rival.named.id = id("evidence-rival");
    rival.named.external_grade = Some(
        relation_grade_binding_with_grade("evidence-rival", EvidenceGrade::Corroborated).reference,
    );
    rival.predicate.family = Some(RelationFamily::Contradicts);
    "rival fact contradicting the causal proposition".clone_into(&mut rival.predicate.expression);
    rival.polarity = RelationEvidencePolarity::Counter;
    input.counterevidence.push(rival);
    let mut no_relation = input.evidence[0].clone();
    no_relation.named.id = id("evidence-none");
    no_relation.named.external_grade = Some(relation_grade_binding("evidence-none").reference);
    no_relation.predicate.family = None;
    no_relation.predicate.direction = None;
    "no-relation alternative fact".clone_into(&mut no_relation.predicate.expression);
    no_relation.polarity = RelationEvidencePolarity::Counter;
    input.counterevidence.push(no_relation);
    input.disclosure_evidence = Some(disclosure(&input));
    causal_times(&mut input);
    let mut policy = causal_policy();
    policy.seal().expect("causal policy");
    input.policy_digest.clone_from(&policy.digest);
    let ctx = causal_context(
        &mut input, &base_ctx, job, bundle, receipt, grounded, request,
    );
    (input, policy, ctx)
}

fn causal_context(
    input: &mut RelationInput,
    base_ctx: &CurationAcceptanceCtx<'static>,
    job: DreamJobInput,
    bundle: DreamInputBundle,
    receipt: ValidationReceipt,
    grounded: GroundedDreamDraft,
    mut request: TypedCurationHandlerRequest,
) -> CurationAcceptanceCtx<'static> {
    let item_digest = input
        .item
        .item_digest(&grounded)
        .expect("causal item digest");
    let mut screen = (*base_ctx.screen).clone();
    screen.item_digest = item_digest;
    input.screen = screen.clone();
    let job_ref = Box::leak(Box::new(job));
    let bundle_ref = Box::leak(Box::new(bundle));
    let receipt_ref = Box::leak(Box::new(receipt));
    let grounded_ref = Box::leak(Box::new(grounded));
    let screen_ref = Box::leak(Box::new(screen));
    request.screen_binding = Some((*screen_ref).clone());
    let request_ref = Box::leak(Box::new(request));
    let usage_ref = Box::leak(Box::new(BudgetUsage::default()));
    CurationAcceptanceCtx {
        job: job_ref,
        bundle: bundle_ref,
        receipt: receipt_ref,
        screen: screen_ref,
        grounded: grounded_ref,
        request: request_ref,
        usage: usage_ref,
    }
}

fn snapshot(
    input: &RelationInput,
    relation_id: &str,
    family: RelationFamily,
    direction: RelationDirection,
    source: &str,
    target: &str,
) -> RelationSnapshot {
    RelationSnapshot {
        relation_id: relation_id.to_owned(),
        source_id: source.to_owned(),
        target_id: target.to_owned(),
        family,
        direction,
        scope_id: input.scope_id.clone(),
        registry_digest: input.registry.digest.clone(),
        relation_digest: digest("relation-external"),
        state_fence: input.state_fence.clone(),
        temporal: input.temporal.clone(),
        adapter_revision: "adapter-1".to_owned(),
        build_revision: "build-1".to_owned(),
        invalidation_condition: Some("endpoint digest changes".to_owned()),
        status: EpistemicStatus::Supported,
        lifecycle: LifecycleState::Active,
        provenance_refs: vec!["source-a".to_owned()],
        predecessor: None,
    }
}

#[test]
fn direct_positive_requires_current_disclosure() {
    let (input, policy, ctx) = prepared(fixtures().0);
    let result = propose_relation(input.clone(), &ctx, &policy).expect("positive relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    let mut refused = input;
    refused.disclosure_evidence = None;
    assert!(propose_relation(refused, &ctx, &policy).is_err());
}

#[test]
fn causal_claim_accepts_lower_ceiling_and_rejects_missing_proof() {
    let (input, policy, ctx) = causal_fixtures();
    let result = propose_relation(input.clone(), &ctx, &policy).expect("causal relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    result.validate().expect("sealed causal result");
    let mut missing = policy.clone();
    missing.causal_material = None;
    missing.seal().expect("reseal");
    let mut missing_input = input;
    missing_input.policy_digest = missing.digest.clone();
    assert!(propose_relation(missing_input, &ctx, &missing).is_err());
}

#[test]
fn permitted_path_and_forbidden_path_are_distinct() {
    let (mut input, mut policy, ctx) = prepared(fixtures().0);
    input.evidence.clear();
    input.registry.rules[0].permits_transitive = true;
    input.registry.digest = input.registry.computed_digest().expect("registry");
    input.rivals[0].registry_digest = input.registry.digest.clone();
    input
        .no_relation_alternative
        .as_mut()
        .expect("no relation")
        .registry_digest = input.registry.digest.clone();
    let edge_one_id = "edge-1";
    let edge_one = snapshot(
        &input,
        edge_one_id,
        input.family,
        input.direction,
        "source-a",
        "middle-c",
    );
    let edge_two_id = "edge-2";
    let edge_two = snapshot(
        &input,
        edge_two_id,
        input.family,
        input.direction,
        "middle-c",
        "target-b",
    );
    input
        .neighborhood
        .relations
        .extend([edge_one.clone(), edge_two.clone()]);
    policy.transitive_path = vec![
        eliot_dreamer_relation::PathRef {
            edge_id: edge_one_id.to_owned(),
            relation_digest: edge_one.relation_digest.clone(),
        },
        eliot_dreamer_relation::PathRef {
            edge_id: edge_two_id.to_owned(),
            relation_digest: edge_two.relation_digest.clone(),
        },
    ];
    policy.seal().expect("policy");
    input.policy_digest.clone_from(&policy.digest);
    propose_relation(input.clone(), &ctx, &policy).expect("permitted transitive path");
    let mut forbidden = policy;
    forbidden.transitive_path[0].relation_digest = edge_one.relation_digest;
    input.registry.rules[0].permits_transitive = false;
    input.registry.digest = input.registry.computed_digest().expect("registry");
    input.rivals[0].registry_digest = input.registry.digest.clone();
    input
        .no_relation_alternative
        .as_mut()
        .expect("no relation")
        .registry_digest = input.registry.digest.clone();
    for edge in &mut input.neighborhood.relations {
        edge.registry_digest = input.registry.digest.clone();
    }
    forbidden.seal().expect("policy");
    input.policy_digest = forbidden.digest.clone();
    assert!(propose_relation(input, &ctx, &forbidden).is_err());
}

#[test]
fn duplicate_inverse_and_changed_snapshot_are_retained() {
    let (mut input, mut policy, ctx) = prepared(fixtures().0);
    let id = "external-retained";
    let existing = snapshot(
        &input,
        id,
        input.family,
        input.direction,
        "source-a",
        "target-b",
    );
    input.neighborhood.relations.push(existing.clone());
    policy.proposed_snapshot = Some(existing.clone());
    policy.seal().expect("policy");
    input.policy_digest.clone_from(&policy.digest);
    let result = propose_relation(input.clone(), &ctx, &policy).expect("duplicate");
    assert_eq!(result.disposition, RelationDisposition::Duplicate);
    assert_eq!(result.closure.candidate.relation_id, id);
    let mut changed = existing;
    changed.relation_digest = digest("changed");
    let mut conflict = policy;
    conflict.proposed_snapshot = Some(changed);
    conflict.seal().expect("policy");
    input.policy_digest = conflict.digest.clone();
    assert_eq!(
        propose_relation(input, &ctx, &conflict)
            .expect("conflict")
            .disposition,
        RelationDisposition::Conflict
    );

    let (mut inverse_input, inverse_policy, inverse_ctx) = prepared(fixtures().0);
    let inverse = snapshot(
        &inverse_input,
        "inverse-retained",
        RelationFamily::Contradicts,
        RelationDirection::Forward,
        "target-b",
        "source-a",
    );
    inverse_input.neighborhood.relations.push(inverse.clone());
    inverse_input.policy_digest = inverse_policy.digest.clone();
    let inverse_result =
        propose_relation(inverse_input, &inverse_ctx, &inverse_policy).expect("inverse relation");
    assert_eq!(inverse_result.disposition, RelationDisposition::Inverse);
    assert_eq!(
        inverse_result.closure.candidate.before.as_ref(),
        Some(&inverse)
    );

    let (mut symmetric_input, symmetric_policy, symmetric_ctx) = prepared(fixtures().0);
    symmetric_input.registry.rules[0].symmetric = true;
    symmetric_input.registry.rules[0].inverse_family = None;
    symmetric_input.registry.digest = symmetric_input
        .registry
        .computed_digest()
        .expect("symmetric registry");
    symmetric_input.rivals[0].registry_digest = symmetric_input.registry.digest.clone();
    symmetric_input
        .no_relation_alternative
        .as_mut()
        .expect("no relation")
        .registry_digest = symmetric_input.registry.digest.clone();
    let symmetric = snapshot(
        &symmetric_input,
        "symmetric-retained",
        RelationFamily::Supports,
        RelationDirection::Forward,
        "target-b",
        "source-a",
    );
    symmetric_input
        .neighborhood
        .relations
        .push(symmetric.clone());
    symmetric_input.policy_digest = symmetric_policy.digest.clone();
    let symmetric_result = propose_relation(symmetric_input, &symmetric_ctx, &symmetric_policy)
        .expect("symmetric relation");
    assert_eq!(symmetric_result.disposition, RelationDisposition::Ambiguous);
    assert_eq!(
        symmetric_result.closure.candidate.before.as_ref(),
        Some(&symmetric)
    );
}

#[test]
fn replay_permutation_bounds_and_cancel_are_explicit() {
    let (input, mut policy, ctx) = prepared(fixtures().0);
    let first = propose_relation(input.clone(), &ctx, &policy).expect("first replay");
    first.validate().expect("first sealed replay");
    let digest_before = policy.digest.clone();
    policy.grade_bindings.reverse();
    policy.expected_alternative_refs.reverse();
    policy.seal().expect("normalized policy");
    assert_eq!(digest_before, policy.digest);
    let second = propose_relation(input.clone(), &ctx, &policy).expect("second replay");
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(first.closure.result_digest, second.closure.result_digest);
    let mut permuted_input = input.clone();
    permuted_input.counterevidence.reverse();
    permuted_input.policy_digest.clone_from(&policy.digest);
    let permuted = propose_relation(permuted_input, &ctx, &policy).expect("permuted replay");
    assert_eq!(first.result_digest, permuted.result_digest);
    assert_eq!(first.closure.result_digest, permuted.closure.result_digest);
    let mut cancelled = policy.clone();
    cancelled.cancellation_requested = true;
    cancelled.seal().expect("cancel");
    let mut cancelled_input = input.clone();
    cancelled_input.policy_digest = cancelled.digest.clone();
    assert!(propose_relation(cancelled_input, &ctx, &cancelled).is_err());
    let mut bounded = policy;
    bounded.max_evidence = 1;
    bounded.seal().expect("bound");
    let mut bounded_input = input;
    bounded_input.policy_digest = bounded.digest.clone();
    assert!(propose_relation(bounded_input, &ctx, &bounded).is_err());
}
