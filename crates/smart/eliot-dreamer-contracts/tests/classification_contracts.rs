//! Public proofs for neutral classification input and candidate contracts.
#![allow(clippy::expect_used)]
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, SourceId,
    StateFence, TaskId,
};
use eliot_dreamer_contracts::curation::{ClassificationPayload, TargetEvidence};
use eliot_dreamer_contracts::*;
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};
use std::num::NonZeroU64;

fn id(v: &str) -> ArtifactId {
    ArtifactId::new(v).expect("fixture id")
}
fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}
fn digest(v: &str) -> String {
    eliot_contracts::sha256_hex(v.as_bytes())
}
fn preservation() -> ClassificationPreservation {
    let ds = [
        ClassificationPreservationDimension::Coverage,
        ClassificationPreservationDimension::Preservation,
        ClassificationPreservationDimension::Faithfulness,
        ClassificationPreservationDimension::Lineage,
        ClassificationPreservationDimension::Reversibility,
        ClassificationPreservationDimension::SourceAuthority,
        ClassificationPreservationDimension::DependencyClosure,
    ];
    ClassificationPreservation {
        verdicts: ds
            .into_iter()
            .map(|dimension| ClassificationPreservationVerdict {
                dimension,
                passed: true,
                known: true,
                note: "checked".to_owned(),
            })
            .collect(),
    }
}
fn taxonomy() -> TaxonomyDenominator {
    let criteria = vec![
        GroundedCriterion {
            criterion_id: id("criterion-1"),
            role: ClassificationCriterionRole::Sufficient,
            applicability: CriterionApplicability::Required,
            evidence_refs: vec![id("e-1")],
            rationale: "cache hit discriminator".to_owned(),
        },
        GroundedCriterion {
            criterion_id: id("criterion-2"),
            role: ClassificationCriterionRole::Necessary,
            applicability: CriterionApplicability::Required,
            evidence_refs: vec![id("e-2")],
            rationale: "cache miss discriminator".to_owned(),
        },
    ];
    let alternatives = vec![
        TaxonomyAlternative {
            alternative_id: id("alternative-a"),
            family: ClassificationRecordFamily::Interpretation,
            subtype_ref: Some("cache-hit".to_owned()),
            criterion_refs: vec![id("criterion-1")],
            evidence_refs: vec![id("e-1")],
            counterevidence_refs: Vec::new(),
        },
        TaxonomyAlternative {
            alternative_id: id("alternative-b"),
            family: ClassificationRecordFamily::Interpretation,
            subtype_ref: Some("cache-miss".to_owned()),
            criterion_refs: vec![id("criterion-2")],
            evidence_refs: vec![id("e-2")],
            counterevidence_refs: vec![id("e-1")],
        },
    ];
    let mut t = TaxonomyDenominator {
        owner: "taxonomy-owner".to_owned(),
        schema: "classification-taxonomy-v1".to_owned(),
        revision: "revision-1".to_owned(),
        digest: "0".repeat(64),
        coverage: TaxonomyCoverage::Complete,
        declared_families: vec![ClassificationRecordFamily::Interpretation],
        declared_alternative_ids: vec![id("alternative-a"), id("alternative-b")],
        provided_alternative_ids: vec![id("alternative-a"), id("alternative-b")],
        omitted_alternative_ids: Vec::new(),
        alternatives,
        criteria,
        missing_criteria: Vec::new(),
        alias_mappings: Vec::new(),
    };
    t.digest = t.computed_digest().expect("taxonomy digest");
    t
}
fn job() -> DreamJobAdmission {
    DreamJobAdmission {
        schema_version: 1,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "op-44".to_owned(),
        idempotency_key: "idem-44".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "contract-1".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(1024 * 1024),
            output_bytes: Some(512 * 1024),
            source_width: Some(32),
            reference_width: Some(32),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(1000),
            work_fan_out: Some(2),
            report_bytes: Some(1024),
            max_stu: Some(10),
        },
        deadline_ms: None,
        frozen_manifest_digest: "f".repeat(64),
    }
}
fn bundle() -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: "job-44".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        manifest_digest: "f".repeat(64),
        materials: vec![BundleMaterial {
            handle: "a".to_owned(),
            disposition: SourceDisposition::Required,
            bytes: 12,
            digest: "a".repeat(64),
        }],
        omissions: vec![OmissionHandle {
            handle: "e-1".to_owned(),
            reason: "owner evidence".to_owned(),
            reversible: true,
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            digest: "e".repeat(64),
            nonrecoverable_reason: None,
        }],
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    }
}
fn grounded() -> GroundedDreamDraft {
    GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-44".to_owned(),
        draft_digest: "a".repeat(64),
        residues: vec![
            ClaimResidue {
                claim: "cache hit".to_owned(),
                state: SupportState::Supported,
                detail: "observed hit discriminator".to_owned(),
            },
            ClaimResidue {
                claim: "cache miss".to_owned(),
                state: SupportState::Contradicted,
                detail: "miss discriminator absent".to_owned(),
            },
        ],
        coverage_note: "covered".to_owned(),
    }
}
fn receipt() -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".to_owned(),
        validator_policy: "policy-7".to_owned(),
        job_id: "job-44".to_owned(),
        draft_digest: "a".repeat(64),
        bundle_digest: "f".repeat(64),
        manifest_digest: "f".repeat(64),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: "b".repeat(64),
        output_digest: "c".repeat(64),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: "d".repeat(64),
        budget_digest: "e".repeat(64),
    }
}
fn payload() -> CurationPayload {
    CurationPayload::Classification(ClassificationPayload {
        label: "classification".to_owned(),
        confidence_bps: 100,
        target_evidence: TargetEvidence {
            targets: vec!["a".to_owned()],
            evidence_refs: vec!["e-1".to_owned()],
        },
    })
}

fn classification_evidence() -> Vec<NamedEvidence> {
    vec![
        NamedEvidence {
            id: id("e-1"),
            foundation_evidence_envelope: EvidenceEnvelope {
                authority: EvidenceAuthority::DeterministicRuntimeTest,
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
                status: EpistemicStatus::Supported,
                assertability: Assertability::Assertable,
                provenance: Provenance {
                    source_id: SourceId::new("source-1").expect("source"),
                    capture_route: "route-1".to_owned(),
                    scope: "scope-1".to_owned(),
                    raw_handle: Some("a".to_owned()),
                    revision: Some("rev-1".to_owned()),
                },
                verification: None,
                state_fence: fence(),
            },
            source_handles: vec![id("a")],
            dependence_groups: vec!["group-1".to_owned()],
            external_grade: Some(ExternalGradeRef {
                owner: "eliot.c1.epistemic-contracts".to_owned(),
                schema: "evidence-grade-v1".to_owned(),
                revision: "1".to_owned(),
                record_id: id("grade-1"),
                digest: digest("grade"),
            }),
        },
        NamedEvidence {
            id: id("e-2"),
            foundation_evidence_envelope: EvidenceEnvelope {
                authority: EvidenceAuthority::DeterministicRuntimeTest,
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
                status: EpistemicStatus::Supported,
                assertability: Assertability::Assertable,
                provenance: Provenance {
                    source_id: SourceId::new("source-1").expect("source"),
                    capture_route: "route-1".to_owned(),
                    scope: "scope-1".to_owned(),
                    raw_handle: Some("a".to_owned()),
                    revision: Some("rev-1".to_owned()),
                },
                verification: None,
                state_fence: fence(),
            },
            source_handles: vec![id("a")],
            dependence_groups: vec!["group-1".to_owned()],
            external_grade: Some(ExternalGradeRef {
                owner: "eliot.c1.epistemic-contracts".to_owned(),
                schema: "evidence-grade-v1".to_owned(),
                revision: "1".to_owned(),
                record_id: id("grade-2"),
                digest: digest("grade-2"),
            }),
        },
    ]
}

fn classification_features() -> Vec<FeatureObservation> {
    vec![
        FeatureObservation {
            feature_id: id("feature-1"),
            criterion_id: id("criterion-1"),
            applicability: CriterionApplicability::Required,
            value: Some(true),
            status: CriterionStatus::Supported,
            evidence_refs: vec![id("e-1")],
        },
        FeatureObservation {
            feature_id: id("feature-2"),
            criterion_id: id("criterion-2"),
            applicability: CriterionApplicability::Required,
            value: Some(false),
            status: CriterionStatus::Contradicted,
            evidence_refs: vec![id("e-2")],
        },
    ]
}

fn fixtures() -> (ClassificationInput, CurationAcceptanceCtx<'static>) {
    let job_ref = Box::leak(Box::new(job()));
    let bundle_ref = Box::leak(Box::new(bundle()));
    let grounded_ref = Box::leak(Box::new(grounded()));
    let receipt_ref = Box::leak(Box::new(receipt()));
    let job_digest =
        eliot_contracts::sha256_hex(&canonical_bytes(&*job_ref).expect("job canonical JSON"));
    let item = ValidatedCurationItem {
        receipt: receipt_ref.clone(),
        kind_spelling: "classification".to_owned(),
        family_spelling: "classification".to_owned(),
        payload: payload(),
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["a".to_owned()],
            expected_total: 1,
        },
        source_digest: "a".repeat(64),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        job_digest,
        requester: job_ref.requester.clone(),
        budget_note: "within limits".to_owned(),
    };
    let item_digest = item.item_digest(grounded_ref).expect("item digest");
    let screen_ref = Box::leak(Box::new(ScreenBinding {
        request_id: RequestId::new("req-44").expect("request"),
        receipt_id: ReceiptId::new("screen-44").expect("receipt"),
        screened_targets: vec!["a".to_owned()],
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: "c".repeat(64),
        item_digest,
    }));
    let req = Box::leak(Box::new(TypedCurationHandlerRequest {
        request_id: "req-44".to_owned(),
        receipt_id: "screen-44".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        kind: CurationKind::Classification,
        family: CurationFamily::Classification,
        job_id: "job-44".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        payload: payload(),
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["a".to_owned()],
            expected_total: 1,
        },
        screen_binding: Some(screen_ref.clone()),
    }));
    let usage_ref = Box::leak(Box::new(BudgetUsage::default()));
    let ctx = CurationAcceptanceCtx {
        job: job_ref,
        bundle: bundle_ref,
        receipt: receipt_ref,
        screen: screen_ref,
        grounded: grounded_ref,
        request: req,
        usage: usage_ref,
    };
    let input = ClassificationInput {
        schema_version: 1,
        operation_id: id("op-44"),
        request_id: "req-44".to_owned(),
        idempotency_key: "idem-44".to_owned(),
        target: AdmittedTargetRef {
            target_id: id("a"),
            target_revision: "rev-1".to_owned(),
            target_digest: "a".repeat(64),
            admission: ReceiptIdentity {
                receipt_id: ReceiptId::new("admission-1").expect("receipt"),
                canonical_sha256: "1".repeat(64),
            },
            lifecycle: LifecycleState::Active,
            freshness: EvidenceFreshness::ExactCandidate,
            task_id: TaskId::new("task-1").expect("task"),
            scope_id: WorkScopeId::new("scope-1").expect("scope"),
            state_fence: fence(),
            source_handles: vec![id("a")],
        },
        item,
        screen: (*ctx.screen).clone(),
        evidence: classification_evidence(),
        features: classification_features(),
        taxonomy: taxonomy(),
        prior_assignment: None,
        preservation: preservation(),
        policy_digest: digest("policy-1"),
    };
    (input, ctx)
}
fn candidate(input: &ClassificationInput) -> ClassificationCandidate {
    let id_a = id("alternative-a");
    let input_digest = classification_input_digest(input).expect("input digest");
    ClassificationCandidate {
        candidate_id: ClassificationCandidate::expected_candidate_id(
            "op-44",
            &input_digest,
            &input.policy_digest,
            Some(&id_a),
        ),
        operation_id: id("op-44"),
        input_digest,
        policy_digest: input.policy_digest.clone(),
        kind: CurationKind::Classification,
        target_id: id("a"),
        target_revision: "rev-1".to_owned(),
        selected_alternative_id: Some(id_a),
        sole_legal_alternative_proof: false,
        family_ref: "interpretation".to_owned(),
        subtype_ref: Some("cache-hit".to_owned()),
        disposition: CandidateDisposition::Candidate,
        alternatives: input.taxonomy.declared_alternative_ids.clone(),
        source_handles: vec![id("a")],
        evidence_refs: vec![id("e-1")],
        counterevidence_refs: vec![id("e-2")],
        before: ClassificationAssignmentSnapshot {
            alternative_id: None,
            family_ref: None,
            subtype_ref: None,
            assignment_digest: None,
        },
        after: ClassificationAssignmentSnapshot {
            alternative_id: Some(id("alternative-a")),
            family_ref: Some("interpretation".to_owned()),
            subtype_ref: Some("cache-hit".to_owned()),
            assignment_digest: None,
        },
        rollback: ClassificationRollback {
            target_id: id("a"),
            predecessor: None,
            rollback_handles: vec![id("a")],
            invalidation_handles: vec![id("a")],
            raw_history_handles: vec![id("a")],
            note: "reopen target history".to_owned(),
        },
        preservation: input.preservation.clone(),
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

#[test]
fn supplied_positive_candidate_seals_and_roundtrips() {
    let (input, ctx) = fixtures();
    let supplied_candidate = candidate(&input);
    let closure = seal_classification(input, supplied_candidate, &ctx).expect("seal");
    closure.validate().expect("validate");
    let bytes = serde_json::to_vec(&closure).expect("JSON");
    let decoded: ClassificationCandidateClosure =
        serde_json::from_slice(&bytes).expect("roundtrip");
    decoded.validate().expect("decoded");
}
#[test]
fn input_and_result_set_permutations_preserve_identity() {
    let (input, ctx) = fixtures();
    let supplied_candidate = candidate(&input);
    let first =
        seal_classification(input.clone(), supplied_candidate.clone(), &ctx).expect("first");
    let mut permuted_input = input;
    permuted_input.taxonomy.alternatives.reverse();
    permuted_input.taxonomy.declared_alternative_ids.reverse();
    permuted_input.taxonomy.provided_alternative_ids.reverse();
    permuted_input.evidence.reverse();
    permuted_input.preservation.verdicts.reverse();
    let mut permuted_candidate = supplied_candidate;
    permuted_candidate.alternatives.reverse();
    permuted_candidate.preservation.verdicts.reverse();
    let second = seal_classification(permuted_input, permuted_candidate, &ctx).expect("second");
    assert_eq!(first.input_digest, second.input_digest);
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(
        first.canonical_bytes().expect("first canonical bytes"),
        second.canonical_bytes().expect("second canonical bytes")
    );
}
#[test]
fn target_or_preservation_drift_is_rejected() {
    let (input, ctx) = fixtures();
    let mut bad = candidate(&input);
    bad.target_revision = "drift".to_owned();
    assert!(validate_classification(&input, &bad, &ctx).is_err());
    let mut bad = candidate(&input);
    bad.preservation.verdicts[1].known = false;
    assert!(validate_classification(&input, &bad, &ctx).is_err());
}
#[test]
fn exact_roles_and_bounded_denominator_are_fail_closed() {
    for (role, spelling) in [
        (ClassificationCriterionRole::Necessary, "necessary"),
        (ClassificationCriterionRole::Sufficient, "sufficient"),
        (
            ClassificationCriterionRole::Characteristic,
            "characteristic",
        ),
        (ClassificationCriterionRole::Exclusion, "exclusion"),
    ] {
        assert_eq!(
            serde_json::to_string(&role).expect("role JSON"),
            format!("\"{spelling}\"")
        );
    }
    let mut oversized = taxonomy();
    oversized.declared_alternative_ids =
        (0..257).map(|n| id(&format!("alternative-{n}"))).collect();
    assert!(oversized.validate().is_err());
}
#[test]
fn partial_unknown_input_roundtrips_as_abstention() {
    let (mut input, ctx) = fixtures();
    input.preservation.verdicts[1].known = false;
    let mut abstention_candidate = candidate(&input);
    abstention_candidate.disposition = CandidateDisposition::Abstention;
    abstention_candidate.selected_alternative_id = None;
    abstention_candidate.family_ref = "unresolved".to_owned();
    abstention_candidate.subtype_ref = None;
    abstention_candidate.after = ClassificationAssignmentSnapshot {
        alternative_id: None,
        family_ref: None,
        subtype_ref: None,
        assignment_digest: None,
    };
    abstention_candidate.candidate_id = ClassificationCandidate::expected_candidate_id(
        "op-44",
        &abstention_candidate.input_digest,
        &abstention_candidate.policy_digest,
        None,
    );
    let closure = seal_classification(input, abstention_candidate, &ctx).expect("abstention seals");
    closure.validate().expect("abstention validates");
}

#[test]
fn prior_assignment_closure_is_retained_and_drift_rejected() {
    let (mut input, ctx) = fixtures();
    let prior = PriorAssignmentRef {
        assignment_id: id("assignment-1"),
        selected_alternative_id: Some(id("alternative-a")),
        selected_family: Some("interpretation".to_owned()),
        selected_subtype: Some("cache-hit".to_owned()),
        target_id: id("a"),
        target_revision: "rev-1".to_owned(),
        assignment_digest: digest("prior-1"),
        predecessor: Some(id("assignment-0")),
        source_handles: vec![id("a")],
        status: EpistemicStatus::Supported,
        lifecycle: LifecycleState::Active,
        receipt: None,
    };
    input.prior_assignment = Some(prior.clone());
    let mut supplied = candidate(&input);
    supplied.before = ClassificationAssignmentSnapshot {
        alternative_id: prior.selected_alternative_id.clone(),
        family_ref: prior.selected_family.clone(),
        subtype_ref: prior.selected_subtype.clone(),
        assignment_digest: Some(prior.assignment_digest.clone()),
    };
    supplied.rollback.predecessor = Some(prior.assignment_id.clone());
    let closure = seal_classification(input.clone(), supplied.clone(), &ctx).expect("prior seals");
    closure.validate().expect("prior validates");
    let bytes = serde_json::to_vec(&closure).expect("JSON");
    let decoded: ClassificationCandidateClosure =
        serde_json::from_slice(&bytes).expect("roundtrip");
    decoded.validate().expect("decoded prior validates");
    assert_eq!(decoded.input.prior_assignment, Some(prior));
    assert_eq!(decoded.candidate.before, supplied.before);
    assert_eq!(decoded.candidate.counterevidence_refs, vec![id("e-2")]);
    assert_eq!(decoded.candidate.rollback.raw_history_handles, vec![id("a")]);
    assert_eq!(
        decoded.input.evidence[0].dependence_groups,
        vec!["group-1".to_owned()]
    );
    let mut drifted = input.clone();
    drifted
        .prior_assignment
        .as_mut()
        .expect("prior")
        .target_revision = "rev-2".to_owned();
    assert!(validate_classification(&drifted, &supplied, &ctx).is_err());
    let (plain_input, plain_ctx) = fixtures();
    let mut invented = candidate(&plain_input);
    invented.before = ClassificationAssignmentSnapshot {
        alternative_id: Some(id("alternative-a")),
        family_ref: Some("interpretation".to_owned()),
        subtype_ref: Some("cache-hit".to_owned()),
        assignment_digest: Some(digest("prior-1")),
    };
    invented.rollback.predecessor = Some(id("assignment-1"));
    assert!(validate_classification(&plain_input, &invented, &plain_ctx).is_err());
}

#[test]
fn acceptance_joins_alias_refinement_and_digests_are_fail_closed() {
    let (input, ctx) = fixtures();
    let mut aliased = input.clone();
    aliased.taxonomy.alias_mappings = vec![TaxonomyAliasMapping {
        alias_id: id("alias-x"),
        canonical_alternative_id: id("alternative-a"),
        refinement_of: Some(id("alternative-b")),
    }];
    aliased.taxonomy.digest = aliased
        .taxonomy
        .computed_digest()
        .expect("alias digest");
    aliased.validate().expect("aliased input validates");
    let aliased_candidate = candidate(&aliased);
    let closure =
        seal_classification(aliased.clone(), aliased_candidate, &ctx).expect("alias seals");
    closure.validate().expect("alias closure validates");
    let mut bad = input.clone();
    bad.taxonomy.alias_mappings = vec![TaxonomyAliasMapping {
        alias_id: id("alternative-a"),
        canonical_alternative_id: id("alternative-b"),
        refinement_of: None,
    }];
    assert!(bad.taxonomy.validate().is_err());
    let mut bad = input.clone();
    bad.taxonomy.alias_mappings = vec![TaxonomyAliasMapping {
        alias_id: id("alias-y"),
        canonical_alternative_id: id("missing-alt"),
        refinement_of: None,
    }];
    assert!(bad.taxonomy.validate().is_err());
    let mut bad = input.clone();
    bad.taxonomy.alias_mappings = vec![TaxonomyAliasMapping {
        alias_id: id("alias-z"),
        canonical_alternative_id: id("alternative-a"),
        refinement_of: Some(id("missing-parent")),
    }];
    assert!(bad.taxonomy.validate().is_err());
    let mut bad = input.clone();
    bad.taxonomy.revision = "revision-2".to_owned();
    assert!(bad.validate().is_err());
    let supplied = candidate(&input);
    let screen_mismatch = ScreenBinding {
        result_digest: "d".repeat(64),
        ..(*ctx.screen).clone()
    };
    let bad_ctx = CurationAcceptanceCtx {
        job: ctx.job,
        bundle: ctx.bundle,
        receipt: ctx.receipt,
        screen: Box::leak(Box::new(screen_mismatch)),
        grounded: ctx.grounded,
        request: ctx.request,
        usage: ctx.usage,
    };
    assert!(validate_classification(&input, &supplied, &bad_ctx).is_err());
    let mut bundle_mismatch = (*ctx.bundle).clone();
    bundle_mismatch.materials[0].digest = "b".repeat(64);
    let bad_ctx = CurationAcceptanceCtx {
        job: ctx.job,
        bundle: Box::leak(Box::new(bundle_mismatch)),
        receipt: ctx.receipt,
        screen: ctx.screen,
        grounded: ctx.grounded,
        request: ctx.request,
        usage: ctx.usage,
    };
    assert!(validate_classification(&input, &supplied, &bad_ctx).is_err());
    let mut job_mismatch = (*ctx.job).clone();
    job_mismatch.operation_id = "op-99".to_owned();
    let bad_ctx = CurationAcceptanceCtx {
        job: Box::leak(Box::new(job_mismatch)),
        bundle: ctx.bundle,
        receipt: ctx.receipt,
        screen: ctx.screen,
        grounded: ctx.grounded,
        request: ctx.request,
        usage: ctx.usage,
    };
    assert!(validate_classification(&input, &supplied, &bad_ctx).is_err());
}

#[test]
fn preservation_coverage_rival_and_rollback_gate_complete_candidate() {
    let (input, ctx) = fixtures();
    let mut failed = input.clone();
    failed.preservation.verdicts[0].passed = false;
    let mut failed_candidate = candidate(&failed);
    assert!(validate_classification(&failed, &failed_candidate, &ctx).is_err());
    failed_candidate.disposition = CandidateDisposition::Abstention;
    failed_candidate.selected_alternative_id = None;
    failed_candidate.family_ref = "unresolved".to_owned();
    failed_candidate.subtype_ref = None;
    failed_candidate.after = ClassificationAssignmentSnapshot {
        alternative_id: None,
        family_ref: None,
        subtype_ref: None,
        assignment_digest: None,
    };
    failed_candidate.candidate_id = ClassificationCandidate::expected_candidate_id(
        "op-44",
        &failed_candidate.input_digest,
        &failed_candidate.policy_digest,
        None,
    );
    let closure =
        seal_classification(failed.clone(), failed_candidate, &ctx).expect("failed abstention");
    closure.validate().expect("failed abstention validates");
    let mut partial = input.clone();
    partial.taxonomy.coverage = TaxonomyCoverage::Partial;
    partial.taxonomy.digest = partial
        .taxonomy
        .computed_digest()
        .expect("partial digest");
    let partial_candidate = candidate(&partial);
    assert!(validate_classification(&partial, &partial_candidate, &ctx).is_err());
    let mut single = input.clone();
    single.taxonomy.alternatives.truncate(1);
    single.taxonomy.declared_alternative_ids.truncate(1);
    single.taxonomy.provided_alternative_ids.truncate(1);
    single.taxonomy.digest = single.taxonomy.computed_digest().expect("single digest");
    let mut single_candidate = candidate(&single);
    assert!(validate_classification(&single, &single_candidate, &ctx).is_err());
    single_candidate.sole_legal_alternative_proof = true;
    let closure =
        seal_classification(single.clone(), single_candidate, &ctx).expect("sole proof seals");
    closure.validate().expect("sole proof validates");
    let mut no_rollback = candidate(&input);
    no_rollback.rollback.rollback_handles.clear();
    assert!(validate_classification(&input, &no_rollback, &ctx).is_err());
    let mut dup = input.clone();
    dup.preservation.verdicts[0].dimension = dup.preservation.verdicts[1].dimension;
    assert!(dup.preservation.validate().is_err());
    let mut replaced = candidate(&input);
    replaced.preservation.verdicts[0].passed = false;
    assert!(validate_classification(&input, &replaced, &ctx).is_err());
}

#[test]
fn material_change_changes_identity_and_incompatible_selection_rejected() {
    let (input, ctx) = fixtures();
    let supplied = candidate(&input);
    let closure = seal_classification(input.clone(), supplied.clone(), &ctx).expect("seal");
    closure.validate().expect("validate");
    let mut changed = supplied.clone();
    changed.selected_alternative_id = Some(id("alternative-b"));
    changed.family_ref = "interpretation".to_owned();
    changed.subtype_ref = Some("cache-miss".to_owned());
    changed.after = ClassificationAssignmentSnapshot {
        alternative_id: Some(id("alternative-b")),
        family_ref: Some("interpretation".to_owned()),
        subtype_ref: Some("cache-miss".to_owned()),
        assignment_digest: None,
    };
    changed.candidate_id = ClassificationCandidate::expected_candidate_id(
        "op-44",
        &changed.input_digest,
        &changed.policy_digest,
        changed.selected_alternative_id.as_ref(),
    );
    assert_ne!(changed.candidate_id, supplied.candidate_id);
    let changed_closure =
        seal_classification(input.clone(), changed, &ctx).expect("changed seals");
    assert_ne!(
        changed_closure.result_digest,
        closure.result_digest
    );
    let mut changed_input = input.clone();
    changed_input.evidence[0].dependence_groups = vec!["group-2".to_owned()];
    let changed_digest = classification_input_digest(&changed_input).expect("changed digest");
    assert_ne!(changed_digest, supplied.input_digest);
    let mut unknown = input.clone();
    unknown.features[0].value = None;
    unknown.features[0].status = CriterionStatus::Unknown;
    let unknown_candidate = candidate(&unknown);
    let unknown_closure =
        seal_classification(unknown.clone(), unknown_candidate, &ctx).expect("unknown seals");
    unknown_closure.validate().expect("unknown validates");
    let mut conflict_candidate = candidate(&input);
    conflict_candidate.disposition = CandidateDisposition::Conflict;
    let conflict_closure =
        seal_classification(input.clone(), conflict_candidate, &ctx).expect("conflict seals");
    conflict_closure.validate().expect("conflict validates");
    let mut bad = candidate(&input);
    bad.selected_alternative_id = Some(id("missing-alt"));
    bad.candidate_id = ClassificationCandidate::expected_candidate_id(
        "op-44",
        &bad.input_digest,
        &bad.policy_digest,
        bad.selected_alternative_id.as_ref(),
    );
    assert!(validate_classification(&input, &bad, &ctx).is_err());
    let mut bad = candidate(&input);
    bad.family_ref = "source_record".to_owned();
    assert!(validate_classification(&input, &bad, &ctx).is_err());
    let mut bad = candidate(&input);
    bad.after = ClassificationAssignmentSnapshot {
        alternative_id: Some(id("alternative-b")),
        family_ref: Some("interpretation".to_owned()),
        subtype_ref: Some("cache-miss".to_owned()),
        assignment_digest: None,
    };
    assert!(validate_classification(&input, &bad, &ctx).is_err());
    let mut bad = candidate(&input);
    bad.selected_alternative_id = None;
    bad.family_ref = "unresolved".to_owned();
    bad.subtype_ref = None;
    bad.after = ClassificationAssignmentSnapshot {
        alternative_id: None,
        family_ref: None,
        subtype_ref: None,
        assignment_digest: None,
    };
    bad.candidate_id = ClassificationCandidate::expected_candidate_id(
        "op-44",
        &bad.input_digest,
        &bad.policy_digest,
        None,
    );
    assert!(validate_classification(&input, &bad, &ctx).is_err());
}
