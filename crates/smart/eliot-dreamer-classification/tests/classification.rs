#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, SourceId,
    StateFence, TaskId,
};
use eliot_dreamer_classification::{
    ClassificationDisposition, ClassificationPolicy, EvidenceGradeBinding, classify,
    grade_binding_digest,
};
use eliot_dreamer_contracts::*;
use eliot_epistemic_contracts::{EvidenceGrade, GradeAssignment};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};
use std::num::NonZeroU64;

fn id(v: &str) -> ArtifactId {
    ArtifactId::new(v).expect("id")
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
fn hash(v: &str) -> String {
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
fn evidence(idv: &str) -> NamedEvidence {
    NamedEvidence {
        id: id(idv),
        foundation_evidence_envelope: EvidenceEnvelope {
            authority: EvidenceAuthority::DeterministicRuntimeTest,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Supported,
            assertability: Assertability::Assertable,
            provenance: Provenance {
                source_id: SourceId::new("source").expect("source"),
                capture_route: "route".to_owned(),
                scope: "scope".to_owned(),
                raw_handle: Some("target".to_owned()),
                revision: Some("rev".to_owned()),
            },
            verification: None,
            state_fence: fence(),
        },
        source_handles: vec![id("target")],
        dependence_groups: vec!["same-route".to_owned()],
        external_grade: None,
    }
}
fn taxonomy() -> TaxonomyDenominator {
    let criteria = vec![
        GroundedCriterion {
            criterion_id: id("necessary-a"),
            role: ClassificationCriterionRole::Necessary,
            applicability: CriterionApplicability::Required,
            evidence_refs: vec![id("e1")],
            rationale: "required discriminator".to_owned(),
        },
        GroundedCriterion {
            criterion_id: id("sufficient-a"),
            role: ClassificationCriterionRole::Sufficient,
            applicability: CriterionApplicability::Required,
            evidence_refs: vec![id("e1")],
            rationale: "positive discriminator".to_owned(),
        },
        GroundedCriterion {
            criterion_id: id("necessary-b"),
            role: ClassificationCriterionRole::Necessary,
            applicability: CriterionApplicability::Required,
            evidence_refs: vec![id("e2")],
            rationale: "rival discriminator".to_owned(),
        },
    ];
    let alternatives = vec![
        TaxonomyAlternative {
            alternative_id: id("alt-a"),
            family: ClassificationRecordFamily::Interpretation,
            subtype_ref: Some("known-a".to_owned()),
            criterion_refs: vec![id("necessary-a"), id("sufficient-a")],
            evidence_refs: vec![id("e1")],
            counterevidence_refs: vec![id("e2")],
        },
        TaxonomyAlternative {
            alternative_id: id("alt-b"),
            family: ClassificationRecordFamily::Interpretation,
            subtype_ref: Some("known-b".to_owned()),
            criterion_refs: vec![id("necessary-b")],
            evidence_refs: vec![id("e2")],
            counterevidence_refs: vec![id("e1")],
        },
    ];
    let mut value = TaxonomyDenominator {
        owner: "owner".to_owned(),
        schema: "taxonomy-v1".to_owned(),
        revision: "rev-1".to_owned(),
        digest: "0".repeat(64),
        coverage: TaxonomyCoverage::Complete,
        declared_families: vec![ClassificationRecordFamily::Interpretation],
        declared_alternative_ids: vec![id("alt-a"), id("alt-b")],
        provided_alternative_ids: vec![id("alt-a"), id("alt-b")],
        omitted_alternative_ids: vec![],
        alternatives,
        criteria,
        missing_criteria: vec![],
        alias_mappings: vec![],
    };
    value.digest = value.computed_digest().expect("taxonomy digest");
    value
}
fn policy(input_evidence: &[NamedEvidence]) -> ClassificationPolicy {
    let mut value = ClassificationPolicy::default();
    value.grade_bindings = input_evidence
        .iter()
        .map(|e| {
            let mut binding = EvidenceGradeBinding {
                evidence_id: e.id.clone(),
                reference: ExternalGradeRef {
                    owner: "eliot.c1.epistemic-contracts".to_owned(),
                    schema: "evidence-grade-v1".to_owned(),
                    revision: "1".to_owned(),
                    record_id: id(&format!("grade-{}", e.id)),
                    digest: "0".repeat(64),
                },
                assignment: GradeAssignment::known(EvidenceGrade::Grounded),
            };
            binding.reference.digest = grade_binding_digest(&binding).expect("grade digest");
            binding
        })
        .collect();
    value.policy_digest = value.computed_digest().expect("policy digest");
    value
}
#[allow(clippy::too_many_lines)]
fn make() -> (
    ClassificationInput,
    CurationAcceptanceCtx<'static>,
    ClassificationPolicy,
) {
    let evidence_values = vec![evidence("e1"), evidence("e2")];
    let job = DreamJobAdmission {
        schema_version: 1,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "op".to_owned(),
        idempotency_key: "idem".to_owned(),
        task_id: "task".to_owned(),
        scope_id: "scope".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "contract".to_owned(),
        policy_ref: "policy".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(1_048_576),
            output_bytes: Some(1_048_576),
            source_width: Some(64),
            reference_width: Some(64),
            model_calls: Some(1),
            attempts: Some(1),
            candidates: Some(1),
            wall_ms: Some(1_000),
            work_fan_out: Some(1),
            report_bytes: Some(1_048_576),
            max_stu: Some(10_000),
        },
        deadline_ms: None,
        frozen_manifest_digest: "f".repeat(64),
    };
    let job_ref = Box::leak(Box::new(job.clone()));
    let bundle_ref = Box::leak(Box::new(DreamInputBundle {
        schema_version: 1,
        job_id: "job".to_owned(),
        scope_id: "scope".to_owned(),
        task_id: "task".to_owned(),
        state_fence: fence(),
        manifest_digest: "f".repeat(64),
        materials: vec![
            BundleMaterial {
                handle: "target".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: "a".repeat(64),
            },
            BundleMaterial {
                handle: "e1".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: "a".repeat(64),
            },
            BundleMaterial {
                handle: "e2".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 10,
                digest: "a".repeat(64),
            },
        ],
        omissions: vec![],
        completeness: BundleCompleteness::CompleteForScope,
        authoritative_denominator: Some("scope:1-of-1".to_owned()),
    }));
    let grounded_ref = Box::leak(Box::new(GroundedDreamDraft {
        schema_version: 1,
        job_id: "job".to_owned(),
        draft_digest: "a".repeat(64),
        residues: vec![ClaimResidue {
            claim: "classification".to_owned(),
            state: SupportState::Supported,
            detail: "accepted".to_owned(),
        }],
        coverage_note: "covered".to_owned(),
    }));
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: "validator".to_owned(),
        validator_policy: "policy".to_owned(),
        job_id: "job".to_owned(),
        draft_digest: "a".repeat(64),
        bundle_digest: "f".repeat(64),
        manifest_digest: "f".repeat(64),
        task_id: "task".to_owned(),
        scope_id: "scope".to_owned(),
        input_digest: "b".repeat(64),
        output_digest: "c".repeat(64),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: "d".repeat(64),
        budget_digest: "e".repeat(64),
    };
    let receipt_ref = Box::leak(Box::new(receipt.clone()));
    let payload = CurationPayload::Classification(curation::ClassificationPayload {
        label: "classification".to_owned(),
        confidence_bps: 100,
        target_evidence: curation::TargetEvidence {
            targets: vec!["target".to_owned()],
            evidence_refs: vec!["e1".to_owned()],
        },
    });
    let job_digest = eliot_dreamer_contracts::canonical_bytes(job_ref)
        .map(|b| hash(std::str::from_utf8(&b).expect("utf8")))
        .expect("job digest");
    let item = ValidatedCurationItem {
        receipt: receipt_ref.clone(),
        kind_spelling: "classification".to_owned(),
        family_spelling: "classification".to_owned(),
        payload: payload.clone(),
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["target".to_owned()],
            expected_total: 1,
        },
        source_digest: "a".repeat(64),
        task_id: "task".to_owned(),
        scope_id: "scope".to_owned(),
        state_fence: fence(),
        job_digest,
        requester: job_ref.requester.clone(),
        budget_note: "bounded".to_owned(),
    };
    let item_digest = item.item_digest(grounded_ref).expect("item digest");
    let screen = Box::leak(Box::new(ScreenBinding {
        request_id: RequestId::new("request").expect("request"),
        receipt_id: ReceiptId::new("screen").expect("screen"),
        screened_targets: vec!["target".to_owned()],
        source_snapshot: "snapshot".to_owned(),
        source_revision: "rev".to_owned(),
        profile: "default".to_owned(),
        task_id: "task".to_owned(),
        scope_id: "scope".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: "c".repeat(64),
        item_digest,
    }));
    let request = Box::leak(Box::new(TypedCurationHandlerRequest {
        request_id: "request".to_owned(),
        receipt_id: "screen".to_owned(),
        source_snapshot: "snapshot".to_owned(),
        source_revision: "rev".to_owned(),
        profile: "default".to_owned(),
        kind: CurationKind::Classification,
        family: CurationFamily::Classification,
        job_id: "job".to_owned(),
        scope_id: "scope".to_owned(),
        task_id: "task".to_owned(),
        state_fence: fence(),
        payload,
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["target".to_owned()],
            expected_total: 1,
        },
        screen_binding: Some(screen.clone()),
    }));
    let usage = Box::leak(Box::new(BudgetUsage::default()));
    let context = CurationAcceptanceCtx {
        job: job_ref,
        bundle: bundle_ref,
        receipt: receipt_ref,
        screen,
        grounded: grounded_ref,
        request,
        usage,
    };
    let input = ClassificationInput {
        schema_version: 1,
        operation_id: id("op"),
        request_id: "request".to_owned(),
        idempotency_key: "idem".to_owned(),
        target: AdmittedTargetRef {
            target_id: id("target"),
            target_revision: "rev".to_owned(),
            target_digest: "a".repeat(64),
            admission: ReceiptIdentity {
                receipt_id: ReceiptId::new("admission").expect("receipt"),
                canonical_sha256: "1".repeat(64),
            },
            lifecycle: LifecycleState::Active,
            freshness: EvidenceFreshness::ExactCandidate,
            task_id: TaskId::new("task").expect("task"),
            scope_id: WorkScopeId::new("scope").expect("scope"),
            state_fence: fence(),
            source_handles: vec![id("target")],
        },
        item,
        screen: (*context.screen).clone(),
        evidence: evidence_values.clone(),
        features: vec![
            FeatureObservation {
                feature_id: id("fa"),
                criterion_id: id("necessary-a"),
                applicability: CriterionApplicability::Required,
                value: Some(true),
                status: CriterionStatus::Supported,
                evidence_refs: vec![id("e1")],
            },
            FeatureObservation {
                feature_id: id("fs"),
                criterion_id: id("sufficient-a"),
                applicability: CriterionApplicability::Required,
                value: Some(true),
                status: CriterionStatus::Supported,
                evidence_refs: vec![id("e1")],
            },
            FeatureObservation {
                feature_id: id("fb"),
                criterion_id: id("necessary-b"),
                applicability: CriterionApplicability::Required,
                value: Some(false),
                status: CriterionStatus::Supported,
                evidence_refs: vec![id("e2")],
            },
        ],
        taxonomy: taxonomy(),
        prior_assignment: None,
        preservation: preservation(),
        policy_digest: String::new(),
    };
    let pol = policy(&evidence_values);
    let mut input = input;
    for evidence in &mut input.evidence {
        let binding = pol
            .grade_bindings
            .iter()
            .find(|binding| binding.evidence_id == evidence.id)
            .expect("grade binding");
        evidence.external_grade = Some(binding.reference.clone());
    }
    input.policy_digest.clone_from(&pol.policy_digest);
    (input, context, pol)
}

fn prior(selected: Option<&str>) -> PriorAssignmentRef {
    let selected = selected.map(id);
    PriorAssignmentRef {
        assignment_id: id("prior-assignment"),
        selected_alternative_id: selected.clone(),
        selected_family: selected.as_ref().map(|_| "interpretation".to_owned()),
        selected_subtype: selected.as_ref().map(|alternative| {
            if alternative.as_str() == "alt-a" {
                "known-a".to_owned()
            } else {
                "known-b".to_owned()
            }
        }),
        target_id: id("target"),
        target_revision: "rev".to_owned(),
        assignment_digest: hash("prior"),
        predecessor: None,
        source_handles: vec![id("target")],
        status: EpistemicStatus::Supported,
        lifecycle: LifecycleState::Active,
        receipt: None,
    }
}

fn refresh_taxonomy(input: &mut ClassificationInput) {
    input.taxonomy.digest = input.taxonomy.computed_digest().expect("taxonomy digest");
}

#[test]
fn positive_requires_acceptance_and_known_subtype() {
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    assert!(result.sealed.is_some());
    assert_eq!(
        result
            .candidate
            .as_ref()
            .expect("candidate")
            .subtype_ref
            .as_deref(),
        Some("known-a")
    );
    assert!(
        result
            .traces
            .iter()
            .all(|trace| !trace.explanation.is_empty())
    );
}

#[test]
fn prior_positions_and_admission_guards_are_retained() {
    let (mut input, ctx, policy) = make();
    input.prior_assignment = Some(prior(Some("alt-a")));
    assert_eq!(
        classify(&input, &ctx, &policy)
            .expect("duplicate")
            .disposition,
        ClassificationDisposition::Duplicate
    );
    let (mut input, ctx, policy) = make();
    input.prior_assignment = Some(prior(Some("alt-b")));
    input.taxonomy.alias_mappings.push(TaxonomyAliasMapping {
        alias_id: id("alias-a"),
        canonical_alternative_id: id("alt-a"),
        refinement_of: Some(id("alt-b")),
    });
    refresh_taxonomy(&mut input);
    assert_eq!(
        classify(&input, &ctx, &policy)
            .expect("refinement")
            .disposition,
        ClassificationDisposition::Refinement
    );
    let (mut input, ctx, policy) = make();
    input.prior_assignment = Some(prior(Some("alt-b")));
    let result = classify(&input, &ctx, &policy).expect("conflict");
    assert_eq!(result.disposition, ClassificationDisposition::Conflicted);
    assert!(result.conflict.is_some());
    let (mut input, ctx, policy) = make();
    input.target.freshness = EvidenceFreshness::Stale;
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.cancellation_requested = true;
    policy.policy_digest = policy.computed_digest().expect("digest");
    input.policy_digest = policy.policy_digest.clone();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.target_status = EpistemicStatus::Superseded;
    policy.policy_digest = policy.computed_digest().expect("digest");
    input.policy_digest = policy.policy_digest.clone();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.observed_stu = 1;
    policy.policy_digest = policy.computed_digest().expect("digest");
    input.policy_digest.clone_from(&policy.policy_digest);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.now_ms = Some(10);
    policy.deadline_ms = Some(10);
    policy.policy_digest = policy.computed_digest().expect("digest");
    input.policy_digest.clone_from(&policy.policy_digest);
    assert!(classify(&input, &ctx, &policy).is_err());
}

#[test]
fn policy_and_grade_reference_are_bound() {
    let (mut input, ctx, mut policy) = make();
    policy.grade_bindings[0].assignment = GradeAssignment::known(EvidenceGrade::Corroborated);
    policy.policy_digest = policy.computed_digest().expect("digest");
    input.policy_digest = policy.policy_digest.clone();
    assert!(classify(&input, &ctx, &policy).is_err());
}

#[test]
fn unresolved_rival_abstains_and_preserves_all_alternatives() {
    let (mut input, ctx, policy) = make();
    input.features[2].value = Some(true);
    let result = classify(&input, &ctx, &policy).expect("abstention result");
    assert_eq!(result.disposition, ClassificationDisposition::Abstention);
    assert_eq!(
        result
            .candidate
            .expect("candidate transport")
            .selected_alternative_id,
        None
    );
}

#[test]
fn two_sufficient_alternatives_are_ambiguous_and_set_identity_is_stable() {
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .criteria
        .iter_mut()
        .find(|criterion| criterion.criterion_id == id("necessary-b"))
        .expect("rival criterion")
        .role = ClassificationCriterionRole::Sufficient;
    input.features[2].value = Some(true);
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("ambiguous result");
    assert_eq!(result.disposition, ClassificationDisposition::Ambiguous);
    let (mut permuted, ctx2, mut policy2) = make();
    permuted
        .taxonomy
        .criteria
        .iter_mut()
        .find(|criterion| criterion.criterion_id == id("necessary-b"))
        .expect("rival criterion")
        .role = ClassificationCriterionRole::Sufficient;
    for alternative in &mut permuted.taxonomy.alternatives {
        alternative.criterion_refs.reverse();
        alternative.counterevidence_refs.reverse();
    }
    permuted.features[2].value = Some(true);
    permuted.taxonomy.alternatives.reverse();
    permuted.taxonomy.criteria.reverse();
    permuted.taxonomy.declared_alternative_ids.reverse();
    permuted.taxonomy.provided_alternative_ids.reverse();
    permuted.evidence.reverse();
    refresh_taxonomy(&mut permuted);
    policy2.grade_bindings.reverse();
    policy2.policy_digest = policy2.computed_digest().expect("policy digest");
    permuted.policy_digest = policy2.policy_digest.clone();
    let permuted_result = classify(&permuted, &ctx2, &policy2).expect("permuted result");
    assert_eq!(result.result_digest, permuted_result.result_digest);
    assert_eq!(
        result.candidate.expect("candidate").candidate_id,
        permuted_result.candidate.expect("candidate").candidate_id
    );
}

#[test]
fn target_status_ceiling_is_explicit() {
    let (mut input, ctx, mut policy) = make();
    policy.target_status = EpistemicStatus::Superseded;
    policy.policy_digest = policy.computed_digest().expect("digest");
    input.policy_digest = policy.policy_digest.clone();
    assert!(classify(&input, &ctx, &policy).is_err());
}

fn refresh_policy(input: &mut ClassificationInput, policy: &mut ClassificationPolicy) {
    policy.policy_digest = policy.computed_digest().expect("policy digest");
    input.policy_digest.clone_from(&policy.policy_digest);
}

fn rebind_grade(
    input: &mut ClassificationInput,
    policy: &mut ClassificationPolicy,
    evidence: &ArtifactId,
    assignment: GradeAssignment,
) {
    let binding = policy
        .grade_bindings
        .iter_mut()
        .find(|binding| binding.evidence_id == *evidence)
        .expect("grade binding");
    binding.assignment = assignment;
    binding.reference.digest = grade_binding_digest(binding).expect("grade digest");
    let reference = binding.reference.clone();
    input
        .evidence
        .iter_mut()
        .find(|item| item.id == *evidence)
        .expect("named evidence")
        .external_grade = Some(reference);
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

fn strip_to_sole_legal(input: &mut ClassificationInput) {
    input
        .taxonomy
        .alternatives
        .retain(|alternative| alternative.alternative_id == id("alt-a"));
    input.taxonomy.declared_alternative_ids = vec![id("alt-a")];
    input.taxonomy.provided_alternative_ids = vec![id("alt-a")];
    input.taxonomy.omitted_alternative_ids = vec![];
    input.taxonomy.coverage = TaxonomyCoverage::Complete;
    refresh_taxonomy(input);
}

// WORK_UNIT_CASE: 653/1
#[test]
fn case_01_valid_post_admission_candidate() {
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.family_ref, "interpretation");
    assert_eq!(candidate.subtype_ref.as_deref(), Some("known-a"));
    assert_eq!(candidate.selected_alternative_id, Some(id("alt-a")));
    assert_eq!(candidate.target_id, id("target"));
    assert_eq!(candidate.target_revision, "rev");
    assert!(result.sealed.is_some());
    assert!(!result.result_digest.is_empty());
}

// WORK_UNIT_CASE: 653/2
#[test]
fn case_02_canonical_vocabulary_and_unknown_rejection() {
    let unknown_family = serde_json::json!({
        "alternative_id": "alt-x",
        "family": "not_a_family",
        "subtype_ref": "known-x",
        "criterion_refs": [],
        "evidence_refs": [],
        "counterevidence_refs": []
    });
    assert!(serde_json::from_value::<TaxonomyAlternative>(unknown_family).is_err());
    let unknown_role = serde_json::json!({
        "criterion_id": "c-x",
        "role": "maybe_necessary",
        "applicability": "required",
        "evidence_refs": [],
        "rationale": "r"
    });
    assert!(serde_json::from_value::<GroundedCriterion>(unknown_role).is_err());
    let (mut input, ctx, policy) = make();
    input.taxonomy.alternatives[0].family = ClassificationRecordFamily::DecisionRecord;
    refresh_taxonomy(&mut input);
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/3
#[test]
fn case_03_wrong_kind_payload_rejected() {
    let (mut input, ctx, policy) = make();
    input.item.kind_spelling = "relation".to_owned();
    let err = classify(&input, &ctx, &policy).expect_err("wrong kind must fail");
    assert!(matches!(err, ContractViolation::KindPayload(_)));
    let (mut input, ctx, policy) = make();
    input.item.family_spelling = "relation".to_owned();
    assert!(matches!(
        classify(&input, &ctx, &policy),
        Err(ContractViolation::KindPayload(_))
    ));
    let (mut input, ctx, policy) = make();
    input.item.payload = CurationPayload::Relation(curation::RelationPayload {
        from_handle: "target".to_owned(),
        to_handle: "target".to_owned(),
        relation: "related".to_owned(),
        target_evidence: curation::TargetEvidence {
            targets: vec!["target".to_owned()],
            evidence_refs: vec!["e1".to_owned()],
        },
    });
    input.item.kind_spelling = "relation".to_owned();
    input.item.family_spelling = "relation".to_owned();
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/4
#[test]
fn case_04_unadmitted_target_rejected() {
    let (mut input, ctx, policy) = make();
    input.target.target_digest = "b".repeat(64);
    let err = classify(&input, &ctx, &policy).expect_err("undigested target must fail");
    assert!(format!("{err}").contains("target_digest"));
    let (mut input, ctx, policy) = make();
    input.target.source_handles.push(id("ghost"));
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/5
#[test]
fn case_05_stale_deleted_superseded_wrong_scope() {
    let (mut input, ctx, policy) = make();
    input.target.freshness = EvidenceFreshness::Stale;
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.target.lifecycle = LifecycleState::Extinguished;
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.target.lifecycle = LifecycleState::Quarantined;
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.target_status = EpistemicStatus::Superseded;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.target_status = EpistemicStatus::Rejected;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.evidence[0]
        .foundation_evidence_envelope
        .provenance
        .scope = "other-scope".to_owned();
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/6
#[test]
fn case_06_revision_fence_admission_mismatch() {
    let (mut input, ctx, policy) = make();
    input.target.state_fence = fence_seq2();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.target.task_id = TaskId::new("other-task").expect("task");
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.target.admission.canonical_sha256 = "not-hex".to_owned();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.policy_digest = "0".repeat(64);
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/7
#[test]
fn case_07_single_target_closure() {
    let (mut input, ctx, policy) = make();
    input.item.denominator.members = vec!["target".to_owned(), "target-two".to_owned()];
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    if let CurationPayload::Classification(payload) = &mut input.item.payload {
        payload.target_evidence.targets = vec!["target".to_owned(), "target-two".to_owned()];
    }
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.screen.screened_targets = vec!["target".to_owned(), "target-two".to_owned()];
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/8
#[test]
fn case_08_criterion_role_rules() {
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    let rival = result
        .traces
        .iter()
        .find(|trace| trace.alternative_id == id("alt-b"))
        .expect("rival trace");
    assert!(!rival.excluding_criteria.is_empty());
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .criteria
        .iter_mut()
        .find(|criterion| criterion.criterion_id == id("sufficient-a"))
        .expect("criterion")
        .role = ClassificationCriterionRole::Characteristic;
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("characteristic result");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
    let (mut input, ctx, policy) = make();
    input.taxonomy.criteria.push(GroundedCriterion {
        criterion_id: id("exclusion-a"),
        role: ClassificationCriterionRole::Exclusion,
        applicability: CriterionApplicability::Required,
        evidence_refs: vec![id("e1")],
        rationale: "exclusion discriminator".to_owned(),
    });
    input
        .taxonomy
        .alternatives
        .iter_mut()
        .find(|alternative| alternative.alternative_id == id("alt-a"))
        .expect("alternative")
        .criterion_refs
        .push(id("exclusion-a"));
    input.features.push(FeatureObservation {
        feature_id: id("fx"),
        criterion_id: id("exclusion-a"),
        applicability: CriterionApplicability::Required,
        value: Some(true),
        status: CriterionStatus::Supported,
        evidence_refs: vec![id("e1")],
    });
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("exclusion result");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
    let winner = result
        .traces
        .iter()
        .find(|trace| trace.alternative_id == id("alt-a"))
        .expect("trace");
    assert!(winner.excluding_criteria.contains(&id("exclusion-a")));
}

// WORK_UNIT_CASE: 653/9
#[test]
fn case_09_feature_evidence_statuses() {
    for status in [
        CriterionStatus::Partial,
        CriterionStatus::Unsupported,
        CriterionStatus::Contradicted,
        CriterionStatus::Unknown,
    ] {
        let (mut input, ctx, policy) = make();
        input.features[0].status = status;
        let result = classify(&input, &ctx, &policy).expect("status result");
        assert_ne!(
            result.disposition,
            ClassificationDisposition::Candidate,
            "status {status:?} must not establish class"
        );
    }
    let (mut input, ctx, policy) = make();
    input.features[0].value = None;
    let result = classify(&input, &ctx, &policy).expect("unknown value result");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
}

// WORK_UNIT_CASE: 653/10
#[test]
fn case_10_hints_confidence_frequency_cannot_establish() {
    for authority in [
        EvidenceAuthority::ModelInterpretation,
        EvidenceAuthority::HeuristicStatic,
        EvidenceAuthority::SourceIdentity,
    ] {
        let (mut input, ctx, policy) = make();
        input.evidence[0].foundation_evidence_envelope.authority = authority;
        let result = classify(&input, &ctx, &policy).expect("authority result");
        assert_ne!(result.disposition, ClassificationDisposition::Candidate);
    }
    let (mut input, ctx, policy) = make();
    input.features.clear();
    let result = classify(&input, &ctx, &policy).expect("no-feature result");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
}

// WORK_UNIT_CASE: 653/11
#[test]
fn case_11_similarity_cannot_establish() {
    let (mut input, ctx, policy) = make();
    input
        .features
        .retain(|feature| feature.criterion_id != id("sufficient-a"));
    let result = classify(&input, &ctx, &policy).expect("result");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
    let (mut input, ctx, policy) = make();
    input.features[1].evidence_refs.clear();
    let result = classify(&input, &ctx, &policy).expect("result");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
}

// WORK_UNIT_CASE: 653/12
#[test]
fn case_12_complete_denominator() {
    let (input, ctx, policy) = make();
    assert_eq!(input.taxonomy.coverage, TaxonomyCoverage::Complete);
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    let candidate = result.candidate.expect("candidate");
    assert!(candidate.alternatives.contains(&id("alt-a")));
    assert!(candidate.alternatives.contains(&id("alt-b")));
    assert_eq!(candidate.alternatives.len(), 2);
    assert!(result.omitted_alternatives.is_empty());
    assert!(!candidate.sole_legal_alternative_proof);
}

// WORK_UNIT_CASE: 653/13
#[test]
fn case_13_missing_material_alternative_blocks() {
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .alternatives
        .retain(|alternative| alternative.alternative_id != id("alt-b"));
    input.taxonomy.provided_alternative_ids = vec![id("alt-a")];
    input.taxonomy.omitted_alternative_ids = vec![id("alt-b")];
    input.taxonomy.coverage = TaxonomyCoverage::Partial;
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("partial result");
    assert_eq!(result.disposition, ClassificationDisposition::Incomplete);
    assert_eq!(result.omitted_alternatives, vec![id("alt-b")]);
    assert!(
        result
            .candidate
            .expect("candidate transport")
            .selected_alternative_id
            .is_none()
    );
}

// WORK_UNIT_CASE: 653/14
#[test]
fn case_14_partial_taxonomy_cannot_prove_absence() {
    let (mut input, ctx, policy) = make();
    input.taxonomy.missing_criteria = vec![id("criterion-x")];
    input.taxonomy.coverage = TaxonomyCoverage::Partial;
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("partial result");
    assert_eq!(result.disposition, ClassificationDisposition::Incomplete);
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .alternatives
        .retain(|alternative| alternative.alternative_id == id("alt-a"));
    input.taxonomy.provided_alternative_ids = vec![id("alt-a")];
    input.taxonomy.omitted_alternative_ids = vec![id("alt-b")];
    input.taxonomy.coverage = TaxonomyCoverage::Complete;
    refresh_taxonomy(&mut input);
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/15
#[test]
fn case_15_rival_or_sole_legal_proof() {
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert!(
        !result
            .candidate
            .expect("candidate")
            .sole_legal_alternative_proof
    );
    let (mut input, ctx, policy) = make();
    strip_to_sole_legal(&mut input);
    let result = classify(&input, &ctx, &policy).expect("sole legal");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    assert!(
        result
            .candidate
            .expect("candidate")
            .sole_legal_alternative_proof
    );
    let (mut input, ctx, policy) = make();
    strip_to_sole_legal(&mut input);
    input.taxonomy.coverage = TaxonomyCoverage::Partial;
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("partial sole");
    assert_eq!(result.disposition, ClassificationDisposition::Incomplete);
}

// WORK_UNIT_CASE: 653/16
#[test]
fn case_16_equal_support_yields_ambiguity() {
    let (mut input, ctx, policy) = make();
    input.features[2].value = Some(true);
    let result = classify(&input, &ctx, &policy).expect("abstention");
    assert_eq!(result.disposition, ClassificationDisposition::Abstention);
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .criteria
        .iter_mut()
        .find(|criterion| criterion.criterion_id == id("necessary-b"))
        .expect("criterion")
        .role = ClassificationCriterionRole::Sufficient;
    input.features[2].value = Some(true);
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("ambiguous");
    assert_eq!(result.disposition, ClassificationDisposition::Ambiguous);
    assert!(
        result
            .candidate
            .expect("transport")
            .selected_alternative_id
            .is_none()
    );
}

// WORK_UNIT_CASE: 653/17
#[test]
fn case_17_dependent_sources_do_not_inflate() {
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    assert!(
        result
            .traces
            .iter()
            .all(|trace| trace.omitted_evidence.is_empty())
    );
    let winner = result
        .traces
        .iter()
        .find(|trace| trace.alternative_id == id("alt-a"))
        .expect("winner trace");
    assert!(winner.supporting_criteria.contains(&id("necessary-a")));
    assert!(winner.supporting_criteria.contains(&id("sufficient-a")));
    let (mut input, ctx, mut policy) = make();
    let mut duplicate = input.evidence[0].clone();
    duplicate.id = id("e1-dup");
    input.evidence.push(duplicate);
    let mut dup_binding = policy.grade_bindings[0].clone();
    dup_binding.evidence_id = id("e1-dup");
    dup_binding.reference.record_id = id("grade-e1-dup");
    dup_binding.reference.digest = grade_binding_digest(&dup_binding).expect("grade digest");
    policy.grade_bindings.push(dup_binding);
    for criterion_id in [id("necessary-a"), id("sufficient-a")] {
        input
            .taxonomy
            .criteria
            .iter_mut()
            .find(|criterion| criterion.criterion_id == criterion_id)
            .expect("criterion")
            .evidence_refs
            .push(id("e1-dup"));
    }
    for feature in input
        .features
        .iter_mut()
        .filter(|feature| feature.feature_id == id("fa") || feature.feature_id == id("fs"))
    {
        feature.evidence_refs.push(id("e1-dup"));
    }
    let dup_reference = policy
        .grade_bindings
        .iter()
        .find(|binding| binding.evidence_id == id("e1-dup"))
        .expect("binding")
        .reference
        .clone();
    let mut rebound = false;
    for evidence in input
        .evidence
        .iter_mut()
        .filter(|evidence| evidence.id == id("e1-dup"))
    {
        evidence.external_grade = Some(dup_reference.clone());
        rebound = true;
    }
    assert!(rebound);
    refresh_taxonomy(&mut input);
    refresh_policy(&mut input, &mut policy);
    let result = classify(&input, &ctx, &policy).expect("dup result");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    assert_eq!(
        result.candidate.expect("candidate").selected_alternative_id,
        Some(id("alt-a"))
    );
}

// WORK_UNIT_CASE: 653/18
#[test]
fn case_18_grade_and_domain_ceiling() {
    let (mut input, ctx, mut policy) = make();
    rebind_grade(
        &mut input,
        &mut policy,
        &id("e1"),
        GradeAssignment::known(EvidenceGrade::Orienting),
    );
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.maximum_grade = EvidenceGrade::Corroborated;
    rebind_grade(
        &mut input,
        &mut policy,
        &id("e1"),
        GradeAssignment::known(EvidenceGrade::ScienceGrade),
    );
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    rebind_grade(
        &mut input,
        &mut policy,
        &id("e1"),
        GradeAssignment::unknown("pending review").expect("unknown grade"),
    );
    refresh_policy(&mut input, &mut policy);
    let result = classify(&input, &ctx, &policy).expect("unknown grade result");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
}

// WORK_UNIT_CASE: 653/19
#[test]
fn case_19_same_assignment_is_duplicate() {
    let (mut input, ctx, policy) = make();
    input.prior_assignment = Some(prior(Some("alt-a")));
    let result = classify(&input, &ctx, &policy).expect("duplicate");
    assert_eq!(result.disposition, ClassificationDisposition::Duplicate);
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.selected_alternative_id, Some(id("alt-a")));
    assert_eq!(candidate.after.subtype_ref.as_deref(), Some("known-a"));
    assert!(result.sealed.is_some());
}

// WORK_UNIT_CASE: 653/20
#[test]
fn case_20_compatible_refinement_retains_predecessor() {
    let (mut input, ctx, policy) = make();
    input.prior_assignment = Some(prior(Some("alt-b")));
    input.taxonomy.alias_mappings.push(TaxonomyAliasMapping {
        alias_id: id("alias-a"),
        canonical_alternative_id: id("alt-a"),
        refinement_of: Some(id("alt-b")),
    });
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("refinement");
    assert_eq!(result.disposition, ClassificationDisposition::Refinement);
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.before.alternative_id, Some(id("alt-b")));
    assert_eq!(candidate.after.alternative_id, Some(id("alt-a")));
    assert_eq!(candidate.rollback.predecessor, Some(id("prior-assignment")));
}

// WORK_UNIT_CASE: 653/21
#[test]
fn case_21_incompatible_assignment_preserves_conflict() {
    let (mut input, ctx, policy) = make();
    input.prior_assignment = Some(prior(Some("alt-b")));
    let result = classify(&input, &ctx, &policy).expect("conflict");
    assert_eq!(result.disposition, ClassificationDisposition::Conflicted);
    let conflict = result.conflict.expect("conflict set");
    assert_eq!(conflict.prior_alternative_id, Some(id("alt-b")));
    assert_eq!(conflict.proposed_alternative_id, id("alt-a"));
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.before.alternative_id, Some(id("alt-b")));
    assert_eq!(candidate.after.alternative_id, Some(id("alt-a")));
}

// WORK_UNIT_CASE: 653/22
#[test]
fn case_22_ontology_redesign_returns_owner_challenge() {
    let (mut input, ctx, policy) = make();
    input.item.kind_spelling = "merge".to_owned();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.taxonomy.alias_mappings.push(TaxonomyAliasMapping {
        alias_id: id("alias-x"),
        canonical_alternative_id: id("alt-a"),
        refinement_of: Some(id("alt-ghost")),
    });
    refresh_taxonomy(&mut input);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .alternatives
        .iter_mut()
        .find(|alternative| alternative.alternative_id == id("alt-a"))
        .expect("alternative")
        .subtype_ref = None;
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("unknown subtype");
    assert_eq!(
        result.disposition,
        ClassificationDisposition::UnsupportedTaxonomy
    );
    assert!(result.reason.contains("owner"));
}

// WORK_UNIT_CASE: 653/23
#[test]
fn case_23_no_first_pass_capture_or_lifecycle_action() {
    let (input, ctx, policy) = make();
    let snapshot = input.clone();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(input, snapshot);
    assert_eq!(input.target.lifecycle, LifecycleState::Active);
    let (mut input, ctx, policy) = make();
    input.screen.state = ScreenState::Protected;
    assert!(classify(&input, &ctx, &policy).is_err());
    assert_eq!(
        result.candidate.expect("candidate").proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
}

// WORK_UNIT_CASE: 653/24
#[test]
fn case_24_rollback_and_history_preservation() {
    let (mut input, ctx, policy) = make();
    input.prior_assignment = Some(prior(Some("alt-b")));
    let retained = input.target.source_handles.clone();
    let result = classify(&input, &ctx, &policy).expect("conflict");
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.rollback.target_id, id("target"));
    assert_eq!(candidate.rollback.predecessor, Some(id("prior-assignment")));
    assert!(!candidate.rollback.rollback_handles.is_empty());
    assert!(!candidate.rollback.raw_history_handles.is_empty());
    assert!(!candidate.rollback.invalidation_handles.is_empty());
    for handle in candidate
        .rollback
        .rollback_handles
        .iter()
        .chain(candidate.rollback.raw_history_handles.iter())
        .chain(candidate.rollback.invalidation_handles.iter())
    {
        assert!(retained.contains(handle));
    }
    assert_eq!(candidate.before.alternative_id, Some(id("alt-b")));
    assert_eq!(candidate.before.assignment_digest, Some(hash("prior")));
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("candidate");
    let candidate = result.candidate.expect("candidate");
    assert!(candidate.before.alternative_id.is_none());
    assert!(candidate.rollback.predecessor.is_none());
    assert!(!candidate.rollback.raw_history_handles.is_empty());
}

// WORK_UNIT_CASE: 653/25
#[test]
fn case_25_preservation_dimensions_and_prior_receipt() {
    let (mut input, ctx, policy) = make();
    input.preservation.verdicts.pop();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.preservation.verdicts[0].passed = false;
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.preservation.verdicts[1].known = false;
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.item.receipt.job_id = "other-job".to_owned();
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/26
#[test]
fn case_26_partial_budget_deadline_cancel_omissions() {
    let (mut input, ctx, mut policy) = make();
    policy.cancellation_requested = true;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.now_ms = Some(20);
    policy.deadline_ms = Some(10);
    refresh_policy(&mut input, &mut policy);
    let err = classify(&input, &ctx, &policy).expect_err("deadline");
    assert!(format!("{err}").contains("deadline"));
    let (mut input, ctx, mut policy) = make();
    policy.max_features = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .alternatives
        .retain(|alternative| alternative.alternative_id == id("alt-a"));
    input.taxonomy.provided_alternative_ids = vec![id("alt-a")];
    input.taxonomy.omitted_alternative_ids = vec![id("alt-b")];
    input.taxonomy.coverage = TaxonomyCoverage::Partial;
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("partial");
    assert_eq!(result.disposition, ClassificationDisposition::Incomplete);
    assert_eq!(result.omitted_alternatives, vec![id("alt-b")]);
}

// WORK_UNIT_CASE: 653/27
#[test]
fn case_27_privacy_authority_effect_proof_ceiling() {
    let (input, ctx, policy) = make();
    assert_eq!(ctx.job.privacy_profile, "local_only");
    let result = classify(&input, &ctx, &policy).expect("classify");
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert_eq!(
        result.sealed.expect("sealed").proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    let retained = [id("target")];
    for handle in candidate
        .source_handles
        .iter()
        .chain(candidate.rollback.rollback_handles.iter())
        .chain(candidate.rollback.invalidation_handles.iter())
        .chain(candidate.rollback.raw_history_handles.iter())
    {
        assert!(retained.contains(handle));
    }
    let (mut input, ctx, mut policy) = make();
    policy.maximum_grade = EvidenceGrade::Corroborated;
    rebind_grade(
        &mut input,
        &mut policy,
        &id("e1"),
        GradeAssignment::known(EvidenceGrade::ScienceGrade),
    );
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/28
#[test]
fn case_28_independent_count_byte_stu_work_bounds() {
    let (mut input, ctx, mut policy) = make();
    policy.max_evidence = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.max_alternatives = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.max_source_refs = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.max_work_units = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.observed_stu = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.max_input_bytes = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, mut policy) = make();
    policy.max_output_bytes = 1;
    refresh_policy(&mut input, &mut policy);
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/29
#[test]
fn case_29_set_permutation_determinism() {
    let (input, ctx, policy) = make();
    let first = classify(&input, &ctx, &policy).expect("first");
    let second = classify(&input, &ctx, &policy).expect("second");
    assert_eq!(first.result_digest, second.result_digest);
    let (mut permuted, ctx2, mut policy2) = make();
    for alternative in &mut permuted.taxonomy.alternatives {
        alternative.criterion_refs.reverse();
        alternative.counterevidence_refs.reverse();
    }
    permuted.taxonomy.alternatives.reverse();
    permuted.taxonomy.criteria.reverse();
    permuted.taxonomy.declared_alternative_ids.reverse();
    permuted.taxonomy.provided_alternative_ids.reverse();
    permuted.evidence.reverse();
    refresh_taxonomy(&mut permuted);
    policy2.grade_bindings.reverse();
    refresh_policy(&mut permuted, &mut policy2);
    let permuted_result = classify(&permuted, &ctx2, &policy2).expect("permuted");
    assert_eq!(first.result_digest, permuted_result.result_digest);
    assert_eq!(
        first.candidate.expect("candidate").candidate_id,
        permuted_result.candidate.expect("candidate").candidate_id
    );
}

// WORK_UNIT_CASE: 653/30
#[test]
fn case_30_replay_and_changed_input_policy_conflict() {
    let (input, ctx, policy) = make();
    let first = classify(&input, &ctx, &policy).expect("first");
    let replay = classify(&input, &ctx, &policy).expect("replay");
    assert_eq!(first.result_digest, replay.result_digest);
    let (mut changed, ctx2, policy2) = make();
    changed.features[2].value = Some(true);
    let other = classify(&changed, &ctx2, &policy2).expect("changed");
    assert_ne!(first.result_digest, other.result_digest);
    assert_ne!(
        first.candidate.expect("candidate").candidate_id,
        other.candidate.expect("candidate").candidate_id
    );
    let (input, ctx, mut policy) = make();
    policy.max_features = 999;
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/31
#[test]
fn case_31_malformed_input_never_panics() {
    let (mut input, ctx, policy) = make();
    input.policy_digest = "not-hex".to_owned();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.taxonomy.digest = "z".repeat(64);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.target.target_digest = "short".to_owned();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.target.admission.canonical_sha256 = String::new();
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.features.clear();
    let result = classify(&input, &ctx, &policy).expect("empty features");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
}

// WORK_UNIT_CASE: 653/32
#[test]
fn case_32_positive_requires_known_subtype_and_admitted_target() {
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(result.disposition, ClassificationDisposition::Candidate);
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.subtype_ref.as_deref(), Some("known-a"));
    assert_eq!(candidate.family_ref, "interpretation");
    assert_eq!(candidate.target_id, input.target.target_id);
    assert_eq!(candidate.target_revision, input.target.target_revision);
    assert_eq!(candidate.after.subtype_ref.as_deref(), Some("known-a"));
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .alternatives
        .iter_mut()
        .find(|alternative| alternative.alternative_id == id("alt-a"))
        .expect("alternative")
        .subtype_ref = None;
    refresh_taxonomy(&mut input);
    let result = classify(&input, &ctx, &policy).expect("unknown subtype");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
}

// WORK_UNIT_CASE: 653/33
#[test]
fn case_33_complete_retains_alternatives_or_sole_proof() {
    let (input, ctx, policy) = make();
    let result = classify(&input, &ctx, &policy).expect("classify");
    let candidate = result.candidate.expect("candidate");
    assert_eq!(
        candidate.alternatives.len(),
        input.taxonomy.declared_alternative_ids.len()
    );
    assert!(candidate.alternatives.contains(&id("alt-a")));
    assert!(candidate.alternatives.contains(&id("alt-b")));
    let (mut input, ctx, policy) = make();
    strip_to_sole_legal(&mut input);
    let result = classify(&input, &ctx, &policy).expect("sole legal");
    let candidate = result.candidate.expect("candidate");
    assert_eq!(candidate.alternatives, vec![id("alt-a")]);
    assert!(candidate.sole_legal_alternative_proof);
}

// WORK_UNIT_CASE: 653/34
#[test]
fn case_34_missing_discriminator_invalidates() {
    let (input, ctx, policy) = make();
    let baseline = classify(&input, &ctx, &policy).expect("baseline");
    let (mut input, ctx, policy) = make();
    input
        .features
        .retain(|feature| feature.criterion_id != id("sufficient-a"));
    let result = classify(&input, &ctx, &policy).expect("dropped discriminator");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
    assert_ne!(baseline.result_digest, result.result_digest);
    let (mut input, ctx, policy) = make();
    input
        .taxonomy
        .criteria
        .iter_mut()
        .find(|criterion| criterion.criterion_id == id("sufficient-a"))
        .expect("criterion")
        .evidence_refs = vec![id("ghost-evidence")];
    refresh_taxonomy(&mut input);
    assert!(classify(&input, &ctx, &policy).is_err());
    let (mut input, ctx, policy) = make();
    input.features[0].criterion_id = id("ghost-criterion");
    assert!(classify(&input, &ctx, &policy).is_err());
}

// WORK_UNIT_CASE: 653/35
#[test]
fn case_35_no_capture_index_provider_model_store_finish_path() {
    const LIB: &str = include_str!("../src/lib.rs");
    const EVIDENCE: &str = include_str!("../src/evidence.rs");
    const POLICY: &str = include_str!("../src/policy.rs");
    const RESULT: &str = include_str!("../src/result.rs");
    const SELECTION: &str = include_str!("../src/selection.rs");
    const MANIFEST: &str = include_str!("../Cargo.toml");
    for source in [LIB, EVIDENCE, POLICY, RESULT, SELECTION, MANIFEST] {
        for forbidden in ["provider", "Store", "Finish", "capture", "reqwest", "tokio"] {
            assert!(!source.contains(forbidden), "forbidden path {forbidden}");
        }
    }
    let (input, ctx, policy) = make();
    let snapshot = input.clone();
    let result = classify(&input, &ctx, &policy).expect("classify");
    assert_eq!(input, snapshot);
    assert_eq!(
        result.candidate.expect("candidate").proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    let (mut input, ctx, policy) = make();
    input.evidence[0].foundation_evidence_envelope.authority =
        EvidenceAuthority::ModelInterpretation;
    let result = classify(&input, &ctx, &policy).expect("model authority");
    assert_ne!(result.disposition, ClassificationDisposition::Candidate);
}
