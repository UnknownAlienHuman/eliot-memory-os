#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ReceiptId, RequestId, ResourceGeneration, SourceId, StateFence,
    TaskId,
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
use eliot_receipts::{ReceiptIdentity, WorkScopeId};

fn id(v: &str) -> ArtifactId {
    ArtifactId::new(v).expect("id")
}
fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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
    let job = DreamJobInput {
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
