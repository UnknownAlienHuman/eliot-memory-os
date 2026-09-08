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
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};

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

fn payload() -> CurationPayload {
    CurationPayload::Relation(RelationPayload {
        from_handle: "source-a".to_owned(),
        to_handle: "target-b".to_owned(),
        relation: "supports".to_owned(),
        target_evidence: TargetEvidence {
            targets: vec!["source-a".to_owned(), "target-b".to_owned()],
            evidence_refs: vec!["evidence-1".to_owned()],
        },
    })
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
        registry_digest: registry().digest,
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
        registry: registry(),
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
            Vec::new(),
        )],
        no_relation_alternative: Some(relation_alternative(
            "no-relation-1",
            None,
            None,
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

fn candidate(input: &RelationInput) -> RelationCandidate {
    let input_digest = relation_input_digest(input).expect("input digest");
    let source_id = input.source.endpoint_id().to_owned();
    let target_id = input.target.endpoint_id().to_owned();
    RelationCandidate {
        candidate_id: RelationCandidate::expected_candidate_id(
            &input.operation_id,
            &input_digest,
            &input.policy_digest,
            input.family,
            input.direction,
            &source_id,
            &target_id,
        ),
        relation_id: "relation-1".to_owned(),
        operation_id: input.operation_id.clone(),
        input_digest,
        policy_digest: input.policy_digest.clone(),
        kind: CurationKind::Relation,
        family: input.family,
        direction: input.direction,
        source_id,
        target_id,
        source_material_digest: input.source.material_digest().to_owned(),
        target_material_digest: input.target.material_digest().to_owned(),
        registry_digest: input.registry.digest.clone(),
        temporal: input.temporal.clone(),
        evidence_refs: vec!["evidence-1".to_owned()],
        counterevidence_refs: Vec::new(),
        rival_refs: vec!["rival-1".to_owned()],
        no_relation_ref: Some("no-relation-1".to_owned()),
        before: None,
        after: None,
        preservation: input.preservation.clone(),
        rollback: RelationRollback {
            predecessor: None,
            rollback_refs: vec!["relation-1".to_owned()],
            removal_or_restoration_refs: vec!["relation-1".to_owned()],
            invalidation_refs: Vec::new(),
            raw_history_refs: vec!["source-a".to_owned()],
            note: "reversible".to_owned(),
        },
        disposition: RelationDisposition::Positive,
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

#[test]
fn typed_relation_seals_against_accepted_context() {
    let (input, ctx) = fixtures();
    let supplied_candidate = candidate(&input);
    let closure = seal_relation(input.clone(), supplied_candidate, &ctx).expect("seal");
    closure.validate(&input).expect("closed relation validates");
    assert_eq!(
        closure.candidate.source_material_digest,
        input.source.material_digest()
    );
    let mut mismatched_screen = (*ctx.screen).clone();
    mismatched_screen.item_digest = digest("different-item");
    let mismatched_screen = Box::leak(Box::new(mismatched_screen));
    let mismatched_ctx = CurationAcceptanceCtx {
        screen: mismatched_screen,
        ..ctx
    };
    assert!(input.validate_acceptance(&mismatched_ctx).is_err());
}

#[test]
fn candidate_requires_exact_direction_and_material_digests() {
    let (input, _ctx) = fixtures();
    let mut reversed_candidate = candidate(&input);
    reversed_candidate.direction = RelationDirection::Reverse;
    assert!(reversed_candidate.validate_against(&input).is_err());
    let mut changed_candidate = candidate(&input);
    changed_candidate.target_material_digest = digest("changed");
    assert!(changed_candidate.validate_against(&input).is_err());

    let mut forbidden_self = input.clone();
    forbidden_self.target = endpoint("source-a", "target", "source-a");
    if let CurationPayload::Relation(payload) = &mut forbidden_self.item.payload {
        payload.to_handle = "source-a".to_owned();
        payload.target_evidence.targets = vec!["source-a".to_owned()];
    }
    forbidden_self.item.denominator.members = vec!["source-a".to_owned()];
    forbidden_self.item.denominator.expected_total = 1;
    forbidden_self.evidence[0].predicate.target_id = "source-a".to_owned();
    forbidden_self.rivals.clear();
    forbidden_self.no_relation_alternative = None;
    assert!(validate_relation(&forbidden_self).is_err());
    let mut permitted_self = forbidden_self.clone();
    permitted_self.registry.rules[0].permits_self_relation = true;
    permitted_self.registry.digest = permitted_self
        .registry
        .computed_digest()
        .expect("self registry");
    assert!(validate_relation(&permitted_self).is_ok());
}

#[test]
fn relation_registry_rejects_incomplete_partition() {
    let mut incomplete = registry();
    incomplete.omitted_families.clear();
    assert!(incomplete.validate().is_err());
    let mut duplicate = registry();
    duplicate.omitted_families = vec![RelationFamily::Contradicts, RelationFamily::Contradicts];
    duplicate.digest = duplicate.computed_digest().expect("duplicate digest");
    assert!(duplicate.validate().is_err());

    let (mut input, _ctx) = fixtures();
    input.neighborhood.complete = false;
    input.neighborhood.omitted_refs = vec!["relation-omitted".to_owned()];
    validate_relation(&input).expect("partial neighborhood remains explicit");
    candidate(&input)
        .validate_against(&input)
        .expect("retained rollback and raw history references validate");
    let mut bad = candidate(&input);
    bad.preservation.verdicts[0].known = false;
    assert!(bad.preservation.overall().is_err());
    assert!(bad.validate_against(&input).is_err());
    let mut failed = candidate(&input);
    failed.preservation.verdicts[1].passed = false;
    assert!(failed.preservation.overall().is_err());
}

#[test]
fn typed_alternatives_and_no_relation_are_retained() {
    let (mut input, ctx) = fixtures();
    let mut rival_evidence = evidence();
    rival_evidence.named.id = id("evidence-rival");
    rival_evidence
        .named
        .foundation_evidence_envelope
        .provenance
        .raw_handle = Some("evidence-rival".to_owned());
    rival_evidence.predicate.family = Some(RelationFamily::Contradicts);
    rival_evidence.predicate.expression = "contradicts directly".to_owned();
    rival_evidence.polarity = RelationEvidencePolarity::Counter;
    let mut no_relation_evidence = evidence();
    no_relation_evidence.named.id = id("evidence-none");
    no_relation_evidence
        .named
        .foundation_evidence_envelope
        .provenance
        .raw_handle = Some("evidence-none".to_owned());
    no_relation_evidence.predicate.family = None;
    no_relation_evidence.predicate.direction = None;
    no_relation_evidence.predicate.expression = "no relation observed".to_owned();
    no_relation_evidence.polarity = RelationEvidencePolarity::Unknown;
    input.counterevidence.push(rival_evidence);
    input.counterevidence.push(no_relation_evidence);
    input.rivals[0].evidence_refs = vec!["evidence-rival".to_owned()];
    input
        .no_relation_alternative
        .as_mut()
        .expect("no relation")
        .evidence_refs = vec!["evidence-none".to_owned()];
    validate_relation(&input).expect("typed alternatives validate");
    input
        .validate_acceptance(&ctx)
        .expect("qualified evidence resolves accepted materials");
    assert_eq!(input.rivals[0].family, Some(RelationFamily::Contradicts));
    assert_eq!(
        input.rivals[0].source_revision,
        input.source.admitted.target_revision
    );
    assert_eq!(
        input.rivals[0].target_material_digest,
        input.target.material_digest()
    );
    assert_ne!(
        input.evidence[0].evidence_id(),
        input.counterevidence[0].evidence_id()
    );
    assert_ne!(
        input.counterevidence[0].evidence_id(),
        input.counterevidence[1].evidence_id()
    );
    assert!(
        input
            .no_relation_alternative
            .as_ref()
            .expect("no relation")
            .family
            .is_none()
    );
}

#[test]
fn directed_input_digest_changes_when_endpoints_swap() {
    let (input, ctx) = fixtures();
    let input_digest = relation_input_digest(&input).expect("input digest");
    let closure = seal_relation(input.clone(), candidate(&input), &ctx).expect("seal");
    let mut permuted = closure.clone();
    permuted.input.screen.screened_targets.reverse();
    permuted.input.registry.denominator.reverse();
    assert_eq!(
        relation_input_digest(&permuted.input).expect("permuted input digest"),
        input_digest
    );
    permuted
        .validate(&input)
        .expect("set permutations preserve closure");
    assert_eq!(permuted.result_digest, closure.result_digest);

    let mut reversed = input.clone();
    reversed.direction = RelationDirection::Reverse;
    reversed.registry.rules[0].direction = RelationDirection::Reverse;
    reversed.evidence[0].predicate.direction = Some(RelationDirection::Reverse);
    reversed.registry.digest = reversed
        .registry
        .computed_digest()
        .expect("reverse registry");
    reversed.rivals[0].registry_digest = reversed.registry.digest.clone();
    reversed
        .no_relation_alternative
        .as_mut()
        .expect("no relation")
        .registry_digest = reversed.registry.digest.clone();
    let reversed_candidate = candidate(&reversed);
    assert_ne!(
        candidate(&input).candidate_id,
        reversed_candidate.candidate_id
    );
    reversed_candidate
        .validate_against(&reversed)
        .expect("valid direction change remains structurally valid");
}
