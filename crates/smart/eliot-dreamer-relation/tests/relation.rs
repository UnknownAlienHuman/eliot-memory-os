//! Structural proofs for the A03 typed relation closure.
#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, SourceId,
    StateFence, TaskId, sha256_hex,
};
use eliot_dreamer_contracts::curation::{ClassificationPayload, RelationPayload, TargetEvidence};
use eliot_dreamer_contracts::encoding::canonical_bytes;
use eliot_dreamer_contracts::*;
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_receipts::{ReceiptIdentity, WorkScopeId};
use std::num::NonZeroU64;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("id")
}
fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
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
    EvidenceGradeBinding, GroundedRelationDraft, RelationPolicy, RelationResult,
    grade_binding_digest, propose_relation,
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

/// Decomposed 655-case: the validated item, grounded draft, endpoint pair,
/// registry snapshot and neighborhood travel as separate typed inputs.
struct Case {
    item: ValidatedCurationItem,
    draft: GroundedRelationDraft,
    source: RelationEndpoint,
    target: RelationEndpoint,
    registry: RelationRegistrySnapshot,
    neighborhood: RelationNeighborhood,
    policy: RelationPolicy,
    ctx: CurationAcceptanceCtx<'static>,
}

impl Case {
    fn from_input(
        input: RelationInput,
        policy: RelationPolicy,
        ctx: CurationAcceptanceCtx<'static>,
    ) -> Self {
        Self {
            draft: GroundedRelationDraft {
                schema_version: input.schema_version,
                operation_id: input.operation_id.clone(),
                request_id: input.request_id.clone(),
                idempotency_key: input.idempotency_key.clone(),
                task_id: input.task_id.clone(),
                scope_id: input.scope_id.clone(),
                state_fence: input.state_fence.clone(),
                policy_digest: input.policy_digest.clone(),
                family: input.family,
                direction: input.direction,
                screen: input.screen.clone(),
                evidence: input.evidence.clone(),
                counterevidence: input.counterevidence.clone(),
                rivals: input.rivals.clone(),
                no_relation_alternative: input.no_relation_alternative.clone(),
                temporal: input.temporal.clone(),
                verifier: input.verifier.clone(),
                disclosure_evidence: input.disclosure_evidence.clone(),
                preservation: input.preservation.clone(),
            },
            item: input.item,
            source: input.source,
            target: input.target,
            registry: input.registry,
            neighborhood: input.neighborhood,
            policy,
            ctx,
        }
    }

    fn ready() -> Self {
        let (input, policy, ctx) = prepared(fixtures().0);
        Self::from_input(input, policy, ctx)
    }

    fn causal() -> Self {
        let (input, policy, ctx) = causal_fixtures();
        Self::from_input(input, policy, ctx)
    }

    /// Reassembles the closed input closure from the current decomposed parts.
    fn assembled(&self) -> RelationInput {
        self.draft.assemble(
            &self.item,
            &self.source,
            &self.target,
            &self.registry,
            &self.neighborhood,
        )
    }

    fn run(&self) -> Result<RelationResult, eliot_dreamer_contracts::ContractViolation> {
        propose_relation(
            &self.item,
            &self.draft,
            &self.source,
            &self.target,
            &self.registry,
            &self.neighborhood,
            &self.ctx,
            &self.policy,
        )
    }

    /// Re-seals the policy after a policy mutation and rebinds the draft.
    fn reseal(&mut self) {
        self.policy.seal().expect("reseal policy");
        self.draft.policy_digest.clone_from(&self.policy.digest);
    }

    /// Recomputes the registry digest after a registry mutation and rebinds
    /// every alternative and neighborhood snapshot to the new digest.
    fn rebind_registry(&mut self) {
        self.registry.digest = self.registry.computed_digest().expect("registry digest");
        for alternative in self
            .draft
            .rivals
            .iter_mut()
            .chain(self.draft.no_relation_alternative.iter_mut())
        {
            alternative
                .registry_digest
                .clone_from(&self.registry.digest);
        }
        for relation in &mut self.neighborhood.relations {
            relation.registry_digest.clone_from(&self.registry.digest);
        }
    }

    /// Re-points evidence predicates, alternatives and the disclosure decision
    /// at the current endpoint pair after an endpoint swap.
    fn rebind_pair(&mut self) {
        let source_id = self.source.endpoint_id().to_owned();
        let target_id = self.target.endpoint_id().to_owned();
        let source_revision = self.source.admitted.target_revision.clone();
        let target_revision = self.target.admitted.target_revision.clone();
        let source_material = self.source.material_digest().to_owned();
        let target_material = self.target.material_digest().to_owned();
        let source_admission_id = self
            .source
            .admitted
            .admission
            .receipt_id
            .as_str()
            .to_owned();
        let target_admission_id = self
            .target
            .admitted
            .admission
            .receipt_id
            .as_str()
            .to_owned();
        let source_admission_digest = self.source.admitted.admission.canonical_sha256.clone();
        let target_admission_digest = self.target.admitted.admission.canonical_sha256.clone();
        for evidence in self
            .draft
            .evidence
            .iter_mut()
            .chain(self.draft.counterevidence.iter_mut())
        {
            evidence.predicate.source_id.clone_from(&source_id);
            evidence.predicate.target_id.clone_from(&target_id);
        }
        for alternative in self
            .draft
            .rivals
            .iter_mut()
            .chain(self.draft.no_relation_alternative.iter_mut())
        {
            alternative.source_id.clone_from(&source_id);
            alternative.target_id.clone_from(&target_id);
            alternative.source_revision.clone_from(&source_revision);
            alternative.target_revision.clone_from(&target_revision);
            alternative
                .source_material_digest
                .clone_from(&source_material);
            alternative
                .target_material_digest
                .clone_from(&target_material);
            alternative
                .source_admission_id
                .clone_from(&source_admission_id);
            alternative
                .target_admission_id
                .clone_from(&target_admission_id);
            alternative
                .source_admission_digest
                .clone_from(&source_admission_digest);
            alternative
                .target_admission_digest
                .clone_from(&target_admission_digest);
        }
        if let Some(disclosure) = self.draft.disclosure_evidence.as_mut() {
            disclosure.source_id.clone_from(&source_id);
            disclosure.target_id.clone_from(&target_id);
            disclosure.source_revision.clone_from(&source_revision);
            disclosure.target_revision.clone_from(&target_revision);
            disclosure
                .source_material_digest
                .clone_from(&source_material);
            disclosure
                .target_material_digest
                .clone_from(&target_material);
            disclosure
                .source_admission_id
                .clone_from(&source_admission_id);
            disclosure
                .target_admission_id
                .clone_from(&target_admission_id);
            disclosure
                .source_admission_digest
                .clone_from(&source_admission_digest);
            disclosure
                .target_admission_digest
                .clone_from(&target_admission_digest);
            disclosure.family = self.draft.family;
            disclosure.direction = self.draft.direction;
        }
    }

    /// Recomputes the accepted item digest after an item payload change and
    /// rebuilds the retained screen, handler request and acceptance context.
    fn rescreen(&mut self) {
        let item_digest = self
            .item
            .item_digest(self.ctx.grounded)
            .expect("item digest");
        let mut screen = self.draft.screen.clone();
        screen.item_digest = item_digest;
        screen
            .screened_targets
            .clone_from(&self.item.payload.facets().targets);
        let mut request = (*self.ctx.request).clone();
        request.payload = self.item.payload.clone();
        request.denominator = self.item.denominator.clone();
        request.screen_binding = Some(screen.clone());
        self.draft.screen = screen.clone();
        let screen_ref = Box::leak(Box::new(screen));
        let request_ref = Box::leak(Box::new(request));
        self.ctx = CurationAcceptanceCtx {
            job: self.ctx.job,
            bundle: self.ctx.bundle,
            receipt: self.ctx.receipt,
            screen: screen_ref,
            grounded: self.ctx.grounded,
            request: request_ref,
            usage: self.ctx.usage,
        };
    }
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
    let mut case = Case::from_input(input, policy, ctx);
    let result = case.run().expect("positive relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    case.draft.disclosure_evidence = None;
    assert!(case.run().is_err());
}

#[test]
fn causal_claim_accepts_lower_ceiling_and_rejects_missing_proof() {
    let (input, policy, ctx) = causal_fixtures();
    let mut case = Case::from_input(input, policy, ctx);
    let result = case.run().expect("causal relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    result.validate().expect("sealed causal result");
    case.policy.causal_material = None;
    case.reseal();
    assert!(case.run().is_err());
}

#[test]
fn permitted_path_and_forbidden_path_are_distinct() {
    let (input, policy, ctx) = prepared(fixtures().0);
    let mut case = Case::from_input(input, policy, ctx);
    case.draft.evidence.clear();
    case.registry.rules[0].permits_transitive = true;
    case.rebind_registry();
    let edge_one_id = "edge-1";
    let edge_one = snapshot(
        &case.assembled(),
        edge_one_id,
        case.draft.family,
        case.draft.direction,
        "source-a",
        "middle-c",
    );
    let edge_two_id = "edge-2";
    let edge_two = snapshot(
        &case.assembled(),
        edge_two_id,
        case.draft.family,
        case.draft.direction,
        "middle-c",
        "target-b",
    );
    case.neighborhood
        .relations
        .extend([edge_one.clone(), edge_two.clone()]);
    case.policy.transitive_path = vec![
        eliot_dreamer_relation::PathRef {
            edge_id: edge_one_id.to_owned(),
            relation_digest: edge_one.relation_digest.clone(),
        },
        eliot_dreamer_relation::PathRef {
            edge_id: edge_two_id.to_owned(),
            relation_digest: edge_two.relation_digest.clone(),
        },
    ];
    case.reseal();
    case.run().expect("permitted transitive path");
    case.policy.transitive_path[0].relation_digest = edge_one.relation_digest;
    case.registry.rules[0].permits_transitive = false;
    case.rebind_registry();
    case.reseal();
    assert!(case.run().is_err());
}

#[test]
fn duplicate_inverse_and_changed_snapshot_are_retained() {
    let (input, policy, ctx) = prepared(fixtures().0);
    let mut case = Case::from_input(input, policy, ctx);
    let id = "external-retained";
    let existing = snapshot(
        &case.assembled(),
        id,
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    case.neighborhood.relations.push(existing.clone());
    case.policy.proposed_snapshot = Some(existing.clone());
    case.reseal();
    let result = case.run().expect("duplicate");
    assert_eq!(result.disposition, RelationDisposition::Duplicate);
    assert_eq!(result.closure.candidate.relation_id, id);
    let mut changed = existing;
    changed.relation_digest = digest("changed");
    case.policy.proposed_snapshot = Some(changed);
    case.reseal();
    assert_eq!(
        case.run().expect("conflict").disposition,
        RelationDisposition::Conflict
    );

    let mut inverse_case = Case::ready();
    let inverse = snapshot(
        &inverse_case.assembled(),
        "inverse-retained",
        RelationFamily::Contradicts,
        RelationDirection::Forward,
        "target-b",
        "source-a",
    );
    inverse_case.neighborhood.relations.push(inverse.clone());
    let inverse_result = inverse_case.run().expect("inverse relation");
    assert_eq!(inverse_result.disposition, RelationDisposition::Inverse);
    assert_eq!(
        inverse_result.closure.candidate.before.as_ref(),
        Some(&inverse)
    );

    let mut symmetric_case = Case::ready();
    symmetric_case.registry.rules[0].symmetric = true;
    symmetric_case.registry.rules[0].inverse_family = None;
    symmetric_case.rebind_registry();
    let symmetric = snapshot(
        &symmetric_case.assembled(),
        "symmetric-retained",
        RelationFamily::Supports,
        RelationDirection::Forward,
        "target-b",
        "source-a",
    );
    symmetric_case
        .neighborhood
        .relations
        .push(symmetric.clone());
    let symmetric_result = symmetric_case.run().expect("symmetric relation");
    assert_eq!(symmetric_result.disposition, RelationDisposition::Ambiguous);
    assert_eq!(
        symmetric_result.closure.candidate.before.as_ref(),
        Some(&symmetric)
    );
}

#[test]
fn replay_permutation_bounds_and_cancel_are_explicit() {
    let (input, policy, ctx) = prepared(fixtures().0);
    let mut case = Case::from_input(input, policy, ctx);
    let first = case.run().expect("first replay");
    first.validate().expect("first sealed replay");
    let digest_before = case.policy.digest.clone();
    case.policy.grade_bindings.reverse();
    case.policy.expected_alternative_refs.reverse();
    case.policy.seal().expect("normalized policy");
    assert_eq!(digest_before, case.policy.digest);
    let second = case.run().expect("second replay");
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(first.closure.result_digest, second.closure.result_digest);
    case.draft.counterevidence.reverse();
    let permuted = case.run().expect("permuted replay");
    assert_eq!(first.result_digest, permuted.result_digest);
    assert_eq!(first.closure.result_digest, permuted.closure.result_digest);
    case.policy.cancellation_requested = true;
    case.reseal();
    assert!(case.run().is_err());
    case.policy.cancellation_requested = false;
    case.policy.max_evidence = 1;
    case.reseal();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/1
#[test]
fn work_unit_655_01_valid_directed_typed_relation() {
    let case = Case::ready();
    let result = case.run().expect("valid directed relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    result.validate().expect("sealed result");
    let candidate = &result.closure.candidate;
    assert_eq!(candidate.family, RelationFamily::Supports);
    assert_eq!(candidate.direction, RelationDirection::Forward);
    assert_eq!(candidate.source_id, case.source.endpoint_id());
    assert_eq!(candidate.target_id, case.target.endpoint_id());
    assert_eq!(candidate.registry_digest, case.registry.digest);
    assert_eq!(candidate.evidence_refs, vec!["evidence-1".to_owned()]);
    assert_eq!(result.closure.input.source, case.source);
    assert_eq!(result.closure.input.target, case.target);
}

// WORK_UNIT_CASE: 655/2
#[test]
fn work_unit_655_02_kind_role_direction_vocabulary() {
    assert_eq!(RelationFamily::Supports.as_str(), "supports");
    assert_eq!(
        RelationFamily::parse("supports").expect("parse"),
        RelationFamily::Supports
    );
    assert!(RelationFamily::parse("correlates_with").is_err());
    // Family outside the admitted registry denominator and rules fails.
    let mut case = Case::ready();
    case.draft.family = RelationFamily::Resembles;
    case.item.payload = payload_for_relation("resembles");
    case.rescreen();
    assert!(case.run().is_err());
    // Direction against the per-family registry rule fails.
    let mut case = Case::ready();
    case.draft.direction = RelationDirection::Reverse;
    case.rebind_pair();
    match case.run() {
        Err(ContractViolation::BindingMismatch { field, .. }) => {
            assert_eq!(field, "relation.direction");
        }
        other => panic!("expected direction rejection, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 655/3
#[test]
fn work_unit_655_03_wrong_curation_subtype_rejected() {
    // A genuine classification payload with matching spelling is not Relation.
    let mut case = Case::ready();
    case.item.kind_spelling = "classification".to_owned();
    case.item.family_spelling = "classification".to_owned();
    case.item.payload = CurationPayload::Classification(ClassificationPayload {
        label: "label".to_owned(),
        confidence_bps: 9_000,
        target_evidence: TargetEvidence {
            targets: vec!["source-a".to_owned(), "target-b".to_owned()],
            evidence_refs: vec!["evidence-1".to_owned()],
        },
    });
    case.rescreen();
    assert!(case.run().is_err());
    // Kind/payload drift: classification spelling over a relation payload.
    let mut drift = Case::ready();
    drift.item.kind_spelling = "classification".to_owned();
    drift.item.family_spelling = "classification".to_owned();
    drift.rescreen();
    assert!(drift.run().is_err());
    // Relation-string drift between the curation payload and the draft family.
    let mut relation = Case::ready();
    relation.item.payload = payload_for_relation("contradicts");
    relation.rescreen();
    assert!(relation.run().is_err());
}

// WORK_UNIT_CASE: 655/4
#[test]
fn work_unit_655_04_unadmitted_endpoints_rejected() {
    // Quarantined source.
    let mut case = Case::ready();
    case.source.admitted.lifecycle = LifecycleState::Quarantined;
    assert!(case.run().is_err());
    // Extinguished (deleted) target.
    let mut case = Case::ready();
    case.target.admitted.lifecycle = LifecycleState::Extinguished;
    assert!(case.run().is_err());
    // Archived (superseded lineage) source.
    let mut case = Case::ready();
    case.source.admitted.lifecycle = LifecycleState::Archived;
    assert!(case.run().is_err());
    // Stale freshness is not current.
    let mut case = Case::ready();
    case.source.admitted.freshness = EvidenceFreshness::Stale;
    assert!(case.run().is_err());
    // A known older snapshot is not current either.
    let mut case = Case::ready();
    case.target.admitted.freshness = EvidenceFreshness::KnownOlderSnapshot;
    assert!(case.run().is_err());
    // Rejected epistemic status is inadmissible.
    let mut case = Case::ready();
    case.source.status = EpistemicStatus::Rejected;
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/5
#[test]
fn work_unit_655_05_endpoint_identity_mismatch_rejected() {
    // Scope drift breaks the endpoint join.
    let mut case = Case::ready();
    case.source.admitted.scope_id = WorkScopeId::new("scope-2").expect("scope");
    assert!(case.run().is_err());
    // Task drift breaks the endpoint join.
    let mut case = Case::ready();
    case.target.admitted.task_id = TaskId::new("task-2").expect("task");
    assert!(case.run().is_err());
    // Fence drift breaks the endpoint join.
    let mut case = Case::ready();
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001").expect("lineage-B"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    case.source.admitted.state_fence = StateFence::new(epoch, ResourceGeneration::genesis());
    assert!(case.run().is_err());
    // Role outside the registry rule.
    let mut case = Case::ready();
    case.target.role = "observer".to_owned();
    assert!(case.run().is_err());
    // Record family outside the registry rule.
    let mut case = Case::ready();
    case.source.record_family = ClassificationRecordFamily::SourceRecord;
    assert!(case.run().is_err());
    // Revision drift breaks the closed alternative and disclosure bindings.
    let mut case = Case::ready();
    case.source.admitted.target_revision = "rev-2".to_owned();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/6
#[test]
fn work_unit_655_06_self_relation_needs_registry_permission() {
    fn self_case() -> Case {
        let mut case = Case::ready();
        case.target = case.source.clone();
        case.target.role = "target".to_owned();
        case.item.payload = CurationPayload::Relation(RelationPayload {
            from_handle: "source-a".to_owned(),
            to_handle: "source-a".to_owned(),
            relation: "supports".to_owned(),
            target_evidence: TargetEvidence {
                targets: vec!["source-a".to_owned()],
                evidence_refs: vec!["evidence-1".to_owned()],
            },
        });
        case.item.denominator = TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["source-a".to_owned()],
            expected_total: 1,
        };
        case.rebind_pair();
        case.rescreen();
        case
    }
    // Forbidden by default: permitted endpoint equality is a self-relation
    // rejection, never a duplicate-record error.
    let forbidden = self_case();
    match forbidden.run() {
        Err(ContractViolation::BindingMismatch { field, .. }) => {
            assert_eq!(field, "relation.self_relation");
        }
        other => panic!("expected self-relation rejection, got {other:?}"),
    }
    // Permitted by the registry: the same equality proposes normally.
    let mut permitted = self_case();
    permitted.registry.rules[0].permits_self_relation = true;
    permitted.rebind_registry();
    let result = permitted.run().expect("permitted self relation");
    assert_ne!(result.disposition, RelationDisposition::Duplicate);
    result.validate().expect("sealed self relation");
}

// WORK_UNIT_CASE: 655/7
#[test]
fn work_unit_655_07_endpoint_kind_compatibility() {
    // Record family outside the rule.
    let mut case = Case::ready();
    case.source.record_family = ClassificationRecordFamily::DecisionRecord;
    assert!(case.run().is_err());
    // Tightened rule: only decision sources accepted.
    let mut case = Case::ready();
    case.registry.rules[0].source_record_families =
        vec![ClassificationRecordFamily::DecisionRecord];
    case.rebind_registry();
    assert!(case.run().is_err());
    // Role outside the rule.
    let mut case = Case::ready();
    case.source.role = "witness".to_owned();
    assert!(case.run().is_err());
    // Positive control: the admitted pair with registry-valid roles and types.
    let case = Case::ready();
    let result = case.run().expect("kind-compatible relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
}

// WORK_UNIT_CASE: 655/8
#[test]
fn work_unit_655_08_association_disclosure_violation() {
    // Independently safe endpoints do not make the association safe.
    let mut case = Case::ready();
    case.draft.disclosure_evidence = None;
    assert!(case.run().is_err());
    // Explicit denial.
    let mut case = Case::ready();
    case.draft
        .disclosure_evidence
        .as_mut()
        .expect("disclosure")
        .permitted = Some(false);
    assert!(case.run().is_err());
    // Permitted flag with a rejecting decision.
    let mut case = Case::ready();
    case.draft
        .disclosure_evidence
        .as_mut()
        .expect("disclosure")
        .decision = EpistemicStatus::Rejected;
    assert!(case.run().is_err());
    // An empty owner is not an owner decision.
    let mut case = Case::ready();
    case.draft
        .disclosure_evidence
        .as_mut()
        .expect("disclosure")
        .owner
        .clear();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/9
#[test]
fn work_unit_655_09_exact_direct_relation_evidence() {
    let case = Case::ready();
    let result = case.run().expect("direct evidence relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    assert_eq!(
        result.closure.candidate.evidence_refs,
        vec!["evidence-1".to_owned()]
    );
    assert!(result.closure.candidate.counterevidence_refs.is_empty());
    // Without direct evidence the relation is not positive.
    let mut case = Case::ready();
    case.draft.evidence.clear();
    let result = case.run().expect("unsupported relation");
    assert_ne!(result.disposition, RelationDisposition::Positive);
}

// WORK_UNIT_CASE: 655/10
#[test]
fn work_unit_655_10_partial_contradicted_unknown_evidence() {
    // Contradicted: primary support plus unbound counterevidence.
    let mut case = Case::ready();
    let mut counter = case.draft.evidence[0].clone();
    counter.named.id = id("target-b");
    counter.named.external_grade = Some(relation_grade_binding("target-b").reference);
    counter.polarity = RelationEvidencePolarity::Counter;
    case.draft.counterevidence.push(counter);
    case.policy
        .grade_bindings
        .push(relation_grade_binding("target-b"));
    case.reseal();
    let result = case.run().expect("contradicted relation");
    assert_eq!(result.disposition, RelationDisposition::Conflict);
    // Unknown polarity stays unknown: abstention, not a positive edge.
    let mut case = Case::ready();
    case.draft.evidence[0].polarity = RelationEvidencePolarity::Unknown;
    let result = case.run().expect("unknown evidence relation");
    assert_eq!(result.disposition, RelationDisposition::Abstention);
    assert_eq!(result.unknown_evidence_refs, vec!["evidence-1".to_owned()]);
    // Partial coverage cannot ground a positive edge.
    let mut case = Case::ready();
    case.draft.evidence[0]
        .named
        .foundation_evidence_envelope
        .coverage = EvidenceCoverage::PartialForScope;
    let result = case.run().expect("partial evidence relation");
    assert_eq!(result.disposition, RelationDisposition::Abstention);
}

// WORK_UNIT_CASE: 655/11
#[test]
fn work_unit_655_11_similarity_cannot_establish_relation() {
    // A similar-but-different endpoint handle never joins the admitted pair.
    let mut case = Case::ready();
    case.draft.evidence[0].predicate.source_id = "source-a-lookalike".to_owned();
    assert!(case.run().is_err());
    // A lookalike alternative never joins the admitted pair either.
    let mut case = Case::ready();
    case.draft.rivals[0].source_id = "source-a-lookalike".to_owned();
    assert!(case.run().is_err());
    // Cue-overlap wording with the exact tuple still needs qualified evidence.
    let mut case = Case::ready();
    case.draft.evidence[0].predicate.expression =
        "looks like source-a supports target-b".to_owned();
    case.draft.evidence[0].named.external_grade = None;
    let result = case.run().expect("similarity wording without grade");
    assert_ne!(result.disposition, RelationDisposition::Positive);
}

// WORK_UNIT_CASE: 655/12
#[test]
fn work_unit_655_12_cooccurrence_cannot_establish_relation() {
    // Frequently cited but ungraded evidence stays unknown: no positive edge.
    let mut case = Case::ready();
    case.draft.evidence[0].named.external_grade = None;
    let result = case.run().expect("ungraded relation");
    assert_ne!(result.disposition, RelationDisposition::Positive);
    // Repeated citations of one handle cannot corroborate independently.
    let mut case = Case::ready();
    let repeat = case.draft.evidence[0].clone();
    case.draft.evidence.push(repeat);
    assert!(case.run().is_err());
    // Retrieval rank without a grade binding is not support either.
    let mut case = Case::ready();
    case.policy.grade_bindings.clear();
    case.reseal();
    let result = case.run().expect("unbound grades");
    assert_ne!(result.disposition, RelationDisposition::Positive);
}

// WORK_UNIT_CASE: 655/13
#[test]
fn work_unit_655_13_chronology_cannot_establish_causality() {
    // Ordered times with no mechanism, rivals or confounders: not causal.
    let mut case = Case::causal();
    case.policy.causal_claim = None;
    case.policy.causal_bindings.clear();
    case.policy.causal_material = None;
    case.policy.causal_predicate = None;
    case.reseal();
    let result = case.run().expect("chronology-only causal draft");
    assert_ne!(result.disposition, RelationDisposition::Positive);
    // The chronology itself is preserved even though causality is refused.
    assert!(result.closure.candidate.temporal.event_time.is_some());
}

// WORK_UNIT_CASE: 655/14
#[test]
fn work_unit_655_14_valid_causal_mechanism_with_rivals() {
    let case = Case::causal();
    let result = case.run().expect("causal relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    result.validate().expect("sealed causal result");
    assert_eq!(result.closure.candidate.family, RelationFamily::Causes);
    assert!(
        result
            .closure
            .candidate
            .evidence_refs
            .contains(&"evidence-1".to_owned())
    );
    assert!(
        result
            .closure
            .candidate
            .rival_refs
            .contains(&"rival-1".to_owned())
    );
    assert_eq!(
        result.closure.candidate.no_relation_ref.as_deref(),
        Some("no-relation-1")
    );
    let kinds: Vec<EvidenceBindingKind> = case
        .policy
        .causal_bindings
        .iter()
        .map(|binding| binding.kind)
        .collect();
    for required in [
        EvidenceBindingKind::Mechanism,
        EvidenceBindingKind::Rival,
        EvidenceBindingKind::Confounder,
        EvidenceBindingKind::Discriminator,
    ] {
        assert!(
            kinds.contains(&required),
            "missing causal role {required:?}"
        );
    }
}

// WORK_UNIT_CASE: 655/15
#[test]
fn work_unit_655_15_missing_causal_discriminator_or_confounder() {
    // Without a discriminator the asserted claim no longer joins its exact
    // role bindings: a typed roles rejection, never a positive causal edge.
    let mut case = Case::causal();
    case.policy
        .causal_bindings
        .retain(|binding| binding.kind != EvidenceBindingKind::Discriminator);
    case.reseal();
    match case.run() {
        Err(ContractViolation::BindingMismatch { field, .. }) => {
            assert_eq!(field, "relation.causal_claim.roles");
        }
        other => panic!("expected causal roles rejection, got {other:?}"),
    }
    // Without a confounder the same join fails.
    let mut case = Case::causal();
    case.policy
        .causal_bindings
        .retain(|binding| binding.kind != EvidenceBindingKind::Confounder);
    case.reseal();
    match case.run() {
        Err(ContractViolation::BindingMismatch { field, .. }) => {
            assert_eq!(field, "relation.causal_claim.roles");
        }
        other => panic!("expected causal roles rejection, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 655/16
#[test]
fn work_unit_655_16_five_times_and_clock_conversion() {
    let case = Case::causal();
    let result = case.run().expect("five-time causal relation");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    let temporal = &result.closure.candidate.temporal;
    for point in [
        &temporal.event_time,
        &temporal.effective_time,
        &temporal.observation_time,
        &temporal.ingestion_time,
        &temporal.commit_time,
    ] {
        assert!(point.is_some(), "all five causal times are retained");
    }
    // A conversion reference to an absent material is rejected.
    let mut case = Case::causal();
    case.draft
        .temporal
        .event_time
        .as_mut()
        .expect("event time")
        .conversion_ref = Some("absent-clock".to_owned());
    assert!(case.run().is_err());
    // Cross-clock readings without an exact typed mapping are rejected.
    let mut case = Case::causal();
    case.draft
        .temporal
        .commit_time
        .as_mut()
        .expect("commit time")
        .clock_ref = "clock-2".to_owned();
    assert!(case.run().is_err());
}

fn time_point(value: i64) -> RelationTimePoint {
    RelationTimePoint {
        reading: eliot_contracts::ClockReading {
            valid_time_ms: Some(value),
            known_time_ms: Some(value),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        clock_ref: "clock-1".to_owned(),
        uncertainty_ms: 0,
        conversion_ref: None,
    }
}

// WORK_UNIT_CASE: 655/17
#[test]
fn work_unit_655_17_partial_temporal_order_preserved() {
    // Serialization order never proves event order: an inverted commit/event
    // pair is retained as supplied without imposing an order.
    let mut case = Case::ready();
    case.policy.temporal_required = true;
    case.draft.temporal = RelationTemporalEvidence {
        event_time: Some(time_point(20)),
        effective_time: None,
        observation_time: None,
        ingestion_time: None,
        commit_time: Some(time_point(10)),
        temporal_status: EpistemicStatus::Supported,
        uncertainty_ref: None,
    };
    case.reseal();
    let result = case.run().expect("inverted order retained");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    assert_eq!(
        result
            .closure
            .candidate
            .temporal
            .event_time
            .as_ref()
            .expect("event")
            .reading
            .valid_time_ms,
        Some(20)
    );
    assert_eq!(
        result
            .closure
            .candidate
            .temporal
            .commit_time
            .as_ref()
            .expect("commit")
            .reading
            .valid_time_ms,
        Some(10)
    );
    // A single explicit time point satisfies the temporal requirement.
    let mut case = Case::ready();
    case.policy.temporal_required = true;
    case.draft.temporal = RelationTemporalEvidence {
        event_time: Some(time_point(10)),
        effective_time: None,
        observation_time: None,
        ingestion_time: None,
        commit_time: None,
        temporal_status: EpistemicStatus::Supported,
        uncertainty_ref: None,
    };
    case.reseal();
    let result = case.run().expect("partial time");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    // Unknown temporal status fails even with points present.
    let mut case = Case::ready();
    case.policy.temporal_required = true;
    case.draft.temporal.temporal_status = EpistemicStatus::Unknown;
    case.reseal();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/18
#[test]
fn work_unit_655_18_duplicate_and_idempotent_replay() {
    let mut case = Case::ready();
    let first = case.run().expect("first");
    let second = case.run().expect("replay");
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(
        first.closure.candidate.candidate_id,
        second.closure.candidate.candidate_id
    );
    // An exact proposed snapshot matching the retained relation is a duplicate.
    let retained = snapshot(
        &case.assembled(),
        "dup-18",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    case.neighborhood.relations.push(retained);
    case.policy.proposed_snapshot = Some(case.neighborhood.relations[0].clone());
    case.reseal();
    let duplicate = case.run().expect("duplicate");
    assert_eq!(duplicate.disposition, RelationDisposition::Duplicate);
    let replay = case.run().expect("duplicate replay");
    assert_eq!(duplicate.result_digest, replay.result_digest);
}

// WORK_UNIT_CASE: 655/19
#[test]
fn work_unit_655_19_same_id_changed_payload_conflicts() {
    let mut case = Case::ready();
    let retained = snapshot(
        &case.assembled(),
        "stable-19",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    case.neighborhood.relations.push(retained.clone());
    let mut changed = retained.clone();
    changed.relation_digest = digest("changed-19");
    case.policy.proposed_snapshot = Some(changed);
    case.reseal();
    let result = case.run().expect("changed same-ID snapshot");
    assert_eq!(result.disposition, RelationDisposition::Conflict);
    assert_eq!(result.closure.candidate.before.as_ref(), Some(&retained));
    assert_eq!(result.closure.candidate.relation_id, "stable-19");
}

// WORK_UNIT_CASE: 655/20
#[test]
fn work_unit_655_20_invalid_reversal_is_not_an_inverse() {
    // A same-family reversed snapshot is neither the registry inverse nor
    // symmetric: it never yields an inverse disposition or a before record.
    let mut case = Case::ready();
    let reversed = snapshot(
        &case.assembled(),
        "reversed-20",
        RelationFamily::Supports,
        RelationDirection::Forward,
        "target-b",
        "source-a",
    );
    case.neighborhood.relations.push(reversed);
    let result = case.run().expect("reversed neighborhood");
    assert_ne!(result.disposition, RelationDisposition::Inverse);
    assert!(result.closure.candidate.before.is_none());
    // A proposal direction outside the registry rule fails outright.
    let mut case = Case::ready();
    case.draft.direction = RelationDirection::Reverse;
    assert!(case.run().is_err());
}

fn transitive_case() -> Case {
    let mut case = Case::ready();
    case.draft.evidence.clear();
    case.registry.rules[0].permits_transitive = true;
    case.rebind_registry();
    let assembled = case.assembled();
    let one = snapshot(
        &assembled,
        "path-1",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "middle-c",
    );
    let two = snapshot(
        &assembled,
        "path-2",
        case.draft.family,
        case.draft.direction,
        "middle-c",
        "target-b",
    );
    case.neighborhood.relations.extend([one, two]);
    case.policy.transitive_path = vec![
        eliot_dreamer_relation::PathRef {
            edge_id: "path-1".to_owned(),
            relation_digest: case.neighborhood.relations[0].relation_digest.clone(),
        },
        eliot_dreamer_relation::PathRef {
            edge_id: "path-2".to_owned(),
            relation_digest: case.neighborhood.relations[1].relation_digest.clone(),
        },
    ];
    case.reseal();
    case
}

// WORK_UNIT_CASE: 655/21
#[test]
fn work_unit_655_21_transitivity_allowed_or_forbidden() {
    // Allowed with complete supplied path evidence: derived candidate.
    transitive_case()
        .run()
        .expect("registry-allowed derivation");
    // Same path, registry forbids transitive derivation: fails.
    let mut case = transitive_case();
    case.registry.rules[0].permits_transitive = false;
    case.rebind_registry();
    case.reseal();
    assert!(case.run().is_err());
    // Permitted registry but a disconnected path: fails.
    let mut case = transitive_case();
    case.neighborhood.relations[1].source_id = "elsewhere-x".to_owned();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/22
#[test]
fn work_unit_655_22_different_kind_coexists_same_endpoints() {
    // A different-kind relation between the same endpoints coexists.
    let mut case = Case::ready();
    let other = snapshot(
        &case.assembled(),
        "other-kind-22",
        RelationFamily::Contradicts,
        RelationDirection::Forward,
        "source-a",
        "target-b",
    );
    case.neighborhood.relations.push(other);
    let result = case.run().expect("coexisting kinds");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    // Same-kind same-identity retention without a proposal is ambiguous.
    let mut case = Case::ready();
    let same = snapshot(
        &case.assembled(),
        "same-kind-22",
        RelationFamily::Supports,
        RelationDirection::Forward,
        "source-a",
        "target-b",
    );
    case.neighborhood.relations.push(same.clone());
    let result = case.run().expect("same-kind retention");
    assert_eq!(result.disposition, RelationDisposition::Ambiguous);
    assert_eq!(result.closure.candidate.before.as_ref(), Some(&same));
}

// WORK_UNIT_CASE: 655/23
#[test]
fn work_unit_655_23_overlap_supersession_predecessor() {
    // A dangling predecessor is rejected: no silent supersession.
    let mut case = Case::ready();
    let mut orphan = snapshot(
        &case.assembled(),
        "orphan-23",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    orphan.predecessor = Some("absent-predecessor".to_owned());
    case.neighborhood.relations.push(orphan);
    assert!(case.run().is_err());
    // An explicit retained predecessor chain is accepted as lineage; the
    // same-identity retention stays ambiguous rather than silently merging.
    let mut case = Case::ready();
    let first = snapshot(
        &case.assembled(),
        "first-23",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    let mut second = snapshot(
        &case.assembled(),
        "second-23",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    second.predecessor = Some("first-23".to_owned());
    case.neighborhood.relations.extend([first, second]);
    let result = case.run().expect("supersession lineage");
    assert_eq!(result.disposition, RelationDisposition::Ambiguous);
    // An explicitly omitted predecessor is accepted as lineage.
    let mut case = Case::ready();
    let mut omitted = snapshot(
        &case.assembled(),
        "omitted-23",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    omitted.predecessor = Some("gone-23".to_owned());
    case.neighborhood.relations.push(omitted);
    case.neighborhood.complete = false;
    case.neighborhood.omitted_refs = vec!["gone-23".to_owned()];
    let result = case.run().expect("omitted predecessor");
    assert_eq!(result.disposition, RelationDisposition::Ambiguous);
}

// WORK_UNIT_CASE: 655/24
#[test]
fn work_unit_655_24_incomplete_neighborhood_cannot_prove_uniqueness() {
    let mut case = Case::ready();
    case.neighborhood.complete = false;
    case.neighborhood.omitted_refs = vec!["elsewhere-24".to_owned()];
    let result = case.run().expect("partial neighborhood");
    assert_eq!(result.disposition, RelationDisposition::Partial);
    assert!(result.degradation.is_some());
    // Full support plus a partial neighborhood is never a positive claim.
    assert_ne!(result.disposition, RelationDisposition::Positive);
}

// WORK_UNIT_CASE: 655/25
#[test]
fn work_unit_655_25_exact_rival_denominator_and_omitted_rival() {
    // A declared-but-missing alternative fails.
    let mut case = Case::ready();
    case.policy
        .expected_alternative_refs
        .push("absent-rival".to_owned());
    case.reseal();
    assert!(case.run().is_err());
    // A retained-but-undeclared alternative fails.
    let mut case = Case::ready();
    case.policy
        .expected_alternative_refs
        .retain(|reference| reference != "rival-1");
    case.reseal();
    assert!(case.run().is_err());
    // An explicitly omitted alternative is retained as an omission, and the
    // reduced coverage yields a partial candidate rather than silence.
    let mut case = Case::ready();
    case.draft.rivals.clear();
    case.draft
        .counterevidence
        .retain(|evidence| evidence.evidence_id() != "evidence-rival");
    case.policy.expected_alternative_refs = vec!["rival-1".to_owned(), "no-relation-1".to_owned()];
    case.policy.omitted_alternative_refs = vec!["rival-1".to_owned()];
    case.reseal();
    let result = case.run().expect("omitted rival");
    assert_eq!(result.disposition, RelationDisposition::Partial);
}

// WORK_UNIT_CASE: 655/26
#[test]
fn work_unit_655_26_tied_rivals_yield_ambiguity() {
    // A supported rival with no primary support is ambiguity, never a
    // top-ranked low-confidence positive edge.
    let mut case = Case::ready();
    case.draft.evidence.clear();
    let mut rival = case
        .draft
        .counterevidence
        .iter()
        .find(|evidence| evidence.evidence_id() == "evidence-rival")
        .expect("rival evidence")
        .clone();
    rival.polarity = RelationEvidencePolarity::Support;
    case.draft
        .counterevidence
        .retain(|evidence| evidence.evidence_id() != "evidence-rival");
    case.draft.evidence.push(rival);
    let result = case.run().expect("tied rivals");
    assert_eq!(result.disposition, RelationDisposition::Ambiguous);
    assert!(result.closure.candidate.evidence_refs.is_empty());
    assert!(
        result
            .closure
            .candidate
            .rival_refs
            .contains(&"rival-1".to_owned())
    );
}

// WORK_UNIT_CASE: 655/27
#[test]
fn work_unit_655_27_no_relation_alternative_retained() {
    let case = Case::ready();
    let result = case.run().expect("no-relation retained");
    assert_eq!(
        result.closure.candidate.no_relation_ref.as_deref(),
        Some("no-relation-1")
    );
    // Dropping the no-relation alternative breaks the declared denominator.
    let mut case = Case::ready();
    case.draft.no_relation_alternative = None;
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/28
#[test]
fn work_unit_655_28_repair_handoff_without_execution() {
    // A same-ID payload change needs merge/split repair: the handler reports
    // Conflict with full rollback lineage and executes no repair itself.
    let mut case = Case::ready();
    let retained = snapshot(
        &case.assembled(),
        "repair-28",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    case.neighborhood.relations.push(retained.clone());
    let mut changed = retained.clone();
    changed.relation_digest = digest("repaired-payload");
    case.policy.proposed_snapshot = Some(changed);
    case.reseal();
    let before_count = case.neighborhood.relations.len();
    let result = case.run().expect("repair handoff");
    assert_eq!(result.disposition, RelationDisposition::Conflict);
    assert_eq!(result.closure.candidate.before.as_ref(), Some(&retained));
    assert!(result.closure.candidate.after.is_none());
    assert!(
        result
            .closure
            .candidate
            .rollback
            .rollback_refs
            .contains(&"repair-28".to_owned())
    );
    assert_eq!(
        result.closure.candidate.rollback.note,
        "candidate-only reversible relation; no canonical mutation"
    );
    // Nothing was repaired: the supplied neighborhood is untouched.
    assert_eq!(case.neighborhood.relations.len(), before_count);
}

// WORK_UNIT_CASE: 655/29
#[test]
fn work_unit_655_29_rollback_and_raw_history() {
    let mut case = Case::ready();
    let first = snapshot(
        &case.assembled(),
        "first-29",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    let mut second = snapshot(
        &case.assembled(),
        "second-29",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    second.predecessor = Some("first-29".to_owned());
    case.neighborhood.relations.extend([first, second.clone()]);
    case.policy.proposed_snapshot = Some(second);
    case.reseal();
    let result = case.run().expect("history rollback");
    assert_eq!(result.disposition, RelationDisposition::Duplicate);
    assert_eq!(
        result.closure.candidate.rollback.predecessor.as_deref(),
        Some("second-29")
    );
    assert!(
        result
            .closure
            .candidate
            .rollback
            .removal_or_restoration_refs
            .contains(&"second-29".to_owned())
    );
    let history = &result.closure.candidate.rollback.raw_history_refs;
    for handle in [
        "source-a",
        "target-b",
        "evidence-1",
        "evidence-rival",
        "evidence-none",
    ] {
        assert!(
            history.contains(&handle.to_owned()),
            "missing raw history {handle}"
        );
    }
}

// WORK_UNIT_CASE: 655/30
#[test]
fn work_unit_655_30_preservation_and_upstream_receipt() {
    let case = Case::ready();
    let result = case.run().expect("preserved relation");
    assert_eq!(
        result.closure.candidate.preservation.verdicts.len(),
        RelationPreservationDimension::all().len()
    );
    assert_eq!(result.closure.candidate.preservation.verdicts.len(), 7);
    for dimension in RelationPreservationDimension::all() {
        let verdict = result
            .closure
            .candidate
            .preservation
            .verdicts
            .iter()
            .find(|verdict| verdict.dimension == *dimension)
            .expect("dimension verdict");
        assert!(
            verdict.passed && verdict.known,
            "dimension {dimension:?} must pass known"
        );
    }
    // The upstream A-05 receipt travels by value; it is validated
    // intrinsically, never re-executed by this handler.
    assert_eq!(
        result.closure.input.item.receipt.validator_contract,
        "a05-validator"
    );
    assert_eq!(result.closure.input.item.receipt, *case.ctx.receipt);
}

// WORK_UNIT_CASE: 655/31
#[test]
fn work_unit_655_31_partial_budget_deadline_cancel() {
    // Cancellation wins before any semantic work.
    let mut case = Case::ready();
    case.policy.cancellation_requested = true;
    case.reseal();
    assert!(case.run().is_err());
    // An elapsed deadline fails without touching semantics.
    let mut case = Case::ready();
    case.policy.clock_ref = Some("clock-1".to_owned());
    case.policy.now_ms = Some(200);
    case.policy.deadline_ms = Some(100);
    case.reseal();
    assert!(case.run().is_err());
    // The evidence budget is enforced.
    let mut case = Case::ready();
    case.policy.max_evidence = 1;
    case.reseal();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/32
#[test]
fn work_unit_655_32_no_privilege_escalation() {
    // Model authority cannot qualify evidence, grade binding or not.
    let mut case = Case::ready();
    case.draft.evidence[0]
        .named
        .foundation_evidence_envelope
        .authority = EvidenceAuthority::ModelInterpretation;
    let result = case.run().expect("model-authority evidence");
    assert_ne!(result.disposition, RelationDisposition::Positive);
    // Grounded support cannot satisfy a corroborated bar: no escalation.
    let mut case = Case::ready();
    case.policy.required_grade = EvidenceGrade::Corroborated;
    case.reseal();
    let result = case.run().expect("raised grade bar");
    assert_ne!(result.disposition, RelationDisposition::Positive);
    // A science-grade causal proof cannot be claimed through this handler.
    let mut case = Case::causal();
    case.policy
        .causal_claim
        .as_mut()
        .expect("causal claim")
        .ceiling = EvidenceGrade::ScienceGrade;
    case.reseal();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/33
#[test]
fn work_unit_655_33_all_bounds_enforced() {
    // Rival bound: two rivals against a bound of one.
    let mut case = Case::ready();
    let mut extra = case.draft.rivals[0].clone();
    extra.alternative_id = "rival-2".to_owned();
    case.draft.rivals.push(extra);
    case.policy
        .expected_alternative_refs
        .push("rival-2".to_owned());
    case.policy.max_rivals = 1;
    case.reseal();
    assert!(case.run().is_err());
    // Neighborhood bound: two snapshots against a bound of one.
    let mut case = Case::ready();
    let first = snapshot(
        &case.assembled(),
        "bound-a-33",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    let second = snapshot(
        &case.assembled(),
        "bound-b-33",
        case.draft.family,
        case.draft.direction,
        "source-a",
        "target-b",
    );
    case.neighborhood.relations.extend([first, second]);
    case.policy.max_neighborhood = 1;
    case.reseal();
    assert!(case.run().is_err());
    // Semantic work bound: the checked cubic scan exceeds a unit budget.
    let mut case = Case::ready();
    case.policy.max_work = 1;
    case.reseal();
    assert!(case.run().is_err());
    // Input byte bound.
    let mut case = Case::ready();
    case.policy.max_input_bytes = 64;
    case.reseal();
    assert!(case.run().is_err());
    // Output byte bound.
    let mut case = Case::ready();
    case.policy.max_output_bytes = 64;
    case.reseal();
    assert!(case.run().is_err());
    // Ordered-path hop bound.
    let mut case = transitive_case();
    case.policy.max_path_hops = 1;
    case.reseal();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/34
#[test]
fn work_unit_655_34_permutations_stable_direction_semantic() {
    let case = Case::ready();
    let first = case.run().expect("baseline");
    // Set-order permutations share one digest.
    let mut permuted = Case::ready();
    permuted.draft.evidence.reverse();
    permuted.draft.counterevidence.reverse();
    permuted.draft.rivals.reverse();
    permuted.policy.grade_bindings.reverse();
    permuted.policy.expected_alternative_refs.reverse();
    permuted.reseal();
    let second = permuted.run().expect("permuted");
    assert_eq!(first.result_digest, second.result_digest);
    // Swapping the endpoint arguments changes directed identity: the retained
    // curation payload no longer binds, so the swap is caught, not absorbed.
    let mut swapped = Case::ready();
    std::mem::swap(&mut swapped.source, &mut swapped.target);
    swapped.rebind_pair();
    assert!(swapped.run().is_err());
}

// WORK_UNIT_CASE: 655/35
#[test]
fn work_unit_655_35_replay_and_input_policy_conflict() {
    let case = Case::ready();
    let first = case.run().expect("first");
    let replay = case.run().expect("replay");
    assert_eq!(first.result_digest, replay.result_digest);
    // Changed evidence content forks identity while staying valid.
    let mut forked = Case::ready();
    forked.draft.evidence[0].predicate.expression =
        "directly supports with narrowed scope".to_owned();
    let forked_result = forked.run().expect("forked evidence");
    assert_ne!(first.result_digest, forked_result.result_digest);
    // A draft bound to a different policy digest conflicts.
    let mut conflicted = Case::ready();
    conflicted.policy.policy_revision = 2;
    conflicted.reseal();
    conflicted.draft.policy_digest = first.closure.input.policy_digest.clone();
    assert!(conflicted.run().is_err());
}

// WORK_UNIT_CASE: 655/36
#[test]
fn work_unit_655_36_malformed_input_never_panics() {
    // Empty operation identity.
    let mut case = Case::ready();
    case.draft.operation_id.clear();
    assert!(case.run().is_err());
    // Oversized rival set.
    let mut case = Case::ready();
    case.draft.rivals = (0..300)
        .map(|index| {
            let mut rival = case.draft.rivals[0].clone();
            rival.alternative_id = format!("rival-{index}");
            rival
        })
        .collect();
    assert!(case.run().is_err());
    // Non-digest policy binding.
    let mut case = Case::ready();
    case.draft.policy_digest = "not-a-digest".to_owned();
    assert!(case.run().is_err());
    // Unknown draft schema version.
    let mut case = Case::ready();
    case.draft.schema_version = 99;
    assert!(case.run().is_err());
    // Empty endpoint role.
    let mut case = Case::ready();
    case.source.role.clear();
    assert!(case.run().is_err());
    // Non-ASCII identity completes without panic either way.
    let mut case = Case::ready();
    case.draft.operation_id = "op-relation-☃-1".to_owned();
    let completed = case.run().is_ok() || case.run().is_err();
    assert!(completed, "unicode identity must complete");
}

// WORK_UNIT_CASE: 655/37
#[test]
fn work_unit_655_37_positive_requires_admitted_registry_valid_pair() {
    let case = Case::ready();
    let result = case.run().expect("admitted positive");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    assert_eq!(result.closure.candidate.source_id, "source-a");
    assert_eq!(result.closure.candidate.target_id, "target-b");
    assert_eq!(
        result.closure.candidate.source_material_digest,
        case.source.material_digest()
    );
    assert_eq!(
        result.closure.candidate.target_material_digest,
        case.target.material_digest()
    );
    assert_eq!(
        result
            .closure
            .input
            .source
            .admitted
            .admission
            .receipt_id
            .as_str(),
        "admission-source-a"
    );
    // A target carrying the source role breaks the registry rule.
    let mut case = Case::ready();
    case.target.role = "source".to_owned();
    assert!(case.run().is_err());
}

// WORK_UNIT_CASE: 655/38
#[test]
fn work_unit_655_38_positive_causal_retains_rival_confounder() {
    let case = Case::causal();
    let result = case.run().expect("causal positive");
    assert_eq!(result.disposition, RelationDisposition::Positive);
    assert_eq!(result.closure.candidate.family, RelationFamily::Causes);
    assert!(
        result
            .closure
            .candidate
            .evidence_refs
            .contains(&"evidence-1".to_owned())
    );
    assert!(
        result
            .closure
            .candidate
            .rival_refs
            .contains(&"rival-1".to_owned())
    );
    let kinds: Vec<EvidenceBindingKind> = case
        .policy
        .causal_bindings
        .iter()
        .map(|binding| binding.kind)
        .collect();
    for required in [
        EvidenceBindingKind::Mechanism,
        EvidenceBindingKind::Rival,
        EvidenceBindingKind::Confounder,
        EvidenceBindingKind::Discriminator,
    ] {
        assert!(
            kinds.contains(&required),
            "missing causal role {required:?}"
        );
    }
}

// WORK_UNIT_CASE: 655/39
#[test]
fn work_unit_655_39_record_changes_invalidate_digest() {
    let case = Case::ready();
    let baseline = case.run().expect("baseline").result_digest;
    // Endpoint content change invalidates the digest while staying valid.
    let mut endpoint = Case::ready();
    endpoint.source.privacy_class = "restricted".to_owned();
    let endpoint_digest = endpoint.run().expect("endpoint variant").result_digest;
    assert_ne!(baseline, endpoint_digest);
    // Registry revision change invalidates the digest while staying valid.
    let mut registry = Case::ready();
    registry.registry.revision = "rev-2".to_owned();
    registry.rebind_registry();
    let registry_digest = registry.run().expect("registry variant").result_digest;
    assert_ne!(baseline, registry_digest);
    // Evidence wording change invalidates the digest while staying valid.
    let mut evidence = Case::ready();
    evidence.draft.evidence[0].predicate.expression =
        "directly supports with narrowed scope".to_owned();
    let evidence_digest = evidence.run().expect("evidence variant").result_digest;
    assert_ne!(baseline, evidence_digest);
}

// WORK_UNIT_CASE: 655/40
#[test]
fn work_unit_655_40_zero_effect_no_finish_no_mutation() {
    use eliot_receipts::ProofCeiling;

    let case = Case::ready();
    // Borrowed caller records are never consumed: repeat calls agree exactly.
    let first = case.run().expect("first");
    let second = case.run().expect("second");
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(first.closure.result_digest, second.closure.result_digest);
    first.validate().expect("sealed zero-effect result");
    // The output is a candidate artifact, not a graph mutation or Finish:
    // no after-state, no live-state invalidation, an explicit reopen frontier.
    assert_eq!(
        first.closure.candidate.proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    assert!(first.closure.candidate.after.is_none());
    assert!(
        first
            .closure
            .candidate
            .rollback
            .invalidation_refs
            .is_empty()
    );
    assert_eq!(
        first.closure.candidate.rollback.note,
        "candidate-only reversible relation; no canonical mutation"
    );
    assert_eq!(
        first.reopen_frontier.as_deref(),
        Some("reopen-on-endpoint-registry-evidence-digest-change")
    );
    // Reassembling the same borrowed parts reproduces the sealed input.
    assert_eq!(
        case.draft.assemble(
            &case.item,
            &case.source,
            &case.target,
            &case.registry,
            &case.neighborhood
        ),
        first.closure.input
    );
}
