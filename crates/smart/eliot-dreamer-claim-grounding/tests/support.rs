#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_contracts::grounding::canonical::{
    AbsenceClaim, AbsenceClaimParams, ArtifactId, AuthorityEpoch, BoundedProof, CausalClaim,
    CausalClaimParams, CausalStatus, CoverageDenominator, CoverageDenominatorParams,
    CoverageReceipt, CoverageReceiptParams, DenominatorKind, EvidenceAuthority, EvidenceFreshness,
    EvidenceGrade, FrontierRevision, FrontierSpec, LineageRootId, MemberDisposition, MemberOutcome,
    OwnerLookup, PaginationBounds, PositionAssertability, Precision, PrivacyHandling,
    QueryRevision, QuerySpec, ResourceGeneration, SnapshotRef, SourceAssurance, SourceId,
    SourceLineage, SourceRevisionId, StateFence, TaskId, TemporalRecord, ValidityBounds,
};
use eliot_dreamer_contracts::grounding::{
    AllowedReferenceManifest, AttemptIdentity, ClaimKind, GroundingPolicy, MaterialClaim,
    ModelDraft, PrecisionPayload, RouteIdentity, ScreenTargetBinding, TypedEvidenceAssertion,
};
use eliot_dreamer_contracts::{
    AtomicityMode, BudgetLimits, BundleCompleteness, DreamInputBundle, DreamJobInput, JobClass,
    Requester, RequesterOrigin, ScreenBinding, ScreenState, TargetDenominator,
};

pub const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("artifact")
}

pub fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

pub fn task() -> TaskId {
    TaskId::new("grounding-test-task").expect("task")
}

pub fn eligible_screen() -> ScreenBinding {
    ScreenBinding {
        request_id: eliot_dreamer_contracts::grounding::canonical::RequestId::new(
            "grounding-screen-request",
        )
        .expect("request"),
        receipt_id: eliot_dreamer_contracts::grounding::canonical::ReceiptId::new(
            "grounding-screen-receipt",
        )
        .expect("receipt"),
        screened_targets: vec!["target-1".into()],
        source_snapshot: "snapshot-grounding".into(),
        source_revision: "revision-grounding".into(),
        profile: "grounding-profile".into(),
        task_id: task().to_string(),
        scope_id: "grounding-scope".into(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: DIGEST.into(),
        item_digest: DIGEST.into(),
    }
}

pub fn screen_target(screen: ScreenBinding) -> ScreenTargetBinding {
    let mode = AtomicityMode::AllOrNothing;
    let members = screen.screened_targets.clone();
    let expected_total = u32::try_from(members.len()).expect("target count");
    let target_digest = eliot_dreamer_contracts::grounding::canonical::sha256_hex(
        &eliot_dreamer_contracts::grounding::canonical::canonical_json_bytes(&(
            &mode,
            &members,
            expected_total,
        ))
        .expect("target preimage"),
    );
    ScreenTargetBinding {
        screen,
        target_denominator: TargetDenominator {
            mode,
            members,
            expected_total,
        },
        target_digest,
    }
}

pub fn payload() -> PrecisionPayload {
    PrecisionPayload::NumericQuantified {
        value: "42".into(),
        unit: "items".into(),
        denominator: Some("100".into()),
        interval: None,
        rounding: None,
        uncertainty: Some("exact".into()),
    }
}

pub const CAUSAL_CONTENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const CAUSAL_PROOF: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

pub fn causal_payload() -> PrecisionPayload {
    let source = SourceId::new("causal-source").expect("source");
    let revision = SourceRevisionId::new("revision-grounding").expect("revision");
    let assurance =
        SourceAssurance::new(source.clone(), revision.clone(), CAUSAL_PROOF).expect("assurance");
    let causal = CausalClaim::new(CausalClaimParams {
        subject: eliot_dreamer_contracts::grounding::PropositionId::new("proposition-causal")
            .expect("proposition"),
        status: CausalStatus::Mechanism,
        mechanism: "mechanism-1".into(),
        rivals: BTreeSet::from(["rival-1".into()]),
        confounders: BTreeSet::from(["confounder-1".into()]),
        evidence_refs: BTreeSet::from([artifact("evidence-1")]),
        outcome: "outcome-1".into(),
        control: "control-1".into(),
        source: source.clone(),
        source_lineage: SourceLineage::new(
            source,
            revision,
            CAUSAL_CONTENT,
            None,
            BTreeSet::new(),
            None,
        )
        .expect("lineage"),
        assurance,
        lineage: LineageRootId::new("causal-lineage").expect("lineage root"),
        fence: fence(),
        temporal: TemporalRecord::new(90, 100, 110, 120, 130).expect("temporal"),
        proof_digest: CAUSAL_PROOF.into(),
        ceiling: EvidenceGrade::Corroborated,
        scope: "grounding-scope".into(),
    })
    .expect("causal");
    PrecisionPayload::Causal {
        causal: Box::new(causal),
    }
}

pub fn complete_denominator() -> CoverageDenominator {
    CoverageDenominator::new(CoverageDenominatorParams {
        class: "source-record".into(),
        schema: "schema-1".into(),
        revision: "revision-grounding".into(),
        scope: "grounding-scope".into(),
        fence: fence(),
        members: BTreeSet::from([artifact("member-1")]),
        roles: BTreeSet::from(["primary".into()]),
        query: Some(QuerySpec::new("query", QueryRevision("query-1".into())).expect("query")),
        frontier: Some(
            FrontierSpec::new("frontier", FrontierRevision("frontier-1".into())).expect("frontier"),
        ),
        snapshot: SnapshotRef::new("snapshot-grounding", SourceId::new("owner").expect("owner"))
            .expect("snapshot"),
        exclusions: Vec::new(),
        bounds: PaginationBounds::new(0, 1, 1, false).expect("bounds"),
        validity: ValidityBounds::new(
            "grounding-scope",
            Some(100),
            Some(200),
            "revision-grounding",
            Precision("file".into()),
        )
        .expect("validity"),
        kind: DenominatorKind::CompleteScope,
    })
    .expect("denominator")
}

pub fn complete_absence_payload() -> (PrecisionPayload, CoverageDenominator, CoverageReceipt) {
    let denominator = complete_denominator();
    let query = denominator.query.clone().expect("query");
    let frontier = denominator.frontier.clone().expect("frontier");
    let receipt = CoverageReceipt::new(CoverageReceiptParams {
        query: query.clone(),
        frontier,
        denominator: denominator.digest.clone(),
        denominator_size: 1,
        task_id: task(),
        scope: "grounding-scope".into(),
        fence: fence(),
        policy: "grounding-policy".into(),
        groups: BTreeSet::new(),
        members: vec![
            MemberOutcome::new(
                artifact("member-1"),
                "primary",
                MemberDisposition::AuthoritativeAbsence,
            )
            .expect("member"),
        ],
        omissions: Vec::new(),
        proof_digest: CAUSAL_PROOF.into(),
    })
    .expect("receipt");
    let owner = SourceId::new("owner").expect("owner");
    let lookup = OwnerLookup::new(
        owner.clone(),
        OwnerLookup::expected_proof(&owner, &denominator.digest, CAUSAL_PROOF)
            .expect("lookup proof"),
    )
    .expect("lookup");
    let query_digest = eliot_dreamer_contracts::grounding::canonical::sha256_hex(
        &eliot_dreamer_contracts::grounding::canonical::canonical_json_bytes(&query)
            .expect("query bytes"),
    );
    let absence = AbsenceClaim::new(AbsenceClaimParams {
        proposition: eliot_dreamer_contracts::grounding::PropositionId::new("proposition-absence")
            .expect("proposition"),
        domain: denominator.class.clone(),
        schema: denominator.schema.clone(),
        scope: denominator.scope.clone(),
        window_start_ms: denominator.validity.window_start_ms,
        window_end_ms: denominator.validity.window_end_ms,
        version: denominator.validity.version.clone(),
        task_id: task(),
        policy: "grounding-policy".into(),
        owner_lookup: lookup,
        denominator_digest: denominator.digest.clone(),
        denominator_kind: DenominatorKind::CompleteScope,
        query_digest,
        snapshot_id: denominator.snapshot.snapshot_id.clone(),
        receipt: receipt.clone(),
        proof: BoundedProof::new(CAUSAL_CONTENT, 64).expect("proof"),
    })
    .expect("absence");
    (
        PrecisionPayload::AbsenceExhaustiveNegative {
            domain: denominator.class.clone(),
            denominator: Box::new(denominator.clone()),
            receipt: Some(Box::new(receipt.clone())),
            absence_proof: Some(Box::new(absence)),
        },
        denominator,
        receipt,
    )
}

pub fn job(manifest_digest: String, class: JobClass) -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: class,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "grounding-test".into(),
            session: None,
        },
        operation_id: "grounding-operation".into(),
        idempotency_key: "grounding-idempotency".into(),
        task_id: task().to_string(),
        scope_id: "grounding-scope".into(),
        state_fence: fence(),
        privacy_profile: "local_only".into(),
        contract_ref: "grounding-v2".into(),
        policy_ref: "grounding-policy".into(),
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
            report_bytes: Some(1_024),
            max_stu: Some(10),
        },
        deadline_ms: None,
        frozen_manifest_digest: manifest_digest,
    }
}

pub fn manifest_for(
    proposition: &str,
    assertion_support: Option<eliot_dreamer_contracts::grounding::canonical::SupportRecord>,
) -> AllowedReferenceManifest {
    manifest_for_typed(
        proposition,
        payload(),
        assertion_support,
        None,
        None,
        DIGEST,
    )
}

pub fn manifest_for_typed(
    proposition: &str,
    precision: PrecisionPayload,
    assertion_support: Option<eliot_dreamer_contracts::grounding::canonical::SupportRecord>,
    source_lineage: Option<SourceLineage>,
    source_assurance: Option<SourceAssurance>,
    content_digest: &str,
) -> AllowedReferenceManifest {
    let proposition_id =
        eliot_dreamer_contracts::grounding::PropositionId::new(proposition).expect("proposition");
    let kind = precision.kind();
    let source_lineage = source_lineage.or_else(|| {
        Some(
            SourceLineage::new(
                SourceId::new("fixture-source").expect("source"),
                SourceRevisionId::new("revision-grounding").expect("revision"),
                content_digest,
                None,
                BTreeSet::new(),
                None,
            )
            .expect("lineage"),
        )
    });
    let assertion = TypedEvidenceAssertion {
        assertion_id: "assertion-1".into(),
        proposition: proposition_id.clone(),
        proposition_digest: eliot_dreamer_contracts::grounding::proposition_content_digest(
            &kind, &precision,
        )
        .expect("digest"),
        component: "value".into(),
        precision,
        source_span_digest: DIGEST.into(),
        support: assertion_support.map(Box::new),
    };
    let mut manifest = AllowedReferenceManifest {
        schema_version: 2,
        manifest_id: "manifest-grounding".into(),
        run_id: "run-grounding".into(),
        task_id: task(),
        scope_id: "grounding-scope".into(),
        state_fence: fence(),
        source_snapshot: "snapshot-grounding".into(),
        source_revision: "revision-grounding".into(),
        references: BTreeMap::from([(
            artifact("evidence-1"),
            eliot_dreamer_contracts::grounding::AuthorizedReference {
                handle: artifact("evidence-1"),
                source_lineage,
                support: None,
                provenance: None,
                content_digest: content_digest.into(),
                source_revision: "revision-grounding".into(),
                authority_digest: DIGEST.into(),
                authority: EvidenceAuthority::SourceIdentity,
                freshness: EvidenceFreshness::ExactCommit,
                source_assurance,
                grade_ceiling: EvidenceGrade::Grounded,
                assertability_ceiling: PositionAssertability::ObservedFact,
                privacy: PrivacyHandling::Unrestricted,
                disclosure: eliot_dreamer_contracts::grounding::canonical::DisclosureClass::Open,
                origin: "fixture".into(),
                invalidated: false,
                revocation_reason: None,
                assertions: vec![assertion],
                stale: false,
            },
        )]),
        coverage_denominators: BTreeMap::new(),
        coverage_receipts: BTreeMap::new(),
        dependence_groups: BTreeSet::new(),
        digest: String::new(),
    };
    manifest.digest = manifest.computed_digest().expect("manifest digest");
    manifest
}

pub fn claim_with_payload(
    id: &str,
    proposition: &str,
    payload: PrecisionPayload,
    handle: Option<&str>,
) -> MaterialClaim {
    let proposition_id =
        eliot_dreamer_contracts::grounding::PropositionId::new(proposition).expect("proposition");
    let kind = payload.kind();
    let mut claim = MaterialClaim {
        claim_id: id.into(),
        proposition: proposition_id.clone(),
        proposition_digest: eliot_dreamer_contracts::grounding::proposition_content_digest(
            &kind, &payload,
        )
        .expect("digest"),
        kind,
        payload,
        subclaim_ids: BTreeSet::new(),
        proposed_support: handle.into_iter().map(artifact).collect(),
        proposed_counterevidence: BTreeSet::new(),
        component_digests: BTreeMap::from([(
            "value".into(),
            eliot_dreamer_contracts::grounding::component_content_digest(&proposition_id, "value")
                .expect("component"),
        )]),
        screen_target: None,
        source_preimage_digest: String::new(),
    };
    claim.source_preimage_digest = claim.computed_digest().expect("claim digest");
    claim
}

pub fn claim(id: &str, proposition: &str, handle: Option<&str>) -> MaterialClaim {
    let proposition_id =
        eliot_dreamer_contracts::grounding::PropositionId::new(proposition).expect("proposition");
    let precision = payload();
    let mut claim = MaterialClaim {
        claim_id: id.into(),
        proposition: proposition_id.clone(),
        proposition_digest: eliot_dreamer_contracts::grounding::proposition_content_digest(
            &ClaimKind::NumericQuantified,
            &precision,
        )
        .expect("digest"),
        kind: ClaimKind::NumericQuantified,
        payload: precision,
        subclaim_ids: BTreeSet::new(),
        proposed_support: handle.into_iter().map(artifact).collect(),
        proposed_counterevidence: BTreeSet::new(),
        component_digests: BTreeMap::from([(
            "value".into(),
            eliot_dreamer_contracts::grounding::component_content_digest(&proposition_id, "value")
                .expect("component"),
        )]),
        screen_target: None,
        source_preimage_digest: String::new(),
    };
    claim.source_preimage_digest = claim.computed_digest().expect("claim digest");
    claim
}

pub fn draft(
    manifest: &AllowedReferenceManifest,
    claims: Vec<MaterialClaim>,
    class: JobClass,
) -> ModelDraft {
    let provisional_job = job(manifest.digest.clone(), class);
    let bundle = DreamInputBundle {
        schema_version: 1,
        job_id: provisional_job.canonical_id(),
        scope_id: "grounding-scope".into(),
        task_id: task().to_string(),
        state_fence: fence(),
        manifest_digest: manifest.digest.clone(),
        materials: Vec::new(),
        omissions: Vec::new(),
        completeness: BundleCompleteness::Unknown,
        authoritative_denominator: None,
    };
    let mut draft = ModelDraft {
        schema_version: 2,
        job_id: provisional_job.canonical_id(),
        task_id: task(),
        scope_id: "grounding-scope".into(),
        state_fence: fence(),
        job: provisional_job.clone(),
        bundle: bundle.clone(),
        raw_output_digest: DIGEST.into(),
        requester_digest: eliot_dreamer_contracts::grounding::requester_digest(&provisional_job)
            .expect("requester"),
        attempt: AttemptIdentity {
            attempt_id: "attempt-1".into(),
            attempt_number: 1,
            maximum_attempts: 1,
        },
        route: {
            let route = RouteIdentity {
                provider: "fixture".into(),
                model: "fixture-model".into(),
                route_revision: "route-1".into(),
                fingerprint: String::new(),
            };
            RouteIdentity {
                fingerprint: eliot_dreamer_contracts::grounding::route_fingerprint(&route)
                    .expect("route"),
                ..route
            }
        },
        budget_digest: eliot_dreamer_contracts::grounding::budget_digest(&provisional_job)
            .expect("budget"),
        bundle_digest: eliot_dreamer_contracts::grounding::bundle_digest(&bundle).expect("bundle"),
        input_manifest_digest: manifest.digest.clone(),
        claims,
        non_material_claims: Vec::new(),
        screen: None,
        draft_digest: String::new(),
    };
    draft.draft_digest = draft.computed_digest().expect("draft digest");
    draft
}

pub fn policy() -> GroundingPolicy {
    let mut policy = GroundingPolicy {
        schema_version: 2,
        policy_id: "grounding-policy".into(),
        revision: "policy-revision".into(),
        permitted_kinds: BTreeSet::from([
            ClaimKind::NumericQuantified,
            ClaimKind::TemporalVersioned,
            ClaimKind::Causal,
            ClaimKind::AbsenceExhaustiveNegative,
            ClaimKind::ComparativeSuperlative,
            ClaimKind::QuoteAttribution,
            ClaimKind::RecommendationNormativeInference,
            ClaimKind::IdentityEntity,
        ]),
        permitted_nonmaterial_classes: BTreeSet::from(["unresolved".into()]),
        max_claims: 4_096,
        max_subclaims_per_claim: 16_384,
        max_support_handles_per_claim: 64,
        max_output_bytes: 1_048_576,
        digest: String::new(),
    };
    policy.digest = policy.computed_digest().expect("policy digest");
    policy
}
