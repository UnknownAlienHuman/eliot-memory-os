#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, AuthorityEpoch, ResourceGeneration, StateFence, TaskId};
use eliot_dreamer_contracts::grounding::{
    AllowedReferenceManifest, AssertionWitness, AttemptIdentity, ClaimGroundingLedger,
    ClaimGroundingRecord, ClaimKind, GroundingDisposition, GroundingPolicy, MaterialClaim,
    ModelDraft, NonMaterialClaim, PrecisionPayload, RouteIdentity,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BundleCompleteness, DreamInputBundle, DreamJobInput, JobClass, Requester,
    RequesterOrigin,
};

pub const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}
pub fn task() -> TaskId {
    TaskId::new("task-grounding").expect("task")
}
pub fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("artifact")
}

pub fn job() -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "grounding-test".into(),
            session: None,
        },
        operation_id: "operation-grounding".into(),
        idempotency_key: "idempotency-grounding".into(),
        task_id: "task-grounding".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        privacy_profile: "local_only".into(),
        contract_ref: "grounding-v2".into(),
        policy_ref: "policy-1".into(),
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
        frozen_manifest_digest: manifest().digest,
    }
}

pub fn bundle() -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: job().canonical_id(),
        scope_id: "scope-1".into(),
        task_id: "task-grounding".into(),
        state_fence: fence(),
        manifest_digest: manifest().digest,
        materials: Vec::new(),
        omissions: Vec::new(),
        completeness: BundleCompleteness::Unknown,
        authoritative_denominator: None,
    }
}

pub fn claim(id: &str) -> MaterialClaim {
    claim_with_handle(
        id,
        if id == "claim-2" {
            "evidence-2"
        } else {
            "evidence-1"
        },
    )
}

fn claim_with_handle(id: &str, handle: &str) -> MaterialClaim {
    let proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new(format!("proposition-{id}"))
            .expect("proposition");
    let payload = PrecisionPayload::NumericQuantified {
        value: "42".into(),
        unit: "items".into(),
        denominator: Some("100".into()),
        interval: None,
        rounding: None,
        uncertainty: Some("exact".into()),
    };
    let mut claim = MaterialClaim {
        claim_id: id.into(),
        proposition: proposition.clone(),
        proposition_digest: eliot_dreamer_contracts::grounding::proposition_content_digest(
            &ClaimKind::NumericQuantified,
            &payload,
        )
        .expect("proposition digest"),
        kind: ClaimKind::NumericQuantified,
        payload,
        subclaim_ids: BTreeSet::new(),
        proposed_support: BTreeSet::from([artifact(handle)]),
        proposed_counterevidence: BTreeSet::new(),
        component_digests: BTreeMap::from([(
            "value".into(),
            eliot_dreamer_contracts::grounding::component_content_digest(&proposition, "value")
                .expect("component digest"),
        )]),
        screen_target: None,
        source_preimage_digest: String::new(),
    };
    claim.source_preimage_digest = claim.computed_digest().expect("claim digest");
    claim
}

pub fn draft() -> ModelDraft {
    let mut claims = vec![claim("claim-1"), claim("claim-2")];
    claims[0].subclaim_ids.insert("claim-2".into());
    claims[0].source_preimage_digest = claims[0].computed_digest().expect("claim digest");
    let mut draft = ModelDraft {
        schema_version: 2,
        job_id: job().canonical_id(),
        task_id: task(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        raw_output_digest: DIGEST.into(),
        job: job(),
        bundle: bundle(),
        requester_digest: eliot_dreamer_contracts::grounding::requester_digest(&job())
            .expect("requester digest"),
        attempt: AttemptIdentity {
            attempt_id: "attempt-1".into(),
            attempt_number: 1,
            maximum_attempts: 2,
        },
        route: {
            let route = RouteIdentity {
                provider: "fixture".into(),
                model: "model-1".into(),
                route_revision: "r1".into(),
                fingerprint: String::new(),
            };
            RouteIdentity {
                fingerprint: eliot_dreamer_contracts::grounding::route_fingerprint(&route)
                    .expect("route digest"),
                ..route
            }
        },
        budget_digest: eliot_dreamer_contracts::grounding::budget_digest(&job())
            .expect("budget digest"),
        bundle_digest: eliot_dreamer_contracts::grounding::bundle_digest(&bundle())
            .expect("bundle digest"),
        input_manifest_digest: manifest().digest,
        claims,
        non_material_claims: Vec::<NonMaterialClaim>::new(),
        screen: None,
        draft_digest: String::new(),
    };
    draft.draft_digest = draft.computed_digest().expect("draft digest");
    draft
}

#[allow(clippy::too_many_lines)]
pub fn manifest() -> AllowedReferenceManifest {
    let mut manifest = AllowedReferenceManifest {
        schema_version: 2,
        manifest_id: "manifest-1".into(),
        run_id: "run-1".into(),
        task_id: task(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        source_snapshot: "snapshot-1".into(),
        source_revision: "revision-1".into(),
        references: BTreeMap::from([(
            artifact("evidence-1"),
            eliot_dreamer_contracts::grounding::AuthorizedReference {
                handle: artifact("evidence-1"),
                source_lineage: None,
                support: None,
                provenance: None,
                content_digest: DIGEST.into(),
                source_revision: "revision-1".into(),
                authority_digest: DIGEST.into(),
                authority: eliot_evidence::EvidenceAuthority::SourceIdentity,
                freshness: eliot_evidence::EvidenceFreshness::ExactCommit,
                source_assurance: None,
                grade_ceiling: eliot_epistemic_contracts::EvidenceGrade::Grounded,
                assertability_ceiling:
                    eliot_epistemic_contracts::PositionAssertability::QualifiedInference,
                privacy: eliot_epistemic_contracts::PrivacyHandling::Unrestricted,
                disclosure: eliot_epistemic_contracts::DisclosureClass::Open,
                origin: "grounding-fixture".into(),
                invalidated: false,
                revocation_reason: None,
                assertions: vec![eliot_dreamer_contracts::grounding::TypedEvidenceAssertion {
                    assertion_id: "assertion-1".into(),
                    proposition: eliot_dreamer_contracts::grounding::PropositionId::new(
                        "proposition-claim-1",
                    )
                    .expect("proposition"),
                    proposition_digest:
                        eliot_dreamer_contracts::grounding::proposition_content_digest(
                            &ClaimKind::NumericQuantified,
                            &PrecisionPayload::NumericQuantified {
                                value: "42".into(),
                                unit: "items".into(),
                                denominator: Some("100".into()),
                                interval: None,
                                rounding: None,
                                uncertainty: Some("exact".into()),
                            },
                        )
                        .expect("proposition digest"),
                    component: "value".into(),
                    precision: PrecisionPayload::NumericQuantified {
                        value: "42".into(),
                        unit: "items".into(),
                        denominator: Some("100".into()),
                        interval: None,
                        rounding: None,
                        uncertainty: Some("exact".into()),
                    },
                    source_span_digest: DIGEST.into(),
                    support: Some(Box::new(eliot_epistemic_contracts::SupportRecord {
                        proposition: eliot_dreamer_contracts::grounding::PropositionId::new(
                            "proposition-claim-1",
                        )
                        .expect("proposition"),
                        result: GroundingDisposition::Supported,
                        handles: BTreeSet::from([artifact("evidence-1")]),
                        validity: eliot_epistemic_contracts::ValidityBounds {
                            scope: "scope-1".into(),
                            window_start_ms: None,
                            window_end_ms: None,
                            version: "revision-1".into(),
                            precision: "file".into(),
                        },
                        grade: eliot_epistemic_contracts::GradeAssignment::known(
                            eliot_epistemic_contracts::EvidenceGrade::Grounded,
                        ),
                        task_id: task(),
                        fence: fence(),
                        temporal: None,
                        assurance: None,
                        reopen_reason: None,
                        proof_digest: DIGEST.into(),
                    })),
                }],
                stale: false,
            },
        )]),
        coverage_denominators: BTreeMap::new(),
        coverage_receipts: BTreeMap::new(),
        dependence_groups: BTreeSet::from(["independent-1".into()]),
        digest: String::new(),
    };
    let mut second = manifest.references[&artifact("evidence-1")].clone();
    second.handle = artifact("evidence-2");
    second.assertions[0].assertion_id = "assertion-2".into();
    second.assertions[0].proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-claim-2")
            .expect("proposition");
    if let Some(support) = &mut second.assertions[0].support {
        support.proposition =
            eliot_dreamer_contracts::grounding::PropositionId::new("proposition-claim-2")
                .expect("proposition");
        support.handles = BTreeSet::from([artifact("evidence-2")]);
    }
    manifest.references.insert(artifact("evidence-2"), second);
    let mut extra_assertion = manifest.references[&artifact("evidence-1")].assertions[0].clone();
    extra_assertion.assertion_id = "assertion-1b".into();
    manifest
        .references
        .get_mut(&artifact("evidence-1"))
        .expect("reference")
        .assertions
        .push(extra_assertion);
    manifest.digest = manifest.computed_digest().expect("manifest digest");
    manifest
}

pub fn policy() -> GroundingPolicy {
    let mut policy = GroundingPolicy {
        schema_version: 2,
        policy_id: "policy-1".into(),
        revision: "r1".into(),
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
        max_claims: 100,
        max_subclaims_per_claim: 100,
        max_support_handles_per_claim: 64,
        permitted_nonmaterial_classes: BTreeSet::from(["unresolved".into()]),
        max_output_bytes: 500_000,
        digest: String::new(),
    };
    policy.digest = policy.computed_digest().expect("policy digest");
    policy
}

pub fn ledger() -> ClaimGroundingLedger {
    let mut record = ClaimGroundingRecord {
        claim_id: "claim-1".into(),
        proposition: eliot_dreamer_contracts::grounding::PropositionId::new("proposition-claim-1")
            .expect("proposition"),
        proposition_digest: eliot_dreamer_contracts::grounding::proposition_content_digest(
            &ClaimKind::NumericQuantified,
            &PrecisionPayload::NumericQuantified {
                value: "42".into(),
                unit: "items".into(),
                denominator: Some("100".into()),
                interval: None,
                rounding: None,
                uncertainty: Some("exact".into()),
            },
        )
        .expect("proposition digest"),
        kind: ClaimKind::NumericQuantified,
        proposed_support: BTreeSet::from([artifact("evidence-1")]),
        accepted_support: BTreeSet::from([artifact("evidence-1")]),
        rejected_support: BTreeSet::new(),
        unresolved_support: BTreeSet::new(),
        proposed_counterevidence: BTreeSet::new(),
        accepted_counterevidence: BTreeSet::new(),
        rejected_counterevidence: BTreeSet::new(),
        unresolved_counterevidence: BTreeSet::new(),
        witnesses: vec![AssertionWitness {
            claim_id: "claim-1".into(),
            component: "value".into(),
            handle: artifact("evidence-1"),
            assertion_id: "assertion-1".into(),
        }],
        component_outcomes: BTreeMap::from([("value".into(), GroundingDisposition::Supported)]),
        disposition: GroundingDisposition::Supported,
        grade: None,
        grade_ceiling: eliot_epistemic_contracts::EvidenceGrade::Grounded,
        assertability_ceiling: eliot_epistemic_contracts::PositionAssertability::QualifiedInference,
        coverage_denominator_ids: BTreeSet::new(),
        dependence_groups: BTreeSet::from(["independent-1".into()]),
        unknowns: BTreeSet::new(),
        precision_findings: BTreeSet::new(),
        record_digest: String::new(),
    };
    record.record_digest = record.computed_digest().expect("record digest");
    let mut second_record = record.clone();
    second_record.claim_id = "claim-2".into();
    second_record.proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-claim-2")
            .expect("proposition");
    second_record.proposed_support = BTreeSet::from([artifact("evidence-2")]);
    second_record.accepted_support = BTreeSet::from([artifact("evidence-2")]);
    second_record.witnesses[0].claim_id = "claim-2".into();
    second_record.witnesses[0].handle = artifact("evidence-2");
    second_record.witnesses[0].assertion_id = "assertion-2".into();
    second_record.record_digest = second_record.computed_digest().expect("record digest");
    let mut ledger = ClaimGroundingLedger {
        schema_version: 2,
        operation_id: "operation-grounding".into(),
        run_id: "run-1".into(),
        job_id: job().canonical_id(),
        task_id: task(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        draft_digest: draft().draft_digest,
        manifest_digest: manifest().digest,
        policy_digest: policy().digest,
        expected_claim_ids: BTreeSet::from(["claim-1".into(), "claim-2".into()]),
        expected_subclaim_ids: BTreeMap::from([
            ("claim-1".into(), BTreeSet::from(["claim-2".into()])),
            ("claim-2".into(), BTreeSet::new()),
        ]),
        records: BTreeMap::from([
            ("claim-1".into(), record),
            ("claim-2".into(), second_record),
        ]),
        nonmaterial_claim_ids: BTreeSet::new(),
        unprocessed_claim_ids: BTreeSet::new(),
        unprocessed_reason: None,
        ledger_digest: String::new(),
    };
    ledger.ledger_digest = ledger.computed_digest().expect("ledger digest");
    ledger
}
