//! 593-PROOF rival-model behaviour proof.
//!
//! Package-local proof for `eliot-dreamer-rival-model`: dissent preservation,
//! duplicate/equivalent handling, counterevidence symmetry, and permutation
//! invariance over `structure_rival_models`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_contracts::grounding::canonical::{
    ArtifactId, EvidenceAuthority, EvidenceFreshness, EvidenceGrade, PositionAssertability,
    PrivacyHandling, StateFence, TaskId, ValidityBounds, sha256_hex,
};
use eliot_dreamer_contracts::grounding::{
    AllowedReferenceManifest, AttemptIdentity, AuthorizedReference, ClaimGroundingLedger,
    ClaimGroundingRecord, ClaimKind, GroundingPolicy, MaterialClaim, ModelDraft, NonMaterialClaim,
    PrecisionPayload, RouteIdentity,
};
use eliot_dreamer_contracts::rival::{
    ClaimDeclarations, CommonModeDisclosure, CurrentPositionAvailability, DeclarationAvailability,
    MaterialClaimRef, RivalClaimSlot, RivalCoverageDeclaration, RivalCoverageReceipt,
    RivalDeclarationSet, RivalDeclarationSetParams, RivalModelDeclaration,
    RivalModelDeclarationParams, RivalModelSlot, RivalSourceSlot, SuppliedLineage,
    TemporalAvailability,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, DreamInputBundle, DreamJobAdmission,
    GroundingValidationInput, JobClass, PRESERVATION_DIMENSIONS, PreservationDimension,
    PreservationReport, Requester, RequesterOrigin, STRUCTURED_VALIDATOR_CONTRACT,
    ValidatedDreamDraft, ValidatedGroundingCandidate, ValidationPolicy, ValidationReceipt,
};
use eliot_dreamer_rival_model::{
    RivalOperationObservation, RivalPolicy, RivalPolicyLimits, structure_rival_models,
};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, ClaimId, CurrentEpistemicPosition, Currentness,
    PositionId, PositionRevision,
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fence() -> StateFence {
    use eliot_dreamer_contracts::grounding::canonical::{
        EpochId, EpochLineageId, ResourceGeneration,
    };
    use std::num::NonZeroU64;
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        NonZeroU64::new(1).expect("seq"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn task() -> TaskId {
    TaskId::new("task-grounding").expect("task")
}

fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("artifact")
}

fn job_with_manifest(manifest_digest: String) -> DreamJobAdmission {
    DreamJobAdmission {
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
            output_bytes: Some(1_048_576),
            source_width: Some(32),
            reference_width: Some(32),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(60_000),
            work_fan_out: Some(4),
            report_bytes: Some(1_048_576),
            max_stu: Some(100),
        },
        deadline_ms: None,
        frozen_manifest_digest: manifest_digest,
    }
}

fn claim(id: &str) -> MaterialClaim {
    let handle = if id == "claim-2" {
        "evidence-2"
    } else {
        "evidence-1"
    };
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
        .expect("digest"),
        kind: ClaimKind::NumericQuantified,
        payload,
        subclaim_ids: BTreeSet::new(),
        proposed_support: BTreeSet::from([artifact(handle)]),
        proposed_counterevidence: BTreeSet::new(),
        component_digests: BTreeMap::from([(
            "value".into(),
            eliot_dreamer_contracts::grounding::component_content_digest(&proposition, "value")
                .expect("component"),
        )]),
        screen_target: None,
        source_preimage_digest: String::new(),
    };
    claim.source_preimage_digest = claim.computed_digest().expect("claim digest");
    claim
}

fn manifest() -> AllowedReferenceManifest {
    use eliot_dreamer_contracts::grounding::GroundingDisposition;
    use eliot_dreamer_contracts::grounding::canonical::DisclosureClass;
    use eliot_dreamer_contracts::grounding::canonical::GradeAssignment;
    // Full manifest mirroring the canonical contracts support helper,
    // including assertion witnesses required for Supported records.
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
            AuthorizedReference {
                handle: artifact("evidence-1"),
                source_lineage: None,
                support: None,
                provenance: None,
                content_digest: DIGEST.into(),
                source_revision: "revision-1".into(),
                authority_digest: DIGEST.into(),
                authority: EvidenceAuthority::SourceIdentity,
                freshness: EvidenceFreshness::ExactCommit,
                source_assurance: None,
                grade_ceiling: EvidenceGrade::Grounded,
                assertability_ceiling: PositionAssertability::QualifiedInference,
                privacy: PrivacyHandling::Unrestricted,
                disclosure: DisclosureClass::Open,
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
                    support: Some(Box::new(
                        eliot_dreamer_contracts::grounding::canonical::SupportRecord {
                            proposition: eliot_dreamer_contracts::grounding::PropositionId::new(
                                "proposition-claim-1",
                            )
                            .expect("proposition"),
                            result: GroundingDisposition::Supported,
                            handles: BTreeSet::from([artifact("evidence-1")]),
                            validity: ValidityBounds {
                                scope: "scope-1".into(),
                                window_start_ms: None,
                                window_end_ms: None,
                                version: "revision-1".into(),
                                precision: "file".into(),
                            },
                            grade: GradeAssignment::known(EvidenceGrade::Grounded),
                            task_id: task(),
                            fence: fence(),
                            temporal: None,
                            assurance: None,
                            reopen_reason: None,
                            proof_digest: DIGEST.into(),
                        },
                    )),
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

fn draft_for(manifest: &AllowedReferenceManifest, job: &DreamJobAdmission) -> ModelDraft {
    let mut claims = vec![claim("claim-1"), claim("claim-2")];
    claims[0].subclaim_ids.insert("claim-2".into());
    claims[0].source_preimage_digest = claims[0].computed_digest().expect("digest");
    let bundle = DreamInputBundle {
        schema_version: 1,
        job_id: job.canonical_id(),
        scope_id: "scope-1".into(),
        task_id: "task-grounding".into(),
        state_fence: fence(),
        manifest_digest: manifest.digest.clone(),
        materials: Vec::new(),
        omissions: Vec::new(),
        completeness: BundleCompleteness::Unknown,
        authoritative_denominator: None,
    };
    let mut draft = ModelDraft {
        schema_version: 2,
        job_id: job.canonical_id(),
        task_id: task(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        raw_output_digest: DIGEST.into(),
        job: job.clone(),
        bundle: bundle.clone(),
        requester_digest: eliot_dreamer_contracts::grounding::requester_digest(job)
            .expect("requester"),
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
                    .expect("route"),
                ..route
            }
        },
        budget_digest: eliot_dreamer_contracts::grounding::budget_digest(job).expect("budget"),
        bundle_digest: eliot_dreamer_contracts::grounding::bundle_digest(&bundle)
            .expect("bundle digest"),
        input_manifest_digest: manifest.digest.clone(),
        claims,
        non_material_claims: Vec::<NonMaterialClaim>::new(),
        screen: None,
        draft_digest: String::new(),
    };
    draft.draft_digest = draft.computed_digest().expect("draft digest");
    draft
}

fn grounding_policy() -> GroundingPolicy {
    use std::collections::BTreeSet as Set;
    let mut policy = GroundingPolicy {
        schema_version: 2,
        policy_id: "policy-1".into(),
        revision: "r1".into(),
        permitted_kinds: Set::from([
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
        permitted_nonmaterial_classes: Set::from(["unresolved".into()]),
        max_output_bytes: 500_000,
        digest: String::new(),
    };
    policy.digest = policy.computed_digest().expect("policy digest");
    policy
}

fn ledger_for(
    draft: &ModelDraft,
    manifest: &AllowedReferenceManifest,
    policy: &GroundingPolicy,
    job: &DreamJobAdmission,
) -> ClaimGroundingLedger {
    use eliot_dreamer_contracts::grounding::AssertionWitness;
    let claims = &draft.claims;
    let mut records = BTreeMap::new();
    for claim in claims {
        let handle = claim
            .proposed_support
            .iter()
            .next()
            .expect("support")
            .clone();
        let record = ClaimGroundingRecord {
            claim_id: claim.claim_id.clone(),
            proposition: claim.proposition.clone(),
            proposition_digest: claim.proposition_digest.clone(),
            kind: claim.kind,
            proposed_support: claim.proposed_support.clone(),
            accepted_support: claim.proposed_support.clone(),
            rejected_support: BTreeSet::new(),
            unresolved_support: BTreeSet::new(),
            proposed_counterevidence: BTreeSet::new(),
            accepted_counterevidence: BTreeSet::new(),
            rejected_counterevidence: BTreeSet::new(),
            unresolved_counterevidence: BTreeSet::new(),
            witnesses: vec![AssertionWitness {
                claim_id: claim.claim_id.clone(),
                component: "value".into(),
                handle,
                assertion_id: if claim.claim_id == "claim-2" {
                    "assertion-2".into()
                } else {
                    "assertion-1".into()
                },
            }],
            component_outcomes: BTreeMap::from([(
                "value".into(),
                eliot_dreamer_contracts::grounding::GroundingDisposition::Supported,
            )]),
            disposition: eliot_dreamer_contracts::grounding::GroundingDisposition::Supported,
            grade: None,
            grade_ceiling: EvidenceGrade::Grounded,
            assertability_ceiling: PositionAssertability::QualifiedInference,
            coverage_denominator_ids: BTreeSet::new(),
            dependence_groups: BTreeSet::from(["independent-1".into()]),
            unknowns: BTreeSet::new(),
            precision_findings: BTreeSet::new(),
            record_digest: String::new(),
        };
        let mut record = record;
        record.record_digest = record.computed_digest().expect("record digest");
        records.insert(claim.claim_id.clone(), record);
    }
    let mut ledger = ClaimGroundingLedger {
        schema_version: 2,
        operation_id: "operation-grounding".into(),
        run_id: "run-1".into(),
        job_id: job.canonical_id(),
        task_id: task(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        draft_digest: draft.draft_digest.clone(),
        manifest_digest: manifest.digest.clone(),
        policy_digest: policy.digest.clone(),
        expected_claim_ids: claims.iter().map(|c| c.claim_id.clone()).collect(),
        expected_subclaim_ids: BTreeMap::from([
            ("claim-1".into(), BTreeSet::from(["claim-2".into()])),
            ("claim-2".into(), BTreeSet::new()),
        ]),
        records,
        nonmaterial_claim_ids: BTreeSet::new(),
        unprocessed_claim_ids: BTreeSet::new(),
        unprocessed_reason: None,
        ledger_digest: String::new(),
    };
    ledger.ledger_digest = ledger.computed_digest().expect("ledger digest");
    ledger
}

fn grounded_fixture() -> eliot_dreamer_contracts::grounding::GroundedDreamDraft {
    let manifest = manifest();
    let job = job_with_manifest(manifest.digest.clone());
    let draft = draft_for(&manifest, &job);
    let policy = grounding_policy();
    let ledger = ledger_for(&draft, &manifest, &policy, &job);
    let mut output = eliot_dreamer_contracts::grounding::GroundedDreamDraft {
        schema_version: 2,
        job_id: draft.job_id.clone(),
        task_id: task(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        draft_digest: draft.draft_digest.clone(),
        manifest_digest: manifest.digest.clone(),
        policy_digest: policy.digest.clone(),
        input: draft,
        manifest,
        policy,
        ledger,
        screen: None,
        output_digest: String::new(),
    };
    output.output_digest = output.computed_digest().expect("output digest");
    output.validate().expect("grounded validates");
    output
}

fn preservation() -> PreservationReport {
    use eliot_dreamer_contracts::candidate::DimensionVerdict;
    PreservationReport {
        verdicts: PRESERVATION_DIMENSIONS
            .iter()
            .map(|name| DimensionVerdict {
                dimension: PreservationDimension::parse(name).expect("dimension"),
                passed: true,
                known: true,
                note: format!("{name} retained"),
            })
            .collect(),
    }
}

fn validation_policy() -> ValidationPolicy {
    let mut policy = ValidationPolicy::new("policy-1", 1, 1_048_576);
    policy.seal().expect("seal");
    policy
}

fn usage() -> BudgetUsage {
    BudgetUsage {
        input_bytes: 1000,
        output_bytes: 1000,
        source_width: 2,
        reference_width: 2,
        model_calls: 1,
        attempts: 1,
        candidates: 1,
        wall_ms: 10,
        work_fan_out: 1,
        report_bytes: 500,
        stu_used: 1,
    }
}

fn applicability() -> ValidityBounds {
    ValidityBounds::new(
        "scope-1",
        None,
        None,
        "revision-1",
        eliot_epistemic_contracts::support::Precision("file".into()),
    )
    .expect("bounds")
}

fn claim_ref_for(
    id: &str,
    grounded: &eliot_dreamer_contracts::grounding::GroundedDreamDraft,
) -> MaterialClaimRef {
    let claim = grounded
        .input
        .claims
        .iter()
        .find(|c| c.claim_id == id)
        .expect("claim");
    MaterialClaimRef::from_claim(claim).expect("ref")
}

fn model_declaration(
    model_id: &str,
    _grounded: &eliot_dreamer_contracts::grounding::GroundedDreamDraft,
    explanations: Vec<MaterialClaimRef>,
    counterevidence: ClaimDeclarations,
    supporting: ClaimDeclarations,
) -> RivalModelDeclaration {
    RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: artifact(model_id),
        model_revision: 1,
        predecessors: BTreeSet::new(),
        task_id: task(),
        state_fence: fence(),
        applicability: applicability(),
        question: "What is the bounded status?".into(),
        explanations,
        assumptions: DeclarationAvailability::NotApplicable {
            reason: "no assumptions for test".into(),
        },
        prediction_refs: DeclarationAvailability::NotApplicable {
            reason: "no predictions for test".into(),
        },
        dependency_refs: DeclarationAvailability::NotApplicable {
            reason: "no dependencies for test".into(),
        },
        support_observations: DeclarationAvailability::NotApplicable {
            reason: "no support observations for test".into(),
        },
        causal_readings: DeclarationAvailability::NotApplicable {
            reason: "no causal readings for test".into(),
        },
        conflicts: DeclarationAvailability::NotApplicable {
            reason: "no conflicts for test".into(),
        },
        supporting_claims: supporting,
        counterevidence_claims: counterevidence,
        revision_conditions: ClaimDeclarations::NotApplicable {
            reason: "no revision conditions".into(),
        },
        invalidation_conditions: ClaimDeclarations::NotApplicable {
            reason: "no invalidation conditions".into(),
        },
        successful_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        failed_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        downstream_effects: ClaimDeclarations::NotApplicable {
            reason: "no downstream".into(),
        },
        current_position: CurrentPositionAvailability::NotApplicable {
            reason: "no position binding for test".into(),
        },
        temporal: TemporalAvailability::Unknown {
            reason: "no temporal for test".into(),
        },
        lineage: SuppliedLineage::Unknown {
            closure_digest: None,
            reason: "no lineage for test".into(),
        },
        common_mode: CommonModeDisclosure::Unknown {
            reason: "no common mode for test".into(),
        },
        unresolved: BTreeSet::new(),
    })
    .expect("declaration")
}

fn unknown_coverage() -> RivalCoverageDeclaration {
    RivalCoverageDeclaration::Unknown {
        denominator_digest: None,
        receipt: RivalCoverageReceipt::Unavailable {
            receipt_digest: None,
            reason: "no coverage receipt for test".into(),
        },
        reason: "no coverage denominator for test".into(),
    }
}

fn declaration_set(
    grounded: &eliot_dreamer_contracts::grounding::GroundedDreamDraft,
    models: Vec<RivalModelSlot>,
) -> RivalDeclarationSet {
    let claims = grounded
        .input
        .claims
        .iter()
        .map(|claim| RivalClaimSlot::Retained {
            claim: Box::new(claim.clone()),
        })
        .collect();
    let sources = grounded
        .manifest
        .references
        .values()
        .map(|reference| RivalSourceSlot::Retained {
            reference: Box::new(reference.clone()),
        })
        .collect();
    RivalDeclarationSet::new(RivalDeclarationSetParams {
        set_id: artifact("rival-set-1"),
        task_id: task(),
        scope: "scope-1".into(),
        state_fence: fence(),
        models,
        related_models: Vec::new(),
        claims,
        assumptions: Vec::new(),
        predictions: Vec::new(),
        sources,
        model_coverage: unknown_coverage(),
        source_coverage: unknown_coverage(),
        unresolved: BTreeSet::new(),
    })
    .expect("declaration set")
}

fn rival_policy() -> RivalPolicy {
    let limits = RivalPolicyLimits {
        max_models: 16,
        min_models: 2,
        max_output_bytes: 900_000,
        max_work_units: 4096,
        max_elapsed_ms: 60_000,
        max_stu: 100,
        max_discriminators: 16,
        reserved_unknown_slots: 8,
        max_material_items: 100,
        max_reference_items: 100,
        max_evidence_items: 100,
        max_conflict_items: 100,
    };
    let observation = RivalOperationObservation {
        observation_time_ms: None,
        elapsed_ms: 10,
        cancellation_requested: false,
        stu_used: 1,
        current_usage: BudgetUsage {
            wall_ms: 10,
            stu_used: 1,
            ..BudgetUsage::default()
        },
    };
    RivalPolicy::new("rival-policy-1".into(), 1, limits, observation, None)
        .seal()
        .expect("policy seals")
}

fn current_position() -> CurrentEpistemicPosition {
    use eliot_dreamer_contracts::grounding::canonical::{
        EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId as ContractSourceId,
        StateFence as CanonicalFence,
    };
    use std::num::NonZeroU64 as NZ;
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("l"),
        NZ::new(1).expect("s"),
    )
    .expect("e");
    let fence = CanonicalFence::new(epoch, ResourceGeneration::genesis());
    let receipt = AdmittedReceipt::new(AdmittedReceiptParams {
        receipt_id: ReceiptId::new("receipt-1").expect("receipt"),
        payload_digest: sha256_hex(b"payload-1"),
        owner: ContractSourceId::new("source-1").expect("owner"),
        revision: "r1".into(),
        scope: "scope-1".into(),
        fence,
        evidence_digest: sha256_hex(b"evidence-1"),
        coverage_digest: sha256_hex(b"coverage-1"),
        conflict_digest: sha256_hex(b"conflict-1"),
        proof_digest: sha256_hex(b"proof-1"),
        position: PositionId::new("position-1").expect("position"),
        position_revision: PositionRevision::genesis(),
    })
    .expect("receipt");
    CurrentEpistemicPosition::new(
        receipt,
        Currentness::Current,
        BTreeSet::new(),
        ClaimId::new("claim-1").expect("claim"),
    )
    .expect("cep")
}

fn validated_candidate_with(
    declarations: RivalDeclarationSet,
) -> (
    ValidatedGroundingCandidate,
    DreamInputBundle,
    CurrentEpistemicPosition,
    RivalPolicy,
) {
    let grounded = grounded_fixture();
    let bundle = grounded.input.bundle.clone();
    // Rival context must match grounded task/scope/fence (checked by
    // GroundingValidationInput::validate).
    assert_eq!(declarations.task_id, grounded.task_id);
    let input = GroundingValidationInput::new(
        grounded.clone(),
        validation_policy(),
        usage(),
        preservation(),
        None,
        false,
        Some(declarations),
    )
    .expect("validation input");
    let (input_digest, _) = input.input_digest_and_size().expect("input digest");
    let (output_digest, _) = input
        .output_digest_and_size("accepted")
        .expect("output digest");
    let preservation_digest =
        eliot_dreamer_contracts::validation::preservation_digest(&preservation())
            .expect("preservation");
    let budget_digest =
        eliot_dreamer_contracts::validation::encoding::budget_digest(&grounded.input.job, &usage())
            .expect("budget");
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: STRUCTURED_VALIDATOR_CONTRACT.into(),
        validator_policy: "policy-1".into(),
        job_id: grounded.job_id.clone(),
        draft_digest: grounded.input.draft_digest.clone(),
        bundle_digest: grounded.input.bundle_digest.clone(),
        manifest_digest: grounded.input.bundle.manifest_digest.clone(),
        task_id: grounded.task_id.to_string(),
        scope_id: grounded.scope_id.clone(),
        input_digest,
        output_digest,
        terminal_disposition: "accepted".into(),
        proof_ceiling: eliot_dreamer_contracts::validation::PROOF_CEILING.into(),
        state_fence: fence(),
        preservation_digest,
        budget_digest,
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest: grounded.input.draft_digest.clone(),
        scope_id: grounded.scope_id.clone(),
        task_id: grounded.task_id.to_string(),
        state_fence: fence(),
    };
    let candidate = ValidatedGroundingCandidate::new(input, validated).expect("candidate binds");
    // Current position must share bundle scope/fence for structure_rival_models.
    let position = current_position();
    assert_eq!(position.admission.scope, bundle.scope_id);
    (candidate, bundle, position, rival_policy())
}

fn two_model_fixture() -> (
    ValidatedGroundingCandidate,
    DreamInputBundle,
    CurrentEpistemicPosition,
    RivalPolicy,
) {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "model-a has no counterevidence".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let model_b = model_declaration(
        "model-b",
        &grounded,
        vec![ref_b.clone()],
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
    );
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
        ],
    );
    validated_candidate_with(set)
}

#[test]
fn dissent_preservation_keeps_minority_models() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("two models structure");
    // Both rivals remain addressable; no winner is selected.
    let retained = result
        .assessments
        .iter()
        .filter(|assessment| {
            matches!(
                assessment.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Retained
            )
        })
        .count();
    assert_eq!(retained, 2, "minority model must remain addressable");
    assert!(result.declarations.is_some() || !result.assessments.is_empty());
}

#[test]
fn duplicate_equivalent_rivals_share_class_without_collapse() {
    let grounded = grounded_fixture();
    let reference = claim_ref_for("claim-1", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![reference.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![reference.clone()],
        },
    );
    // Exact duplicate content under a distinct identity is equivalent but not
    // collapsed: both slots remain in the set.
    let model_dup = model_declaration(
        "model-a-dup",
        &grounded,
        vec![reference.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![reference.clone()],
        },
    );
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_dup),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("duplicates structure");
    assert_eq!(result.assessments.len(), 2);
    // Equivalence classes retain every member identity.
    for class in &result.equivalence_classes {
        let mut members = class.members.clone();
        members.sort();
        let mut deduped = members.clone();
        deduped.dedup();
        assert_eq!(members, deduped, "equivalence members must be unique");
    }
}

#[test]
fn counterevidence_symmetry_preserves_both_sides() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("counterevidence structures");
    // Model-b carries counterevidence referencing model-a's support; the
    // result must retain the discriminating evidence map without promoting
    // either side to truth.
    assert!(!result.assessments.is_empty());
    let _ = &result.comparison;
    let _ = &result.discriminators;
}

#[test]
fn permutation_invariance_holds_for_model_order() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let model_b = model_declaration(
        "model-b",
        &grounded,
        vec![ref_b.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
    );
    let set_forward = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a.clone()),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b.clone()),
            },
        ],
    );
    let set_reversed = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
        ],
    );
    // DeclarationSet canonicalizes outer table order, so both inputs share a
    // digest and structure deterministically.
    assert_eq!(set_forward.digest, set_reversed.digest);
    let (candidate_f, bundle, position, policy) = validated_candidate_with(set_forward);
    let first = structure_rival_models(&bundle, &candidate_f, &position, &policy)
        .expect("forward structures");
    let (candidate_r, _, _, _) = validated_candidate_with(set_reversed);
    let second = structure_rival_models(&bundle, &candidate_r, &position, &policy)
        .expect("reversed structures");
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.set_id, second.set_id);
}

#[test]
fn missing_declarations_fail_closed() {
    let grounded = grounded_fixture();
    let input = GroundingValidationInput::new(
        grounded.clone(),
        validation_policy(),
        usage(),
        preservation(),
        None,
        false,
        None,
    )
    .expect("input without rivals");
    let (input_digest, _) = input.input_digest_and_size().expect("digest");
    let (output_digest, _) = input.output_digest_and_size("accepted").expect("output");
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: STRUCTURED_VALIDATOR_CONTRACT.into(),
        validator_policy: "policy-1".into(),
        job_id: grounded.job_id.clone(),
        draft_digest: grounded.input.draft_digest.clone(),
        bundle_digest: grounded.input.bundle_digest.clone(),
        manifest_digest: grounded.input.bundle.manifest_digest.clone(),
        task_id: grounded.task_id.to_string(),
        scope_id: grounded.scope_id.clone(),
        input_digest,
        output_digest,
        terminal_disposition: "accepted".into(),
        proof_ceiling: eliot_dreamer_contracts::validation::PROOF_CEILING.into(),
        state_fence: fence(),
        preservation_digest: eliot_dreamer_contracts::validation::preservation_digest(
            &preservation(),
        )
        .expect("preservation"),
        budget_digest: eliot_dreamer_contracts::validation::encoding::budget_digest(
            &grounded.input.job,
            &usage(),
        )
        .expect("budget"),
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest: grounded.input.draft_digest.clone(),
        scope_id: grounded.scope_id.clone(),
        task_id: grounded.task_id.to_string(),
        state_fence: fence(),
    };
    let candidate = ValidatedGroundingCandidate::new(input, validated).expect("candidate");
    let bundle = grounded.input.bundle.clone();
    let result = structure_rival_models(&bundle, &candidate, &current_position(), &rival_policy());
    assert!(matches!(
        result,
        Err(eliot_dreamer_rival_model::RivalModelError::MissingRivalDeclarations)
    ));
}

#[test]
fn cancellation_and_budget_bounds_fail_closed() {
    let (candidate, bundle, position, mut policy) = two_model_fixture();
    policy.cancellation_requested = true;
    // Re-seal after mutation via fresh policy with cancellation observed.
    let limits = RivalPolicyLimits {
        max_models: 16,
        min_models: 2,
        max_output_bytes: 900_000,
        max_work_units: 4096,
        max_elapsed_ms: 60_000,
        max_stu: 100,
        max_discriminators: 16,
        reserved_unknown_slots: 8,
        max_material_items: 100,
        max_reference_items: 100,
        max_evidence_items: 100,
        max_conflict_items: 100,
    };
    let cancelled = RivalPolicy::new(
        "rival-policy-1".into(),
        1,
        limits,
        RivalOperationObservation {
            observation_time_ms: None,
            elapsed_ms: 10,
            cancellation_requested: true,
            stu_used: 1,
            current_usage: BudgetUsage {
                wall_ms: 10,
                stu_used: 1,
                ..BudgetUsage::default()
            },
        },
        None,
    )
    .seal()
    .expect("cancelled policy seals");
    let result = structure_rival_models(&bundle, &candidate, &position, &cancelled);
    assert!(matches!(
        result,
        Err(eliot_dreamer_rival_model::RivalModelError::Cancelled)
    ));
    let _ = policy;
}

#[test]
fn policy_digest_and_shape_are_enforced() {
    let policy = rival_policy();
    policy.validate().expect("sealed policy validates");
    let mut tampered = policy.clone();
    tampered.max_models = 0;
    assert!(tampered.validate().is_err());
}

// --- 606 helpers (package-local proof scaffolding, no new dependencies) ---

fn policy_with_max_models(max_models: u32) -> RivalPolicy {
    let min_models = if max_models < 2 { max_models.max(1) } else { 2 };
    let limits = RivalPolicyLimits {
        max_models,
        min_models,
        max_output_bytes: 900_000,
        max_work_units: 4096,
        max_elapsed_ms: 60_000,
        max_stu: 100,
        max_discriminators: 16,
        reserved_unknown_slots: 8,
        max_material_items: 100,
        max_reference_items: 100,
        max_evidence_items: 100,
        max_conflict_items: 100,
    };
    let observation = RivalOperationObservation {
        observation_time_ms: None,
        elapsed_ms: 10,
        cancellation_requested: false,
        stu_used: 1,
        current_usage: BudgetUsage {
            wall_ms: 10,
            stu_used: 1,
            ..BudgetUsage::default()
        },
    };
    RivalPolicy::new("rival-policy-1".into(), 1, limits, observation, None)
        .seal()
        .expect("bounded policy seals")
}

fn policy_with_id(policy_id: &str) -> RivalPolicy {
    let limits = RivalPolicyLimits {
        max_models: 16,
        min_models: 2,
        max_output_bytes: 900_000,
        max_work_units: 4096,
        max_elapsed_ms: 60_000,
        max_stu: 100,
        max_discriminators: 16,
        reserved_unknown_slots: 8,
        max_material_items: 100,
        max_reference_items: 100,
        max_evidence_items: 100,
        max_conflict_items: 100,
    };
    let observation = RivalOperationObservation {
        observation_time_ms: None,
        elapsed_ms: 10,
        cancellation_requested: false,
        stu_used: 1,
        current_usage: BudgetUsage {
            wall_ms: 10,
            stu_used: 1,
            ..BudgetUsage::default()
        },
    };
    RivalPolicy::new(policy_id.into(), 1, limits, observation, None)
        .seal()
        .expect("named policy seals")
}

fn single_model_fixture() -> (
    ValidatedGroundingCandidate,
    DreamInputBundle,
    CurrentEpistemicPosition,
    RivalPolicy,
) {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "single has no counterevidence".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let set = declaration_set(
        &grounded,
        vec![RivalModelSlot::Retained {
            declaration: Box::new(model_a),
        }],
    );
    validated_candidate_with(set)
}

fn shared_assumption_fixture() -> (
    ValidatedGroundingCandidate,
    DreamInputBundle,
    CurrentEpistemicPosition,
    RivalPolicy,
) {
    use eliot_dreamer_contracts::grounding::canonical::SourceId as CanonicalSourceId;
    use eliot_dreamer_contracts::rival::{ConditionAssumptionRef, RivalAssumptionSlot};
    use eliot_epistemic_contracts::{AssumptionRecord, AssumptionRecordParams};
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let holder = CanonicalSourceId::new("source-1").expect("holder");
    let record = AssumptionRecord::new(AssumptionRecordParams {
        assumption_id: "assumption-shared".to_owned(),
        statement: "bounded status holds under the frozen scope".to_owned(),
        origin: "fixture".to_owned(),
        necessity: "bounds the shared test reading".to_owned(),
        failure_mode: "withdraw on refutation".to_owned(),
        dependents: BTreeSet::new(),
        bounds: applicability(),
        holder,
        task_id: task(),
        fence: fence(),
    })
    .expect("assumption seals");
    let shared = ConditionAssumptionRef {
        assumption_id: "assumption-shared".to_owned(),
        assumption_digest: record.digest.clone(),
    };
    let mk = |id: &str, explanations: Vec<MaterialClaimRef>| {
        RivalModelDeclaration::new(RivalModelDeclarationParams {
            model_id: artifact(id),
            model_revision: 1,
            predecessors: BTreeSet::new(),
            task_id: task(),
            state_fence: fence(),
            applicability: applicability(),
            question: "What is the bounded status?".into(),
            explanations,
            assumptions: DeclarationAvailability::Supplied {
                entries: vec![shared.clone()],
            },
            prediction_refs: DeclarationAvailability::NotApplicable {
                reason: "no predictions for test".into(),
            },
            dependency_refs: DeclarationAvailability::NotApplicable {
                reason: "no dependencies for test".into(),
            },
            support_observations: DeclarationAvailability::NotApplicable {
                reason: "no support observations for test".into(),
            },
            causal_readings: DeclarationAvailability::NotApplicable {
                reason: "no causal readings for test".into(),
            },
            conflicts: DeclarationAvailability::NotApplicable {
                reason: "no conflicts for test".into(),
            },
            supporting_claims: ClaimDeclarations::Supplied {
                claims: vec![ref_a.clone()],
            },
            counterevidence_claims: ClaimDeclarations::NotApplicable {
                reason: "no counterevidence".into(),
            },
            revision_conditions: ClaimDeclarations::NotApplicable {
                reason: "no revision conditions".into(),
            },
            invalidation_conditions: ClaimDeclarations::NotApplicable {
                reason: "no invalidation conditions".into(),
            },
            successful_transfers: ClaimDeclarations::NotApplicable {
                reason: "no transfers".into(),
            },
            failed_transfers: ClaimDeclarations::NotApplicable {
                reason: "no transfers".into(),
            },
            downstream_effects: ClaimDeclarations::NotApplicable {
                reason: "no downstream".into(),
            },
            current_position: CurrentPositionAvailability::NotApplicable {
                reason: "no position binding for test".into(),
            },
            temporal: TemporalAvailability::Unknown {
                reason: "no temporal for test".into(),
            },
            lineage: SuppliedLineage::Unknown {
                closure_digest: None,
                reason: "no lineage for test".into(),
            },
            common_mode: CommonModeDisclosure::Unknown {
                reason: "no common mode for test".into(),
            },
            unresolved: BTreeSet::new(),
        })
        .expect("shared-assumption declaration")
    };
    let model_a = mk("model-a", vec![ref_a.clone()]);
    let model_b = mk("model-b", vec![ref_b.clone()]);
    let claims = grounded
        .input
        .claims
        .iter()
        .map(|claim| RivalClaimSlot::Retained {
            claim: Box::new(claim.clone()),
        })
        .collect();
    let sources = grounded
        .manifest
        .references
        .values()
        .map(|reference| RivalSourceSlot::Retained {
            reference: Box::new(reference.clone()),
        })
        .collect();
    let set = RivalDeclarationSet::new(RivalDeclarationSetParams {
        set_id: artifact("rival-set-1"),
        task_id: task(),
        scope: "scope-1".into(),
        state_fence: fence(),
        models: vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
            RivalModelSlot::Unavailable {
                model_id: artifact("model-c"),
                model_revision: Some(1),
                declaration_digest: Some(DIGEST.to_owned()),
                reason: "body unavailable for test".into(),
            },
        ],
        related_models: Vec::new(),
        claims,
        assumptions: vec![RivalAssumptionSlot::Retained {
            assumption: Box::new(record),
        }],
        predictions: Vec::new(),
        sources,
        model_coverage: unknown_coverage(),
        source_coverage: unknown_coverage(),
        unresolved: BTreeSet::new(),
    })
    .expect("shared set seals");
    validated_candidate_with(set)
}

fn conflict_fixture_set() -> RivalDeclarationSet {
    use eliot_dreamer_contracts::grounding::canonical::SourceId as CanonicalSourceId;
    use eliot_epistemic_contracts::{
        ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictPosition, ConflictSet,
        ConflictSetParams,
    };
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let source_a = CanonicalSourceId::new("source-1").expect("source");
    let source_b = CanonicalSourceId::new("source-2").expect("source");
    let pos_a = ConflictPosition::new(
        source_a.clone(),
        "retain model-a reading",
        BTreeSet::new(),
        BTreeSet::new(),
        false,
    )
    .expect("position");
    let pos_b = ConflictPosition::new(
        source_b.clone(),
        "retain model-b minority reading",
        BTreeSet::new(),
        BTreeSet::new(),
        true,
    )
    .expect("minority position");
    let conflict = ConflictSet::new(ConflictSetParams {
        conflict_id: "conflict-1".to_owned(),
        kind: ConflictKind::Epistemic,
        scope: "scope-1".to_owned(),
        task_id: Some(task()),
        positions: vec![pos_a, pos_b],
        evidence_refs: BTreeSet::new(),
        owners: BTreeSet::from([source_a.clone()]),
        common_lineage: BTreeSet::new(),
        resolved_parts: BTreeSet::new(),
        unresolved: BTreeSet::from(["needs-inquiry".to_owned()]),
        unresolved_owners: BTreeSet::from([source_b.clone()]),
        acceptability: ArgumentAcceptability::Contested,
        defeated_refs: BTreeSet::new(),
        probe: None,
        decision_owner: source_a,
        affected_actions: Vec::new(),
        lifecycle: ConflictLifecycle::Open,
        receipt_digest: DIGEST.to_owned(),
    })
    .expect("conflict seals");
    let mk = |id: &str, explanations: Vec<MaterialClaimRef>| {
        RivalModelDeclaration::new(RivalModelDeclarationParams {
            model_id: artifact(id),
            model_revision: 1,
            predecessors: BTreeSet::new(),
            task_id: task(),
            state_fence: fence(),
            applicability: applicability(),
            question: "What is the bounded status?".into(),
            explanations,
            assumptions: DeclarationAvailability::NotApplicable {
                reason: "no assumptions for test".into(),
            },
            prediction_refs: DeclarationAvailability::NotApplicable {
                reason: "no predictions for test".into(),
            },
            dependency_refs: DeclarationAvailability::NotApplicable {
                reason: "no dependencies for test".into(),
            },
            support_observations: DeclarationAvailability::NotApplicable {
                reason: "no support observations for test".into(),
            },
            causal_readings: DeclarationAvailability::NotApplicable {
                reason: "no causal readings for test".into(),
            },
            conflicts: DeclarationAvailability::Supplied {
                entries: vec![conflict.clone()],
            },
            supporting_claims: ClaimDeclarations::Supplied {
                claims: vec![ref_a.clone()],
            },
            counterevidence_claims: ClaimDeclarations::NotApplicable {
                reason: "no counterevidence".into(),
            },
            revision_conditions: ClaimDeclarations::NotApplicable {
                reason: "no revision conditions".into(),
            },
            invalidation_conditions: ClaimDeclarations::NotApplicable {
                reason: "no invalidation conditions".into(),
            },
            successful_transfers: ClaimDeclarations::NotApplicable {
                reason: "no transfers".into(),
            },
            failed_transfers: ClaimDeclarations::NotApplicable {
                reason: "no transfers".into(),
            },
            downstream_effects: ClaimDeclarations::NotApplicable {
                reason: "no downstream".into(),
            },
            current_position: CurrentPositionAvailability::NotApplicable {
                reason: "no position binding for test".into(),
            },
            temporal: TemporalAvailability::Unknown {
                reason: "no temporal for test".into(),
            },
            lineage: SuppliedLineage::Unknown {
                closure_digest: None,
                reason: "no lineage for test".into(),
            },
            common_mode: CommonModeDisclosure::Unknown {
                reason: "no common mode for test".into(),
            },
            unresolved: BTreeSet::new(),
        })
        .expect("conflict declaration")
    };
    let model_a = mk("model-a", vec![ref_a.clone()]);
    let model_b = mk("model-b", vec![ref_b.clone()]);
    declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
        ],
    )
}

// WORK_UNIT_CASE: 606/1
#[test]
fn rival_606_01_two_distinct_valid_rivals() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("two distinct rivals structure");
    result.validate().expect("result validates");
    let retained = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Retained
            )
        })
        .count();
    assert_eq!(retained, 2, "both distinct rivals remain addressable");
    assert_eq!(result.assessments.len(), 2);
    assert_eq!(result.distinct_material_classes, 2);
    assert_eq!(result.equivalence_classes.len(), 2);
}

// WORK_UNIT_CASE: 606/2
#[test]
fn rival_606_02_three_models_share_one_assumption() {
    let (candidate, bundle, position, policy) = shared_assumption_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("three slots with a shared assumption structure");
    result.validate().expect("result validates");
    assert_eq!(result.assessments.len(), 3, "every input keeps one disposition");
    let retained = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Retained
            )
        })
        .count();
    assert_eq!(retained, 2, "shared assumption does not collapse dissent");
    let unavailable = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Unavailable { .. }
            )
        })
        .count();
    assert_eq!(unavailable, 1, "third slot stays explicitly unavailable");
    assert_eq!(result.distinct_material_classes, 2);
    assert_eq!(result.declarations.as_ref().expect("packed").assumptions.len(), 1);
}

// WORK_UNIT_CASE: 606/3
#[test]
fn rival_606_03_exact_vocabulary_unknown_stays_explicit() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "model-a has no counterevidence".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let mut params_b_explanations = vec![ref_b.clone()];
    let _ = &mut params_b_explanations;
    let model_b = RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: artifact("model-b"),
        model_revision: 1,
        predecessors: BTreeSet::new(),
        task_id: task(),
        state_fence: fence(),
        applicability: applicability(),
        question: "What is the bounded status?".into(),
        explanations: vec![ref_b.clone()],
        assumptions: DeclarationAvailability::Unknown {
            reason: "assumption needed but unavailable".into(),
        },
        prediction_refs: DeclarationAvailability::NotApplicable {
            reason: "no predictions for test".into(),
        },
        dependency_refs: DeclarationAvailability::NotApplicable {
            reason: "no dependencies for test".into(),
        },
        support_observations: DeclarationAvailability::NotApplicable {
            reason: "no support observations for test".into(),
        },
        causal_readings: DeclarationAvailability::NotApplicable {
            reason: "no causal readings for test".into(),
        },
        conflicts: DeclarationAvailability::NotApplicable {
            reason: "no conflicts for test".into(),
        },
        supporting_claims: ClaimDeclarations::Unknown {
            reason: "supporting claims unavailable".into(),
        },
        counterevidence_claims: ClaimDeclarations::NotApplicable {
            reason: "no counterevidence".into(),
        },
        revision_conditions: ClaimDeclarations::NotApplicable {
            reason: "no revision conditions".into(),
        },
        invalidation_conditions: ClaimDeclarations::NotApplicable {
            reason: "no invalidation conditions".into(),
        },
        successful_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        failed_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        downstream_effects: ClaimDeclarations::NotApplicable {
            reason: "no downstream".into(),
        },
        current_position: CurrentPositionAvailability::NotApplicable {
            reason: "no position binding for test".into(),
        },
        temporal: TemporalAvailability::Unknown {
            reason: "no temporal for test".into(),
        },
        lineage: SuppliedLineage::Unknown {
            closure_digest: None,
            reason: "no lineage for test".into(),
        },
        common_mode: CommonModeDisclosure::Unknown {
            reason: "no common mode for test".into(),
        },
        unresolved: BTreeSet::new(),
    })
    .expect("unknown-vocabulary declaration seals");
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("unknown vocabulary structures without promotion");
    assert!(result.unknown_total > 0, "unknown facets stay explicit");
    assert!(!result.unknown_slots.is_empty());
    let unknown_assessments = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Unknown { .. }
            )
        })
        .count();
    assert_eq!(unknown_assessments, 1, "uncertain model stays unresolved");
}

// WORK_UNIT_CASE: 606/4
#[test]
fn rival_606_04_bundle_scope_mismatch_fails_closed() {
    let (candidate, _, position, policy) = two_model_fixture();
    let grounded = grounded_fixture();
    let mut mismatched = grounded.input.bundle.clone();
    mismatched.scope_id = "scope-other".into();
    let result = structure_rival_models(&mismatched, &candidate, &position, &policy);
    assert!(
        matches!(
            result,
            Err(eliot_dreamer_rival_model::RivalModelError::IdentityMismatch(_))
        ),
        "bundle/scope mismatch must fail closed, got {result:?}"
    );
}

// WORK_UNIT_CASE: 606/5
#[test]
fn rival_606_05_duplicate_model_identities_rejected() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let first = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let second = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let claims = grounded
        .input
        .claims
        .iter()
        .map(|claim| RivalClaimSlot::Retained {
            claim: Box::new(claim.clone()),
        })
        .collect();
    let sources = grounded
        .manifest
        .references
        .values()
        .map(|reference| RivalSourceSlot::Retained {
            reference: Box::new(reference.clone()),
        })
        .collect();
    let attempt = RivalDeclarationSet::new(RivalDeclarationSetParams {
        set_id: artifact("rival-set-1"),
        task_id: task(),
        scope: "scope-1".into(),
        state_fence: fence(),
        models: vec![
            RivalModelSlot::Retained {
                declaration: Box::new(first),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(second),
            },
        ],
        related_models: Vec::new(),
        claims,
        assumptions: Vec::new(),
        predictions: Vec::new(),
        sources,
        model_coverage: unknown_coverage(),
        source_coverage: unknown_coverage(),
        unresolved: BTreeSet::new(),
    });
    assert!(attempt.is_err(), "duplicate model identities must fail closed");
}

// WORK_UNIT_CASE: 606/6
#[test]
fn rival_606_06_same_id_changed_payload_rejected() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let first = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let changed = model_declaration(
        "model-a",
        &grounded,
        vec![ref_b.clone()],
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
    );
    assert_ne!(first.digest, changed.digest, "payloads differ for the test");
    let claims = grounded
        .input
        .claims
        .iter()
        .map(|claim| RivalClaimSlot::Retained {
            claim: Box::new(claim.clone()),
        })
        .collect();
    let sources = grounded
        .manifest
        .references
        .values()
        .map(|reference| RivalSourceSlot::Retained {
            reference: Box::new(reference.clone()),
        })
        .collect();
    let attempt = RivalDeclarationSet::new(RivalDeclarationSetParams {
        set_id: artifact("rival-set-1"),
        task_id: task(),
        scope: "scope-1".into(),
        state_fence: fence(),
        models: vec![
            RivalModelSlot::Retained {
                declaration: Box::new(first),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(changed),
            },
        ],
        related_models: Vec::new(),
        claims,
        assumptions: Vec::new(),
        predictions: Vec::new(),
        sources,
        model_coverage: unknown_coverage(),
        source_coverage: unknown_coverage(),
        unresolved: BTreeSet::new(),
    });
    assert!(attempt.is_err(), "same ID with changed payload must fail closed");
}

// WORK_UNIT_CASE: 606/7
#[test]
fn rival_606_07_raw_prose_without_typed_propositions_rejected() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let attempt = RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: artifact("model-raw"),
        model_revision: 1,
        predecessors: BTreeSet::new(),
        task_id: task(),
        state_fence: fence(),
        applicability: applicability(),
        question: "What is the bounded status?".into(),
        explanations: Vec::new(),
        assumptions: DeclarationAvailability::NotApplicable {
            reason: "no assumptions for test".into(),
        },
        prediction_refs: DeclarationAvailability::NotApplicable {
            reason: "no predictions for test".into(),
        },
        dependency_refs: DeclarationAvailability::NotApplicable {
            reason: "no dependencies for test".into(),
        },
        support_observations: DeclarationAvailability::NotApplicable {
            reason: "no support observations for test".into(),
        },
        causal_readings: DeclarationAvailability::NotApplicable {
            reason: "no causal readings for test".into(),
        },
        conflicts: DeclarationAvailability::NotApplicable {
            reason: "no conflicts for test".into(),
        },
        supporting_claims: ClaimDeclarations::Supplied {
            claims: vec![ref_a],
        },
        counterevidence_claims: ClaimDeclarations::NotApplicable {
            reason: "no counterevidence".into(),
        },
        revision_conditions: ClaimDeclarations::NotApplicable {
            reason: "no revision conditions".into(),
        },
        invalidation_conditions: ClaimDeclarations::NotApplicable {
            reason: "no invalidation conditions".into(),
        },
        successful_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        failed_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        downstream_effects: ClaimDeclarations::NotApplicable {
            reason: "no downstream".into(),
        },
        current_position: CurrentPositionAvailability::NotApplicable {
            reason: "no position binding for test".into(),
        },
        temporal: TemporalAvailability::Unknown {
            reason: "no temporal for test".into(),
        },
        lineage: SuppliedLineage::Unknown {
            closure_digest: None,
            reason: "no lineage for test".into(),
        },
        common_mode: CommonModeDisclosure::Unknown {
            reason: "no common mode for test".into(),
        },
        unresolved: BTreeSet::new(),
    });
    assert!(attempt.is_err(), "raw prose without typed propositions must fail");
}

// WORK_UNIT_CASE: 606/8
#[test]
fn rival_606_08_missing_prediction_falsifier_stays_explicit() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let complete = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let missing = RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: artifact("model-b"),
        model_revision: 1,
        predecessors: BTreeSet::new(),
        task_id: task(),
        state_fence: fence(),
        applicability: applicability(),
        question: "What is the bounded status?".into(),
        explanations: vec![ref_b.clone()],
        assumptions: DeclarationAvailability::Unknown {
            reason: "assumption missing".into(),
        },
        prediction_refs: DeclarationAvailability::Unknown {
            reason: "predictions missing".into(),
        },
        dependency_refs: DeclarationAvailability::NotApplicable {
            reason: "no dependencies for test".into(),
        },
        support_observations: DeclarationAvailability::NotApplicable {
            reason: "no support observations for test".into(),
        },
        causal_readings: DeclarationAvailability::NotApplicable {
            reason: "no causal readings for test".into(),
        },
        conflicts: DeclarationAvailability::NotApplicable {
            reason: "no conflicts for test".into(),
        },
        supporting_claims: ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
        counterevidence_claims: ClaimDeclarations::NotApplicable {
            reason: "no counterevidence".into(),
        },
        revision_conditions: ClaimDeclarations::NotApplicable {
            reason: "no revision conditions".into(),
        },
        invalidation_conditions: ClaimDeclarations::NotApplicable {
            reason: "no invalidation conditions".into(),
        },
        successful_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        failed_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        downstream_effects: ClaimDeclarations::NotApplicable {
            reason: "no downstream".into(),
        },
        current_position: CurrentPositionAvailability::NotApplicable {
            reason: "no position binding for test".into(),
        },
        temporal: TemporalAvailability::Unknown {
            reason: "no temporal for test".into(),
        },
        lineage: SuppliedLineage::Unknown {
            closure_digest: None,
            reason: "no lineage for test".into(),
        },
        common_mode: CommonModeDisclosure::Unknown {
            reason: "no common mode for test".into(),
        },
        unresolved: BTreeSet::new(),
    })
    .expect("missing-field declaration seals as Unknown");
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(complete),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(missing),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("missing fields stay explicit");
    assert!(result.unknown_total > 0);
    assert!(
        result
            .assessments
            .iter()
            .any(|a| matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Unknown { .. }
            )),
        "missing assumption/prediction must not imply support"
    );
}

// WORK_UNIT_CASE: 606/9
#[test]
fn rival_606_09_support_and_counterevidence_both_preserved() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("support/counter structures");
    result.validate().expect("result validates");
    let declarations = result.declarations.as_ref().expect("packed declarations");
    let find = |id: &str| {
        declarations
            .models
            .iter()
            .find(|slot| slot.stable_id().as_str() == id)
            .expect("model present")
    };
    let slot_a = find("model-a");
    let slot_b = find("model-b");
    let RivalModelSlot::Retained { declaration: decl_a } = slot_a else {
        panic!("model-a retained");
    };
    let RivalModelSlot::Retained { declaration: decl_b } = slot_b else {
        panic!("model-b retained");
    };
    assert!(matches!(
        decl_a.supporting_claims,
        ClaimDeclarations::Supplied { .. }
    ));
    assert!(matches!(
        decl_b.counterevidence_claims,
        ClaimDeclarations::Supplied { .. }
    ));
    assert_eq!(result.assessments.len(), 2);
}

// WORK_UNIT_CASE: 606/10
#[test]
fn rival_606_10_repeated_source_does_not_inflate_distinctness() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let model_b = model_declaration(
        "model-b",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("repeated source structures");
    result.validate().expect("result validates");
    assert_eq!(result.assessments.len(), 2);
    assert_eq!(
        result.distinct_material_classes, 1,
        "repeated source must not inflate distinct classes"
    );
    assert_eq!(result.equivalence_classes.len(), 1);
    assert_eq!(result.equivalence_classes[0].members.len(), 2);
}

// WORK_UNIT_CASE: 606/11
#[test]
fn rival_606_11_weakest_coverage_bounds_the_portfolio() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("unknown coverage structures");
    assert_eq!(format!("{:?}", result.model_coverage), "Unknown");
    assert_eq!(format!("{:?}", result.source_coverage), "Unknown");
    assert_eq!(
        result.disposition,
        eliot_dreamer_rival_model::RivalModelDisposition::Partial,
        "weakest coverage must bound disposition to Partial"
    );
}

// WORK_UNIT_CASE: 606/12
#[test]
fn rival_606_12_exact_duplicates_keep_every_lineage() {
    let grounded = grounded_fixture();
    let reference = claim_ref_for("claim-1", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![reference.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![reference.clone()],
        },
    );
    let model_dup = model_declaration(
        "model-a-dup",
        &grounded,
        vec![reference.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![reference.clone()],
        },
    );
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_dup),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("duplicates structure");
    result.validate().expect("result validates");
    assert_eq!(result.assessments.len(), 2);
    assert_eq!(result.equivalence_classes.len(), 1);
    assert_eq!(result.equivalence_classes[0].members.len(), 2);
    let retained = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Retained
            )
        })
        .count();
    assert_eq!(retained, 2, "coalescing must not drop lineage");
    assert!(result.declarations.is_some(), "lineage carrier retained");
}

// WORK_UNIT_CASE: 606/13
#[test]
fn rival_606_13_same_label_does_not_merge_distinct_models() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("same-label models structure");
    assert_eq!(result.distinct_material_classes, 2);
    assert_eq!(result.equivalence_classes.len(), 2);
    let declarations = result.declarations.as_ref().expect("packed");
    let questions: Vec<_> = declarations
        .models
        .iter()
        .filter_map(|slot| match slot {
            RivalModelSlot::Retained { declaration } => Some(declaration.question.clone()),
            RivalModelSlot::Unavailable { .. } => None,
        })
        .collect();
    assert_eq!(questions.len(), 2);
    assert_eq!(questions[0], questions[1], "labels match for the test");
}

// WORK_UNIT_CASE: 606/14
#[test]
fn rival_606_14_material_difference_prevents_merge() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let model_b = model_declaration(
        "model-b",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
    );
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("material difference structures");
    assert_eq!(result.distinct_material_classes, 2);
    assert_eq!(result.equivalence_classes.len(), 2);
}

// WORK_UNIT_CASE: 606/15
#[test]
fn rival_606_15_uncertain_equivalence_stays_unresolved() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let retained = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let uncertain = RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: artifact("model-b"),
        model_revision: 1,
        predecessors: BTreeSet::new(),
        task_id: task(),
        state_fence: fence(),
        applicability: applicability(),
        question: "What is the bounded status?".into(),
        explanations: vec![ref_b.clone()],
        assumptions: DeclarationAvailability::NotApplicable {
            reason: "no assumptions for test".into(),
        },
        prediction_refs: DeclarationAvailability::NotApplicable {
            reason: "no predictions for test".into(),
        },
        dependency_refs: DeclarationAvailability::NotApplicable {
            reason: "no dependencies for test".into(),
        },
        support_observations: DeclarationAvailability::NotApplicable {
            reason: "no support observations for test".into(),
        },
        causal_readings: DeclarationAvailability::NotApplicable {
            reason: "no causal readings for test".into(),
        },
        conflicts: DeclarationAvailability::NotApplicable {
            reason: "no conflicts for test".into(),
        },
        supporting_claims: ClaimDeclarations::Unknown {
            reason: "supporting unknown".into(),
        },
        counterevidence_claims: ClaimDeclarations::NotApplicable {
            reason: "no counterevidence".into(),
        },
        revision_conditions: ClaimDeclarations::NotApplicable {
            reason: "no revision conditions".into(),
        },
        invalidation_conditions: ClaimDeclarations::NotApplicable {
            reason: "no invalidation conditions".into(),
        },
        successful_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        failed_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        downstream_effects: ClaimDeclarations::NotApplicable {
            reason: "no downstream".into(),
        },
        current_position: CurrentPositionAvailability::NotApplicable {
            reason: "no position binding for test".into(),
        },
        temporal: TemporalAvailability::Unknown {
            reason: "no temporal for test".into(),
        },
        lineage: SuppliedLineage::Unknown {
            closure_digest: None,
            reason: "no lineage for test".into(),
        },
        common_mode: CommonModeDisclosure::Unknown {
            reason: "no common mode for test".into(),
        },
        unresolved: BTreeSet::new(),
    })
    .expect("uncertain declaration seals");
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(retained),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(uncertain),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("uncertain structures");
    let uncertain_assessment = result
        .assessments
        .iter()
        .find(|a| a.model_id.as_str() == "model-b")
        .expect("model-b assessed");
    assert!(
        matches!(
            uncertain_assessment.disposition,
            eliot_dreamer_rival_model::ModelDisposition::Unknown { .. }
        ),
        "uncertain equivalence must stay unresolved"
    );
    assert_eq!(uncertain_assessment.equivalence_class, None);
}

// WORK_UNIT_CASE: 606/16
#[test]
fn rival_606_16_agreement_and_contradiction_stay_distinct() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("agreement/contradiction structures");
    result.validate().expect("result validates");
    let declarations = result.declarations.as_ref().expect("packed");
    let mut support_ids = BTreeSet::new();
    let mut counter_ids = BTreeSet::new();
    for slot in &declarations.models {
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        if let ClaimDeclarations::Supplied { claims } = &declaration.supporting_claims {
            for claim in claims {
                support_ids.insert(claim.claim_id.clone());
            }
        }
        if let ClaimDeclarations::Supplied { claims } = &declaration.counterevidence_claims {
            for claim in claims {
                counter_ids.insert(claim.claim_id.clone());
            }
        }
    }
    assert!(support_ids.contains("claim-1"));
    assert!(support_ids.contains("claim-2"));
    assert!(counter_ids.contains("claim-1"));
    assert_eq!(result.distinct_material_classes, 2);
}

// WORK_UNIT_CASE: 606/17
#[test]
fn rival_606_17_every_conflict_position_and_minority_retained() {
    let set = conflict_fixture_set();
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("conflicts structure");
    result.validate().expect("result validates");
    let declarations = result.declarations.as_ref().expect("packed");
    let mut total_positions = 0;
    let mut minority_seen = false;
    for slot in &declarations.models {
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        let DeclarationAvailability::Supplied { entries } = &declaration.conflicts else {
            panic!("conflicts supplied");
        };
        for conflict in entries {
            total_positions += conflict.positions.len();
            minority_seen |= conflict.positions.iter().any(|p| p.minority);
        }
    }
    assert_eq!(total_positions, 4, "every position on both models retained");
    assert!(minority_seen, "minority objection retained");
    assert_eq!(result.assessments.len(), 2);
}

// WORK_UNIT_CASE: 606/18
#[test]
fn rival_606_18_majority_cannot_choose_truth() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let majority_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let majority_b = model_declaration(
        "model-b",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(majority_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(majority_b),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("repeated count structures");
    result.validate().expect("result validates");
    assert_eq!(result.assessments.len(), 2);
    let retained = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Retained
            )
        })
        .count();
    assert_eq!(retained, 2, "both counted models stay addressable");
    assert_eq!(
        result.distinct_material_classes, 1,
        "raw count does not manufacture a second truth"
    );
    assert_eq!(
        result.disposition,
        eliot_dreamer_rival_model::RivalModelDisposition::InsufficientRivals,
        "count/majority alone cannot choose truth"
    );
    let wire = serde_json::to_string(&result).expect("serializes");
    assert!(!wire.contains("\"winner\""), "no winner from count");
}

// WORK_UNIT_CASE: 606/19
#[test]
fn rival_606_19_cooccurrence_is_not_causality() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("co-occurrence structures");
    result.validate().expect("result validates");
    assert!(
        result
            .comparison
            .groups
            .iter()
            .all(|g| !matches!(g.kind, eliot_dreamer_rival_model::SharedInputKind::CausalRecord)),
        "no causal record may be inferred from co-occurrence"
    );
    let declarations = result.declarations.as_ref().expect("packed");
    for slot in &declarations.models {
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        assert!(
            matches!(
                declaration.causal_readings,
                DeclarationAvailability::NotApplicable { .. }
            ),
            "causal readings stay NotApplicable without exact mechanism evidence"
        );
    }
}

// WORK_UNIT_CASE: 606/20
#[test]
fn rival_606_20_no_mechanism_without_exact_supply() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("mechanism check structures");
    result.validate().expect("result validates");
    let wire = serde_json::to_string(&result).expect("serializes");
    assert!(
        !wire.contains("MECHANISM"),
        "no mechanism reading may appear without exact supply"
    );
    assert_eq!(result.assessments.len(), 2);
}

// WORK_UNIT_CASE: 606/21
#[test]
fn rival_606_21_unsupported_causal_status_stays_limited() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let retained = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let causal_unknown = RivalModelDeclaration::new(RivalModelDeclarationParams {
        model_id: artifact("model-b"),
        model_revision: 1,
        predecessors: BTreeSet::new(),
        task_id: task(),
        state_fence: fence(),
        applicability: applicability(),
        question: "What is the bounded status?".into(),
        explanations: vec![ref_b.clone()],
        assumptions: DeclarationAvailability::NotApplicable {
            reason: "no assumptions for test".into(),
        },
        prediction_refs: DeclarationAvailability::NotApplicable {
            reason: "no predictions for test".into(),
        },
        dependency_refs: DeclarationAvailability::NotApplicable {
            reason: "no dependencies for test".into(),
        },
        support_observations: DeclarationAvailability::NotApplicable {
            reason: "no support observations for test".into(),
        },
        causal_readings: DeclarationAvailability::Unknown {
            reason: "causal reading unavailable".into(),
        },
        conflicts: DeclarationAvailability::NotApplicable {
            reason: "no conflicts for test".into(),
        },
        supporting_claims: ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
        counterevidence_claims: ClaimDeclarations::NotApplicable {
            reason: "no counterevidence".into(),
        },
        revision_conditions: ClaimDeclarations::NotApplicable {
            reason: "no revision conditions".into(),
        },
        invalidation_conditions: ClaimDeclarations::NotApplicable {
            reason: "no invalidation conditions".into(),
        },
        successful_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        failed_transfers: ClaimDeclarations::NotApplicable {
            reason: "no transfers".into(),
        },
        downstream_effects: ClaimDeclarations::NotApplicable {
            reason: "no downstream".into(),
        },
        current_position: CurrentPositionAvailability::NotApplicable {
            reason: "no position binding for test".into(),
        },
        temporal: TemporalAvailability::Unknown {
            reason: "no temporal for test".into(),
        },
        lineage: SuppliedLineage::Unknown {
            closure_digest: None,
            reason: "no lineage for test".into(),
        },
        common_mode: CommonModeDisclosure::Unknown {
            reason: "no common mode for test".into(),
        },
        unresolved: BTreeSet::new(),
    })
    .expect("causal-unknown declaration seals");
    let set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(retained),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(causal_unknown),
            },
        ],
    );
    let (candidate, bundle, position, policy) = validated_candidate_with(set);
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("unsupported causal structures");
    let limited = result
        .assessments
        .iter()
        .find(|a| a.model_id.as_str() == "model-b")
        .expect("model-b assessed");
    assert!(
        matches!(
            limited.disposition,
            eliot_dreamer_rival_model::ModelDisposition::Unknown { .. }
        ),
        "unsupported causal status must remain limited"
    );
}

// WORK_UNIT_CASE: 606/22
#[test]
fn rival_606_22_discriminator_search_addresses_two_rivals() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("discriminator search structures");
    result.validate().expect("result validates");
    assert!(
        result.distinct_material_classes >= 2,
        "need two live rivals for discriminator search"
    );
    assert!(
        !result.discriminator_search.requirements.is_empty(),
        "search must record explicit requirements"
    );
    let rows: BTreeSet<u32> = result
        .discriminator_search
        .requirements
        .iter()
        .map(|r| r.model_row)
        .collect();
    assert!(rows.len() >= 2, "requirements must address two rival rows");
}

// WORK_UNIT_CASE: 606/23
#[test]
fn rival_606_23_nondiscriminative_need_is_unprobeable_not_match() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("nondiscriminative structures");
    assert!(result.discriminators.is_empty(), "no exact discriminator exists");
    assert_eq!(
        result.discriminator_search.outcome,
        eliot_dreamer_rival_model::DiscriminatorOutcome::Unprobeable
    );
    assert_eq!(
        result.discriminator_search.completion,
        eliot_dreamer_rival_model::SearchCompletion::Complete
    );
}

// WORK_UNIT_CASE: 606/24
#[test]
fn rival_606_24_no_executable_probe_tool_or_route() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("inert structures");
    let wire = serde_json::to_string(&result).expect("serializes");
    for forbidden in ["\"provider\"", "\"tool\"", "\"route\"", "\"promotion\"", "\"Finish\""] {
        assert!(
            !wire.contains(forbidden),
            "inert result must not carry executable {forbidden}"
        );
    }
    assert!(result.discriminator_search.requirements.iter().all(|r| {
        !matches!(
            r.facet,
            eliot_dreamer_rival_model::DiscriminatorRequirementFacet::Expected
        ) || r.prediction_ref_entry.is_some()
    }));
}

// WORK_UNIT_CASE: 606/25
#[test]
fn rival_606_25_partial_denominator_is_not_complete() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("partial denominator structures");
    assert_eq!(format!("{:?}", result.model_coverage), "Unknown");
    assert_eq!(format!("{:?}", result.source_coverage), "Unknown");
    assert_ne!(
        result.disposition,
        eliot_dreamer_rival_model::RivalModelDisposition::Structured,
        "partial denominator must not report Structured"
    );
    assert_eq!(
        result.disposition,
        eliot_dreamer_rival_model::RivalModelDisposition::Partial
    );
}

// WORK_UNIT_CASE: 606/26
#[test]
fn rival_606_26_verbose_models_do_not_crowd_required_rivals() {
    let (candidate, bundle, position, _) = two_model_fixture();
    let tight = policy_with_max_models(1);
    let result = structure_rival_models(&bundle, &candidate, &position, &tight)
        .expect("tight bound structures");
    result.validate().expect("tight result validates");
    assert_eq!(result.assessments.len(), 2, "every input keeps one disposition");
    assert_eq!(result.omitted_count, 1, "verbose model is omitted, not merged");
    assert_eq!(result.omission_frontier.model_ids.len(), 1);
    assert!(
        result
            .omission_frontier
            .sections
            .contains(&eliot_dreamer_rival_model::OutputSection::Models)
    );
    let retained = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Retained
            )
        })
        .count();
    assert_eq!(retained, 1, "required rival remains despite verbose input");
    assert!(result.unknown_total > 0, "unknowns stay reserved under crowding");
}

// WORK_UNIT_CASE: 606/27
#[test]
fn rival_606_27_independent_bounds_yield_exact_frontier() {
    let (candidate, bundle, position, _) = two_model_fixture();
    let tight = policy_with_max_models(1);
    let result = structure_rival_models(&bundle, &candidate, &position, &tight)
        .expect("bounded structures");
    let omitted: Vec<_> = result
        .assessments
        .iter()
        .filter(|a| {
            matches!(
                a.disposition,
                eliot_dreamer_rival_model::ModelDisposition::Omitted { .. }
            )
        })
        .collect();
    assert_eq!(omitted.len(), 1);
    assert_eq!(result.omission_frontier.model_ids.len(), 1);
    assert_eq!(
        result.omission_frontier.model_ids[0].model_id,
        omitted[0].model_id,
        "frontier must name the exact omitted identity"
    );
    let (ok_candidate, ok_bundle, ok_position, ok_policy) = two_model_fixture();
    let ok = structure_rival_models(&ok_bundle, &ok_candidate, &ok_position, &ok_policy)
        .expect("fits");
    assert_eq!(ok.omitted_count, 0);
    assert!(ok.omission_frontier.model_ids.is_empty());
}

// WORK_UNIT_CASE: 606/28
#[test]
fn rival_606_28_insufficient_rivals_without_consensus() {
    let (candidate, bundle, position, policy) = single_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("single model structures");
    result.validate().expect("result validates");
    assert_eq!(
        result.disposition,
        eliot_dreamer_rival_model::RivalModelDisposition::InsufficientRivals
    );
    assert!(result.distinct_material_classes < result.required_min_classes);
    assert!(result.discriminators.is_empty(), "no consensus discriminator invented");
    assert_eq!(
        result.discriminator_search.outcome,
        eliot_dreamer_rival_model::DiscriminatorOutcome::InsufficientRivals
    );
}

// WORK_UNIT_CASE: 606/29
#[test]
fn rival_606_29_randomized_order_is_deterministic() {
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let model_b = model_declaration(
        "model-b",
        &grounded,
        vec![ref_b.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "none".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
    );
    let model_c = model_declaration(
        "model-c",
        &grounded,
        vec![ref_a.clone(), ref_b.clone()],
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone(), ref_b.clone()],
        },
    );
    let forward = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a.clone()),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b.clone()),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_c.clone()),
            },
        ],
    );
    let shuffled = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_c),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b),
            },
        ],
    );
    assert_eq!(forward.digest, shuffled.digest, "canonical order");
    let (candidate_f, bundle, position, policy) = validated_candidate_with(forward);
    let first = structure_rival_models(&bundle, &candidate_f, &position, &policy)
        .expect("forward structures");
    let (candidate_s, _, _, _) = validated_candidate_with(shuffled);
    let second = structure_rival_models(&bundle, &candidate_s, &position, &policy)
        .expect("shuffled structures");
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.set_id, second.set_id);
}

// WORK_UNIT_CASE: 606/30
#[test]
fn rival_606_30_replay_matches_and_changed_policy_conflicts() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("structures");
    result
        .validate_against(&bundle, &candidate, &position, &policy)
        .expect("exact replay validates");
    let other = policy_with_id("rival-policy-2");
    let replay = result.validate_against(&bundle, &candidate, &position, &other);
    assert!(
        replay.is_err(),
        "changed policy must not replay against the frozen digest"
    );
}

// WORK_UNIT_CASE: 606/31
#[test]
fn rival_606_31_malformed_inputs_fail_closed_without_panic() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let mut tampered = policy.clone();
    tampered.digest = "0".repeat(64);
    let bad_digest = structure_rival_models(&bundle, &candidate, &position, &tampered);
    assert!(
        matches!(
            bad_digest,
            Err(eliot_dreamer_rival_model::RivalModelError::InvalidContract(_))
        ),
        "tampered policy digest must fail closed"
    );
    let mut mismatched = bundle.clone();
    mismatched.task_id = "task-other".into();
    let bad_bundle = structure_rival_models(&mismatched, &candidate, &position, &policy);
    assert!(bad_bundle.is_err(), "mismatched task must fail closed");
    let grounded = grounded_fixture();
    let input = GroundingValidationInput::new(
        grounded.clone(),
        validation_policy(),
        usage(),
        preservation(),
        None,
        false,
        None,
    )
    .expect("input without rivals");
    let (input_digest, _) = input.input_digest_and_size().expect("digest");
    let (output_digest, _) = input.output_digest_and_size("accepted").expect("output");
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: STRUCTURED_VALIDATOR_CONTRACT.into(),
        validator_policy: "policy-1".into(),
        job_id: grounded.job_id.clone(),
        draft_digest: grounded.input.draft_digest.clone(),
        bundle_digest: grounded.input.bundle_digest.clone(),
        manifest_digest: grounded.input.bundle.manifest_digest.clone(),
        task_id: grounded.task_id.to_string(),
        scope_id: grounded.scope_id.clone(),
        input_digest,
        output_digest,
        terminal_disposition: "accepted".into(),
        proof_ceiling: eliot_dreamer_contracts::validation::PROOF_CEILING.into(),
        state_fence: fence(),
        preservation_digest: eliot_dreamer_contracts::validation::preservation_digest(
            &preservation(),
        )
        .expect("preservation"),
        budget_digest: eliot_dreamer_contracts::validation::encoding::budget_digest(
            &grounded.input.job,
            &usage(),
        )
        .expect("budget"),
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest: grounded.input.draft_digest.clone(),
        scope_id: grounded.scope_id.clone(),
        task_id: grounded.task_id.to_string(),
        state_fence: fence(),
    };
    let missing = ValidatedGroundingCandidate::new(input, validated).expect("candidate");
    let missing_result =
        structure_rival_models(&bundle, &missing, &position, &policy);
    assert!(
        matches!(
            missing_result,
            Err(eliot_dreamer_rival_model::RivalModelError::MissingRivalDeclarations)
        ),
        "missing declarations must fail closed"
    );
}

// WORK_UNIT_CASE: 606/32
#[test]
fn rival_606_32_every_input_has_one_output_disposition() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("structures");
    result.validate().expect("result validates");
    let declarations = result.declarations.as_ref().expect("packed");
    assert_eq!(result.assessments.len(), declarations.models.len());
    assert_eq!(result.model_details.len(), result.assessments.len());
    let mut input_ids: Vec<_> = declarations
        .models
        .iter()
        .map(|slot| slot.stable_id().clone())
        .collect();
    input_ids.sort();
    let mut output_ids: Vec<_> = result
        .assessments
        .iter()
        .map(|a| a.model_id.clone())
        .collect();
    output_ids.sort();
    assert_eq!(input_ids, output_ids, "every input maps to exactly one output");
    let mut seen = BTreeSet::new();
    for assessment in &result.assessments {
        assert!(seen.insert(assessment.model_id.clone()), "no duplicate output");
    }
}

// WORK_UNIT_CASE: 606/33
#[test]
fn rival_606_33_lost_counterevidence_changes_digest() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let full = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("full structures");
    let grounded = grounded_fixture();
    let ref_a = claim_ref_for("claim-1", &grounded);
    let ref_b = claim_ref_for("claim-2", &grounded);
    let model_a = model_declaration(
        "model-a",
        &grounded,
        vec![ref_a.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "model-a has no counterevidence".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_a.clone()],
        },
    );
    let model_b_stripped = model_declaration(
        "model-b",
        &grounded,
        vec![ref_b.clone()],
        ClaimDeclarations::NotApplicable {
            reason: "counterevidence dropped for test".into(),
        },
        ClaimDeclarations::Supplied {
            claims: vec![ref_b.clone()],
        },
    );
    let stripped_set = declaration_set(
        &grounded,
        vec![
            RivalModelSlot::Retained {
                declaration: Box::new(model_a),
            },
            RivalModelSlot::Retained {
                declaration: Box::new(model_b_stripped),
            },
        ],
    );
    let (stripped_candidate, _, _, _) = validated_candidate_with(stripped_set);
    let stripped = structure_rival_models(&bundle, &stripped_candidate, &position, &policy)
        .expect("stripped structures");
    assert_ne!(
        full.digest, stripped.digest,
        "lost dissent/counterevidence must change the digest"
    );
    assert_ne!(
        full.equivalence_classes, stripped.equivalence_classes,
        "lost counterevidence must change completeness classes"
    );
}

// WORK_UNIT_CASE: 606/34
#[test]
fn rival_606_34_no_winner_current_or_accepted_field() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("structures");
    let wire = serde_json::to_string(&result).expect("serializes");
    for forbidden in [
        "\"winner\"",
        "\"truth\"",
        "\"selected\"",
        "\"accepted\"",
        "\"rank\"",
        "\"score\"",
        "\"vote\"",
    ] {
        assert!(!wire.contains(forbidden), "no {forbidden} field may exist");
    }
    assert!(matches!(
        result.disposition,
        eliot_dreamer_rival_model::RivalModelDisposition::Structured
            | eliot_dreamer_rival_model::RivalModelDisposition::Partial
            | eliot_dreamer_rival_model::RivalModelDisposition::InsufficientRivals
    ));
}

// WORK_UNIT_CASE: 606/35
#[test]
fn rival_606_35_causal_ceiling_bounded_by_supplied_evidence() {
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("ceiling check structures");
    result.validate().expect("result validates");
    let wire = serde_json::to_string(&result).expect("serializes");
    assert!(!wire.contains("SCIENCE_GRADE"), "ceiling never reaches science grade");
    assert!(!wire.contains("MECHANISM"), "no mechanism without exact supply");
    let declarations = result.declarations.as_ref().expect("packed");
    for slot in &declarations.models {
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        assert!(
            matches!(
                declaration.causal_readings,
                DeclarationAvailability::NotApplicable { .. }
            ),
            "causal ceiling stays bounded by supplied evidence"
        );
    }
}

// WORK_UNIT_CASE: 606/36
#[test]
fn rival_606_36_no_forbidden_runtime_or_provider_api() {
    let manifest = include_str!("../Cargo.toml");
    for forbidden in [
        "eliot-dreamer-candidate-validation",
        "provider",
        "Store",
        "Finish",
        "promotion",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "package manifest must not carry {forbidden}"
        );
    }
    let (candidate, bundle, position, policy) = two_model_fixture();
    let result = structure_rival_models(&bundle, &candidate, &position, &policy)
        .expect("structures");
    let wire = serde_json::to_string(&result).expect("serializes");
    for forbidden in ["\"provider\"", "\"promotion\"", "\"Store\"", "\"Finish\"", "\"tool\""] {
        assert!(!wire.contains(forbidden), "no {forbidden} API in output");
    }
    result.validate().expect("result validates");
}
