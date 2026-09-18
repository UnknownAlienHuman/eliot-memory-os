#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, DreamDraftValidationError, RejectionCode,
    StructuredCandidateValidationOutcome, ValidationPolicy, validate_grounded_dream_draft_at,
    validate_grounding_candidate_at,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::curation::{
    CURATION_WIRE_KINDS, ClassificationPayload, CurationKind, CurationPayload, TargetEvidence,
    kind_family, parse_kind, route_payload,
};
use eliot_dreamer_contracts::validation::{PROOF_CEILING, VALIDATOR_CONTRACT};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, CURATION_FAMILIES,
    CandidateDisposition, CandidateProposal, ClaimResidue, ContractViolation, DreamInputBundle,
    DreamJobAdmission, GroundedDreamDraft, GroundingValidationInput, JobClass, ModelDraft,
    OmissionHandle, PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport, Requester,
    RequesterOrigin, SourceDisposition, SupportState, parse_family, parse_job_class,
    propose_candidate,
};
use std::num::NonZeroU64;

const MAX: u64 = 1_048_576;

type ValidateGroundedDraftFn = fn(
    &DreamJobAdmission,
    &DreamInputBundle,
    &ModelDraft,
    &GroundedDreamDraft,
    &ValidationPolicy,
    &BudgetUsage,
    &PreservationReport,
    Option<u64>,
    bool,
) -> Result<CandidateValidationOutcome, DreamDraftValidationError>;

type ValidateStructuredFn =
    fn(
        &GroundingValidationInput,
    ) -> Result<StructuredCandidateValidationOutcome, DreamDraftValidationError>;

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn drift_fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001")
            .expect("canonical test lineage-B"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

#[allow(clippy::too_many_lines)]
fn fixture() -> (
    DreamJobAdmission,
    DreamInputBundle,
    ModelDraft,
    GroundedDreamDraft,
    ValidationPolicy,
    BudgetUsage,
    PreservationReport,
) {
    let job = DreamJobAdmission {
        schema_version: 1,
        job_class: JobClass::Orientation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: Some("session-1".to_owned()),
        },
        operation_id: "operation-1".to_owned(),
        idempotency_key: "idempotency-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "contract-1".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(MAX),
            output_bytes: Some(MAX),
            source_width: Some(512),
            reference_width: Some(512),
            model_calls: Some(1),
            attempts: Some(1),
            candidates: Some(1),
            wall_ms: Some(600_000),
            work_fan_out: Some(1),
            report_bytes: Some(MAX),
            max_stu: Some(1),
        },
        deadline_ms: None,
        frozen_manifest_digest: sha256_hex(b"manifest-1"),
    };
    let job_id = job.canonical_id();
    let bundle = DreamInputBundle {
        schema_version: 1,
        job_id: job_id.clone(),
        scope_id: job.scope_id.clone(),
        task_id: job.task_id.clone(),
        state_fence: job.state_fence.clone(),
        manifest_digest: job.frozen_manifest_digest.clone(),
        materials: vec![BundleMaterial {
            handle: "source-1".to_owned(),
            disposition: SourceDisposition::Required,
            bytes: 32,
            digest: sha256_hex(b"source-1"),
        }],
        omissions: vec![OmissionHandle {
            handle: "source-2".to_owned(),
            reason: "not supplied in this bounded snapshot".to_owned(),
            reversible: true,
            scope_id: job.scope_id.clone(),
            task_id: job.task_id.clone(),
            digest: sha256_hex(b"omission-2"),
            nonrecoverable_reason: None,
        }],
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    };
    let model = ModelDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        statement: "The supplied source supports the bounded hypothesis.".to_owned(),
        source_handles: vec!["source-1".to_owned()],
        counterevidence: vec!["The snapshot is partial.".to_owned()],
        uncertainty: "medium".to_owned(),
        expected_benefit: "A testable proposal.".to_owned(),
        recommended_probes: vec!["measure the outcome".to_owned()],
        invalidation_conditions: vec!["the source contradicts it".to_owned()],
        declared_confirmed_handles: Vec::new(),
    };
    let draft_digest = sha256_hex(&eliot_dreamer_contracts::canonical_bytes(&model).unwrap());
    let grounded = GroundedDreamDraft {
        schema_version: 1,
        job_id,
        draft_digest,
        residues: vec![ClaimResidue {
            claim: "The supplied source supports the bounded hypothesis.".to_owned(),
            state: SupportState::Supported,
            detail: "source-1 provides bounded support".to_owned(),
        }],
        coverage_note: "one source-backed claim retained".to_owned(),
    };
    let mut policy = ValidationPolicy::new("policy-1", 1, MAX);
    policy.seal().unwrap();
    let usage = BudgetUsage {
        input_bytes: MAX,
        output_bytes: MAX,
        source_width: 1,
        reference_width: 2,
        candidates: 1,
        report_bytes: MAX,
        ..BudgetUsage::default()
    };
    let preservation = PreservationReport {
        verdicts: PRESERVATION_DIMENSIONS
            .iter()
            .map(|name| DimensionVerdict {
                dimension: PreservationDimension::parse(name).unwrap(),
                passed: true,
                known: true,
                note: format!("{name} retained"),
            })
            .collect(),
    };
    (job, bundle, model, grounded, policy, usage, preservation)
}

fn passing_preservation() -> PreservationReport {
    PreservationReport {
        verdicts: PRESERVATION_DIMENSIONS
            .iter()
            .map(|name| DimensionVerdict {
                dimension: PreservationDimension::parse(name).unwrap(),
                passed: true,
                known: true,
                note: format!("{name} retained"),
            })
            .collect(),
    }
}

fn run(
    job: &DreamJobAdmission,
    bundle: &DreamInputBundle,
    model: &ModelDraft,
    grounded: &GroundedDreamDraft,
    policy: &ValidationPolicy,
    usage: &BudgetUsage,
    preservation: &PreservationReport,
) -> Result<CandidateValidationOutcome, DreamDraftValidationError> {
    validate_grounded_dream_draft_at(
        job,
        bundle,
        model,
        grounded,
        policy,
        usage,
        preservation,
        Some(10),
        false,
    )
}

// WORK_UNIT_CASE: 595/1
#[test]
fn wu595_01_router_prehandler_ownership() {
    let draft_fn: ValidateGroundedDraftFn = validate_grounded_dream_draft_at;
    let structured_fn: ValidateStructuredFn = validate_grounding_candidate_at;
    assert!(std::ptr::fn_addr_eq(
        structured_fn,
        validate_grounding_candidate_at as ValidateStructuredFn
    ));
    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    let outcome = draft_fn(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(10),
        false,
    )
    .unwrap();
    let CandidateValidationOutcome::Accepted(candidate) = outcome else {
        panic!("valid fixture must be accepted by the pre-handler gate");
    };
    assert_eq!(
        candidate.validated.receipt.validator_contract, VALIDATOR_CONTRACT,
        "receipt must carry the A-03 validator contract identity"
    );
    assert_eq!(
        candidate.validated.receipt.proof_ceiling, PROOF_CEILING,
        "receipt must carry the candidate-only proof ceiling"
    );
    assert_eq!(candidate.validated.receipt.terminal_disposition, "accepted");
    let wire = serde_json::to_string(&candidate).unwrap();
    assert!(
        !wire.contains("\"effect\""),
        "accepted candidate must carry no effect handle"
    );
    assert!(
        !wire.contains("\"dispatch\""),
        "accepted candidate must carry no dispatch handle"
    );
    assert!(
        !wire.contains("\"handler\""),
        "accepted candidate must carry no handler handle"
    );
}

// WORK_UNIT_CASE: 595/2
#[test]
fn wu595_02_valid_grounded_draft_for_each_job_class() {
    let structured_fn: ValidateStructuredFn = validate_grounding_candidate_at;
    assert!(std::ptr::fn_addr_eq(
        structured_fn,
        validate_grounding_candidate_at as ValidateStructuredFn
    ));
    assert_ne!(
        RejectionCode::UnsupportedJobShape,
        RejectionCode::LineageMismatch,
        "structured Curation shape rejection must be its own code"
    );
    let classes = [
        JobClass::Orientation,
        JobClass::Curation,
        JobClass::Clarification,
        JobClass::ResearchSynthesis,
        JobClass::ArchitectureSelfQuery,
        JobClass::DevelopmentDiagnosis,
        JobClass::Maintenance,
        JobClass::OrchestrationPlanning,
        JobClass::ConfigurationAssistance,
    ];
    assert_eq!(classes.len(), 9, "all nine job classes must be covered");
    for class in classes {
        let (mut job, mut bundle, mut model, mut grounded, policy, usage, preservation) = fixture();
        job.job_class = class;
        let job_id = job.canonical_id();
        bundle.job_id = job_id.clone();
        model.job_id = job_id.clone();
        grounded.job_id = job_id;
        grounded.draft_digest =
            sha256_hex(&eliot_dreamer_contracts::canonical_bytes(&model).unwrap());
        let outcome = run(
            &job,
            &bundle,
            &model,
            &grounded,
            &policy,
            &usage,
            &preservation,
        )
        .unwrap();
        assert!(
            matches!(outcome, CandidateValidationOutcome::Accepted(_)),
            "class {class:?} must be accepted on the A-03 pre-handler path"
        );
    }
}

// WORK_UNIT_CASE: 595/3
#[test]
fn wu595_03_eleven_curation_kinds_map_to_ten_families() {
    assert_eq!(CURATION_WIRE_KINDS.len(), 11);
    assert_eq!(CURATION_FAMILIES.len(), 10);
    for spelling in CURATION_WIRE_KINDS {
        let kind = parse_kind(spelling).unwrap();
        assert_eq!(kind.as_str(), *spelling);
        let family = kind_family(kind);
        assert!(
            CURATION_FAMILIES.contains(&family),
            "kind {spelling} must map to a known family"
        );
        parse_family(family).unwrap();
        let proposal = CandidateProposal {
            candidate_id: "candidate-1".to_owned(),
            kind,
            family_spelling: family.to_owned(),
            job_id: "job-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            statement: "proposed statement".to_owned(),
            disposition: CandidateDisposition::Candidate,
            preservation: passing_preservation(),
            support_note: "supported by source-1".to_owned(),
            rollback_note: "drop candidate-1 to roll back".to_owned(),
            source_handles: vec!["source-1".to_owned()],
        };
        let candidate = propose_candidate(proposal).unwrap();
        candidate.validate().unwrap();
        let wrong = if family == "classification" {
            "relation"
        } else {
            "classification"
        };
        let mut mismatch = candidate.clone();
        mismatch.family_spelling = wrong.to_owned();
        assert!(
            matches!(mismatch.validate(), Err(ContractViolation::KindPayload(_))),
            "kind {spelling} must reject family {wrong}"
        );
    }
    assert_eq!(kind_family(CurationKind::Merge), "structure_repair");
    assert_eq!(kind_family(CurationKind::Split), "structure_repair");
    assert_eq!(kind_family(CurationKind::Repair), "memory_repair");
}

// WORK_UNIT_CASE: 595/4
#[test]
fn wu595_04_unknown_schema_job_kind_field_variant_rejected() {
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.schema_version = 999;
    let err = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap_err();
    assert!(
        matches!(err, DreamDraftValidationError::InvalidContract { .. }),
        "schema_version 999 must fail as an invalid contract"
    );
    let (job, _, _, _, _, _, _) = fixture();
    let wire = serde_json::to_string(&job).unwrap();
    let injected = wire.replacen('{', "{\"unknown_probe_key\":true,", 1);
    let decoded = serde_json::from_str::<DreamJobAdmission>(&injected);
    assert!(decoded.is_err(), "unknown JSON field must fail decode");
    assert!(
        decoded.unwrap_err().to_string().contains("unknown field"),
        "deny_unknown_fields must name the unknown field"
    );
    let err = parse_job_class("orientation_extended").unwrap_err();
    assert!(
        matches!(err, ContractViolation::UnknownVariant { .. }),
        "unknown job spelling must fail as an unknown variant"
    );
    let err = parse_kind("structure_repair").unwrap_err();
    assert!(
        matches!(err, ContractViolation::UnknownVariant { .. }),
        "family spellings are wire kinds of nothing"
    );
    assert!(
        serde_json::from_str::<SupportState>("\"backed\"").is_err(),
        "unknown support variant must fail decode"
    );
}

// WORK_UNIT_CASE: 595/5
#[test]
fn wu595_05_wrong_missing_family_payload_rejected() {
    let proposal = CandidateProposal {
        candidate_id: "candidate-1".to_owned(),
        kind: CurationKind::Classification,
        family_spelling: "classification".to_owned(),
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        statement: "proposed statement".to_owned(),
        disposition: CandidateDisposition::Candidate,
        preservation: passing_preservation(),
        support_note: "supported by source-1".to_owned(),
        rollback_note: "drop candidate-1 to roll back".to_owned(),
        source_handles: vec!["source-1".to_owned()],
    };
    let valid = propose_candidate(proposal).unwrap();
    valid.validate().unwrap();
    let mut wrong_family = valid.clone();
    wrong_family.family_spelling = "memory_repair".to_owned();
    assert!(matches!(
        wrong_family.validate(),
        Err(ContractViolation::KindPayload(_))
    ));
    let mut missing_family = valid.clone();
    missing_family.family_spelling = String::new();
    assert!(matches!(
        missing_family.validate(),
        Err(ContractViolation::MissingField(_))
    ));
    let payload = CurationPayload::Classification(ClassificationPayload {
        label: "memory".to_owned(),
        confidence_bps: 9000,
        target_evidence: TargetEvidence {
            targets: vec!["a".to_owned()],
            evidence_refs: vec!["e-1".to_owned()],
        },
    });
    payload.validate().unwrap();
    let json = serde_json::to_string(&payload).unwrap();
    assert!(
        matches!(
            route_payload(CurationKind::Relation, &json),
            Err(ContractViolation::KindPayload(_))
        ),
        "payload routed under the wrong kind must fail"
    );
    route_payload(CurationKind::Classification, &json).unwrap();
}

// WORK_UNIT_CASE: 595/6
#[test]
fn wu595_06_duplicate_dimension_evidence_rejected_handles_deterministic() {
    let (job, bundle, mut model, grounded, policy, mut usage, preservation) = fixture();
    let mut duplicated_dimension = preservation.clone();
    duplicated_dimension.verdicts[6] = duplicated_dimension.verdicts[0].clone();
    assert!(matches!(
        duplicated_dimension.validate(),
        Err(ContractViolation::Preservation(_))
    ));
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &duplicated_dimension,
    );
    assert!(
        matches!(
            outcome,
            Err(DreamDraftValidationError::InvalidContract { .. })
        ),
        "duplicate preservation dimension must never be accepted"
    );
    let duplicated_evidence = TargetEvidence {
        targets: vec!["a".to_owned()],
        evidence_refs: vec!["e-1".to_owned(), "e-1".to_owned()],
    };
    assert!(matches!(
        duplicated_evidence.validate("classification"),
        Err(ContractViolation::BindingMismatch { .. })
    ));
    let mut duplicated_claim = grounded.clone();
    duplicated_claim
        .residues
        .push(duplicated_claim.residues[0].clone());
    let outcome = run(
        &job,
        &bundle,
        &model,
        &duplicated_claim,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Accepted(_)),
        "duplicate claim residues are retained without deduplication"
    );
    model.source_handles = vec!["source-1".to_owned(), "source-1".to_owned()];
    usage.source_width = 2;
    let mut grounded_dup = grounded.clone();
    grounded_dup.draft_digest =
        sha256_hex(&eliot_dreamer_contracts::canonical_bytes(&model).unwrap());
    let first = run(
        &job,
        &bundle,
        &model,
        &grounded_dup,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    let second = run(
        &job,
        &bundle,
        &model,
        &grounded_dup,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    let (CandidateValidationOutcome::Accepted(first), CandidateValidationOutcome::Accepted(second)) =
        (first, second)
    else {
        panic!("duplicate source handles must replay deterministically");
    };
    assert_eq!(
        first.validated.receipt.input_digest, second.validated.receipt.input_digest,
        "same duplicate-handle input must replay to the same input digest"
    );
}

// WORK_UNIT_CASE: 595/7
#[test]
fn wu595_07_same_id_changed_content_rejected_as_lineage_mismatch() {
    let (job, bundle, mut model, grounded, policy, usage, preservation) = fixture();
    let frozen_id = job.canonical_id();
    model.statement = "A rewritten hypothesis with no new support.".to_owned();
    assert_eq!(
        job.canonical_id(),
        frozen_id,
        "rewriting the model must not move the frozen job identity"
    );
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    let CandidateValidationOutcome::Rejected(report) = outcome else {
        panic!("stale draft digest must be rejected");
    };
    assert_eq!(report.code, RejectionCode::LineageMismatch);
    assert_eq!(
        report.model, model,
        "rejected report must retain the supplied rewritten model"
    );
    assert!(
        report.model.statement.contains("rewritten"),
        "retained model must carry the changed content"
    );
    assert_eq!(report.grounded, grounded);
}

// WORK_UNIT_CASE: 595/8
#[test]
fn wu595_08_task_scope_fence_requester_bindings_rejected() {
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.task_id = "task-9".to_owned();
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Rejected(report) if report.code == RejectionCode::LineageMismatch),
        "mutated task binding must be a lineage mismatch"
    );
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.scope_id = "scope-9".to_owned();
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Rejected(report) if report.code == RejectionCode::IdentityMismatch),
        "mutated scope binding moves the canonical job identity"
    );
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.state_fence = drift_fence();
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Rejected(report) if report.code == RejectionCode::LineageMismatch),
        "mutated fence binding must be a lineage mismatch"
    );
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.requester.principal = String::new();
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    );
    assert!(
        !matches!(outcome, Ok(CandidateValidationOutcome::Accepted(_))),
        "mutated requester binding must never be accepted"
    );
    assert!(matches!(
        outcome,
        Err(DreamDraftValidationError::InvalidContract { .. })
    ));
}

// WORK_UNIT_CASE: 595/9
#[test]
fn wu595_09_stale_cross_task_cross_scope_rejected() {
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.deadline_ms = Some(100);
    let outcome = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(100),
        false,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Rejected(report) if report.code == RejectionCode::DeadlineExceeded),
        "observation at the deadline is stale"
    );
    let (job, mut bundle, model, grounded, policy, usage, preservation) = fixture();
    bundle.task_id = "task-9".to_owned();
    for omission in &mut bundle.omissions {
        omission.task_id = "task-9".to_owned();
    }
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Rejected(report) if report.code == RejectionCode::LineageMismatch),
        "cross-task bundle must be a lineage mismatch"
    );
    let (job, mut bundle, model, grounded, policy, usage, preservation) = fixture();
    bundle.scope_id = "scope-9".to_owned();
    for omission in &mut bundle.omissions {
        omission.scope_id = "scope-9".to_owned();
    }
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Rejected(report) if report.code == RejectionCode::LineageMismatch),
        "cross-scope bundle must be a lineage mismatch"
    );
    let (job, mut bundle, model, grounded, policy, usage, preservation) = fixture();
    bundle.state_fence = drift_fence();
    let outcome = run(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    )
    .unwrap();
    assert!(
        matches!(outcome, CandidateValidationOutcome::Rejected(report) if report.code == RejectionCode::LineageMismatch),
        "cross-fence bundle must be a lineage mismatch"
    );
}
