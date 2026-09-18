#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, StructuredCandidateValidationOutcome, ValidationPolicy,
    validate_grounded_dream_draft_at, validate_grounding_candidate_at,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue,
    DreamDraftValidationError, DreamInputBundle, DreamJobAdmission, GroundedDreamDraft,
    GroundingValidationInput, JobClass, ModelDraft, OmissionHandle, PRESERVATION_DIMENSIONS,
    PreservationDimension, PreservationReport, Requester, RequesterOrigin, SourceDisposition,
    SupportState, canonical_bytes,
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

fn fence_b() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001")
            .expect("canonical test lineage-B"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn is_hex64_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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

fn accept_fixture() -> eliot_dreamer_contracts::validation::ValidatedCandidate {
    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    let result = validate_grounded_dream_draft_at(
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
    let CandidateValidationOutcome::Accepted(candidate) = result else {
        panic!("valid fixture must be accepted");
    };
    *candidate
}

// WORK_UNIT_CASE: 595/46
#[test]
fn wu595_46_diagnostic_redaction() {
    let (job, bundle, mut model, grounded, policy, usage, preservation) = fixture();
    model.job_id = "other-job".to_owned();
    let result = validate_grounded_dream_draft_at(
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
    let CandidateValidationOutcome::Rejected(report) = result else {
        panic!("identity drift must be rejected");
    };
    assert!(report.detail.len() <= 1024, "detail must stay bounded");
    assert!(
        !report.detail.to_lowercase().contains("verified"),
        "detail must never carry a verified authority grant"
    );
    assert!(
        !report
            .detail
            .contains("The supplied source supports the bounded hypothesis."),
        "detail must never echo the full model authority text"
    );
    assert!(
        is_hex64_lower(&report.input_digest),
        "input_digest must be 64 lowercase hex"
    );
}

// WORK_UNIT_CASE: 595/47
#[test]
fn wu595_47_malformed_input_no_panic() {
    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues.clear();
    let empty = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(10),
        false,
    );
    assert!(
        empty.is_err(),
        "empty residues must be a contract Err, not a panic"
    );

    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues[0].claim = "   ".to_owned();
    let blank = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(10),
        false,
    );
    assert!(
        blank.is_err(),
        "blank claim must be a contract Err, not a panic"
    );

    let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
    preservation.verdicts[0].note = "n".repeat(1025);
    let oversize = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(10),
        false,
    );
    assert!(
        oversize.is_err(),
        "oversize note must be a contract Err, not a panic"
    );
}

// WORK_UNIT_CASE: 595/48
#[test]
fn wu595_48_lineage_binding() {
    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    let expected_digest = sha256_hex(&canonical_bytes(&model).unwrap());
    let result = validate_grounded_dream_draft_at(
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
    let CandidateValidationOutcome::Accepted(candidate) = result else {
        panic!("valid fixture must be accepted");
    };
    assert_eq!(candidate.job, job);
    assert_eq!(candidate.bundle, bundle);
    assert_eq!(candidate.grounded.residues, grounded.residues);
    assert_eq!(candidate.validated.receipt.job_id, job.canonical_id());
    assert_eq!(
        candidate.validated.receipt.draft_digest,
        grounded.draft_digest
    );
    assert_eq!(candidate.validated.receipt.draft_digest, expected_digest);
    assert_eq!(candidate.validated.draft_digest, expected_digest);
    candidate.validate_binding().unwrap();
}

// WORK_UNIT_CASE: 595/49
#[test]
fn wu595_49_dimensions_ceiling() {
    let candidate = accept_fixture();
    assert!(candidate.preservation.overall().is_ok());
    assert_eq!(candidate.preservation.verdicts.len(), 7);
    assert_eq!(PRESERVATION_DIMENSIONS.len(), 7);
    assert!(!candidate.validated.receipt.proof_ceiling.is_empty());
    assert_eq!(candidate.validated.receipt.proof_ceiling, "candidate-only");
    assert_eq!(candidate.validated.receipt.terminal_disposition, "accepted");
}

// WORK_UNIT_CASE: 595/50
#[test]
fn wu595_50_stale_receipt_rejected() {
    let mut task_drift = accept_fixture();
    task_drift.job.task_id = "task-9".to_owned();
    assert!(task_drift.validate_binding().is_err());

    let mut fence_drift = accept_fixture();
    fence_drift.validated.state_fence = fence_b();
    assert!(fence_drift.validate_binding().is_err());

    let mut manifest_drift = accept_fixture();
    manifest_drift.bundle.manifest_digest = sha256_hex(b"other-manifest");
    assert!(manifest_drift.validate_binding().is_err());

    let mut grounding_drift = accept_fixture();
    grounding_drift.grounded.residues[0]
        .detail
        .push_str(" changed");
    assert!(grounding_drift.validate_binding().is_err());

    let mut policy_drift = accept_fixture();
    policy_drift.policy = {
        let mut policy = ValidationPolicy::new("policy-9", 1, MAX);
        policy.seal().unwrap();
        policy
    };
    assert!(policy_drift.validate_binding().is_err());
}

// WORK_UNIT_CASE: 595/51
#[test]
fn wu595_51_no_authority_carry() {
    let candidate = accept_fixture();
    for forbidden in ["canonical", "current", "effect", "Finish"] {
        assert_ne!(candidate.validated.receipt.proof_ceiling, forbidden);
    }
    assert!(matches!(
        candidate.validated.receipt.terminal_disposition.as_str(),
        "accepted" | "partial"
    ));

    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues[0].state = SupportState::Partial;
    let result = validate_grounded_dream_draft_at(
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
    let CandidateValidationOutcome::Accepted(partial) = result else {
        panic!("partial fixture must be accepted");
    };
    for forbidden in ["canonical", "current", "effect", "Finish"] {
        assert_ne!(partial.validated.receipt.proof_ceiling, forbidden);
    }
    assert!(matches!(
        partial.validated.receipt.terminal_disposition.as_str(),
        "accepted" | "partial"
    ));
    partial.validate_binding().unwrap();
}

// WORK_UNIT_CASE: 595/52
#[test]
fn wu595_52_pure_deterministic() {
    let pure_unstructured: ValidateGroundedDraftFn = validate_grounded_dream_draft_at;
    let pure_structured: ValidateStructuredFn = validate_grounding_candidate_at;
    let _ = (pure_unstructured, pure_structured);

    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    let first = pure_unstructured(
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
    let second = pure_unstructured(
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
    let (CandidateValidationOutcome::Accepted(first), CandidateValidationOutcome::Accepted(second)) =
        (first, second)
    else {
        panic!("valid fixture must be accepted deterministically");
    };
    assert_eq!(
        first.validated.receipt.input_digest,
        second.validated.receipt.input_digest
    );
    assert_eq!(
        first.validated.receipt.output_digest,
        second.validated.receipt.output_digest
    );
    assert_eq!(
        first.validated.receipt.draft_digest,
        second.validated.receipt.draft_digest
    );
    assert_eq!(
        first.validated.receipt.bundle_digest,
        second.validated.receipt.bundle_digest
    );
    assert!(is_hex64_lower(&first.validated.receipt.input_digest));
    assert!(is_hex64_lower(&first.validated.receipt.output_digest));
}
