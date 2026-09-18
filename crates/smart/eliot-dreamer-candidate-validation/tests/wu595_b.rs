#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, DreamDraftValidationError, RejectionCode, ValidationPolicy,
    validate_grounded_dream_draft_at,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobAdmission, GroundedDreamDraft, JobClass, ModelDraft, OmissionHandle,
    PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport, Requester, RequesterOrigin,
    SourceDisposition, SupportState,
};
use std::num::NonZeroU64;

const MAX: u64 = 1_048_576;

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
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

// WORK_UNIT_CASE: 595/10
#[test]
fn wu595_10_mismatched_lineage_rejected() {
    let (job, mut bundle, model, grounded, policy, usage, preservation) = fixture();
    bundle.manifest_digest = sha256_hex(b"other-manifest");
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
        panic!("manifest drift must be rejected");
    };
    assert_eq!(report.code, RejectionCode::LineageMismatch);

    let (job, bundle, mut model, mut grounded, policy, usage, preservation) = fixture();
    model.source_handles = vec!["source-2".to_owned()];
    grounded.draft_digest = sha256_hex(&eliot_dreamer_contracts::canonical_bytes(&model).unwrap());
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
        panic!("omitted handle must be rejected");
    };
    assert_eq!(report.code, RejectionCode::LineageMismatch);

    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.draft_digest = sha256_hex(b"other-draft");
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
        panic!("grounding digest drift must be rejected");
    };
    assert_eq!(report.code, RejectionCode::LineageMismatch);
}

// WORK_UNIT_CASE: 595/11
#[test]
fn wu595_11_material_claims_resolve_inside_manifest() {
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
    let materials: Vec<&str> = bundle
        .materials
        .iter()
        .map(|material| material.handle.as_str())
        .collect();
    for handle in &model.source_handles {
        assert!(
            materials.contains(&handle.as_str()),
            "model handle {handle} must resolve inside bundle materials"
        );
    }
    assert_eq!(candidate.validated.receipt.terminal_disposition, "accepted");
    candidate.validate_binding().unwrap();
}

// WORK_UNIT_CASE: 595/12
#[test]
fn wu595_12_unresolvable_reference_rejected() {
    let (job, bundle, mut model, mut grounded, policy, usage, preservation) = fixture();
    model.source_handles = vec!["ghost-source".to_owned()];
    grounded.draft_digest = sha256_hex(&eliot_dreamer_contracts::canonical_bytes(&model).unwrap());
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
        panic!("stale ghost handle must be rejected");
    };
    assert_eq!(report.code, RejectionCode::LineageMismatch);

    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues[0].state = SupportState::OutsideManifest;
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
        panic!("outside-manifest residue must be rejected");
    };
    assert_eq!(report.code, RejectionCode::UnsupportedPrecision);
    assert_eq!(report.grounded.residues, grounded.residues);
}

// WORK_UNIT_CASE: 595/13
#[test]
fn wu595_13_support_states_retained_verbatim() {
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
        panic!("supported residue must be accepted");
    };
    assert_eq!(candidate.validated.receipt.terminal_disposition, "accepted");
    assert_eq!(candidate.grounded.residues, grounded.residues);

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
    let CandidateValidationOutcome::Accepted(candidate) = result else {
        panic!("partial residue must be accepted");
    };
    assert_eq!(candidate.validated.receipt.terminal_disposition, "partial");
    assert_eq!(candidate.grounded.residues, grounded.residues);

    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues[0].state = SupportState::Contradicted;
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
        panic!("contradicted residue must be accepted");
    };
    assert_eq!(candidate.validated.receipt.terminal_disposition, "partial");
    assert_eq!(candidate.grounded.residues, grounded.residues);

    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues[0].state = SupportState::UnsupportedPrecision;
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
        panic!("unsupported precision must be rejected");
    };
    assert_eq!(report.code, RejectionCode::UnsupportedPrecision);
    assert_eq!(report.grounded.residues, grounded.residues);

    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues[0].state = SupportState::OutsideManifest;
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
        panic!("outside-manifest residue must be rejected");
    };
    assert_eq!(report.code, RejectionCode::UnsupportedPrecision);
    assert_eq!(report.grounded.residues, grounded.residues);
}

// WORK_UNIT_CASE: 595/14
#[test]
fn wu595_14_counterevidence_retention_changes_digest() {
    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    let first = validate_grounded_dream_draft_at(
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
    let CandidateValidationOutcome::Accepted(candidate_a) = first else {
        panic!("fixture with counterevidence must be accepted");
    };
    assert_eq!(candidate_a.model.counterevidence, model.counterevidence);
    assert_eq!(
        candidate_a.model.invalidation_conditions,
        model.invalidation_conditions
    );

    let mut model_b = model.clone();
    model_b.counterevidence = Vec::new();
    let mut grounded_b = grounded.clone();
    grounded_b.draft_digest =
        sha256_hex(&eliot_dreamer_contracts::canonical_bytes(&model_b).unwrap());
    let second = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model_b,
        &grounded_b,
        &policy,
        &usage,
        &preservation,
        Some(10),
        false,
    )
    .unwrap();
    let CandidateValidationOutcome::Accepted(candidate_b) = second else {
        panic!("fixture without counterevidence must be accepted");
    };
    assert!(candidate_b.model.counterevidence.is_empty());
    assert_ne!(
        candidate_a.validated.receipt.input_digest, candidate_b.validated.receipt.input_digest,
        "dropping hidden counterevidence must change the input digest"
    );
}

// WORK_UNIT_CASE: 595/15
#[test]
fn wu595_15_unsupported_precision_rejected() {
    for claim in [
        "the value is exactly 42.0001",
        "the event date is exactly 2026-09-18",
        "the version is exactly 2.4.1",
        "the cause is exactly the cache layer",
    ] {
        let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
        grounded.residues[0].state = SupportState::UnsupportedPrecision;
        grounded.residues[0].claim = claim.to_owned();
        grounded.residues[0].detail = format!("{claim} demands precision beyond the manifest");
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
            panic!("precision claim {claim} must be rejected");
        };
        assert_eq!(report.code, RejectionCode::UnsupportedPrecision);
        assert_eq!(report.grounded.residues, grounded.residues);
    }
}

// WORK_UNIT_CASE: 595/16
#[test]
fn wu595_16_excluded_material_requires_exact_residue() {
    let (job, mut bundle, model, grounded, policy, usage, preservation) = fixture();
    bundle.materials[0].disposition = SourceDisposition::Excluded;
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
        panic!("excluded material handle must be rejected");
    };
    assert_eq!(report.code, RejectionCode::LineageMismatch);
    assert_eq!(report.bundle, bundle);
    assert_eq!(report.model, model);
}

// WORK_UNIT_CASE: 595/17
#[test]
fn wu595_17_no_authority_escalation() {
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
    assert_eq!(candidate.validated.receipt.proof_ceiling, "candidate-only");
    assert_eq!(candidate.validated.receipt.terminal_disposition, "accepted");
    assert_eq!(candidate.validated.state_fence, job.state_fence);
    candidate.validate_binding().unwrap();

    let (job, bundle, mut model, grounded, policy, usage, preservation) = fixture();
    model.declared_confirmed_handles = vec!["source-1".to_owned()];
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
    );
    assert!(
        matches!(
            result,
            Err(DreamDraftValidationError::InvalidContract { .. })
        ),
        "declared confirmed handles must fail as a contract error"
    );
}

// WORK_UNIT_CASE: 595/18
#[test]
fn wu595_18_privacy_profile_retained_verbatim() {
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.privacy_profile = "governed_external".to_owned();
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
        panic!("governed_external profile must validate shape");
    };
    assert_eq!(candidate.job.privacy_profile, "governed_external");

    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.privacy_profile = "public".to_owned();
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
    );
    assert!(
        matches!(
            result,
            Err(DreamDraftValidationError::InvalidContract { .. })
        ),
        "invalid privacy spelling must fail as a contract error"
    );
}
