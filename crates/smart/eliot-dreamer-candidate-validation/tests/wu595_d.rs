#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, RejectionCode, ValidationPolicy, validate_grounded_dream_draft_at,
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

fn redigest_model(model: &ModelDraft) -> String {
    sha256_hex(&eliot_dreamer_contracts::canonical_bytes(model).unwrap())
}

fn rebind_job_id(
    job: &DreamJobAdmission,
    bundle: &mut DreamInputBundle,
    model: &mut ModelDraft,
    grounded: &mut GroundedDreamDraft,
) {
    let job_id = job.canonical_id();
    bundle.job_id.clone_from(&job_id);
    model.job_id.clone_from(&job_id);
    grounded.job_id = job_id;
    grounded.draft_digest = redigest_model(model);
}

// WORK_UNIT_CASE: 595/28
#[test]
fn wu595_28_exact_seven_preservation_dimensions() {
    assert_eq!(PRESERVATION_DIMENSIONS.len(), 7);
    assert_eq!(
        PRESERVATION_DIMENSIONS,
        &[
            "coverage",
            "faithfulness",
            "lineage",
            "reversibility",
            "authority_ceiling",
            "dependency_closure",
            "provenance_retention",
        ]
    );
    for spelling in PRESERVATION_DIMENSIONS {
        let parsed = PreservationDimension::parse(spelling).unwrap();
        assert_eq!(parsed.as_str(), *spelling);
    }
    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    assert!(preservation.validate().is_ok());
    assert!(preservation.overall().is_ok());
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
    let CandidateValidationOutcome::Accepted(_) = result else {
        panic!("seven-dimension fixture must be accepted");
    };
}

// WORK_UNIT_CASE: 595/29
#[test]
fn wu595_29_each_dimension_valid_failed_unknown_missing_duplicate() {
    assert_eq!(PRESERVATION_DIMENSIONS.len(), 7);
    for index in 0..7 {
        {
            let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
            preservation.verdicts[index].passed = false;
            assert!(preservation.validate().is_ok());
            assert!(preservation.overall().is_err());
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
                panic!("failed dimension {index} must be rejected");
            };
            assert_eq!(report.code, RejectionCode::PreservationFailed);
            assert_eq!(report.preservation, preservation);
        }
        {
            let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
            preservation.verdicts[index].known = false;
            assert!(preservation.validate().is_ok());
            assert!(preservation.overall().is_err());
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
                panic!("unknown dimension {index} must be rejected");
            };
            assert_eq!(report.code, RejectionCode::PreservationFailed);
            assert_eq!(report.preservation, preservation);
        }
        {
            let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
            preservation.verdicts.remove(index);
            assert_eq!(preservation.verdicts.len(), 6);
            assert!(preservation.validate().is_err());
            assert!(preservation.overall().is_err());
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
                result.is_err(),
                "missing dimension {index} must be a contract error"
            );
        }
        {
            let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
            let dup = preservation.verdicts[index].clone();
            preservation.verdicts.push(dup);
            assert_eq!(preservation.verdicts.len(), 8);
            assert!(preservation.validate().is_err());
            assert!(preservation.overall().is_err());
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
                result.is_err(),
                "duplicate dimension {index} must be a contract error"
            );
        }
    }
}

// WORK_UNIT_CASE: 595/30
#[test]
fn wu595_30_hidden_provenance_retention_loss_fails() {
    let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
    let provenance_index = PRESERVATION_DIMENSIONS
        .iter()
        .position(|name| *name == "provenance_retention")
        .unwrap();
    preservation.verdicts[provenance_index].passed = false;
    assert!(preservation.validate().is_ok());
    assert!(preservation.overall().is_err());
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
        panic!("provenance retention loss must be rejected");
    };
    assert_eq!(report.code, RejectionCode::PreservationFailed);
    assert_eq!(report.preservation, preservation);
    assert_eq!(report.grounded, grounded);
    assert_eq!(report.model, model);
}

// WORK_UNIT_CASE: 595/31
#[test]
fn wu595_31_missing_invalidation_still_accepted_but_omission_changes_digest() {
    let (job, bundle, mut model, mut grounded, policy, usage, preservation) = fixture();
    model.invalidation_conditions.clear();
    assert!(model.validate().is_ok());
    grounded.draft_digest = redigest_model(&model);
    assert!(grounded.validate().is_ok());
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
        panic!("empty invalidation_conditions must still be accepted");
    };
    assert!(candidate.model.invalidation_conditions.is_empty());
    assert!(
        candidate
            .bundle
            .omissions
            .iter()
            .any(|o| o.handle == "source-2")
    );
    let full_digest = candidate.validated.receipt.input_digest.clone();

    let mut omitted_bundle = bundle.clone();
    omitted_bundle.omissions.clear();
    assert!(omitted_bundle.validate().is_ok());
    let omitted_result = validate_grounded_dream_draft_at(
        &job,
        &omitted_bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(10),
        false,
    )
    .unwrap();
    let CandidateValidationOutcome::Accepted(omitted_candidate) = omitted_result else {
        panic!("omission-stripped bundle must still be accepted");
    };
    assert_ne!(
        full_digest, omitted_candidate.validated.receipt.input_digest,
        "removing omissions must change the input digest"
    );
}

// WORK_UNIT_CASE: 595/32
#[test]
fn wu595_32_aggregate_member_mismatch_no_averaging() {
    let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
    for (index, verdict) in preservation.verdicts.iter_mut().enumerate() {
        if index == 0 {
            verdict.passed = false;
        } else {
            assert!(verdict.passed && verdict.known);
        }
    }
    assert!(preservation.validate().is_ok());
    assert!(preservation.overall().is_err());
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
        panic!("six passed plus one failed must be rejected without averaging");
    };
    assert_eq!(report.code, RejectionCode::PreservationFailed);
    assert_eq!(report.preservation, preservation);
}

// WORK_UNIT_CASE: 595/33
#[test]
fn wu595_33_no_dimension_compensation_all_but_one_passed() {
    let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
    let failed_index = PRESERVATION_DIMENSIONS
        .iter()
        .position(|name| *name == "dependency_closure")
        .unwrap();
    preservation.verdicts[failed_index].passed = false;
    let passing = preservation
        .verdicts
        .iter()
        .filter(|v| v.passed && v.known)
        .count();
    assert_eq!(passing, 6, "exactly all-but-one dimensions pass");
    assert!(preservation.validate().is_ok());
    assert!(preservation.overall().is_err());
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
        panic!("all-but-one passed must still be rejected");
    };
    assert_eq!(report.code, RejectionCode::PreservationFailed);
}

// WORK_UNIT_CASE: 595/34
#[test]
fn wu595_34_orientation_rivals_unknowns_retained() {
    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    assert_eq!(job.job_class, JobClass::Orientation);
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
        panic!("orientation with partial unknowns must not be hard-rejected");
    };
    assert_eq!(candidate.validated.receipt.terminal_disposition, "partial");
    assert!(!candidate.model.counterevidence.is_empty());
    assert_eq!(candidate.model.counterevidence, model.counterevidence);
    assert_eq!(candidate.grounded.residues[0].state, SupportState::Partial);
}

// WORK_UNIT_CASE: 595/35
#[test]
fn wu595_35_one_clarification_question_accepted() {
    let (mut job, mut bundle, mut model, mut grounded, policy, usage, preservation) = fixture();
    job.job_class = JobClass::Clarification;
    rebind_job_id(&job, &mut bundle, &mut model, &mut grounded);
    assert!(job.validate().is_ok());
    assert!(bundle.validate().is_ok());
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
        panic!("clarification job class fixture must be accepted");
    };
    assert_eq!(candidate.job.job_class, JobClass::Clarification);
    assert_eq!(candidate.job, job);
}

// WORK_UNIT_CASE: 595/36
#[test]
fn wu595_36_research_manifest_claims_bound() {
    let (mut job, mut bundle, mut model, mut grounded, policy, usage, preservation) = fixture();
    job.job_class = JobClass::ResearchSynthesis;
    rebind_job_id(&job, &mut bundle, &mut model, &mut grounded);
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
        panic!("research synthesis job must be accepted");
    };
    assert_eq!(candidate.job.job_class, JobClass::ResearchSynthesis);
    assert!(!candidate.grounded.residues.is_empty());
    for handle in &candidate.model.source_handles {
        assert!(
            candidate
                .bundle
                .materials
                .iter()
                .any(|m| &m.handle == handle),
            "residue handle {handle} must be bound to the manifest"
        );
    }
    assert_eq!(
        candidate.validated.receipt.manifest_digest, candidate.bundle.manifest_digest,
        "residues must be bound to the manifest digest"
    );
    assert_eq!(
        candidate.bundle.manifest_digest, candidate.job.frozen_manifest_digest,
        "bundle manifest must match the frozen job manifest"
    );
}
