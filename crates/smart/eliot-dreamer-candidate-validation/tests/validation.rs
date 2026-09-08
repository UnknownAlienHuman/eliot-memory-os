#![allow(clippy::unwrap_used)]

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, RejectionCode, ValidationPolicy, validate_grounded_dream_draft_at,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobInput, GroundedDreamDraft, JobClass, ModelDraft, OmissionHandle,
    PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport, Requester, RequesterOrigin,
    SourceDisposition, SupportState,
};

const MAX: u64 = 1_048_576;

#[allow(clippy::too_many_lines)]
fn fixture() -> (
    DreamJobInput,
    DreamInputBundle,
    ModelDraft,
    GroundedDreamDraft,
    ValidationPolicy,
    BudgetUsage,
    PreservationReport,
) {
    let job = DreamJobInput {
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
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
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
        reference_width: 1,
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

#[test]
fn accepts_and_retains_the_complete_a03_values() {
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
    assert_eq!(candidate.job, job);
    assert_eq!(candidate.bundle, bundle);
    assert_eq!(candidate.model, model);
    assert_eq!(candidate.grounded, grounded);
    assert_eq!(candidate.preservation, preservation);
    assert_eq!(candidate.usage, usage);
    assert_eq!(candidate.policy, policy);
    candidate.validated.validate().unwrap();
    assert_eq!(candidate.validated.receipt.job_id, job.canonical_id());
}

#[test]
fn rejects_identity_and_lineage_drift_without_rewriting_inputs() {
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
    assert_eq!(report.code, RejectionCode::IdentityMismatch);
    assert_eq!(report.model, model);
    assert_eq!(report.bundle, bundle);
}

#[test]
fn rejects_structured_unsupported_precision_and_preserves_residue() {
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
    assert_eq!(report.grounded, grounded);
}

#[test]
fn rejects_unknown_preservation_as_one_failed_dimension() {
    let (job, bundle, model, grounded, policy, usage, mut preservation) = fixture();
    preservation.verdicts[3].known = false;
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
        panic!("unknown preservation must be rejected");
    };
    assert_eq!(report.code, RejectionCode::PreservationFailed);
    assert_eq!(report.preservation, preservation);
}

#[test]
fn cancellation_and_deadline_are_independent_and_deterministic() {
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.deadline_ms = Some(100);
    let cancelled = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(100),
        true,
    )
    .unwrap();
    let CandidateValidationOutcome::Rejected(report) = cancelled else {
        panic!("cancelled input must be rejected");
    };
    assert_eq!(report.code, RejectionCode::Cancelled);
    let late = validate_grounded_dream_draft_at(
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
    let CandidateValidationOutcome::Rejected(report) = late else {
        panic!("late input must be rejected");
    };
    assert_eq!(report.code, RejectionCode::DeadlineExceeded);
}

#[test]
fn rejects_independent_input_budget_before_acceptance() {
    let (job, bundle, model, grounded, policy, mut usage, preservation) = fixture();
    usage.input_bytes = 0;
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
        panic!("underreported input must be rejected");
    };
    assert_eq!(report.code, RejectionCode::BudgetExceeded);
}
