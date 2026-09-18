#![allow(clippy::unwrap_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use std::num::NonZeroU64;
use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, ValidationPolicy, validate_grounded_dream_draft_at,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobAdmission, GroundedDreamDraft, JobClass, ModelDraft, OmissionHandle,
    PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport, Requester, RequesterOrigin,
    SourceDisposition, SupportState, canonical_bytes, digest_hex,
};

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
    let draft_digest = sha256_hex(&canonical_bytes(&model).unwrap());
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

#[test]
fn accepted_and_partial_results_bind_through_a03_and_keep_receipt_bytes() {
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
        panic!("fixture must be accepted");
    };
    candidate.validate_binding().unwrap();
    assert_eq!(candidate.validated.receipt.terminal_disposition, "accepted");
    let receipt_bytes = canonical_bytes(&candidate.validated.receipt).unwrap();
    assert_eq!(
        digest_hex(&receipt_bytes),
        "584f7acf347035fbc16ca54d9d7e95811c70d12c52b99654a3defa06950e2c99"
    );

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
        panic!("partial fixture must be accepted");
    };
    candidate.validate_binding().unwrap();
    assert_eq!(candidate.validated.receipt.terminal_disposition, "partial");
}

#[test]
fn binding_rejects_grounding_body_and_usage_drift() {
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
    let CandidateValidationOutcome::Accepted(mut candidate) = result else {
        panic!("fixture must be accepted");
    };
    candidate.grounded.residues[0].detail.push_str(" changed");
    assert!(candidate.validate_binding().is_err());

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
    let CandidateValidationOutcome::Accepted(mut candidate) = result else {
        panic!("fixture must be accepted");
    };
    candidate.usage.output_bytes = candidate.usage.output_bytes.saturating_sub(1);
    assert!(candidate.validate_binding().is_err());
}
