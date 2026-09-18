//! Work-unit cases 595/37..595/45 for the A-05 pre-handler validation gate.
//!
//! Pure, zero-I/O, deterministic coverage over the real
//! `eliot_dreamer_candidate_validation` APIs. No files, no clock, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, RejectionCode, ValidationPolicy, validate_grounded_dream_draft_at,
};
use eliot_dreamer_contracts::candidate::{CandidateProposal, DimensionVerdict, propose_candidate};
use eliot_dreamer_contracts::curation::{
    ClassificationPayload, CurationKind, TargetEvidence, route_payload,
};
use eliot_dreamer_contracts::job::{
    ARCHITECTURE_BRIEF_KIND, ArchitectureBriefMarker, IMPLEMENTATION_BRIEF_KIND,
    ImplementationBriefMarker, brief_kinds_distinct,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, CandidateDisposition,
    ClaimResidue, ContractViolation, DreamInputBundle, DreamJobAdmission, GroundedDreamDraft,
    JobClass, ModelDraft, OmissionHandle, PRESERVATION_DIMENSIONS, PreservationDimension,
    PreservationReport, Requester, RequesterOrigin, SourceDisposition, SupportState,
    canonical_bytes,
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

/// Re-derive every job-bound identity after switching the job class, so the
/// A-03 lineage gate sees a coherent aggregate for any class.
fn fixture_with_class(
    class: JobClass,
) -> (
    DreamJobAdmission,
    DreamInputBundle,
    ModelDraft,
    GroundedDreamDraft,
    ValidationPolicy,
    BudgetUsage,
    PreservationReport,
) {
    let (mut job, mut bundle, mut model, mut grounded, policy, usage, preservation) = fixture();
    job.job_class = class;
    let job_id = job.canonical_id();
    bundle.job_id.clone_from(&job_id);
    model.job_id.clone_from(&job_id);
    let draft_digest = sha256_hex(&canonical_bytes(&model).unwrap());
    grounded.job_id = job_id;
    grounded.draft_digest = draft_digest;
    (job, bundle, model, grounded, policy, usage, preservation)
}

fn accept(
    job: &DreamJobAdmission,
    bundle: &DreamInputBundle,
    model: &ModelDraft,
    grounded: &GroundedDreamDraft,
    policy: &ValidationPolicy,
    usage: &BudgetUsage,
    preservation: &PreservationReport,
) -> CandidateValidationOutcome {
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
    .unwrap()
}

/// Exhaustive, wildcard-free classifier: adding any handler-result variant to
/// `CandidateValidationOutcome` breaks compilation here.
fn outcome_kind(outcome: &CandidateValidationOutcome) -> &'static str {
    match outcome {
        CandidateValidationOutcome::Accepted(_) => "accepted",
        CandidateValidationOutcome::Rejected(_) => "rejected",
    }
}

// WORK_UNIT_CASE: 595/37
#[test]
fn wu595_37_architecture_implementation_authority_separation() {
    assert_ne!(ARCHITECTURE_BRIEF_KIND, IMPLEMENTATION_BRIEF_KIND);
    assert!(brief_kinds_distinct());
    assert_eq!(ARCHITECTURE_BRIEF_KIND, "architecture_brief");
    assert_eq!(IMPLEMENTATION_BRIEF_KIND, "implementation_brief");
    assert_ne!(
        ArchitectureBriefMarker::KIND,
        ImplementationBriefMarker::KIND
    );
    assert_eq!(ArchitectureBriefMarker::KIND, ARCHITECTURE_BRIEF_KIND);
    assert_eq!(ImplementationBriefMarker::KIND, IMPLEMENTATION_BRIEF_KIND);
    let (arch_job, arch_bundle, arch_model, arch_grounded, arch_policy, arch_usage, arch_pres) =
        fixture_with_class(JobClass::ArchitectureSelfQuery);
    let (dev_job, dev_bundle, dev_model, dev_grounded, dev_policy, dev_usage, dev_pres) =
        fixture_with_class(JobClass::DevelopmentDiagnosis);
    assert_ne!(arch_job.canonical_id(), dev_job.canonical_id());
    let CandidateValidationOutcome::Accepted(arch) = accept(
        &arch_job,
        &arch_bundle,
        &arch_model,
        &arch_grounded,
        &arch_policy,
        &arch_usage,
        &arch_pres,
    ) else {
        panic!("architecture self-query must be accepted");
    };
    let CandidateValidationOutcome::Accepted(dev) = accept(
        &dev_job,
        &dev_bundle,
        &dev_model,
        &dev_grounded,
        &dev_policy,
        &dev_usage,
        &dev_pres,
    ) else {
        panic!("development diagnosis must be accepted");
    };
    assert_eq!(arch.job.job_class, JobClass::ArchitectureSelfQuery);
    assert_eq!(dev.job.job_class, JobClass::DevelopmentDiagnosis);
    assert_ne!(arch.validated.receipt.job_id, dev.validated.receipt.job_id);
}

// WORK_UNIT_CASE: 595/38
#[test]
fn wu595_38_curation_kind_payload_screen_binding() {
    let (job, bundle, model, grounded, policy, usage, preservation) =
        fixture_with_class(JobClass::Curation);
    let CandidateValidationOutcome::Accepted(candidate) = accept(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    ) else {
        panic!("curation via A-03 must be accepted pre-handler");
    };
    assert_eq!(candidate.job.job_class, JobClass::Curation);
    assert_eq!(
        format!("{:?}", RejectionCode::UnsupportedJobShape),
        "UnsupportedJobShape"
    );
    let facets = TargetEvidence {
        targets: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
        evidence_refs: vec!["e-1".to_owned()],
    };
    let classification =
        eliot_dreamer_contracts::CurationPayload::Classification(ClassificationPayload {
            label: "memory".to_owned(),
            confidence_bps: 9000,
            target_evidence: facets,
        });
    classification.validate().unwrap();
    let json = serde_json::to_string(&classification).unwrap();
    let err = route_payload(CurationKind::Relation, &json).unwrap_err();
    assert!(matches!(err, ContractViolation::KindPayload(_)));
    let (_, _, _, _, _, _, preservation) = fixture();
    let bad = propose_candidate(CandidateProposal {
        candidate_id: "candidate-1".to_owned(),
        kind: CurationKind::Classification,
        family_spelling: "memory_repair".to_owned(),
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        statement: "proposed statement".to_owned(),
        disposition: CandidateDisposition::Candidate,
        preservation,
        support_note: "supported by source-1".to_owned(),
        rollback_note: "drop candidate-1 to roll back".to_owned(),
        source_handles: vec!["source-1".to_owned()],
    });
    assert!(matches!(bad, Err(ContractViolation::KindPayload(_))));
}

// WORK_UNIT_CASE: 595/39
#[test]
fn wu595_39_inert_development_maintenance_configuration_orchestration() {
    for class in [
        JobClass::DevelopmentDiagnosis,
        JobClass::Maintenance,
        JobClass::OrchestrationPlanning,
        JobClass::ConfigurationAssistance,
    ] {
        let (job, bundle, model, grounded, policy, usage, preservation) = fixture_with_class(class);
        let outcome = accept(
            &job,
            &bundle,
            &model,
            &grounded,
            &policy,
            &usage,
            &preservation,
        );
        let CandidateValidationOutcome::Accepted(candidate) = outcome else {
            panic!("{class:?} must be accepted");
        };
        assert_eq!(candidate.job, job);
        assert_eq!(candidate.bundle, bundle);
        assert_eq!(candidate.model, model);
        assert_eq!(candidate.grounded, grounded);
        assert_eq!(candidate.preservation, preservation);
        assert_eq!(candidate.usage, usage);
        assert_eq!(candidate.policy, policy);
        assert_eq!(candidate.observation_time_ms, Some(10));
        assert!(!candidate.cancellation_requested);
        candidate.validate_binding().unwrap();
    }
}

// WORK_UNIT_CASE: 595/40
#[test]
fn wu595_40_every_handler_family_compiles_through_a03_only() {
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
    assert_eq!(classes.len(), 9);
    for class in classes {
        let (job, bundle, model, grounded, policy, usage, preservation) = fixture_with_class(class);
        let outcome = accept(
            &job,
            &bundle,
            &model,
            &grounded,
            &policy,
            &usage,
            &preservation,
        );
        assert_eq!(
            outcome_kind(&outcome),
            "accepted",
            "{class:?} must be accepted"
        );
        let CandidateValidationOutcome::Accepted(candidate) = outcome else {
            unreachable!("pinned accepted above");
        };
        assert_eq!(candidate.job.job_class, class);
    }
}

// WORK_UNIT_CASE: 595/41
#[test]
fn wu595_41_no_handler_a04_a14b_a31_algorithm_dependency() {
    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    let outcome = accept(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    );
    assert_eq!(outcome_kind(&outcome), "accepted");
    let CandidateValidationOutcome::Accepted(candidate) = outcome else {
        panic!("fixture must be accepted");
    };
    candidate.validate_binding().unwrap();
    assert_eq!(candidate.validated.receipt.job_id, job.canonical_id());
    assert!(matches!(
        candidate.validated.receipt.terminal_disposition.as_str(),
        "accepted" | "partial"
    ));
    assert_eq!(candidate.job, job);
    assert_eq!(candidate.grounded, grounded);
}

// WORK_UNIT_CASE: 595/42
#[test]
fn wu595_42_no_post_handler_candidate_validation_operation() {
    let (job, bundle, mut model, grounded, policy, usage, preservation) = fixture();
    model.job_id = "other-job".to_owned();
    let outcome = validate_grounded_dream_draft_at(
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
    assert_eq!(outcome_kind(&outcome), "rejected");
    let CandidateValidationOutcome::Rejected(report) = outcome else {
        panic!("identity drift must be rejected");
    };
    assert_eq!(report.code, RejectionCode::IdentityMismatch);
    assert_eq!(report.model, model);
    assert_eq!(report.bundle, bundle);
    assert_eq!(report.job, job);
    assert_eq!(report.grounded, grounded);
    assert!(!report.input_digest.is_empty());
}

// WORK_UNIT_CASE: 595/43
#[test]
fn wu595_43_irrelevant_order_preserves_output_digest() {
    let (job, bundle, model, grounded, policy, usage, preservation) = fixture();
    let first = accept(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    );
    let second = accept(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    );
    let CandidateValidationOutcome::Accepted(first) = first else {
        panic!("fixture must be accepted");
    };
    let CandidateValidationOutcome::Accepted(second) = second else {
        panic!("fixture must be accepted");
    };
    assert_eq!(
        first.validated.receipt.input_digest,
        second.validated.receipt.input_digest
    );
    assert_eq!(
        first.validated.receipt.output_digest,
        second.validated.receipt.output_digest
    );
    assert_eq!(first, second);
}

// WORK_UNIT_CASE: 595/44
#[test]
fn wu595_44_semantic_sequence_dependency_order_preserved() {
    let (job, bundle, model, mut grounded, policy, usage, preservation) = fixture();
    grounded.residues.push(ClaimResidue {
        claim: "A second bounded claim follows the first.".to_owned(),
        state: SupportState::Supported,
        detail: "source-1 provides further bounded support".to_owned(),
    });
    let CandidateValidationOutcome::Accepted(candidate) = accept(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
    ) else {
        panic!("multi-residue fixture must be accepted");
    };
    assert_eq!(candidate.grounded.residues, grounded.residues);
    assert_eq!(candidate.grounded.residues.len(), 2);
    assert_eq!(
        candidate.grounded.residues[0].claim,
        "The supplied source supports the bounded hypothesis."
    );
    assert_eq!(
        candidate.grounded.residues[1].claim,
        "A second bounded claim follows the first."
    );
    candidate.validate_binding().unwrap();
}

// WORK_UNIT_CASE: 595/45
#[test]
fn wu595_45_failure_precedence_bounded_multi_error_ordering() {
    let (mut job, bundle, model, grounded, policy, usage, preservation) = fixture();
    job.schema_version = 0;
    let first = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(10),
        true,
    );
    let second = validate_grounded_dream_draft_at(
        &job,
        &bundle,
        &model,
        &grounded,
        &policy,
        &usage,
        &preservation,
        Some(10),
        true,
    );
    let (Err(first), Err(second)) = (first, second) else {
        panic!("cancelled malformed input must be a contract error");
    };
    assert_eq!(first.to_string(), second.to_string());
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
    let (job, bundle, mut model, grounded, policy, usage, preservation) = fixture();
    model.job_id = "other-job".to_owned();
    let run = || {
        validate_grounded_dream_draft_at(
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
        .unwrap()
    };
    let CandidateValidationOutcome::Rejected(first) = run() else {
        panic!("identity drift must be rejected");
    };
    let CandidateValidationOutcome::Rejected(second) = run() else {
        panic!("identity drift must be rejected");
    };
    assert_eq!(first.code, second.code);
    assert_eq!(first.detail, second.detail);
    assert_eq!(first.input_digest, second.input_digest);
}
