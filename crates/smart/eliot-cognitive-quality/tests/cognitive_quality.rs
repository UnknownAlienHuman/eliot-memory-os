//! Package fixtures for candidate-only cognitive quality assessments.
//!
//! Fixtures use owner vocabulary only: evidence cursors, receipt bindings,
//! owner projection envelopes, and admitted positions are all constructible
//! from scalars. Pose acceptance with execution belongs to package proof;
//! these fixtures pin the status and candidate contract shapes, including
//! the equivalent-retry Mechanism Review gate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_cognitive_quality::{
    ExperienceProjections, OwnerSnapshot, QualityAssessmentCandidate, QualityError,
    SkillEvidenceProjectionStatus, SkillEvidenceRef, assess_dreamer_economics, assess_intervention,
    assess_self_quality, assess_skill_lifecycle, assess_tool_surface, recheck_candidate,
};
use eliot_contracts::{
    ArtifactId, ContractVersion, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision,
};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, ClaimId, CurrentEpistemicPosition, Currentness,
    PositionId, PositionRevision,
};
use eliot_learning_contracts::identity::SourceLineage;
use eliot_learning_contracts::{
    ContractBinding, HarnessActivationReceiptCandidate, LifecycleStage, OverlayId, ProofCeiling,
    SourceDenominator, StageDisposition, StageObservation, TargetId,
};
use eliot_observation_contracts::{
    BankProjection, CoverageDisposition, CoverageEvidence, CoverageGap, ExperienceRecordRef,
    FeedbackProjection, GapDisposition, JournalProjection, ObservationRecordEnvelope,
    ObservationRecordKind, ObservationScope, ProjectionCoverage, ProjectionOmission,
    ProjectionOmissionClass, SourceRevisionHandle,
};
use eliot_receipts::WorkScopeId;

fn hex64() -> String {
    "0123456789abcdef".repeat(4)
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-cogq").expect("fixture scope")
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(1).expect("non-zero"),
        )
        .expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

fn other_fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(7).expect("non-zero"),
        )
        .expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

fn evidence_ref(handle: &str, revision: &str) -> SkillEvidenceRef {
    SkillEvidenceRef {
        evidence_handle: aid(handle),
        owner: SourceId::new("governor.skill").expect("fixture owner"),
        revision: revision.to_owned(),
        digest: hex64(),
    }
}

fn status() -> SkillEvidenceProjectionStatus {
    SkillEvidenceProjectionStatus::assemble(
        aid("status-1"),
        aid("skill-1"),
        SourceId::new("governor.skill").expect("fixture owner"),
        scope(),
        fence(),
        vec![evidence_ref("ev-1", "r1"), evidence_ref("ev-2", "r2")],
        vec![aid("rc-1")],
        SourceDenominator {
            declared: 2,
            observed: 2,
        },
        vec![],
    )
    .expect("fixture status")
}

fn receipt_binding(scope_text: &str) -> ContractBinding {
    ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new("request-cogq").expect("fixture request"),
        operation_id: OperationId::new("operation-cogq").expect("fixture operation"),
        product_id: ProductId::new("eliot").expect("fixture product"),
        task_id: TaskId::new("task-cogq").expect("fixture task"),
        scope: WorkScopeId::new(scope_text).expect("fixture scope"),
        state_fence: fence(),
        source: SourceLineage {
            owner: SourceId::new("source-cogq").expect("fixture source"),
            snapshot: aid("snapshot-cogq"),
            revision: TaskRevision::genesis(),
            digest: hex64(),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

fn receipt() -> HarnessActivationReceiptCandidate {
    receipt_with(receipt_binding("scope-cogq"))
}

fn receipt_with(binding: ContractBinding) -> HarnessActivationReceiptCandidate {
    let mut receipt = HarnessActivationReceiptCandidate {
        binding,
        activation_id: aid("act-cogq"),
        target: TargetId::new("target-cogq").expect("fixture target"),
        view_digest: hex64(),
        delta_id: aid("delta-cogq"),
        overlay_id: OverlayId::from_artifact(aid("overlay-cogq")),
        admission_receipt: aid("adm-cogq"),
        activation_request_receipt: aid("areq-cogq"),
        stages: vec![StageObservation {
            stage: LifecycleStage::CandidateProduced,
            disposition: StageDisposition::Observed,
            predecessor: None,
            owner_receipt: Some(aid("stage-rc-cogq")),
            evidence: vec![aid("stage-ev-cogq")],
            denominator: SourceDenominator {
                declared: 1,
                observed: 1,
            },
        }],
        member_denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metrics: vec![],
        attrition: vec![],
        confounders: vec![],
        independent_evaluator_receipt: None,
        canonical_digest: String::new(),
    };
    receipt.seal().expect("fixture seal");
    receipt
}

fn observation_scope() -> ObservationScope {
    ObservationScope {
        work_scope: scope(),
        task_ref: None,
        attempt_ref: None,
        module_or_route_ref: None,
    }
}

fn coverage(observed: u64) -> ProjectionCoverage {
    ProjectionCoverage {
        evidence: CoverageEvidence {
            disposition: CoverageDisposition::Partial,
            denominator_source_ref: "owner-enumeration-1".to_owned(),
            interval: None,
            blind_intervals: vec![],
            observed_count: observed,
        },
        coverage_digest: hex64(),
    }
}

fn record_ref(handle: &str) -> ExperienceRecordRef {
    ExperienceRecordRef {
        handle: aid(handle),
        revision: SourceRevisionHandle {
            source_id: "bank-1".to_owned(),
            revision: "r1".to_owned(),
            content_sha256: hex64(),
            byte_length: 100,
        },
        scope: observation_scope(),
        fence: fence(),
    }
}

fn bank() -> BankProjection {
    BankProjection::assemble(
        aid("proj-bank-1"),
        observation_scope(),
        fence(),
        "r1".to_owned(),
        vec![record_ref("bk-1"), record_ref("bk-2")],
        coverage(2),
        vec![],
    )
    .expect("fixture bank")
}

fn feedback() -> FeedbackProjection {
    FeedbackProjection::assemble(
        aid("proj-fb-1"),
        observation_scope(),
        fence(),
        "r1".to_owned(),
        vec![record_ref("fb-1")],
        coverage(1),
        vec![],
    )
    .expect("fixture feedback")
}

fn journal() -> JournalProjection {
    let gap = CoverageGap {
        gap_id: "gap-1".to_owned(),
        obligation_profile_ref: "obl-1".to_owned(),
        reason_ref: "reason-1".to_owned(),
        affected_interval: None,
        disposition: GapDisposition::Continue,
        protected: false,
        evidence_refs: vec![],
    };
    let record = ObservationRecordEnvelope {
        record_id: "rec-1".to_owned(),
        kind: ObservationRecordKind::CoverageGap,
        event: None,
        coverage_gap: Some(gap),
        journal_control_event: false,
        parent_record_id: None,
    };
    JournalProjection::assemble(
        aid("proj-journal-1"),
        observation_scope(),
        fence(),
        "r1".to_owned(),
        vec![record],
        coverage(1),
        vec![],
    )
    .expect("fixture journal")
}

fn admission_receipt() -> AdmittedReceipt {
    AdmittedReceipt::new(AdmittedReceiptParams {
        receipt_id: eliot_contracts::ReceiptId::new("rc-1").expect("fixture receipt"),
        payload_digest: hex64(),
        owner: SourceId::new("source-epi").expect("fixture source"),
        revision: "rev-1".to_owned(),
        scope: "scope-epi".to_owned(),
        fence: fence(),
        evidence_digest: hex64(),
        coverage_digest: hex64(),
        conflict_digest: hex64(),
        proof_digest: hex64(),
        position: PositionId::new("pos-1").expect("fixture position"),
        position_revision: PositionRevision::new(1).expect("fixture revision"),
    })
    .expect("fixture admission")
}

fn position(currentness: Currentness) -> CurrentEpistemicPosition {
    let supersession = match currentness {
        Currentness::Current => BTreeSet::new(),
        Currentness::Superseded => BTreeSet::from([aid("pos-2")]),
    };
    CurrentEpistemicPosition::new(
        admission_receipt(),
        currentness,
        supersession,
        ClaimId::new("claim-1").expect("fixture claim"),
    )
    .expect("fixture position")
}

fn projections<'a>(
    journal: Option<&'a JournalProjection>,
    bank: Option<&'a BankProjection>,
    feedback: Option<&'a FeedbackProjection>,
) -> ExperienceProjections<'a> {
    ExperienceProjections {
        journal,
        bank,
        feedback,
    }
}

fn intervention() -> QualityAssessmentCandidate {
    assess_intervention(
        aid("assess-int-1"),
        scope(),
        fence(),
        &[aid("prob-1")],
        &[aid("imp-1")],
        &[aid("ver-1")],
        None,
    )
    .expect("fixture intervention")
}

#[test]
fn status_assembles_with_exact_denominator() {
    let made = status();
    made.validate().expect("valid status");
    assert_eq!(made.handles().len(), 2);
    assert_eq!(made.denominator.observed, 2);
}

#[test]
fn status_denominator_mismatch_is_rejected() {
    let made = SkillEvidenceProjectionStatus::assemble(
        aid("status-1"),
        aid("skill-1"),
        SourceId::new("governor.skill").expect("fixture owner"),
        scope(),
        fence(),
        vec![evidence_ref("ev-1", "r1"), evidence_ref("ev-2", "r2")],
        vec![aid("rc-1")],
        SourceDenominator {
            declared: 2,
            observed: 1,
        },
        vec![],
    )
    .expect_err("observed must equal carried refs");
    assert!(matches!(
        made,
        QualityError::IncompleteDenominator { .. }
    ));
}

#[test]
fn status_duplicate_evidence_is_rejected() {
    let error = SkillEvidenceProjectionStatus::assemble(
        aid("status-1"),
        aid("skill-1"),
        SourceId::new("governor.skill").expect("fixture owner"),
        scope(),
        fence(),
        vec![evidence_ref("ev-1", "r1"), evidence_ref("ev-1", "r2")],
        vec![],
        SourceDenominator {
            declared: 2,
            observed: 2,
        },
        vec![],
    )
    .expect_err("duplicate evidence must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

#[test]
fn skill_lifecycle_assesses_valid_closure() {
    let made = assess_skill_lifecycle(aid("assess-skill-1"), &status(), &[receipt()])
        .expect("valid assessment");
    made.validate().expect("candidate validates");
    assert_eq!(
        made.section,
        eliot_cognitive_quality::AssessmentSection::SkillLifecycle
    );
    assert_eq!(made.input_digests.len(), 2);
    assert_eq!(made.denominators.len(), 2);
}

#[test]
fn skill_lifecycle_empty_receipts_are_rejected() {
    let error = assess_skill_lifecycle(aid("assess-skill-1"), &status(), &[])
        .expect_err("empty receipts must fail");
    assert!(matches!(
        error,
        QualityError::IncompleteDenominator { .. }
    ));
}

#[test]
fn skill_lifecycle_receipt_scope_mismatch_is_rejected() {
    let stray = receipt_with(receipt_binding("scope-other"));
    let error = assess_skill_lifecycle(aid("assess-skill-1"), &status(), &[stray])
        .expect_err("scope mismatch must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

#[test]
fn skill_lifecycle_receipt_fence_mismatch_is_rejected() {
    let mut stray = receipt();
    stray.binding.state_fence = other_fence();
    stray.seal().expect("fixture re-seal");
    let error = assess_skill_lifecycle(aid("assess-skill-1"), &status(), &[stray])
        .expect_err("fence mismatch must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

#[test]
fn tool_surface_cites_version_handles() {
    let made = assess_tool_surface(aid("assess-tool-1"), &status(), &[receipt()], &[aid("tool-v1")])
        .expect("valid tool assessment");
    made.validate().expect("candidate validates");
    assert_eq!(
        made.section,
        eliot_cognitive_quality::AssessmentSection::ToolSurface
    );
    assert_eq!(made.evidence_handles.len(), 1);
}

#[test]
fn tool_surface_empty_versions_are_rejected() {
    let error = assess_tool_surface(aid("assess-tool-1"), &status(), &[receipt()], &[])
        .expect_err("empty versions must fail");
    assert!(matches!(
        error,
        QualityError::IncompleteDenominator { .. }
    ));
}

#[test]
fn dreamer_economics_assesses_jobs_by_handle() {
    let made = assess_dreamer_economics(
        aid("assess-dream-1"),
        scope(),
        fence(),
        &[receipt()],
        &[aid("job-1")],
    )
    .expect("valid economics assessment");
    made.validate().expect("candidate validates");
    assert_eq!(
        made.section,
        eliot_cognitive_quality::AssessmentSection::DreamerJobEconomics
    );
    assert_eq!(made.denominators.len(), 1);
    assert_eq!(made.evidence_handles.len(), 1);
}

#[test]
fn dreamer_economics_empty_jobs_are_rejected() {
    let error = assess_dreamer_economics(aid("assess-dream-1"), scope(), fence(), &[receipt()], &[])
        .expect_err("empty jobs must fail");
    assert!(matches!(
        error,
        QualityError::IncompleteDenominator { .. }
    ));
}

#[test]
fn self_quality_assesses_owner_projections() {
    let journal_value = journal();
    let bank_value = bank();
    let feedback_value = feedback();
    let made = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(
            Some(&journal_value),
            Some(&bank_value),
            Some(&feedback_value),
        ),
        &position(Currentness::Current),
        &[receipt()],
        &[aid("obl-1")],
    )
    .expect("valid self assessment");
    made.validate().expect("candidate validates");
    assert_eq!(
        made.section,
        eliot_cognitive_quality::AssessmentSection::SelfQualityView
    );
    assert!(made.input_digests.len() >= 7);
    assert_eq!(made.evidence_handles.len(), 4);
}

#[test]
fn self_quality_without_projection_is_rejected() {
    let error = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(None, None, None),
        &position(Currentness::Current),
        &[receipt()],
        &[aid("obl-1")],
    )
    .expect_err("missing projections must fail");
    assert!(matches!(
        error,
        QualityError::IncompleteDenominator { .. }
    ));
}

#[test]
fn self_quality_superseded_position_is_rejected() {
    let bank_value = bank();
    let error = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(None, Some(&bank_value), None),
        &position(Currentness::Superseded),
        &[receipt()],
        &[aid("obl-1")],
    )
    .expect_err("superseded position must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

#[test]
fn self_quality_empty_obligations_are_rejected() {
    let bank_value = bank();
    let error = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(None, Some(&bank_value), None),
        &position(Currentness::Current),
        &[receipt()],
        &[],
    )
    .expect_err("empty obligations must fail");
    assert!(matches!(
        error,
        QualityError::IncompleteDenominator { .. }
    ));
}

#[test]
fn intervention_freezes_handle_closure() {
    let made = intervention();
    made.validate().expect("candidate validates");
    assert_eq!(
        made.section,
        eliot_cognitive_quality::AssessmentSection::InterventionCandidate
    );
    assert!(made.input_digests.is_empty());
    assert!(made.denominators.is_empty());
    assert_eq!(made.evidence_handles.len(), 3);
}

#[test]
fn intervention_equivalent_retry_requires_mechanism_review() {
    let prior = intervention();
    let error = assess_intervention(
        aid("assess-int-2"),
        scope(),
        fence(),
        &[aid("prob-1")],
        &[aid("imp-1")],
        &[aid("ver-1")],
        Some(&prior),
    )
    .expect_err("equivalent retry must fail");
    assert!(matches!(error, QualityError::MechanismReviewRequired));
}

#[test]
fn intervention_changed_closure_assesses() {
    let prior = intervention();
    let made = assess_intervention(
        aid("assess-int-2"),
        scope(),
        fence(),
        &[aid("prob-1")],
        &[aid("imp-2")],
        &[aid("ver-1")],
        Some(&prior),
    )
    .expect("changed closure assesses");
    made.validate().expect("candidate validates");
}

#[test]
fn intervention_missing_verifiers_are_rejected() {
    let error = assess_intervention(
        aid("assess-int-1"),
        scope(),
        fence(),
        &[aid("prob-1")],
        &[aid("imp-1")],
        &[],
        None,
    )
    .expect_err("missing verifiers must fail");
    assert!(matches!(
        error,
        QualityError::IncompleteDenominator { .. }
    ));
}

#[test]
fn candidate_tampered_digest_is_rejected() {
    let mut made = intervention();
    made.digest = hex64();
    let error = made.validate().expect_err("tampered digest must fail");
    assert!(matches!(error, QualityError::DigestMismatch));
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "contract_version": {"major": 0, "minor": 1, "patch": 0},
        "assessment_id": "assess-int-1",
        "section": "INTERVENTION_CANDIDATE",
        "scope": "scope-cogq",
        "fence": {
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1
            },
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        },
        "input_digests": [],
        "denominators": [],
        "evidence_handles": [],
        "omissions": [],
        "digest": hex64(),
        "aggregate_score": 0.99
    });
    let error = serde_json::from_value::<QualityAssessmentCandidate>(json)
        .expect_err("unknown field must fail");
    assert!(error.to_string().contains("aggregate_score"));
}

#[test]
fn candidate_roundtrips_over_the_wire() {
    let made = intervention();
    let wire = serde_json::to_string(&made).expect("serialize candidate");
    let back: QualityAssessmentCandidate =
        serde_json::from_str(&wire).expect("deserialize candidate");
    assert_eq!(made, back);
}

#[test]
fn candidate_foreign_version_is_rejected_before_wire_acceptance() {
    let mut made = intervention();
    made.contract_version = ContractVersion::new(9, 9, 9);
    let error = made.validate().expect_err("foreign version must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
    let error = recheck_candidate(&made, &OwnerSnapshot {
        statuses: vec![],
        receipts: vec![],
        journals: vec![],
        banks: vec![],
        feedbacks: vec![],
        positions: vec![],
        attested_handles: vec![],
    })
    .expect_err("foreign version must fail recheck");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

fn status_with_omission() -> SkillEvidenceProjectionStatus {
    let omission = ProjectionOmission {
        handle: aid("ev-9"),
        class: ProjectionOmissionClass::TruncatedAtBound,
        detail: "assembly bound 256".to_owned(),
    };
    SkillEvidenceProjectionStatus::assemble(
        aid("status-1"),
        aid("skill-1"),
        SourceId::new("governor.skill").expect("fixture owner"),
        scope(),
        fence(),
        vec![evidence_ref("ev-1", "r1")],
        vec![],
        SourceDenominator {
            declared: 2,
            observed: 1,
        },
        vec![omission],
    )
    .expect("fixture status with omission")
}

#[test]
fn status_omissions_propagate_into_skill_candidate() {
    let made = assess_skill_lifecycle(aid("assess-skill-1"), &status_with_omission(), &[receipt()])
        .expect("valid assessment");
    made.validate().expect("candidate validates");
    assert_eq!(made.omissions.len(), 1);
    assert_eq!(
        made.omissions[0].class,
        ProjectionOmissionClass::TruncatedAtBound
    );
}

#[test]
fn projection_omissions_propagate_into_self_candidate() {
    let omission = ProjectionOmission {
        handle: aid("bk-9"),
        class: ProjectionOmissionClass::TruncatedAtBound,
        detail: "assembly bound 1024".to_owned(),
    };
    let gapped = BankProjection::assemble(
        aid("proj-bank-1"),
        observation_scope(),
        fence(),
        "r1".to_owned(),
        vec![record_ref("bk-1")],
        coverage(2),
        vec![omission],
    )
    .expect("fixture gapped bank");
    let made = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(None, Some(&gapped), None),
        &position(Currentness::Current),
        &[receipt()],
        &[aid("obl-1")],
    )
    .expect("valid self assessment");
    made.validate().expect("candidate validates");
    assert_eq!(made.omissions.len(), 1);
}

fn self_snapshot<'a>(
    journal: Option<&'a JournalProjection>,
    bank: Option<&'a BankProjection>,
    feedback: Option<&'a FeedbackProjection>,
    position: &'a CurrentEpistemicPosition,
    receipt: &'a HarnessActivationReceiptCandidate,
    attested: Vec<ArtifactId>,
) -> OwnerSnapshot<'a> {
    OwnerSnapshot {
        statuses: vec![],
        receipts: vec![receipt],
        journals: journal.into_iter().collect(),
        banks: bank.into_iter().collect(),
        feedbacks: feedback.into_iter().collect(),
        positions: vec![position],
        attested_handles: attested,
    }
}

#[test]
fn recheck_valid_closure_passes() {
    let journal_value = journal();
    let bank_value = bank();
    let feedback_value = feedback();
    let position_value = position(Currentness::Current);
    let receipt_value = receipt();
    let made = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(
            Some(&journal_value),
            Some(&bank_value),
            Some(&feedback_value),
        ),
        &position_value,
        std::slice::from_ref(&receipt_value),
        &[aid("obl-1")],
    )
    .expect("valid self assessment");
    recheck_candidate(
        &made,
        &self_snapshot(
            Some(&journal_value),
            Some(&bank_value),
            Some(&feedback_value),
            &position_value,
            &receipt_value,
            vec![aid("obl-1")],
        ),
    )
    .expect("valid closure rechecks");
}

#[test]
fn recheck_stale_digest_fails() {
    let bank_value = bank();
    let position_value = position(Currentness::Current);
    let receipt_value = receipt();
    let made = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(None, Some(&bank_value), None),
        &position_value,
        std::slice::from_ref(&receipt_value),
        &[aid("obl-1")],
    )
    .expect("valid self assessment");
    // Edge supplies a different receipt sealing a different digest under the
    // same scope and fence: the echoed digest resolves nowhere.
    let mut drifted = receipt();
    drifted.activation_id = aid("act-cogq-2");
    drifted.seal().expect("fixture re-seal");
    let error = recheck_candidate(
        &made,
        &self_snapshot(
            None,
            Some(&bank_value),
            None,
            &position_value,
            &drifted,
            vec![aid("obl-1")],
        ),
    )
    .expect_err("stale digest must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

#[test]
fn recheck_denominator_mismatch_fails() {
    let bank_value = bank();
    let position_value = position(Currentness::Current);
    let receipt_value = receipt();
    let mut made = assess_self_quality(
        aid("assess-self-1"),
        scope(),
        fence(),
        &projections(None, Some(&bank_value), None),
        &position_value,
        std::slice::from_ref(&receipt_value),
        &[aid("obl-1")],
    )
    .expect("valid self assessment");
    made.denominators.push(SourceDenominator {
        declared: 9,
        observed: 9,
    });
    made.digest = made.compute_digest().expect("re-digest");
    let error = recheck_candidate(
        &made,
        &self_snapshot(
            None,
            Some(&bank_value),
            None,
            &position_value,
            &receipt_value,
            vec![aid("obl-1")],
        ),
    )
    .expect_err("foreign denominator must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

#[test]
fn recheck_unattested_handle_fails() {
    let made = intervention();
    let empty = OwnerSnapshot {
        statuses: vec![],
        receipts: vec![],
        journals: vec![],
        banks: vec![],
        feedbacks: vec![],
        positions: vec![],
        attested_handles: vec![],
    };
    let error = recheck_candidate(&made, &empty).expect_err("unattested handles must fail");
    assert!(matches!(error, QualityError::InvalidField { .. }));
}

#[test]
fn recheck_attested_handles_pass() {
    let made = intervention();
    let snapshot = OwnerSnapshot {
        statuses: vec![],
        receipts: vec![],
        journals: vec![],
        banks: vec![],
        feedbacks: vec![],
        positions: vec![],
        attested_handles: vec![aid("prob-1"), aid("imp-1"), aid("ver-1")],
    };
    recheck_candidate(&made, &snapshot).expect("attested closure rechecks");
}

#[test]
fn recheck_resolves_propagated_omissions_via_attestation() {
    let gapped = status_with_omission();
    let receipt_value = receipt();
    let made = assess_skill_lifecycle(aid("assess-skill-1"), &gapped, std::slice::from_ref(&receipt_value))
        .expect("valid assessment");
    assert_eq!(made.omissions.len(), 1);
    let snapshot = OwnerSnapshot {
        statuses: vec![&gapped],
        receipts: vec![&receipt_value],
        journals: vec![],
        banks: vec![],
        feedbacks: vec![],
        positions: vec![],
        // ev-9 is named-but-uncarried: only edge attestation resolves it.
        attested_handles: vec![aid("ev-9")],
    };
    recheck_candidate(&made, &snapshot).expect("gapped closure rechecks");
}

#[test]
fn omission_classes_stay_closed() {
    let omission = ProjectionOmission {
        handle: aid("ev-9"),
        class: ProjectionOmissionClass::TruncatedAtBound,
        detail: "assembly bound 256".to_owned(),
    };
    let made = SkillEvidenceProjectionStatus::assemble(
        aid("status-1"),
        aid("skill-1"),
        SourceId::new("governor.skill").expect("fixture owner"),
        scope(),
        fence(),
        vec![evidence_ref("ev-1", "r1")],
        vec![],
        SourceDenominator {
            declared: 1,
            observed: 1,
        },
        vec![omission],
    )
    .expect("omissions travel");
    assert_eq!(made.omissions.len(), 1);
}
