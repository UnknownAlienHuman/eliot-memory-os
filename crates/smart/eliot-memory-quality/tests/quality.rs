//! Quality fixtures over the shared CC-008 fence and CC-004 projections.
//!
//! These fixtures bind the exact same task, scope, session, and fence the
//! provider and applicability tests use. The applicability verdict is built
//! explicitly per test (no hidden classifier): every negative case changes
//! exactly one field.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_agent_contracts::{AgentAttemptId, TargetId};
use eliot_context_contracts::{
    AffordanceProjection, CanonicalProjectionSet, ContextBinding, ContinuityProjection,
    SafetyProjection, TaskProjection,
};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId,
    RequestId, ResourceGeneration, SessionId, SourceId, StateFence, TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_learning_contracts::identity::{
    ContractBinding, SourceLineage, LEARNING_SCHEMA_VERSION, digest_without_field,
};
use eliot_learning_contracts::{
    HarnessActivationReceiptCandidate, LifecycleStage, OverlayId, ProofCeiling, SourceDenominator,
    StageDisposition, StageObservation,
};
use eliot_memory_projection_contracts::{
    ApplicableMemory, ApplicableMemorySet, DenominatorState, ExcludedMemory, ExclusionReason,
    FreshnessState, MemoryFreshness, MemoryKind, MemoryProjectionBatch, MemoryProjectionRecord,
    MemoryRole, MemoryScopeBinding, NegativeTrigger, ProjectionCoverage,
};
use eliot_memory_quality::{
    GravityNoteKind, MaintenanceNoteKind, QualityError, QualityRequest, assess_quality,
};
use eliot_receipts::WorkScopeId;

fn task() -> TaskId {
    TaskId::new("task-memq").expect("fixture task")
}

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-memq").expect("fixture scope")
}

fn session() -> SessionId {
    SessionId::new("session-memq").expect("fixture session")
}

fn source() -> SourceId {
    SourceId::new("source-memq").expect("fixture source")
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

fn hex_byte(byte: &str) -> String {
    byte.repeat(32)
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

fn binding() -> MemoryScopeBinding {
    MemoryScopeBinding {
        task_id: task(),
        scope_id: scope(),
        session_id: Some(session()),
        state_fence: fence(),
    }
}

fn provenance() -> Provenance {
    Provenance {
        source_id: source(),
        capture_route: "governor.read.memory".to_owned(),
        scope: "scope-memq".to_owned(),
        raw_handle: None,
        revision: Some("rev-1".to_owned()),
    }
}

fn trigger(text: &str) -> NegativeTrigger {
    NegativeTrigger {
        trigger: text.to_owned(),
        failed_action: "act".to_owned(),
        outcome: "out".to_owned(),
        violated_invariant: "inv".to_owned(),
        reopen_condition: "reopen".to_owned(),
        extinction_condition: "extinct".to_owned(),
    }
}

fn record(handle: &str) -> MemoryProjectionRecord {
    MemoryProjectionRecord {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        handle: aid(handle),
        kind: MemoryKind::Episode,
        binding: binding(),
        state_fence: fence(),
        projection_revision: 1,
        epistemic: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        lifecycle: LifecycleState::Active,
        freshness: MemoryFreshness {
            state: FreshnessState::Current,
            note: "projected at the batch fence".to_owned(),
        },
        provenance: provenance(),
        predecessor: None,
        roles: vec![MemoryRole::Minority],
        influence_eligible: true,
        preconditions: vec![],
        applicability_limits: vec![],
        cue_triggers: vec![],
        negative_trigger: None,
        source_id: source(),
    }
}

fn batch(records: Vec<MemoryProjectionRecord>) -> MemoryProjectionBatch {
    let total = records.len();
    MemoryProjectionBatch {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        binding: binding(),
        records,
        coverage: ProjectionCoverage {
            denominator: DenominatorState::Known { total },
            truncated: false,
            frontier: vec![],
            omissions: vec![],
            revalidation_required: false,
        },
    }
}

/// Build the owner verdict explicitly: handles listed in `excluded` carry
/// the given rule, every other batch record is applicable with kept roles.
fn set_for(
    batch: &MemoryProjectionBatch,
    excluded: &[(&str, ExclusionReason)],
    cue_hits: &[&str],
) -> ApplicableMemorySet {
    let mut applicable = Vec::new();
    let mut excluded_out = Vec::new();
    for record in &batch.records {
        let handle = record.handle.as_str();
        let cue_hit = cue_hits.contains(&handle);
        match excluded.iter().find(|(name, _)| *name == handle) {
            None => applicable.push(ApplicableMemory {
                handle: record.handle.clone(),
                kind: record.kind,
                roles: record.roles.clone(),
                cue_hit,
            }),
            Some((_, reason)) => excluded_out.push(ExcludedMemory {
                handle: record.handle.clone(),
                kind: record.kind,
                reason: reason.clone(),
                cue_hit,
            }),
        }
    }
    ApplicableMemorySet {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        binding: batch.binding.clone(),
        applicable,
        excluded: excluded_out,
        denominator: batch.coverage.denominator.clone(),
        truncated: batch.coverage.truncated,
        revalidation_required: batch.coverage.revalidation_required,
        cue_hits_considered: cue_hits.len(),
    }
}

fn context_binding() -> ContextBinding {
    ContextBinding {
        task_id: task(),
        attempt_id: AgentAttemptId::new("attempt-memq").expect("fixture attempt"),
        scope_id: scope(),
        state_fence: fence(),
        decision_id: DecisionId::new("decision-memq").expect("fixture decision"),
        operation_id: None,
    }
}

fn projections(triggers: Vec<String>) -> CanonicalProjectionSet {
    let binding = context_binding();
    CanonicalProjectionSet {
        binding: binding.clone(),
        task: TaskProjection {
            schema_version: 1,
            binding: binding.clone(),
            goal: "assess one bounded scope".to_owned(),
            commitments: vec!["no invention".to_owned()],
        },
        continuity: ContinuityProjection {
            schema_version: 1,
            binding: binding.clone(),
            plan_state: "collecting".to_owned(),
            continuity_note: "resume at scope fence".to_owned(),
        },
        safety: SafetyProjection {
            schema_version: 1,
            binding: binding.clone(),
            safety_note: "verbatim triggers only".to_owned(),
            negative_memory_triggers: triggers,
        },
        affordance: AffordanceProjection {
            schema_version: 1,
            binding: binding.clone(),
            affordances: vec!["afford-memq".to_owned()],
        },
        omissions: vec![],
    }
}

fn receipt_binding() -> ContractBinding {
    ContractBinding {
        schema_version: LEARNING_SCHEMA_VERSION,
        policy_revision: PolicyRevision::new(1).expect("fixture policy"),
        request_id: RequestId::new("request-memq").expect("fixture request"),
        operation_id: OperationId::new("operation-memq").expect("fixture operation"),
        product_id: ProductId::new("product-memq").expect("fixture product"),
        task_id: task(),
        scope: scope(),
        state_fence: fence(),
        source: SourceLineage {
            owner: source(),
            snapshot: aid("snapshot-memq"),
            revision: TaskRevision::new(1).expect("fixture revision"),
            digest: hex_byte("ab"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

fn receipt() -> HarnessActivationReceiptCandidate {
    let mut candidate = HarnessActivationReceiptCandidate {
        binding: receipt_binding(),
        activation_id: aid("activation-memq"),
        target: TargetId::new("target-memq").expect("fixture target"),
        view_digest: hex_byte("cd"),
        delta_id: aid("delta-memq"),
        overlay_id: OverlayId::from_artifact(aid("overlay-memq")),
        admission_receipt: aid("admission-memq"),
        activation_request_receipt: aid("request-receipt-memq"),
        stages: vec![StageObservation {
            stage: LifecycleStage::CandidateProduced,
            disposition: StageDisposition::NotAttempted,
            predecessor: None,
            owner_receipt: None,
            evidence: vec![],
            denominator: SourceDenominator {
                declared: 1,
                observed: 0,
            },
        }],
        member_denominator: SourceDenominator {
            declared: 1,
            observed: 0,
        },
        metrics: vec![],
        attrition: vec![],
        confounders: vec![],
        independent_evaluator_receipt: None,
        canonical_digest: String::new(),
    };
    candidate.canonical_digest =
        digest_without_field(&candidate, "canonical_digest").expect("fixture digest");
    candidate
}

fn request(
    batch: MemoryProjectionBatch,
    excluded: &[(&str, ExclusionReason)],
    cue_hits: &[&str],
    triggers: Vec<String>,
) -> QualityRequest {
    let applicable = set_for(&batch, excluded, cue_hits);
    QualityRequest {
        batch,
        applicable,
        projections: projections(triggers),
        receipts: vec![receipt()],
    }
}

#[test]
fn happy_path_emits_complete_sections_with_exact_denominator() {
    let mut first = record("mem-1");
    first.negative_trigger = Some(trigger("trig-1"));
    let mut second = record("mem-2");
    second.freshness.state = FreshnessState::Stale;
    second.roles = vec![MemoryRole::Counterexample];
    let batch_value = batch(vec![first, second]);
    let candidate = request(
        batch_value,
        &[("mem-2", ExclusionReason::Stale)],
        &["mem-1", "mem-2"],
        vec!["trig-1".to_owned()],
    );
    let assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.validate().expect("assessment validates");
    assert_eq!(assessment.items.len(), 2);
    assert_eq!(assessment.counter_metrics.denominator_total, 2);
    assert_eq!(assessment.counter_metrics.records_assessed, 2);
    assert_eq!(assessment.counter_metrics.applicable_count, 1);
    assert_eq!(assessment.counter_metrics.excluded_count, 1);
    assert_eq!(assessment.counter_metrics.excluded_by_rule.len(), 1);
    assert_eq!(assessment.counter_metrics.excluded_by_rule[0].rule, "STALE");
    assert_eq!(assessment.counter_metrics.excluded_by_rule[0].count, 1);
    assert_eq!(assessment.receipts_considered, 1);
    let gravity: Vec<GravityNoteKind> = assessment
        .gravity
        .iter()
        .map(|note| note.kind)
        .collect();
    assert!(gravity.contains(&GravityNoteKind::SafetySurfacedNegativeTrigger));
    assert!(gravity.contains(&GravityNoteKind::MinorityPreserved));
    assert!(gravity.contains(&GravityNoteKind::CueHitButExcluded));
    assert!(gravity.contains(&GravityNoteKind::CounterexamplePreserved));
    assert!(
        assessment
            .maintenance
            .iter()
            .any(|note| note.kind == MaintenanceNoteKind::StaleMaterial)
    );
}

#[test]
fn unknown_denominator_fails_closed() {
    let mut batch_value = batch(vec![record("mem-1")]);
    batch_value.coverage.denominator = DenominatorState::Unknown {
        reason: "read-side recount pending".to_owned(),
    };
    let applicable = set_for(&batch_value, &[], &[]);
    let candidate = QualityRequest {
        batch: batch_value,
        applicable,
        projections: projections(vec![]),
        receipts: vec![],
    };
    assert_eq!(
        assess_quality(&candidate),
        Err(QualityError::MissingDenominator)
    );
}

#[test]
fn verdict_missing_a_batch_record_is_rejected() {
    let batch_value = batch(vec![record("mem-1"), record("mem-2")]);
    let applicable = set_for(&batch_value, &[], &[]);
    let mut partial = applicable;
    partial.applicable.pop();
    let candidate = QualityRequest {
        batch: batch_value,
        applicable: partial,
        projections: projections(vec![]),
        receipts: vec![],
    };
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::HandleMismatch { .. })
    ));
}

#[test]
fn projection_binding_drift_is_rejected() {
    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[]);
    let mut drifted = projections(vec![]);
    drifted.binding.task_id = TaskId::new("other-task").expect("fixture drift");
    for projection in [
        &mut drifted.task.binding,
        &mut drifted.continuity.binding,
        &mut drifted.safety.binding,
        &mut drifted.affordance.binding,
    ] {
        projection.task_id = TaskId::new("other-task").expect("fixture drift");
    }
    let candidate = QualityRequest {
        batch: batch_value,
        applicable,
        projections: drifted,
        receipts: vec![],
    };
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::BindingMismatch { .. })
    ));
}

#[test]
fn invalid_receipt_propagates_the_owner_error() {
    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[]);
    let mut broken = receipt();
    broken.stages.clear();
    let candidate = QualityRequest {
        batch: batch_value,
        applicable,
        projections: projections(vec![]),
        receipts: vec![broken],
    };
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::Learning(_))
    ));
}

#[test]
fn lineage_and_lifecycle_facts_become_maintenance_notes() {
    let mut archived = record("mem-9");
    archived.lifecycle = LifecycleState::Archived;
    archived.predecessor = Some(aid("mem-8"));
    archived.roles = vec![];
    archived.influence_eligible = false;
    let batch_value = batch(vec![archived]);
    let candidate = request(
        batch_value,
        &[("mem-9", ExclusionReason::LifecycleInactive)],
        &[],
        vec![],
    );
    let assessment = assess_quality(&candidate).expect("quality assessment");
    let kinds: Vec<MaintenanceNoteKind> = assessment
        .maintenance
        .iter()
        .map(|note| note.kind)
        .collect();
    assert!(kinds.contains(&MaintenanceNoteKind::SupersededWithLineage));
    assert!(kinds.contains(&MaintenanceNoteKind::LifecycleArchived));
    let lineage = assessment
        .maintenance
        .iter()
        .find(|note| note.kind == MaintenanceNoteKind::SupersededWithLineage)
        .expect("lineage note");
    assert_eq!(lineage.predecessor, Some(aid("mem-8")));
    assert!(
        assessment
            .gravity
            .iter()
            .any(|note| note.kind == GravityNoteKind::InfluenceIneligible)
    );
}

#[test]
fn tampered_assessment_version_is_rejected() {
    let batch_value = batch(vec![record("mem-1")]);
    let candidate = request(batch_value, &[], &[], vec![]);
    let mut assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.contract_version = eliot_contracts::ContractVersion::new(9, 9, 9);
    assert_eq!(
        assessment.validate(),
        Err(QualityError::VersionMismatch)
    );
}
