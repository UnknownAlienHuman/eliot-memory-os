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
    DecisionRevision, LossPolicy, NonRecoverableReason, OmissionReason, OmissionRecord, ProviderId,
    ProviderRole, SafetyProjection, SemanticRole, TaskProjection,
};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId,
    RequestId, ResourceGeneration, SessionId, SourceId, StateFence, TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_learning_contracts::identity::{
    ContractBinding, LEARNING_SCHEMA_VERSION, SourceLineage, digest_without_field,
};
use eliot_learning_contracts::{
    ActivationSection, ActivationStatus, AdherenceSection, AdherenceStatus, DeliverySection,
    DeliveryStatus, HarnessActivationReceiptCandidate, LifecycleStage, OverlayId, ProofCeiling,
    RetrievalSection, RetrievalStatus, SourceDenominator, StageDisposition, StageObservation,
};
use eliot_memory_projection_contracts::{
    ApplicableMemory, ApplicableMemorySet, CoverageOmission, DenominatorState, ExcludedMemory,
    ExclusionReason, FreshnessState, MemoryFreshness, MemoryKind, MemoryProjectionBatch,
    MemoryProjectionRecord, MemoryRole, MemoryScopeBinding, NegativeTrigger, ProjectionCoverage,
};
use eliot_memory_quality::{
    CoverageStatus, GravityNoteKind, MaintenanceNoteKind, QualityError, QualityRequest,
    assess_quality,
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
    StateFence {
        task_revision: Some(TaskRevision::new(1).expect("fixture revision")),
        ..StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("fixture lineage"),
                NonZeroU64::new(1).expect("non-zero"),
            )
            .expect("fixture epoch"),
            ResourceGeneration::genesis(),
        )
    }
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
        projection_revision: 7,
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

fn coverage(total: usize) -> ProjectionCoverage {
    ProjectionCoverage {
        denominator: DenominatorState::Known { total },
        truncated: false,
        frontier: vec![],
        omissions: vec![],
        revalidation_required: false,
    }
}

fn batch(records: Vec<MemoryProjectionRecord>) -> MemoryProjectionBatch {
    let total = records.len();
    MemoryProjectionBatch {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        binding: binding(),
        records,
        coverage: coverage(total),
    }
}

/// Build the owner verdict explicitly: handles listed in `excluded` carry
/// the given rule, every other batch record is applicable with kept roles.
/// A caller-supplied kind override proves the consumer derives identity
/// from the batch record, never from the repeated verdict field.
fn set_for(
    batch: &MemoryProjectionBatch,
    excluded: &[(&str, ExclusionReason)],
    cue_hits: &[&str],
    kind_override: Option<MemoryKind>,
) -> ApplicableMemorySet {
    let mut applicable = Vec::new();
    let mut excluded_out = Vec::new();
    for record in &batch.records {
        let handle = record.handle.as_str();
        let cue_hit = cue_hits.contains(&handle);
        let kind = kind_override.unwrap_or(record.kind);
        match excluded.iter().find(|(name, _)| *name == handle) {
            None => applicable.push(ApplicableMemory {
                handle: record.handle.clone(),
                kind,
                roles: record.roles.clone(),
                cue_hit,
            }),
            Some((_, reason)) => excluded_out.push(ExcludedMemory {
                handle: record.handle.clone(),
                kind,
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

fn omission_record() -> OmissionRecord {
    OmissionRecord {
        atom_id: aid("atom-memq"),
        source_id: aid("source-atom-memq"),
        provider_role: ProviderRole {
            provider: ProviderId::new("provider-memq").expect("fixture provider"),
            role: SemanticRole::Source,
        },
        decision: DecisionRevision {
            decision_id: DecisionId::new("decision-memq").expect("fixture decision"),
            recipe_revision: TaskRevision::new(1).expect("fixture revision"),
            policy_sha256: hex_byte("ef"),
        },
        task_revision: TaskRevision::new(1).expect("fixture revision"),
        reason: OmissionReason::Capacity,
        competing_constraint: "context window".to_owned(),
        measured_cost: None,
        allowed_representation: LossPolicy::HandleOnly,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::PolicyDisallows),
        authorization_requirement: "owner release".to_owned(),
        privacy_requirement: "none".to_owned(),
        proof_requirement: "reprojection".to_owned(),
        expires: None,
        invalidation: None,
        digest: hex_byte("01"),
    }
}

fn projections(triggers: Vec<String>, omissions: Vec<OmissionRecord>) -> CanonicalProjectionSet {
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
        omissions,
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
        compiled_view_ref: aid("compiled-view-memq"),
        context_compiler_revision: "compiler-rev-memq".to_owned(),
        render_profile_revision: "render-rev-memq".to_owned(),
        stable_harness_refs: vec![],
        task_family_harness_refs: vec![],
        skill_refs: vec![],
        memory_refs: vec![],
        procedure_refs: vec![],
        preserved_success_ref: None,
        eligibility_and_retrieval_reason: None,
        retrieval: RetrievalSection {
            status: RetrievalStatus::Unknown,
            expansion_or_tool_query_refs: vec![],
        },
        delivery: DeliverySection {
            status: DeliveryStatus::Missing,
            packet_position: None,
            serialized_digest: None,
            bytes: None,
            actual_tokens: None,
        },
        activation: ActivationSection {
            status: ActivationStatus::Unknown,
            acknowledgement_ref: None,
            observation_limit_reason: None,
            first_qualifying_observable_use_ref: None,
        },
        adherence: AdherenceSection {
            status: AdherenceStatus::Unknown,
            early_mid_final_checkpoint_refs: vec![],
            prescribed_or_avoided_action_and_required_verifier_refs: vec![],
        },
        conflicts_suppression_or_compaction_loss: vec![],
        downstream_decision_action_artifact_and_verifier_refs: vec![],
        receipt_completeness_and_missing_fields: vec![],
        invalidation_expiry_and_missingness: vec![],
        canonical_digest: String::new(),
    };
    candidate.canonical_digest =
        digest_without_field(&candidate, "canonical_digest").expect("fixture digest");
    candidate
}

fn bind_request(
    batch: MemoryProjectionBatch,
    applicable: ApplicableMemorySet,
    projections: CanonicalProjectionSet,
    receipts: Vec<HarnessActivationReceiptCandidate>,
    missing_owner: Option<SourceId>,
) -> QualityRequest {
    let source_batch_digest = batch.canonical_digest().unwrap_or_else(|_| "0".repeat(64));
    QualityRequest {
        batch,
        projection_read_receipt: aid("memory-read-receipt"),
        source_batch_digest,
        missing_owner,
        applicable,
        projections,
        receipts,
    }
}

fn request(
    batch: MemoryProjectionBatch,
    excluded: &[(&str, ExclusionReason)],
    cue_hits: &[&str],
    triggers: Vec<String>,
) -> QualityRequest {
    let applicable = set_for(&batch, excluded, cue_hits, None);
    bind_request(
        batch,
        applicable,
        projections(triggers, vec![]),
        vec![receipt()],
        None,
    )
}

#[test]
fn happy_path_emits_complete_assessment_with_exact_denominator() {
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
    assert_eq!(assessment.status, CoverageStatus::Complete);
    assert_eq!(assessment.items.len(), 2);
    assert_eq!(assessment.items[0].kind, MemoryKind::Episode);
    assert_eq!(assessment.items[0].projection_revision, 7);
    assert_eq!(assessment.counter_metrics.denominator_total, 2);
    assert_eq!(assessment.counter_metrics.records_assessed, 2);
    assert_eq!(assessment.counter_metrics.unaccounted_volume, 0);
    assert_eq!(assessment.counter_metrics.applicable_count, 1);
    assert_eq!(assessment.counter_metrics.excluded_count, 1);
    assert_eq!(assessment.counter_metrics.excluded_by_rule.len(), 1);
    assert_eq!(assessment.counter_metrics.excluded_by_rule[0].rule, "STALE");
    assert_eq!(assessment.counter_metrics.excluded_by_rule[0].count, 1);
    assert_eq!(assessment.receipts.len(), 1);
    assert_eq!(assessment.receipts[0].activation_id, aid("activation-memq"));
    assert_eq!(
        assessment.receipts[0].member_denominator,
        SourceDenominator {
            declared: 1,
            observed: 0,
        }
    );
    let gravity: Vec<GravityNoteKind> = assessment.gravity.iter().map(|note| note.kind).collect();
    assert!(gravity.contains(&GravityNoteKind::SafetySurfacedNegativeTrigger));
    assert!(gravity.contains(&GravityNoteKind::MinorityPreserved));
    assert!(gravity.contains(&GravityNoteKind::CueHitButExcluded));
    assert!(gravity.contains(&GravityNoteKind::CounterexamplePreserved));
    let stale_note = assessment
        .maintenance
        .iter()
        .find(|note| note.kind == MaintenanceNoteKind::StaleMaterial)
        .expect("stale note");
    assert_eq!(
        stale_note.rationale,
        Some("projected at the batch fence".to_owned())
    );
    assert_eq!(stale_note.source_revision, Some("rev-1".to_owned()));
}

#[test]
fn canonical_identity_comes_from_the_batch_record_not_the_verdict() {
    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[], Some(MemoryKind::Observation));
    let candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![]),
        vec![],
        None,
    );
    let assessment = assess_quality(&candidate).expect("quality assessment");
    assert_eq!(assessment.items[0].kind, MemoryKind::Episode);
}

#[test]
fn unknown_denominator_fails_closed() {
    let mut batch_value = batch(vec![record("mem-1")]);
    batch_value.coverage.denominator = DenominatorState::Unknown {
        reason: "read-side recount pending".to_owned(),
    };
    let applicable = set_for(&batch_value, &[], &[], None);
    let candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![]),
        vec![],
        None,
    );
    assert_eq!(
        assess_quality(&candidate),
        Err(QualityError::MissingDenominator)
    );
}

#[test]
fn truncated_coverage_is_inconclusive_with_frontier() {
    let mut batch_value = batch(vec![record("mem-1")]);
    batch_value.coverage.denominator = DenominatorState::Known { total: 2 };
    batch_value.coverage.truncated = true;
    batch_value.coverage.frontier = vec!["resume-1".to_owned()];
    batch_value.coverage.revalidation_required = true;
    let applicable = set_for(&batch_value, &[], &[], None);
    let candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![]),
        vec![],
        None,
    );
    let assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.validate().expect("assessment validates");
    assert_eq!(assessment.status, CoverageStatus::Inconclusive);
    assert_eq!(assessment.frontier, vec!["resume-1".to_owned()]);
    assert_eq!(assessment.counter_metrics.unaccounted_volume, 1);
    let mut complete = assessment.clone();
    complete.status = CoverageStatus::Complete;
    assert!(complete.validate().is_err());
}

#[test]
fn batch_omissions_are_carried_with_identities() {
    let mut batch_value = batch(vec![record("mem-1")]);
    batch_value.coverage.denominator = DenominatorState::Known { total: 2 };
    batch_value.coverage.omissions = vec![CoverageOmission {
        handle: aid("mem-omitted"),
        reason: "fence-mismatch".to_owned(),
    }];
    batch_value.coverage.revalidation_required = true;
    let applicable = set_for(&batch_value, &[], &[], None);
    let candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![]),
        vec![],
        Some(SourceId::new("memory-read-owner").expect("fixture owner")),
    );
    let assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.validate().expect("assessment validates");
    assert_eq!(assessment.status, CoverageStatus::Inconclusive);
    assert_eq!(
        assessment.projection_read_receipt,
        aid("memory-read-receipt")
    );
    assert_eq!(
        assessment.source_batch_digest,
        candidate.source_batch_digest
    );
    assert_eq!(
        assessment.missing_owner.as_ref().map(SourceId::as_str),
        Some("memory-read-owner")
    );
    assert_eq!(assessment.batch_omissions.len(), 1);
    assert_eq!(assessment.batch_omissions[0].handle, aid("mem-omitted"));
    assert_eq!(assessment.counter_metrics.omissions_carried, 1);
    assert_eq!(assessment.counter_metrics.unaccounted_volume, 0);
}

#[test]
fn undeclared_volume_is_rejected_by_the_batch_owner() {
    let batch_value = batch(vec![record("mem-1")]);
    let mut lossy = batch_value;
    lossy.coverage.denominator = DenominatorState::Known { total: 3 };
    let applicable = set_for(&lossy, &[], &[], None);
    let candidate = bind_request(lossy, applicable, projections(vec![], vec![]), vec![], None);
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::Projection(
            eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch { .. }
        ))
    ));
}

#[test]
fn searched_memory_recovery_identity_must_match_and_name_real_gaps() {
    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[], None);
    let mut candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![]),
        vec![],
        None,
    );
    candidate.source_batch_digest = "f".repeat(64);
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::BindingMismatch {
            left: "request.source_batch_digest",
            ..
        })
    ));

    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[], None);
    let candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![]),
        vec![],
        Some(SourceId::new("memory-read-owner").expect("fixture owner")),
    );
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::InvalidField {
            field: "request.missing_owner",
            ..
        })
    ));
}

#[test]
fn projection_omissions_block_completeness() {
    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[], None);
    let candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![omission_record()]),
        vec![],
        None,
    );
    let assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.validate().expect("assessment validates");
    assert_eq!(assessment.status, CoverageStatus::Inconclusive);
    assert_eq!(assessment.projection_omissions.len(), 1);
    assert_eq!(assessment.counter_metrics.projection_omissions, 1);
}

#[test]
fn verdict_missing_a_batch_record_is_rejected() {
    let batch_value = batch(vec![record("mem-1"), record("mem-2")]);
    let applicable = set_for(&batch_value, &[], &[], None);
    let mut partial = applicable;
    partial.applicable.pop();
    let candidate = bind_request(
        batch_value,
        partial,
        projections(vec![], vec![]),
        vec![],
        None,
    );
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::HandleMismatch { .. })
    ));
}

#[test]
fn projection_binding_drift_is_rejected() {
    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[], None);
    let mut drifted = projections(vec![], vec![]);
    drifted.binding.task_id = TaskId::new("other-task").expect("fixture drift");
    for projection in [
        &mut drifted.task.binding,
        &mut drifted.continuity.binding,
        &mut drifted.safety.binding,
        &mut drifted.affordance.binding,
    ] {
        projection.task_id = TaskId::new("other-task").expect("fixture drift");
    }
    let candidate = bind_request(batch_value, applicable, drifted, vec![], None);
    assert!(matches!(
        assess_quality(&candidate),
        Err(QualityError::BindingMismatch { .. })
    ));
}

#[test]
fn invalid_receipt_propagates_the_owner_error() {
    let batch_value = batch(vec![record("mem-1")]);
    let applicable = set_for(&batch_value, &[], &[], None);
    let mut broken = receipt();
    broken.stages.clear();
    let candidate = bind_request(
        batch_value,
        applicable,
        projections(vec![], vec![]),
        vec![broken],
        None,
    );
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
    assert_eq!(lineage.source_revision, Some("rev-1".to_owned()));
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
    assert_eq!(assessment.validate(), Err(QualityError::VersionMismatch));
}

#[test]
fn tampered_denominator_total_is_rejected() {
    let batch_value = batch(vec![record("mem-1")]);
    let candidate = request(batch_value, &[], &[], vec![]);
    let mut assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.counter_metrics.denominator_total = 99;
    assert!(assessment.validate().is_err());
}

#[test]
fn invented_or_unordered_rules_are_rejected() {
    let batch_value = batch(vec![record("mem-1"), record("mem-2")]);
    let candidate = request(
        batch_value,
        &[
            ("mem-1", ExclusionReason::Stale),
            ("mem-2", ExclusionReason::Rejected),
        ],
        &[],
        vec![],
    );
    let assessment = assess_quality(&candidate).expect("quality assessment");
    // Constructor emits sorted closed rules: REJECTED then STALE.
    assert_eq!(
        assessment.counter_metrics.excluded_by_rule[0].rule,
        "REJECTED"
    );
    let mut invented = assessment.clone();
    invented.counter_metrics.excluded_by_rule[0].rule = "VIBES".to_owned();
    assert!(invented.validate().is_err());
    let mut unordered = assessment.clone();
    unordered.counter_metrics.excluded_by_rule.reverse();
    assert!(unordered.validate().is_err());
    let mut dropped = assessment;
    dropped.counter_metrics.excluded_by_rule.pop();
    assert!(dropped.validate().is_err());
}

#[test]
fn dropped_freshness_rationale_is_rejected() {
    let mut stale = record("mem-1");
    stale.freshness.state = FreshnessState::Stale;
    let batch_value = batch(vec![stale]);
    let candidate = request(
        batch_value,
        &[("mem-1", ExclusionReason::Stale)],
        &[],
        vec![],
    );
    let mut assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.maintenance[0].rationale = None;
    assert!(assessment.validate().is_err());
}

#[test]
fn tampered_receipt_digest_is_rejected() {
    let batch_value = batch(vec![record("mem-1")]);
    let candidate = request(batch_value, &[], &[], vec![]);
    let mut assessment = assess_quality(&candidate).expect("quality assessment");
    assessment.receipts[0].canonical_digest = "not-a-digest".to_owned();
    assert!(assessment.validate().is_err());
}
