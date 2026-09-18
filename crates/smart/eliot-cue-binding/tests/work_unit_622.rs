//! WORK UNIT 622 acceptance proof: cold-safe cue-binding candidate derivation.
//!
//! 41 substantive cases, one per test, over
//! the public [`eliot_cue_binding::derive_cue_binding_candidates`] operation.
//! The seven prototype tests in `tests/binding.rs` are untouched precursors.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use eliot_change_monitor::{
    Attribution, ChangeKind, ChangeObservation, ChangeOrigin, ObservedChangeRecord,
    ResourceSnapshot,
};
use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_cue_binding::{
    BindingProfile, BindingRule, ColdReason, ResourceField, TouchedResourceProjection,
};
use eliot_cue_contracts::{
    BindingDisposition, BindingRole, CONTRACT_REVISION, CueContext, CueKind, Digest,
    NormalizationProfile, ObservedCue, ObservedCueId, PrivacyClass, ProofCeiling, SourceHandle,
    TargetHandle, WorkScopeId,
};
use eliot_cue_normalizer::{NormalizationPolicy, NormalizationRule, PolicyRule, capture_cue};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_observation::{
    CandidateDisposition, CaptureRoute, CoverageDisposition, CoverageEvidence, Durability,
    ObservationAdmissionResult, ObservationEventCore, ObservationEventIdentity, ObservationJournal,
    ObservationKind, ObservationRecordEnvelope, ObservationRecordKind, ObservationScope,
    ObservationSubmission, ProducerTrace, TaskSelectionEvidence,
};
use eliot_observation_contracts::PrivacyRetentionDisclosure;

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(), ResourceGeneration::genesis())
}

fn seeded(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("digest")
}

fn provenance(index: usize) -> Provenance {
    Provenance {
        source_id: SourceId::new(format!("source-{index}")).expect("source"),
        capture_route: "test".into(),
        scope: "scope".into(),
        raw_handle: Some(format!("raw-{index}")),
        revision: Some(format!("rev-{index}")),
    }
}

fn cue_context(
    index: usize,
    state: &StateFence,
    task: &str,
    status: EpistemicStatus,
    lifecycle: LifecycleState,
) -> CueContext {
    CueContext::new(
        TaskId::new(task).expect("task"),
        WorkScopeId::new("scope").expect("scope"),
        state.clone(),
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status,
            assertability: Assertability::NonAssertableUnverified,
            provenance: provenance(index),
            verification: None,
            state_fence: state.clone(),
        },
        lifecycle,
        PrivacyClass::Public,
        ProofCeiling::Observation,
    )
}

#[derive(Clone)]
struct RowSpec {
    cue_kind: CueKind,
    change_kind: ChangeKind,
    value: String,
    target: String,
    status: EpistemicStatus,
    lifecycle: LifecycleState,
    task: String,
    drop_after: bool,
    drop_path: bool,
}

impl RowSpec {
    fn file(index: usize) -> Self {
        let value = format!("src/file-{index}.rs");
        Self {
            cue_kind: CueKind::FilePath,
            change_kind: ChangeKind::Modified,
            target: value.clone(),
            value,
            status: EpistemicStatus::Observed,
            lifecycle: LifecycleState::Active,
            task: "task-1".to_owned(),
            drop_after: false,
            drop_path: false,
        }
    }

    fn symbol(index: usize) -> Self {
        Self {
            cue_kind: CueKind::Symbol,
            change_kind: ChangeKind::Modified,
            value: format!("symbol_{index}"),
            target: format!("symbol:symbol_{index}"),
            status: EpistemicStatus::Observed,
            lifecycle: LifecycleState::Active,
            task: "task-1".to_owned(),
            drop_after: false,
            drop_path: false,
        }
    }

    fn concept(index: usize) -> Self {
        Self {
            cue_kind: CueKind::Concept,
            change_kind: ChangeKind::Modified,
            value: format!("concept-{index}"),
            target: format!("concept:concept-{index}"),
            status: EpistemicStatus::Observed,
            lifecycle: LifecycleState::Active,
            task: "task-1".to_owned(),
            drop_after: false,
            drop_path: false,
        }
    }
}

struct Fixture {
    receipt: eliot_observation::ObservationAdmissionReceipt,
    rows: Vec<TouchedResourceProjection>,
    profile: BindingProfile,
}

fn file_rule() -> BindingRule {
    BindingRule {
        cue_kind: CueKind::FilePath,
        change_kind: ChangeKind::Modified,
        role: BindingRole::Touched,
        resource_field: ResourceField::Path,
        rule_ref: "modified-file-path".into(),
    }
}

fn symbol_rule() -> BindingRule {
    BindingRule {
        cue_kind: CueKind::Symbol,
        change_kind: ChangeKind::Modified,
        role: BindingRole::Touched,
        resource_field: ResourceField::Symbol,
        rule_ref: "modified-symbol".into(),
    }
}

#[derive(Clone, Copy)]
enum Selection {
    TaskBound,
    Quarantined,
}

#[allow(
    clippy::too_many_lines,
    reason = "one shared admitted-receipt fixture keeps 41 cases independent"
)]
fn fixture(specs: &[RowSpec], selection: Selection, rules: Option<Vec<BindingRule>>) -> Fixture {
    let state = fence();
    let scope = WorkScopeId::new("scope").expect("scope");
    let policy = NormalizationPolicy::sealed(
        "owner".into(),
        "policy".into(),
        1,
        NormalizationProfile::new("a11-profile".into(), 1, seeded(2)),
        scope.clone(),
        state.clone(),
        vec![
            PolicyRule {
                kind: CueKind::FilePath,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::Symbol,
                rule: NormalizationRule::Preserve,
            },
        ],
    )
    .expect("policy");
    let a11_profile = policy.profile.clone();
    let mut handles = Vec::new();
    let mut rows = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let raw = format!("raw-{index}");
        handles.push(raw.clone());
        let target = TargetHandle::new(spec.target.clone()).expect("target");
        let content_digest = u8::try_from(index).expect("fixture index").wrapping_add(1);
        let content_digest = seeded(content_digest);
        let observed = ObservedCue::new(
            CONTRACT_REVISION.into(),
            ObservedCueId::new(format!("cue-{index}")).expect("cue"),
            spec.cue_kind,
            spec.value.clone(),
            SourceHandle::new(target.clone(), content_digest.clone(), provenance(index)),
            cue_context(index, &state, &spec.task, spec.status, spec.lifecycle),
        );
        let normalization = capture_cue(&observed, &policy, &a11_profile).expect("normalize");
        let snapshot = |revision: String| ResourceSnapshot {
            resource_ref: spec.target.clone(),
            revision,
            path: if spec.cue_kind == CueKind::FilePath && !spec.drop_path {
                Some(spec.value.clone())
            } else {
                None
            },
            symbol: if spec.cue_kind == CueKind::Symbol {
                Some(spec.value.clone())
            } else {
                None
            },
            content_digest: Some(content_digest.as_str().into()),
            structural_digest: None,
        };
        let change = ChangeObservation {
            change_id: format!("change-{index}"),
            state_fence: state.clone(),
            kind: spec.change_kind,
            before: Some(snapshot(format!("old-{index}"))),
            after: if spec.drop_after {
                None
            } else {
                Some(snapshot(format!("rev-{index}")))
            },
            origin: ChangeOrigin::HostEvent,
            attribution: Attribution::Exact,
            origin_ref: Some(raw),
            session_ref: None,
            action_lease_ref: None,
            operation_ref: None,
            diff_or_artifact_ref: None,
            unknown_origin: false,
            invalidations: Vec::new(),
        };
        let observation_digest = change.digest().expect("change digest");
        rows.push(TouchedResourceProjection {
            target,
            normalization,
            change: ObservedChangeRecord {
                observation: change,
                observation_digest,
            },
        });
    }
    let event = ObservationEventCore {
        event_id_and_time: ObservationEventIdentity {
            event_id: "event-1".into(),
            clock: ClockReading::default(),
        },
        producer_generation_and_trace: ProducerTrace {
            producer: "producer".into(),
            generation: "generation-1".into(),
            trace_ref: None,
        },
        kind: ObservationKind::ToolOrRoute,
        affected_scope: ObservationScope {
            work_scope: scope,
            task_ref: Some("task-1".into()),
            attempt_ref: Some("attempt-1".into()),
            module_or_route_ref: None,
        },
        observed_delta: "changed".into(),
        expected_baseline: None,
        evidence_and_raw_handles: handles,
        coverage_and_blind_intervals: CoverageEvidence {
            disposition: CoverageDisposition::Complete,
            denominator_source_ref: "denominator".into(),
            interval: None,
            blind_intervals: Vec::new(),
            observed_count: specs.len() as u64,
        },
        privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
            privacy_domain_ref: "public".into(),
            retention_policy_ref: "default".into(),
            disclosure_class: "internal".into(),
        },
        candidate_importance: 1,
        dedup_key: "event-1".into(),
    };
    let submission = ObservationSubmission {
        operation_id: "operation-1".into(),
        idempotency_key: "idem-1".into(),
        state_fence: state.clone(),
        record: ObservationRecordEnvelope {
            record_id: "record-1".into(),
            kind: ObservationRecordKind::Change,
            event: Some(event),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: None,
        },
        record_v2: None,
        capture_route: CaptureRoute::CanonicalJournal,
        durability: Durability::Durable,
        plan: None,
        task_selection: match selection {
            Selection::TaskBound => Some(TaskSelectionEvidence {
                task_ref: "task-1".into(),
                task_revision: 1,
                acceptance_digest: "ab".repeat(32),
                work_scope_ref: "scope".into(),
                selection_source_ref: "selection".into(),
                evidence_ref: "selection-evidence".into(),
                contamination_flags: Vec::new(),
            }),
            Selection::Quarantined => Some(TaskSelectionEvidence {
                task_ref: "task-1".into(),
                task_revision: 1,
                acceptance_digest: "ab".repeat(32),
                work_scope_ref: "scope".into(),
                selection_source_ref: "selection".into(),
                evidence_ref: "selection-evidence".into(),
                contamination_flags: vec!["test-contamination".into()],
            }),
        },
        evidence: None,
    };
    let mut journal = ObservationJournal::default();
    let receipt = match journal.admit(submission).expect("admit") {
        ObservationAdmissionResult::Accepted { receipt }
        | ObservationAdmissionResult::Replayed { receipt } => receipt,
        ObservationAdmissionResult::Rejected { rejection } => {
            panic!("accepted fixture, got rejection: {rejection:?}")
        }
    };
    let profile = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("scope").expect("scope"),
        state,
        rules.unwrap_or_else(|| vec![file_rule()]),
        a11_profile,
    )
    .expect("binding profile");
    Fixture {
        receipt,
        rows,
        profile,
    }
}

fn redigest(row: &mut TouchedResourceProjection) {
    row.change.observation_digest = row.change.observation.digest().expect("change digest");
}

fn derive(
    fx: &Fixture,
    rows: &[TouchedResourceProjection],
    hint: Option<&eliot_cue_binding::ExpectedReuseHint>,
) -> eliot_cue_binding::CueBindingResult {
    eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, rows, hint, &fx.profile)
        .expect("derive")
}

// WORK_UNIT_CASE: 622/1
#[test]
fn minimal_admitted_observation_derivation() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 1);
    assert!(result.cold.is_empty());
    assert!(result.omitted.is_empty());
    assert!(result.continuation_digest.is_none());
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::CandidatesForSuppliedInputs
    );
    assert_eq!(result.state_fence, fx.receipt.state_fence);
    assert_eq!(result.schema_revision, "1.0.0");
}

// WORK_UNIT_CASE: 622/2
#[test]
fn exact_schema_receipt_binding() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.admission, fx.receipt);
    assert_eq!(result.profile, fx.profile);
    assert_eq!(result.touched, fx.rows);
    assert_eq!(
        result.normalization_profile(),
        Some(&fx.profile.expected_normalization_profile)
    );
    let resealed = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("scope").expect("scope"),
        fence(),
        vec![file_rule()],
        fx.profile.expected_normalization_profile.clone(),
    )
    .expect("reseal");
    assert_eq!(resealed.profile_digest, fx.profile.profile_digest);
    assert_eq!(
        fx.receipt.candidate_disposition,
        CandidateDisposition::TaskBound
    );
}

// WORK_UNIT_CASE: 622/3
#[test]
fn wrong_task_scope_fence_attempt_rejected() {
    let mut wrong_task = RowSpec::file(0);
    wrong_task.task = "task-2".into();
    let fx = fixture(&[wrong_task], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::IdentityConflict);

    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let wrong_scope = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("other-scope").expect("scope"),
        fence(),
        vec![file_rule()],
        fx.profile.expected_normalization_profile.clone(),
    )
    .expect("seal wrong scope");
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, &fx.rows, None, &wrong_scope)
            .is_err()
    );

    let wrong_fence = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("scope").expect("scope"),
        StateFence::new(
            test_epoch(),
            ResourceGeneration::new(2).expect("generation"),
        ),
        vec![file_rule()],
        fx.profile.expected_normalization_profile.clone(),
    )
    .expect("seal wrong fence");
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, &fx.rows, None, &wrong_fence)
            .is_err()
    );

    let mut tampered = fx.receipt.clone();
    tampered
        .record
        .event
        .as_mut()
        .expect("event")
        .affected_scope
        .attempt_ref = Some("attempt-9".into());
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(&tampered, &fx.rows, None, &fx.profile)
            .is_err()
    );
}

// WORK_UNIT_CASE: 622/4
#[test]
fn unadmitted_observation_rejected() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let mut tampered = fx.receipt.clone();
    tampered.record_id = "record-9".into();
    let error =
        eliot_cue_binding::derive_cue_binding_candidates(&tampered, &fx.rows, None, &fx.profile)
            .expect_err("tampered record identity must fail");
    assert_eq!(
        error,
        eliot_cue_binding::CueBindingError::Contract { field: "admission" }
    );

    let mut blank = fx.receipt.clone();
    blank.operation_id = String::new();
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(&blank, &fx.rows, None, &fx.profile)
            .is_err()
    );

    let quarantined = fixture(&[RowSpec::file(0)], Selection::Quarantined, None);
    assert_eq!(
        quarantined.receipt.candidate_disposition,
        CandidateDisposition::Quarantined
    );
    let quarantined_result = derive(&quarantined, &quarantined.rows, None);
    assert!(quarantined_result.candidates.is_empty());
    assert_eq!(quarantined_result.cold.len(), 1);
    assert_eq!(
        quarantined_result.cold[0].reason,
        ColdReason::MissingEvidence
    );
}

// WORK_UNIT_CASE: 622/5
#[test]
fn stale_superseded_quarantined_deleted_stay_cold() {
    let mut stale = RowSpec::file(0);
    stale.status = EpistemicStatus::Stale;
    let mut superseded = RowSpec::file(1);
    superseded.status = EpistemicStatus::Superseded;
    let mut quarantined = RowSpec::file(2);
    quarantined.lifecycle = LifecycleState::Quarantined;
    let mut deleted = RowSpec::file(3);
    deleted.change_kind = ChangeKind::Deleted;
    let fx = fixture(
        &[stale, superseded, quarantined, deleted],
        Selection::TaskBound,
        None,
    );
    let result = derive(&fx, &fx.rows, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold.len(), 4);
    assert_eq!(result.outcome, eliot_cue_binding::BindingOutcome::Cold);
    let statuses: BTreeSet<String> = result
        .touched
        .iter()
        .map(|row| {
            format!(
                "{:?}",
                row.normalization
                    .normalized
                    .observed
                    .context
                    .evidence
                    .status
            )
        })
        .collect();
    assert!(statuses.contains("Stale"));
    assert!(statuses.contains("Superseded"));
    assert!(result.touched.iter().any(
        |row| row.normalization.normalized.observed.context.lifecycle
            == LifecycleState::Quarantined
    ));
    assert!(
        result
            .touched
            .iter()
            .any(|row| row.change.observation.kind == ChangeKind::Deleted)
    );
}

// WORK_UNIT_CASE: 622/6
#[test]
fn provenance_assurance_privacy_proof_preserved() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.touched[0].normalization, fx.rows[0].normalization);
    let observed = &result.touched[0].normalization.normalized.observed;
    assert_eq!(
        observed.source.provenance.raw_handle.as_deref(),
        Some("raw-0")
    );
    assert_eq!(
        observed.source.provenance.revision.as_deref(),
        Some("rev-0")
    );
    assert_eq!(observed.context.privacy, PrivacyClass::Public);
    assert_eq!(
        observed.context.evidence.assertability,
        Assertability::NonAssertableUnverified
    );
    assert_eq!(observed.context.proof_ceiling, ProofCeiling::Observation);
    assert_eq!(result.admission.task_selection, fx.receipt.task_selection);
    assert_eq!(
        result.candidates[0].freshness,
        EvidenceFreshness::ExactCandidate
    );
}

// WORK_UNIT_CASE: 622/7
#[test]
fn complete_exact_denominator_binds() {
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1), RowSpec::file(2)],
        Selection::TaskBound,
        None,
    );
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 3);
    assert!(result.cold.is_empty());
    assert!(result.omitted.is_empty());
    assert_eq!(result.touched.len(), 3);
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::CandidatesForSuppliedInputs
    );
}

// WORK_UNIT_CASE: 622/8
#[test]
fn unavailable_source_remains_cold() {
    let mut missing = RowSpec::file(0);
    missing.drop_after = true;
    let fx = fixture(&[missing], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::MissingEvidence);
    assert_eq!(result.outcome, eliot_cue_binding::BindingOutcome::Cold);
}

// WORK_UNIT_CASE: 622/9
#[test]
fn exact_structured_target_handle_binds() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates[0].target, fx.rows[0].target);
    assert_eq!(result.candidates[0].target.as_str(), "src/file-0.rs");
    assert_eq!(result.candidates[0].role, BindingRole::Touched);
}

// WORK_UNIT_CASE: 622/10
#[test]
fn outside_denominator_target_rejected() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let mut rows = fx.rows.clone();
    rows[0].target = TargetHandle::new("src/elsewhere.rs").expect("target");
    let result = derive(&fx, &rows, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::IdentityConflict);
    assert_eq!(result.cold[0].target.as_str(), "src/elsewhere.rs");
}

// WORK_UNIT_CASE: 622/11
#[test]
fn stale_revision_and_wrong_kind_target_rejected() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let mut stale_revision = fx.rows.clone();
    stale_revision[0]
        .change
        .observation
        .after
        .as_mut()
        .expect("after")
        .revision = "rev-99".into();
    redigest(&mut stale_revision[0]);
    let result = derive(&fx, &stale_revision, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold[0].reason, ColdReason::MissingEvidence);

    let mut wrong_kind = fx.rows.clone();
    wrong_kind[0].change.observation.kind = ChangeKind::Created;
    redigest(&mut wrong_kind[0]);
    let result = derive(&fx, &wrong_kind, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold[0].reason, ColdReason::MissingEvidence);

    let mut wrong_path = fx.rows.clone();
    wrong_path[0]
        .change
        .observation
        .after
        .as_mut()
        .expect("after")
        .path = Some("src/other.rs".into());
    redigest(&mut wrong_path[0]);
    let result = derive(&fx, &wrong_path, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold[0].reason, ColdReason::IdentityConflict);
}

// WORK_UNIT_CASE: 622/12
#[test]
fn proven_hint_is_evidence_only() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: "raw-0".to_owned(),
    };
    let without =
        eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, &fx.rows, None, &fx.profile)
            .expect("derive");
    let with = derive(&fx, &fx.rows, Some(&hint));
    assert_eq!(with.candidates, without.candidates);
    assert!(with.cold.is_empty());
    assert_eq!(with.hint, Some(hint));
}

// WORK_UNIT_CASE: 622/13
#[test]
fn unproved_hint_is_explicit_cold() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: "unproved-evidence-handle".to_owned(),
    };
    let result = derive(&fx, &fx.rows, Some(&hint));
    assert_eq!(result.candidates.len(), 1);
    assert!(
        result
            .cold
            .iter()
            .any(|cold| cold.reason == ColdReason::HintUnproved && cold.target == hint.target)
    );
    assert_eq!(result.hint, Some(hint));
}

// WORK_UNIT_CASE: 622/14
#[test]
fn hint_cannot_add_unsupplied_target() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: TargetHandle::new("src/ghost.rs").expect("target"),
        evidence_ref: "raw-0".to_owned(),
    };
    let result = derive(&fx, &fx.rows, Some(&hint));
    assert_eq!(result.candidates.len(), 1);
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.target.as_str() != "src/ghost.rs")
    );
    assert!(
        result
            .cold
            .iter()
            .any(|cold| cold.reason == ColdReason::HintUnproved
                && cold.target.as_str() == "src/ghost.rs")
    );
}

// WORK_UNIT_CASE: 622/15
#[test]
fn hint_cannot_create_relation_or_widen_scope() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: "raw-0".to_owned(),
    };
    let result = derive(&fx, &fx.rows, Some(&hint));
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.role == BindingRole::Touched)
    );
    assert_eq!(
        result.profile.scope_id.as_str(),
        fx.receipt
            .record
            .event
            .as_ref()
            .expect("event")
            .affected_scope
            .work_scope
            .as_str()
    );
    assert_eq!(result.state_fence, fx.receipt.state_fence);
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::CandidatesForSuppliedInputs
    );
}

// WORK_UNIT_CASE: 622/16
#[test]
fn valid_relation_target_profile_rule_binds() {
    let fx = fixture(
        &[RowSpec::symbol(0)],
        Selection::TaskBound,
        Some(vec![symbol_rule()]),
    );
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.candidates[0].role, BindingRole::Touched);
    assert_eq!(result.candidates[0].target.as_str(), "symbol:symbol_0");
    assert_eq!(result.candidates[0].canonical.canonical_value, "symbol_0");
}

// WORK_UNIT_CASE: 622/17
#[test]
fn unknown_relation_or_profile_rejected() {
    let fx = fixture(&[RowSpec::concept(0)], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::UnsupportedKind);

    let bad_rule = BindingRule {
        cue_kind: CueKind::Concept,
        change_kind: ChangeKind::Modified,
        role: BindingRole::Touched,
        resource_field: ResourceField::Path,
        rule_ref: "concept-path".into(),
    };
    let bad_profile = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("scope").expect("scope"),
        fence(),
        vec![bad_rule],
        fx.profile.expected_normalization_profile.clone(),
    )
    .expect("seal defers kind validation to derive");
    let error =
        eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, &fx.rows, None, &bad_profile)
            .expect_err("concept/path rule must fail");
    assert_eq!(
        error,
        eliot_cue_binding::CueBindingError::UnsupportedKind {
            field: "profile.rule"
        }
    );
}

// WORK_UNIT_CASE: 622/18
#[test]
fn missing_rule_evidence_yields_cold() {
    let mut no_path = RowSpec::file(0);
    no_path.drop_path = true;
    let fx = fixture(&[no_path], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::MissingEvidence);
    assert_eq!(result.outcome, eliot_cue_binding::BindingOutcome::Cold);
}

// WORK_UNIT_CASE: 622/19
#[test]
fn equal_keys_never_merge_identities() {
    let first = RowSpec {
        value: "src/dup.rs".to_owned(),
        target: "src/dup.rs".to_owned(),
        ..RowSpec::file(0)
    };
    let second = RowSpec {
        value: "src/dup.rs".to_owned(),
        target: "src/dup.rs".to_owned(),
        ..RowSpec::file(1)
    };
    let fx = fixture(&[first, second], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 2);
    assert_ne!(result.candidates[0].digest, result.candidates[1].digest);
    assert_eq!(
        result.candidates[0].target, result.candidates[1].target,
        "same handle, still two separate candidates"
    );
}

// WORK_UNIT_CASE: 622/20
#[test]
fn candidate_identity_and_lineage_exact() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    let candidate = &result.candidates[0];
    assert_eq!(
        candidate.binding_candidate_id.as_str(),
        format!("a12:{}", candidate.digest.as_str())
    );
    assert_eq!(candidate.target.as_str(), "src/file-0.rs");
    assert_eq!(candidate.canonical.canonical_value, "src/file-0.rs");
    assert_eq!(candidate.role, BindingRole::Touched);
    assert_eq!(candidate.disposition, BindingDisposition::Withheld);
    let replay = derive(&fx, &fx.rows, None);
    assert_eq!(replay.candidates[0].digest, candidate.digest);
    assert_eq!(replay.result_digest, result.result_digest);
}

// WORK_UNIT_CASE: 622/21
#[test]
fn same_id_changed_evidence_conflicts() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let duplicated = vec![fx.rows[0].clone(), fx.rows[0].clone()];
    let error = eliot_cue_binding::derive_cue_binding_candidates(
        &fx.receipt,
        &duplicated,
        None,
        &fx.profile,
    )
    .expect_err("duplicate projection must fail");
    assert_eq!(
        error,
        eliot_cue_binding::CueBindingError::IdentityConflict {
            field: "touched.projection"
        }
    );

    let mut second = RowSpec::file(1);
    second.value = "src/file-0.rs".to_owned();
    second.target = "src/file-0.rs".to_owned();
    let fx2 = fixture(&[RowSpec::file(0), second], Selection::TaskBound, None);
    let mut clash = fx2.rows;
    clash[1].change.observation.change_id = "change-0".into();
    redigest(&mut clash[1]);
    let error =
        eliot_cue_binding::derive_cue_binding_candidates(&fx2.receipt, &clash, None, &fx2.profile)
            .expect_err("same change id with a different digest must fail");
    assert_eq!(
        error,
        eliot_cue_binding::CueBindingError::IdentityConflict {
            field: "change.observation_digest"
        }
    );
}

// WORK_UNIT_CASE: 622/22
#[test]
fn observation_target_profile_fence_change_invalidates() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let base = derive(&fx, &fx.rows, None);

    let bumped = BindingProfile::sealed(
        "a12-profile".into(),
        2,
        WorkScopeId::new("scope").expect("scope"),
        fence(),
        vec![file_rule()],
        fx.profile.expected_normalization_profile.clone(),
    )
    .expect("reseal");
    let evolved =
        eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, &fx.rows, None, &bumped)
            .expect("derive");
    assert_ne!(evolved.profile.profile_digest, base.profile.profile_digest);
    assert_ne!(evolved.result_digest, base.result_digest);

    let mut retargeted = fx.rows.clone();
    retargeted[0].target = TargetHandle::new("src/moved.rs").expect("target");
    let moved = derive(&fx, &retargeted, None);
    assert_ne!(moved.result_digest, base.result_digest);
    assert!(moved.candidates.is_empty());
}

// WORK_UNIT_CASE: 622/23
#[test]
fn multiple_valid_targets_stay_separate() {
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1)],
        Selection::TaskBound,
        None,
    );
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 2);
    let targets: BTreeSet<&str> = result
        .candidates
        .iter()
        .map(|candidate| candidate.target.as_str())
        .collect();
    assert_eq!(targets.len(), 2);
    assert!(targets.contains("src/file-0.rs"));
    assert!(targets.contains("src/file-1.rs"));
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.disposition == BindingDisposition::Withheld)
    );
}

// WORK_UNIT_CASE: 622/24
#[test]
fn counterevidence_stays_visible_next_to_candidates() {
    let mut contested = RowSpec::file(1);
    contested.status = EpistemicStatus::Contested;
    let fx = fixture(&[RowSpec::file(0), contested], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::MissingEvidence);
    assert_eq!(result.cold[0].change_id, "change-1");
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::CandidatesForSuppliedInputs
    );
}

// WORK_UNIT_CASE: 622/25
#[test]
fn order_recency_or_count_cannot_choose_winner() {
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1), RowSpec::file(2)],
        Selection::TaskBound,
        None,
    );
    let forward = derive(&fx, &fx.rows, None);
    let mut reversed = fx.rows.clone();
    reversed.reverse();
    let backward = derive(&fx, &reversed, None);
    assert_eq!(forward.candidates, backward.candidates);
    assert_eq!(forward.result_digest, backward.result_digest);
    assert_eq!(forward.outcome, backward.outcome);
    assert_eq!(forward.candidates.len(), 3);
}

// WORK_UNIT_CASE: 622/26
#[test]
fn no_safe_rule_yields_cold_with_missing_evidence() {
    let fx = fixture(
        &[RowSpec::file(0)],
        Selection::TaskBound,
        Some(vec![symbol_rule()]),
    );
    let result = derive(&fx, &fx.rows, None);
    assert!(result.candidates.is_empty());
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::MissingEvidence);
    assert_eq!(result.outcome, eliot_cue_binding::BindingOutcome::Cold);
}

// WORK_UNIT_CASE: 622/27
#[test]
fn known_empty_needs_complete_authoritative_denominator() {
    let fx = fixture(&[], Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert!(result.candidates.is_empty());
    assert!(result.cold.is_empty());
    assert!(result.omitted.is_empty());
    assert_eq!(result.outcome, eliot_cue_binding::BindingOutcome::Cold);
}

// WORK_UNIT_CASE: 622/28
#[allow(
    clippy::too_many_lines,
    reason = "bounds battery asserts each independent bound plus its one-over"
)]
#[test]
fn every_independent_bound_and_one_over() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let boundary = "r".repeat(8192);
    let exact = BindingRule {
        rule_ref: boundary,
        ..file_rule()
    };
    assert!(
        BindingProfile::sealed(
            "a12-profile".into(),
            1,
            WorkScopeId::new("scope").expect("scope"),
            fence(),
            vec![exact],
            fx.profile.expected_normalization_profile.clone(),
        )
        .is_ok()
    );
    let over = BindingRule {
        rule_ref: "r".repeat(8193),
        ..file_rule()
    };
    assert!(
        BindingProfile::sealed(
            "a12-profile".into(),
            1,
            WorkScopeId::new("scope").expect("scope"),
            fence(),
            vec![over],
            fx.profile.expected_normalization_profile.clone(),
        )
        .is_err()
    );
    assert!(
        BindingProfile::sealed(
            "a12-profile".into(),
            1,
            WorkScopeId::new("scope").expect("scope"),
            fence(),
            Vec::new(),
            fx.profile.expected_normalization_profile.clone(),
        )
        .is_err()
    );
    assert!(
        BindingProfile::sealed(
            "a12-profile".into(),
            1,
            WorkScopeId::new("scope").expect("scope"),
            fence(),
            vec![file_rule(); 33],
            fx.profile.expected_normalization_profile.clone(),
        )
        .is_err()
    );
    assert!(
        BindingProfile::sealed(
            String::new(),
            1,
            WorkScopeId::new("scope").expect("scope"),
            fence(),
            vec![file_rule()],
            fx.profile.expected_normalization_profile.clone(),
        )
        .is_err()
    );

    let duplicated_rules = vec![file_rule(), file_rule()];
    let conflicted = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("scope").expect("scope"),
        fence(),
        duplicated_rules,
        fx.profile.expected_normalization_profile.clone(),
    )
    .expect("seal defers duplicate detection to derive");
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, &fx.rows, None, &conflicted)
            .is_err()
    );

    let empty_hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: String::new(),
    };
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(
            &fx.receipt,
            &fx.rows,
            Some(&empty_hint),
            &fx.profile
        )
        .is_err()
    );

    let full: Vec<RowSpec> = (0..12).map(RowSpec::file).collect();
    let fx_full = fixture(&full, Selection::TaskBound, None);
    let complete = derive(&fx_full, &fx_full.rows, None);
    assert_eq!(complete.candidates.len(), 12);
    assert!(complete.omitted.is_empty());
    assert_eq!(
        complete.outcome,
        eliot_cue_binding::BindingOutcome::CandidatesForSuppliedInputs
    );
    let over_full: Vec<RowSpec> = (0..13).map(RowSpec::file).collect();
    let fx_over = fixture(&over_full, Selection::TaskBound, None);
    let overflow = derive(&fx_over, &fx_over.rows, None);
    assert_eq!(overflow.candidates.len(), 12);
    assert_eq!(overflow.omitted.len(), 1);
}

// WORK_UNIT_CASE: 622/29
#[test]
fn continuation_preserves_exact_omitted_denominator() {
    let shared: Vec<RowSpec> = (0..13)
        .map(|index| RowSpec {
            value: "src/shared.rs".to_owned(),
            target: "src/shared.rs".to_owned(),
            ..RowSpec::file(index)
        })
        .collect();
    let fx = fixture(&shared, Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 12);
    assert_eq!(result.omitted.len(), 1);
    let omitted = &result.omitted[0];
    assert_eq!(omitted.target.as_str(), "src/shared.rs");
    assert!(omitted.revision.is_some());
    assert!(omitted.candidate_digest.is_some());
    assert!(result.continuation_digest.is_some());
    let position = fx
        .rows
        .iter()
        .position(|row| {
            row.change
                .observation
                .after
                .as_ref()
                .is_some_and(|after| Some(after.revision.clone()) == omitted.revision)
        })
        .expect("omitted revision belongs to the supplied denominator");
    let single = derive(&fx, &fx.rows[position..=position], None);
    assert_eq!(
        omitted.candidate_digest,
        Some(single.candidates[0].digest.clone())
    );
}

// WORK_UNIT_CASE: 622/30
#[test]
fn bound_hit_cannot_return_complete() {
    let specs: Vec<RowSpec> = (0..13).map(RowSpec::file).collect();
    let fx = fixture(&specs, Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert!(!result.omitted.is_empty());
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::PartialOverflow
    );
    assert_ne!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::CandidatesForSuppliedInputs
    );
}

// WORK_UNIT_CASE: 622/31
#[test]
fn ambiguity_and_counterevidence_survive_bounds() {
    let mut specs: Vec<RowSpec> = (0..14)
        .map(|index| RowSpec {
            value: "src/shared.rs".to_owned(),
            target: "src/shared.rs".to_owned(),
            ..RowSpec::file(index)
        })
        .collect();
    specs[0].status = EpistemicStatus::Contested;
    let fx = fixture(&specs, Selection::TaskBound, None);
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[1].target.clone(),
        evidence_ref: "unproved-evidence-handle".to_owned(),
    };
    let result = derive(&fx, &fx.rows, Some(&hint));
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::PartialOverflow
    );
    assert!(
        result
            .cold
            .iter()
            .any(|cold| !cold.change_id.is_empty() && cold.reason == ColdReason::MissingEvidence),
        "contested row disposition must survive the page bound"
    );
    assert!(
        result
            .cold
            .iter()
            .any(|cold| cold.change_id.is_empty() && cold.reason == ColdReason::HintUnproved),
        "hint conflict must survive the page bound"
    );
}

// WORK_UNIT_CASE: 622/32
#[test]
fn one_disposition_per_possibility() {
    let mut contested = RowSpec::file(2);
    contested.status = EpistemicStatus::Contested;
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1), contested],
        Selection::TaskBound,
        None,
    );
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: "unproved-evidence-handle".to_owned(),
    };
    let result = derive(&fx, &fx.rows, Some(&hint));
    let touched_cold = result
        .cold
        .iter()
        .filter(|cold| !cold.change_id.is_empty())
        .count();
    let hint_cold = result
        .cold
        .iter()
        .filter(|cold| cold.change_id.is_empty())
        .count();
    assert_eq!(result.candidates.len(), 2);
    assert_eq!(touched_cold, 1);
    assert_eq!(hint_cold, 1);
    assert_eq!(result.candidates.len() + touched_cold, fx.rows.len());
    assert_eq!(result.cold.len(), touched_cold + hint_cold);
}

// WORK_UNIT_CASE: 622/33
#[test]
fn canonical_set_order_invariance() {
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1), RowSpec::file(2)],
        Selection::TaskBound,
        None,
    );
    let base = derive(&fx, &fx.rows, None);
    let mut rotated = fx.rows.clone();
    rotated.rotate_left(1);
    let mut reversed = fx.rows.clone();
    reversed.reverse();
    for permutation in [rotated, reversed] {
        let replay = derive(&fx, &permutation, None);
        assert_eq!(replay.candidates, base.candidates);
        assert_eq!(replay.result_digest, base.result_digest);
    }
    let mut sorted = base.candidates.clone();
    sorted.sort_by(|a, b| {
        a.target
            .as_str()
            .cmp(b.target.as_str())
            .then_with(|| a.digest.as_str().cmp(b.digest.as_str()))
    });
    assert_eq!(base.candidates, sorted);
}

// WORK_UNIT_CASE: 622/34
#[test]
fn semantic_profile_order_preserved() {
    let dir_rule = BindingRule {
        cue_kind: CueKind::DirPath,
        change_kind: ChangeKind::Created,
        role: BindingRole::Touched,
        resource_field: ResourceField::Path,
        rule_ref: "created-dir-path".into(),
    };
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::symbol(1)],
        Selection::TaskBound,
        Some(vec![file_rule(), symbol_rule(), dir_rule]),
    );
    let result = derive(&fx, &fx.rows, None);
    let order: Vec<&str> = result
        .profile
        .rules
        .iter()
        .map(|rule| rule.rule_ref.as_str())
        .collect();
    assert_eq!(
        order,
        vec!["modified-file-path", "modified-symbol", "created-dir-path"]
    );
    assert_eq!(result.candidates.len(), 2);
}

// WORK_UNIT_CASE: 622/35
#[test]
fn exact_replay_and_changed_same_id_conflict() {
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1)],
        Selection::TaskBound,
        None,
    );
    let first = derive(&fx, &fx.rows, None);
    let second = derive(&fx, &fx.rows, None);
    assert_eq!(first, second);

    let mut conflict = fx.rows.clone();
    conflict[1] = fx.rows[0].clone();
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(&fx.receipt, &conflict, None, &fx.profile)
            .is_err()
    );
}

// WORK_UNIT_CASE: 622/36
#[test]
fn unknown_field_variant_or_default_rejected() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let mut json = serde_json::to_value(&fx.profile).expect("encode");
    json.as_object_mut()
        .expect("object")
        .insert("unknown_future_field".into(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<BindingProfile>(json).is_err());
    assert!(serde_json::from_str::<ColdReason>("\"bogus_variant\"").is_err());
    assert!(TargetHandle::new(String::new()).is_err());
    assert!(Digest::new("not-a-digest").is_err());

    let mut row_json = serde_json::to_value(&fx.rows[0]).expect("encode");
    row_json.as_object_mut().expect("object").remove("target");
    assert!(serde_json::from_value::<TouchedResourceProjection>(row_json).is_err());
}

// WORK_UNIT_CASE: 622/37
#[test]
fn malformed_input_panics_never_and_stays_bounded() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let mut blank_operation = fx.receipt.clone();
    blank_operation.operation_id = String::new();
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(
            &blank_operation,
            &fx.rows,
            None,
            &fx.profile
        )
        .is_err()
    );

    let mut blank_change = fx.rows.clone();
    blank_change[0].change.observation.change_id = String::new();
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(
            &fx.receipt,
            &blank_change,
            None,
            &fx.profile
        )
        .is_err()
    );

    let blank_hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: String::new(),
    };
    assert!(
        eliot_cue_binding::derive_cue_binding_candidates(
            &fx.receipt,
            &fx.rows,
            Some(&blank_hint),
            &fx.profile
        )
        .is_err()
    );

    assert!(
        BindingProfile::sealed(
            "a12-profile".into(),
            1,
            WorkScopeId::new("scope").expect("scope"),
            fence(),
            vec![BindingRule {
                rule_ref: "bad\x00ref".into(),
                ..file_rule()
            }],
            fx.profile.expected_normalization_profile.clone(),
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 622/38
#[test]
fn output_excludes_effect_and_finish_claims() {
    fn collect_keys(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, nested) in map {
                    out.push(key.clone());
                    collect_keys(nested, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_keys(item, out);
                }
            }
            _ => {}
        }
    }

    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1)],
        Selection::TaskBound,
        None,
    );
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: "raw-0".to_owned(),
    };
    let result = derive(&fx, &fx.rows, Some(&hint));
    let json = serde_json::to_value(&result).expect("encode");
    let mut keys = Vec::new();
    collect_keys(&json, &mut keys);
    let forbidden = [
        "admitted",
        "persisted",
        "current",
        "indexed",
        "activated",
        "delivered",
        "used",
        "support",
        "influence",
        "hard_block",
        "hard-block",
        "effect",
        "finish",
    ];
    let violations: Vec<&String> = keys
        .iter()
        .filter(|key| forbidden.iter().any(|banned| key.to_lowercase() == *banned))
        .collect();
    assert!(
        violations.is_empty(),
        "forbidden output claims present: {violations:?}"
    );
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.disposition == BindingDisposition::Withheld)
    );
}

// WORK_UNIT_CASE: 622/39
#[test]
fn derivation_is_closed_world_without_lookup() {
    let fx = fixture(
        &[RowSpec::file(0), RowSpec::file(1), RowSpec::file(2)],
        Selection::TaskBound,
        None,
    );
    let hint = eliot_cue_binding::ExpectedReuseHint {
        target: fx.rows[0].target.clone(),
        evidence_ref: "raw-0".to_owned(),
    };
    let first = derive(&fx, &fx.rows, Some(&hint));
    let second = derive(&fx, &fx.rows, Some(&hint));
    assert_eq!(first, second);

    let denominator: BTreeSet<&str> = fx.rows.iter().map(|row| row.target.as_str()).collect();
    for candidate in &first.candidates {
        assert!(denominator.contains(candidate.target.as_str()));
    }
    for cold in &first.cold {
        assert!(denominator.contains(cold.target.as_str()) || cold.target == hint.target);
    }
    for omitted in &first.omitted {
        assert!(denominator.contains(omitted.target.as_str()));
    }
}

// WORK_UNIT_CASE: 622/40
#[test]
fn derivation_writes_no_admission_or_canonical_state() {
    let fx = fixture(&[RowSpec::file(0)], Selection::TaskBound, None);
    let snapshot = fx.receipt.clone();
    let first = derive(&fx, &fx.rows, None);
    assert_eq!(fx.receipt, snapshot);
    fx.receipt.validate().expect("receipt still valid");
    let second = derive(&fx, &fx.rows, None);
    assert_eq!(first, second);
    assert_eq!(first.admission, snapshot);
}

// WORK_UNIT_CASE: 622/41
#[test]
fn every_positive_target_is_supplied_and_ceiled() {
    let specs: Vec<RowSpec> = (0..5).map(RowSpec::file).collect();
    let fx = fixture(&specs, Selection::TaskBound, None);
    let result = derive(&fx, &fx.rows, None);
    assert_eq!(result.candidates.len(), 5);
    let denominator: BTreeSet<&str> = fx.rows.iter().map(|row| row.target.as_str()).collect();
    for candidate in &result.candidates {
        assert!(denominator.contains(candidate.target.as_str()));
        assert_eq!(candidate.role, BindingRole::Touched);
        assert_eq!(candidate.disposition, BindingDisposition::Withheld);
        assert_eq!(candidate.freshness, EvidenceFreshness::ExactCandidate);
    }
    assert_eq!(result.state_fence, fx.receipt.state_fence);
    assert_eq!(
        result.profile.scope_id.as_str(),
        fx.receipt
            .record
            .event
            .as_ref()
            .expect("event")
            .affected_scope
            .work_scope
            .as_str()
    );
}
