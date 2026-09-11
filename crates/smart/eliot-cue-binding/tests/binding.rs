//! Focused A-12 shape and bounded-page proofs.
#![allow(clippy::expect_used)]
use eliot_change_monitor::{
    Attribution, ChangeKind, ChangeObservation, ChangeOrigin, ObservedChangeRecord,
    ResourceSnapshot,
};
use eliot_contracts::{
    AuthorityEpoch, ClockReading, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_cue_binding::{BindingProfile, BindingRule, ColdBinding, ColdReason, ResourceField};
use eliot_cue_contracts::{
    BindingDisposition, BindingRole, CONTRACT_REVISION, CueContext, CueKind, Digest,
    NormalizationProfile, ObservedCue, ObservedCueId, PrivacyClass, SourceHandle, TargetHandle,
    WorkScopeId,
};
use eliot_cue_normalizer::{NormalizationPolicy, NormalizationRule, PolicyRule, capture_cue};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_observation::{
    CaptureRoute, CoverageDisposition, CoverageEvidence, Durability, ObservationEventCore,
    ObservationEventIdentity, ObservationJournal, ObservationKind, ObservationRecordEnvelope,
    ObservationRecordKind, ObservationScope, ObservationSubmission, ProducerTrace,
    TaskSelectionEvidence,
};
use eliot_observation_contracts::PrivacyRetentionDisclosure;

#[test]
fn cold_identity_retains_reason_without_admission_claim() {
    let value = ColdBinding {
        target: eliot_cue_contracts::TargetHandle::new("src/lib.rs").expect("target"),
        revision: Some("r1".into()),
        observed_cue_id: "cue-1".into(),
        change_id: "change-1".into(),
        reason: ColdReason::MissingEvidence,
    };
    let encoded = serde_json::to_vec(&value).expect("encode");
    let decoded: ColdBinding = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded, value);
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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
fn cue_context(index: usize, state: &StateFence) -> CueContext {
    let p = provenance(index);
    CueContext::new(
        TaskId::new("task-1").expect("task"),
        WorkScopeId::new("scope").expect("scope"),
        state.clone(),
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            provenance: p,
            verification: None,
            state_fence: state.clone(),
        },
        LifecycleState::Active,
        PrivacyClass::Public,
        eliot_cue_contracts::ProofCeiling::Observation,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture retains the full admitted receipt and A-11 row"
)]
fn admitted_rows(
    count: usize,
    shared_target: bool,
) -> (
    eliot_observation::ObservationAdmissionReceipt,
    Vec<eliot_cue_binding::TouchedResourceProjection>,
    BindingProfile,
) {
    let state = fence();
    let a11_profile = NormalizationProfile::new("a11-profile".into(), 1, seeded(2));
    let policy = NormalizationPolicy::sealed(
        "owner".into(),
        "policy".into(),
        1,
        a11_profile,
        WorkScopeId::new("scope").expect("scope"),
        state.clone(),
        vec![PolicyRule {
            kind: CueKind::FilePath,
            rule: NormalizationRule::Preserve,
        }],
    )
    .expect("policy");
    let a11_profile = policy.profile.clone();
    let mut handles = Vec::new();
    let mut rows = Vec::new();
    for index in 0..count {
        let raw = format!("raw-{index}");
        handles.push(raw.clone());
        let value = if shared_target {
            "src/shared.rs".to_owned()
        } else {
            format!("src/file-{index}.rs")
        };
        let target = TargetHandle::new(value.clone()).expect("target");
        let content_digest = seeded(u8::try_from(index).expect("fixture index").wrapping_add(1));
        let observed = ObservedCue::new(
            CONTRACT_REVISION.into(),
            ObservedCueId::new(format!("cue-{index}")).expect("cue"),
            CueKind::FilePath,
            value.clone(),
            SourceHandle::new(target.clone(), content_digest.clone(), provenance(index)),
            cue_context(index, &state),
        );
        let normalization = capture_cue(&observed, &policy, &a11_profile).expect("normalize");
        let change = ChangeObservation {
            change_id: format!("change-{index}"),
            state_fence: state.clone(),
            kind: ChangeKind::Modified,
            before: Some(ResourceSnapshot {
                resource_ref: value.clone(),
                revision: format!("old-{index}"),
                path: Some(value.clone()),
                symbol: None,
                content_digest: Some(seeded(9).as_str().into()),
                structural_digest: None,
            }),
            after: Some(ResourceSnapshot {
                resource_ref: value.clone(),
                revision: format!("rev-{index}"),
                path: Some(value),
                symbol: None,
                content_digest: Some(content_digest.as_str().into()),
                structural_digest: None,
            }),
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
        rows.push(eliot_cue_binding::TouchedResourceProjection {
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
            work_scope: WorkScopeId::new("scope").expect("scope"),
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
            observed_count: count as u64,
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
        capture_route: CaptureRoute::CanonicalJournal,
        durability: Durability::Durable,
        plan: None,
        task_selection: Some(TaskSelectionEvidence {
            task_ref: "task-1".into(),
            task_revision: 1,
            acceptance_digest: "ab".repeat(32),
            work_scope_ref: "scope".into(),
            selection_source_ref: "selection".into(),
            evidence_ref: "selection-evidence".into(),
            contamination_flags: Vec::new(),
        }),
        evidence: None,
    };
    let mut journal = ObservationJournal::default();
    let eliot_observation::ObservationAdmissionResult::Accepted { receipt } =
        journal.admit(submission).expect("admit")
    else {
        panic!("accepted fixture")
    };
    let binding_profile = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("scope").expect("scope"),
        state,
        vec![BindingRule {
            cue_kind: CueKind::FilePath,
            change_kind: ChangeKind::Modified,
            role: BindingRole::Touched,
            resource_field: ResourceField::Path,
            rule_ref: "modified-file-path".into(),
        }],
        a11_profile,
    )
    .expect("binding profile");
    (receipt, rows, binding_profile)
}

#[test]
fn derives_two_touched_targets_and_is_permutation_stable() {
    let (receipt, rows, profile) = admitted_rows(2, false);
    let first = eliot_cue_binding::derive_cue_binding_candidates(&receipt, &rows, None, &profile)
        .expect("derive");
    let mut reversed = rows.clone();
    reversed.reverse();
    let second =
        eliot_cue_binding::derive_cue_binding_candidates(&receipt, &reversed, None, &profile)
            .expect("derive");
    assert_eq!(first.candidates, second.candidates);
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(first.candidates.len(), 2);
    assert!(
        first
            .candidates
            .iter()
            .all(
                |candidate| candidate.disposition == BindingDisposition::Withheld
                    && candidate.freshness == EvidenceFreshness::ExactCandidate
            )
    );
}

#[test]
fn overflow_retains_omitted_identity_and_continuation() {
    let (receipt, rows, profile) = admitted_rows(13, true);
    let result = eliot_cue_binding::derive_cue_binding_candidates(&receipt, &rows, None, &profile)
        .expect("derive");
    assert_eq!(result.candidates.len(), 12);
    assert_eq!(result.omitted.len(), 1);
    let omitted = &result.omitted[0];
    assert_eq!(omitted.target.as_str(), "src/shared.rs");
    let omitted_index = rows
        .iter()
        .position(|row| {
            row.change
                .observation
                .after
                .as_ref()
                .is_some_and(|after| Some(after.revision.clone()) == omitted.revision)
        })
        .expect("omitted revision belongs to a supplied row");
    let one = eliot_cue_binding::derive_cue_binding_candidates(
        &receipt,
        &rows[omitted_index..=omitted_index],
        None,
        &profile,
    )
    .expect("derive omitted row");
    assert_eq!(
        omitted.candidate_digest,
        Some(one.candidates[0].digest.clone())
    );
    assert!(result.continuation_digest.is_some());
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::PartialOverflow
    );
}

#[test]
fn foreign_origin_link_is_retained_as_cold() {
    let (receipt, mut rows, profile) = admitted_rows(2, false);
    rows[0].change.observation.origin_ref = Some("foreign-handle".into());
    let result = eliot_cue_binding::derive_cue_binding_candidates(&receipt, &rows, None, &profile)
        .expect("derive");
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.cold.len(), 1);
    assert_eq!(result.cold[0].reason, ColdReason::MissingEvidence);
    assert_eq!(
        result.outcome,
        eliot_cue_binding::BindingOutcome::CandidatesForSuppliedInputs
    );
}
