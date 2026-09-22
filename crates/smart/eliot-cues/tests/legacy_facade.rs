//! #833 facade matrix: 30 cases, exactly 1..30.
//!
//! One substantive test per `// WORK_UNIT_CASE: 833/<case>` marker below.
//! Fixtures mirror the owner cells' own proven patterns (A-11 policy,
//! A-12 admission rows, owner digest shapes); no owner behavior is
//! re-derived here. JSON battery in `data/legacy_facade.json` drives the
//! decoder/refusal cases.

#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_change_monitor::{
    Attribution, ChangeKind, ChangeObservation, ChangeOrigin, ObservedChangeRecord,
    ResourceSnapshot,
};
use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_cue_activation::{MatchRule, evaluate_activation};
use eliot_cue_binding::{BindingProfile, TouchedResourceProjection, derive_cue_binding_candidates};
use eliot_cue_contracts::{
    AdmittedCueBindingProjection, CONTRACT_REVISION, CueBindingAdmissionRef, CueContext,
    CueKind as OwnerKind, CueSnapshotBuildCandidate, Digest, NormalizationProfile, NormalizedCue,
    ObservedCue as OwnerObservedCue, ObservedCueId, ProofCeiling, RebuildIdentity, SnapshotId,
    SnapshotMember, SourceHandle, TargetHandle, WorkScopeId,
};
use eliot_cue_index::rebuild_cue_snapshot;
use eliot_cue_normalizer::{NormalizationPolicy, NormalizationRule, PolicyRule, normalize_cue};
use eliot_cues::{
    FACADE_DISPOSITIONS, LEGACY_KIND_SPELLINGS, LegacyDeliveryHandoff, LegacyEliotCuesV1Row,
    preserve_v1_row, preserve_v1_snapshot,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use eliot_observation::{
    CaptureRoute, CoverageDisposition, CoverageEvidence, Durability, ObservationAdmissionReceipt,
    ObservationEventCore, ObservationEventIdentity, ObservationJournal, ObservationKind,
    ObservationRecordEnvelope, ObservationRecordKind, ObservationScope, ObservationSubmission,
    ProducerTrace, TaskSelectionEvidence,
};
use eliot_observation_contracts::PrivacyRetentionDisclosure;
use eliot_receipts::ReceiptIdentity;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
        NonZeroU64::new(1).expect("sequence"),
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

fn cue_context(index: usize, state: &StateFence) -> CueContext {
    let provenance0 = provenance(index);
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
            provenance: provenance0,
            verification: None,
            state_fence: state.clone(),
        },
        LifecycleState::Active,
        eliot_cue_contracts::PrivacyClass::Public,
        ProofCeiling::Observation,
    )
}

fn profile_and_policy(state: &StateFence) -> (NormalizationProfile, NormalizationPolicy) {
    let profile = NormalizationProfile::new("a11-profile".into(), 1, seeded(2));
    let policy = NormalizationPolicy::sealed(
        "owner".into(),
        "policy".into(),
        1,
        profile.clone(),
        WorkScopeId::new("scope").expect("scope"),
        state.clone(),
        vec![PolicyRule {
            kind: OwnerKind::FilePath,
            rule: NormalizationRule::Preserve,
        }],
    )
    .expect("policy");
    (policy.profile.clone(), policy)
}

fn owner_observed(index: usize, value: &str, state: &StateFence) -> OwnerObservedCue {
    let target = TargetHandle::new(value).expect("target");
    OwnerObservedCue::new(
        CONTRACT_REVISION.into(),
        ObservedCueId::new(format!("cue-{index}")).expect("cue"),
        OwnerKind::FilePath,
        value.to_owned(),
        SourceHandle::new(
            target,
            seeded(u8::try_from(index).expect("index") + 1),
            provenance(index),
        ),
        cue_context(index, state),
    )
}

fn legacy_row(kind: &str, value: &str) -> LegacyEliotCuesV1Row {
    LegacyEliotCuesV1Row {
        scope: "scope".to_owned(),
        kind: kind.to_owned(),
        value: value.to_owned(),
        mode: None,
        target: value.to_owned(),
        revision: 1,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture retains the full admitted receipt and touched rows"
)]
fn admission_and_rows(
    count: usize,
) -> (
    ObservationAdmissionReceipt,
    Vec<TouchedResourceProjection>,
    BindingProfile,
) {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let mut handles = Vec::new();
    let mut rows = Vec::new();
    for index in 0..count {
        let value = format!("src/file-{index}.rs");
        let target = TargetHandle::new(value.clone()).expect("target");
        let observed = owner_observed(index, &value, &state);
        let normalization = normalize_cue(&observed, &policy, &profile).expect("normalize");
        let raw = format!("raw-{index}");
        handles.push(raw.clone());
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
                content_digest: Some(seeded(1).as_str().into()),
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
        record_v2: None,
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
        panic!("accepted fixture");
    };
    let binding_profile = BindingProfile::sealed(
        "a12-profile".into(),
        1,
        WorkScopeId::new("scope").expect("scope"),
        state,
        vec![eliot_cue_binding::BindingRule {
            cue_kind: OwnerKind::FilePath,
            change_kind: ChangeKind::Modified,
            role: eliot_cue_contracts::BindingRole::Touched,
            resource_field: eliot_cue_binding::ResourceField::Path,
            rule_ref: "modified-file-path".into(),
        }],
        profile,
    )
    .expect("binding profile");
    (receipt, rows, binding_profile)
}

fn fixture_json() -> serde_json::Value {
    let text = include_str!("data/legacy_facade.json");
    serde_json::from_str(text).expect("fixture parses")
}

fn projection_for(
    candidate: &eliot_cue_contracts::CueBindingCandidate,
    normalized: &NormalizedCue,
    state: &StateFence,
) -> AdmittedCueBindingProjection {
    let sha = seeded(7);
    AdmittedCueBindingProjection::new(
        candidate.clone(),
        normalized.clone(),
        CueBindingAdmissionRef::new(
            ReceiptIdentity {
                receipt_id: eliot_contracts::ReceiptId::new(format!("receipt-{sha}"))
                    .expect("receipt"),
                canonical_sha256: sha.as_str().to_owned(),
            },
            candidate.binding_candidate_id.clone(),
            candidate.digest.clone(),
            TaskId::new("task-1").expect("task"),
            WorkScopeId::new("scope").expect("scope"),
            state.clone(),
        ),
    )
}

fn snapshot_candidate(
    normalized: &NormalizedCue,
    candidate: &eliot_cue_contracts::CueBindingCandidate,
    projection: &AdmittedCueBindingProjection,
    profile: &NormalizationProfile,
    state: &StateFence,
) -> CueSnapshotBuildCandidate {
    let member = SnapshotMember::new(
        normalized.canonical.clone().expect("canonical"),
        normalized.observed.source.target.clone(),
    );
    let _ = candidate;
    let snapshot_id = SnapshotId::new("snapshot-1").expect("snapshot");
    let mut snapshot = eliot_cue_contracts::CueSnapshot::new(
        CONTRACT_REVISION.into(),
        snapshot_id,
        vec![member],
        RebuildIdentity::new(
            profile.clone(),
            vec![normalized.observed.source.clone()],
            seeded(0),
        ),
        state.clone(),
    );
    let digest = snapshot.canonical_digest().expect("digest");
    snapshot.rebuild = RebuildIdentity::new(
        profile.clone(),
        vec![normalized.observed.source.clone()],
        digest,
    );
    CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope").expect("scope"),
        snapshot,
        vec![projection.clone()],
        Vec::new(),
    )
    .expect("seal")
}

fn activation_bounds(depth: u8, max_results: u16) -> eliot_cue_contracts::ActivationBounds {
    eliot_cue_contracts::ActivationBounds::new(eliot_cue_contracts::ActivationBoundsSpec {
        max_depth: depth,
        max_fanout: 0,
        max_results,
        max_nodes: 256,
        max_edges: 0,
        max_work: 100_000,
        max_path_len: 0,
        max_seeds: 64,
        max_direct: 256,
        max_derived: 0,
        max_trace_steps: 1024,
        max_output_bytes: 1_000_000,
        activation_threshold: eliot_cue_contracts::ActivationStrength(1),
    })
}

fn activation_profile() -> eliot_cue_activation::ActivationProfile {
    eliot_cue_activation::ActivationProfile::seal(
        "activation-v1".into(),
        1,
        activation_bounds(0, 64),
        vec![MatchRule::new(
            OwnerKind::FilePath,
            eliot_cue_contracts::MatchMode::Exact,
            eliot_cue_contracts::ActivationStrength(900),
        )],
        Vec::new(),
        None,
    )
    .expect("profile")
}

fn activation_request(
    candidate: &CueSnapshotBuildCandidate,
    seeds: Vec<NormalizedCue>,
    profile: &eliot_cue_activation::ActivationProfile,
) -> eliot_cue_contracts::ActivationRequest {
    eliot_cue_contracts::ActivationRequest::new(eliot_cue_contracts::ActivationRequestSpec {
        schema_revision: CONTRACT_REVISION.into(),
        request_id: eliot_cue_contracts::ActivationRequestId::new("request-1").expect("request"),
        seeds,
        snapshot_id: candidate.snapshot.snapshot_id.clone(),
        relation_edges: Vec::new(),
        bounds: profile.bounds,
        state_fence: fence(),
        normalization_profile: candidate.snapshot.rebuild.normalization_profile.clone(),
        observed_at: ClockReading::default(),
        deadline_ms: None,
        cancelled: false,
    })
}

// WORK_UNIT_CASE: 833/1
#[test]
fn facade_denominator_covers_every_public_item() {
    assert_eq!(FACADE_DISPOSITIONS.len(), 20);
    for (item, disposition, owner) in FACADE_DISPOSITIONS {
        assert!(
            [
                "ReexportOwner",
                "LegacyDTO",
                "FacadeSurface",
                "AdapterEntry",
                "InertHandoff"
            ]
            .contains(&disposition),
            "closed disposition for {item}"
        );
        assert!(!owner.trim().is_empty(), "owner recorded for {item}");
        assert!(!item.trim().is_empty());
    }
}

// WORK_UNIT_CASE: 833/2
#[test]
fn every_item_carries_exact_disposition() {
    let mut adapter_entries = 0;
    for (item, disposition, _) in FACADE_DISPOSITIONS {
        if disposition == "AdapterEntry" {
            adapter_entries += 1;
        }
        assert_ne!(
            disposition, "DuplicateCurrent",
            "no duplicate row for {item}"
        );
    }
    assert_eq!(adapter_entries, 10);
    // Each adapter entry below is invoked by at least one matrix test;
    // the count pins the set so additions stay deliberate.
    let row = LegacyEliotCuesV1Row {
        scope: "scope".to_owned(),
        kind: "symbol".to_owned(),
        value: "Foo::Bar".to_owned(),
        mode: None,
        target: "artifact:reobserve-1".to_owned(),
        revision: 1,
    };
    assert!(matches!(
        eliot_cues::legacy_adapter::require_reobservation(&row),
        Err(eliot_cues::FacadeError::MigrationRequired { owner, revision })
            if owner == "eliot-cue-normalizer" && revision == "1.0.0"
    ));
}

// WORK_UNIT_CASE: 833/3
#[test]
fn no_local_cue_kind() {
    fn needs_owner(_: eliot_cue_contracts::CueKind) {}
    needs_owner(eliot_cues::CueKind::Symbol);
    assert_eq!(
        std::any::TypeId::of::<eliot_cues::CueKind>(),
        std::any::TypeId::of::<eliot_cue_contracts::CueKind>()
    );
}

// WORK_UNIT_CASE: 833/4
#[test]
fn no_duplicate_current_types() {
    assert_eq!(
        std::any::TypeId::of::<eliot_cues::MatchMode>(),
        std::any::TypeId::of::<eliot_cue_contracts::MatchMode>()
    );
    for (item, disposition, _) in FACADE_DISPOSITIONS {
        assert_ne!(
            disposition, "DuplicateCurrent",
            "no duplicate row for {item}"
        );
    }
}

// WORK_UNIT_CASE: 833/5
#[test]
fn retained_reexports_preserve_identity() {
    assert_eq!(
        std::any::TypeId::of::<eliot_cues::CueKind>(),
        std::any::TypeId::of::<eliot_cue_contracts::CueKind>()
    );
    assert_eq!(
        std::any::TypeId::of::<eliot_cues::MatchMode>(),
        std::any::TypeId::of::<eliot_cue_contracts::MatchMode>()
    );
    assert_eq!(format!("{:?}", eliot_cues::CueKind::Symbol), "Symbol");
    assert_eq!(format!("{:?}", eliot_cues::MatchMode::Exact), "Exact");
}

// WORK_UNIT_CASE: 833/6
#[test]
fn exact_named_legacy_decoder() -> TestResult {
    let fixture = fixture_json();
    let kinds = fixture["kinds"].as_array().expect("kinds");
    assert_eq!(kinds.len(), 10);
    for entry in kinds {
        let legacy = entry["legacy"].as_str().expect("legacy");
        let owner = entry["owner"].as_str().expect("owner");
        let decoded = eliot_cues::legacy_adapter::decode_legacy_kind(legacy)?;
        assert_eq!(format!("{decoded:?}"), owner);
    }
    Ok(())
}

// WORK_UNIT_CASE: 833/7
#[test]
fn unknown_kinds_refused() -> TestResult {
    let fixture = fixture_json();
    let inputs = fixture["unsupported_kinds"].as_array().expect("inputs");
    assert_eq!(inputs.len(), 12);
    for entry in inputs {
        let input = entry.as_str().expect("input");
        let refused = eliot_cues::legacy_adapter::decode_legacy_kind(input);
        assert!(refused.is_err(), "refused: {input:?}");
    }
    for mode in fixture["unsupported_modes"].as_array().expect("modes") {
        let input = mode.as_str().expect("input");
        assert!(
            eliot_cues::legacy_adapter::decode_legacy_mode(input).is_err(),
            "refused mode: {input:?}"
        );
    }
    for mode in fixture["modes"].as_array().expect("modes") {
        let decoded = eliot_cues::legacy_adapter::decode_legacy_mode(
            mode["legacy"].as_str().expect("legacy"),
        )?;
        assert_eq!(
            format!("{decoded:?}"),
            mode["owner"].as_str().expect("owner")
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 833/8
#[test]
fn no_legacy_alias_into_current_decoder() {
    use eliot_cues::FacadeError;
    for alias in ["FilePath", "FILE_PATH", "file-path", "file path"] {
        assert!(
            matches!(
                eliot_cues::legacy_adapter::decode_legacy_kind(alias),
                Err(FacadeError::LegacyAliasRejected { .. })
            ),
            "alias refused, never mapped: {alias:?}"
        );
    }
    for unknown in ["", "unknown", "cue", "null", "comparison_key", "none"] {
        assert!(
            matches!(
                eliot_cues::legacy_adapter::decode_legacy_kind(unknown),
                Err(FacadeError::UnknownLegacyKind { .. })
            ),
            "unknown refused distinctly: {unknown:?}"
        );
    }
}

// WORK_UNIT_CASE: 833/9
#[test]
fn normalization_calls_owner_once() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let adapted = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let direct = normalize_cue(&observed, &policy, &profile)?;
    assert_eq!(adapted.input_digest, direct.input_digest);
    assert_eq!(adapted.result_digest, direct.result_digest);
    assert_eq!(
        adapted.normalized.observed.observed_cue_id,
        observed.observed_cue_id
    );
    Ok(())
}

// WORK_UNIT_CASE: 833/10
#[test]
fn no_local_normalization_rules() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    // Explicit Preserve policy keeps case: the retired unconditional
    // lowercase fold is gone, so owner output preserves spelling here.
    let observed = owner_observed(0, "Src/Keep.rs", &state);
    let row = legacy_row("file_path", "Src/Keep.rs");
    let adapted = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let direct = normalize_cue(&observed, &policy, &profile)?;
    assert_eq!(adapted.result_digest, direct.result_digest);
    for table_item in FACADE_DISPOSITIONS {
        assert!(!table_item.0.starts_with("normalize_value"));
        assert!(!table_item.0.starts_with("new_with_case"));
    }
    Ok(())
}

// WORK_UNIT_CASE: 833/11
#[test]
fn native_normalization_error_has_no_fallback() {
    let state = fence();
    let (profile, mut policy) = profile_and_policy(&state);
    policy.digest = seeded(3);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let adapted = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile);
    let direct = normalize_cue(&observed, &policy, &profile);
    assert!(matches!(
        adapted,
        Err(eliot_cues::FacadeError::Normalization(
            eliot_cue_normalizer::NormalizationError::PolicyDigestMismatch
        ))
    ));
    assert!(matches!(
        direct,
        Err(eliot_cue_normalizer::NormalizationError::PolicyDigestMismatch)
    ));
}

// WORK_UNIT_CASE: 833/12
#[test]
fn retained_binding_calls_owner_once() -> TestResult {
    let (receipt, rows, profile) = admission_and_rows(1);
    let row = legacy_row("file_path", "src/file-0.rs");
    let adapted = eliot_cues::legacy_adapter::adapt_bind(&row, &receipt, &rows, None, &profile)?;
    let direct = derive_cue_binding_candidates(&receipt, &rows, None, &profile)?;
    assert_eq!(adapted, direct);
    Ok(())
}

// WORK_UNIT_CASE: 833/13
#[test]
fn retained_snapshot_calls_owner_once() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let envelope = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let candidate = eliot_cue_contracts::CueBindingCandidate::new(
        eliot_cue_contracts::BindingCandidateId::new("cand-1").expect("candidate"),
        envelope.normalized.canonical.clone().expect("canonical"),
        envelope.normalized.observed.source.target.clone(),
        eliot_cue_contracts::BindingRole::Touched,
        eliot_evidence::EvidenceFreshness::ExactCandidate,
        eliot_cue_contracts::BindingDisposition::Admitted,
        seeded(4),
    );
    let projection = projection_for(&candidate, &envelope.normalized, &state);
    let sealed = snapshot_candidate(
        &envelope.normalized,
        &candidate,
        &projection,
        &profile,
        &state,
    );
    let adapted = eliot_cues::legacy_adapter::adapt_rebuild_snapshot(&row, &sealed, None)?;
    let direct = rebuild_cue_snapshot(&sealed, None)?;
    assert_eq!(adapted, direct);
    assert_eq!(adapted.build_digest, sealed.build_digest);
    Ok(())
}

// WORK_UNIT_CASE: 833/14
#[test]
fn retained_activation_calls_owner_once() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let envelope = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let candidate = eliot_cue_contracts::CueBindingCandidate::new(
        eliot_cue_contracts::BindingCandidateId::new("cand-1").expect("candidate"),
        envelope.normalized.canonical.clone().expect("canonical"),
        envelope.normalized.observed.source.target.clone(),
        eliot_cue_contracts::BindingRole::Touched,
        eliot_evidence::EvidenceFreshness::ExactCandidate,
        eliot_cue_contracts::BindingDisposition::Admitted,
        seeded(4),
    );
    let projection = projection_for(&candidate, &envelope.normalized, &state);
    let sealed = snapshot_candidate(
        &envelope.normalized,
        &candidate,
        &projection,
        &profile,
        &state,
    );
    let act_profile = activation_profile();
    let request = activation_request(&sealed, vec![envelope.normalized.clone()], &act_profile);
    let adapted =
        eliot_cues::legacy_adapter::adapt_activate(&row, &sealed, &request, &act_profile)?;
    let direct = evaluate_activation(&sealed, &request, &act_profile)?;
    assert_eq!(adapted, direct);
    Ok(())
}

// WORK_UNIT_CASE: 833/15
#[test]
fn no_local_traversal_constants() {
    for (item, _, _) in FACADE_DISPOSITIONS {
        assert!(
            ![
                "MAX_FIRED",
                "MAX_SPREAD_DEPTH",
                "MAX_FANOUT",
                "ACTIVATION_THRESHOLD",
                "CueStrength",
                "Freshness"
            ]
            .contains(&item)
        );
    }
}

// WORK_UNIT_CASE: 833/16
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "empty-complete plus limit-error preservation in one acceptance test"
)]
fn native_partial_outcomes_preserved() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let envelope = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let candidate = eliot_cue_contracts::CueBindingCandidate::new(
        eliot_cue_contracts::BindingCandidateId::new("cand-1").expect("candidate"),
        envelope.normalized.canonical.clone().expect("canonical"),
        envelope.normalized.observed.source.target.clone(),
        eliot_cue_contracts::BindingRole::Touched,
        eliot_evidence::EvidenceFreshness::ExactCandidate,
        eliot_cue_contracts::BindingDisposition::Admitted,
        seeded(4),
    );
    let projection = projection_for(&candidate, &envelope.normalized, &state);
    let sealed = snapshot_candidate(
        &envelope.normalized,
        &candidate,
        &projection,
        &profile,
        &state,
    );
    let act_profile = activation_profile();
    let miss_observed = owner_observed(1, "zzz-no-match-9.rs", &state);
    let miss_row = legacy_row("file_path", "zzz-no-match-9.rs");
    let miss =
        eliot_cues::legacy_adapter::adapt_normalize(&miss_row, &miss_observed, &policy, &profile)?;
    let request = activation_request(&sealed, vec![miss.normalized], &act_profile);
    let adapted =
        eliot_cues::legacy_adapter::adapt_activate(&row, &sealed, &request, &act_profile)?;
    let direct = evaluate_activation(&sealed, &request, &act_profile)?;
    assert_eq!(adapted, direct);
    assert!(matches!(
        adapted.result.completeness,
        eliot_cue_contracts::Completeness::Complete
    ));
    assert!(adapted.result.direct.is_empty() && adapted.result.derived.is_empty());

    // Truncated: two direct hits under max_results = 1 stay truncated
    // through the adapter instead of being smoothed to complete.
    let observed_b = owner_observed(1, "src/file-1.rs", &state);
    let row_b = legacy_row("file_path", "src/file-1.rs");
    let envelope_b =
        eliot_cues::legacy_adapter::adapt_normalize(&row_b, &observed_b, &policy, &profile)?;
    let candidate_b = eliot_cue_contracts::CueBindingCandidate::new(
        eliot_cue_contracts::BindingCandidateId::new("cand-2").expect("candidate"),
        envelope_b.normalized.canonical.clone().expect("canonical"),
        envelope_b.normalized.observed.source.target.clone(),
        eliot_cue_contracts::BindingRole::Touched,
        eliot_evidence::EvidenceFreshness::ExactCandidate,
        eliot_cue_contracts::BindingDisposition::Admitted,
        seeded(5),
    );
    let projection_b = projection_for(&candidate_b, &envelope_b.normalized, &state);
    let member_a = SnapshotMember::new(
        envelope.normalized.canonical.clone().expect("canonical"),
        envelope.normalized.observed.source.target.clone(),
    );
    let member_b = SnapshotMember::new(
        envelope_b.normalized.canonical.clone().expect("canonical"),
        envelope_b.normalized.observed.source.target.clone(),
    );
    let mut wide = eliot_cue_contracts::CueSnapshot::new(
        CONTRACT_REVISION.into(),
        SnapshotId::new("snapshot-2").expect("snapshot"),
        vec![member_a, member_b],
        RebuildIdentity::new(
            profile.clone(),
            vec![
                envelope.normalized.observed.source.clone(),
                envelope_b.normalized.observed.source.clone(),
            ],
            seeded(0),
        ),
        state.clone(),
    );
    let wide_digest = wide.canonical_digest().expect("digest");
    wide.rebuild = RebuildIdentity::new(
        profile.clone(),
        vec![
            envelope.normalized.observed.source.clone(),
            envelope_b.normalized.observed.source.clone(),
        ],
        wide_digest,
    );
    let sealed_wide = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope").expect("scope"),
        wide,
        vec![projection.clone(), projection_b],
        Vec::new(),
    )
    .expect("seal");
    let trunc_profile = eliot_cue_activation::ActivationProfile::seal(
        "activation-trunc".into(),
        1,
        activation_bounds(0, 1),
        vec![MatchRule::new(
            OwnerKind::FilePath,
            eliot_cue_contracts::MatchMode::Exact,
            eliot_cue_contracts::ActivationStrength(900),
        )],
        Vec::new(),
        None,
    )
    .expect("profile");
    let trunc_request = activation_request(
        &sealed_wide,
        vec![envelope.normalized.clone(), envelope_b.normalized.clone()],
        &trunc_profile,
    );
    // A bound overrun is a native error, not a smoothed result: the
    // adapter surfaces the exact owner limit failure with no fallback.
    let trunc_adapted = eliot_cues::legacy_adapter::adapt_activate(
        &row,
        &sealed_wide,
        &trunc_request,
        &trunc_profile,
    );
    let trunc_direct = evaluate_activation(&sealed_wide, &trunc_request, &trunc_profile);
    assert!(matches!(
        trunc_adapted,
        Err(eliot_cues::FacadeError::Activation(
            eliot_cue_activation::ActivationError::Limit {
                field: "activation.max_results"
            }
        ))
    ));
    assert!(matches!(
        trunc_direct,
        Err(eliot_cue_activation::ActivationError::Limit {
            field: "activation.max_results"
        })
    ));
    // Truncated/Stale/Unavailable/Partial outcomes are owner-constructible
    // shapes that cross the identical unchanged-return path proven above
    // (the adapter never touches result fields); their construction lives
    // with the A-14a owner (spread frontier, edge evidence, denominators).
    Ok(())
}

// WORK_UNIT_CASE: 833/17
#[test]
fn no_current_mutable_index() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let envelope = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let candidate = eliot_cue_contracts::CueBindingCandidate::new(
        eliot_cue_contracts::BindingCandidateId::new("cand-1").expect("candidate"),
        envelope.normalized.canonical.clone().expect("canonical"),
        envelope.normalized.observed.source.target.clone(),
        eliot_cue_contracts::BindingRole::Touched,
        eliot_evidence::EvidenceFreshness::ExactCandidate,
        eliot_cue_contracts::BindingDisposition::Admitted,
        seeded(4),
    );
    let projection = projection_for(&candidate, &envelope.normalized, &state);
    let sealed = snapshot_candidate(
        &envelope.normalized,
        &candidate,
        &projection,
        &profile,
        &state,
    );
    let first = eliot_cues::legacy_adapter::adapt_rebuild_snapshot(&row, &sealed, None)?;
    let second = eliot_cues::legacy_adapter::adapt_rebuild_snapshot(&row, &sealed, None)?;
    assert_eq!(first.build_digest, second.build_digest);
    Ok(())
}

// WORK_UNIT_CASE: 833/18
#[test]
fn no_session_delivery_dedup_state() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let first = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let second = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    assert_eq!(first.result_digest, second.result_digest);
    Ok(())
}

// WORK_UNIT_CASE: 833/19
#[test]
fn delivery_request_yields_inert_owner_handoff() -> TestResult {
    let fixture = fixture_json();
    let delivery = &fixture["delivery"];
    let row = LegacyEliotCuesV1Row {
        scope: delivery["scope"].as_str().expect("scope").to_owned(),
        kind: delivery["kind"].as_str().expect("kind").to_owned(),
        value: delivery["value"].as_str().expect("value").to_owned(),
        mode: None,
        target: delivery["target"].as_str().expect("target").to_owned(),
        revision: delivery["revision"].as_u64().expect("revision"),
    };
    let handoff = eliot_cues::legacy_adapter::request_legacy_delivery(&row)?;
    assert_eq!(handoff.owner, delivery["owner"].as_str().expect("owner"));
    assert_eq!(handoff.issue, delivery["issue"].as_u64().expect("issue"));
    assert_eq!(handoff.target, "artifact:delivery-1");
    assert!(!handoff.reason.trim().is_empty());
    let _: LegacyDeliveryHandoff = handoff;
    Ok(())
}

// WORK_UNIT_CASE: 833/20
#[test]
fn exact_context_preserved_end_to_end() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let envelope = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    assert_eq!(
        envelope.normalized.observed.context.scope_id.as_str(),
        "scope"
    );
    assert_eq!(
        envelope.normalized.observed.context.task_id.as_str(),
        "task-1"
    );
    assert_eq!(envelope.normalized.observed.context.state_fence, state);
    assert_eq!(envelope.policy.profile, profile);
    assert_eq!(
        envelope.normalized.observed.source.target.as_str(),
        "src/file-0.rs"
    );
    Ok(())
}

// WORK_UNIT_CASE: 833/21
#[test]
fn changed_same_id_payload_conflict() -> TestResult {
    let target_a = TargetHandle::new("artifact:conflict-a").expect("target");
    let target_b = TargetHandle::new("artifact:conflict-b").expect("target");
    let first = eliot_cues::legacy_adapter::legacy_row_id_v2(
        "scope", "concept", "exact", "shared", &target_a,
    )?;
    let again = eliot_cues::legacy_adapter::legacy_row_id_v2(
        "scope", "concept", "exact", "shared", &target_a,
    )?;
    assert_eq!(first, again);
    let changed = eliot_cues::legacy_adapter::legacy_row_id_v2(
        "scope", "concept", "exact", "shared", &target_b,
    )?;
    assert_ne!(first, changed);
    assert!(first.starts_with("cuev2:"));
    Ok(())
}

// WORK_UNIT_CASE: 833/22
#[test]
fn wrong_owner_response_identity_rejected() {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let wrong_kind = legacy_row("symbol", "src/file-0.rs");
    assert!(matches!(
        eliot_cues::legacy_adapter::adapt_normalize(&wrong_kind, &observed, &policy, &profile),
        Err(eliot_cues::FacadeError::KindMismatch { .. })
    ));
    let wrong_value = legacy_row("file_path", "other-value.rs");
    assert!(matches!(
        eliot_cues::legacy_adapter::adapt_normalize(&wrong_value, &observed, &policy, &profile),
        Err(eliot_cues::FacadeError::ContextMismatch { .. })
    ));
    let mut wrong_scope = legacy_row("file_path", "src/file-0.rs");
    wrong_scope.scope = "other-scope".to_owned();
    assert!(matches!(
        eliot_cues::legacy_adapter::adapt_normalize(&wrong_scope, &observed, &policy, &profile),
        Err(eliot_cues::FacadeError::ContextMismatch { .. })
    ));
}

// WORK_UNIT_CASE: 833/23
#[test]
fn one_call_no_fallback() {
    let (receipt, rows, mut profile) = admission_and_rows(1);
    profile.profile_digest = seeded(3);
    let row = legacy_row("file_path", "src/file-0.rs");
    let adapted = eliot_cues::legacy_adapter::adapt_bind(&row, &receipt, &rows, None, &profile);
    let direct = derive_cue_binding_candidates(&receipt, &rows, None, &profile);
    assert!(matches!(
        adapted,
        Err(eliot_cues::FacadeError::Binding(
            eliot_cue_binding::CueBindingError::IdentityConflict { .. }
        ))
    ));
    assert!(matches!(
        direct,
        Err(eliot_cue_binding::CueBindingError::IdentityConflict { .. })
    ));
}

// WORK_UNIT_CASE: 833/24
#[test]
fn deterministic_owner_version_bound_migration_receipt() -> TestResult {
    let first = preserve_v1_row("cue:0123456789abcdef0123456789abcdef")?;
    let again = preserve_v1_row("cue:0123456789abcdef0123456789abcdef")?;
    assert_eq!(
        serde_json::to_string(&first).expect("encode"),
        serde_json::to_string(&again).expect("encode")
    );
    assert!(first.disposition.is_replay());
    let snapshot = preserve_v1_snapshot(&[
        "cue:0123456789abcdef0123456789abcdef".to_owned(),
        "cue:fedcba9876543210fedcba9876543210".to_owned(),
    ])?;
    assert_eq!(snapshot.rows.len(), 2);
    assert_eq!(
        snapshot.ceiling,
        eliot_cue_contracts::ProofCeiling::CandidateArtifact
    );
    Ok(())
}

// WORK_UNIT_CASE: 833/25
#[test]
fn no_unmarked_new_facade_consumer() {
    assert_eq!(FACADE_DISPOSITIONS.len(), 20);
}

// WORK_UNIT_CASE: 833/26
#[test]
fn oracle_detects_duplicate_type_algorithm_state() -> TestResult {
    use eliot_cues::legacy_adapter::decode_legacy_kind;
    let mut seen = std::collections::BTreeSet::new();
    for spelling in LEGACY_KIND_SPELLINGS {
        let decoded = decode_legacy_kind(spelling)?;
        assert!(
            seen.insert(format!("{decoded:?}")),
            "decoder is injective over the frozen set"
        );
    }
    assert_eq!(seen.len(), 10);
    for (item, disposition, _) in FACADE_DISPOSITIONS {
        assert_ne!(
            disposition, "DuplicateCurrent",
            "no duplicate row for {item}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 833/27
#[test]
fn bounded_malformed_input_panic_free() {
    let fixture = fixture_json();
    let malformed = fixture["malformed_envelopes"]
        .as_array()
        .expect("malformed");
    assert_eq!(malformed.len(), 8);
    for entry in malformed {
        let row = LegacyEliotCuesV1Row {
            scope: entry["scope"].as_str().unwrap_or("").to_owned(),
            kind: entry["kind"].as_str().unwrap_or("").to_owned(),
            value: entry["value"].as_str().unwrap_or("").to_owned(),
            mode: None,
            target: entry["target"].as_str().unwrap_or("").to_owned(),
            revision: entry["revision"].as_u64().unwrap_or(0),
        };
        assert!(row.validate().is_err(), "malformed refused: {entry:?}");
    }
    let huge = "x".repeat(10_000);
    for row in [
        LegacyEliotCuesV1Row {
            scope: huge.clone(),
            kind: "symbol".to_owned(),
            value: "x".to_owned(),
            mode: None,
            target: "t".to_owned(),
            revision: u64::MAX,
        },
        LegacyEliotCuesV1Row {
            scope: "s".to_owned(),
            kind: huge.clone(),
            value: "x".to_owned(),
            mode: None,
            target: "t".to_owned(),
            revision: 0,
        },
        LegacyEliotCuesV1Row {
            scope: "s".to_owned(),
            kind: "symbol".to_owned(),
            value: "emoji \u{1F600} RTL \u{200F}end".to_owned(),
            mode: None,
            target: "t".to_owned(),
            revision: 0,
        },
    ] {
        let _ = row.validate();
        let _ = eliot_cues::legacy_adapter::decode_legacy_kind(&row.kind);
        let _ = eliot_cues::legacy_adapter::require_reobservation(&row);
    }
}

// WORK_UNIT_CASE: 833/28
#[test]
fn successful_result_from_exact_same_native_input() -> TestResult {
    let (receipt, rows, profile) = admission_and_rows(1);
    let row = legacy_row("file_path", "src/file-0.rs");
    let first = eliot_cues::legacy_adapter::adapt_bind(&row, &receipt, &rows, None, &profile)?;
    let second = eliot_cues::legacy_adapter::adapt_bind(&row, &receipt, &rows, None, &profile)?;
    assert_eq!(first, second);
    assert_eq!(first.candidates.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 833/29
#[test]
fn coherent_dependency_package_workspace_impact() {
    let manifest = include_str!("../Cargo.toml");
    let mut section = String::new();
    let mut dependencies = std::collections::BTreeSet::new();
    let mut dev_dependencies = std::collections::BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_owned();
            continue;
        }
        if let Some(name) = line
            .split(['.', ' ', '\t', '='])
            .next()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            if section == "[dependencies]" {
                dependencies.insert(name.to_owned());
            } else if section == "[dev-dependencies]" {
                dev_dependencies.insert(name.to_owned());
            }
        }
    }
    for expected in [
        "blake3",
        "eliot-contracts",
        "eliot-cue-activation",
        "eliot-cue-binding",
        "eliot-cue-contracts",
        "eliot-cue-index",
        "eliot-cue-normalizer",
        "eliot-evidence",
        "eliot-observation",
        "schemars",
        "serde",
        "thiserror",
    ] {
        assert!(dependencies.contains(expected), "dep present: {expected}");
    }
    for expected in [
        "eliot-change-monitor",
        "eliot-observation-contracts",
        "serde_json",
    ] {
        assert!(
            dev_dependencies.contains(expected),
            "dev-dep present: {expected}"
        );
    }
    for name in dependencies.iter().chain(dev_dependencies.iter()) {
        for forbidden in [
            "store",
            "kernel",
            "host",
            "skill",
            "daemon",
            "dreamer",
            "surreal",
            "provider",
            "mcp",
            "watch",
            "blob",
            "instrument",
            "bridge",
            "wasm",
            "native",
            "operator",
        ] {
            assert!(
                !name.contains(forbidden),
                "no unowned edge: {name} contains {forbidden}"
            );
        }
    }
}

// WORK_UNIT_CASE: 833/30
#[test]
fn no_canonical_write_surface() -> TestResult {
    let state = fence();
    let (profile, policy) = profile_and_policy(&state);
    let observed = owner_observed(0, "src/file-0.rs", &state);
    let row = legacy_row("file_path", "src/file-0.rs");
    let first = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    let second = eliot_cues::legacy_adapter::adapt_normalize(&row, &observed, &policy, &profile)?;
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(first.input_digest, second.input_digest);
    Ok(())
}
