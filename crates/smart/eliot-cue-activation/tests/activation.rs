#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
    TaskId,
};
use eliot_cue_activation::{
    ActivationError, ActivationProfile, MatchRule, RelationRule, evaluate_activation,
};
use eliot_cue_contracts::PrivacyClass;
use eliot_cue_contracts::{
    ActivationBounds, ActivationBoundsSpec, ActivationRequest, ActivationRequestSpec,
    ActivationStrength, AdmittedCueBindingProjection, BindingCandidateId, BindingDisposition,
    BindingRole, CONTRACT_REVISION, CanonicalCueId, CanonicalCueIdentity, ComparisonForm,
    ComparisonKey, ComparisonKeyId, CueBindingAdmissionRef, CueBindingCandidate, CueContext,
    CueKind, CueSnapshot, CueSnapshotBuildCandidate, Digest, MatchMode, NormalizationOutcome,
    NormalizationProfile, NormalizedCue, ObservedCue, ObservedCueId, ProofCeiling, RebuildIdentity,
    RelationEdge, RelationEdgeId, SnapshotId, SnapshotMember, SourceHandle, TargetHandle,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance, RelationKind,
};
use eliot_receipts::{ReceiptIdentity, WorkScopeId};

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("digest")
}
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
fn norm_profile() -> NormalizationProfile {
    NormalizationProfile::new("norm-v1".into(), 1, digest(1))
}
fn provenance(id: &str) -> Provenance {
    Provenance {
        source_id: SourceId::new(format!("source-{id}")).unwrap(),
        capture_route: "activation-test".into(),
        scope: "scope-1".into(),
        raw_handle: None,
        revision: Some("rev-1".into()),
    }
}
fn context(id: &str) -> CueContext {
    let f = fence();
    CueContext::new(
        TaskId::new("task-1").unwrap(),
        WorkScopeId::new("scope-1").unwrap(),
        f.clone(),
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            provenance: provenance(id),
            verification: None,
            state_fence: f,
        },
        LifecycleState::Active,
        PrivacyClass::Public,
        ProofCeiling::Observation,
    )
}
fn normalized(
    kind: CueKind,
    value: &str,
    id: &str,
    target: &str,
    keys: &[(u8, &str, MatchMode, ComparisonForm)],
    seed: u8,
) -> NormalizedCue {
    let canonical = CanonicalCueIdentity::new(
        CanonicalCueId::new(format!("canonical-{id}")).unwrap(),
        kind,
        value.into(),
        digest(seed),
    );
    let observed = ObservedCue::new(
        CONTRACT_REVISION.into(),
        ObservedCueId::new(format!("observed-{id}")).unwrap(),
        kind,
        value.into(),
        SourceHandle::new(
            TargetHandle::new(target).unwrap(),
            digest(seed.wrapping_add(1)),
            provenance(id),
        ),
        context(id),
    );
    let comparison_keys = keys
        .iter()
        .map(|(key_seed, text, mode, form)| {
            ComparisonKey::new(
                ComparisonKeyId::new(format!("key-{id}-{key_seed}")).unwrap(),
                norm_profile(),
                (*text).into(),
                *mode,
                *form,
            )
        })
        .collect();
    NormalizedCue::new(
        CONTRACT_REVISION.into(),
        observed,
        norm_profile(),
        Some(canonical),
        comparison_keys,
        NormalizationOutcome::Lossless,
        Vec::new(),
    )
}
fn projection(
    cue: NormalizedCue,
    id: &str,
    target: &str,
    seed: u8,
) -> AdmittedCueBindingProjection {
    let candidate = CueBindingCandidate::new(
        BindingCandidateId::new(format!("candidate-{id}")).unwrap(),
        cue.canonical.clone().unwrap(),
        TargetHandle::new(target).unwrap(),
        BindingRole::Names,
        EvidenceFreshness::ExactCandidate,
        BindingDisposition::Withheld,
        digest(seed),
    );
    let receipt_digest = digest(seed.wrapping_add(40));
    let admission = CueBindingAdmissionRef::new(
        ReceiptIdentity {
            receipt_id: ReceiptId::new(format!("receipt-{}", receipt_digest.as_str())).unwrap(),
            canonical_sha256: receipt_digest.as_str().into(),
        },
        candidate.binding_candidate_id.clone(),
        candidate.digest.clone(),
        TaskId::new("task-1").unwrap(),
        WorkScopeId::new("scope-1").unwrap(),
        fence(),
    );
    AdmittedCueBindingProjection::new(candidate, cue, admission)
}
fn snapshot(projections: &[AdmittedCueBindingProjection]) -> CueSnapshot {
    let members = projections
        .iter()
        .map(|p| SnapshotMember::new(p.candidate.canonical.clone(), p.candidate.target.clone()))
        .collect();
    let sources = projections
        .iter()
        .map(|p| p.normalized.observed.source.clone())
        .collect();
    let mut value = CueSnapshot::new(
        CONTRACT_REVISION.into(),
        SnapshotId::new("snapshot-1").unwrap(),
        members,
        RebuildIdentity::new(norm_profile(), sources, digest(250)),
        fence(),
    );
    value.rebuild.digest = value.canonical_digest().unwrap();
    value
}
fn build(
    projections: Vec<AdmittedCueBindingProjection>,
    edges: Vec<RelationEdge>,
) -> CueSnapshotBuildCandidate {
    let snap = snapshot(&projections);
    let targets: Vec<_> = snap
        .members
        .iter()
        .map(|member| member.target.as_str().to_owned())
        .collect();
    let endpoints: Vec<_> = edges
        .iter()
        .map(|edge| (edge.from.as_str().to_owned(), edge.to.as_str().to_owned()))
        .collect();
    CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1").unwrap(),
        snap,
        projections,
        edges,
    )
    .unwrap_or_else(|error| {
        panic!("build error: {error:?}, targets={targets:?}, endpoints={endpoints:?}")
    })
}
fn bounds(depth: u8) -> ActivationBounds {
    ActivationBounds::new(ActivationBoundsSpec {
        max_depth: depth,
        max_fanout: if depth == 0 { 0 } else { 16 },
        max_results: 64,
        max_nodes: 256,
        max_edges: if depth == 0 { 0 } else { 4096 },
        max_work: 100_000,
        max_path_len: if depth == 0 { 0 } else { 8 },
        max_seeds: 64,
        max_direct: 256,
        max_derived: if depth == 0 { 0 } else { 512 },
        max_trace_steps: 1024,
        max_output_bytes: 1_000_000,
        activation_threshold: ActivationStrength(1),
    })
}
fn request(
    candidate: &CueSnapshotBuildCandidate,
    seeds: Vec<NormalizedCue>,
    depth: u8,
) -> ActivationRequest {
    ActivationRequest::new(ActivationRequestSpec {
        schema_revision: CONTRACT_REVISION.into(),
        request_id: eliot_cue_contracts::ActivationRequestId::new("request-1").unwrap(),
        seeds,
        snapshot_id: candidate.snapshot.snapshot_id.clone(),
        relation_edges: candidate.relation_edges.clone(),
        bounds: bounds(depth),
        state_fence: fence(),
        normalization_profile: norm_profile(),
        observed_at: ClockReading::default(),
        deadline_ms: None,
        cancelled: false,
    })
}
fn profile(
    depth: u8,
    rules: Vec<MatchRule>,
    relations: Vec<RelationRule>,
    registry: Option<String>,
) -> ActivationProfile {
    ActivationProfile::seal(
        "activation-v1".into(),
        1,
        bounds(depth),
        rules,
        relations,
        registry,
    )
    .unwrap()
}
fn edge(id: u8, from: &str, to: &str) -> RelationEdge {
    edge_kind(id, RelationKind::Supports, from, to)
}
fn edge_kind(id: u8, kind: RelationKind, from: &str, to: &str) -> RelationEdge {
    RelationEdge::new(
        RelationEdgeId::new(format!("edge-{id}")).unwrap(),
        kind,
        TargetHandle::new(from).unwrap(),
        TargetHandle::new(to).unwrap(),
        "registry-1".into(),
        digest(id.wrapping_add(100)),
        context(&format!("edge-{id}")).evidence,
    )
}
fn exact_rule(kind: CueKind, strength: u16) -> MatchRule {
    MatchRule::new(kind, MatchMode::Exact, ActivationStrength(strength))
}

// WORK_UNIT_CASE: 600/1
#[test]
fn zero_edge_exact_hit_and_miss_are_distinct() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        10,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 20)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let hit =
        evaluate_activation(&candidate, &request(&candidate, vec![cue.clone()], 0), &p).unwrap();
    assert_eq!(hit.result.direct.len(), 1);
    assert!(hit.result.derived.is_empty());
    let mut miss_seed = cue;
    miss_seed.comparison_keys[0].key_value = "missing".into();
    let miss =
        evaluate_activation(&candidate, &request(&candidate, vec![miss_seed], 0), &p).unwrap();
    assert!(miss.result.is_known_empty());
}

// WORK_UNIT_CASE: 600/3
#[test]
fn exact_matches_are_retained_before_broader_modes() {
    let cue = normalized(
        CueKind::FilePath,
        "src/main.rs",
        "path",
        "target-a",
        &[
            (
                1,
                "src/main.rs",
                MatchMode::Exact,
                ComparisonForm::PathNormalized,
            ),
            (2, "src/", MatchMode::Prefix, ComparisonForm::PathNormalized),
        ],
        30,
    );
    let candidate = build(
        vec![projection(cue.clone(), "path", "target-a", 40)],
        Vec::new(),
    );
    let p = profile(
        0,
        vec![
            exact_rule(CueKind::FilePath, 900),
            MatchRule::new(
                CueKind::FilePath,
                MatchMode::Prefix,
                ActivationStrength(700),
            ),
        ],
        Vec::new(),
        None,
    );
    let result = evaluate_activation(&candidate, &request(&candidate, vec![cue], 0), &p)
        .unwrap()
        .result;
    assert_eq!(result.direct.len(), 2);
    assert_eq!(result.direct[0].matched_key.match_mode, MatchMode::Exact);
    assert_eq!(result.direct[1].matched_key.match_mode, MatchMode::Prefix);
}

// WORK_UNIT_CASE: 600/23
#[test]
fn stronger_later_diamond_path_wins_without_losing_shallower_state() {
    let mut projections = Vec::new();
    for (index, id, target, value) in [
        (0, "d", "d", "seed"),
        (1, "x", "x", "x"),
        (2, "p", "p", "p"),
        (3, "y", "y", "y"),
        (4, "z", "z", "z"),
        (5, "q", "q", "q"),
    ] {
        let keys = if index == 0 {
            vec![(1, "seed", MatchMode::Exact, ComparisonForm::Exact)]
        } else {
            vec![(1, value, MatchMode::Exact, ComparisonForm::Exact)]
        };
        projections.push(projection(
            normalized(CueKind::Symbol, value, id, target, &keys, 50 + index),
            id,
            target,
            60 + index,
        ));
    }
    let candidate = build(
        projections,
        vec![
            edge_kind(1, RelationKind::Supports, "d", "x"),
            edge_kind(2, RelationKind::Counters, "d", "p"),
            edge_kind(3, RelationKind::DerivedFrom, "p", "x"),
            edge_kind(4, RelationKind::AppliesTo, "x", "y"),
            edge_kind(5, RelationKind::ObservedIn, "y", "z"),
            edge_kind(6, RelationKind::ObservedIn, "z", "q"),
        ],
    );
    let p = profile(
        3,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![
            RelationRule::new(RelationKind::Supports, 400),
            RelationRule::new(RelationKind::Counters, 900),
            RelationRule::new(RelationKind::DerivedFrom, 900),
            RelationRule::new(RelationKind::AppliesTo, 900),
            RelationRule::new(RelationKind::ObservedIn, 900),
        ],
        Some("registry-1".into()),
    );
    let req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        3,
    );
    let evaluation = evaluate_activation(&candidate, &req, &p).unwrap();
    evaluation.validate_against(&candidate, &req, &p).unwrap();
    let result = &evaluation.result;
    assert_eq!(
        result
            .derived
            .iter()
            .find(|item| item.target.as_str() == "y")
            .unwrap()
            .strength,
        ActivationStrength(729)
    );
    assert_eq!(
        result
            .derived
            .iter()
            .find(|item| item.target.as_str() == "z")
            .unwrap()
            .strength,
        ActivationStrength(324)
    );
    assert_eq!(
        result
            .derived
            .iter()
            .find(|item| item.target.as_str() == "y")
            .unwrap()
            .path
            .iter()
            .map(RelationEdgeId::as_str)
            .collect::<Vec<_>>(),
        vec!["edge-2", "edge-3", "edge-4"]
    );
    assert_eq!(
        result
            .derived
            .iter()
            .find(|item| item.target.as_str() == "z")
            .unwrap()
            .path
            .iter()
            .map(RelationEdgeId::as_str)
            .collect::<Vec<_>>(),
        vec!["edge-1", "edge-4", "edge-5"]
    );
    assert!(matches!(
        &result.completeness,
        eliot_cue_contracts::Completeness::Truncated { frontier, bound_hit: eliot_cue_contracts::BoundKind::Depth }
            if frontier.iter().any(|id| id.as_str() == "edge-6")
    ));
}

// WORK_UNIT_CASE: 600/34
#[test]
fn stale_cancelled_and_profile_drift_are_rejected() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let mut cancelled = request(&candidate, vec![cue.clone()], 0);
    cancelled.cancelled = true;
    assert!(matches!(
        evaluate_activation(&candidate, &cancelled, &p),
        Err(ActivationError::Cancelled)
    ));
    let mut stale = cue.clone();
    stale.observed.context.lifecycle = LifecycleState::Archived;
    assert!(matches!(
        evaluate_activation(&candidate, &request(&candidate, vec![stale], 0), &p),
        Err(ActivationError::StaleInput)
    ));
    let drift = ActivationProfile::seal(
        "other-policy".into(),
        1,
        bounds(0),
        vec![exact_rule(CueKind::Symbol, 900)],
        Vec::new(),
        None,
    )
    .unwrap();
    let valid_drift = evaluate_activation(
        &candidate,
        &request(&candidate, vec![cue.clone()], 0),
        &drift,
    )
    .unwrap();
    assert!(matches!(
        valid_drift.validate_against(&candidate, &request(&candidate, vec![cue], 0), &p),
        Err(ActivationError::ProfileBinding)
    ));
}

// WORK_UNIT_CASE: 600/29
#[test]
fn edge_and_output_limits_are_explicit() {
    let first = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let second = normalized(
        CueKind::Symbol,
        "second",
        "b",
        "b",
        &[(1, "second", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(first.clone(), "a", "a", 92),
            projection(second, "b", "b", 93),
        ],
        vec![edge(1, "a", "b"), edge(2, "b", "a")],
    );
    let mut edge_limited_bounds = bounds(2);
    edge_limited_bounds.max_edges = 2;
    let p = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        edge_limited_bounds,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    )
    .unwrap();
    let mut req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        2,
    );
    req.bounds.max_edges = 2;
    let edge_result = evaluate_activation(&candidate, &req, &p);
    assert!(matches!(
        edge_result,
        Err(ActivationError::Limit {
            field: "activation.max_edges"
        })
    ));
    let output_candidate = build(
        vec![
            projection(first.clone(), "a", "a", 92),
            projection(
                candidate.admitted_bindings[1].normalized.clone(),
                "b",
                "b",
                93,
            ),
        ],
        Vec::new(),
    );
    let mut output_req = request(
        &output_candidate,
        vec![output_candidate.admitted_bindings[0].normalized.clone()],
        0,
    );
    output_req.bounds.max_output_bytes = 1;
    let low_output = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        output_req.bounds,
        vec![exact_rule(CueKind::Symbol, 1000)],
        Vec::new(),
        None,
    )
    .unwrap();
    let output_result = evaluate_activation(&output_candidate, &output_req, &low_output);
    assert!(matches!(
        output_result,
        Err(ActivationError::Limit {
            field: "activation.max_output_bytes"
        } | ActivationError::Contract(eliot_cue_contracts::CueContractError::BoundExceeded {
            field: "result.output_bytes",
            ..
        }))
    ));
}

// WORK_UNIT_CASE: 600/39
#[test]
fn evaluation_identity_is_stable_for_edge_order_permutations() {
    let first = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        110,
    );
    let second = normalized(
        CueKind::Symbol,
        "second",
        "b",
        "b",
        &[(1, "second", MatchMode::Exact, ComparisonForm::Exact)],
        111,
    );
    let e1 = edge(1, "a", "b");
    let e2 = edge(2, "a", "b");
    let left = build(
        vec![
            projection(first.clone(), "a", "a", 112),
            projection(second.clone(), "b", "b", 113),
        ],
        vec![e1.clone(), e2.clone()],
    );
    let right = build(
        vec![
            projection(second, "b", "b", 113),
            projection(first.clone(), "a", "a", 112),
        ],
        vec![e2, e1],
    );
    let p = profile(
        1,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let left_eval =
        evaluate_activation(&left, &request(&left, vec![first.clone()], 1), &p).unwrap();
    let right_eval = evaluate_activation(&right, &request(&right, vec![first], 1), &p).unwrap();
    assert_eq!(left_eval.input_digest, right_eval.input_digest);
    assert_eq!(left_eval.result, right_eval.result);
}

fn fence_seq(seq: u64) -> StateFence {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(seq).expect("sequence"),
    )
    .map(|epoch| StateFence::new(epoch, ResourceGeneration::genesis()))
    .expect("fence")
}

// WORK_UNIT_CASE: 600/2
#[test]
fn zero_edge_direct_miss_reports_complete_empty() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        10,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 20)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let mut miss_seed = cue;
    miss_seed.comparison_keys[0].key_value = "missing".into();
    let evaluation =
        evaluate_activation(&candidate, &request(&candidate, vec![miss_seed], 0), &p).unwrap();
    assert!(evaluation.result.is_known_empty());
    assert!(matches!(
        evaluation.result.completeness,
        eliot_cue_contracts::Completeness::Complete
    ));
    assert!(evaluation.result.derived.is_empty());
    assert!(evaluation.result.trace.steps.is_empty());
}

// WORK_UNIT_CASE: 600/4
#[test]
fn broader_mode_requires_explicit_profile_rule() {
    let cue = normalized(
        CueKind::FilePath,
        "src/main.rs",
        "path",
        "target-a",
        &[
            (
                1,
                "src/main.rs",
                MatchMode::Exact,
                ComparisonForm::PathNormalized,
            ),
            (2, "src/", MatchMode::Prefix, ComparisonForm::PathNormalized),
        ],
        30,
    );
    let candidate = build(
        vec![projection(cue.clone(), "path", "target-a", 40)],
        Vec::new(),
    );
    let exact_only = profile(0, vec![exact_rule(CueKind::FilePath, 900)], Vec::new(), None);
    let gated = evaluate_activation(
        &candidate,
        &request(&candidate, vec![cue.clone()], 0),
        &exact_only,
    );
    assert!(matches!(
        gated,
        Err(ActivationError::Unsupported)
    ));
    let with_prefix = profile(
        0,
        vec![
            exact_rule(CueKind::FilePath, 900),
            MatchRule::new(
                CueKind::FilePath,
                MatchMode::Prefix,
                ActivationStrength(700),
            ),
        ],
        Vec::new(),
        None,
    );
    let result = evaluate_activation(&candidate, &request(&candidate, vec![cue], 0), &with_prefix)
        .unwrap()
        .result;
    assert_eq!(result.direct.len(), 2);
}

// WORK_UNIT_CASE: 600/5
#[test]
fn wrong_kind_has_no_direct_hit() {
    let stored = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        10,
    );
    let candidate = build(
        vec![projection(stored, "alpha", "target-a", 20)],
        Vec::new(),
    );
    let query = normalized(
        CueKind::FilePath,
        "src/other.rs",
        "other",
        "target-other",
        &[(
            1,
            "src/other.rs",
            MatchMode::Exact,
            ComparisonForm::PathNormalized,
        )],
        11,
    );
    let p = profile(
        0,
        vec![
            exact_rule(CueKind::Symbol, 900),
            exact_rule(CueKind::FilePath, 900),
        ],
        Vec::new(),
        None,
    );
    let evaluation =
        evaluate_activation(&candidate, &request(&candidate, vec![query], 0), &p).unwrap();
    assert!(evaluation.result.is_known_empty());
}

// WORK_UNIT_CASE: 600/6
#[test]
fn wrong_task_scope_fence_is_rejected() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let mut other_task = cue.clone();
    other_task.observed.context.task_id = TaskId::new("task-2").unwrap();
    let mixed = evaluate_activation(
        &candidate,
        &request(&candidate, vec![cue.clone(), other_task], 0),
        &p,
    );
    assert!(mixed.is_err());
    let mut fenced = request(&candidate, vec![cue], 0);
    fenced.state_fence = fence_seq(2);
    let drifted = evaluate_activation(&candidate, &fenced, &p);
    assert!(drifted.is_err());
}

// WORK_UNIT_CASE: 600/7
#[test]
fn wrong_snapshot_denominator_is_rejected() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let mut req = request(&candidate, vec![cue], 0);
    req.snapshot_id = SnapshotId::new("snapshot-2").unwrap();
    assert!(matches!(
        evaluate_activation(&candidate, &req, &p),
        Err(ActivationError::ProfileBinding)
    ));
}

// WORK_UNIT_CASE: 600/8
#[test]
fn wrong_normalizer_profile_is_rejected() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let mut req = request(&candidate, vec![cue], 0);
    req.normalization_profile = NormalizationProfile::new("norm-v2".into(), 1, digest(2));
    assert!(evaluate_activation(&candidate, &req, &p).is_err());
}

// WORK_UNIT_CASE: 600/9
#[test]
fn wrong_registry_revision_is_rejected() {
    let first = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let second = normalized(
        CueKind::Symbol,
        "second",
        "b",
        "b",
        &[(1, "second", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(first.clone(), "a", "a", 92),
            projection(second, "b", "b", 93),
        ],
        vec![edge(1, "a", "b")],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-2".into()),
    );
    let req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        2,
    );
    assert!(matches!(
        evaluate_activation(&candidate, &req, &p),
        Err(ActivationError::ProfileBinding)
    ));
}

// WORK_UNIT_CASE: 600/10
#[test]
fn injected_time_mismatch_is_rejected() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let mut req = request(&candidate, vec![cue], 0);
    req.observed_at = ClockReading {
        valid_time_ms: Some(1_000),
        known_time_ms: Some(1_000),
        transaction_sequence: None,
        monotonic_ns: None,
    };
    req.deadline_ms = Some(500);
    assert!(evaluate_activation(&candidate, &req, &p).is_err());
}

// WORK_UNIT_CASE: 600/11
#[test]
fn stale_snapshot_tamper_is_rejected() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let mut tampered = candidate.clone();
    tampered.snapshot.members.pop();
    let req = request(&candidate, vec![cue], 0);
    assert!(evaluate_activation(&tampered, &req, &p).is_err());
}

// WORK_UNIT_CASE: 600/12
#[test]
fn non_active_rows_are_rejected() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    for state in [
        LifecycleState::Archived,
        LifecycleState::Suppressed,
        LifecycleState::Extinguished,
        LifecycleState::Quarantined,
    ] {
        let mut stale = cue.clone();
        stale.observed.context.lifecycle = state;
        assert!(
            matches!(
                evaluate_activation(&candidate, &request(&candidate, vec![stale], 0), &p),
                Err(ActivationError::StaleInput)
            ),
            "lifecycle {state:?} must be stale"
        );
    }
}

// WORK_UNIT_CASE: 600/13
#[test]
fn duplicate_seed_identity_cannot_inflate() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let duplicated = evaluate_activation(
        &candidate,
        &request(&candidate, vec![cue.clone(), cue], 0),
        &p,
    );
    assert!(matches!(
        duplicated,
        Err(ActivationError::Contract(
            eliot_cue_contracts::CueContractError::DuplicateIdentity { .. }
        ))
    ));
}

// WORK_UNIT_CASE: 600/14
#[test]
fn duplicate_exact_row_keeps_single_lineage() {
    let base = normalized(
        CueKind::Symbol,
        "alpha",
        "dup",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(base.clone(), "dup", "target-a", 80)],
        Vec::new(),
    );
    let mut sibling = base.clone();
    sibling.observed.observed_cue_id =
        ObservedCueId::new("observed-dup-2".to_string()).unwrap();
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let evaluation = evaluate_activation(
        &candidate,
        &request(&candidate, vec![base, sibling], 0),
        &p,
    )
    .unwrap();
    assert_eq!(evaluation.result.direct.len(), 1);
    assert_eq!(
        evaluation.result.direct[0].matched_key.comparison_key_id.as_str(),
        "key-dup-1"
    );
    assert_eq!(evaluation.result.direct[0].target.as_str(), "target-a");
}

// WORK_UNIT_CASE: 600/15
#[test]
fn only_valid_direct_targets_seed_spreading() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let other = normalized(
        CueKind::Symbol,
        "other",
        "b",
        "b",
        &[(1, "other", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let far = normalized(
        CueKind::Symbol,
        "far",
        "c",
        "c",
        &[(1, "far", MatchMode::Exact, ComparisonForm::Exact)],
        92,
    );
    let candidate = build(
        vec![
            projection(seed_cue.clone(), "a", "a", 93),
            projection(other, "b", "b", 94),
            projection(far, "c", "c", 95),
        ],
        vec![edge(1, "b", "c")],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let evaluation = evaluate_activation(
        &candidate,
        &request(&candidate, vec![seed_cue], 2),
        &p,
    )
    .unwrap();
    assert_eq!(evaluation.result.direct.len(), 1);
    assert_eq!(evaluation.result.direct[0].target.as_str(), "a");
    assert!(evaluation.result.derived.is_empty());
    assert!(matches!(
        evaluation.result.completeness,
        eliot_cue_contracts::Completeness::Complete
    ));
}

// WORK_UNIT_CASE: 600/16
#[test]
fn no_direct_hit_performs_no_nearest_traversal() {
    let stored = normalized(
        CueKind::Symbol,
        "stored",
        "a",
        "a",
        &[(1, "stored", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let next = normalized(
        CueKind::Symbol,
        "next",
        "b",
        "b",
        &[(1, "next", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(stored, "a", "a", 92),
            projection(next, "b", "b", 93),
        ],
        vec![edge(1, "a", "b")],
    );
    let miss = normalized(
        CueKind::Symbol,
        "query",
        "q",
        "query-target",
        &[(1, "absent", MatchMode::Exact, ComparisonForm::Exact)],
        94,
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let evaluation =
        evaluate_activation(&candidate, &request(&candidate, vec![miss], 2), &p).unwrap();
    assert!(evaluation.result.is_known_empty());
    assert!(evaluation.result.derived.is_empty());
}

// WORK_UNIT_CASE: 600/17
#[test]
fn valid_one_hop_activation_uses_direct_seed_path() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let next = normalized(
        CueKind::Symbol,
        "next",
        "b",
        "b",
        &[(1, "next", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(seed_cue.clone(), "a", "a", 92),
            projection(next, "b", "b", 93),
        ],
        vec![edge(1, "a", "b")],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let evaluation = evaluate_activation(
        &candidate,
        &request(&candidate, vec![seed_cue], 2),
        &p,
    )
    .unwrap();
    assert_eq!(evaluation.result.derived.len(), 1);
    let derived = &evaluation.result.derived[0];
    assert_eq!(derived.target.as_str(), "b");
    assert_eq!(derived.direct_seed.as_str(), "a");
    assert_eq!(derived.depth, 1);
    assert_eq!(
        derived.path.iter().map(RelationEdgeId::as_str).collect::<Vec<_>>(),
        vec!["edge-1"]
    );
    assert_eq!(derived.strength, ActivationStrength(1000));
}

// WORK_UNIT_CASE: 600/18
#[test]
fn bounded_multihop_activation_chains_scores() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let mid = normalized(
        CueKind::Symbol,
        "mid",
        "b",
        "b",
        &[(1, "mid", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let far = normalized(
        CueKind::Symbol,
        "far",
        "c",
        "c",
        &[(1, "far", MatchMode::Exact, ComparisonForm::Exact)],
        92,
    );
    let candidate = build(
        vec![
            projection(seed_cue.clone(), "a", "a", 93),
            projection(mid, "b", "b", 94),
            projection(far, "c", "c", 95),
        ],
        vec![edge(1, "a", "b"), edge(2, "b", "c")],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        2,
    );
    let evaluation = evaluate_activation(&candidate, &req, &p).unwrap();
    evaluation.validate_against(&candidate, &req, &p).unwrap();
    let by_target = |name: &str| {
        evaluation
            .result
            .derived
            .iter()
            .find(|item| item.target.as_str() == name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .clone()
    };
    assert_eq!(by_target("b").depth, 1);
    assert_eq!(by_target("c").depth, 2);
    assert_eq!(
        by_target("c").path.iter().map(RelationEdgeId::as_str).collect::<Vec<_>>(),
        vec!["edge-1", "edge-2"]
    );
}

// WORK_UNIT_CASE: 600/19
#[test]
fn prohibited_direction_is_not_traversed() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let other = normalized(
        CueKind::Symbol,
        "other",
        "b",
        "b",
        &[(1, "other", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(seed_cue.clone(), "a", "a", 92),
            projection(other, "b", "b", 93),
        ],
        vec![edge(1, "b", "a")],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let evaluation = evaluate_activation(
        &candidate,
        &request(&candidate, vec![seed_cue], 2),
        &p,
    )
    .unwrap();
    assert_eq!(evaluation.result.direct.len(), 1);
    assert!(evaluation.result.derived.is_empty());
    assert!(matches!(
        evaluation.result.completeness,
        eliot_cue_contracts::Completeness::Complete
    ));
}

// WORK_UNIT_CASE: 600/20
#[test]
fn stale_edge_is_rejected_not_traversed() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let next = normalized(
        CueKind::Symbol,
        "next",
        "b",
        "b",
        &[(1, "next", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let mut stale_edge = edge(1, "a", "b");
    stale_edge.evidence.freshness = EvidenceFreshness::Stale;
    let candidate = build(
        vec![
            projection(seed_cue.clone(), "a", "a", 92),
            projection(next, "b", "b", 93),
        ],
        vec![stale_edge],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    assert!(matches!(
        evaluate_activation(&candidate, &request(&candidate, vec![seed_cue], 2), &p),
        Err(ActivationError::StaleInput)
    ));
}

// WORK_UNIT_CASE: 600/21
#[test]
fn cycle_terminates_deterministically() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let other = normalized(
        CueKind::Symbol,
        "other",
        "b",
        "b",
        &[(1, "other", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(seed_cue.clone(), "a", "a", 92),
            projection(other, "b", "b", 93),
        ],
        vec![edge(1, "a", "b"), edge(2, "b", "a")],
    );
    let p = profile(
        4,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let first = evaluate_activation(&candidate, &request(&candidate, vec![seed_cue.clone()], 4), &p)
        .unwrap();
    let second =
        evaluate_activation(&candidate, &request(&candidate, vec![seed_cue], 4), &p).unwrap();
    assert_eq!(first.result, second.result);
    assert_eq!(first.input_digest, second.input_digest);
    assert_eq!(first.result.derived.len(), 1);
    assert_eq!(first.result.derived[0].target.as_str(), "b");
}

// WORK_UNIT_CASE: 600/22
#[test]
fn self_loop_terminates_without_inflation() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let candidate = build(
        vec![projection(seed_cue.clone(), "a", "a", 92)],
        vec![edge(1, "a", "a")],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let evaluation = evaluate_activation(
        &candidate,
        &request(&candidate, vec![seed_cue], 2),
        &p,
    )
    .unwrap();
    assert_eq!(evaluation.result.direct.len(), 1);
    assert_eq!(
        evaluation.result.direct[0].strength,
        ActivationStrength(1000)
    );
    assert!(evaluation.result.derived.is_empty());
}

// WORK_UNIT_CASE: 600/24
#[test]
fn duplicate_paths_cannot_inflate_popularity() {
    let seed_cue = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let next = normalized(
        CueKind::Symbol,
        "next",
        "b",
        "b",
        &[(1, "next", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(seed_cue.clone(), "a", "a", 92),
            projection(next, "b", "b", 93),
        ],
        vec![edge(1, "a", "b"), edge(2, "a", "b")],
    );
    let p = profile(
        1,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 500)],
        Some("registry-1".into()),
    );
    let evaluation = evaluate_activation(
        &candidate,
        &request(&candidate, vec![seed_cue], 1),
        &p,
    )
    .unwrap();
    assert_eq!(evaluation.result.derived.len(), 1);
    assert_eq!(evaluation.result.derived[0].target.as_str(), "b");
    assert_eq!(
        evaluation.result.derived[0].strength,
        ActivationStrength(500)
    );
}

// WORK_UNIT_CASE: 600/25
#[test]
fn equal_best_paths_obey_evidence_bound() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![
            mk("a", "a", "seed", 90),
            mk("b", "b", "b", 91),
            mk("c", "c", "c", 92),
            mk("d", "d", "d", 93),
        ],
        vec![
            edge(1, "a", "b"),
            edge(2, "a", "c"),
            edge(3, "b", "d"),
            edge(4, "c", "d"),
        ],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let evaluation = evaluate_activation(
        &candidate,
        &request(
            &candidate,
            vec![candidate.admitted_bindings[0].normalized.clone()],
            2,
        ),
        &p,
    )
    .unwrap();
    let targets: Vec<&str> = evaluation
        .result
        .derived
        .iter()
        .map(|item| item.target.as_str())
        .collect();
    assert!(targets.contains(&"b"));
    assert!(targets.contains(&"c"));
    assert!(targets.contains(&"d"));
    assert_eq!(targets.len(), 3);
    let d = evaluation
        .result
        .derived
        .iter()
        .find(|item| item.target.as_str() == "d")
        .unwrap();
    assert_eq!(d.strength, ActivationStrength(1000));
}

// WORK_UNIT_CASE: 600/26
#[test]
fn depth_boundary_records_frontier() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "b", 91), mk("c", "c", "c", 92)],
        vec![edge(1, "a", "b"), edge(2, "b", "c")],
    );
    let p = profile(
        1,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let evaluation = evaluate_activation(
        &candidate,
        &request(
            &candidate,
            vec![candidate.admitted_bindings[0].normalized.clone()],
            1,
        ),
        &p,
    )
    .unwrap();
    assert!(matches!(
        &evaluation.result.completeness,
        eliot_cue_contracts::Completeness::Truncated { frontier, bound_hit }
        if *bound_hit == eliot_cue_contracts::BoundKind::Depth
            && frontier.iter().any(|id| id.as_str() == "edge-2")
    ));
    assert!(evaluation.result.derived.iter().any(|item| item.target.as_str() == "b"));
    assert!(!evaluation.result.derived.iter().any(|item| item.target.as_str() == "c"));
}

// WORK_UNIT_CASE: 600/27
#[test]
fn fanout_boundary_records_frontier() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![
            mk("a", "a", "seed", 90),
            mk("b", "b", "b", 91),
            mk("c", "c", "c", 92),
            mk("d", "d", "d", 93),
        ],
        vec![edge(1, "a", "b"), edge(2, "a", "c"), edge(3, "a", "d")],
    );
    let mut limited = bounds(2);
    limited.max_fanout = 2;
    let p = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        limited,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    )
    .unwrap();
    let mut req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        2,
    );
    req.bounds = limited;
    let evaluation = evaluate_activation(&candidate, &req, &p).unwrap();
    assert!(matches!(
        &evaluation.result.completeness,
        eliot_cue_contracts::Completeness::Truncated { frontier, bound_hit }
        if *bound_hit == eliot_cue_contracts::BoundKind::Fanout
            && frontier.iter().any(|id| id.as_str() == "edge-3")
    ));
    assert_eq!(evaluation.result.derived.len(), 2);
}

// WORK_UNIT_CASE: 600/28
#[test]
fn visited_node_boundary_is_explicit() {
    let first = normalized(
        CueKind::Symbol,
        "seed",
        "a",
        "a",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        90,
    );
    let second = normalized(
        CueKind::Symbol,
        "second",
        "b",
        "b",
        &[(1, "second", MatchMode::Exact, ComparisonForm::Exact)],
        91,
    );
    let candidate = build(
        vec![
            projection(first.clone(), "a", "a", 92),
            projection(second, "b", "b", 93),
        ],
        Vec::new(),
    );
    let mut limited = bounds(0);
    limited.max_nodes = 1;
    let p = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        limited,
        vec![exact_rule(CueKind::Symbol, 1000)],
        Vec::new(),
        None,
    )
    .unwrap();
    let mut req = request(&candidate, vec![first], 0);
    req.bounds = limited;
    assert!(matches!(
        evaluate_activation(&candidate, &req, &p),
        Err(ActivationError::Limit { field: "activation.max_nodes" })
    ));
}

// WORK_UNIT_CASE: 600/30
#[test]
fn path_length_boundary_is_explicit() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "b", 91), mk("c", "c", "c", 92)],
        vec![edge(1, "a", "b"), edge(2, "b", "c")],
    );
    let mut limited = bounds(2);
    limited.max_path_len = 1;
    let p = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        limited,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    )
    .unwrap();
    let mut req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        2,
    );
    req.bounds = limited;
    assert!(matches!(
        evaluate_activation(&candidate, &req, &p),
        Err(ActivationError::Limit { field: "activation.max_path_len" })
    ));
}

// WORK_UNIT_CASE: 600/31
#[test]
fn result_count_boundaries_are_explicit() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "other", 91)],
        Vec::new(),
    );
    let mut direct_limited = bounds(0);
    direct_limited.max_direct = 1;
    let direct_profile = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        direct_limited,
        vec![exact_rule(CueKind::Symbol, 1000)],
        Vec::new(),
        None,
    )
    .unwrap();
    let seeds = vec![
        candidate.admitted_bindings[0].normalized.clone(),
        candidate.admitted_bindings[1].normalized.clone(),
    ];
    let mut direct_req = request(&candidate, seeds, 0);
    direct_req.bounds = direct_limited;
    assert!(matches!(
        evaluate_activation(&candidate, &direct_req, &direct_profile),
        Err(ActivationError::Limit { field: "activation.max_direct" })
    ));
    let spread = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "b", 91), mk("c", "c", "c", 92)],
        vec![edge(1, "a", "b"), edge(2, "a", "c")],
    );
    let mut derived_limited = bounds(1);
    derived_limited.max_derived = 1;
    let derived_profile = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        derived_limited,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    )
    .unwrap();
    let mut derived_req = request(
        &spread,
        vec![spread.admitted_bindings[0].normalized.clone()],
        1,
    );
    derived_req.bounds = derived_limited;
    assert!(matches!(
        evaluate_activation(&spread, &derived_req, &derived_profile),
        Err(ActivationError::Limit { field: "activation.max_derived" })
    ));
}

// WORK_UNIT_CASE: 600/32
#[test]
fn trace_and_output_boundaries_are_explicit() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(vec![mk("a", "a", "seed", 90), mk("b", "b", "other", 91)], Vec::new());
    let mut trace_limited = bounds(0);
    trace_limited.max_trace_steps = 1;
    let trace_profile = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        trace_limited,
        vec![exact_rule(CueKind::Symbol, 1000)],
        Vec::new(),
        None,
    )
    .unwrap();
    let seeds = vec![
        candidate.admitted_bindings[0].normalized.clone(),
        candidate.admitted_bindings[1].normalized.clone(),
    ];
    let mut trace_req = request(&candidate, seeds, 0);
    trace_req.bounds = trace_limited;
    assert!(matches!(
        evaluate_activation(&candidate, &trace_req, &trace_profile),
        Err(ActivationError::Limit { field: "activation.trace" })
    ));
    let solo = build(vec![mk("a", "a", "seed", 90)], Vec::new());
    let mut output_req = request(
        &solo,
        vec![solo.admitted_bindings[0].normalized.clone()],
        0,
    );
    output_req.bounds.max_output_bytes = 1;
    let output_profile = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        output_req.bounds,
        vec![exact_rule(CueKind::Symbol, 1000)],
        Vec::new(),
        None,
    )
    .unwrap();
    assert!(evaluate_activation(&solo, &output_req, &output_profile).is_err());
}

// WORK_UNIT_CASE: 600/33
#[test]
fn unknown_zero_limit_is_not_unlimited() {
    let mut zeroed = bounds(1);
    zeroed.max_results = 0;
    assert!(
        ActivationProfile::seal(
            "activation-v1".into(),
            1,
            zeroed,
            vec![exact_rule(CueKind::Symbol, 1000)],
            vec![RelationRule::new(RelationKind::Supports, 1000)],
            Some("registry-1".into()),
        )
        .is_err(),
        "zero max_results must be rejected, never unlimited"
    );
    let mut zero_nodes = bounds(0);
    zero_nodes.max_nodes = 0;
    assert!(
        ActivationProfile::seal(
            "activation-v1".into(),
            1,
            zero_nodes,
            vec![exact_rule(CueKind::Symbol, 900)],
            Vec::new(),
            None,
        )
        .is_err(),
        "zero max_nodes must be rejected, never unlimited"
    );
}

// WORK_UNIT_CASE: 600/35
#[test]
fn direct_complete_with_derived_partial() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "b", 91), mk("c", "c", "c", 92)],
        vec![edge(1, "a", "b"), edge(2, "b", "c")],
    );
    let p = profile(
        1,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        1,
    );
    let evaluation = evaluate_activation(&candidate, &req, &p).unwrap();
    assert_eq!(evaluation.result.direct.len(), 1);
    assert_eq!(evaluation.result.direct[0].target.as_str(), "a");
    assert_eq!(evaluation.result.derived.len(), 1);
    assert_eq!(evaluation.result.derived[0].target.as_str(), "b");
    assert!(matches!(
        &evaluation.result.completeness,
        eliot_cue_contracts::Completeness::Truncated { .. }
    ));
}

// WORK_UNIT_CASE: 600/36
#[test]
fn completeness_taxonomy_stays_distinct() {
    use eliot_cue_contracts::{BoundKind, Completeness};
    let edge_id = RelationEdgeId::new("edge-1".to_string()).unwrap();
    let complete = Completeness::Complete;
    let truncated = Completeness::Truncated {
        frontier: vec![edge_id.clone()],
        bound_hit: BoundKind::Depth,
    };
    let partial = Completeness::Partial { frontier: vec![edge_id.clone()] };
    let blocked = Completeness::Blocked { reason: "policy".to_string() };
    let unavailable = Completeness::Unavailable { reason: "missing".to_string() };
    let unknown = Completeness::Unknown { reason: "unknown".to_string() };
    let source_unavailable = Completeness::SourceUnavailable { reason: "io".to_string() };
    let no_direct = Completeness::NoDirectMatch { reason: "empty".to_string() };
    let stale = Completeness::Stale { snapshot_fence: fence() };
    assert_ne!(complete, truncated);
    assert_ne!(truncated, partial);
    assert_ne!(blocked, unavailable);
    assert_ne!(unavailable, unknown);
    assert_ne!(source_unavailable, no_direct);
    assert_ne!(no_direct, stale);
    assert_ne!(complete, stale);
    assert!(matches!(complete, Completeness::Complete));
    assert!(matches!(truncated, Completeness::Truncated { .. }));
}

// WORK_UNIT_CASE: 600/37
#[test]
fn every_bound_carries_frontier_evidence() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let chain = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "b", 91), mk("c", "c", "c", 92)],
        vec![edge(1, "a", "b"), edge(2, "b", "c")],
    );
    let depth_profile = profile(
        1,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let depth_eval = evaluate_activation(
        &chain,
        &request(
            &chain,
            vec![chain.admitted_bindings[0].normalized.clone()],
            1,
        ),
        &depth_profile,
    )
    .unwrap();
    match &depth_eval.result.completeness {
        eliot_cue_contracts::Completeness::Truncated { frontier, bound_hit } => {
            assert_eq!(*bound_hit, eliot_cue_contracts::BoundKind::Depth);
            assert!(!frontier.is_empty());
            assert!(frontier.iter().any(|id| id.as_str() == "edge-2"));
        }
        other => panic!("expected depth truncation, got {other:?}"),
    }
    let fan = build(
        vec![
            mk("a", "a", "seed", 90),
            mk("b", "b", "b", 91),
            mk("c", "c", "c", 92),
            mk("d", "d", "d", 93),
        ],
        vec![edge(1, "a", "b"), edge(2, "a", "c"), edge(3, "a", "d")],
    );
    let mut fan_bounds = bounds(2);
    fan_bounds.max_fanout = 2;
    let fan_profile = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        fan_bounds,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    )
    .unwrap();
    let mut fan_req = request(
        &fan,
        vec![fan.admitted_bindings[0].normalized.clone()],
        2,
    );
    fan_req.bounds = fan_bounds;
    let fan_eval = evaluate_activation(&fan, &fan_req, &fan_profile).unwrap();
    match &fan_eval.result.completeness {
        eliot_cue_contracts::Completeness::Truncated { frontier, bound_hit } => {
            assert_eq!(*bound_hit, eliot_cue_contracts::BoundKind::Fanout);
            assert!(!frontier.is_empty());
        }
        other => panic!("expected fanout truncation, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 600/38
#[test]
fn direct_and_derived_variants_keep_lineage() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "other", 91)],
        vec![edge(1, "a", "b")],
    );
    let p = profile(
        1,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 1000)],
        Some("registry-1".into()),
    );
    let seeds = vec![
        candidate.admitted_bindings[0].normalized.clone(),
        candidate.admitted_bindings[1].normalized.clone(),
    ];
    let evaluation = evaluate_activation(&candidate, &request(&candidate, seeds, 1), &p).unwrap();
    assert_eq!(evaluation.result.direct.len(), 2);
    assert!(evaluation.result.derived.is_empty());
    for direct in &evaluation.result.direct {
        assert_eq!(direct.matched_key.profile, norm_profile());
    }
    let solo_seed = vec![candidate.admitted_bindings[0].normalized.clone()];
    let solo = evaluate_activation(&candidate, &request(&candidate, solo_seed, 1), &p).unwrap();
    assert_eq!(solo.result.direct.len(), 1);
    assert_eq!(solo.result.derived.len(), 1);
    assert_eq!(solo.result.derived[0].direct_seed.as_str(), "a");
    assert!(!solo.result.derived[0].path.is_empty());
}

// WORK_UNIT_CASE: 600/40
#[test]
fn malformed_inputs_are_bounded_and_panic_free() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let empty = ActivationRequest::new(ActivationRequestSpec {
        schema_revision: CONTRACT_REVISION.into(),
        request_id: eliot_cue_contracts::ActivationRequestId::new("request-1").unwrap(),
        seeds: Vec::new(),
        snapshot_id: candidate.snapshot.snapshot_id.clone(),
        relation_edges: Vec::new(),
        bounds: bounds(0),
        state_fence: fence(),
        normalization_profile: norm_profile(),
        observed_at: ClockReading::default(),
        deadline_ms: None,
        cancelled: false,
    });
    assert!(evaluate_activation(&candidate, &empty, &p).is_err());
    let mut keyless = cue;
    keyless.comparison_keys.clear();
    assert!(evaluate_activation(&candidate, &request(&candidate, vec![keyless], 0), &p).is_err());
}

// WORK_UNIT_CASE: 600/41
#[test]
fn evaluator_is_pure_with_no_delivery_side_effects() {
    let cue = normalized(
        CueKind::Symbol,
        "alpha",
        "alpha",
        "target-a",
        &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let candidate = build(
        vec![projection(cue.clone(), "alpha", "target-a", 80)],
        Vec::new(),
    );
    let before = candidate.clone();
    let p = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let first = evaluate_activation(&candidate, &request(&candidate, vec![cue.clone()], 0), &p)
        .unwrap();
    let second = evaluate_activation(&candidate, &request(&candidate, vec![cue], 0), &p).unwrap();
    assert_eq!(candidate, before);
    assert_eq!(candidate.build_digest, before.build_digest);
    assert_eq!(first, second);
    assert_eq!(first.policy_id, "activation-v1");
    assert!(first.result.derived.is_empty());
}

// WORK_UNIT_CASE: 600/42
#[test]
fn derived_results_follow_bounded_exact_seed_paths() {
    let mk = |id: &str, target: &str, value: &str, seed: u8| {
        projection(
            normalized(
                CueKind::Symbol,
                value,
                id,
                target,
                &[(1, value, MatchMode::Exact, ComparisonForm::Exact)],
                seed,
            ),
            id,
            target,
            seed + 10,
        )
    };
    let candidate = build(
        vec![mk("a", "a", "seed", 90), mk("b", "b", "b", 91), mk("c", "c", "c", 92)],
        vec![edge(1, "a", "b"), edge(2, "b", "c")],
    );
    let p = profile(
        2,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 800)],
        Some("registry-1".into()),
    );
    let req = request(
        &candidate,
        vec![candidate.admitted_bindings[0].normalized.clone()],
        2,
    );
    let evaluation = evaluate_activation(&candidate, &req, &p).unwrap();
    evaluation.validate_against(&candidate, &req, &p).unwrap();
    let direct_targets: Vec<&str> = evaluation
        .result
        .direct
        .iter()
        .map(|hit| hit.target.as_str())
        .collect();
    assert_eq!(direct_targets, vec!["a"]);
    for derived in &evaluation.result.derived {
        assert!(direct_targets.contains(&derived.direct_seed.as_str()));
        assert!(!derived.path.is_empty());
        assert_eq!(usize::from(derived.depth), derived.path.len());
        assert!(derived.depth <= req.bounds.max_depth);
        assert!(derived.path.len() <= usize::from(req.bounds.max_path_len));
        assert!(derived.strength <= evaluation.result.direct[0].strength);
    }
    assert!(matches!(
        evaluation.result.completeness,
        eliot_cue_contracts::Completeness::Complete
    ));
    for derived in &evaluation.result.derived {
        assert_ne!(derived.direct_seed, derived.target);
    }
}
