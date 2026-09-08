#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    AuthorityEpoch, ClockReading, ReceiptId, ResourceGeneration, SourceId, StateFence, TaskId,
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
fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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
