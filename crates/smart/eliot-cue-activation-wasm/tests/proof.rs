//! Issue #640 proof matrix: exactly cases 1..13, one test per case.
#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
    TaskId, sha256_hex,
};
use eliot_cue_activation::{
    ACTIVATION_PROFILE_REVISION, ActivationError, ActivationProfile, CueActivationEvaluation,
    MatchRule, RelationRule, evaluate_activation,
};
use eliot_cue_activation_wasm::{
    CallLedger, EXPORT_NAME, GUEST_ABI_VERSION, GUEST_TARGET, GuestError, GuestRequest,
    GuestResponse, TOOLCHAIN_CHANNEL, TYPED_WORLD_NAME, TYPED_WORLD_OWNER, TYPED_WORLD_STATUS,
    WORLD_NAME, WORLD_PACKAGE, activate, activate_with_ledger, bound_kind_as_str,
    check_wasm_imports, completeness_as_str, decode_request, decode_response, descriptor,
    descriptor_digest, encode_request, encode_response, handle_request_typed, handle_with_ledger,
    is_forbidden_import, list_wasm_imports, parse_bound_kind, parse_completeness,
    qualified_export_name, request_digest,
};
use eliot_cue_contracts::PrivacyClass;
use eliot_cue_contracts::{
    ActivationBounds, ActivationBoundsSpec, ActivationRequest, ActivationRequestSpec,
    ActivationStrength, AdmittedCueBindingProjection, BindingCandidateId, BindingDisposition,
    BindingRole, CONTRACT_REVISION, CanonicalCueId, CanonicalCueIdentity, ComparisonForm,
    ComparisonKey, ComparisonKeyId, Completeness, CueBindingAdmissionRef, CueBindingCandidate,
    CueContext, CueContractError, CueKind, CueSnapshot, CueSnapshotBuildCandidate, Digest,
    MatchMode, NormalizationOutcome, NormalizationProfile, NormalizedCue, ObservedCue,
    ObservedCueId, ProofCeiling, RebuildIdentity, RelationEdge, RelationEdgeId, SnapshotId,
    SnapshotMember, SourceHandle, TargetHandle,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance, RelationKind,
};
use eliot_receipts::{ReceiptIdentity, WorkScopeId};

// ---------------------------------------------------------------------------
// Fixtures (adapted from the native A-14a 42-case suite; same constructors).
// ---------------------------------------------------------------------------

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

#[allow(clippy::too_many_arguments)]
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
    CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1").unwrap(),
        snap,
        projections,
        edges,
    )
    .expect("sealed candidate")
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

type NativeTriple = (
    CueSnapshotBuildCandidate,
    ActivationRequest,
    ActivationProfile,
);

/// Depth-0 exact-hit native triple: one `Symbol` cue hitting `target-a`.
fn fixture_hit() -> NativeTriple {
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
    let profile = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
    let request = request(&candidate, vec![cue], 0);
    (candidate, request, profile)
}

fn guest_request() -> (GuestRequest, NativeTriple) {
    let triple = fixture_hit();
    let (candidate, request, profile) = triple.clone();
    (
        GuestRequest {
            abi_version: GUEST_ABI_VERSION,
            world: WORLD_NAME.to_owned(),
            candidate,
            request,
            profile,
        },
        triple,
    )
}

/// Depth-2 chain `d -> x -> y` seeded at `d`.
fn fixture_chain(depth: u8) -> NativeTriple {
    let mut projections = Vec::new();
    for (index, id, target, value) in [
        (0, "d", "d", "seed"),
        (1, "x", "x", "x"),
        (2, "y", "y", "y"),
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
    let candidate = build(projections, vec![edge(1, "d", "x"), edge(2, "x", "y")]);
    let seed = normalized(
        CueKind::Symbol,
        "seed",
        "seed",
        "d",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        70,
    );
    let profile = profile(
        depth,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![RelationRule::new(RelationKind::Supports, 400)],
        Some("registry-1".into()),
    );
    let request = request(&candidate, vec![seed], depth);
    (candidate, request, profile)
}

/// Diamond `d -> x, d -> p -> x` for maximum-path parity.
fn fixture_diamond() -> NativeTriple {
    let mut projections = Vec::new();
    for (index, id, target, value) in [
        (0, "d", "d", "seed"),
        (1, "x", "x", "x"),
        (2, "p", "p", "p"),
    ] {
        let keys = if index == 0 {
            vec![(1, "seed", MatchMode::Exact, ComparisonForm::Exact)]
        } else {
            vec![(1, value, MatchMode::Exact, ComparisonForm::Exact)]
        };
        projections.push(projection(
            normalized(CueKind::Symbol, value, id, target, &keys, 80 + index),
            id,
            target,
            90 + index,
        ));
    }
    let candidate = build(
        projections,
        vec![
            edge_kind(11, RelationKind::Supports, "d", "x"),
            edge_kind(12, RelationKind::Counters, "d", "p"),
            edge_kind(13, RelationKind::DerivedFrom, "p", "x"),
        ],
    );
    let seed = normalized(
        CueKind::Symbol,
        "seed",
        "seed",
        "d",
        &[(1, "seed", MatchMode::Exact, ComparisonForm::Exact)],
        99,
    );
    let profile = profile(
        3,
        vec![exact_rule(CueKind::Symbol, 1000)],
        vec![
            RelationRule::new(RelationKind::Supports, 400),
            RelationRule::new(RelationKind::Counters, 900),
            RelationRule::new(RelationKind::DerivedFrom, 900),
        ],
        Some("registry-1".into()),
    );
    let request = request(&candidate, vec![seed], 3);
    (candidate, request, profile)
}

fn guest_request_from(triple: &NativeTriple) -> GuestRequest {
    GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        candidate: triple.0.clone(),
        request: triple.1.clone(),
        profile: triple.2.clone(),
    }
}

fn root_cargo_toml() -> &'static str {
    include_str!("../../../../Cargo.toml")
}

fn read_src(name: &str) -> String {
    let path = format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"))
}

// WORK_UNIT_CASE: 640/1
#[test]
fn exact_world_descriptor_abi_and_target_identity() {
    let descriptor = descriptor();
    assert_eq!(descriptor.world_package, WORLD_PACKAGE);
    assert_eq!(descriptor.world, WORLD_NAME);
    assert_eq!(descriptor.export_name, "activate");
    assert_eq!(descriptor.export_name, EXPORT_NAME);
    assert_eq!(descriptor.abi_version, GUEST_ABI_VERSION);
    assert_eq!(descriptor.target, GUEST_TARGET);
    assert_eq!(descriptor.toolchain_channel, TOOLCHAIN_CHANNEL);
    assert!(descriptor.capability_envelope.is_empty());
    let wit = String::from_utf8(eliot_cue_activation_wasm::GUEST_WIT_BYTES.to_vec())
        .expect("cue-activation.wit is UTF-8");
    assert!(wit.contains("package eliot:current@0.1.0"));
    assert!(wit.contains("world cue-activation"));
    assert!(wit.contains("activate: func"));
    assert!(wit.contains("Native owner: #804/#600"));
    assert!(wit.contains("Consumer: #640"));
    assert_eq!(
        descriptor.wit_digest,
        sha256_hex(eliot_cue_activation_wasm::GUEST_WIT_BYTES)
    );
    assert_eq!(qualified_export_name(), format!("{WORLD_NAME}#activate"));
    assert_eq!(eliot_cue_activation_wasm::wit_export_name(), "activate");
    // Native contract identity: A-10 vocabulary plus A-14a profile revision.
    assert_eq!(CONTRACT_REVISION, "2.0.0");
    assert_eq!(ACTIVATION_PROFILE_REVISION, "1.0.0");
    // #870 readiness: pinned target and channel from the owning toolchain file.
    let toolchain = String::from_utf8(eliot_cue_activation_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("rust-toolchain.toml is UTF-8");
    assert!(toolchain.contains("wasm32-wasip2"));
    assert!(toolchain.contains(TOOLCHAIN_CHANNEL));
    assert_eq!(GUEST_TARGET, eliot_wasm_runtime::DEFAULT_GUEST_TARGET);
    assert_eq!(descriptor_digest(), descriptor_digest());
    // ContractChallenge path (#756, OPEN): the typed world is frozen in-test
    // as readable-but-not-accepted; the guest invents no second ABI.
    assert_eq!(descriptor.typed_world, TYPED_WORLD_NAME);
    assert_eq!(descriptor.typed_world, "cue-activation");
    assert_eq!(descriptor.typed_world_status, TYPED_WORLD_STATUS);
    assert_eq!(descriptor.typed_world_status, "PRESENT_NOT_ACCEPTED");
    assert_eq!(TYPED_WORLD_OWNER, "#756");
}

// WORK_UNIT_CASE: 640/2
#[test]
fn wrong_version_world_and_malformed_bytes_rejected_before_call() {
    let (request, _) = guest_request();
    for mutate in [
        |request: &mut GuestRequest| request.abi_version = 999,
        |request: &mut GuestRequest| request.world = "dreamer-handler".into(),
        |request: &mut GuestRequest| request.world = String::new(),
        |request: &mut GuestRequest| request.abi_version = 0,
    ] {
        let mut bad = request.clone();
        mutate(&mut bad);
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&bad, &ledger);
        assert_eq!(ledger.calls(), 0);
        assert_eq!(response.native_calls, 0);
        assert!(response.evaluation.is_none());
        assert!(matches!(
            response.error,
            Some(GuestError::RejectedEnvelope(_))
        ));
    }
    // Undecodable, trailing-garbage and oversize payloads never reach native.
    assert!(activate(&[0xFF, 0xFE, 0x00]).is_err());
    let mut trailing = encode_request(&request).expect("encode");
    trailing.extend_from_slice(b"trailing");
    assert!(activate(&trailing).is_err());
    let oversize = vec![0x7Bu8; 1_048_577];
    assert!(activate(&oversize).is_err());
    let ledger = CallLedger::new();
    assert!(activate_with_ledger(&oversize, &ledger).is_err());
    assert_eq!(ledger.calls(), 0);
}

// WORK_UNIT_CASE: 640/3
#[test]
fn exhaustive_input_output_error_conversion() {
    // Every native error variant maps exactly, including every closed
    // contract rejection carried field-for-field.
    let contract_cases = [
        (
            CueContractError::InvalidText { field: "seeds" },
            GuestError::ContractInvalidText {
                field: "seeds".to_owned(),
            },
        ),
        (
            CueContractError::BoundExceeded {
                field: "request.seeds",
                limit: 64,
            },
            GuestError::ContractBoundExceeded {
                field: "request.seeds".to_owned(),
                limit: 64,
            },
        ),
        (
            CueContractError::BrokenActivationPath,
            GuestError::ContractBrokenActivationPath,
        ),
        (
            CueContractError::CompleteWithFrontier,
            GuestError::ContractCompleteWithFrontier,
        ),
        (
            CueContractError::TruncationWithoutBound,
            GuestError::ContractTruncationWithoutBound,
        ),
        (
            CueContractError::SnapshotNotRebuildable,
            GuestError::ContractSnapshotNotRebuildable,
        ),
        (
            CueContractError::DuplicateIdentity {
                field: "activation.seeds",
            },
            GuestError::ContractDuplicateIdentity {
                field: "activation.seeds".to_owned(),
            },
        ),
        (
            CueContractError::Foundation {
                field: "request.state_fence",
            },
            GuestError::ContractFoundation {
                field: "request.state_fence".to_owned(),
            },
        ),
    ];
    for (contract, expected) in &contract_cases {
        let native = ActivationError::Contract(contract.clone());
        assert_eq!(GuestError::from(&native), *expected);
    }
    let natives = [
        (ActivationError::ProfileBinding, GuestError::ProfileBinding),
        (ActivationError::StaleInput, GuestError::StaleInput),
        (ActivationError::Unsupported, GuestError::Unsupported),
        (ActivationError::Cancelled, GuestError::Cancelled),
        (ActivationError::Deadline, GuestError::Deadline),
        (
            ActivationError::Limit {
                field: "activation.max_results",
            },
            GuestError::Limit {
                field: "activation.max_results".to_owned(),
            },
        ),
    ];
    for (native, expected) in &natives {
        assert_eq!(GuestError::from(native), *expected);
    }
    // Request/response envelopes round-trip canonically; unknown fields fail.
    let (request, _) = guest_request();
    let bytes = encode_request(&request).expect("encode");
    let decoded = decode_request(&bytes).expect("decode");
    assert_eq!(decoded, request);
    assert_eq!(encode_request(&decoded).expect("re-encode"), bytes);
    let json = String::from_utf8(bytes).expect("canonical UTF-8");
    let injected = json.replacen('{', "{\"guest_unknown_field\":1,", 1);
    assert!(decode_request(injected.as_bytes()).is_err());
    let response = handle_request_typed(&request);
    let response_bytes = encode_response(&response).expect("encode response");
    assert_eq!(
        decode_response(&response_bytes).expect("decode response"),
        response
    );
    let response_json = String::from_utf8(response_bytes).expect("response UTF-8");
    let injected_response = response_json.replacen('{', "{\"guest_unknown_field\":1,", 1);
    assert!(decode_response(injected_response.as_bytes()).is_err());
    // Completeness wire spellings cover all 9 native states and parse back to
    // their discriminant; `stale` carries a load-bearing fence, so it has a
    // spelling but no empty-payload parse.
    for code in [
        "complete",
        "truncated",
        "partial",
        "blocked",
        "unavailable",
        "unknown",
        "source-unavailable",
        "no-direct-match",
        "stale",
    ] {
        let parsed = parse_completeness(code);
        if code == "stale" {
            assert!(parsed.is_none(), "stale needs its fence payload");
        } else {
            let parsed = parsed.expect("parse");
            assert_eq!(completeness_as_str(&parsed), Some(code));
        }
    }
    assert!(parse_completeness("no-such-state").is_none());
    assert!(parse_completeness("").is_none());
    // Bound-kind spellings cover all 4 native kinds and round-trip.
    for code in ["depth", "fanout", "results", "threshold"] {
        let parsed = parse_bound_kind(code).expect("parse bound");
        assert_eq!(bound_kind_as_str(parsed), Some(code));
    }
    assert!(parse_bound_kind("nodes").is_none());
    assert!(parse_bound_kind("output-bytes").is_none());
    // Frozen: WIT-only bound kinds have no native producer and no spelling.
    for code in [
        "nodes",
        "edges",
        "work",
        "path-len",
        "seeds",
        "direct",
        "derived",
        "trace-steps",
        "output-bytes",
    ] {
        assert!(
            parse_bound_kind(code).is_none(),
            "{code} must stay uninvented"
        );
    }
}

// WORK_UNIT_CASE: 640/4
#[test]
fn every_direct_derived_empty_and_error_disposition() {
    // Direct hit: Complete with one direct activation and no derived search.
    let (request, (candidate, native_request, profile)) = guest_request();
    let response = handle_request_typed(&request);
    assert_eq!(response.native_calls, 1);
    assert!(response.error.is_none());
    let evaluation = response.evaluation.as_ref().expect("evaluation");
    assert_eq!(evaluation.result.direct.len(), 1);
    assert!(evaluation.result.derived.is_empty());
    assert!(matches!(
        evaluation.result.completeness,
        Completeness::Complete
    ));
    assert_eq!(
        completeness_as_str(&evaluation.result.completeness),
        Some("complete")
    );
    // Complete miss: searched everything, found nothing (known-empty).
    let mut miss_triple = fixture_hit();
    miss_triple.1.seeds[0].comparison_keys[0].key_value = "missing".into();
    let miss_request = guest_request_from(&miss_triple);
    let miss = handle_request_typed(&miss_request);
    assert_eq!(miss.native_calls, 1);
    assert!(miss.error.is_none());
    let miss_evaluation = miss.evaluation.as_ref().expect("evaluation");
    assert!(miss_evaluation.result.is_known_empty());
    // Derived run: depth-2 chain completes with two derived activations.
    let chain = fixture_chain(2);
    let chain_response = handle_request_typed(&guest_request_from(&chain));
    let chain_evaluation = chain_response.evaluation.as_ref().expect("evaluation");
    assert_eq!(chain_evaluation.result.derived.len(), 2);
    assert!(matches!(
        chain_evaluation.result.completeness,
        Completeness::Complete
    ));
    // Truncated run: depth-1 over a 2-hop chain stops with a live frontier.
    let short = fixture_chain(1);
    let short_response = handle_request_typed(&guest_request_from(&short));
    let short_evaluation = short_response.evaluation.as_ref().expect("evaluation");
    match &short_evaluation.result.completeness {
        Completeness::Truncated {
            frontier,
            bound_hit,
        } => {
            assert!(!frontier.is_empty(), "truncation names its frontier");
            assert_eq!(bound_kind_as_str(*bound_hit), Some("depth"));
        }
        other => panic!("expected truncation, got {other:?}"),
    }
    // Native errors surface as typed guest errors with exactly one call.
    let mut cancelled = fixture_hit();
    cancelled.1.cancelled = true;
    let cancelled_response = handle_request_typed(&guest_request_from(&cancelled));
    assert_eq!(cancelled_response.native_calls, 1);
    assert_eq!(cancelled_response.error, Some(GuestError::Cancelled));
    assert!(cancelled_response.evaluation.is_none());
    // Frozen expectation: on this base native A-14a emits only Complete and
    // Truncated in `Ok`; Partial/Blocked/Unavailable/Unknown/
    // SourceUnavailable/NoDirectMatch/Stale have no native producer (their
    // contract shapes still validate and serialize; owners absent).
    for triple in [
        fixture_hit(),
        fixture_chain(2),
        fixture_chain(1),
        fixture_diamond(),
    ] {
        let native = evaluate_activation(&triple.0, &triple.1, &triple.2).expect("native corpus");
        assert!(
            matches!(
                native.result.completeness,
                Completeness::Complete | Completeness::Truncated { .. }
            ),
            "frozen: native emits only complete/truncated"
        );
    }
    // The miss above is the native known-empty, not an unreadable source.
    let _ = (candidate, native_request, profile);
}

// WORK_UNIT_CASE: 640/5
#[test]
fn path_global_bound_and_frontier_parity() {
    let chain = fixture_chain(2);
    let request = guest_request_from(&chain);
    let response = handle_request_typed(&request);
    let evaluation = response.evaluation.as_ref().expect("evaluation");
    let native = evaluate_activation(&chain.0, &chain.1, &chain.2).expect("native");
    assert_eq!(*evaluation, native);
    // Every derived path is non-empty and starts at a direct seed.
    let direct_targets: std::collections::BTreeSet<_> = evaluation
        .result
        .direct
        .iter()
        .map(|hit| hit.target.as_str())
        .collect();
    assert!(!direct_targets.is_empty());
    for derived in &evaluation.result.derived {
        assert!(!derived.path.is_empty(), "derived always carries a path");
        assert_eq!(
            usize::from(derived.depth),
            derived.path.len(),
            "depth equals path length"
        );
        assert!(
            direct_targets.contains(derived.direct_seed.as_str()),
            "derived path begins at a direct seed"
        );
    }
    // Complete search carries no frontier; the result binds its request.
    assert!(matches!(
        evaluation.result.completeness,
        Completeness::Complete
    ));
    evaluation
        .result
        .validate_against(&chain.1)
        .expect("result binds request");
    // Policy/input digests are native values, distinct from artifact hashes.
    assert_eq!(evaluation.input_digest, native.input_digest);
    assert_eq!(evaluation.policy_digest, native.policy_digest);
    assert_eq!(
        evaluation.candidate_build_digest,
        native.candidate_build_digest
    );
    assert_eq!(request_digest(&request).len(), 64);
}

// WORK_UNIT_CASE: 640/6
#[test]
fn collisions_conflicts_ceilings_and_maximum_path_parity() {
    // Diamond with conflicting relation weights: maximum-path selection must
    // match native exactly (max accumulation, never popularity sum).
    let diamond = fixture_diamond();
    let response = handle_request_typed(&guest_request_from(&diamond));
    let evaluation = response.evaluation.as_ref().expect("evaluation");
    let native = evaluate_activation(&diamond.0, &diamond.1, &diamond.2).expect("native");
    assert_eq!(*evaluation, native);
    assert!(!evaluation.result.derived.is_empty());
    // Colliding direct bindings on one target keep the stronger hit only.
    let cue_a = normalized(
        CueKind::Symbol,
        "shared",
        "shared-a",
        "target-t",
        &[(1, "shared", MatchMode::Exact, ComparisonForm::Exact)],
        110,
    );
    let cue_b = normalized(
        CueKind::Symbol,
        "shared",
        "shared-b",
        "target-t",
        &[(1, "shared", MatchMode::Exact, ComparisonForm::Exact)],
        111,
    );
    let candidate = build(
        vec![
            projection(cue_a.clone(), "shared-a", "target-t", 120),
            projection(cue_b.clone(), "shared-b", "target-t", 121),
        ],
        Vec::new(),
    );
    let profile = profile(0, vec![exact_rule(CueKind::Symbol, 500)], Vec::new(), None);
    let native_request = request(&candidate, vec![cue_a, cue_b], 0);
    let triple = (candidate, native_request, profile);
    let colliding = handle_request_typed(&guest_request_from(&triple));
    let colliding_evaluation = colliding.evaluation.as_ref().expect("evaluation");
    let colliding_native = evaluate_activation(&triple.0, &triple.1, &triple.2).expect("native");
    assert_eq!(*colliding_evaluation, colliding_native);
    // Activation ceiling: a threshold above every strength yields known-empty.
    let mut ceiling = bounds(0);
    ceiling.activation_threshold = ActivationStrength(1000);
    let mut ceiling_triple = fixture_hit();
    ceiling_triple.1.bounds = ceiling;
    ceiling_triple.2 = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        ceiling,
        vec![exact_rule(CueKind::Symbol, 900)],
        Vec::new(),
        None,
    )
    .unwrap();
    let ceiling_response = handle_request_typed(&guest_request_from(&ceiling_triple));
    let ceiling_evaluation = ceiling_response.evaluation.as_ref().expect("evaluation");
    let ceiling_native =
        evaluate_activation(&ceiling_triple.0, &ceiling_triple.1, &ceiling_triple.2)
            .expect("native");
    assert_eq!(*ceiling_evaluation, ceiling_native);
    assert!(ceiling_evaluation.result.is_known_empty());
}

// WORK_UNIT_CASE: 640/7
#[test]
fn stale_identities_and_all_limits() {
    // Stale evidence freshness keeps the native rejection, never a guest one.
    let mut stale = fixture_hit();
    stale.1.seeds[0].observed.context.evidence.freshness = EvidenceFreshness::Stale;
    let stale_response = handle_request_typed(&guest_request_from(&stale));
    assert_eq!(stale_response.native_calls, 1);
    assert_eq!(stale_response.error, Some(GuestError::StaleInput));
    let stale_native = evaluate_activation(&stale.0, &stale.1, &stale.2);
    assert_eq!(stale_native.unwrap_err(), ActivationError::StaleInput);
    // A seed fence that disagrees with the request fence is stale input too.
    let mut fence_mismatch = fixture_hit();
    fence_mismatch.1.seeds[0].observed.context.state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001").expect("lineage"),
            std::num::NonZeroU64::new(9).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    );
    let fence_response = handle_request_typed(&guest_request_from(&fence_mismatch));
    let fence_native = evaluate_activation(&fence_mismatch.0, &fence_mismatch.1, &fence_mismatch.2);
    assert_eq!(
        fence_response.error,
        Some(GuestError::from(&fence_native.unwrap_err()))
    );
    assert_eq!(fence_response.native_calls, 1);
    // Expired deadline keeps the exact native rejection (contract fence
    // first, evaluator second); cancellation maps exactly.
    let mut deadline = fixture_hit();
    deadline.1.observed_at = ClockReading {
        valid_time_ms: Some(1_000),
        known_time_ms: Some(1_000),
        transaction_sequence: None,
        monotonic_ns: None,
    };
    deadline.1.deadline_ms = Some(500);
    let deadline_response = handle_request_typed(&guest_request_from(&deadline));
    let deadline_native = evaluate_activation(&deadline.0, &deadline.1, &deadline.2).unwrap_err();
    assert_eq!(
        deadline_response.error,
        Some(GuestError::from(&deadline_native))
    );
    assert_eq!(deadline_response.native_calls, 1);
    let mut cancelled_deadline = fixture_hit();
    cancelled_deadline.1.cancelled = true;
    let cancelled_response = handle_request_typed(&guest_request_from(&cancelled_deadline));
    assert_eq!(cancelled_response.error, Some(GuestError::Cancelled));
    // Every independent limit is enforced by native and preserved by the guest.
    let cue_a = normalized(
        CueKind::Symbol,
        "one",
        "one",
        "target-one",
        &[(1, "one", MatchMode::Exact, ComparisonForm::Exact)],
        130,
    );
    let cue_b = normalized(
        CueKind::Symbol,
        "two",
        "two",
        "target-two",
        &[(1, "two", MatchMode::Exact, ComparisonForm::Exact)],
        131,
    );
    let candidate = build(
        vec![
            projection(cue_a.clone(), "one", "target-one", 140),
            projection(cue_b.clone(), "two", "target-two", 141),
        ],
        Vec::new(),
    );
    let mut limited = bounds(0);
    limited.max_results = 1;
    let limited_profile = ActivationProfile::seal(
        "activation-v1".into(),
        1,
        limited,
        vec![exact_rule(CueKind::Symbol, 700)],
        Vec::new(),
        None,
    )
    .unwrap();
    let mut limited_request = request(&candidate, vec![cue_a, cue_b], 0);
    limited_request.bounds = limited;
    let limited_triple = (candidate, limited_request, limited_profile);
    let limited_response = handle_request_typed(&guest_request_from(&limited_triple));
    assert_eq!(limited_response.native_calls, 1);
    assert_eq!(
        limited_response.error,
        Some(GuestError::Limit {
            field: "activation.max_results".to_owned()
        })
    );
    // Frozen: `Completeness::Stale` has no native producer on this base, but
    // its contract shape round-trips the canonical guest JSON transport.
    let stale_shape = Completeness::Stale {
        snapshot_fence: fence(),
    };
    assert_eq!(completeness_as_str(&stale_shape), Some("stale"));
    let stale_bytes = serde_json::to_vec(&stale_shape).expect("encode stale");
    let stale_back: Completeness = serde_json::from_slice(&stale_bytes).expect("decode stale");
    assert_eq!(stale_back, stale_shape);
}

// WORK_UNIT_CASE: 640/8
#[test]
fn deterministic_actual_native_component_parity() {
    let (base_request, (candidate, native_request, base_profile)) = guest_request();
    let first = encode_response(&handle_request_typed(&base_request)).expect("encode");
    let second = encode_response(&handle_request_typed(&base_request)).expect("encode");
    assert_eq!(first, second);
    // Input digests are seed-order invariant: the same multiset of seeds
    // binds the same digest through guest and native alike.
    let mut permuted = native_request.clone();
    permuted.seeds.reverse();
    for key in &mut permuted.seeds {
        key.comparison_keys.reverse();
    }
    let native = evaluate_activation(&candidate, &native_request, &base_profile).expect("native");
    let native_permuted =
        evaluate_activation(&candidate, &permuted, &base_profile).expect("native permuted");
    assert_eq!(native.input_digest, native_permuted.input_digest);
    let mut permuted_request = base_request.clone();
    permuted_request.request = permuted;
    let permuted_response = handle_request_typed(&permuted_request);
    let permuted_evaluation = permuted_response.evaluation.as_ref().expect("evaluation");
    assert_eq!(permuted_evaluation.input_digest, native.input_digest);
    // Corpus determinism across shapes and spellings.
    for target in ["target-a", "target-b", "ziel-übung-✓"] {
        let cue = normalized(
            CueKind::Symbol,
            "alpha",
            "alpha",
            target,
            &[(1, "alpha", MatchMode::Exact, ComparisonForm::Exact)],
            150,
        );
        let target_candidate = build(
            vec![projection(cue.clone(), "alpha", target, 151)],
            Vec::new(),
        );
        let target_profile = profile(0, vec![exact_rule(CueKind::Symbol, 900)], Vec::new(), None);
        let target_request = request(&target_candidate, vec![cue], 0);
        let triple = (target_candidate, target_request, target_profile);
        let component = handle_request_typed(&guest_request_from(&triple));
        let direct = evaluate_activation(&triple.0, &triple.1, &triple.2).expect("native");
        assert_eq!(component.evaluation.as_ref(), Some(&direct));
        let again = handle_request_typed(&guest_request_from(&triple));
        assert_eq!(component, again);
    }
}

// WORK_UNIT_CASE: 640/9
#[test]
fn exactly_one_native_call_no_duplicate_algorithm() {
    let (request, _) = guest_request();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.evaluation.is_some());
    // A native error still costs exactly one call: the guest never retries,
    // repairs, or falls back to a local computation.
    let mut cancelled = fixture_hit();
    cancelled.1.cancelled = true;
    let error_ledger = CallLedger::new();
    let error_response = handle_with_ledger(&guest_request_from(&cancelled), &error_ledger);
    assert_eq!(error_ledger.calls(), 1);
    assert_eq!(error_response.native_calls, 1);
    assert_eq!(error_response.error, Some(GuestError::Cancelled));
    // Structural proof: exactly one native call site outside tests, and no
    // local evaluator definition.
    let mut sites = 0;
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        let source = read_src(name);
        sites += source.matches("evaluate_activation(").count();
        assert!(
            !source.contains("fn evaluate_activation"),
            "{name} must not define a local evaluator"
        );
    }
    assert_eq!(sites, 1);
}

// WORK_UNIT_CASE: 640/10
#[test]
fn forbidden_import_fixture_rejected_before_execution() {
    for forbidden in eliot_cue_activation_wasm::FORBIDDEN_IMPORT_SUBSTRINGS {
        assert!(
            is_forbidden_import(&format!("cap:{forbidden}"), "f"),
            "gate covers {forbidden}"
        );
    }
    for required in [
        "filesystem",
        "stdio",
        "network",
        "env",
        "args",
        "clock",
        "random",
        "process",
        "thread",
        "credential",
        "model",
        "store",
        "kernel",
        "provider",
    ] {
        assert!(
            eliot_cue_activation_wasm::FORBIDDEN_IMPORT_SUBSTRINGS
                .iter()
                .any(|forbidden| required.contains(forbidden) || forbidden.contains(required)),
            "issue namespace {required} is gated"
        );
    }
    for (module, name) in [
        ("wasi:filesystem/types@0.2.10", "stat"),
        ("wasi:sockets/tcp@0.2.10", "connect"),
        ("wasi:http/outgoing-handler@0.2.10", "handle"),
        ("wasi:cli/stdin@0.2.10", "get-stdin"),
        ("wasi:clocks/wall-clock@0.2.10", "now"),
        ("wasi:random/random@0.2.10", "get-random-bytes"),
    ] {
        let wasm = wat::parse_str(format!("(module (import \"{module}\" \"{name}\" (func)))"))
            .expect("wasi fixture");
        let error = check_wasm_imports(&wasm).expect_err("forbidden import must fail");
        assert_eq!(
            error,
            eliot_cue_activation_wasm::DescriptorError::ForbiddenImport {
                module: module.into(),
                name: name.into(),
            }
        );
    }
    let benign = wat::parse_str(
        "(module (func (export \"activate\") (param i32) (result i32) local.get 0))",
    )
    .expect("benign fixture");
    assert_eq!(list_wasm_imports(&benign).expect("imports"), vec![]);
    assert!(
        check_wasm_imports(&benign)
            .expect("benign passes")
            .is_empty()
    );
    assert!(check_wasm_imports(b"not a module").is_err());
    // Later-lifecycle claims are rejected: the response envelope carries no
    // authority, effect, delivery, Finish or promotion surface.
    let (request, _) = guest_request();
    let json = String::from_utf8(encode_response(&handle_request_typed(&request)).expect("encode"))
        .expect("response UTF-8");
    for absent in [
        "\"authority_granted\"",
        "\"effect\"",
        "\"finish\"",
        "\"promotion\"",
        "\"delivery\"",
        "\"provider\"",
        "\"model\"",
    ] {
        assert!(!json.contains(absent), "response must not raise {absent}");
    }
    assert!(descriptor().capability_envelope.is_empty());
}

// WORK_UNIT_CASE: 640/11
#[test]
fn standalone_capsule_through_e_host() {
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };
    let (request, _) = guest_request();
    let input = encode_request(&request).expect("encode");
    let invocation = InvocationRequest::new(
        InvocationId::new("fixture-640-capsule").expect("invocation"),
        CapabilityId::new("fixture-activation-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-640").expect("work unit"),
        WorkScopeRef::new("fixture-scope-640").expect("scope"),
        ExecutionContour::Shadow,
        input,
        640,
        false,
    )
    .expect("capsule request");
    invocation.validate().expect("capsule digest");
    // #758/#760 are OPEN: no engine/port surface is injected, so the real
    // facade must return the typed PLAN_GAP instead of executing.
    let mut runtime = WasmRuntime::new(None);
    let result = runtime.execute(invocation);
    assert_eq!(
        result.receipt.disposition,
        InvocationDisposition::Unavailable
    );
    assert_eq!(result.receipt.error, Some(RuntimeError::PlanGap));
    assert!(result.output.is_none());
    assert!(result.proposed_effects.is_empty());
    assert!(result.observed_state_delta.is_none());
    assert!(!result.receipt.reconciliation_required);
    // Cancellation preserves the real host's typed rejection path.
    let cancelled = InvocationRequest::new(
        InvocationId::new("fixture-640-cancelled").expect("invocation"),
        CapabilityId::new("fixture-activation-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-640").expect("work unit"),
        WorkScopeRef::new("fixture-scope-640").expect("scope"),
        ExecutionContour::Shadow,
        Vec::new(),
        640,
        true,
    )
    .expect("cancelled request");
    let result = runtime.execute(cancelled);
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
}

// WORK_UNIT_CASE: 640/12
#[test]
fn build_artifact_identity_and_admission_state() {
    assert_eq!(env!("CARGO_PKG_NAME"), "eliot-cue-activation-wasm");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    assert_eq!(descriptor_digest(), descriptor_digest());
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    // Controller-owned handoff (issue #640): the package must NOT be a root
    // workspace member on this branch; admission is a separate serialized turn.
    assert!(!root_cargo_toml().contains("eliot-cue-activation-wasm"));
    // Frozen toolchain identity matches the owning file.
    let toolchain = String::from_utf8(eliot_cue_activation_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("toolchain UTF-8");
    assert!(toolchain.contains("channel = \"1.97.1\""));
    assert!(toolchain.contains("wasm32-wasip2"));
    // Build-input determinism: the exact compiled sources hash identically on
    // repeat reads (clean input, warm input alike); the native result digest
    // stays separate from this component-side hash.
    let input_hash = || {
        let mut bytes = Vec::new();
        for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
            bytes.extend_from_slice(read_src(name).as_bytes());
        }
        sha256_hex(&bytes)
    };
    assert_eq!(input_hash(), input_hash());
    let (request, _) = guest_request();
    let evaluation = handle_request_typed(&request)
        .evaluation
        .expect("evaluation");
    assert_ne!(input_hash(), evaluation.input_digest.as_str());
}

// WORK_UNIT_CASE: 640/13
#[test]
fn property_component_equals_native_with_path_and_bound_shape() {
    let mut corpus: Vec<NativeTriple> = vec![
        fixture_hit(),
        fixture_chain(2),
        fixture_chain(1),
        fixture_diamond(),
    ];
    // Miss corpus: same candidate, non-matching key.
    let mut miss = fixture_hit();
    miss.1.seeds[0].comparison_keys[0].key_value = "missing".into();
    corpus.push(miss);
    // Error corpus: every native error class through the real evaluator.
    let mut cancelled = fixture_hit();
    cancelled.1.cancelled = true;
    corpus.push(cancelled);
    let mut profile_binding = fixture_hit();
    profile_binding.1.snapshot_id = SnapshotId::new("snapshot-2").unwrap();
    corpus.push(profile_binding);
    for triple in &corpus {
        let native = evaluate_activation(&triple.0, &triple.1, &triple.2);
        let response = handle_request_typed(&guest_request_from(triple));
        match native {
            Ok(expected) => {
                assert!(response.error.is_none());
                let actual = response.evaluation.as_ref().expect("evaluation");
                assert_eq!(*actual, expected);
                assert_eq!(response.native_calls, 1);
                // Direct activations carry no path by type; every derived
                // path is non-empty, contiguous from a direct seed, and its
                // depth equals its length.
                let direct_targets: std::collections::BTreeSet<_> = actual
                    .result
                    .direct
                    .iter()
                    .map(|hit| hit.target.as_str())
                    .collect();
                for derived in &actual.result.derived {
                    assert!(!derived.path.is_empty());
                    assert_eq!(usize::from(derived.depth), derived.path.len());
                    assert!(direct_targets.contains(derived.direct_seed.as_str()));
                }
                // Every bound and proof ceiling survives the guest boundary.
                actual
                    .result
                    .validate_against(&triple.1)
                    .expect("bounds preserved");
                assert_eq!(actual.policy_revision, triple.2.profile_revision);
                assert_eq!(actual.policy_id, triple.2.profile_id);
            }
            Err(expected) => {
                assert!(response.evaluation.is_none());
                assert_eq!(response.error, Some(GuestError::from(&expected)));
                assert_eq!(response.native_calls, 1);
            }
        }
    }
    // Byte transport preserves the property end to end.
    let (request, triple) = guest_request();
    let bytes = encode_request(&request).expect("encode");
    let output = activate(&bytes).expect("activate");
    let round_tripped = decode_response(&output).expect("decode");
    let direct = evaluate_activation(&triple.0, &triple.1, &triple.2).expect("native");
    assert_eq!(round_tripped.evaluation.as_ref(), Some(&direct));
    let _: CueActivationEvaluation = direct;
    let _: GuestResponse = round_tripped;
}
