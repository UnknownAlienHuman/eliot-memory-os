//! Behaviour rules of the cue vocabulary, one test per rule.
//!
//! Each test name appears verbatim in `module.toml` under
//! `[acceptance].required_tests`, so a rule cannot be dropped without the gate
//! noticing.

// Assertions in a test use `expect`/`unwrap` deliberately; the workspace lints
// target production paths.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, SourceId, StateFence};
use eliot_cue_contracts::{
    ActivationBounds, ActivationRequest, ActivationRequestId, ActivationResult, ActivationStrength,
    ActivationTrace, BindingCandidateId, BindingDisposition, BindingRole, BoundKind,
    CanonicalCueId, CanonicalCueIdentity, ComparisonKey, ComparisonKeyId, Completeness,
    CueBindingCandidate, CueContractError, CueKind, CueSnapshot, DerivedActivation, Digest,
    DirectActivation, MAX_COMPARISON_KEYS, MatchMode, NormalizationOutcome, NormalizationProfile,
    NormalizedCue, ObservedCue, ObservedCueId, RebuildIdentity, RelationEdgeId, RelationEdgeInput,
    SnapshotId, SnapshotMember, SourceHandle, TargetHandle,
};
use eliot_evidence::{EvidenceFreshness, Provenance};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REVISION: &str = "1.0.0";

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("64 hex characters")
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn provenance() -> Provenance {
    Provenance {
        source_id: SourceId::new("eliot-cue-contracts-tests").expect("source id"),
        capture_route: "unit-test".to_owned(),
        scope: "crates/smart/eliot-cue-contracts".to_owned(),
        raw_handle: None,
        revision: None,
    }
}

fn source() -> SourceHandle {
    SourceHandle::new(
        TargetHandle::new("crates/smart/eliot-cue-contracts/src/lib.rs").expect("target"),
        digest(0xa1),
        provenance(),
    )
}

fn observed(value: &str) -> ObservedCue {
    ObservedCue::new(
        REVISION.to_owned(),
        ObservedCueId::new("observed-1").expect("id"),
        CueKind::Symbol,
        value.to_owned(),
        source(),
        fence(),
    )
}

fn profile() -> NormalizationProfile {
    NormalizationProfile::new("symbol-v1".to_owned(), 1, digest(0xb2))
}

fn canonical(value: &str, seed: u8) -> CanonicalCueIdentity {
    CanonicalCueIdentity::new(
        CanonicalCueId::new(format!("canonical-{seed}")).expect("id"),
        CueKind::Symbol,
        value.to_owned(),
        digest(seed),
    )
}

fn key(value: &str, mode: MatchMode, seed: u8) -> ComparisonKey {
    ComparisonKey::new(
        ComparisonKeyId::new(format!("key-{seed}")).expect("id"),
        profile(),
        value.to_owned(),
        mode,
    )
}

fn normalized(value: &str, keys: Vec<ComparisonKey>) -> NormalizedCue {
    NormalizedCue::new(
        REVISION.to_owned(),
        observed(value),
        canonical(value, 0xc3),
        keys,
        NormalizationOutcome::Lossless,
        Vec::new(),
    )
}

fn edge(index: usize) -> RelationEdgeId {
    RelationEdgeId::new(format!("edge-{index}")).expect("edge id")
}

fn request(edges: Vec<RelationEdgeInput>, depth: u8) -> ActivationRequest {
    ActivationRequest::new(
        REVISION.to_owned(),
        ActivationRequestId::new("request-1").expect("id"),
        vec![normalized(
            "TaskContract",
            vec![key("taskcontract", MatchMode::CaseInsensitive, 1)],
        )],
        SnapshotId::new("snapshot-1").expect("id"),
        edges,
        ActivationBounds::new(depth, 16, 64, ActivationStrength(1)),
        fence(),
    )
}

fn direct_hit() -> DirectActivation {
    DirectActivation::new(
        TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
        key("taskcontract", MatchMode::CaseInsensitive, 1),
        ActivationStrength(10),
    )
}

fn result(
    direct: Vec<DirectActivation>,
    derived: Vec<DerivedActivation>,
    completeness: Completeness,
) -> ActivationResult {
    ActivationResult::new(
        REVISION.to_owned(),
        ActivationRequestId::new("request-1").expect("id"),
        direct,
        derived,
        completeness,
        ActivationTrace::empty(),
    )
}

fn snapshot_with(recorded: Digest) -> CueSnapshot {
    CueSnapshot::new(
        REVISION.to_owned(),
        SnapshotId::new("snapshot-1").expect("id"),
        vec![SnapshotMember::new(
            canonical("TaskContract", 0xc3),
            TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
        )],
        RebuildIdentity::new(profile(), vec![source()], recorded),
        fence(),
    )
}

// Rule 1 -------------------------------------------------------------------
#[test]
fn observed_cue_rejects_unknown_field() -> TestResult {
    let accepted = serde_json::to_string(&observed("TaskContract"))?;
    serde_json::from_str::<ObservedCue>(&accepted)?;

    let with_extra = accepted.replace(
        "{\"schema_revision\"",
        "{\"smuggled\":1,\"schema_revision\"",
    );
    assert_ne!(
        accepted, with_extra,
        "the fixture must actually gain a field"
    );
    let rejected = serde_json::from_str::<ObservedCue>(&with_extra);
    assert!(
        rejected.is_err(),
        "an unknown field must be rejected, not ignored"
    );
    Ok(())
}

// Rule 2 -------------------------------------------------------------------
#[test]
fn canonical_identity_differs_from_comparison_key() -> TestResult {
    // A single exact key equal to the canonical value has collapsed the two
    // roles: lookup would then depend on the spelling the canonical form exists
    // to preserve.
    let collapsed = normalized(
        "TaskContract",
        vec![key("TaskContract", MatchMode::Exact, 1)],
    );
    assert_eq!(
        collapsed.validate(),
        Err(CueContractError::IdentityCollapsedIntoKey)
    );

    // The same canonical value with a folded key is the intended shape.
    let distinct = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::CaseInsensitive, 1)],
    );
    distinct.validate()?;
    assert_ne!(
        distinct.canonical.canonical_value,
        distinct.comparison_keys[0].key_value
    );
    Ok(())
}

// Rule 3 -------------------------------------------------------------------
#[test]
fn snapshot_rebuild_digest_is_stable() -> TestResult {
    let snapshot = snapshot_with(digest(0xd4));
    let first = snapshot.recompute_digest_input();
    let second = snapshot.recompute_digest_input();
    assert_eq!(first, second, "rebuild input must be deterministic");

    snapshot.validate(&|_| digest(0xd4).as_str().to_owned())?;
    Ok(())
}

// Rule 4 -------------------------------------------------------------------
#[test]
fn snapshot_with_wrong_digest_is_rejected() {
    let snapshot = snapshot_with(digest(0xd4));
    let outcome = snapshot.validate(&|_| digest(0xe5).as_str().to_owned());
    assert_eq!(outcome, Err(CueContractError::SnapshotNotRebuildable));
}

// Rule 5 -------------------------------------------------------------------
#[test]
fn direct_activation_valid_with_zero_edges() -> TestResult {
    let direct_only = request(Vec::new(), 0);
    direct_only.validate()?;
    assert!(direct_only.is_direct_only());
    assert!(direct_only.relation_edges.is_empty());

    let answered = result(vec![direct_hit()], Vec::new(), Completeness::Complete);
    answered.validate()?;
    assert_eq!(answered.direct.len(), 1);
    Ok(())
}

// Rule 6 -------------------------------------------------------------------
#[test]
fn direct_and_derived_are_not_interchangeable() -> TestResult {
    let direct = direct_hit();
    let derived =
        DerivedActivation::new(direct.target.clone(), vec![edge(1)], ActivationStrength(4));

    // Both reach the same target, and the records are still different shapes:
    // only the derived one carries a path, and only the direct one a matched key.
    assert_eq!(derived.path.len(), 1);
    assert_eq!(derived.depth, 1);

    let direct_json = serde_json::to_value(&direct)?;
    let derived_json = serde_json::to_value(&derived)?;
    assert!(direct_json.get("path").is_none());
    assert!(derived_json.get("matched_key").is_none());
    Ok(())
}

// Rule 7 -------------------------------------------------------------------
#[test]
fn broken_derived_path_is_rejected() {
    let empty_path = result(
        vec![direct_hit()],
        vec![DerivedActivation::new(
            TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
            Vec::new(),
            ActivationStrength(2),
        )],
        Completeness::Complete,
    );
    assert_eq!(
        empty_path.validate(),
        Err(CueContractError::BrokenActivationPath)
    );

    let depth_disagrees = result(
        vec![direct_hit()],
        vec![DerivedActivation::from_parts(
            TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
            vec![edge(1), edge(2)],
            1,
            ActivationStrength(2),
        )],
        Completeness::Complete,
    );
    assert_eq!(
        depth_disagrees.validate(),
        Err(CueContractError::BrokenActivationPath)
    );
}

// Rule 8 -------------------------------------------------------------------
#[test]
fn complete_result_cannot_carry_frontier() {
    let complete = result(vec![direct_hit()], Vec::new(), Completeness::Complete);
    assert_eq!(
        complete.validate_completeness(&[edge(9)]),
        Err(CueContractError::CompleteWithFrontier)
    );
    assert!(complete.validate_completeness(&[]).is_ok());
}

// Rule 9 -------------------------------------------------------------------
#[test]
fn truncation_names_the_bound_it_hit() -> TestResult {
    let truncated = result(
        vec![direct_hit()],
        Vec::new(),
        Completeness::Truncated {
            frontier: vec![edge(7)],
            bound_hit: BoundKind::Fanout,
        },
    );
    truncated.validate()?;
    match &truncated.completeness {
        Completeness::Truncated {
            bound_hit,
            frontier,
        } => {
            assert_eq!(*bound_hit, BoundKind::Fanout);
            assert!(
                !frontier.is_empty(),
                "a truncation must say where to resume"
            );
        }
        other => panic!("expected a truncation, got {other:?}"),
    }

    let silent = result(
        Vec::new(),
        Vec::new(),
        Completeness::Truncated {
            frontier: Vec::new(),
            bound_hit: BoundKind::Depth,
        },
    );
    assert_eq!(
        silent.validate(),
        Err(CueContractError::TruncationWithoutBound)
    );
    Ok(())
}

// Rule 10 ------------------------------------------------------------------
#[test]
fn known_empty_differs_from_unavailable() {
    let searched_and_found_nothing = result(Vec::new(), Vec::new(), Completeness::Complete);
    assert!(searched_and_found_nothing.is_known_empty());

    let could_not_read = result(
        Vec::new(),
        Vec::new(),
        Completeness::SourceUnavailable {
            reason: "snapshot store unreachable".to_owned(),
        },
    );
    assert!(
        !could_not_read.is_known_empty(),
        "an unreadable snapshot is an unknown, not an empty answer"
    );

    let stopped_early = result(
        Vec::new(),
        Vec::new(),
        Completeness::Truncated {
            frontier: vec![edge(1)],
            bound_hit: BoundKind::Results,
        },
    );
    assert!(!stopped_early.is_known_empty());

    let older_than_the_fence = result(
        Vec::new(),
        Vec::new(),
        Completeness::Stale {
            snapshot_fence: fence(),
        },
    );
    assert!(!older_than_the_fence.is_known_empty());
}

// Rule 11 ------------------------------------------------------------------
#[test]
fn every_collection_bound_is_enforced() {
    let folded = |count: usize| {
        (0..count)
            .map(|index| {
                key(
                    &format!("folded-{index}"),
                    MatchMode::CaseInsensitive,
                    u8::try_from(index).unwrap_or(u8::MAX),
                )
            })
            .collect::<Vec<_>>()
    };

    let over_bound = normalized("TaskContract", folded(MAX_COMPARISON_KEYS + 1));
    assert_eq!(
        over_bound.validate(),
        Err(CueContractError::BoundExceeded {
            field: "comparison_keys",
            limit: MAX_COMPARISON_KEYS,
        })
    );

    let at_bound = normalized("TaskContract", folded(MAX_COMPARISON_KEYS));
    assert!(
        at_bound.validate().is_ok(),
        "the bound itself must be legal"
    );
}

// Rule 12 ------------------------------------------------------------------
#[test]
fn identity_inputs_change_the_digest() {
    let base = snapshot_with(digest(0xd4));

    let mut other_profile = snapshot_with(digest(0xd4));
    other_profile.rebuild.normalization_profile.profile_revision = 2;
    assert_ne!(
        base.recompute_digest_input(),
        other_profile.recompute_digest_input(),
        "a profile revision change must change the rebuild input"
    );

    let mut other_member = snapshot_with(digest(0xd4));
    other_member.members[0].target =
        TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target");
    assert_ne!(
        base.recompute_digest_input(),
        other_member.recompute_digest_input(),
        "a member change must change the rebuild input"
    );
}

// Rule 13 ------------------------------------------------------------------
#[test]
fn cue_kind_covers_the_declared_vocabulary() -> TestResult {
    // This cell is the Level-0 owner of the cue vocabulary (`depends_on = []`),
    // so it defines the kind. `crates/eliot-types/src/ul/cue.rs` carries a
    // parallel definition for the shipped path; F-CUE reconciles them, and this
    // test pins the variant set so that reconciliation has a fixed target.
    let declared = [
        (CueKind::FilePath, "file_path"),
        (CueKind::DirPath, "dir_path"),
        (CueKind::Symbol, "symbol"),
        (CueKind::ErrorSignature, "error_signature"),
        (CueKind::CommandPattern, "command_pattern"),
        (CueKind::Dependency, "dependency"),
        (CueKind::ApiSurface, "api_surface"),
        (CueKind::TaskClass, "task_class"),
        (CueKind::Subsystem, "subsystem"),
        (CueKind::Concept, "concept"),
    ];
    assert_eq!(declared.len(), 10);
    for (kind, wire) in declared {
        assert_eq!(serde_json::to_value(kind)?, serde_json::json!(wire));
    }
    Ok(())
}

// Rule 14 ------------------------------------------------------------------
#[test]
fn malformed_input_never_panics() {
    for payload in [
        "",
        "null",
        "{}",
        "[]",
        "{\"schema_revision\":null}",
        "{\"schema_revision\":\"1.0.0\",\"observed_cue_id\":\"\"}",
        "\u{feff}{\"schema_revision\":\"1.0.0\"}",
        "{\"schema_revision\":\"1.0.0\",\"kind\":\"not_a_kind\"}",
    ] {
        let observed = serde_json::from_str::<ObservedCue>(payload);
        assert!(
            observed.is_err(),
            "{payload:?} must be rejected, not accepted"
        );
        let activation = serde_json::from_str::<ActivationResult>(payload);
        assert!(activation.is_err(), "{payload:?} must be rejected");
    }

    // Blank and control-character identities are rejected at construction.
    assert!(ObservedCueId::new("").is_err());
    assert!(ObservedCueId::new("has\u{0}control").is_err());
    assert!(Digest::new("nothex").is_err());
    assert!(
        Digest::new("A".repeat(64)).is_err(),
        "digests are lowercase"
    );
}

// Rule 15 ------------------------------------------------------------------
#[test]
fn consumer_fixture_compiles_standalone() -> TestResult {
    // A consumer stands in for A-11/A-12/A-13/A-14a/A-16a: it reads a request,
    // proposes a binding, and writes a result using this vocabulary alone. If
    // this compiles, the public surface is sufficient without importing any
    // consumer crate.
    fn propose(cue: &NormalizedCue, target: TargetHandle) -> CueBindingCandidate {
        CueBindingCandidate::new(
            BindingCandidateId::new("candidate-1").expect("id"),
            cue.canonical.clone(),
            target,
            BindingRole::Names,
            EvidenceFreshness::ExactCandidate,
            BindingDisposition::Admitted,
            digest(0xf6),
        )
    }

    fn evaluate(request: &ActivationRequest) -> Result<ActivationResult, CueContractError> {
        request.validate()?;
        let answer = ActivationResult::new(
            request.schema_revision.clone(),
            request.request_id.clone(),
            Vec::new(),
            Vec::new(),
            Completeness::Complete,
            ActivationTrace::empty(),
        );
        answer.validate()?;
        Ok(answer)
    }

    let asked = request(
        vec![RelationEdgeInput::new(
            edge(1),
            TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
            TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
        )],
        1,
    );
    let candidate = propose(
        &asked.seeds[0],
        TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
    );
    candidate.validate()?;
    assert_eq!(candidate.disposition, BindingDisposition::Admitted);

    let answered = evaluate(&asked)?;
    assert!(answered.is_known_empty());
    Ok(())
}
