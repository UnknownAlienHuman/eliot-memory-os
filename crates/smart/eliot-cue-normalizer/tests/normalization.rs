//! Focused A-11 proofs for deterministic, lossless normalization.
//!
//! 48-case work-unit matrix for issue 598: one substantive independently
//! executable test per required case, built only on the exact A-10 public
//! contracts and the single shared `normalize_cue` owner.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence, TaskId, canonical_json_bytes,
};
use eliot_cue_contracts::{
    CONTRACT_REVISION, CanonicalCueId, CanonicalCueIdentity, ComparisonForm, ComparisonKey,
    ComparisonKeyId, CueContext, CueKind, Digest, MatchMode, NormalizationOutcome,
    NormalizationProfile, NormalizedCue, ObservedCue, ObservedCueId, PrivacyClass, SourceHandle,
    TargetHandle, WorkScopeId,
};
use eliot_cue_normalizer::{
    A11_CONTRACT_REVISION, CasePolicy, MAX_POLICY_ID_BYTES, NormalizationEnvelope,
    NormalizationError, NormalizationPolicy, NormalizationRule, PolicyRule, SeparatorPolicy,
    capture_cue, comparison_key, fire_cue, normalize_cue, source_value,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

fn fence_at(sequence: u64) -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn provenance() -> Provenance {
    Provenance {
        source_id: SourceId::new("normalizer-tests").expect("source"),
        capture_route: "test".to_owned(),
        scope: "normalizer".to_owned(),
        raw_handle: None,
        revision: None,
    }
}

fn context() -> CueContext {
    context_with("task-1", "scope-1", PrivacyClass::Public)
}

fn context_with(task: &str, scope: &str, privacy: PrivacyClass) -> CueContext {
    CueContext::new(
        TaskId::new(task).expect("task"),
        WorkScopeId::new(scope).expect("scope"),
        fence(),
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            provenance: provenance(),
            verification: None,
            state_fence: fence(),
        },
        LifecycleState::Active,
        privacy,
        eliot_cue_contracts::ProofCeiling::Observation,
    )
}

fn observed(kind: CueKind, value: &str) -> ObservedCue {
    ObservedCue::new(
        CONTRACT_REVISION.to_owned(),
        ObservedCueId::new("observed-1").expect("observation"),
        kind,
        value.to_owned(),
        SourceHandle::new(
            TargetHandle::new("src/input.rs").expect("target"),
            digest(1),
            provenance(),
        ),
        context(),
    )
}

fn observed_scoped(kind: CueKind, value: &str, scope: &str) -> ObservedCue {
    ObservedCue::new(
        CONTRACT_REVISION.to_owned(),
        ObservedCueId::new("observed-1").expect("observation"),
        kind,
        value.to_owned(),
        SourceHandle::new(
            TargetHandle::new("src/input.rs").expect("target"),
            digest(1),
            provenance(),
        ),
        context_with("task-1", scope, PrivacyClass::Public),
    )
}

fn profile() -> NormalizationProfile {
    NormalizationProfile::new("normalizer-test".to_owned(), 1, digest(2))
}

fn policy(kind: CueKind, rule: NormalizationRule) -> NormalizationPolicy {
    policy_scoped("policy-test", kind, rule, "scope-1")
}

fn policy_scoped(
    id: &str,
    kind: CueKind,
    rule: NormalizationRule,
    scope: &str,
) -> NormalizationPolicy {
    NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        id.to_owned(),
        1,
        profile(),
        WorkScopeId::new(scope).expect("scope"),
        fence(),
        vec![PolicyRule { kind, rule }],
    )
    .expect("sealed policy")
}

fn named_policy(id: &str, kind: CueKind, rule: NormalizationRule) -> NormalizationPolicy {
    policy_scoped(id, kind, rule, "scope-1")
}

/// Policy covering every current A-10 kind with its kind-correct rule.
fn full_policy(id: &str) -> NormalizationPolicy {
    let path_rule = || NormalizationRule::Path {
        case: CasePolicy::Preserve,
        separators: SeparatorPolicy::Preserve,
        match_mode: MatchMode::Exact,
    };
    NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        id.to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![
            PolicyRule {
                kind: CueKind::FilePath,
                rule: path_rule(),
            },
            PolicyRule {
                kind: CueKind::DirPath,
                rule: path_rule(),
            },
            PolicyRule {
                kind: CueKind::Symbol,
                rule: NormalizationRule::Symbol {
                    case: CasePolicy::Preserve,
                },
            },
            PolicyRule {
                kind: CueKind::ErrorSignature,
                rule: NormalizationRule::Signature {
                    algorithm_ref: "owner.signature.v1".to_owned(),
                    prefix: "sig:".to_owned(),
                    hex_length: 8,
                },
            },
            PolicyRule {
                kind: CueKind::CommandPattern,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::Dependency,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::ApiSurface,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::TaskClass,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::Subsystem,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::Concept,
                rule: NormalizationRule::Preserve,
            },
        ],
    )
    .expect("sealed full policy")
}

fn kind_fixture(kind: CueKind) -> &'static str {
    match kind {
        CueKind::FilePath => "src/input.rs",
        CueKind::DirPath => "src/nested",
        CueKind::Symbol => "crate::Main",
        CueKind::ErrorSignature => "sig:deadbeef",
        CueKind::CommandPattern => "cargo test --locked",
        CueKind::Dependency => "serde 1.0.228",
        CueKind::ApiSurface => "eliot_cue_normalizer::normalize_cue",
        CueKind::TaskClass => "cue-normalization",
        CueKind::Subsystem => "smart.cue.normalizer",
        CueKind::Concept => "canonical identity",
        _ => "generic cue value",
    }
}

fn all_kinds() -> [CueKind; 10] {
    [
        CueKind::FilePath,
        CueKind::DirPath,
        CueKind::Symbol,
        CueKind::ErrorSignature,
        CueKind::CommandPattern,
        CueKind::Dependency,
        CueKind::ApiSurface,
        CueKind::TaskClass,
        CueKind::Subsystem,
        CueKind::Concept,
    ]
}

// WORK_UNIT_CASE: 598/1
#[test]
fn a10_kinds_and_modes_consumed_without_local_copy() -> TestResult {
    assert!(
        std::any::type_name::<CueKind>().contains("eliot_cue_contracts"),
        "CueKind must be the exact A-10 type, not a local copy"
    );
    let full = full_policy("policy-kinds");
    for kind in all_kinds() {
        assert!(
            full.rule_for(kind).is_some(),
            "every current A-10 kind has an exact rule"
        );
    }
    for kind in all_kinds() {
        let input = observed(kind, kind_fixture(kind));
        let envelope = capture_cue(&input, &full, &full.profile)?;
        let canonical_kind = envelope
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .kind;
        assert_eq!(canonical_kind, kind);
        for key in &envelope.normalized.comparison_keys {
            assert!(
                matches!(
                    (kind, key.match_mode),
                    (_, MatchMode::Exact)
                        | (CueKind::FilePath | CueKind::DirPath, MatchMode::Prefix)
                        | (CueKind::ErrorSignature, MatchMode::Signature)
                ),
                "only A-10 admissible kind/mode pairs are consumed"
            );
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 598/2
#[test]
fn valid_normalization_for_every_current_kind() -> TestResult {
    let full = full_policy("policy-every-kind");
    for kind in all_kinds() {
        let input = observed(kind, kind_fixture(kind));
        let envelope = capture_cue(&input, &full, &full.profile)?;
        envelope.validate()?;
        assert!(envelope.normalized.canonical.is_some());
        assert_eq!(envelope.normalized.comparison_keys.len(), 1);
        assert!(matches!(
            envelope.normalized.outcome,
            NormalizationOutcome::Lossless
        ));
        assert_eq!(envelope.normalized.observed, input);
    }
    Ok(())
}

// WORK_UNIT_CASE: 598/3
#[test]
fn capture_and_fire_share_full_deterministic_result() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let input = observed(CueKind::Symbol, "crate::Main");
    let captured = capture_cue(&input, &p, &p.profile)?;
    let fired = fire_cue(&input, &p, &p.profile)?;
    assert_eq!(captured, fired);
    assert_eq!(captured.normalized.observed, input);
    assert_eq!(captured.input_digest.as_str().len(), 64);
    assert_eq!(captured.result_digest.as_str().len(), 64);
    Ok(())
}

// WORK_UNIT_CASE: 598/4
#[test]
fn exact_replay_bytes_and_digest() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let input = observed(CueKind::Symbol, "crate::Main");
    let first = capture_cue(&input, &p, &p.profile)?;
    let second = capture_cue(&input, &p, &p.profile)?;
    assert_eq!(first, second);
    assert_eq!(first.input_digest, second.input_digest);
    assert_eq!(first.result_digest, second.result_digest);
    let first_bytes = canonical_json_bytes(&first).expect("canonical bytes");
    let second_bytes = canonical_json_bytes(&second).expect("canonical bytes");
    assert_eq!(first_bytes, second_bytes);
    assert!(!first_bytes.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 598/5
#[test]
fn source_revision_provenance_round_trip() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let input = observed(CueKind::Symbol, "crate::Main");
    let result = capture_cue(&input, &p, &p.profile)?;
    assert_eq!(result.normalized.observed, input);
    assert_eq!(result.normalized.observed.source, input.source);
    assert_eq!(
        result.normalized.observed.context.evidence.provenance,
        input.context.evidence.provenance
    );
    assert_eq!(
        result.normalized.observed.source.digest, input.source.digest,
        "source revision digest round-trips exactly"
    );
    let wire = serde_json::to_string(&result)?;
    let back: NormalizationEnvelope = serde_json::from_str(&wire)?;
    assert_eq!(back, result);
    assert_eq!(back.normalized.observed.source, input.source);
    Ok(())
}

// WORK_UNIT_CASE: 598/6
#[test]
fn wrong_scope_fence_and_profile_are_rejected() {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let input = observed(CueKind::Symbol, "crate::Main");
    let wrong_scope = policy_scoped(
        "policy-test",
        CueKind::Symbol,
        NormalizationRule::Preserve,
        "scope-2",
    );
    let scope_error = capture_cue(&input, &wrong_scope, &wrong_scope.profile);
    assert!(matches!(
        scope_error,
        Err(NormalizationError::InvalidField {
            field: "policy.scope_id"
        })
    ));
    let wrong_fence = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-test".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence_at(2),
        vec![PolicyRule {
            kind: CueKind::Symbol,
            rule: NormalizationRule::Preserve,
        }],
    )
    .expect("sealed fenced policy");
    let fence_error = capture_cue(&input, &wrong_fence, &wrong_fence.profile);
    assert!(matches!(
        fence_error,
        Err(NormalizationError::InvalidField {
            field: "policy.state_fence"
        })
    ));
    let profile_error = capture_cue(&input, &p, &profile());
    assert!(matches!(
        profile_error,
        Err(NormalizationError::ProfileMismatch)
    ));
}

// WORK_UNIT_CASE: 598/7
#[test]
fn empty_control_and_oversized_failures_are_distinct() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let empty = capture_cue(&observed(CueKind::Symbol, ""), &p, &p.profile);
    assert!(matches!(
        empty,
        Err(NormalizationError::InvalidField { .. } | NormalizationError::Contract(_))
    ));
    let control = capture_cue(&observed(CueKind::Symbol, "a\x07b"), &p, &p.profile);
    assert!(matches!(
        control,
        Err(NormalizationError::InvalidField { .. } | NormalizationError::Contract(_))
    ));
    let oversized = capture_cue(
        &observed(CueKind::Symbol, &"x".repeat(8193)),
        &p,
        &p.profile,
    );
    assert!(matches!(
        oversized,
        Err(NormalizationError::BoundExceeded { .. })
    ));
    let at_limit = capture_cue(
        &observed(CueKind::Symbol, &"x".repeat(8192)),
        &p,
        &p.profile,
    )?;
    assert!(matches!(
        at_limit.normalized.outcome,
        NormalizationOutcome::Lossless
    ));
    Ok(())
}

// WORK_UNIT_CASE: 598/8
#[test]
fn invalid_encoding_distinct_from_unsupported_semantics() -> TestResult {
    let sensitive = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let invalid = capture_cue(
        &observed(CueKind::Symbol, "bad\x00value"),
        &sensitive,
        &sensitive.profile,
    );
    assert!(
        invalid.is_err(),
        "invalid encoding is a typed error, never a result"
    );
    let folded = policy(
        CueKind::Symbol,
        NormalizationRule::Symbol {
            case: CasePolicy::AsciiInsensitive,
        },
    );
    let ambiguous_spelling = capture_cue(
        &observed(CueKind::Symbol, "München"),
        &folded,
        &folded.profile,
    )?;
    assert!(
        matches!(
            ambiguous_spelling.normalized.outcome,
            NormalizationOutcome::Unsupported { .. }
        ),
        "unspecified equivalence is unsupported semantics, not an error"
    );
    assert!(ambiguous_spelling.normalized.comparison_keys.is_empty());
    let missing = capture_cue(
        &observed(CueKind::Concept, "idea"),
        &sensitive,
        &sensitive.profile,
    )?;
    assert!(matches!(
        missing.normalized.outcome,
        NormalizationOutcome::Unsupported { .. }
    ));
    Ok(())
}

// WORK_UNIT_CASE: 598/9
#[test]
fn original_canonical_and_comparison_stay_distinct() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "Src\\Main.rs");
    let result = capture_cue(&input, &p, &p.profile)?;
    let canonical = result.normalized.canonical.as_ref().expect("canonical");
    assert_eq!(result.normalized.observed.original_value, "Src\\Main.rs");
    assert_eq!(canonical.canonical_value, "Src\\Main.rs");
    let key = &result.normalized.comparison_keys[0];
    assert_eq!(key.key_value, "src/main.rs");
    assert_ne!(canonical.canonical_value, key.key_value);
    assert_ne!(
        canonical.canonical_cue_id.as_str(),
        key.comparison_key_id.as_str()
    );
    assert_ne!(canonical.digest.as_str(), result.input_digest.as_str());
    Ok(())
}

// WORK_UNIT_CASE: 598/10
#[test]
fn canonical_path_spelling_and_case_preserved() -> TestResult {
    let file_policy = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let file = capture_cue(
        &observed(CueKind::FilePath, "Src\\Main.rs"),
        &file_policy,
        &file_policy.profile,
    )?;
    assert_eq!(
        file.normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        "Src\\Main.rs"
    );
    let dir_policy = policy(
        CueKind::DirPath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let dir = capture_cue(
        &observed(CueKind::DirPath, "Src\\Nested"),
        &dir_policy,
        &dir_policy.profile,
    )?;
    assert_eq!(
        dir.normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        "Src\\Nested"
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/11
#[test]
fn path_policy_folds_key_without_changing_canonical_spelling() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: eliot_cue_contracts::MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "src\\Main.rs");
    let result = capture_cue(&input, &p, &p.profile)?;
    assert_eq!(result.normalized.observed.original_value, "src\\Main.rs");
    assert_eq!(
        result
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        "src\\Main.rs"
    );
    assert_eq!(
        result.normalized.comparison_keys[0].key_value,
        "src/main.rs"
    );
    assert_eq!(result.normalized.transformation_evidence.len(), 2);
    assert_eq!(
        result.normalized.transformation_evidence[0].step,
        "path.separators"
    );
    assert_eq!(
        result.normalized.transformation_evidence[1].step,
        "path.case.ascii"
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/12
#[test]
fn same_spelling_under_case_policies_keeps_source_but_splits_keys() -> TestResult {
    let sensitive = named_policy(
        "policy-case-sensitive",
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Slash,
            match_mode: eliot_cue_contracts::MatchMode::Exact,
        },
    );
    let folded = named_policy(
        "policy-case-insensitive",
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: eliot_cue_contracts::MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "Src/Main.rs");
    let kept = capture_cue(&input, &sensitive, &sensitive.profile)?;
    let lowered = capture_cue(&input, &folded, &folded.profile)?;

    for envelope in [&kept, &lowered] {
        assert_eq!(envelope.normalized.observed.original_value, "Src/Main.rs");
        assert_eq!(
            envelope
                .normalized
                .canonical
                .as_ref()
                .expect("canonical")
                .canonical_value,
            "Src/Main.rs"
        );
    }
    let kept_source = source_value(&input, &sensitive)?;
    let lowered_source = source_value(&input, &folded)?;
    assert_eq!(kept_source.canonical_spelling, "Src/Main.rs");
    assert_eq!(
        kept_source.canonical_spelling,
        lowered_source.canonical_spelling
    );
    assert_ne!(
        kept_source.comparison_policy_ref,
        lowered_source.comparison_policy_ref
    );

    let kept_key = comparison_key(&kept.normalized)?;
    let lowered_key = comparison_key(&lowered.normalized)?;
    assert_eq!(kept_key.normalized_value, "Src/Main.rs");
    assert_eq!(lowered_key.normalized_value, "src/main.rs");
    assert_eq!(kept_key.scope, "scope-1");
    assert_eq!(kept_key.kind, CueKind::FilePath);
    kept_key.validate().expect("valid key");
    lowered_key.validate().expect("valid key");
    Ok(())
}

// WORK_UNIT_CASE: 598/13
#[test]
fn separators_normalized_only_by_exact_policy() -> TestResult {
    let input = observed(CueKind::FilePath, "src\\Main.rs");
    let preserved = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Preserve,
            match_mode: MatchMode::Exact,
        },
    );
    let kept = capture_cue(&input, &preserved, &preserved.profile)?;
    assert_eq!(kept.normalized.comparison_keys[0].key_value, "src\\Main.rs");
    assert!(kept.normalized.transformation_evidence.is_empty());
    let slashed = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let folded = capture_cue(&input, &slashed, &slashed.profile)?;
    assert_eq!(
        folded.normalized.comparison_keys[0].key_value,
        "src/Main.rs"
    );
    assert_eq!(folded.normalized.transformation_evidence.len(), 1);
    assert_eq!(
        folded.normalized.transformation_evidence[0].step,
        "path.separators"
    );
    assert_ne!(kept.result_digest, folded.result_digest);
    Ok(())
}

// WORK_UNIT_CASE: 598/14
#[test]
fn dot_and_repeated_separator_steps_are_recorded_not_collapsed() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "src\\Main.rs");
    let result = capture_cue(&input, &p, &p.profile)?;
    let steps = &result.normalized.transformation_evidence;
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].step, "path.separators");
    assert_eq!(steps[0].result, "src/Main.rs");
    assert_eq!(steps[1].step, "path.case.ascii");
    assert_eq!(steps[1].result, "src/main.rs");
    assert_eq!(
        steps[1].result,
        result.normalized.comparison_keys[0].key_value
    );
    let repeated = capture_cue(&observed(CueKind::FilePath, "src//lib.rs"), &p, &p.profile)?;
    assert!(repeated.normalized.canonical.is_none());
    assert!(repeated.normalized.comparison_keys.is_empty());
    assert!(repeated.normalized.transformation_evidence.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 598/15
#[test]
fn special_paths_are_retained_as_unsupported() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Preserve,
            match_mode: eliot_cue_contracts::MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "C:\\repo\\..\\secret");
    let result = capture_cue(&input, &p, &p.profile)?;
    assert!(result.normalized.canonical.is_none());
    assert!(result.normalized.comparison_keys.is_empty());
    assert_eq!(result.normalized.observed, input);
    Ok(())
}

// WORK_UNIT_CASE: 598/16
#[test]
fn drive_root_unc_and_trailing_shapes_stay_distinct() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let shapes = [
        "C:\\repo\\file.rs",
        "/abs/path.rs",
        "\\\\unc\\share\\f.rs",
        "src/dir/",
        "a/../b",
        "ns:thing",
    ];
    let mut digests = std::collections::BTreeSet::new();
    for shape in shapes {
        let result = capture_cue(&observed(CueKind::FilePath, shape), &p, &p.profile)?;
        assert!(result.normalized.canonical.is_none(), "shape: {shape}");
        assert!(
            result.normalized.comparison_keys.is_empty(),
            "shape: {shape}"
        );
        assert_eq!(result.normalized.observed.original_value, shape);
        assert!(digests.insert(result.input_digest.as_str().to_owned()));
    }
    assert_eq!(digests.len(), shapes.len());
    Ok(())
}

// WORK_UNIT_CASE: 598/17
#[test]
fn no_symlink_junction_or_filesystem_case_resolution() -> TestResult {
    let p = policy(CueKind::FilePath, NormalizationRule::Preserve);
    let missing = observed(CueKind::FilePath, "no/such/tree/never-created-598/input.rs");
    let result = capture_cue(&missing, &p, &p.profile)?;
    assert!(matches!(
        result.normalized.outcome,
        NormalizationOutcome::Lossless
    ));
    assert_eq!(
        result
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        "no/such/tree/never-created-598/input.rs"
    );
    let short_name = capture_cue(&observed(CueKind::FilePath, "PROGRA~1/app"), &p, &p.profile)?;
    assert_eq!(
        short_name
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        "PROGRA~1/app"
    );
    assert_eq!(
        short_name.normalized.comparison_keys[0].key_value,
        "PROGRA~1/app"
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/18
#[test]
fn symbols_and_owner_qualified_signatures_keep_types_distinct() -> TestResult {
    let symbol_policy = policy(
        CueKind::Symbol,
        NormalizationRule::Symbol {
            case: CasePolicy::AsciiInsensitive,
        },
    );
    let symbol = capture_cue(
        &observed(CueKind::Symbol, "crate::Main"),
        &symbol_policy,
        &symbol_policy.profile,
    )?;
    assert_eq!(
        symbol.normalized.comparison_keys[0].form,
        eliot_cue_contracts::ComparisonForm::CaseInsensitive
    );

    let signature_policy = policy(
        CueKind::ErrorSignature,
        NormalizationRule::Signature {
            algorithm_ref: "owner.signature.v1".to_owned(),
            prefix: "sig:".to_owned(),
            hex_length: 8,
        },
    );
    let signature = capture_cue(
        &observed(CueKind::ErrorSignature, "sig:deadbeef"),
        &signature_policy,
        &signature_policy.profile,
    )?;
    assert_eq!(
        signature.normalized.comparison_keys[0].match_mode,
        eliot_cue_contracts::MatchMode::Signature
    );
    assert_eq!(
        signature
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .kind,
        CueKind::ErrorSignature
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/19
#[test]
fn error_signatures_round_trip_byte_identical() -> TestResult {
    let p = named_policy(
        "policy-signatures",
        CueKind::ErrorSignature,
        NormalizationRule::Signature {
            algorithm_ref: "owner.signature.v1".to_owned(),
            prefix: "sig:".to_owned(),
            hex_length: 8,
        },
    );
    let input = observed(CueKind::ErrorSignature, "sig:deadbeef");
    let result = capture_cue(&input, &p, &p.profile)?;
    let canonical = result
        .normalized
        .canonical
        .as_ref()
        .expect("canonical")
        .canonical_value
        .clone();
    assert_eq!(canonical, "sig:deadbeef");
    assert_eq!(result.normalized.comparison_keys[0].key_value, canonical);
    assert_eq!(
        result.normalized.comparison_keys[0].match_mode,
        eliot_cue_contracts::MatchMode::Signature
    );

    let source = source_value(&input, &p)?;
    assert_eq!(source.canonical_spelling, "sig:deadbeef");
    let key = comparison_key(&result.normalized)?;
    assert_eq!(key.normalized_value, "sig:deadbeef");
    assert_eq!(key.mode, eliot_cue_contracts::MatchMode::Signature);

    for malformed in [
        "sig:DEADBEEF",
        "sig:xyz",
        "sig:deadbee",
        "sig:deadbeef00",
        "other:deadbeef",
        "sig:deadbeeg",
    ] {
        let rejected = capture_cue(
            &observed(CueKind::ErrorSignature, malformed),
            &p,
            &p.profile,
        );
        assert!(
            matches!(rejected, Err(NormalizationError::InvalidSignature)),
            "malformed signature rejected: {malformed}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 598/20
#[test]
fn other_kinds_use_explicit_kind_specific_rules() -> TestResult {
    let full = full_policy("policy-other-kinds");
    for (kind, value) in [
        (CueKind::CommandPattern, "cargo test --locked"),
        (CueKind::Dependency, "serde 1.0.228"),
        (CueKind::ApiSurface, "normalize_cue"),
        (CueKind::TaskClass, "cue-normalization"),
        (CueKind::Subsystem, "smart.cue.normalizer"),
        (CueKind::Concept, "canonical identity"),
    ] {
        let result = capture_cue(&observed(kind, value), &full, &full.profile)?;
        assert!(matches!(
            result.normalized.outcome,
            NormalizationOutcome::Lossless
        ));
        assert_eq!(result.normalized.comparison_keys[0].key_value, value);
        assert_eq!(
            result.normalized.comparison_keys[0].match_mode,
            MatchMode::Exact
        );
    }
    let mismatched = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-mismatch".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![PolicyRule {
            kind: CueKind::Concept,
            rule: NormalizationRule::Symbol {
                case: CasePolicy::Preserve,
            },
        }],
    );
    assert!(matches!(
        mismatched,
        Err(NormalizationError::InvalidField {
            field: "policy.rule.kind"
        })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 598/21
#[test]
fn unspecified_unicode_ambiguity_is_not_guessed() -> TestResult {
    let folded = policy(
        CueKind::Symbol,
        NormalizationRule::Symbol {
            case: CasePolicy::AsciiInsensitive,
        },
    );
    let symbol = capture_cue(
        &observed(CueKind::Symbol, "München::Main"),
        &folded,
        &folded.profile,
    )?;
    assert!(matches!(
        symbol.normalized.outcome,
        NormalizationOutcome::Unsupported { .. }
    ));
    assert!(symbol.normalized.comparison_keys.is_empty());
    assert_eq!(symbol.normalized.observed.original_value, "München::Main");
    let path_policy = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Preserve,
            match_mode: MatchMode::Exact,
        },
    );
    let path = capture_cue(
        &observed(CueKind::FilePath, "src/München.rs"),
        &path_policy,
        &path_policy.profile,
    )?;
    assert!(matches!(
        path.normalized.outcome,
        NormalizationOutcome::Unsupported { .. }
    ));
    let explicit = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let kept = capture_cue(
        &observed(CueKind::Symbol, "München::Main"),
        &explicit,
        &explicit.profile,
    )?;
    assert!(matches!(
        kept.normalized.outcome,
        NormalizationOutcome::Lossless
    ));
    Ok(())
}

// WORK_UNIT_CASE: 598/22
#[test]
fn missing_rule_and_profile_drift_are_safe() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let missing = capture_cue(&observed(CueKind::Concept, "idea"), &p, &p.profile)?;
    assert!(missing.normalized.canonical.is_none());
    assert!(missing.normalized.comparison_keys.is_empty());

    let mut changed = p.clone();
    changed.rules[0].rule = NormalizationRule::Symbol {
        case: CasePolicy::AsciiInsensitive,
    };
    let error = capture_cue(&observed(CueKind::Symbol, "Main"), &changed, &p.profile);
    assert!(matches!(
        error,
        Err(NormalizationError::PolicyDigestMismatch)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 598/23
#[test]
fn transformation_evidence_preserves_semantic_order() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let result = capture_cue(&observed(CueKind::FilePath, "Src\\Main.rs"), &p, &p.profile)?;
    let steps = &result.normalized.transformation_evidence;
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].step, "path.separators");
    assert_eq!(steps[1].step, "path.case.ascii");
    assert_eq!(steps[0].result, "Src/Main.rs");
    assert_eq!(steps[1].result, "src/main.rs");
    let replay = capture_cue(&observed(CueKind::FilePath, "Src\\Main.rs"), &p, &p.profile)?;
    assert_eq!(
        replay.normalized.transformation_evidence,
        result.normalized.transformation_evidence
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/24
#[test]
fn destructive_or_unauthorized_loss_never_labelled_lossless() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Preserve,
            match_mode: MatchMode::Exact,
        },
    );
    for value in ["a/../b", "C:\\repo\\x.rs", "src//lib.rs", "src/dir/"] {
        let result = capture_cue(&observed(CueKind::FilePath, value), &p, &p.profile)?;
        assert!(
            !matches!(result.normalized.outcome, NormalizationOutcome::Lossless),
            "destructive shape is never lossless: {value}"
        );
        assert!(result.normalized.canonical.is_none());
        assert!(result.normalized.comparison_keys.is_empty());
    }
    let folded_policy = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let folded = capture_cue(
        &observed(CueKind::FilePath, "Src\\Main.rs"),
        &folded_policy,
        &folded_policy.profile,
    )?;
    assert!(matches!(
        folded.normalized.outcome,
        NormalizationOutcome::Lossless
    ));
    assert_eq!(
        folded
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        "Src\\Main.rs",
        "folding stays in the key; canonical identity keeps every byte"
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/25
#[test]
fn permitted_loss_names_rule_and_owner() -> TestResult {
    let p = policy(CueKind::FilePath, NormalizationRule::Preserve);
    let result = capture_cue(&observed(CueKind::FilePath, "src/input.rs"), &p, &p.profile)?;
    assert_eq!(
        result.normalized.comparison_keys[0].profile.profile_id, p.profile.profile_id,
        "every key carries its rule lineage"
    );
    let input = observed(CueKind::FilePath, "src/input.rs");
    let canonical = CanonicalCueIdentity::new(
        CanonicalCueId::new("canonical-598-loss").expect("canonical id"),
        CueKind::FilePath,
        "src/input.rs".to_owned(),
        digest(3),
    );
    let key = ComparisonKey::new(
        ComparisonKeyId::new("key-598-loss").expect("key id"),
        p.profile.clone(),
        "src/input.rs".to_owned(),
        MatchMode::Prefix,
        ComparisonForm::PathNormalized,
    );
    let named = NormalizedCue::new(
        CONTRACT_REVISION.to_owned(),
        input.clone(),
        p.profile.clone(),
        Some(canonical.clone()),
        vec![key],
        NormalizationOutcome::AuthorizedLoss {
            policy_ref: "a11-test-policy-owner/policy-test:1".to_owned(),
        },
        Vec::new(),
    );
    assert!(named.validate().is_ok());
    let unnamed = NormalizedCue::new(
        CONTRACT_REVISION.to_owned(),
        input,
        p.profile.clone(),
        Some(canonical),
        vec![ComparisonKey::new(
            ComparisonKeyId::new("key-598-loss-2").expect("key id"),
            p.profile.clone(),
            "src/input.rs".to_owned(),
            MatchMode::Prefix,
            ComparisonForm::PathNormalized,
        )],
        NormalizationOutcome::AuthorizedLoss {
            policy_ref: String::new(),
        },
        Vec::new(),
    );
    assert!(unnamed.validate().is_err());
    Ok(())
}

// WORK_UNIT_CASE: 598/26
#[test]
fn ambiguous_output_retains_bounded_rivals_and_original() -> TestResult {
    let input = observed(CueKind::Symbol, "Main");
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let rivals = vec![
        CanonicalCueIdentity::new(
            CanonicalCueId::new("canonical-598-a").expect("rival a"),
            CueKind::Symbol,
            "Main".to_owned(),
            digest(3),
        ),
        CanonicalCueIdentity::new(
            CanonicalCueId::new("canonical-598-b").expect("rival b"),
            CueKind::Symbol,
            "Main".to_owned(),
            digest(4),
        ),
    ];
    let ambiguous = NormalizedCue::new(
        CONTRACT_REVISION.to_owned(),
        input.clone(),
        p.profile.clone(),
        None,
        Vec::new(),
        NormalizationOutcome::Ambiguous {
            rivals: rivals.clone(),
        },
        Vec::new(),
    );
    assert!(ambiguous.validate().is_ok());
    assert_eq!(ambiguous.observed, input);
    let lone = NormalizedCue::new(
        CONTRACT_REVISION.to_owned(),
        input.clone(),
        p.profile.clone(),
        None,
        Vec::new(),
        NormalizationOutcome::Ambiguous {
            rivals: vec![rivals[0].clone()],
        },
        Vec::new(),
    );
    assert!(lone.validate().is_err());
    let missing = capture_cue(&observed(CueKind::Concept, "idea"), &p, &p.profile)?;
    assert!(matches!(
        missing.normalized.outcome,
        NormalizationOutcome::Unsupported { .. }
    ));
    assert_eq!(missing.normalized.observed.original_value, "idea");
    Ok(())
}

// WORK_UNIT_CASE: 598/27
#[test]
fn unsupported_valid_output_retains_source_and_missing_owner() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let input = observed(CueKind::Concept, "idea");
    let result = capture_cue(&input, &p, &p.profile)?;
    assert!(matches!(
        result.normalized.outcome,
        NormalizationOutcome::Unsupported { .. }
    ));
    assert_eq!(result.normalized.observed, input);
    assert!(result.normalized.canonical.is_none());
    assert!(result.normalized.comparison_keys.is_empty());
    assert_eq!(result.normalized.profile, p.profile);
    if let NormalizationOutcome::Unsupported { reason } = &result.normalized.outcome {
        assert!(!reason.trim().is_empty());
    } else {
        panic!("expected unsupported outcome");
    }
    result.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 598/28
#[test]
fn exact_mode_cannot_carry_fuzzy_meaning() -> TestResult {
    let full = full_policy("policy-exact-modes");
    for kind in all_kinds() {
        let result = capture_cue(&observed(kind, kind_fixture(kind)), &full, &full.profile)?;
        for key in &result.normalized.comparison_keys {
            assert!(
                matches!(
                    key.match_mode,
                    MatchMode::Exact | MatchMode::Prefix | MatchMode::Signature
                ),
                "only exact owner modes are emitted"
            );
            assert!(
                matches!(
                    key.form,
                    ComparisonForm::Exact
                        | ComparisonForm::CaseInsensitive
                        | ComparisonForm::PathNormalized
                ),
                "no fuzzy or embedding form is emitted"
            );
            if key.match_mode == MatchMode::Signature {
                assert_eq!(kind, CueKind::ErrorSignature);
            }
        }
        let wire = serde_json::to_string(&result)?;
        for marker in ["fuzzy", "embed", "semantic", "similar"] {
            assert!(!wire.contains(marker), "no fuzzy marker: {marker}");
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 598/29
#[test]
fn exact_equivalent_key_coalescing_retains_lineage() -> TestResult {
    let first_policy = named_policy(
        "policy-lineage",
        CueKind::Symbol,
        NormalizationRule::Preserve,
    );
    let input = observed(CueKind::Symbol, "crate::Main");
    let first = capture_cue(&input, &first_policy, &first_policy.profile)?;
    let second = capture_cue(&input, &first_policy, &first_policy.profile)?;
    assert_eq!(
        first.normalized.comparison_keys[0].comparison_key_id,
        second.normalized.comparison_keys[0].comparison_key_id,
        "equivalent keys coalesce to one stable identity"
    );
    assert_eq!(
        first.normalized.comparison_keys[0].profile,
        first_policy.profile
    );
    let other_policy = named_policy(
        "policy-lineage-other",
        CueKind::Symbol,
        NormalizationRule::Preserve,
    );
    let other = capture_cue(&input, &other_policy, &other_policy.profile)?;
    assert_ne!(
        first.normalized.comparison_keys[0].comparison_key_id,
        other.normalized.comparison_keys[0].comparison_key_id,
        "different rule lineage never shares a key identity"
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/30
#[test]
fn incompatible_collision_remains_conflict() -> TestResult {
    let duplicate = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-duplicate".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![
            PolicyRule {
                kind: CueKind::Symbol,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::Symbol,
                rule: NormalizationRule::Symbol {
                    case: CasePolicy::Preserve,
                },
            },
        ],
    );
    assert!(matches!(duplicate, Err(NormalizationError::DuplicateRule)));
    let full = full_policy("policy-collision");
    let symbol = capture_cue(&observed(CueKind::Symbol, "Main"), &full, &full.profile)?;
    let concept = capture_cue(&observed(CueKind::Concept, "Main"), &full, &full.profile)?;
    assert_ne!(symbol.result_digest, concept.result_digest);
    assert_ne!(
        symbol
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .digest,
        concept
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .digest
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/31
#[test]
fn bounds_and_envelope_binding_reject_tampering() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let result = capture_cue(&observed(CueKind::Symbol, "Main"), &p, &p.profile)?;
    let mut tampered = result.clone();
    tampered.input_digest = digest(9);
    assert!(tampered.validate().is_err());

    let mut oversized_profile = result.clone();
    oversized_profile.policy.profile.profile_id = "p".repeat(MAX_POLICY_ID_BYTES + 1);
    assert!(matches!(
        oversized_profile.validate(),
        Err(NormalizationError::BoundExceeded {
            field: "profile.profile_id",
            ..
        })
    ));

    let mut invalid_revision = result.clone();
    invalid_revision.policy.policy_revision = 0;
    assert!(matches!(
        invalid_revision.validate(),
        Err(NormalizationError::InvalidField {
            field: "envelope.policy.policy_revision"
        })
    ));

    let huge = NormalizationPolicy::sealed(
        "a".repeat(513),
        "policy-test".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![PolicyRule {
            kind: CueKind::Symbol,
            rule: NormalizationRule::Preserve,
        }],
    );
    assert!(matches!(
        huge,
        Err(NormalizationError::BoundExceeded {
            field: "policy.owner_reference",
            ..
        })
    ));

    let wire = serde_json::to_string(&result)?;
    assert!(wire.contains("\"normalized\""));
    Ok(())
}

// WORK_UNIT_CASE: 598/32
#[test]
fn invalid_zero_or_unknown_limits_are_not_unlimited() {
    let zero_revision = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-zero".to_owned(),
        0,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![PolicyRule {
            kind: CueKind::Symbol,
            rule: NormalizationRule::Preserve,
        }],
    );
    assert!(matches!(
        zero_revision,
        Err(NormalizationError::InvalidField {
            field: "policy.policy_revision"
        })
    ));
    let zero_hex = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-zero-hex".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![PolicyRule {
            kind: CueKind::ErrorSignature,
            rule: NormalizationRule::Signature {
                algorithm_ref: "owner.signature.v1".to_owned(),
                prefix: "sig:".to_owned(),
                hex_length: 0,
            },
        }],
    );
    assert!(zero_hex.is_err());
    let zero_profile = NormalizationProfile::new("normalizer-test".to_owned(), 0, digest(2));
    assert!(zero_profile.validate().is_err());
    let blank_id = NormalizationPolicy::sealed(
        String::new(),
        "policy-blank".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![PolicyRule {
            kind: CueKind::Symbol,
            rule: NormalizationRule::Preserve,
        }],
    );
    assert!(blank_id.is_err());
}

// WORK_UNIT_CASE: 598/33
#[test]
fn profile_version_and_digest_round_trip_deterministically() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    assert_eq!(p.expected_digest()?, p.digest);
    assert_eq!(p.profile.digest, p.digest);
    let wire = serde_json::to_string(&p.profile)?;
    let back: NormalizationProfile = serde_json::from_str(&wire)?;
    assert_eq!(back, p.profile);
    let resealed = NormalizationPolicy::sealed(
        p.owner_reference.clone(),
        p.policy_id.clone(),
        p.policy_revision,
        profile(),
        p.scope_id.clone(),
        p.state_fence.clone(),
        p.rules.clone(),
    )?;
    assert_eq!(resealed.digest, p.digest);
    assert_eq!(resealed.profile.digest, p.profile.digest);
    Ok(())
}

// WORK_UNIT_CASE: 598/34
#[test]
fn same_version_changed_rules_conflict() {
    let base = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let altered = policy(
        CueKind::Symbol,
        NormalizationRule::Symbol {
            case: CasePolicy::AsciiInsensitive,
        },
    );
    assert_eq!(base.policy_revision, altered.policy_revision);
    assert_ne!(base.digest, altered.digest);
    let mut tampered = base.clone();
    tampered.rules[0].rule = NormalizationRule::Symbol {
        case: CasePolicy::AsciiInsensitive,
    };
    assert!(matches!(
        tampered.validate(),
        Err(NormalizationError::PolicyDigestMismatch)
    ));
    let stale = capture_cue(&observed(CueKind::Symbol, "Main"), &tampered, &base.profile);
    assert!(matches!(
        stale,
        Err(NormalizationError::PolicyDigestMismatch)
    ));
}

// WORK_UNIT_CASE: 598/35
#[test]
fn profile_and_path_policy_change_emit_dependent_invalidation() -> TestResult {
    let sensitive = named_policy(
        "policy-invalidation",
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let folded = named_policy(
        "policy-invalidation-folded",
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "Src/Main.rs");
    let kept = capture_cue(&input, &sensitive, &sensitive.profile)?;
    let lowered = capture_cue(&input, &folded, &folded.profile)?;
    assert_ne!(kept.policy.policy_digest, lowered.policy.policy_digest);
    assert_ne!(kept.input_digest, lowered.input_digest);
    assert_ne!(kept.result_digest, lowered.result_digest);
    assert_ne!(
        kept.normalized.comparison_keys[0].key_value,
        lowered.normalized.comparison_keys[0].key_value
    );
    assert_eq!(
        kept.normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        lowered
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value
    );
    kept.validate()?;
    lowered.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 598/36
#[test]
fn legacy_revisions_cannot_silently_decode_current() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let result = capture_cue(&observed(CueKind::Symbol, "Main"), &p, &p.profile)?;
    assert_eq!(result.schema_revision, A11_CONTRACT_REVISION);
    assert_eq!(result.normalized.schema_revision, CONTRACT_REVISION);
    let mut legacy_envelope = result.clone();
    legacy_envelope.schema_revision = "0.9.0".to_owned();
    assert!(matches!(
        legacy_envelope.validate(),
        Err(NormalizationError::InvalidField {
            field: "envelope.schema_revision"
        })
    ));
    let mut legacy_record = result.clone();
    legacy_record.normalized.schema_revision = "1.0.0".to_owned();
    assert!(legacy_record.validate().is_err());
    let mut retargeted = result.clone();
    retargeted.result_digest = digest(7);
    assert!(matches!(
        retargeted.validate(),
        Err(NormalizationError::ResultInvalid)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 598/37
#[test]
fn capture_fire_profile_mismatch_is_typed_not_no_match() {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let input = observed(CueKind::Symbol, "crate::Main");
    let other = profile();
    let capture_error = capture_cue(&input, &p, &other);
    let fire_error = fire_cue(&input, &p, &other);
    assert!(matches!(
        capture_error,
        Err(NormalizationError::ProfileMismatch)
    ));
    assert!(matches!(
        fire_error,
        Err(NormalizationError::ProfileMismatch)
    ));
    assert_eq!(
        capture_error.unwrap_err().to_string(),
        fire_error.unwrap_err().to_string()
    );
}

// WORK_UNIT_CASE: 598/38
#[test]
fn wrappers_call_one_owner_without_altering_policy() {
    let full = full_policy("policy-single-owner");
    for kind in all_kinds() {
        let input = observed(kind, kind_fixture(kind));
        let via_capture = capture_cue(&input, &full, &full.profile);
        let via_fire = fire_cue(&input, &full, &full.profile);
        let via_owner = normalize_cue(&input, &full, &full.profile);
        assert_eq!(via_capture, via_fire);
        assert_eq!(via_capture, via_owner);
    }
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let bad = observed(CueKind::Symbol, "bad\x00value");
    assert_eq!(
        capture_cue(&bad, &p, &p.profile).unwrap_err(),
        fire_cue(&bad, &p, &p.profile).unwrap_err()
    );
    assert_eq!(
        capture_cue(&bad, &p, &p.profile).unwrap_err(),
        normalize_cue(&bad, &p, &p.profile).unwrap_err()
    );
}

// WORK_UNIT_CASE: 598/39
#[test]
fn irrelevant_rule_order_gives_identical_output() -> TestResult {
    let ordered = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-order".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![
            PolicyRule {
                kind: CueKind::Symbol,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::Concept,
                rule: NormalizationRule::Preserve,
            },
        ],
    )
    .expect("sealed ordered");
    let permuted = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-order".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![
            PolicyRule {
                kind: CueKind::Concept,
                rule: NormalizationRule::Preserve,
            },
            PolicyRule {
                kind: CueKind::Symbol,
                rule: NormalizationRule::Preserve,
            },
        ],
    )
    .expect("sealed permuted");
    assert_eq!(ordered.digest, permuted.digest);
    let input = observed(CueKind::Symbol, "crate::Main");
    let from_ordered = capture_cue(&input, &ordered, &ordered.profile)?;
    let from_permuted = capture_cue(&input, &permuted, &permuted.profile)?;
    assert_eq!(from_ordered, from_permuted);
    Ok(())
}

// WORK_UNIT_CASE: 598/40
#[test]
fn meaningful_transformation_order_changes_identity() -> TestResult {
    let preserved = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Preserve,
            match_mode: MatchMode::Exact,
        },
    );
    let folded = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "Src\\Main.rs");
    let kept = capture_cue(&input, &preserved, &preserved.profile)?;
    let changed = capture_cue(&input, &folded, &folded.profile)?;
    assert_eq!(kept.normalized.comparison_keys[0].key_value, "Src\\Main.rs");
    assert_eq!(
        changed.normalized.comparison_keys[0].key_value,
        "src/main.rs"
    );
    assert_ne!(kept.input_digest, changed.input_digest);
    assert_ne!(kept.result_digest, changed.result_digest);
    assert_eq!(
        kept.normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        changed
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/41
#[test]
fn every_load_bearing_input_changes_or_invalidates_digest() -> TestResult {
    let full = full_policy("policy-digest-load");
    let baseline_input = observed(CueKind::Symbol, "crate::Main");
    let baseline = capture_cue(&baseline_input, &full, &full.profile)?;
    let value_changed = capture_cue(
        &observed(CueKind::Symbol, "crate::Other"),
        &full,
        &full.profile,
    )?;
    assert_ne!(baseline.input_digest, value_changed.input_digest);
    assert_ne!(baseline.result_digest, value_changed.result_digest);
    let kind_changed = capture_cue(
        &observed(CueKind::Concept, "crate::Main"),
        &full,
        &full.profile,
    )?;
    assert_ne!(baseline.result_digest, kind_changed.result_digest);
    let scope_policy = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-digest-load".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-2").expect("scope"),
        fence(),
        full.rules.clone(),
    )
    .expect("sealed rescoped");
    let scope_changed = capture_cue(
        &observed_scoped(CueKind::Symbol, "crate::Main", "scope-2"),
        &scope_policy,
        &scope_policy.profile,
    )?;
    assert_ne!(baseline.input_digest, scope_changed.input_digest);
    let revised = NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-digest-load".to_owned(),
        2,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        full.rules.clone(),
    )
    .expect("sealed revised");
    let revision_changed = capture_cue(&baseline_input, &revised, &revised.profile)?;
    assert_ne!(baseline.result_digest, revision_changed.result_digest);
    Ok(())
}

// WORK_UNIT_CASE: 598/42
#[test]
fn privacy_disclosure_and_proof_cannot_widen() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let open = observed(CueKind::Symbol, "crate::Main");
    let open_result = capture_cue(&open, &p, &p.profile)?;
    assert_eq!(
        open_result.normalized.observed.context.privacy,
        PrivacyClass::Public
    );
    assert_eq!(
        open_result.normalized.observed.context.proof_ceiling,
        eliot_cue_contracts::ProofCeiling::Observation
    );
    let closed_observed = ObservedCue::new(
        CONTRACT_REVISION.to_owned(),
        ObservedCueId::new("observed-1").expect("observation"),
        CueKind::Symbol,
        "crate::Main".to_owned(),
        SourceHandle::new(
            TargetHandle::new("src/input.rs").expect("target"),
            digest(1),
            provenance(),
        ),
        context_with("task-1", "scope-1", PrivacyClass::Private),
    );
    let closed_result = capture_cue(&closed_observed, &p, &p.profile)?;
    assert_eq!(
        closed_result.normalized.observed.context.privacy,
        PrivacyClass::Private
    );
    assert_ne!(open_result.input_digest, closed_result.input_digest);
    assert_ne!(open_result.result_digest, closed_result.result_digest);
    Ok(())
}

// WORK_UNIT_CASE: 598/43
#[test]
fn result_excludes_binding_activation_and_effect_state() -> TestResult {
    let full = full_policy("policy-no-effect");
    let result = capture_cue(
        &observed(CueKind::Symbol, "crate::Main"),
        &full,
        &full.profile,
    )?;
    let wire = serde_json::to_string(&result)?;
    for present in [
        "\"schema_revision\"",
        "\"policy\"",
        "\"input_digest\"",
        "\"result_digest\"",
        "\"normalized\"",
        "\"canonical\"",
        "\"comparison_keys\"",
        "\"transformation_evidence\"",
    ] {
        assert!(wire.contains(present), "result carries {present}");
    }
    for absent in [
        "\"binding\"",
        "\"activation\"",
        "\"delivery\"",
        "\"finish\"",
        "\"support\"",
        "\"effect\"",
        "\"member\"",
        "\"index\"",
    ] {
        assert!(!wire.contains(absent), "result must not carry {absent}");
    }
    // Evidence authority is input lineage retained from the observation; it
    // grants no binding, activation, delivery, or effect state.
    Ok(())
}

// WORK_UNIT_CASE: 598/44
#[test]
fn source_api_guard_excludes_filesystem_git_network_and_store() -> TestResult {
    let full = full_policy("policy-no-io");
    let local = capture_cue(
        &observed(CueKind::FilePath, "no/such/tree/never-created-598/input.rs"),
        &full,
        &full.profile,
    )?;
    assert!(matches!(
        local.normalized.outcome,
        NormalizationOutcome::Lossless
    ));
    let git_shape = capture_cue(
        &observed(CueKind::FilePath, "C:\\repo\\.git\\config"),
        &full,
        &full.profile,
    )?;
    assert!(matches!(
        git_shape.normalized.outcome,
        NormalizationOutcome::Unsupported { .. }
    ));
    let network_shape = capture_cue(
        &observed(CueKind::FilePath, "https://example.invalid/x"),
        &full,
        &full.profile,
    )?;
    assert!(matches!(
        network_shape.normalized.outcome,
        NormalizationOutcome::Unsupported { .. }
    ));
    let ignore = capture_cue(
        &observed(CueKind::FilePath, "src/.gitignore"),
        &full,
        &full.profile,
    )?;
    assert!(matches!(
        ignore.normalized.outcome,
        NormalizationOutcome::Lossless
    ));
    assert_eq!(
        ignore
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        "src/.gitignore"
    );
    Ok(())
}

// WORK_UNIT_CASE: 598/45
#[test]
fn malformed_and_property_inputs_are_panic_free_and_bounded() -> TestResult {
    let p = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let hostile = [
        String::new(),
        " ".to_owned(),
        "\x00".to_owned(),
        "a\x07b".to_owned(),
        "".to_owned(),
        "x".repeat(9000),
        "C:\\..\\..\\windows".to_owned(),
        "sig:nothex!".to_owned(),
        "Src\\Main.rs".to_owned(),
        "München::Main".to_owned(),
    ];
    for value in &hostile {
        let outcome = capture_cue(&observed(CueKind::Symbol, value), &p, &p.profile);
        if let Ok(envelope) = outcome {
            envelope.validate()?;
            let bytes = canonical_json_bytes(&envelope).expect("canonical bytes");
            assert!(bytes.len() < 4 * 1024 * 1024);
        }
    }
    let path_policy = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::Preserve,
            separators: SeparatorPolicy::Preserve,
            match_mode: MatchMode::Exact,
        },
    );
    for value in &hostile {
        let outcome = capture_cue(
            &observed(CueKind::FilePath, value),
            &path_policy,
            &path_policy.profile,
        );
        if let Ok(envelope) = outcome {
            envelope.validate()?;
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 598/46
#[test]
fn same_input_policy_and_profile_always_same_result() -> TestResult {
    let p = policy(
        CueKind::FilePath,
        NormalizationRule::Path {
            case: CasePolicy::AsciiInsensitive,
            separators: SeparatorPolicy::Slash,
            match_mode: MatchMode::Exact,
        },
    );
    let input = observed(CueKind::FilePath, "Src\\Main.rs");
    let first = capture_cue(&input, &p, &p.profile)?;
    for _ in 0..25 {
        let next = capture_cue(&input, &p, &p.profile)?;
        assert_eq!(next, first);
        let fired = fire_cue(&input, &p, &p.profile)?;
        assert_eq!(fired, first);
        assert_eq!(next.input_digest, first.input_digest);
        assert_eq!(next.result_digest, first.result_digest);
    }
    Ok(())
}

// WORK_UNIT_CASE: 598/47
#[test]
fn policy_profile_and_owner_revision_invalidate_prior_output() -> TestResult {
    let base = policy(CueKind::Symbol, NormalizationRule::Preserve);
    let input = observed(CueKind::Symbol, "crate::Main");
    let baseline = capture_cue(&input, &base, &base.profile)?;
    let renamed_owner = NormalizationPolicy::sealed(
        "a11-test-other-owner".to_owned(),
        base.policy_id.clone(),
        base.policy_revision,
        profile(),
        base.scope_id.clone(),
        base.state_fence.clone(),
        base.rules.clone(),
    )
    .expect("sealed renamed owner");
    let renamed = capture_cue(&input, &renamed_owner, &renamed_owner.profile)?;
    assert_ne!(baseline.policy.policy_digest, renamed.policy.policy_digest);
    assert_ne!(baseline.result_digest, renamed.result_digest);
    let renamed_id = NormalizationPolicy::sealed(
        base.owner_reference.clone(),
        "policy-renamed".to_owned(),
        base.policy_revision,
        profile(),
        base.scope_id.clone(),
        base.state_fence.clone(),
        base.rules.clone(),
    )
    .expect("sealed renamed id");
    let reidentified = capture_cue(&input, &renamed_id, &renamed_id.profile)?;
    assert_ne!(baseline.result_digest, reidentified.result_digest);
    let bumped = NormalizationPolicy::sealed(
        base.owner_reference.clone(),
        base.policy_id.clone(),
        base.policy_revision + 1,
        profile(),
        base.scope_id.clone(),
        base.state_fence.clone(),
        base.rules.clone(),
    )
    .expect("sealed bumped");
    let upgraded = capture_cue(&input, &bumped, &bumped.profile)?;
    assert_ne!(baseline.result_digest, upgraded.result_digest);
    baseline.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 598/48
#[test]
fn no_second_schema_or_ad_hoc_consumer_algorithm() -> TestResult {
    let full = full_policy("policy-single-schema");
    for kind in all_kinds() {
        let input = observed(kind, kind_fixture(kind));
        let envelope = capture_cue(&input, &full, &full.profile)?;
        assert_eq!(envelope.normalized.observed.kind, kind);
        if let Some(canonical) = &envelope.normalized.canonical {
            assert_eq!(canonical.kind, kind);
        }
        for key in &envelope.normalized.comparison_keys {
            assert_eq!(key.profile, full.profile);
        }
        envelope.validate()?;
    }
    let first_symbol = capture_cue(
        &observed(CueKind::Symbol, "crate::Alpha"),
        &full,
        &full.profile,
    )?;
    let concept = capture_cue(
        &observed(CueKind::Concept, "unrelated-idea"),
        &full,
        &full.profile,
    )?;
    let second_symbol = capture_cue(
        &observed(CueKind::Symbol, "crate::Alpha"),
        &full,
        &full.profile,
    )?;
    assert_eq!(first_symbol, second_symbol);
    assert_ne!(first_symbol.result_digest, concept.result_digest);
    Ok(())
}
