//! Focused A-11 proofs for deterministic, lossless normalization.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, SourceId, StateFence, TaskId};
use eliot_cue_contracts::{
    CONTRACT_REVISION, CueContext, CueKind, Digest, NormalizationProfile, ObservedCue,
    ObservedCueId, PrivacyClass, SourceHandle, TargetHandle, WorkScopeId,
};
use eliot_cue_normalizer::{
    CasePolicy, MAX_POLICY_ID_BYTES, NormalizationError, NormalizationPolicy, NormalizationRule,
    PolicyRule, SeparatorPolicy, capture_cue, fire_cue,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance,
};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("digest")
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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
    CueContext::new(
        TaskId::new("task-1").expect("task"),
        WorkScopeId::new("scope-1").expect("scope"),
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
        PrivacyClass::Public,
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

fn profile() -> NormalizationProfile {
    NormalizationProfile::new("normalizer-test".to_owned(), 1, digest(2))
}

fn policy(kind: CueKind, rule: NormalizationRule) -> NormalizationPolicy {
    NormalizationPolicy::sealed(
        "a11-test-policy-owner".to_owned(),
        "policy-test".to_owned(),
        1,
        profile(),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        vec![PolicyRule { kind, rule }],
    )
    .expect("sealed policy")
}

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
    let input = observed(CueKind::FilePath, r"src\Main.rs");
    let result = capture_cue(&input, &p, &p.profile)?;
    assert_eq!(result.normalized.observed.original_value, r"src\Main.rs");
    assert_eq!(
        result
            .normalized
            .canonical
            .as_ref()
            .expect("canonical")
            .canonical_value,
        r"src\Main.rs"
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
    let input = observed(CueKind::FilePath, r"C:\repo\..\secret");
    let result = capture_cue(&input, &p, &p.profile)?;
    assert!(result.normalized.canonical.is_none());
    assert!(result.normalized.comparison_keys.is_empty());
    assert_eq!(result.normalized.observed, input);
    Ok(())
}

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

    let json: Value = serde_json::to_value(&result)?;
    assert!(json.get("normalized").is_some());
    Ok(())
}
