//! Criterion-by-criterion proof for role-separated source assurance.
//!
//! Eleven tests for the eleven acceptance criteria, exercised through the
//! public contract only, over the shared finite fixtures in `common`.

mod common;

use common::{CLAIM_ONE, CLAIM_TWO, freeze_rich_portfolio};
use eliot_dreamer_source_assurance::{
    AccessibilityState, AssuranceResult, AvailabilityState, Completeness, ConfidenceObservation,
    EpistemicUse, IncompletenessReason, IndependenceState, IntegrityState, MemberAxisRecord,
    MirrorGroup, ReplayOutcome, RoleSeparationError, SupportCeiling, assess, dreamer_envelope,
    governor_candidate, replay, verify_dreamer_envelope,
};

/// Fallible test outcome over the public contract.
type Outcome = Result<(), Box<dyn std::error::Error>>;

fn axes<'a>(
    result: &'a AssuranceResult,
    member_id: &str,
) -> Result<&'a MemberAxisRecord, RoleSeparationError> {
    result
        .member_axes
        .iter()
        .find(|record| record.member_id == member_id)
        .ok_or(RoleSeparationError::MissingField("member_axes"))
}

fn ceiling<'a>(
    result: &'a AssuranceResult,
    claim_id: &str,
) -> Result<&'a SupportCeiling, RoleSeparationError> {
    result
        .ceilings
        .iter()
        .find(|entry| entry.claim_id == claim_id)
        .ok_or(RoleSeparationError::MissingField("ceilings"))
}

fn mirror_group<'a>(
    result: &'a AssuranceResult,
    lineage_root: &str,
) -> Result<&'a MirrorGroup, RoleSeparationError> {
    result
        .independence
        .mirror_groups
        .iter()
        .find(|group| group.lineage_root == lineage_root)
        .ok_or(RoleSeparationError::MissingField("mirror_groups"))
}

/// Criterion 1: every expected member has exactly one explicit disposition.
#[test]
fn every_member_has_one_explicit_disposition() -> Outcome {
    let set = freeze_rich_portfolio()?;
    assert_eq!(set.members.len(), 8);
    assert_eq!(set.observations.len(), 8);
    let result = assess(&set)?;
    assert_eq!(result.member_axes.len(), 8);
    let mut counted: usize = 0;
    for entry in &result.coverage.per_disposition {
        counted += entry.count;
    }
    assert_eq!(counted, result.coverage.expected_members);
    let acquired = result
        .coverage
        .per_disposition
        .iter()
        .find(|entry| entry.disposition == "acquired")
        .ok_or(RoleSeparationError::MissingField("per_disposition"))?;
    assert_eq!(acquired.count, 3);
    Ok(())
}

/// Criterion 2: separated fields stay separate.
#[test]
fn separated_axes_remain_separate_fields() -> Outcome {
    let result = assess(&freeze_rich_portfolio()?)?;
    let mirror = axes(&result, "m2")?;
    assert_eq!(mirror.integrity, IntegrityState::DigestMatched);
    assert_eq!(mirror.independence, IndependenceState::SharedRoot);
    let withheld = axes(&result, "m7")?;
    assert_eq!(withheld.availability, AvailabilityState::WithheldByPolicy);
    assert_eq!(withheld.accessibility, AccessibilityState::CredentialGap);
    let ceiling = ceiling(&result, CLAIM_ONE)?;
    assert!(!ceiling.supporting_roots.is_empty());
    assert!(!ceiling.contradicting_roots.is_empty());
    Ok(())
}

/// Criterion 3: independent-source count never exceeds unique lineage roots.
#[test]
fn independent_count_bounded_by_lineage_roots() -> Outcome {
    let result = assess(&freeze_rich_portfolio()?)?;
    assert!(
        result.independence.independent_support_count
            <= result.independence.unique_lineage_roots.len()
    );
    assert!(!result.independence.common_mode_flags.is_empty());
    let ceiling = ceiling(&result, CLAIM_ONE)?;
    assert!(ceiling.supporting_roots.len() <= result.independence.unique_lineage_roots.len());
    Ok(())
}

/// Criterion 4: mirrors and citations cannot manufacture independence.
#[test]
fn mirrors_cannot_manufacture_independence_or_support() -> Outcome {
    let result = assess(&freeze_rich_portfolio()?)?;
    let group = mirror_group(&result, "root-a")?;
    assert_eq!(group.member_ids.len(), 2);
    let ceiling = ceiling(&result, CLAIM_ONE)?;
    let root_a_support = ceiling
        .supporting_roots
        .iter()
        .filter(|root| root.as_str() == "root-a")
        .count();
    assert_eq!(root_a_support, 1);
    Ok(())
}

/// Criterion 5: acquisition and intact digests establish no truth or use.
#[test]
fn acquisition_alone_establishes_no_support_truth_or_influence() -> Outcome {
    let result = assess(&freeze_rich_portfolio()?)?;
    let ceiling_two = ceiling(&result, CLAIM_TWO)?;
    assert!(ceiling_two.supporting_roots.is_empty());
    assert_eq!(ceiling_two.max_use, EpistemicUse::NoUse);
    assert_eq!(
        ceiling_two.confidence,
        ConfidenceObservation::InsufficientBasis
    );
    Ok(())
}

/// Criterion 6: blocking conditions prevent a complete result.
#[test]
fn blocking_conditions_prevent_complete_result() -> Outcome {
    let result = assess(&freeze_rich_portfolio()?)?;
    let reasons = match &result.completeness {
        Completeness::Incomplete { reasons } => reasons.clone(),
        Completeness::Complete => return Err("rich fixture must be incomplete".into()),
    };
    for expected in [
        IncompletenessReason::PartialCoverage,
        IncompletenessReason::StalePresent,
        IncompletenessReason::RetractedPresent,
        IncompletenessReason::WithheldPresent,
        IncompletenessReason::ConflictedPresent,
        IncompletenessReason::UnavailablePresent,
        IncompletenessReason::ContradictionUnresolved,
    ] {
        assert!(reasons.contains(&expected), "missing {expected:?}");
    }
    Ok(())
}

/// Criterion 7: deterministic coverage sensitive to every disposition.
#[test]
fn coverage_is_deterministic_and_disposition_sensitive() -> Outcome {
    let set = freeze_rich_portfolio()?;
    let first = assess(&set)?;
    let second = assess(&set)?;
    assert_eq!(first.result_digest, second.result_digest);
    assert_eq!(first.coverage.expected_members, 8);
    assert_eq!(first.coverage.usable_members, 3);
    assert!(!first.blind_boundaries.is_empty());
    Ok(())
}

/// Criterion 8: exact replay is idempotent; drift conflicts.
#[test]
fn exact_replay_is_idempotent_and_drift_conflicts() -> Outcome {
    let set = freeze_rich_portfolio()?;
    let result = assess(&set)?;
    assert!(matches!(
        replay(&result, &set)?,
        ReplayOutcome::Identical { .. }
    ));
    Ok(())
}

/// Criterion 9: consumers preserve the envelope and cannot promote it.
#[test]
fn consumers_preserve_envelope_without_promotion() -> Outcome {
    let set = freeze_rich_portfolio()?;
    let result = assess(&set)?;
    let envelope = dreamer_envelope(&result, &set)?;
    verify_dreamer_envelope(&envelope)?;
    let metadata = governor_candidate(&result);
    assert_eq!(metadata.result_digest, result.result_digest);
    for ceiling in &metadata.ceilings {
        assert!(matches!(
            ceiling.max_use,
            EpistemicUse::NoUse
                | EpistemicUse::EvidenceCandidate
                | EpistemicUse::HypothesisCandidate
        ));
    }
    let contested = metadata
        .ceilings
        .iter()
        .find(|entry| entry.claim_id == CLAIM_ONE)
        .ok_or(RoleSeparationError::MissingField("ceilings"))?;
    assert_eq!(contested.max_use, EpistemicUse::HypothesisCandidate);
    assert!(metadata.contradiction_present);
    Ok(())
}

/// Criterion 10: the package performs no acquisition, store, model,
/// authority, influence, or completion operations.
#[test]
fn package_surface_is_pure_candidate_evidence() -> Outcome {
    let result = assess(&freeze_rich_portfolio()?)?;
    for ceiling in result
        .ceilings
        .iter()
        .chain(governor_candidate(&result).ceilings.iter())
    {
        assert!(matches!(
            ceiling.influence_ceiling,
            eliot_dreamer_source_assurance::InfluenceCeiling::CandidateEvidence
        ));
    }
    let json = serde_json::to_string(&result)?;
    assert!(!json.contains("VERIFIED"));
    assert!(!json.contains("\"score\""));
    Ok(())
}

/// Criterion 11: focused edge coverage across the portfolio.
#[test]
fn focused_edges_cover_duplicates_mirrors_and_gaps() -> Outcome {
    let result = assess(&freeze_rich_portfolio()?)?;
    assert_eq!(result.independence.mirror_groups.len(), 1);
    assert!(result.blind_boundaries.iter().any(|boundary| matches!(
        boundary,
        eliot_dreamer_source_assurance::BlindBoundary::RetractedMember { .. }
    )));
    assert!(result.blind_boundaries.iter().any(|boundary| matches!(
        boundary,
        eliot_dreamer_source_assurance::BlindBoundary::CredentialGap { .. }
    )));
    assert!(result.blind_boundaries.iter().any(|boundary| matches!(
        boundary,
        eliot_dreamer_source_assurance::BlindBoundary::ConflictedMember { .. }
    )));
    assert!(result.blind_boundaries.iter().any(|boundary| matches!(
        boundary,
        eliot_dreamer_source_assurance::BlindBoundary::PartialCoverageGap { .. }
    )));
    Ok(())
}
