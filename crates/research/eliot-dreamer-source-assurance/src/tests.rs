//! Module proof for role-separated source assurance.
//!
//! Each test targets one genuine condition: envelope-closure rejections,
//! deterministic coverage, lineage-root independence, ceiling behavior,
//! replay and invalidation, and consumer-envelope preservation.

use super::*;
use crate::assess::{
    AccessibilityState, AvailabilityState, Completeness, ConfidenceObservation, EpistemicUse,
    IncompletenessReason, IndependenceState, IntegrityState, MemberContradiction, ProvenanceState,
    RelevanceState, ReplayConflict, ReplayOutcome,
};
use crate::portfolio::{
    AssurancePolicy, ClaimLinkage, ExpectedMember, FreezeInput, FrozenEvidenceSet,
    InfluenceCeiling, LineageAttribution, MemberDisposition, MemberObservation, SupportStance,
};

const BOUNDARY: &str = "research-evidence/v1";
const CLAIM: &str = "claim-alpha";

fn digest(seed: &str) -> String {
    blake3::hash(seed.as_bytes()).to_hex().to_string()
}

fn lineage(root: Option<&str>) -> LineageAttribution {
    LineageAttribution {
        root: root.map(str::to_owned),
        acquisition_route: "route-frozen-capture".to_owned(),
        publisher: "research-publisher".to_owned(),
        generator: None,
    }
}

fn member(id: &str, root: Option<&str>, class: &str) -> ExpectedMember {
    ExpectedMember {
        member_id: id.to_owned(),
        content_digest: digest(&format!("bytes:{id}")),
        lineage: lineage(root),
        source_class: class.to_owned(),
        citation_refs: vec![format!("https://example.invalid/{id}")],
    }
}

fn acquired(id: &str, seed: &str) -> MemberObservation {
    MemberObservation {
        member_id: id.to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Acquired {
            observed_digest: digest(&format!("bytes:{seed}")),
            lineage_complete: true,
        },
    }
}

fn linked(id: &str, stance: SupportStance) -> ClaimLinkage {
    let claim_id = match stance {
        SupportStance::Unlinked => None,
        _ => Some(CLAIM.to_owned()),
    };
    ClaimLinkage {
        member_id: id.to_owned(),
        claim_id,
        stance,
    }
}

fn policy() -> AssurancePolicy {
    AssurancePolicy {
        policy_version: ASSURANCE_POLICY_VERSION.to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        excluded_source_classes: Vec::new(),
        credential_gap_refs: Vec::new(),
        allowed_influence: InfluenceCeiling::CandidateEvidence,
    }
}

fn input_two_supporters() -> FreezeInput {
    FreezeInput {
        set_id: "set-1".to_owned(),
        revision: "rev-1".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        evaluated_at_secs: 1_000,
        expires_at_secs: 2_000,
        members: vec![
            member("m-b", Some("root-beta"), "paper"),
            member("m-a", Some("root-alpha"), "paper"),
        ],
        observations: vec![acquired("m-a", "m-a"), acquired("m-b", "m-b")],
        linkages: vec![
            linked("m-a", SupportStance::Supports),
            linked("m-b", SupportStance::Supports),
        ],
        policy: policy(),
    }
}

fn freeze_two_supporters() -> Result<FrozenEvidenceSet, RoleSeparationError> {
    FrozenEvidenceSet::freeze(input_two_supporters())
}

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

#[test]
fn freeze_canonicalizes_member_order() -> Result<(), RoleSeparationError> {
    let first = FrozenEvidenceSet::freeze(input_two_supporters())?;
    let mut reversed = input_two_supporters();
    reversed.members.reverse();
    reversed.observations.reverse();
    reversed.linkages.reverse();
    let second = FrozenEvidenceSet::freeze(reversed)?;
    assert_eq!(first.set_digest, second.set_digest);
    assert_eq!(first.members[0].member_id, "m-a");
    assert_eq!(first.members[1].member_id, "m-b");
    Ok(())
}

#[test]
fn freeze_rejects_empty_denominator() {
    let mut input = input_two_supporters();
    input.members.clear();
    input.observations.clear();
    input.linkages.clear();
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::MissingDenominator)
    );
}

#[test]
fn freeze_rejects_duplicate_member_id() {
    let mut input = input_two_supporters();
    input
        .members
        .push(member("m-a", Some("root-gamma"), "paper"));
    input.observations.push(acquired("m-a", "m-a"));
    input
        .linkages
        .push(linked("m-a", SupportStance::ContextOnly));
    assert!(matches!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::DuplicateMemberId(_))
    ));
}

#[test]
fn freeze_rejects_missing_observation() {
    let mut input = input_two_supporters();
    input.observations.pop();
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::MissingObservation("m-b".to_owned()))
    );
}

#[test]
fn freeze_rejects_unknown_observation() {
    let mut input = input_two_supporters();
    input.observations.push(acquired("m-ghost", "m-ghost"));
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::UnknownObservation(
            "m-ghost".to_owned()
        ))
    );
}

#[test]
fn freeze_rejects_mixed_observation_boundary() {
    let mut input = input_two_supporters();
    input.observations[0].evaluation_boundary = "other-boundary".to_owned();
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::MixedEvaluationBoundary {
            expected: BOUNDARY.to_owned(),
            observed: "other-boundary".to_owned(),
        })
    );
}

#[test]
fn freeze_rejects_mixed_policy_boundary() {
    let mut input = input_two_supporters();
    input.policy.evaluation_boundary = "other-boundary".to_owned();
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::MixedEvaluationBoundary {
            expected: BOUNDARY.to_owned(),
            observed: "other-boundary".to_owned(),
        })
    );
}

#[test]
fn freeze_rejects_changed_content_under_immutable_identity() {
    let mut input = input_two_supporters();
    input.observations[0] = acquired("m-a", "tampered-bytes");
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::ChangedContentUnderImmutableIdentity(
            "m-a".to_owned()
        ))
    );
}

#[test]
fn freeze_rejects_unsupported_policy_version() {
    let mut input = input_two_supporters();
    input.policy.policy_version = "bogus-policy".to_owned();
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::UnsupportedPolicy(
            "bogus-policy".to_owned()
        ))
    );
}

#[test]
fn freeze_rejects_undeclared_withheld_exclusion() {
    let mut input = input_two_supporters();
    input.observations[0] = MemberObservation {
        member_id: "m-a".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Withheld {
            policy_ref: "gap-never-declared".to_owned(),
            reason: "no such gap".to_owned(),
        },
    };
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::UndeclaredExclusion("m-a".to_owned()))
    );
}

#[test]
fn freeze_accepts_declared_credential_gap_and_class_exclusion() {
    let mut input = input_two_supporters();
    input.policy.credential_gap_refs = vec!["gap-credentialed".to_owned()];
    input.observations[0] = MemberObservation {
        member_id: "m-a".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Withheld {
            policy_ref: "gap-credentialed".to_owned(),
            reason: "credentialed source".to_owned(),
        },
    };
    input.policy.excluded_source_classes = vec!["licensed".to_owned()];
    input.members[0].source_class = "licensed".to_owned();
    input.observations[1] = MemberObservation {
        member_id: "m-b".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Withheld {
            policy_ref: "class:licensed".to_owned(),
            reason: "licensed class excluded".to_owned(),
        },
    };
    assert!(FrozenEvidenceSet::freeze(input).is_ok());
}

#[test]
fn freeze_rejects_inconsistent_claim_binding() {
    let mut input = input_two_supporters();
    input.linkages[0] = ClaimLinkage {
        member_id: "m-a".to_owned(),
        claim_id: None,
        stance: SupportStance::Supports,
    };
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::InconsistentClaimBinding(
            "m-a".to_owned()
        ))
    );
    let mut input = input_two_supporters();
    input.linkages[0] = ClaimLinkage {
        member_id: "m-a".to_owned(),
        claim_id: Some(CLAIM.to_owned()),
        stance: SupportStance::Unlinked,
    };
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::InconsistentClaimBinding(
            "m-a".to_owned()
        ))
    );
}

#[test]
fn freeze_rejects_duplicate_missing_and_unknown_linkages() {
    let mut input = input_two_supporters();
    input
        .linkages
        .push(linked("m-a", SupportStance::ContextOnly));
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::DuplicateLinkage("m-a".to_owned()))
    );
    let mut input = input_two_supporters();
    input.linkages.pop();
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::MissingLinkage("m-b".to_owned()))
    );
    let mut input = input_two_supporters();
    input.linkages[0].member_id = "m-ghost".to_owned();
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::UnknownMemberLinkage(
            "m-ghost".to_owned()
        ))
    );
}

#[test]
fn freeze_rejects_invalid_evaluation_window() {
    let mut input = input_two_supporters();
    input.expires_at_secs = input.evaluated_at_secs;
    assert_eq!(
        FrozenEvidenceSet::freeze(input),
        Err(RoleSeparationError::InvalidEvaluationWindow)
    );
}

#[test]
fn verify_digest_detects_post_freeze_mutation() -> Result<(), RoleSeparationError> {
    let mut set = freeze_two_supporters()?;
    set.members[0].source_class = "mutated".to_owned();
    assert_eq!(
        set.verify_digest(),
        Err(RoleSeparationError::EnvelopeBindingMismatch)
    );
    let mut set = freeze_two_supporters()?;
    set.schema_version = "bogus-schema".to_owned();
    assert_eq!(
        set.verify_digest(),
        Err(RoleSeparationError::UnsupportedSchema(
            "bogus-schema".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn assessment_is_deterministic() -> Result<(), RoleSeparationError> {
    let set = freeze_two_supporters()?;
    let first = assess(&set)?;
    let second = assess(&set)?;
    assert_eq!(first, second);
    let json = serde_json::to_string(&first)?;
    let decoded: AssuranceResult = serde_json::from_str(&json)?;
    assert_eq!(decoded, first);
    assert_eq!(decoded.result_digest, first.result_digest);
    Ok(())
}

#[test]
fn complete_result_for_clean_support() -> Result<(), RoleSeparationError> {
    let result = assess(&freeze_two_supporters()?)?;
    assert_eq!(result.completeness, Completeness::Complete);
    assert_eq!(result.coverage.expected_members, 2);
    assert_eq!(result.coverage.usable_members, 2);
    assert_eq!(result.independence.independent_support_count, 2);
    assert_eq!(result.independence.unique_lineage_roots.len(), 2);
    assert_eq!(result.ceilings.len(), 1);
    let ceiling = &result.ceilings[0];
    assert_eq!(ceiling.max_use, EpistemicUse::EvidenceCandidate);
    assert_eq!(
        ceiling.confidence,
        ConfidenceObservation::SupportedByIndependentRoots
    );
    assert_eq!(ceiling.supporting_roots.len(), 2);
    assert!(ceiling.contradicting_roots.is_empty());
    Ok(())
}

#[test]
fn mirrors_share_one_independent_root() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    let mut mirror = member("m-mirror", Some("root-alpha"), "paper");
    mirror.citation_refs = vec![
        "https://mirror-a.invalid/x".to_owned(),
        "https://mirror-b.invalid/x".to_owned(),
        "https://mirror-c.invalid/x".to_owned(),
    ];
    input.members.push(mirror);
    input.observations.push(acquired("m-mirror", "m-mirror"));
    input
        .linkages
        .push(linked("m-mirror", SupportStance::Supports));
    let set = FrozenEvidenceSet::freeze(input)?;
    let result = assess(&set)?;
    assert_eq!(result.coverage.expected_members, 3);
    assert_eq!(result.coverage.usable_members, 3);
    assert_eq!(result.independence.unique_lineage_roots.len(), 2);
    assert_eq!(result.independence.independent_support_count, 1 + 1);
    assert!(
        result.independence.independent_support_count
            <= result.independence.unique_lineage_roots.len()
    );
    let group = mirror_group(&result, "root-alpha")?;
    assert_eq!(group.member_ids.len(), 2);
    let axes: Vec<&MemberAxisRecord> = result
        .member_axes
        .iter()
        .filter(|record| record.member_id == "m-mirror" || record.member_id == "m-a")
        .collect();
    assert!(
        axes.iter()
            .all(|record| record.independence == IndependenceState::SharedRoot)
    );
    Ok(())
}

#[test]
fn acquisition_without_linkage_yields_no_support() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    input.linkages = vec![
        linked("m-a", SupportStance::Unlinked),
        linked("m-b", SupportStance::Unlinked),
    ];
    let result = assess(&FrozenEvidenceSet::freeze(input)?)?;
    assert!(result.ceilings.is_empty());
    assert_eq!(result.coverage.usable_members, 2);
    assert_eq!(
        result.member_axes[0].integrity,
        IntegrityState::DigestMatched
    );
    assert_eq!(result.member_axes[0].relevance, RelevanceState::Unlinked);
    Ok(())
}

#[test]
fn contradiction_caps_use_and_is_preserved() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    input.linkages[1] = linked("m-b", SupportStance::Contradicts);
    let result = assess(&FrozenEvidenceSet::freeze(input)?)?;
    let ceiling = ceiling(&result, CLAIM)?;
    assert_eq!(ceiling.max_use, EpistemicUse::HypothesisCandidate);
    assert_eq!(
        ceiling.confidence,
        ConfidenceObservation::ContestedByIndependentRoots
    );
    assert_eq!(ceiling.supporting_roots, vec!["root-alpha".to_owned()]);
    assert_eq!(ceiling.contradicting_roots, vec!["root-beta".to_owned()]);
    assert!(matches!(
        result.completeness,
        Completeness::Incomplete { .. }
    ));
    let supporter = axes(&result, "m-a")?;
    assert_eq!(
        supporter.contradiction,
        MemberContradiction::ContestedByPeers
    );
    let dissenter = axes(&result, "m-b")?;
    assert_eq!(
        dissenter.contradiction,
        MemberContradiction::AssertsAgainstClaim
    );
    Ok(())
}

#[test]
fn unknown_lineage_blocks_completeness() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    input.members[1] = member("m-a", None, "paper");
    let result = assess(&FrozenEvidenceSet::freeze(input)?)?;
    let reasons = match &result.completeness {
        Completeness::Incomplete { reasons } => reasons.clone(),
        Completeness::Complete => panic!("must be incomplete"),
    };
    assert!(reasons.contains(&IncompletenessReason::UnknownLineage));
    assert!(!reasons.contains(&IncompletenessReason::PartialCoverage));
    assert_eq!(
        result.independence.unknown_lineage_members,
        vec!["m-a".to_owned()]
    );
    assert_eq!(result.independence.independent_support_count, 1);
    let ceiling = &result.ceilings[0];
    assert!(ceiling.support_from_unknown_lineage);
    assert_eq!(ceiling.supporting_roots, vec!["root-beta".to_owned()]);
    Ok(())
}

#[test]
fn stale_retracted_and_unavailable_block_completeness() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    input
        .members
        .push(member("m-c", Some("root-gamma"), "paper"));
    input
        .members
        .push(member("m-d", Some("root-delta"), "paper"));
    input
        .members
        .push(member("m-e", Some("root-epsilon"), "paper"));
    input.observations.push(MemberObservation {
        member_id: "m-c".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Stale {
            observed_digest: digest("bytes:m-c"),
            observed_at_secs: 10,
            frontier_generation: 1,
        },
    });
    input.observations.push(MemberObservation {
        member_id: "m-d".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Retracted {
            retraction_ref: "retraction-1".to_owned(),
        },
    });
    input.observations.push(MemberObservation {
        member_id: "m-e".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Unavailable {
            reason: "host unreachable".to_owned(),
        },
    });
    input.linkages.push(linked("m-c", SupportStance::Unlinked));
    input.linkages.push(linked("m-d", SupportStance::Unlinked));
    input.linkages.push(linked("m-e", SupportStance::Unlinked));
    let result = assess(&FrozenEvidenceSet::freeze(input)?)?;
    let reasons = match &result.completeness {
        Completeness::Incomplete { reasons } => reasons.clone(),
        Completeness::Complete => panic!("must be incomplete"),
    };
    for expected in [
        IncompletenessReason::PartialCoverage,
        IncompletenessReason::StalePresent,
        IncompletenessReason::RetractedPresent,
        IncompletenessReason::UnavailablePresent,
    ] {
        assert!(reasons.contains(&expected), "missing {expected:?}");
    }
    assert_eq!(result.coverage.usable_members, 2);
    let stale = axes(&result, "m-c")?;
    assert_eq!(stale.integrity, IntegrityState::DigestMatched);
    assert_eq!(stale.availability, AvailabilityState::Observed);
    assert_eq!(stale.accessibility, AccessibilityState::Accessible);
    let missing: Vec<&str> = result
        .blind_boundaries
        .iter()
        .filter_map(|boundary| match boundary {
            BlindBoundary::PartialCoverageGap { missing_member_ids } => Some(missing_member_ids),
            _ => None,
        })
        .flat_map(|ids| ids.iter().map(String::as_str))
        .collect();
    for id in ["m-c", "m-d", "m-e"] {
        assert!(missing.contains(&id), "gap names {id}");
    }
    Ok(())
}

#[test]
fn policy_exclusion_bars_support_but_keeps_evidence() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    input.policy.excluded_source_classes = vec!["licensed".to_owned()];
    input.members[1].source_class = "licensed".to_owned();
    let set = FrozenEvidenceSet::freeze(input)?;
    let result = assess(&set)?;
    assert_eq!(result.coverage.usable_members, 1);
    assert_eq!(
        result.coverage.excluded_class_members,
        vec!["m-a".to_owned()]
    );
    let ceiling = &result.ceilings[0];
    assert_eq!(ceiling.supporting_roots, vec!["root-beta".to_owned()]);
    assert!(result.blind_boundaries.iter().any(|boundary| matches!(
        boundary,
        BlindBoundary::PolicyExcludedClass { class } if class == "licensed"
    )));
    Ok(())
}

#[test]
fn coverage_is_sensitive_to_every_disposition() -> Result<(), RoleSeparationError> {
    let base = assess(&freeze_two_supporters()?)?;
    let mut input = input_two_supporters();
    input.observations[0] = MemberObservation {
        member_id: "m-a".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Withheld {
            policy_ref: "class:paper".to_owned(),
            reason: "embargo".to_owned(),
        },
    };
    input.policy.excluded_source_classes = vec!["paper".to_owned()];
    let changed = assess(&FrozenEvidenceSet::freeze(input)?)?;
    assert_ne!(base.result_digest, changed.result_digest);
    assert_ne!(
        base.coverage.denominator_digest,
        changed.coverage.denominator_digest
    );
    Ok(())
}

#[test]
fn coverage_is_sensitive_to_policy_exclusions() -> Result<(), RoleSeparationError> {
    let base = freeze_two_supporters()?;
    let mut input = input_two_supporters();
    input.policy.excluded_source_classes = vec!["paper".to_owned()];
    let changed = FrozenEvidenceSet::freeze(input)?;
    assert_ne!(base.set_digest, changed.set_digest);
    assert_ne!(base.policy_digest, changed.policy_digest);
    Ok(())
}

#[test]
fn replay_of_exact_input_is_idempotent() -> Result<(), RoleSeparationError> {
    let set = freeze_two_supporters()?;
    let result = assess(&set)?;
    assert_eq!(
        replay(&result, &set)?,
        ReplayOutcome::Identical {
            result_digest: result.result_digest.clone(),
        }
    );
    assert!(matches!(
        replay_at(&result, &set, 1_500)?,
        ReplayOutcome::Identical { .. }
    ));
    Ok(())
}

#[test]
fn replay_conflicts_on_denominator_change() -> Result<(), RoleSeparationError> {
    let set = freeze_two_supporters()?;
    let result = assess(&set)?;
    let mut input = input_two_supporters();
    input.revision = "rev-2".to_owned();
    input
        .members
        .push(member("m-c", Some("root-gamma"), "paper"));
    input.observations.push(acquired("m-c", "m-c"));
    input.linkages.push(linked("m-c", SupportStance::Supports));
    let grown = FrozenEvidenceSet::freeze(input)?;
    let outcome = replay(&result, &grown)?;
    let reasons = match outcome {
        ReplayOutcome::Conflict { reasons } => reasons,
        ReplayOutcome::Identical { .. } => panic!("must conflict"),
    };
    assert!(reasons.contains(&ReplayConflict::SetDigestChanged));
    assert!(reasons.contains(&ReplayConflict::CoverageChanged));
    Ok(())
}

#[test]
fn replay_conflicts_when_evaluation_expired() -> Result<(), RoleSeparationError> {
    let set = freeze_two_supporters()?;
    let result = assess(&set)?;
    let outcome = replay_at(&result, &set, 2_001)?;
    assert!(matches!(
        outcome,
        ReplayOutcome::Conflict { ref reasons } if reasons.contains(&ReplayConflict::EvaluationExpired)
    ));
    Ok(())
}

#[test]
fn replay_detects_altered_stored_result() -> Result<(), RoleSeparationError> {
    let set = freeze_two_supporters()?;
    let mut result = assess(&set)?;
    result.ceilings.clear();
    let outcome = replay(&result, &set)?;
    assert!(matches!(
        outcome,
        ReplayOutcome::Conflict { ref reasons } if reasons.contains(&ReplayConflict::ResultDigestMismatch)
    ));
    Ok(())
}

#[test]
fn dreamer_envelope_preserves_and_detects_tampering() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    input.linkages[1] = linked("m-b", SupportStance::Contradicts);
    let set = FrozenEvidenceSet::freeze(input)?;
    let result = assess(&set)?;
    let envelope = dreamer_envelope(&result, &set)?;
    verify_dreamer_envelope(&envelope)?;
    let mut stripped = envelope.clone();
    stripped.result.ceilings.clear();
    stripped.result.blind_boundaries.clear();
    assert_eq!(
        verify_dreamer_envelope(&stripped),
        Err(RoleSeparationError::EnvelopeVerificationFailed)
    );
    let other = freeze_two_supporters()?;
    assert_eq!(
        dreamer_envelope(&result, &other),
        Err(RoleSeparationError::EnvelopeBindingMismatch)
    );
    Ok(())
}

#[test]
fn governor_metadata_decides_nothing() -> Result<(), RoleSeparationError> {
    let result = assess(&freeze_two_supporters()?)?;
    let metadata = governor_candidate(&result);
    assert_eq!(metadata.set_digest, result.set_digest);
    assert_eq!(metadata.result_digest, result.result_digest);
    assert!(!metadata.contradiction_present);
    for ceiling in &metadata.ceilings {
        assert!(matches!(
            ceiling.max_use,
            EpistemicUse::EvidenceCandidate
                | EpistemicUse::HypothesisCandidate
                | EpistemicUse::NoUse
        ));
        assert!(matches!(
            ceiling.influence_ceiling,
            InfluenceCeiling::NoInfluence | InfluenceCeiling::CandidateEvidence
        ));
    }
    let mut input = input_two_supporters();
    input.linkages[1] = linked("m-b", SupportStance::Contradicts);
    let contested = assess(&FrozenEvidenceSet::freeze(input)?)?;
    assert!(governor_candidate(&contested).contradiction_present);
    Ok(())
}

#[test]
fn result_contract_has_schema_and_no_scalar_shape() -> Result<(), RoleSeparationError> {
    let schema = serde_json::to_string(&assurance_result_schema())?;
    assert!(schema.contains("AssuranceResult"));
    let result = assess(&freeze_two_supporters()?)?;
    let json = serde_json::to_string(&result)?;
    assert!(!json.contains("\"score\""));
    assert!(!json.contains("VERIFIED"));
    Ok(())
}

#[test]
fn axes_stay_separate_fields() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    input.policy.credential_gap_refs = vec!["gap-1".to_owned()];
    input.members.push(member("m-c", None, "paper"));
    input.observations.push(acquired("m-c", "m-c"));
    input.linkages.push(linked("m-c", SupportStance::Supports));
    let result = assess(&FrozenEvidenceSet::freeze(input)?)?;
    let record = axes(&result, "m-c")?;
    assert_eq!(record.provenance, ProvenanceState::UnknownLineage);
    assert_eq!(record.integrity, IntegrityState::DigestMatched);
    assert_eq!(record.availability, AvailabilityState::Observed);
    assert_eq!(record.independence, IndependenceState::UnknownLineage);
    assert_eq!(record.relevance, RelevanceState::DirectlyLinked);
    assert_eq!(record.stance, SupportStance::Supports);
    Ok(())
}

#[test]
fn shared_route_and_generator_raise_common_mode() -> Result<(), RoleSeparationError> {
    let mut input = input_two_supporters();
    for member in &mut input.members {
        member.lineage.generator = Some("shared-synthesis-run".to_owned());
    }
    let result = assess(&FrozenEvidenceSet::freeze(input)?)?;
    assert!(
        result
            .independence
            .common_mode_flags
            .iter()
            .any(|flag| matches!(flag.kind, CommonModeKind::SharedAcquisitionRoute))
    );
    assert!(
        result
            .independence
            .common_mode_flags
            .iter()
            .any(|flag| matches!(flag.kind, CommonModeKind::SharedGenerator))
    );
    assert!(
        result
            .blind_boundaries
            .iter()
            .any(|boundary| matches!(boundary, BlindBoundary::CommonModeRisk { .. }))
    );
    Ok(())
}
