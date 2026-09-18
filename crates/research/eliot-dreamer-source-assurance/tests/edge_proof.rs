//! Edge proof: one frozen Research evidence set through source assurance
//! and the Dreamer and Governor adapters.
//!
//! The proof runs the shared portfolio with mirrors, common lineage, an
//! unavailable member, a retraction, a conflict, stale evidence, a
//! credentialed gap, and a partial denominator, then proves invalidation:
//! a retraction and a denominator change each conflict exact replay.

mod common;

use common::{BOUNDARY, CLAIM_ONE, digest, freeze_rich_portfolio};
use eliot_dreamer_source_assurance::{
    ClaimLinkage, ExpectedMember, FreezeInput, FrozenEvidenceSet, LineageAttribution,
    MemberDisposition, MemberObservation, ReplayConflict, ReplayOutcome, RoleSeparationError,
    SupportStance, assess, dreamer_envelope, governor_candidate, replay, replay_at,
    verify_dreamer_envelope,
};

/// Fallible edge-proof outcome over the public contract.
type Outcome = Result<(), Box<dyn std::error::Error>>;

/// The full edge: frozen set, assurance, Dreamer envelope, Governor metadata.
#[test]
fn frozen_evidence_set_edge_proof() -> Outcome {
    let set = freeze_rich_portfolio()?;
    let result = assess(&set)?;
    assert_eq!(result.set_digest, set.set_digest);
    assert_eq!(result.coverage.expected_members, 8);
    assert_eq!(result.coverage.usable_members, 3);
    assert_eq!(result.independence.independent_support_count, 2);
    assert!(
        result.independence.independent_support_count
            <= result.independence.unique_lineage_roots.len()
    );

    let envelope = dreamer_envelope(&result, &set)?;
    verify_dreamer_envelope(&envelope)?;

    let metadata = governor_candidate(&result);
    assert_eq!(metadata.set_digest, set.set_digest);
    assert_eq!(metadata.result_digest, result.result_digest);
    assert!(metadata.contradiction_present);

    assert!(matches!(
        replay(&result, &set)?,
        ReplayOutcome::Identical { .. }
    ));
    assert!(matches!(
        replay_at(&result, &set, 1_500)?,
        ReplayOutcome::Identical { .. }
    ));
    Ok(())
}

/// A retraction of a supporting member invalidates exact replay.
#[test]
fn retraction_invalidates_exact_replay() -> Outcome {
    let set = freeze_rich_portfolio()?;
    let before = assess(&set)?;
    let members: Vec<ExpectedMember> = set.members.clone();
    assert!(members.iter().any(|member| member.member_id == "m3"));
    let observations: Vec<MemberObservation> = set
        .observations
        .iter()
        .map(|observation| {
            if observation.member_id == "m3" {
                MemberObservation {
                    member_id: "m3".to_owned(),
                    evaluation_boundary: BOUNDARY.to_owned(),
                    disposition: MemberDisposition::Retracted {
                        retraction_ref: "retraction-3".to_owned(),
                    },
                }
            } else {
                observation.clone()
            }
        })
        .collect();
    let linkages: Vec<ClaimLinkage> = set
        .linkages
        .iter()
        .map(|linkage| {
            if linkage.member_id == "m3" {
                ClaimLinkage {
                    member_id: "m3".to_owned(),
                    claim_id: None,
                    stance: SupportStance::Unlinked,
                }
            } else {
                linkage.clone()
            }
        })
        .collect();
    let retracted = FrozenEvidenceSet::freeze(FreezeInput {
        set_id: set.set_id.clone(),
        revision: "rev-2".to_owned(),
        evaluation_boundary: set.evaluation_boundary.clone(),
        evaluated_at_secs: set.evaluated_at_secs,
        expires_at_secs: set.expires_at_secs,
        members,
        observations,
        linkages,
        policy: set.policy.clone(),
    })?;
    let outcome = replay(&before, &retracted)?;
    let reasons = match outcome {
        ReplayOutcome::Conflict { reasons } => reasons,
        ReplayOutcome::Identical { .. } => {
            return Err("retraction must conflict replay".into());
        }
    };
    assert!(reasons.contains(&ReplayConflict::SetDigestChanged));
    assert!(reasons.contains(&ReplayConflict::CoverageChanged));
    let after = assess(&retracted)?;
    assert_ne!(before.result_digest, after.result_digest);
    assert_eq!(after.coverage.usable_members, 2);
    let ceiling = after
        .ceilings
        .iter()
        .find(|entry| entry.claim_id == CLAIM_ONE)
        .ok_or(RoleSeparationError::MissingField("ceilings"))?;
    assert_eq!(ceiling.supporting_roots.len(), 1);
    Ok(())
}

/// A denominator change mints a new identity and conflicts replay.
#[test]
fn denominator_change_conflicts_replay() -> Outcome {
    let set = freeze_rich_portfolio()?;
    let before = assess(&set)?;
    let mut members = set.members.clone();
    members.push(ExpectedMember {
        member_id: "m9".to_owned(),
        content_digest: digest("bytes:m9"),
        lineage: LineageAttribution {
            root: Some("root-h".to_owned()),
            acquisition_route: "route-8".to_owned(),
            publisher: "research-publisher".to_owned(),
            generator: None,
        },
        source_class: "paper".to_owned(),
        citation_refs: vec!["https://origin.invalid/paper-9".to_owned()],
    });
    let mut observations = set.observations.clone();
    observations.push(MemberObservation {
        member_id: "m9".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Acquired {
            observed_digest: digest("bytes:m9"),
            lineage_complete: true,
        },
    });
    let mut linkages = set.linkages.clone();
    linkages.push(ClaimLinkage {
        member_id: "m9".to_owned(),
        claim_id: Some(CLAIM_ONE.to_owned()),
        stance: SupportStance::Supports,
    });
    let grown = FrozenEvidenceSet::freeze(FreezeInput {
        set_id: set.set_id.clone(),
        revision: "rev-2".to_owned(),
        evaluation_boundary: set.evaluation_boundary.clone(),
        evaluated_at_secs: set.evaluated_at_secs,
        expires_at_secs: set.expires_at_secs,
        members,
        observations,
        linkages,
        policy: set.policy.clone(),
    })?;
    let outcome = replay(&before, &grown)?;
    assert!(matches!(
        outcome,
        ReplayOutcome::Conflict { ref reasons }
            if reasons.contains(&ReplayConflict::SetDigestChanged)
                && reasons.contains(&ReplayConflict::CoverageChanged)
    ));
    let after = assess(&grown)?;
    assert_eq!(after.coverage.expected_members, 9);
    assert_eq!(after.coverage.usable_members, 4);
    Ok(())
}
