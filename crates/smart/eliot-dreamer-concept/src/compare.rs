//! Deterministic comparison with the supplied immutable neighborhood.

use crate::evidence::evidence_is_strong;
use eliot_dreamer_contracts::{
    ConceptApplicability, ConceptCriterionRole, ConceptInput, ConceptProposal, ConceptSnapshot,
    ContractViolation, concept_proposal_digest,
};

/// Outcome of comparing a proposal with supplied existing concepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Comparison {
    None,
    Duplicate,
    Refinement,
    Ambiguity,
    Distinct,
}

fn narrower(candidate: &ConceptApplicability, prior: &ConceptApplicability) -> bool {
    let same_axes = candidate.domain == prior.domain
        && candidate.population == prior.population
        && candidate.role == prior.role
        && candidate.environment == prior.environment
        && candidate.time == prior.time
        && candidate.version == prior.version;
    let parameters_preserved = candidate.parameters == prior.parameters;
    let exclusions_added = candidate.exclusions.len() > prior.exclusions.len()
        && prior
            .exclusions
            .iter()
            .all(|old| candidate.exclusions.contains(old));
    same_axes && parameters_preserved && exclusions_added
}

fn retains_history(candidate: &ConceptProposal, snapshot: &ConceptSnapshot) -> bool {
    let prior = &snapshot.proposal;
    if candidate.criteria.len() < prior.criteria.len()
        || !prior
            .applicability
            .exclusions
            .iter()
            .all(|exclusion| candidate.applicability.exclusions.contains(exclusion))
        || candidate.criteria[prior.criteria.len()..]
            .iter()
            .any(|criterion| criterion.role != ConceptCriterionRole::Exclusion)
    {
        return false;
    }
    let mut projected = candidate.clone();
    projected.concept_id = prior.concept_id.clone();
    projected.criteria.truncate(prior.criteria.len());
    projected
        .applicability
        .exclusions
        .clone_from(&prior.applicability.exclusions);
    concept_proposal_digest(&projected).ok().as_deref() == Some(snapshot.content_digest.as_str())
}

fn grounded_narrowing(candidate: &ConceptProposal, prior: &ConceptProposal) -> bool {
    let added = candidate
        .applicability
        .exclusions
        .iter()
        .filter(|exclusion| !prior.applicability.exclusions.contains(exclusion));
    let mut found = false;
    for exclusion in added {
        found = true;
        let grounded = candidate.criteria.iter().any(|criterion| {
            criterion.role == ConceptCriterionRole::Exclusion
                && criterion.statement == *exclusion
                && criterion.status == eliot_dreamer_contracts::CriterionStatus::Supported
                && !matches!(
                    criterion.applicability,
                    eliot_dreamer_contracts::CriterionApplicability::Unknown
                        | eliot_dreamer_contracts::CriterionApplicability::NotApplicable
                )
                && qualified_criterion(candidate, criterion)
        });
        if !grounded {
            return false;
        }
    }
    found
}

fn qualified_criterion(
    proposal: &ConceptProposal,
    criterion: &eliot_dreamer_contracts::ConceptCriterion,
) -> bool {
    !criterion.evidence_refs.is_empty()
        && criterion
            .evidence_refs
            .iter()
            .chain(&criterion.exception_refs)
            .all(|id| {
                proposal.evidence.iter().any(|evidence| {
                    evidence.evidence_id() == id && { evidence_is_strong(evidence) }
                })
            })
}

/// Compares only retained typed definitions, features, applicability and discriminator.
pub(crate) fn compare_neighborhood(input: &ConceptInput) -> Result<Comparison, ContractViolation> {
    let mut refinement_count = 0_usize;
    let mut duplicate = false;
    let proposal_digest = concept_proposal_digest(&input.proposal)?;
    for snapshot in &input.neighborhood.concepts {
        let snapshot_digest = concept_proposal_digest(&snapshot.proposal)?;
        if input.proposal.concept_id == snapshot.concept_id {
            if proposal_digest != snapshot_digest {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.neighborhood.concept_id",
                    reason: "changed proposal reuses an existing concept identity".to_owned(),
                });
            }
            duplicate = true;
        } else if proposal_digest == snapshot_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.neighborhood.content_digest",
                reason: "identical proposal content has a different concept identity".to_owned(),
            });
        }
        if input.proposal.name == snapshot.proposal.name
            && input.proposal.definition == snapshot.proposal.definition
            && narrower(
                &input.proposal.applicability,
                &snapshot.proposal.applicability,
            )
            && grounded_narrowing(&input.proposal, &snapshot.proposal)
            && retains_history(&input.proposal, snapshot)
        {
            refinement_count =
                refinement_count
                    .checked_add(1)
                    .ok_or(ContractViolation::Budget {
                        dimension: "concept.comparison",
                        reason: "eligible predecessor count overflow".to_owned(),
                    })?;
        }
    }
    if refinement_count > 1 {
        Ok(Comparison::Ambiguity)
    } else if duplicate {
        Ok(Comparison::Duplicate)
    } else if refinement_count == 1 {
        Ok(Comparison::Refinement)
    } else if input.neighborhood.concepts.is_empty() {
        Ok(Comparison::None)
    } else {
        Ok(Comparison::Distinct)
    }
}

/// Returns a predecessor only for a typed narrower match.
pub(crate) fn predecessor(
    input: &ConceptInput,
    comparison: Comparison,
) -> Option<&ConceptSnapshot> {
    if comparison != Comparison::Refinement {
        return None;
    }
    input.neighborhood.concepts.iter().find(|snapshot| {
        snapshot.proposal.name == input.proposal.name
            && snapshot.proposal.definition == input.proposal.definition
            && narrower(
                &input.proposal.applicability,
                &snapshot.proposal.applicability,
            )
            && grounded_narrowing(&input.proposal, &snapshot.proposal)
            && retains_history(&input.proposal, snapshot)
    })
}
