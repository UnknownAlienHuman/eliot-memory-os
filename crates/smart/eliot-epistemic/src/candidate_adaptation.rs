//! Owner-local adaptation for a captured observation whose truth remains open.
//! The original resolver algebra stays private to this call boundary.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::{
    ClaimAuditOutcome, ClaimVerdict, ContractError, EpistemicPositionCandidate,
    PositionAssertability, PositionRequest, SupportResult,
};
use eliot_evidence::{EpistemicStatus, EvidenceAuthority, ObservationRecord};

/// Resolves the actual observation and validates its inert proposed candidate.
/// This first revision family records an observation with an explicit withheld
/// proposition. It grants neither support nor verifier standing to source text.
pub(crate) fn observed_candidate(
    request: &PositionRequest,
    observation: &ObservationRecord,
    candidate: &EpistemicPositionCandidate,
) -> Result<EpistemicPositionCandidate, ContractError> {
    let refused = || ContractError::ImpossibleCombination {
        field: "observed_candidate",
    };
    request.validate()?;
    candidate.validate()?;
    observation.validate().map_err(|_| refused())?;
    if observation.evidence.status != EpistemicStatus::Observed
        || observation.evidence.authority != EvidenceAuthority::SourceIdentity
        || observation.subject != request.question
        || request.records.len() != 1
        || !request.records.contains(&observation.observation_id)
    {
        return Err(refused());
    }
    let resolved = crate::resolve(&crate::PositionRequest {
        question: request.question.clone(),
        scope: request.scope.clone(),
        state_fence: request.fence.clone(),
        records: vec![crate::EpistemicRecord {
            handle: observation.observation_id.clone(),
            subject: observation.subject.clone(),
            scope: observation.evidence.provenance.scope.clone(),
            evidence: observation.evidence.clone(),
            supersedes: Vec::new(),
            note: None,
        }],
    })
    .map_err(|_| refused())?;
    if resolved.state != crate::PositionState::Observed
        || candidate.support.len() != 1
        || candidate.claims.len() != 1
        || candidate.proposed_assertability != PositionAssertability::UnknownWithheldQuarantined
        || !candidate.grade.is_unknown()
        || candidate.unknowns.is_empty()
        || candidate.verifier.is_some()
        || !candidate.rivals.is_empty()
        || !candidate.conflict_digests.is_empty()
    {
        return Err(refused());
    }
    let proof = canonical_json_bytes(observation).map_err(|_| refused())?;
    let proof_digest = sha256_hex(&proof);
    let statement = canonical_json_bytes(&observation.subject).map_err(|_| refused())?;
    let support = &candidate.support[0];
    let claim = &candidate.claims[0];
    if support.result != SupportResult::Unknown
        || support.handles != request.records
        || !support.grade.is_unknown()
        || support.proof_digest != proof_digest
        || candidate.proof_digest != proof_digest
        || candidate.authority != observation.evidence.authority
        || claim.authority != observation.evidence.authority
        || claim.statement_digest != sha256_hex(&statement)
        || claim.verdict != ClaimVerdict::Withheld
        || claim.audit != ClaimAuditOutcome::NotVerifiableInScope
        || !claim.grade.is_unknown()
        || claim.support != request.records
        || !claim.counterevidence.is_empty()
        || claim.conflict.is_some()
        || !claim.assumptions.is_empty()
    {
        return Err(refused());
    }
    Ok(candidate.clone())
}
