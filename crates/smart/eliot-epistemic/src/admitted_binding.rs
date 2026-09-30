//! Exact join between an admitted observed candidate and the resolver's native
//! view of the source observation that produced it.

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::{
    ClaimAuditOutcome, ClaimVerdict, CurrentEpistemicPosition as AdmittedPosition, Currentness,
    EpistemicPositionCandidate, PositionAssertability, SupportResult,
};
use eliot_evidence::{
    EvidenceAuthority, EvidenceFreshness, EpistemicStatus, LifecycleState, ObservationRecord,
};
use serde::Serialize;
use thiserror::Error;

use crate::{CurrentEpistemicPosition, PositionRequest, PositionState};

/// Refusal to join the observed-candidate owner record to native resolver input.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdmittedBindingError {
    /// The original candidate is malformed or its frozen digest changed.
    #[error("original candidate failed contract validation")]
    CandidateContract,
    /// The original admitted view is malformed or its frozen digest changed.
    #[error("original admitted position failed contract validation")]
    PositionContract,
    /// The resolver request is not a valid native owner request.
    #[error("native resolver request failed validation")]
    ResolverRequest,
    /// The captured source record is not a valid observation.
    #[error("original observation failed source validation")]
    Observation,
    /// Canonical bytes could not be produced for a source-owned preimage.
    #[error("source preimage could not be canonicalized")]
    Canonicalization,
    /// A typed input or retained result differs from its original owner value.
    #[error("admitted position binding mismatch: {field}")]
    Mismatch { field: &'static str },
    /// This producer only supports the observed candidate shape with exact source evidence.
    #[error("observed candidate binding does not support: {field}")]
    Unsupported { field: &'static str },
}

/// A validated borrow of the original candidate and admitted view.
///
/// This value does not issue or copy a receipt. Its references remain bound to
/// the candidate and Current view returned together by storage readback.
#[derive(Clone, Copy, Debug)]
pub struct AdmittedPositionBinding<'a> {
    candidate: &'a EpistemicPositionCandidate,
    position: &'a AdmittedPosition,
}

impl<'a> AdmittedPositionBinding<'a> {
    /// The exact candidate returned by the storage readback producer.
    pub fn candidate(self) -> &'a EpistemicPositionCandidate {
        self.candidate
    }

    /// The exact admitted Current view returned beside that candidate.
    pub fn position(self) -> &'a AdmittedPosition {
        self.position
    }
}

/// Verifies the original storage-issued view and exact native observed resolver
/// result against the original candidate and captured observation.
///
/// The supported path deliberately matches the existing observed-candidate
/// producer: one active, fresh, SourceIdentity observation yields one withheld
/// claim and an Unknown support result. Other candidate families have no
/// faithful mapping to this resolver algebra and are refused explicitly.
pub fn bind_admitted_position<'a>(
    candidate: &'a EpistemicPositionCandidate,
    admitted: &'a AdmittedPosition,
    observation: &ObservationRecord,
    request: &PositionRequest,
    resolved: &CurrentEpistemicPosition,
) -> Result<AdmittedPositionBinding<'a>, AdmittedBindingError> {
    candidate
        .validate()
        .map_err(|_| AdmittedBindingError::CandidateContract)?;
    admitted
        .validate()
        .map_err(|_| AdmittedBindingError::PositionContract)?;
    request
        .validate()
        .map_err(|_| AdmittedBindingError::ResolverRequest)?;
    observation
        .validate()
        .map_err(|_| AdmittedBindingError::Observation)?;

    if admitted.currentness != Currentness::Current || !admitted.supersession.is_empty() {
        return Err(AdmittedBindingError::Mismatch {
            field: "position currentness",
        });
    }
    if candidate.digest != admitted.admission.payload_digest {
        return Err(AdmittedBindingError::Mismatch {
            field: "original candidate payload digest",
        });
    }
    if candidate.scope != admitted.admission.scope || candidate.scope != request.scope {
        return Err(AdmittedBindingError::Mismatch {
            field: "original candidate scope",
        });
    }
    if candidate.fence != admitted.admission.fence || candidate.fence != request.state_fence {
        return Err(AdmittedBindingError::Mismatch {
            field: "original candidate state fence",
        });
    }
    if digest(&candidate.support)? != admitted.admission.evidence_digest {
        return Err(AdmittedBindingError::Mismatch {
            field: "original evidence digest preimage",
        });
    }
    if candidate.coverage_digest != admitted.admission.coverage_digest {
        return Err(AdmittedBindingError::Mismatch {
            field: "original coverage digest preimage",
        });
    }
    if digest(&candidate.conflict_digests)? != admitted.admission.conflict_digest {
        return Err(AdmittedBindingError::Mismatch {
            field: "original conflict digest preimage",
        });
    }
    if candidate.proof_digest != admitted.admission.proof_digest {
        return Err(AdmittedBindingError::Mismatch {
            field: "original proof digest preimage",
        });
    }

    if candidate.claims.len() != 1 || candidate.support.len() != 1 {
        return Err(AdmittedBindingError::Unsupported {
            field: "candidate must be the existing single-observation producer shape",
        });
    }
    let claim = &candidate.claims[0];
    let support = &candidate.support[0];
    if admitted.claim != claim.claim {
        return Err(AdmittedBindingError::Mismatch {
            field: "admitted claim identity",
        });
    }
    if candidate.scope != request.scope
        || candidate.fence != request.state_fence
        || observation.subject != request.question
        || observation.evidence.provenance.scope != request.scope
        || observation.evidence.state_fence != request.state_fence
        || observation.evidence.authority != EvidenceAuthority::SourceIdentity
        || observation.evidence.status != EpistemicStatus::Observed
        || observation.lifecycle != LifecycleState::Active
        || request.records.len() != 1
        || !request.records.contains(&observation.observation_id)
    {
        return Err(AdmittedBindingError::Mismatch {
            field: "captured observation and resolver request",
        });
    }
    if !matches!(
        observation.evidence.freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    ) {
        return Err(AdmittedBindingError::Unsupported {
            field: "non-current observation freshness",
        });
    }
    let Some(record) = request.records.first() else {
        return Err(AdmittedBindingError::ResolverRequest);
    };
    if record.handle != observation.observation_id
        || record.subject != observation.subject
        || record.scope != observation.evidence.provenance.scope
        || record.evidence != observation.evidence
        || !record.supersedes.is_empty()
        || record.note.is_some()
    {
        return Err(AdmittedBindingError::Mismatch {
            field: "native resolver record and original observation",
        });
    }

    let source_proof = digest(observation)?;
    if candidate.proof_digest != source_proof || support.proof_digest != source_proof {
        return Err(AdmittedBindingError::Mismatch {
            field: "original observation proof digest",
        });
    }
    let statement_digest = digest(&observation.subject)?;
    let only_handle = BTreeSet::from([observation.observation_id.clone()]);
    if claim.statement_digest != statement_digest
        || claim.verdict != ClaimVerdict::Withheld
        || claim.audit != ClaimAuditOutcome::NotVerifiableInScope
        || !claim.grade.is_unknown()
        || claim.authority != observation.evidence.authority
        || claim.support != only_handle
        || !claim.counterevidence.is_empty()
        || claim.conflict.is_some()
        || !claim.assumptions.is_empty()
        || support.result != SupportResult::Unknown
        || support.handles != only_handle
        || !support.grade.is_unknown()
        || support.assurance.is_some()
        || support.temporal.is_some()
        || candidate.authority != observation.evidence.authority
        || !candidate.grade.is_unknown()
        || candidate.proposed_assertability
            != PositionAssertability::UnknownWithheldQuarantined
        || candidate.unknowns != BTreeSet::from(["proposition-unverified".to_owned()])
        || candidate.verifier.is_some()
        || !candidate.rivals.is_empty()
        || !candidate.conflict_digests.is_empty()
        || !candidate.temporal_digests.is_empty()
    {
        return Err(AdmittedBindingError::Mismatch {
            field: "observed candidate claim and support semantics",
        });
    }

    let record_handles = vec![observation.observation_id.clone()];
    let source_ids = vec![observation.evidence.provenance.source_id.to_string()];
    let raw_handles = observation
        .evidence
        .provenance
        .raw_handle
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let revisions = observation
        .evidence
        .provenance
        .revision
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    if resolved.question != request.question
        || resolved.scope != request.scope
        || resolved.state_fence != request.state_fence
        || resolved.state != PositionState::Observed
        || resolved.direct_observations != record_handles
        || !resolved.supporting_records.is_empty()
        || !resolved.rival_records.is_empty()
        || !resolved.stale_records.is_empty()
        || !resolved.superseded_records.is_empty()
        || !resolved.unknowns.is_empty()
        || !resolved.required_inquiry.is_empty()
        || resolved.provenance.record_handles != record_handles
        || resolved.provenance.source_ids != source_ids
        || resolved.provenance.raw_handles != raw_handles
        || resolved.provenance.revisions != revisions
        || resolved.provenance.mixed_sources
        || resolved.provenance.assertability != observation.evidence.assertability
    {
        return Err(AdmittedBindingError::Mismatch {
            field: "native resolver result and original observation",
        });
    }

    Ok(AdmittedPositionBinding {
        candidate,
        position: admitted,
    })
}

fn digest<T: Serialize>(value: &T) -> Result<String, AdmittedBindingError> {
    let bytes = canonical_json_bytes(value).map_err(|_| AdmittedBindingError::Canonicalization)?;
    Ok(sha256_hex(&bytes))
}
