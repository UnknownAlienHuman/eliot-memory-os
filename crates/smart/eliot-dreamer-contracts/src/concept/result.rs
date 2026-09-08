//! Candidate-only Concept result closure.

use eliot_contracts::ArtifactId;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use crate::candidate::CandidateDisposition;
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};
use crate::registry::TypedCurationHandlerResult;
use crate::relation::RelationPreservation;

use super::input::{ConceptInput, concept_input_digest, concept_request_digest};
use super::proposal::{
    ConceptMode, ConceptProposal, MAX_ITEMS, MAX_TEXT, normalized_preservation, normalized_proposal,
};

const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;

/// Concept-local semantic disposition; it remains nested under the common A-03 result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConceptDisposition {
    Candidate,
    Hypothesis,
    Duplicate,
    Refinement,
    Conflict,
    Partial,
    Insufficient,
    Ambiguity,
    Unsupported,
    Blocked,
    NoChange,
    OwnerHandoff,
    Abstention,
    Cancelled,
    InternalDefect,
}

/// Addressable history and reversal references retained by a candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptRollback {
    pub predecessor: Option<ArtifactId>,
    pub history_refs: Vec<ArtifactId>,
    pub reversal_refs: Vec<ArtifactId>,
    pub invalidation_refs: Vec<ArtifactId>,
    pub note: String,
}

impl ConceptRollback {
    fn validate(&self) -> Result<(), ContractViolation> {
        for refs in [
            &self.history_refs,
            &self.reversal_refs,
            &self.invalidation_refs,
        ] {
            check_vec_bound(refs.len(), MAX_ITEMS, "concept.rollback.refs")?;
            for (index, id) in refs.iter().enumerate() {
                check_text(id.as_str(), "concept.rollback.ref", MAX_TEXT)?;
                if refs[..index].contains(id) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "concept.rollback.refs",
                        reason: "duplicate rollback identity".to_owned(),
                    });
                }
            }
        }
        if let Some(id) = &self.predecessor {
            check_text(id.as_str(), "concept.rollback.predecessor", MAX_TEXT)?;
        }
        check_text(&self.note, "concept.rollback.note", MAX_TEXT)
    }

    fn validate_against(&self, input: &ConceptInput) -> Result<(), ContractViolation> {
        self.validate()?;
        let mut allowed = Vec::new();
        allowed.extend(
            input
                .sources
                .sources
                .iter()
                .map(|source| source.source_id.clone()),
        );
        allowed.extend(
            input
                .proposal
                .evidence
                .iter()
                .map(|evidence| evidence.evidence_id().clone()),
        );
        allowed.extend(
            input
                .neighborhood
                .concepts
                .iter()
                .map(|snapshot| snapshot.concept_id.clone()),
        );
        let check = |id: &ArtifactId, field: &'static str| {
            if allowed.contains(id) {
                Ok(())
            } else {
                Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "rollback identity is outside input closure".to_owned(),
                })
            }
        };
        if let Some(predecessor) = &self.predecessor {
            check(predecessor, "concept.rollback.predecessor")?;
        }
        for id in self
            .history_refs
            .iter()
            .chain(&self.reversal_refs)
            .chain(&self.invalidation_refs)
        {
            check(id, "concept.rollback.refs")?;
        }
        Ok(())
    }
}

/// Typed Concept candidate that preserves the entire validated proposal closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptCandidate {
    pub schema_version: u32,
    pub candidate_id: ArtifactId,
    pub operation_id: ArtifactId,
    pub input_digest: String,
    pub policy_digest: String,
    pub mode: ConceptMode,
    pub proposal: ConceptProposal,
    pub disposition: ConceptDisposition,
    pub common_disposition: CandidateDisposition,
    pub preservation: RelationPreservation,
    pub rollback: ConceptRollback,
    pub proof_ceiling: ProofCeiling,
    pub handler_result: TypedCurationHandlerResult,
}

impl ConceptCandidate {
    pub fn validate_against(&self, input: &ConceptInput) -> Result<(), ContractViolation> {
        input.validate()?;
        preflight_candidate(self)?;
        check_text(self.candidate_id.as_str(), "concept.candidate_id", MAX_TEXT)?;
        check_text(self.operation_id.as_str(), "concept.operation_id", MAX_TEXT)?;
        if self.schema_version != 1 {
            return Err(ContractViolation::OutOfBounds {
                field: "concept.result.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        if !is_hex64_lower(&self.input_digest) {
            return Err(ContractViolation::Malformed {
                field: "concept.input_digest",
                reason: "must be lowercase sha256".to_owned(),
            });
        }
        let expected_candidate_id = candidate_identity(self)?;
        if self.candidate_id != expected_candidate_id {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.candidate_id",
                reason: "candidate identity is not derived from operation/input/policy".to_owned(),
            });
        }
        if self.operation_id != input.operation_id
            || self.input_digest != concept_input_digest(input)?
            || self.policy_digest != input.policy_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.result.identity",
                reason: "result does not bind exact input".to_owned(),
            });
        }
        if self.mode != input.proposal.mode || self.proposal != input.proposal {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.result.proposal",
                reason: "result changed structured proposal or scope".to_owned(),
            });
        }
        let structurally_complete = self.proposal.case_coverage
            == super::proposal::ConceptCoverage::Complete
            && input.sources.denominator.coverage == super::proposal::ConceptCoverage::Complete
            && input.neighborhood.coverage == super::proposal::ConceptCoverage::Complete
            && self.preservation.overall().is_ok();
        if common_disposition(self.disposition, structurally_complete) != self.common_disposition {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.result.disposition",
                reason: "local Concept disposition has no compatible common disposition".to_owned(),
            });
        }
        if matches!(
            self.disposition,
            ConceptDisposition::Candidate | ConceptDisposition::Refinement
        ) && !structurally_complete
        {
            return Err(ContractViolation::Preservation(
                "complete Concept result requires complete coverage and passing known preservation"
                    .to_owned(),
            ));
        }
        self.proposal.validate()?;
        self.preservation.validate()?;
        if self.preservation != input.preservation {
            return Err(ContractViolation::Preservation(
                "result cannot replace input preservation report".to_owned(),
            ));
        }
        self.rollback.validate_against(input)?;
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(ContractViolation::ForbiddenCarry(
                "concept result exceeds CandidateArtifact proof ceiling".to_owned(),
            ));
        }
        self.validate_handler_result(input)?;
        Ok(())
    }

    fn validate_handler_result(&self, input: &ConceptInput) -> Result<(), ContractViolation> {
        self.handler_result.validate()?;
        if self.handler_result.kind != crate::curation::CurationKind::Concept
            || self.handler_result.family != crate::registry::CurationFamily::Concept
        {
            return Err(ContractViolation::KindPayload(
                "concept result handler envelope drift".to_owned(),
            ));
        }
        if self.handler_result.disposition != self.common_disposition {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.result.handler_disposition",
                reason: "handler result disposition differs from common result disposition"
                    .to_owned(),
            });
        }
        if self.handler_result.request_id != input.request_id
            || self.handler_result.request_digest != concept_request_digest(&input.request)?
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.result.handler_identity",
                reason: "handler result does not bind exact typed request".to_owned(),
            });
        }
        if self.handler_result.result_digest != candidate_digest(self)? {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.result.result_digest",
                reason: "result digest does not bind canonical candidate content".to_owned(),
            });
        }
        Ok(())
    }
}

/// Seals a Concept candidate after exact input-closure validation.
pub fn seal_concept(
    candidate: ConceptCandidate,
    input: &ConceptInput,
) -> Result<ConceptCandidate, ContractViolation> {
    preflight_candidate(&candidate)?;
    let mut sealed = candidate;
    sealed.candidate_id = candidate_identity(&sealed)?;
    sealed.handler_result.result_digest = candidate_digest(&sealed)?;
    sealed.validate_against(input)?;
    Ok(sealed)
}

fn common_disposition(
    disposition: ConceptDisposition,
    structurally_complete: bool,
) -> CandidateDisposition {
    match disposition {
        ConceptDisposition::Candidate | ConceptDisposition::Refinement => {
            CandidateDisposition::Candidate
        }
        ConceptDisposition::Hypothesis => {
            if structurally_complete {
                CandidateDisposition::Candidate
            } else {
                CandidateDisposition::Partial
            }
        }
        ConceptDisposition::Duplicate => CandidateDisposition::Duplicate,
        ConceptDisposition::Conflict => CandidateDisposition::Conflict,
        ConceptDisposition::Partial
        | ConceptDisposition::Insufficient
        | ConceptDisposition::Ambiguity => CandidateDisposition::Partial,
        ConceptDisposition::Unsupported => CandidateDisposition::Unsupported,
        ConceptDisposition::NoChange
        | ConceptDisposition::OwnerHandoff
        | ConceptDisposition::Abstention
        | ConceptDisposition::Cancelled => CandidateDisposition::Abstention,
        ConceptDisposition::Blocked => CandidateDisposition::Blocked,
        ConceptDisposition::InternalDefect => CandidateDisposition::InternalDefect,
    }
}

fn candidate_digest(candidate: &ConceptCandidate) -> Result<String, ContractViolation> {
    let mut preimage = candidate.clone();
    preimage.proposal = normalized_proposal(&preimage.proposal);
    preimage.preservation = normalized_preservation(&preimage.preservation);
    preimage.rollback.history_refs.sort();
    preimage.rollback.reversal_refs.sort();
    preimage.rollback.invalidation_refs.sort();
    preimage.handler_result.result_digest = "0".repeat(64);
    Ok(digest_hex(&canonical_bytes(&preimage)?))
}

fn candidate_identity(candidate: &ConceptCandidate) -> Result<ArtifactId, ContractViolation> {
    #[derive(Serialize)]
    struct Identity<'a> {
        operation_id: &'a ArtifactId,
        input_digest: &'a str,
        policy_digest: &'a str,
    }
    let identity = Identity {
        operation_id: &candidate.operation_id,
        input_digest: &candidate.input_digest,
        policy_digest: &candidate.policy_digest,
    };
    ArtifactId::new(digest_hex(&canonical_bytes(&identity)?)).map_err(|_| {
        ContractViolation::Malformed {
            field: "concept.candidate_id",
            reason: "derived candidate identity is invalid".to_owned(),
        }
    })
}

fn preflight_candidate(candidate: &ConceptCandidate) -> Result<(), ContractViolation> {
    let mut writer = BoundedWriter {
        len: 0,
        max: MAX_RESULT_BYTES,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, candidate) {
        Ok(()) => Ok(()),
        Err(_error) if writer.exceeded => Err(ContractViolation::OutOfBounds {
            field: "concept.result_bytes",
            min: 0,
            max: i64::try_from(MAX_RESULT_BYTES).unwrap_or(i64::MAX),
            got: i64::try_from(writer.len).unwrap_or(i64::MAX),
        }),
        Err(error) => Err(ContractViolation::Malformed {
            field: "concept.result",
            reason: error.to_string(),
        }),
    }
}

struct BoundedWriter {
    len: usize,
    max: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized Concept result length overflow"))?;
        if next > self.max {
            self.len = self.max.checked_add(1).unwrap_or(self.max);
            self.exceeded = true;
            return Err(io::Error::other("serialized Concept result exceeds bound"));
        }
        self.len = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
