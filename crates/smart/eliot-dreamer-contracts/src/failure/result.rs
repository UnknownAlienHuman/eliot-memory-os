//! Candidate-only typed result for the A-03 Failure handoff.

use eliot_evidence::EvidenceEnvelope;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::candidate::CandidateDisposition;
use crate::curation::CurationKind;
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};
use crate::registry::TypedCurationHandlerResult;

use super::input::{FailureInput, failure_input_digest, failure_request_digest, normalize_input};
use super::records::{
    FailureCoverage, FailureEvidence, FailureProposal, FailureRollback, SCHEMA_VERSION,
    normalize_preservation, normalize_proposal, refs,
};

const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;

fn retained_envelope(
    envelopes: &[EvidenceEnvelope],
    evidence: &FailureEvidence,
) -> Result<bool, ContractViolation> {
    for envelope in envelopes {
        let bytes = canonical_bytes(envelope).map_err(|error| ContractViolation::Malformed {
            field: "failure.result.evidence_envelope",
            reason: error.to_string(),
        })?;
        if digest_hex(&bytes) == evidence.envelope_digest {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Failure-local dispositions retain uncertainty and lifecycle without granting effect authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureDisposition {
    Candidate,
    Hypothesis,
    Duplicate,
    Refinement,
    Conflict,
    Partial,
    Insufficient,
    Unsupported,
    Blocked,
    Abstention,
    Cancelled,
    Stale,
    Extinguished,
    InternalDefect,
}

/// Complete candidate result, retaining the full typed proposal and common handler envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureResult {
    pub schema_version: u32,
    pub candidate_id: String,
    pub operation_id: String,
    pub input_digest: String,
    pub policy_digest: String,
    pub input: FailureInput,
    pub proposal: FailureProposal,
    pub disposition: FailureDisposition,
    pub common_disposition: CandidateDisposition,
    pub preservation: crate::relation::RelationPreservation,
    pub final_preservation: crate::relation::RelationPreservation,
    pub assessment_refs: Vec<String>,
    pub assessment_missing_refs: Vec<String>,
    pub rollback: FailureRollback,
    pub proof_ceiling: ProofCeiling,
    pub handler_result: TypedCurationHandlerResult,
}

pub type FailureCandidate = FailureResult;

struct BoundedWriter {
    len: usize,
    max: usize,
}
impl std::io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.len = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("bounded result length overflow"))?;
        if self.len > self.max {
            return Err(std::io::Error::other("bounded result exceeded"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl FailureResult {
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        let mut writer = BoundedWriter {
            len: 0,
            max: MAX_RESULT_BYTES,
        };
        match serde_json::to_writer(&mut writer, self) {
            Ok(()) => Ok(()),
            Err(_error) if writer.len > MAX_RESULT_BYTES => Err(ContractViolation::OutOfBounds {
                field: "failure.result_bytes",
                min: 0,
                max: i64::try_from(MAX_RESULT_BYTES).unwrap_or(i64::MAX),
                got: i64::try_from(writer.len).unwrap_or(i64::MAX),
            }),
            Err(error) => Err(ContractViolation::Malformed {
                field: "failure.result",
                reason: error.to_string(),
            }),
        }
    }

    pub fn validate_against(&self, input: &FailureInput) -> Result<(), ContractViolation> {
        self.validate_identity_and_closure(input)?;
        self.validate_assessments(input)?;
        let complete = self.is_complete(input);
        self.validate_disposition(complete)?;
        self.validate_handler(input)
    }

    fn validate_identity_and_closure(&self, input: &FailureInput) -> Result<(), ContractViolation> {
        input.validate()?;
        self.preflight()?;
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "failure.result.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        for (value, field) in [
            (&self.candidate_id, "failure.result.candidate_id"),
            (&self.operation_id, "failure.result.operation_id"),
        ] {
            check_text(value, field, 1024)?;
        }
        for (value, field) in [
            (&self.input_digest, "failure.result.input_digest"),
            (&self.policy_digest, "failure.result.policy_digest"),
        ] {
            if !is_hex64_lower(value) {
                return Err(ContractViolation::Malformed {
                    field,
                    reason: "must be lowercase sha256".to_owned(),
                });
            }
        }
        if self.candidate_id
            != candidate_identity(
                self.operation_id.as_str(),
                &self.input_digest,
                &self.policy_digest,
            )?
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.candidate_id",
                reason: "candidate identity does not derive from operation/input/policy".to_owned(),
            });
        }
        if self.operation_id != input.operation.operation_id
            || self.input_digest != failure_input_digest(input)?
            || self.policy_digest != input.policy_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.identity",
                reason: "result does not bind exact input".to_owned(),
            });
        }
        if self.input != *input
            || self.proposal != input.proposal
            || self.preservation != input.preservation
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.closure",
                reason: "result does not retain the complete input closure".to_owned(),
            });
        }
        self.proposal.validate()?;
        self.preservation.validate()?;
        self.final_preservation.validate()?;
        Ok(())
    }

    fn validate_assessments(&self, input: &FailureInput) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.assessment_refs.len(),
            super::records::MAX_ITEMS,
            "failure.result.assessment_refs",
        )?;
        check_vec_bound(
            self.assessment_missing_refs.len(),
            super::records::MAX_ITEMS,
            "failure.result.assessment_missing_refs",
        )?;
        for reference in self
            .assessment_refs
            .iter()
            .chain(self.assessment_missing_refs.iter())
        {
            check_text(reference, "failure.result.assessment_ref", 1024)?;
        }
        refs(&self.assessment_refs, "failure.result.assessment_refs")?;
        refs(
            &self.assessment_missing_refs,
            "failure.result.assessment_missing_refs",
        )?;
        let mut retained = Vec::new();
        let mut omitted = Vec::new();
        for evidence in input
            .action_evidence
            .evidence
            .iter()
            .chain(input.history.historical_evidence.iter())
        {
            let present = retained_envelope(&input.action_evidence.evidence_envelopes, evidence)?
                || retained_envelope(&input.history.historical_evidence_envelopes, evidence)?;
            if present {
                if !retained
                    .iter()
                    .any(|id: &String| id == &evidence.evidence_id)
                {
                    retained.push(evidence.evidence_id.clone());
                }
            } else if (input
                .action_evidence
                .omitted_envelope_refs
                .contains(&evidence.envelope_digest)
                || input
                    .history
                    .omitted_evidence_envelope_refs
                    .contains(&evidence.envelope_digest))
                && !omitted
                    .iter()
                    .any(|id: &String| id == &evidence.evidence_id)
            {
                omitted.push(evidence.evidence_id.clone());
            }
        }
        if self
            .assessment_refs
            .iter()
            .any(|reference| !retained.iter().any(|id| id == reference))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.assessment_refs",
                reason: "assessment references outside complete closure".to_owned(),
            });
        }
        if self
            .assessment_missing_refs
            .iter()
            .any(|reference| retained.iter().any(|id| id == reference))
            || self
                .assessment_refs
                .iter()
                .any(|reference| self.assessment_missing_refs.contains(reference))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.assessment_missing_refs",
                reason: "assessment references and missing references must be disjoint".to_owned(),
            });
        }
        if self
            .assessment_missing_refs
            .iter()
            .any(|reference| !omitted.iter().any(|id| id == reference))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.assessment_missing_refs",
                reason: "missing assessment must name an explicit omitted closure member"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn is_complete(&self, input: &FailureInput) -> bool {
        self.proposal.history.coverage == FailureCoverage::Complete
            && self.proposal.outcome.coverage == FailureCoverage::Complete
            && self.proposal.environment.coverage == FailureCoverage::Complete
            && self.proposal.applicability.coverage == FailureCoverage::Complete
            && input.action_evidence.coverage == FailureCoverage::Complete
            && input.environment.coverage == FailureCoverage::Complete
            && matches!(
                input.proposal.comparison.comparator,
                super::records::FailureComparator::ExactEquality
            )
            && input.proposal.comparison.missing_dimensions.is_empty()
            && !input.proposal.comparison.dimensions.is_empty()
            && self.assessment_missing_refs.is_empty()
            && self.preservation.overall().is_ok()
            && self.final_preservation.overall().is_ok()
            && matches!(
                input.bundle.completeness,
                crate::bundle::BundleCompleteness::CompleteForScope
                    | crate::bundle::BundleCompleteness::KnownEmpty
            )
    }

    fn validate_disposition(&self, complete: bool) -> Result<(), ContractViolation> {
        self.rollback.validate()?;
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(ContractViolation::ForbiddenCarry(
                "failure result exceeds CandidateArtifact".to_owned(),
            ));
        }
        if common_disposition(self.disposition, complete) != self.common_disposition {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.disposition",
                reason: "local and common dispositions disagree".to_owned(),
            });
        }
        if matches!(
            self.disposition,
            FailureDisposition::Candidate | FailureDisposition::Refinement
        ) && !complete
        {
            return Err(ContractViolation::Preservation(
                "candidate/refinement requires complete outcome/history and passing preservation"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_handler(&self, input: &FailureInput) -> Result<(), ContractViolation> {
        self.handler_result.validate()?;
        if self.handler_result.kind != CurationKind::Failure
            || self.handler_result.family != crate::registry::CurationFamily::Failure
            || self.handler_result.disposition != self.common_disposition
            || self.handler_result.request_id != input.operation.request_id
            || self.handler_result.request_digest != failure_request_digest(&input.request)?
            || self.handler_result.result_digest != failure_result_digest(self)?
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.result.handler_result",
                reason: "handler envelope does not bind exact request/result".to_owned(),
            });
        }
        Ok(())
    }
}

fn common_disposition(local: FailureDisposition, complete: bool) -> CandidateDisposition {
    match local {
        FailureDisposition::Candidate | FailureDisposition::Refinement => {
            CandidateDisposition::Candidate
        }
        FailureDisposition::Hypothesis => {
            if complete {
                CandidateDisposition::Candidate
            } else {
                CandidateDisposition::Partial
            }
        }
        FailureDisposition::Duplicate => CandidateDisposition::Duplicate,
        FailureDisposition::Conflict => CandidateDisposition::Conflict,
        FailureDisposition::Partial | FailureDisposition::Insufficient => {
            CandidateDisposition::Partial
        }
        FailureDisposition::Unsupported
        | FailureDisposition::Stale
        | FailureDisposition::Extinguished => CandidateDisposition::Unsupported,
        FailureDisposition::Blocked => CandidateDisposition::Blocked,
        FailureDisposition::Abstention | FailureDisposition::Cancelled => {
            CandidateDisposition::Abstention
        }
        FailureDisposition::InternalDefect => CandidateDisposition::InternalDefect,
    }
}

fn candidate_identity(
    operation_id: &str,
    input_digest: &str,
    policy_digest: &str,
) -> Result<String, ContractViolation> {
    #[derive(Serialize)]
    struct Identity<'a> {
        operation_id: &'a str,
        input_digest: &'a str,
        policy_digest: &'a str,
    }
    Ok(digest_hex(&canonical_bytes(&Identity {
        operation_id,
        input_digest,
        policy_digest,
    })?))
}

pub fn failure_proposal_digest(proposal: &FailureProposal) -> Result<String, ContractViolation> {
    proposal.validate()?;
    let mut normalized = proposal.clone();
    normalize_proposal(&mut normalized)?;
    normalize_preservation(&mut normalized.preservation);
    Ok(digest_hex(&canonical_bytes(&normalized)?))
}

pub fn failure_result_digest(result: &FailureResult) -> Result<String, ContractViolation> {
    result.preflight()?;
    let mut normalized = result.clone();
    normalize_input(&mut normalized.input)?;
    normalize_proposal(&mut normalized.proposal)?;
    normalize_preservation(&mut normalized.input.preservation);
    normalize_preservation(&mut normalized.proposal.preservation);
    normalize_preservation(&mut normalized.preservation);
    normalize_preservation(&mut normalized.final_preservation);
    normalized.handler_result.result_digest = "0".repeat(64);
    normalized.assessment_refs.sort();
    normalized.assessment_missing_refs.sort();
    normalized.rollback.inverse_refs.sort();
    normalized.rollback.invalidation_refs.sort();
    normalized.rollback.raw_history_refs.sort();
    Ok(digest_hex(&canonical_bytes(&normalized)?))
}

/// Seals a result only after deriving its candidate and result identities.
pub fn seal_failure(
    mut result: FailureResult,
    input: &FailureInput,
) -> Result<FailureResult, ContractViolation> {
    result.preflight()?;
    result.input_digest = failure_input_digest(input)?;
    result.input.clone_from(input);
    result
        .operation_id
        .clone_from(&input.operation.operation_id);
    result.policy_digest.clone_from(&input.policy_digest);
    result.candidate_id = candidate_identity(
        &result.operation_id,
        &result.input_digest,
        &result.policy_digest,
    )?;
    result.handler_result.request_digest = failure_request_digest(&input.request)?;
    result.handler_result.result_digest = failure_result_digest(&result)?;
    result.validate_against(input)?;
    Ok(result)
}
