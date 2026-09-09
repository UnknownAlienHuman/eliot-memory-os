//! Phase-oriented Failure candidate assembly.

use crate::assessment::{
    ApplicabilityAssessment, FailureAssessment, OutcomeAssessment, TriggerAssessment,
};
use crate::policy::FailurePolicy;
use eliot_dreamer_contracts::{
    CandidateDisposition, ContractViolation, CurationFamily, CurationHandlerDescriptor,
    CurationHandlerPort, CurationKind, FailureActionEvidence, FailureDisposition,
    FailureEnvironment, FailureHistory, FailureInput, FailureProposal, TypedCurationHandlerResult,
    canonical_bytes, digest_hex, failure_result_digest, seal_failure,
};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_DECISION_BYTES: u64 = 4 * 1024 * 1024;

struct DecisionWriter {
    used: usize,
    max: usize,
}

impl Write for DecisionWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("decision length overflow"))?;
        if self.used > self.max {
            return Err(io::Error::other("bounded decision exceeded"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_serialized_len<T: Serialize>(
    value: &T,
    max: u64,
    field: &'static str,
) -> Result<u64, ContractViolation> {
    let mut writer = DecisionWriter {
        used: 0,
        max: usize::try_from(max).unwrap_or(usize::MAX),
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => u64::try_from(writer.used).map_err(|_| ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: i64::MAX,
            got: i64::MAX,
        }),
        Err(_) if writer.used > writer.max => Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: i64::try_from(max).unwrap_or(i64::MAX),
            got: i64::try_from(writer.used).unwrap_or(i64::MAX),
        }),
        Err(error) => Err(ContractViolation::Malformed {
            field,
            reason: error.to_string(),
        }),
    }
}

/// The A03 result type is retained as the public candidate artifact.
pub type FailureResult = eliot_dreamer_contracts::FailureResult;

/// A local assessment and its sealed candidate, bound as one serialized output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureHandlerDecision {
    pub schema_version: u32,
    pub decision_id: String,
    pub output_digest: String,
    pub assessment: FailureAssessment,
    pub result: FailureResult,
}

#[derive(Serialize)]
struct DecisionIdentity<'a> {
    domain: &'static str,
    schema_version: u32,
    assessment: &'a FailureAssessment,
    normalized_result_digest: &'a str,
}

fn a03_complete(
    input: &FailureInput,
    assessment: &FailureAssessment,
    final_preservation: &eliot_dreamer_contracts::RelationPreservation,
) -> bool {
    input.proposal.history.coverage == eliot_dreamer_contracts::FailureCoverage::Complete
        && input.proposal.outcome.coverage == eliot_dreamer_contracts::FailureCoverage::Complete
        && input.proposal.environment.coverage == eliot_dreamer_contracts::FailureCoverage::Complete
        && input.proposal.applicability.coverage
            == eliot_dreamer_contracts::FailureCoverage::Complete
        && input.action_evidence.coverage == eliot_dreamer_contracts::FailureCoverage::Complete
        && input.environment.coverage == eliot_dreamer_contracts::FailureCoverage::Complete
        && matches!(
            input.proposal.comparison.comparator,
            eliot_dreamer_contracts::FailureComparator::ExactEquality
        )
        && input.proposal.comparison.missing_dimensions.is_empty()
        && !input.proposal.comparison.dimensions.is_empty()
        && assessment.missing_evidence_refs.is_empty()
        && input.preservation.overall().is_ok()
        && final_preservation.overall().is_ok()
        && matches!(
            input.bundle.completeness,
            eliot_dreamer_contracts::bundle::BundleCompleteness::CompleteForScope
                | eliot_dreamer_contracts::bundle::BundleCompleteness::KnownEmpty
        )
}

impl FailureHandlerDecision {
    /// Validates the bounded serialized decision envelope.
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        bounded_serialized_len(self, MAX_DECISION_BYTES, "failure.handler_decision_bytes")
            .map(|_| ())
    }
}

/// Returns the registry descriptor owned by this cell.
#[must_use]
pub fn handler_port() -> CurationHandlerPort {
    CurationHandlerPort {
        port_id: super::HANDLER_ID.to_owned(),
        descriptor: CurationHandlerDescriptor {
            family: CurationFamily::Failure,
            handler_id: super::HANDLER_ID.to_owned(),
            accepted_kinds: vec![CurationKind::Failure],
        },
    }
}

/// Proposes one exact, inert `FailureFingerprint` candidate from six typed inputs.
///
/// The first input is the complete validated A03 closure. The remaining four
/// closure arguments are explicit ownership joins so callers cannot accidentally
/// assess a draft, action, environment, or history from another operation.
pub fn propose_failure_fingerprint(
    validated_curation_input: &FailureInput,
    grounded_failure_draft: &FailureProposal,
    attempt_action_outcome_evidence: &FailureActionEvidence,
    environment_and_capability_snapshot: &FailureEnvironment,
    existing_failure_history: &FailureHistory,
    policy: &FailurePolicy,
) -> Result<FailureHandlerDecision, ContractViolation> {
    policy.check_input(validated_curation_input)?;
    validate_joins(
        validated_curation_input,
        grounded_failure_draft,
        attempt_action_outcome_evidence,
        environment_and_capability_snapshot,
        existing_failure_history,
    )?;
    let candidate_limit =
        validated_curation_input
            .job
            .budget
            .candidates
            .ok_or(ContractViolation::Budget {
                dimension: "candidates",
                reason: "canonical candidate budget is unknown".to_owned(),
            })?;
    let next_candidates = validated_curation_input
        .usage
        .candidates
        .checked_add(1)
        .ok_or(ContractViolation::Budget {
            dimension: "candidates",
            reason: "candidate usage overflow".to_owned(),
        })?;
    if next_candidates > candidate_limit {
        return Err(ContractViolation::Budget {
            dimension: "candidates",
            reason: "candidate exceeds remaining canonical budget".to_owned(),
        });
    }
    let assessment = FailureAssessment::evaluate_validated(validated_curation_input)?;
    let disposition = choose_disposition(&assessment, policy.cancellation_requested);
    assemble(validated_curation_input, policy, disposition, &assessment)
}

fn validate_joins(
    input: &FailureInput,
    proposal: &FailureProposal,
    action: &FailureActionEvidence,
    environment: &FailureEnvironment,
    history: &FailureHistory,
) -> Result<(), ContractViolation> {
    input.validate()?;
    if proposal != &input.proposal {
        return Err(ContractViolation::BindingMismatch {
            field: "failure.grounded_failure_draft",
            reason: "draft is not the exact admitted proposal".to_owned(),
        });
    }
    if action != &input.action_evidence {
        return Err(ContractViolation::BindingMismatch {
            field: "failure.attempt_action_outcome_evidence",
            reason: "action evidence is not the exact admitted stream".to_owned(),
        });
    }
    if environment != &input.environment {
        return Err(ContractViolation::BindingMismatch {
            field: "failure.environment_and_capability_snapshot",
            reason: "environment snapshot is not the exact admitted stream".to_owned(),
        });
    }
    if history != &input.history {
        return Err(ContractViolation::BindingMismatch {
            field: "failure.existing_failure_history",
            reason: "history is not the exact admitted stream".to_owned(),
        });
    }
    Ok(())
}

fn choose_disposition(assessment: &FailureAssessment, cancelled: bool) -> FailureDisposition {
    if cancelled {
        return FailureDisposition::Cancelled;
    }
    if matches!(
        assessment.outcome,
        OutcomeAssessment::Cancelled
            | OutcomeAssessment::TimedOut
            | OutcomeAssessment::Rejected
            | OutcomeAssessment::Unavailable
            | OutcomeAssessment::NotAttempted
    ) {
        return FailureDisposition::Abstention;
    }
    if matches!(
        assessment.outcome,
        OutcomeAssessment::PartiallyApplied | OutcomeAssessment::UnknownOutcome
    ) || matches!(
        assessment.applicability,
        ApplicabilityAssessment::Incomplete
            | ApplicabilityAssessment::ChangedEnvironment
            | ApplicabilityAssessment::ScopeMismatch
    ) {
        return FailureDisposition::Partial;
    }
    match (
        assessment.trigger,
        assessment.outcome,
        assessment.applicability,
    ) {
        (TriggerAssessment::Unsupported, _, _) => FailureDisposition::Unsupported,
        (
            TriggerAssessment::Exact,
            OutcomeAssessment::ExecutedButSemanticallyFailed,
            ApplicabilityAssessment::Scoped,
        ) => FailureDisposition::Hypothesis,
        (TriggerAssessment::NearMatch | TriggerAssessment::Missing, _, _) => {
            FailureDisposition::Partial
        }
        _ => FailureDisposition::Partial,
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

fn assemble(
    input: &FailureInput,
    policy: &FailurePolicy,
    disposition: FailureDisposition,
    assessment: &FailureAssessment,
) -> Result<FailureHandlerDecision, ContractViolation> {
    let rollback = eliot_dreamer_contracts::FailureRollback {
        predecessor: input.proposal.lifecycle.predecessor_fingerprint.clone(),
        inverse_refs: input.proposal.lifecycle.inverse_refs.clone(),
        invalidation_refs: input.proposal.counterevidence_refs.clone(),
        raw_history_refs: input.proposal.lifecycle.raw_history_refs.clone(),
        note: "candidate-only lifecycle metadata; no mutation or automatic mitigation".to_owned(),
    };
    let result = FailureResult {
        schema_version: eliot_dreamer_contracts::failure::SCHEMA_VERSION,
        candidate_id: ZERO_DIGEST.to_owned(),
        operation_id: input.operation.operation_id.clone(),
        input_digest: ZERO_DIGEST.to_owned(),
        policy_digest: policy.digest.clone(),
        input: input.clone(),
        proposal: input.proposal.clone(),
        disposition,
        common_disposition: CandidateDisposition::Partial,
        preservation: input.preservation.clone(),
        final_preservation: unknown_preservation(),
        assessment_refs: assessment.evidence_refs.clone(),
        assessment_missing_refs: assessment.missing_evidence_refs.clone(),
        rollback: rollback.clone(),
        proof_ceiling: ProofCeiling::CandidateArtifact,
        handler_result: TypedCurationHandlerResult {
            request_id: input.operation.request_id.clone(),
            kind: CurationKind::Failure,
            family: CurationFamily::Failure,
            disposition: CandidateDisposition::Partial,
            handler_id: super::HANDLER_ID.to_owned(),
            request_digest: ZERO_DIGEST.to_owned(),
            result_digest: ZERO_DIGEST.to_owned(),
        },
    };
    let mut result = result;
    result.final_preservation = local_preservation(&result, input, assessment, &rollback);
    let complete = a03_complete(input, assessment, &result.final_preservation);
    let common = common_disposition(disposition, complete);
    result.common_disposition = common;
    result.handler_result.disposition = common;
    let sealed = seal_failure(result, input)?;
    let job_output_remaining = input
        .job
        .budget
        .output_bytes
        .ok_or(ContractViolation::Budget {
            dimension: "output_bytes",
            reason: "canonical output budget is unknown".to_owned(),
        })?
        .checked_sub(input.usage.output_bytes)
        .ok_or(ContractViolation::Budget {
            dimension: "output_bytes",
            reason: "admitted output usage already exceeds job budget".to_owned(),
        })?;
    let output_limit = policy.max_output_bytes.min(job_output_remaining);
    let job_report_remaining = input
        .job
        .budget
        .report_bytes
        .ok_or(ContractViolation::Budget {
            dimension: "report_bytes",
            reason: "canonical report budget is unknown".to_owned(),
        })?
        .checked_sub(input.usage.report_bytes)
        .ok_or(ContractViolation::Budget {
            dimension: "report_bytes",
            reason: "admitted report usage already exceeds job budget".to_owned(),
        })?;
    let report_limit = policy.max_output_bytes.min(job_report_remaining);
    let remaining_output = output_limit;
    let remaining_report = report_limit;
    let remaining_serialization = remaining_output.min(remaining_report);
    let _result_bytes =
        bounded_serialized_len(&sealed, remaining_serialization, "failure.result_bytes")?;
    let normalized_result_digest = failure_result_digest(&sealed)?;
    let decision_id = digest_hex(&canonical_bytes(&DecisionIdentity {
        domain: "eliot-dreamer-failure/decision-id/v1",
        schema_version: 1,
        assessment,
        normalized_result_digest: &normalized_result_digest,
    })?);
    let mut decision = FailureHandlerDecision {
        schema_version: 1,
        decision_id,
        output_digest: ZERO_DIGEST.to_owned(),
        assessment: assessment.clone(),
        result: sealed,
    };
    let mut output_preimage = decision.clone();
    ZERO_DIGEST.clone_into(&mut output_preimage.output_digest);
    decision.output_digest = digest_hex(&canonical_bytes(&output_preimage)?);
    decision.preflight()?;
    bounded_serialized_len(
        &decision,
        remaining_serialization,
        "failure.handler_decision_bytes",
    )?;
    Ok(decision)
}

fn local_preservation(
    result: &FailureResult,
    input: &FailureInput,
    assessment: &FailureAssessment,
    rollback: &eliot_dreamer_contracts::FailureRollback,
) -> eliot_dreamer_contracts::RelationPreservation {
    use eliot_dreamer_contracts::{
        BundleCompleteness, RelationPreservation, RelationPreservationDimension,
        RelationPreservationVerdict,
    };
    let coverage = result.input.bundle.completeness == BundleCompleteness::CompleteForScope
        && assessment.missing_evidence_refs.is_empty();
    let preservation = result.input == *input
        && result.proposal == input.proposal
        && result.proposal.validate().is_ok();
    let retained_ids: Vec<&str> = result
        .input
        .action_evidence
        .evidence
        .iter()
        .chain(result.input.history.historical_evidence.iter())
        .map(|evidence| evidence.evidence_id.as_str())
        .collect();
    let faithfulness = !assessment.evidence_refs.is_empty()
        && assessment
            .evidence_refs
            .iter()
            .all(|reference| retained_ids.contains(&reference.as_str()));
    let lineage = result.operation_id == result.input.operation.operation_id
        && result.proposal.operation == result.input.proposal.operation;
    let exact_sources = !result.proposal.source_refs.is_empty()
        && result.proposal.source_refs.iter().all(|reference| {
            result.input.source_members.iter().any(|member| {
                member.handle == *reference && digest_hex(&member.bytes) == member.digest
            })
        });
    let exact_materials = result
        .input
        .action_evidence
        .receipt_materials
        .iter()
        .chain(result.input.history.receipt_materials.iter())
        .all(|material| digest_hex(&material.bytes) == material.digest);
    let reversibility = result.rollback == *rollback
        && result.rollback.validate().is_ok()
        && exact_sources
        && exact_materials;
    let source_authority = result.proposal.source_refs == input.proposal.source_refs
        && result.proposal.proof_ceiling == ProofCeiling::CandidateArtifact
        && result.proof_ceiling == ProofCeiling::CandidateArtifact
        && result.proposal.source_refs.iter().all(|reference| {
            result.input.source_members.iter().any(|member| {
                member.handle == *reference && digest_hex(&member.bytes) == member.digest
            })
        });
    let dependency_closure = false;
    let predicates = [
        (
            RelationPreservationDimension::Coverage,
            coverage,
            "local closure coverage",
        ),
        (
            RelationPreservationDimension::Preservation,
            preservation,
            "proposal retained",
        ),
        (
            RelationPreservationDimension::Faithfulness,
            faithfulness,
            "typed evidence retained",
        ),
        (
            RelationPreservationDimension::Lineage,
            lineage,
            "result operation lineage retained",
        ),
        (
            RelationPreservationDimension::Reversibility,
            reversibility,
            "exact retained source and receipt material bytes",
        ),
        (
            RelationPreservationDimension::SourceAuthority,
            source_authority,
            "source bindings and candidate proof ceiling retained",
        ),
        (
            RelationPreservationDimension::DependencyClosure,
            dependency_closure,
            "revocation propagation is not established by this inert handoff",
        ),
    ];
    RelationPreservation {
        verdicts: predicates
            .into_iter()
            .map(|(dimension, passed, note)| RelationPreservationVerdict {
                dimension,
                passed,
                known: dimension != RelationPreservationDimension::DependencyClosure,
                note: note.to_owned(),
            })
            .collect(),
    }
}

fn unknown_preservation() -> eliot_dreamer_contracts::RelationPreservation {
    use eliot_dreamer_contracts::{
        RelationPreservation, RelationPreservationDimension, RelationPreservationVerdict,
    };
    RelationPreservation {
        verdicts: RelationPreservationDimension::all()
            .iter()
            .copied()
            .map(|dimension| RelationPreservationVerdict {
                dimension,
                passed: false,
                known: false,
                note: "local closure not assessed yet".to_owned(),
            })
            .collect(),
    }
}
