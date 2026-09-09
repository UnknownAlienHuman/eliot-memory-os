//! Phase-oriented Concept candidate assembly.

use eliot_dreamer_contracts::{
    CandidateDisposition, ConceptCandidate, ConceptDisposition, ConceptInput, ConceptRollback,
    ContractViolation, CurationAcceptanceCtx, CurationFamily, CurationHandlerDescriptor,
    CurationHandlerPort, CurationKind, TypedCurationHandlerResult, canonical_bytes, digest_hex,
    family_of, seal_concept, validate_concept_acceptance,
};
use eliot_receipts::ProofCeiling;
use serde::Serialize;
use std::io::{self, Write};

use crate::compare::{Comparison, compare_neighborhood, predecessor};
use crate::evidence::{EvidenceAssessment, EvidenceLedger, build_ledger};
use crate::policy::{ConceptPolicy, work_bound};

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Local decision projection for callers that need to inspect the outcome.
pub type ConceptDecision = ConceptDisposition;

/// Returns the one registry descriptor owned by this cell.
#[must_use]
pub fn handler_port() -> CurationHandlerPort {
    CurationHandlerPort {
        port_id: super::HANDLER_ID.to_owned(),
        descriptor: CurationHandlerDescriptor {
            family: CurationFamily::Concept,
            handler_id: super::HANDLER_ID.to_owned(),
            accepted_kinds: vec![CurationKind::Concept],
        },
    }
}

/// Proposes one bounded Concept or Abstraction candidate from an accepted A03 closure.
///
/// The acceptance context is required because a structurally valid input is not
/// itself evidence that the validator receipt, bundle, screen and budget were
/// accepted. This function only emits a candidate and never mutates state.
pub fn propose_concept_or_abstraction(
    input: &ConceptInput,
    ctx: &CurationAcceptanceCtx<'_>,
    policy: &ConceptPolicy,
) -> Result<ConceptCandidate, ContractViolation> {
    // Freeze and limits phase: acceptance precedes semantic work.
    validate_concept_acceptance(input, ctx)?;
    policy.check_input(input)?;
    let work = work_bound(input)?;
    if work > policy.max_work {
        return Err(ContractViolation::Budget {
            dimension: "concept.work",
            reason: "semantic work exceeds local policy ceiling".to_owned(),
        });
    }
    if ctx.usage.stu_used > policy.max_stu {
        return Err(ContractViolation::Budget {
            dimension: "concept.stu",
            reason: "supplied STU usage exceeds local policy ceiling".to_owned(),
        });
    }
    if ctx
        .usage
        .candidates
        .checked_add(1)
        .ok_or(ContractViolation::Budget {
            dimension: "concept.candidates",
            reason: "candidate usage overflow".to_owned(),
        })?
        > ctx.job.budget.candidates.ok_or(ContractViolation::Budget {
            dimension: "concept.candidates",
            reason: "canonical candidate budget is unknown".to_owned(),
        })?
    {
        return Err(ContractViolation::Budget {
            dimension: "concept.candidates",
            reason: "emitted candidate exceeds remaining canonical budget".to_owned(),
        });
    }
    if policy.cancellation_requested {
        return assemble(
            input,
            ctx,
            policy,
            ConceptDisposition::Cancelled,
            Comparison::None,
            None,
        );
    }

    // Evidence ledger phase: every source, criterion, case and omission stays addressable.
    let ledger = build_ledger(input)?;
    let assessment = ledger.assess(&input.proposal, input.proposal.mode);
    let semantic_guard = semantic_guard(input, assessment);
    let mut local = match semantic_guard {
        Some(disposition) => disposition,
        None => EvidenceLedger::disposition(assessment),
    };
    if matches!(
        local,
        ConceptDisposition::Candidate | ConceptDisposition::Refinement
    ) && input.preservation.overall().is_err()
    {
        local = ConceptDisposition::Hypothesis;
    }

    // Compare only the typed retained neighborhood; labels never establish identity.
    let comparison = compare_neighborhood(input)?;
    let disposition = match comparison {
        Comparison::Duplicate
            if ledger.coverage_complete
                && assessment.grounded_definition
                && assessment.discriminator_supported
                && matches!(
                    local,
                    ConceptDisposition::Candidate | ConceptDisposition::Hypothesis
                ) =>
        {
            ConceptDisposition::Duplicate
        }
        Comparison::Refinement if local == ConceptDisposition::Candidate => {
            ConceptDisposition::Refinement
        }
        Comparison::Ambiguity
            if matches!(
                local,
                ConceptDisposition::Candidate | ConceptDisposition::Hypothesis
            ) =>
        {
            ConceptDisposition::Ambiguity
        }
        _ => local,
    };
    let prior = predecessor(input, comparison);
    assemble(input, ctx, policy, disposition, comparison, prior)
}

fn semantic_guard(
    input: &ConceptInput,
    assessment: EvidenceAssessment,
) -> Option<ConceptDisposition> {
    let proposal = &input.proposal;
    let name = proposal.name.trim().to_lowercase();
    let definition = proposal.definition.trim().to_lowercase();
    if name == definition
        || proposal
            .discriminator
            .predicted_distinction
            .trim()
            .eq_ignore_ascii_case(proposal.discriminator.falsification_condition.trim())
    {
        return Some(ConceptDisposition::Unsupported);
    }
    if !assessment.discriminator_supported {
        return Some(ConceptDisposition::Insufficient);
    }
    if input.neighborhood.concepts.is_empty()
        && input.neighborhood.coverage != eliot_dreamer_contracts::ConceptCoverage::Complete
    {
        return Some(ConceptDisposition::Ambiguity);
    }
    if proposal.cases.is_empty() || proposal.source_refs.is_empty() {
        return Some(ConceptDisposition::Insufficient);
    }
    None
}

fn assemble(
    input: &ConceptInput,
    ctx: &CurationAcceptanceCtx<'_>,
    policy: &ConceptPolicy,
    disposition: ConceptDisposition,
    comparison: Comparison,
    prior: Option<&eliot_dreamer_contracts::ConceptSnapshot>,
) -> Result<ConceptCandidate, ContractViolation> {
    let common_disposition = common_disposition(disposition, input);
    let predecessor_id = prior.map(|snapshot| snapshot.concept_id.clone());
    let mut history_refs = input
        .neighborhood
        .concepts
        .iter()
        .map(|snapshot| snapshot.concept_id.clone())
        .collect::<Vec<_>>();
    history_refs.sort();
    let mut reversal_refs = input
        .sources
        .sources
        .iter()
        .map(|source| source.source_id.clone())
        .collect::<Vec<_>>();
    reversal_refs.sort();
    let mut invalidation_refs = input
        .proposal
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id().clone())
        .collect::<Vec<_>>();
    invalidation_refs.sort();
    let rollback = ConceptRollback {
        predecessor: predecessor_id,
        history_refs,
        reversal_refs,
        invalidation_refs,
        note: rollback_note(disposition, comparison).to_owned(),
    };
    let request_digest = request_digest(input)?;
    let result = TypedCurationHandlerResult {
        request_id: input.request_id.clone(),
        kind: CurationKind::Concept,
        family: family_of(CurationKind::Concept),
        disposition: common_disposition,
        handler_id: super::HANDLER_ID.to_owned(),
        request_digest,
        result_digest: ZERO_DIGEST.to_owned(),
    };
    let candidate_id = input.operation_id.clone();
    let candidate = ConceptCandidate {
        schema_version: 1,
        candidate_id,
        operation_id: input.operation_id.clone(),
        input_digest: eliot_dreamer_contracts::concept_input_digest(input)?,
        policy_digest: policy.digest.clone(),
        mode: input.proposal.mode,
        proposal: input.proposal.clone(),
        disposition,
        common_disposition,
        preservation: input.preservation.clone(),
        rollback,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        handler_result: result,
    };
    let output_limit = output_limit(ctx, policy)?;
    let _ = bounded_len(&candidate, output_limit)?;
    let sealed = seal_concept(candidate, input)?;
    let output_len = bounded_len(&sealed, output_limit)?;
    let _ = ctx
        .usage
        .output_bytes
        .checked_add(output_len)
        .ok_or(ContractViolation::Budget {
            dimension: "concept.output_bytes",
            reason: "output usage overflow".to_owned(),
        })?;
    Ok(sealed)
}

fn common_disposition(
    disposition: ConceptDisposition,
    input: &ConceptInput,
) -> CandidateDisposition {
    let complete = input.proposal.case_coverage
        == eliot_dreamer_contracts::ConceptCoverage::Complete
        && input.sources.denominator.coverage == eliot_dreamer_contracts::ConceptCoverage::Complete
        && input.neighborhood.coverage == eliot_dreamer_contracts::ConceptCoverage::Complete
        && input.preservation.overall().is_ok();
    match disposition {
        ConceptDisposition::Candidate | ConceptDisposition::Refinement => {
            CandidateDisposition::Candidate
        }
        ConceptDisposition::Hypothesis => {
            if complete {
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

fn rollback_note(disposition: ConceptDisposition, comparison: Comparison) -> &'static str {
    match (disposition, comparison) {
        (ConceptDisposition::Duplicate, _) => {
            "duplicate replay retains the existing concept identity"
        }
        (ConceptDisposition::Refinement, Comparison::Refinement) => {
            "refinement is reversible through its retained predecessor"
        }
        (ConceptDisposition::Cancelled, _) => {
            "cancelled before semantic effects; retained input is the reopen point"
        }
        _ => "candidate remains reversible through retained history and source identities",
    }
}

fn request_digest(input: &ConceptInput) -> Result<String, ContractViolation> {
    let mut request = input.request.clone();
    if let eliot_dreamer_contracts::CurationPayload::Concept(payload) = &mut request.payload {
        payload.target_evidence.targets.sort();
        payload.target_evidence.evidence_refs.sort();
    }
    Ok(digest_hex(&canonical_bytes(&request)?))
}

fn output_limit(
    ctx: &CurationAcceptanceCtx<'_>,
    policy: &ConceptPolicy,
) -> Result<usize, ContractViolation> {
    let remaining = ctx
        .job
        .budget
        .output_bytes
        .ok_or(ContractViolation::Budget {
            dimension: "concept.output_bytes",
            reason: "canonical output budget is unknown".to_owned(),
        })?
        .checked_sub(ctx.usage.output_bytes)
        .ok_or(ContractViolation::Budget {
            dimension: "concept.output_bytes",
            reason: "canonical output usage already exceeds budget".to_owned(),
        })?;
    let limit = remaining.min(policy.max_output_bytes);
    usize::try_from(limit).map_err(|_| ContractViolation::Budget {
        dimension: "concept.output_bytes",
        reason: "output bound conversion overflow".to_owned(),
    })
}

fn bounded_len<T: Serialize>(value: &T, limit: usize) -> Result<u64, ContractViolation> {
    let mut writer = BoundedWriter {
        used: 0,
        limit,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => u64::try_from(writer.used).map_err(|_| ContractViolation::Budget {
            dimension: "concept.output_bytes",
            reason: "output length conversion overflow".to_owned(),
        }),
        Err(_) if writer.exceeded => Err(ContractViolation::Budget {
            dimension: "concept.output_bytes",
            reason: "candidate exceeds remaining output bound".to_owned(),
        }),
        Err(error) => Err(ContractViolation::Malformed {
            field: "concept.output",
            reason: error.to_string(),
        }),
    }
}

struct BoundedWriter {
    used: usize,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.used.checked_add(bytes.len()).ok_or_else(|| {
            self.exceeded = true;
            io::Error::other("output length overflow")
        })?;
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("output bound exceeded"));
        }
        self.used = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
