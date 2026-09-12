use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::Serialize;

use crate::model::{
    AnswerSchema, ClarificationCandidate, ClarificationDecision, ClarificationDisposition,
    ClarificationPolicy, DecisionOwner, RoutingRecommendation, UnansweredFallback,
};
use crate::ClarificationError;

/// Validates the context-free integrity of a clarification decision.
///
/// This complements the owner-bound input validation by checking relationships
/// that cross the decision and candidate envelopes. It does not authenticate a
/// responder, validate an answer, deliver a question, or grant authority.
pub fn validate_clarification_decision(
    decision: &ClarificationDecision,
    policy: &ClarificationPolicy,
) -> Result<(), ClarificationError> {
    decision.validate(policy)
}

pub(crate) fn validate_decision_cross_envelope(
    decision: &ClarificationDecision,
    policy: &ClarificationPolicy,
) -> Result<(), ClarificationError> {
    let encoded = canonical_json_bytes(decision).map_err(|_| ClarificationError::Canonicalization)?;
    if encoded.len() > policy.max_output_bytes {
        return Err(ClarificationError::limit(
            "decision.serialized_output_bytes",
            policy.max_output_bytes,
        ));
    }

    match (&decision.disposition, &decision.candidate) {
        (ClarificationDisposition::Candidate, Some(candidate)) => {
            validate_candidate(candidate, &decision.input_digest)
        }
        (ClarificationDisposition::NoQuestion { .. }, None) => Ok(()),
        _ => Err(ClarificationError::invalid(
            "decision.disposition",
            "candidate and disposition disagree",
        )),
    }
}

fn validate_candidate(
    candidate: &ClarificationCandidate,
    decision_input_digest: &str,
) -> Result<(), ClarificationError> {
    if !is_lower_hex_digest(&candidate.candidate_id) {
        return Err(ClarificationError::invalid(
            "candidate.candidate_id",
            "must be lowercase SHA-256 hexadecimal",
        ));
    }

    let expected_candidate_id = canonical_json_bytes(&CandidateIdentity {
        operation_id: &candidate.operation_id,
        idempotency_key: &candidate.idempotency_key,
        ambiguity_id: &candidate.ambiguity_id,
        variable_id: &candidate.variable.variable_id,
        input_digest: decision_input_digest,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| ClarificationError::Canonicalization)?;
    if candidate.candidate_id != expected_candidate_id {
        return Err(ClarificationError::IdentityConflict);
    }

    if candidate.state_fence != candidate.invalidation.state_fence {
        return Err(ClarificationError::binding(
            "candidate.invalidation.state_fence",
        ));
    }

    let variable_id = candidate.variable.variable_id.as_str();
    require_exact_variable(
        &candidate.variable.component_ids,
        variable_id,
        "candidate.variable.component_ids",
    )?;
    require_exact_variable(
        &candidate.materiality.referenced_variables,
        variable_id,
        "candidate.materiality.referenced_variables",
    )?;
    require_exact_variable(
        fallback_variables(&candidate.fallback),
        variable_id,
        "candidate.fallback.referenced_variables",
    )?;

    match &candidate.variable.answer_schema {
        AnswerSchema::Choice { options } | AnswerSchema::Reference { allowed: options, .. } => {
            for option in options {
                require_exact_variable(
                    &option.referenced_variables,
                    variable_id,
                    "candidate.variable.answer_schema.referenced_variables",
                )?;
            }
        }
        AnswerSchema::Boolean
        | AnswerSchema::Ternary
        | AnswerSchema::Scalar { .. }
        | AnswerSchema::Date
        | AnswerSchema::DateTime
        | AnswerSchema::Interval
        | AnswerSchema::Version
        | AnswerSchema::BoundedText { .. } => {}
    }

    for branch in &candidate.variable.branches {
        require_exact_variable(
            &branch.referenced_variables,
            variable_id,
            "candidate.variable.branches.referenced_variables",
        )?;
    }

    validate_routing(candidate)?;

    let source_refs: BTreeSet<_> = candidate.source_refs.iter().map(String::as_str).collect();
    if candidate
        .materiality
        .evidence_refs
        .iter()
        .any(|evidence| !source_refs.contains(evidence.as_str()))
    {
        return Err(ClarificationError::binding(
            "candidate.materiality.evidence_refs",
        ));
    }

    Ok(())
}

fn validate_routing(candidate: &ClarificationCandidate) -> Result<(), ClarificationError> {
    match (&candidate.variable.owner, &candidate.routing) {
        (
            DecisionOwner::TaskLocalAgent,
            RoutingRecommendation::TaskLocalAgent { capability_id, .. },
        ) if candidate.variable.required_capability.as_deref() == Some(capability_id.as_str()) => {
            Ok(())
        }
        (
            DecisionOwner::Human(expected_kind),
            RoutingRecommendation::Human { decision_kind, .. },
        ) if expected_kind == decision_kind => Ok(()),
        (DecisionOwner::Unknown, _) => Err(ClarificationError::binding(
            "candidate.routing.unknown_owner",
        )),
        _ => Err(ClarificationError::binding("candidate.routing.owner")),
    }
}

fn fallback_variables(fallback: &UnansweredFallback) -> &[String] {
    match fallback {
        UnansweredFallback::PartialResult {
            referenced_variables,
            ..
        }
        | UnansweredFallback::Abstain {
            referenced_variables,
            ..
        }
        | UnansweredFallback::PreserveCurrent {
            referenced_variables,
            ..
        }
        | UnansweredFallback::Defer {
            referenced_variables,
            ..
        }
        | UnansweredFallback::BlockedWithoutAnswer {
            referenced_variables,
            ..
        } => referenced_variables,
    }
}

fn require_exact_variable(
    values: &[String],
    variable_id: &str,
    field: &'static str,
) -> Result<(), ClarificationError> {
    if values.len() == 1 && values[0] == variable_id {
        Ok(())
    } else {
        Err(ClarificationError::invalid(
            field,
            "must reference exactly the candidate decision variable",
        ))
    }
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Serialize)]
struct CandidateIdentity<'a> {
    operation_id: &'a str,
    idempotency_key: &'a str,
    ambiguity_id: &'a str,
    variable_id: &'a str,
    input_digest: &'a str,
}
