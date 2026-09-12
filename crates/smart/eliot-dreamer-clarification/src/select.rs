use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::ValidatedDreamDraft;
use serde::Serialize;

use crate::model::{
    ActiveAgentOrHumanBoundary, AdmittedClarificationJob, AmbiguityAccounting,
    AmbiguityAccountingStatus, AmbiguityState, CandidateInvalidation,
    ClarificationAmbiguity, ClarificationCandidate, ClarificationContentClass,
    ClarificationDecision, ClarificationDisposition, ClarificationPolicy, DecisionOwner,
    DecisionVariable, MaterialityBasis, NoQuestionReason, RoutingRecommendation,
    UnansweredFallback, CLARIFICATION_PROOF_CEILING, CLARIFICATION_SCHEMA_VERSION,
};
use crate::ClarificationError;

/// Selects and renders zero or one inert atomic clarification candidate.
///
/// The function is pure: all time, cancellation, owner and source state is
/// supplied explicitly. It never validates an actual answer or performs
/// delivery, authentication, mutation, provider, Store, authority or effect work.
#[allow(clippy::too_many_lines)]
pub fn propose_clarification(
    admitted_job: &AdmittedClarificationJob,
    validated_draft: &ValidatedDreamDraft,
    boundary: &ActiveAgentOrHumanBoundary,
    policy: &ClarificationPolicy,
) -> Result<ClarificationDecision, ClarificationError> {
    policy.validate()?;
    admitted_job.validate(policy)?;
    admitted_job.validate_draft(validated_draft)?;
    boundary.validate_for(&admitted_job.job)?;

    let validated_draft_digest = canonical_digest(validated_draft)?;
    let input_digest = decision_input_digest(
        admitted_job,
        &validated_draft_digest,
        boundary,
        policy,
    )?;
    let work_units = calculate_work_units(admitted_job)?;
    if work_units > policy.max_work_units {
        return Err(ClarificationError::limit(
            "decision.work_units",
            usize::try_from(policy.max_work_units).unwrap_or(usize::MAX),
        ));
    }

    if policy.cancellation_requested {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::Cancelled,
            AmbiguityAccountingStatus::NotSelected,
            "cancelled_before_selection",
        );
    }
    if admitted_job
        .job
        .deadline_ms
        .is_some_and(|deadline| policy.observation_time_ms >= deadline)
    {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::Expired,
            AmbiguityAccountingStatus::NotSelected,
            "deadline_exhausted",
        );
    }

    let unresolved: Vec<_> = admitted_job
        .ambiguities
        .iter()
        .filter(|ambiguity| matches!(ambiguity.state, AmbiguityState::Unresolved))
        .collect();

    if unresolved.is_empty() {
        let reason = no_unresolved_reason(&admitted_job.ambiguities);
        let status = accounting_status_for_reason(reason);
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            reason,
            status,
            reason_code(reason),
        );
    }

    if unresolved.len() != 1 {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::DecompositionRequired,
            AmbiguityAccountingStatus::DecompositionRequired,
            "multiple_material_unknowns",
        );
    }

    let ambiguity = unresolved[0];
    if ambiguity.variables.len() != 1 {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::DecompositionRequired,
            AmbiguityAccountingStatus::DecompositionRequired,
            "compound_decision_variable",
        );
    }
    let variable = &ambiguity.variables[0];
    if variable.content_class != ClarificationContentClass::OrdinaryData {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::SecretOrProtected,
            AmbiguityAccountingStatus::SecretBlocked,
            "protected_or_executable_question_material",
        );
    }

    let materiality = ambiguity.materiality.as_ref().ok_or_else(|| {
        ClarificationError::invalid(
            "ambiguity.materiality",
            "unresolved ambiguity requires materiality evidence",
        )
    })?;
    let fallback = candidate_fallback(ambiguity, variable)?;
    if !is_atomic(variable, materiality, &fallback) {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::DecompositionRequired,
            AmbiguityAccountingStatus::DecompositionRequired,
            "hidden_or_compound_decision_variable",
        );
    }

    let Some(routing) = route_for(variable, boundary) else {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::UnauthorizedResponder,
            AmbiguityAccountingStatus::UnauthorizedResponder,
            "responder_boundary_unavailable",
        );
    };

    let expires_at_ms = policy
        .observation_time_ms
        .checked_add(policy.candidate_ttl_ms)
        .ok_or_else(|| ClarificationError::invalid("candidate.expires_at_ms", "time overflow"))?;
    let expires_at_ms = admitted_job
        .job
        .deadline_ms
        .map_or(expires_at_ms, |deadline| expires_at_ms.min(deadline));
    if expires_at_ms <= policy.observation_time_ms {
        return no_question_decision(
            admitted_job,
            policy,
            boundary,
            &input_digest,
            work_units,
            NoQuestionReason::Expired,
            AmbiguityAccountingStatus::NotSelected,
            "candidate_would_expire_immediately",
        );
    }

    let candidate_id = canonical_digest(&CandidateIdentity {
        operation_id: &admitted_job.job.operation_id,
        idempotency_key: &admitted_job.job.idempotency_key,
        ambiguity_id: &ambiguity.ambiguity_id,
        variable_id: &variable.variable_id,
        input_digest: &input_digest,
    })?;
    let question = render_question(variable, policy)?;
    let invalidation = CandidateInvalidation {
        source_denominator_digest: admitted_job.source_denominator.denominator_digest.clone(),
        validated_draft_digest,
        boundary_digest: boundary.boundary_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        state_fence: admitted_job.job.state_fence.clone(),
    };
    let mut source_refs = ambiguity.source_refs.clone();
    source_refs.sort();
    let mut candidate = ClarificationCandidate {
        schema_version: CLARIFICATION_SCHEMA_VERSION,
        candidate_id,
        operation_id: admitted_job.job.operation_id.clone(),
        idempotency_key: admitted_job.job.idempotency_key.clone(),
        task_id: admitted_job.job.task_id.clone(),
        scope_id: admitted_job.job.scope_id.clone(),
        state_fence: admitted_job.job.state_fence.clone(),
        objective_id: ambiguity.objective_id.clone(),
        ambiguity_id: ambiguity.ambiguity_id.clone(),
        question,
        variable: variable.normalized(),
        materiality: materiality.clone(),
        routing,
        fallback,
        source_refs,
        expires_at_ms,
        policy_id: policy.policy_id.clone(),
        invalidation,
        proof_ceiling: CLARIFICATION_PROOF_CEILING.to_owned(),
        candidate_digest: String::new(),
    };
    candidate.seal(policy)?;

    let accounting = accounting_for(admitted_job, Some(&ambiguity.ambiguity_id), None, None);
    let mut decision = ClarificationDecision {
        schema_version: CLARIFICATION_SCHEMA_VERSION,
        disposition: ClarificationDisposition::Candidate,
        candidate: Some(candidate),
        accounting,
        input_digest,
        policy_digest: policy.policy_digest.clone(),
        boundary_digest: boundary.boundary_digest.clone(),
        work_units,
        output_bytes: 0,
        proof_ceiling: CLARIFICATION_PROOF_CEILING.to_owned(),
        decision_digest: String::new(),
    };
    decision.seal(policy)?;
    decision.validate(policy)?;
    Ok(decision)
}

#[derive(Serialize)]
struct CandidateIdentity<'a> {
    operation_id: &'a str,
    idempotency_key: &'a str,
    ambiguity_id: &'a str,
    variable_id: &'a str,
    input_digest: &'a str,
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ClarificationError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ClarificationError::Canonicalization)
}

fn decision_input_digest(
    admitted_job: &AdmittedClarificationJob,
    validated_draft_digest: &str,
    boundary: &ActiveAgentOrHumanBoundary,
    policy: &ClarificationPolicy,
) -> Result<String, ClarificationError> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        admission_digest: &'a str,
        validated_draft_digest: &'a str,
        boundary_digest: &'a str,
        policy_digest: &'a str,
    }
    canonical_digest(&Preimage {
        admission_digest: &admitted_job.admission_digest,
        validated_draft_digest,
        boundary_digest: &boundary.boundary_digest,
        policy_digest: &policy.policy_digest,
    })
}

fn calculate_work_units(job: &AdmittedClarificationJob) -> Result<u64, ClarificationError> {
    let mut units = u64::try_from(job.ambiguities.len())
        .map_err(|_| ClarificationError::limit("decision.work_units", usize::MAX))?;
    for ambiguity in &job.ambiguities {
        units = units
            .checked_add(u64::try_from(ambiguity.variables.len()).map_err(|_| {
                ClarificationError::limit("decision.work_units", usize::MAX)
            })?)
            .ok_or_else(|| ClarificationError::invalid("decision.work_units", "overflow"))?;
        for variable in &ambiguity.variables {
            units = units
                .checked_add(u64::try_from(variable.branches.len()).map_err(|_| {
                    ClarificationError::limit("decision.work_units", usize::MAX)
                })?)
                .ok_or_else(|| ClarificationError::invalid("decision.work_units", "overflow"))?;
        }
    }
    Ok(units)
}

fn candidate_fallback(
    ambiguity: &ClarificationAmbiguity,
    variable: &DecisionVariable,
) -> Result<UnansweredFallback, ClarificationError> {
    if let Some(fallback) = &ambiguity.fallback {
        return Ok(fallback.clone());
    }
    let Some(materiality) = &ambiguity.materiality else {
        return Err(ClarificationError::invalid(
            "ambiguity.fallback",
            "missing materiality and fallback",
        ));
    };
    if let MaterialityBasis::NoSafeContinuation { blocking_code } = &materiality.basis {
        return Ok(UnansweredFallback::BlockedWithoutAnswer {
            reason_code: blocking_code.clone(),
            referenced_variables: vec![variable.variable_id.clone()],
        });
    }
    Err(ClarificationError::invalid(
        "ambiguity.fallback",
        "candidate requires an explicit safe unanswered fallback",
    ))
}

fn is_atomic(
    variable: &DecisionVariable,
    materiality: &crate::model::MaterialityEvidence,
    fallback: &UnansweredFallback,
) -> bool {
    if variable.component_ids.len() != 1 || variable.component_ids[0] != variable.variable_id {
        return false;
    }
    let mut expected = BTreeSet::new();
    expected.insert(variable.variable_id.clone());
    let mut actual = variable.all_referenced_variables(fallback);
    actual.extend(materiality.referenced_variables.iter().cloned());
    actual == expected
}

fn route_for(
    variable: &DecisionVariable,
    boundary: &ActiveAgentOrHumanBoundary,
) -> Option<RoutingRecommendation> {
    match variable.owner {
        DecisionOwner::TaskLocalAgent => {
            let capability = variable.required_capability.as_ref()?;
            let agent = boundary.active_agent.as_ref()?;
            if !agent.current || !agent.capability_ids.contains(capability) {
                return None;
            }
            Some(RoutingRecommendation::TaskLocalAgent {
                principal: agent.principal.clone(),
                capability_id: capability.clone(),
                boundary_ref: agent.boundary_ref.clone(),
            })
        }
        DecisionOwner::Human(kind) => {
            let human = boundary.human.as_ref()?;
            if !human.current || !human.decision_kinds.contains(&kind) {
                return None;
            }
            Some(RoutingRecommendation::Human {
                principal: human.principal.clone(),
                decision_kind: kind,
                authority_ref: human.authority_ref.clone(),
            })
        }
        DecisionOwner::Unknown => None,
    }
}

fn render_question(
    variable: &DecisionVariable,
    policy: &ClarificationPolicy,
) -> Result<String, ClarificationError> {
    let question = format!("Which value should be used for {}?", variable.label);
    crate::model::validate_text(&question, "candidate.question", policy.max_text_bytes)?;
    if question.matches('?').count() != 1 {
        return Err(ClarificationError::invalid(
            "candidate.question",
            "renderer produced a compound question",
        ));
    }
    Ok(question)
}

fn no_unresolved_reason(ambiguities: &[ClarificationAmbiguity]) -> NoQuestionReason {
    if ambiguities
        .iter()
        .any(|item| matches!(item.state, AmbiguityState::Stale { .. }))
    {
        return NoQuestionReason::StaleInput;
    }
    if ambiguities.iter().any(|item| {
        matches!(item.state, AmbiguityState::SafeDefaultAvailable { .. })
    }) {
        return NoQuestionReason::SafeFallbackAvailable;
    }
    if ambiguities.iter().any(|item| {
        matches!(item.state, AmbiguityState::ResolvedByEvidence { .. })
    }) {
        return NoQuestionReason::AlreadyAnswerable;
    }
    if !ambiguities.is_empty()
        && ambiguities
            .iter()
            .all(|item| matches!(item.state, AmbiguityState::OutOfScope { .. }))
    {
        return NoQuestionReason::OutOfScope;
    }
    NoQuestionReason::NoMaterialAmbiguity
}

const fn accounting_status_for_reason(reason: NoQuestionReason) -> AmbiguityAccountingStatus {
    match reason {
        NoQuestionReason::NoMaterialAmbiguity => AmbiguityAccountingStatus::NonMaterial,
        NoQuestionReason::AlreadyAnswerable => AmbiguityAccountingStatus::ResolvedByEvidence,
        NoQuestionReason::SafeFallbackAvailable => {
            AmbiguityAccountingStatus::SafeDefaultAvailable
        }
        NoQuestionReason::DecompositionRequired => {
            AmbiguityAccountingStatus::DecompositionRequired
        }
        NoQuestionReason::UnauthorizedResponder => {
            AmbiguityAccountingStatus::UnauthorizedResponder
        }
        NoQuestionReason::SecretOrProtected => AmbiguityAccountingStatus::SecretBlocked,
        NoQuestionReason::StaleInput => AmbiguityAccountingStatus::Stale,
        NoQuestionReason::OutOfScope => AmbiguityAccountingStatus::OutOfScope,
        NoQuestionReason::Cancelled
        | NoQuestionReason::Expired
        | NoQuestionReason::NoSafeAtomicCandidate => AmbiguityAccountingStatus::NotSelected,
    }
}

const fn reason_code(reason: NoQuestionReason) -> &'static str {
    match reason {
        NoQuestionReason::NoMaterialAmbiguity => "no_material_ambiguity",
        NoQuestionReason::AlreadyAnswerable => "already_answerable",
        NoQuestionReason::SafeFallbackAvailable => "safe_default_available",
        NoQuestionReason::DecompositionRequired => "decomposition_required",
        NoQuestionReason::UnauthorizedResponder => "unauthorized_responder",
        NoQuestionReason::SecretOrProtected => "secret_or_protected",
        NoQuestionReason::StaleInput => "stale_input",
        NoQuestionReason::OutOfScope => "out_of_scope",
        NoQuestionReason::Cancelled => "cancelled",
        NoQuestionReason::Expired => "expired",
        NoQuestionReason::NoSafeAtomicCandidate => "no_safe_atomic_candidate",
    }
}

fn no_question_decision(
    job: &AdmittedClarificationJob,
    policy: &ClarificationPolicy,
    boundary: &ActiveAgentOrHumanBoundary,
    input_digest: &str,
    work_units: u64,
    reason: NoQuestionReason,
    unresolved_status: AmbiguityAccountingStatus,
    unresolved_reason: &str,
) -> Result<ClarificationDecision, ClarificationError> {
    let accounting = accounting_for(
        job,
        None,
        Some(unresolved_status),
        Some(unresolved_reason),
    );
    let mut decision = ClarificationDecision {
        schema_version: CLARIFICATION_SCHEMA_VERSION,
        disposition: ClarificationDisposition::NoQuestion { reason },
        candidate: None,
        accounting,
        input_digest: input_digest.to_owned(),
        policy_digest: policy.policy_digest.clone(),
        boundary_digest: boundary.boundary_digest.clone(),
        work_units,
        output_bytes: 0,
        proof_ceiling: CLARIFICATION_PROOF_CEILING.to_owned(),
        decision_digest: String::new(),
    };
    decision.seal(policy)?;
    decision.validate(policy)?;
    Ok(decision)
}

fn accounting_for(
    job: &AdmittedClarificationJob,
    selected_id: Option<&str>,
    unresolved_override: Option<AmbiguityAccountingStatus>,
    unresolved_reason: Option<&str>,
) -> Vec<AmbiguityAccounting> {
    let mut accounting: Vec<_> = job
        .ambiguities
        .iter()
        .map(|ambiguity| {
            if selected_id == Some(ambiguity.ambiguity_id.as_str()) {
                return AmbiguityAccounting {
                    ambiguity_id: ambiguity.ambiguity_id.clone(),
                    status: AmbiguityAccountingStatus::Selected,
                    reason_code: "selected_atomic_material_question".to_owned(),
                };
            }
            let (status, reason) = match &ambiguity.state {
                AmbiguityState::Unresolved => (
                    unresolved_override.unwrap_or(AmbiguityAccountingStatus::NotSelected),
                    unresolved_reason.unwrap_or("not_selected"),
                ),
                AmbiguityState::NonMaterial { reason_code } => {
                    (AmbiguityAccountingStatus::NonMaterial, reason_code.as_str())
                }
                AmbiguityState::ResolvedByEvidence { .. } => (
                    AmbiguityAccountingStatus::ResolvedByEvidence,
                    "resolved_by_evidence",
                ),
                AmbiguityState::SafeDefaultAvailable { .. } => (
                    AmbiguityAccountingStatus::SafeDefaultAvailable,
                    "safe_default_available",
                ),
                AmbiguityState::Stale { .. } => {
                    (AmbiguityAccountingStatus::Stale, "stale")
                }
                AmbiguityState::OutOfScope { reason_code } => {
                    (AmbiguityAccountingStatus::OutOfScope, reason_code.as_str())
                }
            };
            AmbiguityAccounting {
                ambiguity_id: ambiguity.ambiguity_id.clone(),
                status,
                reason_code: reason.to_owned(),
            }
        })
        .collect();
    accounting.sort_by(|left, right| left.ambiguity_id.cmp(&right.ambiguity_id));
    accounting
}
