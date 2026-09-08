//! One bounded deterministic Dreamer controller transition.

use std::collections::BTreeSet;

use eliot_receipts::{EffectClass, ProofCeiling};

use crate::contract::{
    CyclePhase, CyclePolicy, CycleStep, DreamerCycleState, InertOwnerRequest, ObservedOutcome,
    OutcomeDisposition, RequestKind, StepDisposition,
};
use crate::error::CycleError;
use crate::policy::{check_dispatch_budget, validate_pending_rule};
use crate::receipt::validate_observation;

/// Performs one finite state transition and emits only inert owner requests.
///
/// The three-argument form intentionally has no ambient clock. Callers that
/// have an injected observation time should use [`step_dreamer_cycle_at`].
pub fn step_dreamer_cycle(
    current: &DreamerCycleState,
    observed_external_outcomes: &[ObservedOutcome],
    cycle_policy: &CyclePolicy,
) -> Result<CycleStep, CycleError> {
    step_dreamer_cycle_at(current, observed_external_outcomes, cycle_policy, None)
}

/// Performs one transition with an explicitly supplied observation time.
pub fn step_dreamer_cycle_at(
    current: &DreamerCycleState,
    observed_external_outcomes: &[ObservedOutcome],
    cycle_policy: &CyclePolicy,
    observation_time_ms: Option<i64>,
) -> Result<CycleStep, CycleError> {
    crate::bounds::preflight_step_inputs(current, observed_external_outcomes, cycle_policy)?;
    validate_step_inputs(current, observed_external_outcomes, cycle_policy)?;
    let new_outcomes = classify_new_outcomes(current, observed_external_outcomes)?;

    let mut next = current.clone();

    let Some(outcome) = new_outcomes.first().copied() else {
        return finish_without_new_observation(
            current,
            next,
            cycle_policy,
            observation_time_ms,
            !observed_external_outcomes.is_empty(),
        );
    };

    let pending_index = next
        .pending
        .iter()
        .position(|pending| pending.request_id == outcome.receipt.core.request.metadata.request_id)
        .ok_or(CycleError::IncompleteOutcome("outcome.pending_request"))?;
    let pending = next.pending[pending_index].clone();
    let expected_predecessor = current
        .outcomes
        .iter()
        .rfind(|previous| previous.receipt.core.request.metadata.request_id == pending.request_id)
        .map(|previous| previous.receipt.identity.receipt_id.clone())
        .or_else(|| pending.predecessor_receipt_id.clone());
    validate_observation(
        current,
        &pending,
        outcome,
        expected_predecessor.as_ref(),
        cycle_policy,
    )?;

    let advances = outcome.disposition == OutcomeDisposition::Completed
        && completion_is_admissible(current, &pending, outcome);
    if next.outcomes.len() >= cycle_policy.max_outcomes as usize {
        return Err(CycleError::BudgetBlocked);
    }
    if advances {
        let expected = current.phase.next().ok_or(CycleError::PhaseViolation(
            "accepted outcome has no adjacent phase",
        ))?;
        if pending.phase != expected {
            return Err(CycleError::PhaseViolation("pending phase is not adjacent"));
        }
    }

    let disposition = record_outcome(
        &mut next,
        pending_index,
        &pending,
        outcome,
        advances,
        RecordContext {
            current,
            cycle_policy,
            observation_time_ms,
        },
    )?;

    increment_revision(&mut next)?;
    next.predecessor_digest = Some(current.canonical_digest.clone());
    next.seal()?;
    let requests = if disposition == StepDisposition::ReconciliationRequired {
        reconciliation_requests(&next, &pending.request_id)?
    } else {
        requests_for_pending(&next)?
    };
    finish_step_with_requests(current, next, requests, disposition, cycle_policy)
}

fn finish_without_new_observation(
    current: &DreamerCycleState,
    mut next: DreamerCycleState,
    cycle_policy: &CyclePolicy,
    observation_time_ms: Option<i64>,
    replayed_input: bool,
) -> Result<CycleStep, CycleError> {
    let disposition = StepDisposition::Replayed;
    if replayed_input || !next.pending.is_empty() {
        let requests = requests_for_pending_with_reconciliation(&next)?;
        return finish_step_with_requests(current, next, requests, disposition, cycle_policy);
    }
    if next.phase.next().is_some_and(|phase| {
        next.proposed_requests
            .iter()
            .any(|request| request.phase == phase)
    }) && check_dispatch_budget(current, cycle_policy, observation_time_ms).is_err()
    {
        return finish_step_with_requests(current, next, Vec::new(), disposition, cycle_policy);
    }
    if activate_proposed_request(&mut next, cycle_policy)? {
        increment_revision(&mut next)?;
        next.predecessor_digest = Some(current.canonical_digest.clone());
        next.seal()?;
        let requests = requests_for_pending(&next)?;
        return finish_step_with_requests(
            current,
            next,
            requests,
            StepDisposition::Advanced,
            cycle_policy,
        );
    }
    finish_step_with_requests(current, next, Vec::new(), disposition, cycle_policy)
}

fn classify_new_outcomes<'a>(
    current: &DreamerCycleState,
    observed_external_outcomes: &'a [ObservedOutcome],
) -> Result<Vec<&'a ObservedOutcome>, CycleError> {
    let mut new_outcomes = Vec::new();
    let mut seen_receipts = BTreeSet::new();
    for outcome in observed_external_outcomes {
        let receipt_id = outcome.receipt.identity.receipt_id.as_str();
        if !seen_receipts.insert(receipt_id) {
            return Err(CycleError::IdentityConflict {
                identity: receipt_id.to_owned(),
            });
        }
        match current.outcomes.iter().find(|previous| {
            previous.receipt.identity.receipt_id == outcome.receipt.identity.receipt_id
        }) {
            Some(previous) if previous == outcome => {}
            Some(_) => {
                return Err(CycleError::IdentityConflict {
                    identity: receipt_id.to_owned(),
                });
            }
            None => new_outcomes.push(outcome),
        }
    }
    if new_outcomes.len() > 1 {
        return Err(CycleError::PhaseViolation(
            "one new observation per transition",
        ));
    }
    Ok(new_outcomes)
}

#[derive(Clone, Copy)]
struct RecordContext<'a> {
    current: &'a DreamerCycleState,
    cycle_policy: &'a CyclePolicy,
    observation_time_ms: Option<i64>,
}

fn record_outcome(
    next: &mut DreamerCycleState,
    pending_index: usize,
    pending: &crate::contract::PendingRequest,
    outcome: &ObservedOutcome,
    advances: bool,
    context: RecordContext<'_>,
) -> Result<StepDisposition, CycleError> {
    next.outcomes.push(outcome.clone());
    let disposition = match outcome.disposition {
        OutcomeDisposition::Accepted => {
            if !next
                .frontier
                .iter()
                .any(|item| item == "owner accepted; completion remains pending")
            {
                next.frontier
                    .push("owner accepted; completion remains pending".to_owned());
            }
            StepDisposition::ReconciliationRequired
        }
        OutcomeDisposition::Completed if advances => {
            if outcome.phase == CyclePhase::ClosureObserved {
                if outcome.receipt.core.operation.effect != EffectClass::ExternalEffect
                    || outcome.receipt.core.authority.proof_ceiling
                        != ProofCeiling::ObservedExternalEffect
                {
                    return Err(CycleError::IncompleteOutcome("external_terminal_evidence"));
                }
                next.phase = CyclePhase::ClosureObserved;
                next.pending.remove(pending_index);
                StepDisposition::Terminal
            } else {
                next.phase = pending.phase;
                next.pending.remove(pending_index);
                if check_dispatch_budget(
                    context.current,
                    context.cycle_policy,
                    context.observation_time_ms,
                )
                .is_ok()
                {
                    activate_proposed_request(next, context.cycle_policy)?;
                }
                StepDisposition::Advanced
            }
        }
        OutcomeDisposition::Completed => {
            next.frontier
                .push("completed outcome has blocked typed evidence".to_owned());
            StepDisposition::Blocked
        }
        OutcomeDisposition::Unknown => {
            if !next
                .frontier
                .iter()
                .any(|item| item == "unknown external outcome")
            {
                next.frontier.push("unknown external outcome".to_owned());
            }
            StepDisposition::ReconciliationRequired
        }
        OutcomeDisposition::Partial => {
            next.frontier.push("partial owner outcome".to_owned());
            StepDisposition::Blocked
        }
        _ => {
            next.frontier
                .push("owner outcome did not advance".to_owned());
            StepDisposition::Blocked
        }
    };
    Ok(disposition)
}

fn completion_is_admissible(
    state: &DreamerCycleState,
    pending: &crate::contract::PendingRequest,
    outcome: &ObservedOutcome,
) -> bool {
    if pending.phase == CyclePhase::CommonValidated {
        return outcome
            .validation_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.terminal_disposition == "accepted");
    }
    if state.job.job_class == eliot_dreamer_contracts::JobClass::Curation
        && pending.phase == CyclePhase::HandlerObserved
    {
        return outcome.handler_result.as_ref().is_some_and(|result| {
            result.disposition == eliot_dreamer_contracts::CandidateDisposition::Candidate
        });
    }
    true
}

fn validate_step_inputs(
    current: &DreamerCycleState,
    outcomes: &[ObservedOutcome],
    policy: &CyclePolicy,
) -> Result<(), CycleError> {
    if outcomes.len() > crate::contract::MAX_RECORDS {
        return Err(CycleError::Bound {
            field: "observed_external_outcomes",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    current.validate()?;
    policy.validate()?;
    if current.job.state_fence != policy.state_fence {
        return Err(CycleError::BindingMismatch {
            field: "cycle_policy.state_fence",
            reason: "policy fence differs from cycle job",
        });
    }
    let job_deadline = current
        .job
        .deadline_ms
        .map(i64::try_from)
        .transpose()
        .map_err(|_| CycleError::BindingMismatch {
            field: "job.deadline_ms",
            reason: "deadline does not fit the controller time domain",
        })?;
    if current.job.policy_ref != policy.policy_id.as_str()
        || current.policy_id != policy.policy_id
        || current.policy_revision != policy.policy_revision
        || current.policy_digest != policy.canonical_digest
        || job_deadline != policy.deadline_ms
    {
        return Err(CycleError::BindingMismatch {
            field: "cycle_policy.identity",
            reason: "state, job and policy identity differ",
        });
    }
    for pending in current
        .pending
        .iter()
        .chain(current.proposed_requests.iter())
    {
        validate_pending_rule(pending, policy)?;
    }
    Ok(())
}

fn activate_proposed_request(
    state: &mut DreamerCycleState,
    policy: &CyclePolicy,
) -> Result<bool, CycleError> {
    if !state.pending.is_empty() {
        return Ok(false);
    }
    let Some(next_phase) = state.phase.next() else {
        return Ok(false);
    };
    let indices: Vec<usize> = state
        .proposed_requests
        .iter()
        .enumerate()
        .filter_map(|(index, request)| (request.phase == next_phase).then_some(index))
        .collect();
    if indices.len() > 1 {
        return Err(CycleError::IdentityConflict {
            identity: "duplicate proposed phase request".to_owned(),
        });
    }
    let Some(index) = indices.first().copied() else {
        return Ok(false);
    };
    let request = state.proposed_requests.remove(index);
    validate_pending_rule(&request, policy)?;
    let expected_predecessor = state
        .outcomes
        .iter()
        .next_back()
        .map(|outcome| outcome.receipt.identity.receipt_id.clone());
    if request.predecessor_receipt_id != expected_predecessor {
        return Err(CycleError::BindingMismatch {
            field: "proposed_request.predecessor",
            reason: "proposal predecessor does not name the current causal tail",
        });
    }
    state.pending.push(request);
    Ok(true)
}

fn requests_for_pending(state: &DreamerCycleState) -> Result<Vec<InertOwnerRequest>, CycleError> {
    state
        .pending
        .iter()
        .filter(|pending| !pending_has_blocked_outcome(state, pending))
        .map(|pending| {
            Ok(InertOwnerRequest {
                request_id: pending.request_id.clone(),
                operation_id: pending.operation_id.clone(),
                attempt_id: pending.attempt_id.clone(),
                owner: pending.owner.clone(),
                kind: pending.kind,
                phase: pending.phase,
                payload_digest: pending.payload_digest.clone(),
                task_id: pending.task_id.clone(),
                scope_id: pending.scope_id.clone(),
                state_fence: pending.state_fence.clone(),
                predecessor_receipt_id: pending.predecessor_receipt_id.clone(),
                reason: "awaiting an externally supplied owner observation".to_owned(),
            })
        })
        .collect()
}

fn pending_has_blocked_outcome(
    state: &DreamerCycleState,
    pending: &crate::contract::PendingRequest,
) -> bool {
    state
        .outcomes
        .iter()
        .rev()
        .find(|outcome| outcome.receipt.core.request.metadata.request_id == pending.request_id)
        .is_some_and(|outcome| {
            !matches!(
                outcome.disposition,
                OutcomeDisposition::Accepted | OutcomeDisposition::Unknown
            )
        })
}

fn reconciliation_requests(
    state: &DreamerCycleState,
    request_id: &eliot_contracts::RequestId,
) -> Result<Vec<InertOwnerRequest>, CycleError> {
    let mut requests = requests_for_pending(state)?;
    requests.retain(|request| &request.request_id == request_id);
    for request in &mut requests {
        request.predecessor_receipt_id = state
            .outcomes
            .iter()
            .rev()
            .find(|outcome| outcome.receipt.core.request.metadata.request_id == request.request_id)
            .map(|outcome| outcome.receipt.identity.receipt_id.clone());
        request.kind = RequestKind::EffectReconciliation;
        "reconcile the same operation; do not issue a replacement retry"
            .clone_into(&mut request.reason);
    }
    Ok(requests)
}

fn requests_for_pending_with_reconciliation(
    state: &DreamerCycleState,
) -> Result<Vec<InertOwnerRequest>, CycleError> {
    let mut requests = requests_for_pending(state)?;
    for request in &mut requests {
        let Some(outcome) =
            state.outcomes.iter().rev().find(|outcome| {
                outcome.receipt.core.request.metadata.request_id == request.request_id
            })
        else {
            continue;
        };
        if matches!(
            outcome.disposition,
            OutcomeDisposition::Accepted | OutcomeDisposition::Unknown
        ) {
            request.kind = RequestKind::EffectReconciliation;
            request.predecessor_receipt_id = Some(outcome.receipt.identity.receipt_id.clone());
            "reconcile the same operation; do not issue a replacement retry"
                .clone_into(&mut request.reason);
        }
    }
    Ok(requests)
}

fn finish_step_with_requests(
    current: &DreamerCycleState,
    next: DreamerCycleState,
    requests: Vec<InertOwnerRequest>,
    disposition: StepDisposition,
    policy: &CyclePolicy,
) -> Result<CycleStep, CycleError> {
    if requests.len() > policy.max_requests as usize
        || requests.len() > crate::contract::MAX_REQUESTS
    {
        return Err(CycleError::BudgetBlocked);
    }
    let candidate = CycleStep {
        predecessor_digest: current.canonical_digest.clone(),
        next_state: next,
        requests,
        disposition,
        transition_digest: String::new(),
    };
    let bytes = eliot_contracts::canonical_json_bytes(&candidate)
        .map_err(|error| CycleError::Encoding(error.to_string()))?;
    if bytes.len() > policy.max_bytes as usize || bytes.len() > crate::contract::MAX_CANONICAL_BYTES
    {
        return Err(CycleError::BudgetBlocked);
    }
    let mut sealed = candidate;
    sealed.transition_digest = eliot_contracts::sha256_hex(&bytes);
    Ok(sealed)
}

fn increment_revision(state: &mut DreamerCycleState) -> Result<(), CycleError> {
    state.controller_revision = state
        .controller_revision
        .checked_add(1)
        .ok_or(CycleError::BudgetBlocked)?;
    Ok(())
}
