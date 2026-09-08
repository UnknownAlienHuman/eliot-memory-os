//! Borrowed size preflight for the pure transition boundary.

use crate::contract::{CyclePolicy, DreamerCycleState, ObservedOutcome, PendingRequest};
use crate::error::CycleError;

/// Checks nested counts and scalar byte widths before any receipt validation,
/// cloning, digesting, or canonical serialization occurs.
pub(crate) fn preflight_step_inputs(
    state: &DreamerCycleState,
    outcomes: &[ObservedOutcome],
    policy: &CyclePolicy,
) -> Result<(), CycleError> {
    if state.pending.len() > crate::contract::MAX_RECORDS
        || state.outcomes.len() > crate::contract::MAX_RECORDS
        || outcomes.len() > crate::contract::MAX_RECORDS
        || state.frontier.len() > crate::contract::MAX_RECORDS
        || state.proposed_requests.len() > crate::contract::MAX_REQUESTS
        || policy.phase_rules.len() > crate::contract::MAX_RECORDS
    {
        return Err(CycleError::Bound {
            field: "transition.collections",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    let mut total = 0usize;
    text(state.cycle_id.as_str(), &mut total, "state.cycle_id")?;
    text(state.policy_id.as_str(), &mut total, "state.policy_id")?;
    text(&state.bundle_digest, &mut total, "state.bundle_digest")?;
    text(&state.policy_digest, &mut total, "state.policy_digest")?;
    text(
        &state.canonical_digest,
        &mut total,
        "state.canonical_digest",
    )?;
    text(&state.job.operation_id, &mut total, "job.operation_id")?;
    text(
        &state.job.idempotency_key,
        &mut total,
        "job.idempotency_key",
    )?;
    text(&state.job.task_id, &mut total, "job.task_id")?;
    text(&state.job.scope_id, &mut total, "job.scope_id")?;
    text(
        &state.job.requester.principal,
        &mut total,
        "job.requester.principal",
    )?;
    text(&state.job.contract_ref, &mut total, "job.contract_ref")?;
    text(&state.job.policy_ref, &mut total, "job.policy_ref")?;
    text(
        &state.job.privacy_profile,
        &mut total,
        "job.privacy_profile",
    )?;
    text(
        &state.job.frozen_manifest_digest,
        &mut total,
        "job.frozen_manifest_digest",
    )?;
    text(
        &policy.canonical_digest,
        &mut total,
        "policy.canonical_digest",
    )?;
    for item in &state.frontier {
        text(item, &mut total, "state.frontier")?;
    }
    for item in state.pending.iter().chain(state.proposed_requests.iter()) {
        preflight_pending(item, &mut total)?;
    }
    for item in state.outcomes.iter().chain(outcomes.iter()) {
        preflight_outcome(item, &mut total)?;
    }
    for rule in &policy.phase_rules {
        text(&rule.owner, &mut total, "policy.phase_rule.owner")?;
        text(
            rule.product_id.as_str(),
            &mut total,
            "policy.phase_rule.product_id",
        )?;
        text(
            rule.source_id.as_str(),
            &mut total,
            "policy.phase_rule.source_id",
        )?;
        text(
            &rule.operation_kind,
            &mut total,
            "policy.phase_rule.operation_kind",
        )?;
    }
    if total > crate::contract::MAX_CANONICAL_BYTES {
        return Err(CycleError::Bound {
            field: "transition.scalar_bytes",
            maximum: crate::contract::MAX_CANONICAL_BYTES,
        });
    }
    Ok(())
}

/// Preflights a policy before its canonical digest is computed.
pub(crate) fn preflight_policy(policy: &CyclePolicy) -> Result<(), CycleError> {
    if policy.phase_rules.len() > crate::contract::MAX_RECORDS {
        return Err(CycleError::Bound {
            field: "policy.phase_rules",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    let mut total = 0usize;
    text(policy.policy_id.as_str(), &mut total, "policy.policy_id")?;
    text(
        &policy.canonical_digest,
        &mut total,
        "policy.canonical_digest",
    )?;
    for rule in &policy.phase_rules {
        text(&rule.owner, &mut total, "policy.phase_rule.owner")?;
        text(
            rule.product_id.as_str(),
            &mut total,
            "policy.phase_rule.product_id",
        )?;
        text(
            rule.source_id.as_str(),
            &mut total,
            "policy.phase_rule.source_id",
        )?;
        text(
            &rule.operation_kind,
            &mut total,
            "policy.phase_rule.operation_kind",
        )?;
    }
    Ok(())
}

/// Preflights retained state before its canonical digest is computed.
pub(crate) fn preflight_state(state: &DreamerCycleState) -> Result<(), CycleError> {
    if state.pending.len() > crate::contract::MAX_RECORDS
        || state.outcomes.len() > crate::contract::MAX_RECORDS
        || state.frontier.len() > crate::contract::MAX_RECORDS
        || state.proposed_requests.len() > crate::contract::MAX_REQUESTS
    {
        return Err(CycleError::Bound {
            field: "state.collections",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    let mut total = 0usize;
    text(state.cycle_id.as_str(), &mut total, "state.cycle_id")?;
    text(state.policy_id.as_str(), &mut total, "state.policy_id")?;
    text(&state.bundle_digest, &mut total, "state.bundle_digest")?;
    text(&state.policy_digest, &mut total, "state.policy_digest")?;
    text(
        &state.canonical_digest,
        &mut total,
        "state.canonical_digest",
    )?;
    for item in &state.frontier {
        text(item, &mut total, "state.frontier")?;
    }
    for item in state.pending.iter().chain(state.proposed_requests.iter()) {
        preflight_pending(item, &mut total)?;
    }
    for item in &state.outcomes {
        preflight_outcome(item, &mut total)?;
    }
    if total > crate::contract::MAX_CANONICAL_BYTES {
        return Err(CycleError::Bound {
            field: "state.scalar_bytes",
            maximum: crate::contract::MAX_CANONICAL_BYTES,
        });
    }
    Ok(())
}

fn preflight_pending(pending: &PendingRequest, total: &mut usize) -> Result<(), CycleError> {
    for (value, field) in [
        (pending.request_id.as_str(), "pending.request_id"),
        (pending.operation_id.as_str(), "pending.operation_id"),
        (pending.idempotency_key.as_str(), "pending.idempotency_key"),
        (pending.product_id.as_str(), "pending.product_id"),
        (pending.source_id.as_str(), "pending.source_id"),
        (pending.operation_kind.as_str(), "pending.operation_kind"),
        (pending.owner.as_str(), "pending.owner"),
        (pending.attempt_id.as_str(), "pending.attempt_id"),
        (pending.payload_digest.as_str(), "pending.payload_digest"),
        (pending.bundle_digest.as_str(), "pending.bundle_digest"),
        (pending.job_digest.as_str(), "pending.job_digest"),
        (pending.task_id.as_str(), "pending.task_id"),
        (pending.scope_id.as_str(), "pending.scope_id"),
    ] {
        text(value, total, field)?;
    }
    if pending.expected_artifacts.len() > crate::contract::MAX_RECORDS {
        return Err(CycleError::Bound {
            field: "pending.expected_artifacts",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    for artifact in &pending.expected_artifacts {
        text(
            artifact.artifact_id.as_str(),
            total,
            "expected_artifact.artifact_id",
        )?;
        text(&artifact.sha256, total, "expected_artifact.sha256")?;
        if let Some(revision) = &artifact.source_revision {
            text(revision, total, "expected_artifact.source_revision")?;
        }
    }
    if let Some(request) = &pending.handler_request {
        for (value, field) in [
            (&request.request_id, "handler.request_id"),
            (&request.receipt_id, "handler.receipt_id"),
            (&request.source_snapshot, "handler.source_snapshot"),
            (&request.source_revision, "handler.source_revision"),
            (&request.profile, "handler.profile"),
            (&request.job_id, "handler.job_id"),
            (&request.scope_id, "handler.scope_id"),
            (&request.task_id, "handler.task_id"),
        ] {
            text(value, total, field)?;
        }
        preflight_facets(request.payload.facets(), total, "handler.payload")?;
        if request.denominator.members.len() > crate::contract::MAX_RECORDS {
            return Err(CycleError::Bound {
                field: "handler.denominator.members",
                maximum: crate::contract::MAX_RECORDS,
            });
        }
        for member in &request.denominator.members {
            text(member, total, "handler.denominator.member")?;
        }
        if let Some(screen) = &request.screen_binding {
            preflight_screen(screen, total)?;
        }
    }
    Ok(())
}

fn preflight_outcome(outcome: &ObservedOutcome, total: &mut usize) -> Result<(), CycleError> {
    text(&outcome.payload_digest, total, "outcome.payload_digest")?;
    if outcome.evidence_refs.len() > crate::contract::MAX_RECORDS {
        return Err(CycleError::Bound {
            field: "outcome.evidence_refs",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    let core = &outcome.receipt.core;
    text(
        outcome.receipt.identity.receipt_id.as_str(),
        total,
        "receipt.receipt_id",
    )?;
    text(
        &outcome.receipt.identity.canonical_sha256,
        total,
        "receipt.canonical_sha256",
    )?;
    text(core.contract.name.as_str(), total, "receipt.contract")?;
    if core.artifacts.len() > crate::contract::MAX_RECORDS
        || core.causal.predecessor_receipt_ids.len() > crate::contract::MAX_RECORDS
    {
        return Err(CycleError::Bound {
            field: "receipt.collections",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    for artifact in &core.artifacts {
        text(artifact.artifact_id.as_str(), total, "receipt.artifact_id")?;
        text(&artifact.sha256, total, "receipt.artifact.sha256")?;
        if let Some(revision) = &artifact.source_revision {
            text(revision, total, "receipt.artifact.source_revision")?;
        }
    }
    text(
        core.request.metadata.request_id.as_str(),
        total,
        "receipt.request_id",
    )?;
    text(
        core.request.metadata.product_id.as_str(),
        total,
        "receipt.product_id",
    )?;
    text(
        core.request.metadata.source_id.as_str(),
        total,
        "receipt.source_id",
    )?;
    for predecessor in &core.causal.predecessor_receipt_ids {
        text(predecessor.as_str(), total, "receipt.predecessor")?;
    }
    text(
        core.operation.operation_id.as_str(),
        total,
        "receipt.operation_id",
    )?;
    text(
        core.operation.request_id.as_str(),
        total,
        "receipt.operation_request_id",
    )?;
    text(
        &core.operation.idempotency_key,
        total,
        "receipt.idempotency_key",
    )?;
    text(
        &core.operation.operation_kind,
        total,
        "receipt.operation_kind",
    )?;
    text(
        &core.authority.authority_owner,
        total,
        "receipt.authority_owner",
    )?;
    if let Some(task) = &core.task {
        text(task.task_id.as_str(), total, "receipt.task_id")?;
    }
    if let Some(session) = &core.session {
        text(session.session_id.as_str(), total, "receipt.session_id")?;
    }
    if let Some(session_id) = &core.request.metadata.session_id {
        text(session_id.as_str(), total, "receipt.metadata.session_id")?;
    }
    text(
        core.authority.authority_id.as_str(),
        total,
        "receipt.authority_id",
    )?;
    if let Some(verifier) = &core.verifier {
        if verifier.artifact_ids.len() > crate::contract::MAX_RECORDS {
            return Err(CycleError::Bound {
                field: "receipt.verifier.artifact_ids",
                maximum: crate::contract::MAX_RECORDS,
            });
        }
        for artifact_id in &verifier.artifact_ids {
            text(artifact_id.as_str(), total, "receipt.verifier.artifact_id")?;
        }
    }
    if let Some(parent) = &core.causal.parent_receipt_id {
        text(parent.as_str(), total, "receipt.parent_receipt_id")?;
    }
    if let Some(problem) = &core.problem {
        text(problem.problem_id.as_str(), total, "receipt.problem_id")?;
    }
    if let Some(coordination) = &core.coordination {
        text(
            coordination.event_id.as_str(),
            total,
            "receipt.coordination_id",
        )?;
        text(
            &coordination.idempotency_key,
            total,
            "receipt.coordination_idempotency",
        )?;
    }
    for evidence in &outcome.evidence_refs {
        text(evidence.as_str(), total, "outcome.evidence_ref")?;
    }
    if let Some(request) = &outcome.handler_result {
        text(&request.request_id, total, "handler_result.request_id")?;
        text(&request.handler_id, total, "handler_result.handler_id")?;
        text(
            &request.request_digest,
            total,
            "handler_result.request_digest",
        )?;
        text(
            &request.result_digest,
            total,
            "handler_result.result_digest",
        )?;
    }
    if let Some(receipt) = &outcome.validation_receipt {
        for (value, field) in [
            (&receipt.validator_contract, "validation.validator_contract"),
            (&receipt.validator_policy, "validation.validator_policy"),
            (&receipt.job_id, "validation.job_id"),
            (&receipt.draft_digest, "validation.draft_digest"),
            (&receipt.bundle_digest, "validation.bundle_digest"),
            (&receipt.manifest_digest, "validation.manifest_digest"),
            (&receipt.task_id, "validation.task_id"),
            (&receipt.scope_id, "validation.scope_id"),
            (&receipt.input_digest, "validation.input_digest"),
            (&receipt.output_digest, "validation.output_digest"),
            (
                &receipt.terminal_disposition,
                "validation.terminal_disposition",
            ),
            (&receipt.proof_ceiling, "validation.proof_ceiling"),
            (
                &receipt.preservation_digest,
                "validation.preservation_digest",
            ),
            (&receipt.budget_digest, "validation.budget_digest"),
        ] {
            text(value, total, field)?;
        }
    }
    if let Some(screen) = &outcome.screen_binding {
        preflight_screen(screen, total)?;
    }
    Ok(())
}

fn preflight_facets(
    facets: &eliot_dreamer_contracts::curation::TargetEvidence,
    total: &mut usize,
    field: &'static str,
) -> Result<(), CycleError> {
    if facets.targets.len() > crate::contract::MAX_RECORDS
        || facets.evidence_refs.len() > crate::contract::MAX_RECORDS
    {
        return Err(CycleError::Bound {
            field,
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    for target in &facets.targets {
        text(target, total, "typed.target")?;
    }
    for evidence in &facets.evidence_refs {
        text(evidence, total, "typed.evidence_ref")?;
    }
    Ok(())
}

fn preflight_screen(
    screen: &eliot_dreamer_contracts::ScreenBinding,
    total: &mut usize,
) -> Result<(), CycleError> {
    for (value, field) in [
        (screen.request_id.as_str(), "screen.request_id"),
        (screen.receipt_id.as_str(), "screen.receipt_id"),
        (screen.source_snapshot.as_str(), "screen.source_snapshot"),
        (screen.source_revision.as_str(), "screen.source_revision"),
        (screen.profile.as_str(), "screen.profile"),
        (screen.task_id.as_str(), "screen.task_id"),
        (screen.scope_id.as_str(), "screen.scope_id"),
        (screen.result_digest.as_str(), "screen.result_digest"),
        (screen.item_digest.as_str(), "screen.item_digest"),
    ] {
        text(value, total, field)?;
    }
    if screen.screened_targets.len() > crate::contract::MAX_RECORDS {
        return Err(CycleError::Bound {
            field: "screen.screened_targets",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    for target in &screen.screened_targets {
        text(target, total, "screen.target")?;
    }
    Ok(())
}

fn text(value: &str, total: &mut usize, field: &'static str) -> Result<(), CycleError> {
    if value.len() > crate::contract::MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(CycleError::Bound {
            field,
            maximum: crate::contract::MAX_TEXT_BYTES,
        });
    }
    *total = total.checked_add(value.len()).ok_or(CycleError::Bound {
        field: "transition.scalar_bytes",
        maximum: crate::contract::MAX_CANONICAL_BYTES,
    })?;
    Ok(())
}
