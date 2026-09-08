//! Validation and reconciliation of supplied owner receipts.

use std::collections::BTreeSet;

use eliot_dreamer_contracts::{ContractViolation, JobClass, canonical_bytes};
use eliot_receipts::{ReceiptDispositionKind, ReceiptKind};

use crate::contract::{
    DreamerCycleState, ExpectedArtifact, ObservedOutcome, OutcomeDisposition, PendingRequest,
};
use crate::error::CycleError;

/// Validates an observed receipt against the exact pending request and job.
pub(crate) fn validate_observation(
    state: &DreamerCycleState,
    pending: &PendingRequest,
    outcome: &ObservedOutcome,
    expected_predecessor: Option<&eliot_contracts::ReceiptId>,
    policy: &crate::contract::CyclePolicy,
) -> Result<(), CycleError> {
    outcome.receipt.validate()?;
    let core = &outcome.receipt.core;
    validate_receipt_bounds(core, outcome)?;
    validate_outer_binding(pending, outcome, expected_predecessor, core)?;
    validate_typed_evidence(state, pending, outcome, core)?;
    validate_required_evidence(state, pending, outcome)?;
    validate_phase_rule(pending, policy, core)
}

fn validate_outer_binding(
    pending: &PendingRequest,
    outcome: &ObservedOutcome,
    expected_predecessor: Option<&eliot_contracts::ReceiptId>,
    core: &eliot_receipts::ReceiptCore,
) -> Result<(), CycleError> {
    if core.kind != ReceiptKind::Operation {
        return Err(CycleError::BindingMismatch {
            field: "receipt.kind",
            reason: "operation receipt required",
        });
    }
    if core.request.metadata.request_id != pending.request_id {
        return Err(CycleError::BindingMismatch {
            field: "receipt.request_id",
            reason: "request identity differs from pending request",
        });
    }
    if core.operation.operation_id != pending.operation_id
        || core.operation.idempotency_key != pending.idempotency_key
        || core.operation.operation_kind != pending.operation_kind
        || core.operation.effect != pending.effect
    {
        return Err(CycleError::BindingMismatch {
            field: "receipt.operation",
            reason: "operation binding differs from pending request",
        });
    }
    if core.work_scope.product_id != pending.product_id
        || core.request.metadata.product_id != pending.product_id
        || core.request.metadata.source_id != pending.source_id
        || core.work_scope.state_fence != pending.state_fence
    {
        return Err(CycleError::BindingMismatch {
            field: "receipt.scope",
            reason: "product, source or fence differs from pending request",
        });
    }
    let Some(task) = core.task.as_ref() else {
        return Err(CycleError::IncompleteOutcome("receipt.task"));
    };
    if task.task_id.as_str() != pending.task_id {
        return Err(CycleError::BindingMismatch {
            field: "receipt.task_id",
            reason: "task differs from pending request",
        });
    }
    if let Some(metadata_task) = core.request.metadata.task_id.as_ref()
        && metadata_task.as_str() != pending.task_id
    {
        return Err(CycleError::BindingMismatch {
            field: "receipt.metadata.task_id",
            reason: "request metadata task differs from pending request",
        });
    }
    if core.work_scope.scope_id.as_str() != pending.scope_id
        || core.authority.authority_owner != pending.owner
        || core.authority.proof_ceiling != pending.proof_ceiling
        || core.authority.allowed_effect != pending.effect
    {
        return Err(CycleError::BindingMismatch {
            field: "receipt.owner_scope",
            reason: "owner, proof ceiling or scope differs from pending request",
        });
    }
    if core.causal.parent_receipt_id.as_ref() != expected_predecessor {
        return Err(CycleError::BindingMismatch {
            field: "receipt.predecessor",
            reason: "causal predecessor differs from pending request",
        });
    }
    if outcome.phase != pending.phase {
        return Err(CycleError::PhaseViolation(
            "outcome phase is not the pending phase",
        ));
    }
    if outcome.payload_digest != pending.payload_digest {
        return Err(CycleError::BindingMismatch {
            field: "outcome.payload_digest",
            reason: "payload does not match pending request digest",
        });
    }
    let outer_request_digest = request_digest(pending)?;
    validate_expected_artifacts(
        &core.artifacts,
        &pending.expected_artifacts,
        &outer_request_digest,
        &pending.payload_digest,
        &outcome.evidence_refs,
    )?;
    validate_outcome_disposition(core.disposition.kind(), outcome.disposition)?;
    if outcome.possible_effect && outcome.disposition != OutcomeDisposition::Unknown {
        return Err(CycleError::BindingMismatch {
            field: "outcome.possible_effect",
            reason: "possible effect must remain unknown for reconciliation",
        });
    }
    Ok(())
}

fn validate_typed_evidence(
    state: &DreamerCycleState,
    pending: &PendingRequest,
    outcome: &ObservedOutcome,
    core: &eliot_receipts::ReceiptCore,
) -> Result<(), CycleError> {
    if let Some(request) = &pending.handler_request {
        if request.job_id != state.job.canonical_id()
            || request.task_id != pending.task_id
            || request.scope_id != pending.scope_id
            || request.state_fence != pending.state_fence
        {
            return Err(CycleError::BindingMismatch {
                field: "pending.handler_request",
                reason: "typed handler request is outside the exact cycle binding",
            });
        }
        let Some(screen) = request.screen_binding.as_ref() else {
            return Err(CycleError::IncompleteOutcome(
                "handler_request.screen_binding",
            ));
        };
        let prior_screen = state
            .outcomes
            .iter()
            .rev()
            .find(|previous| previous.phase == crate::contract::CyclePhase::Screened)
            .and_then(|previous| previous.screen_binding.as_ref());
        if prior_screen != Some(screen) {
            return Err(CycleError::BindingMismatch {
                field: "handler_request.screen_binding",
                reason: "handler request screen differs from retained eligible screen",
            });
        }
    }
    if let Some(result) = &outcome.handler_result {
        validate_handler_result(pending, outcome, core, result)?;
    }
    if let Some(receipt) = &outcome.validation_receipt {
        validate_validation_receipt(state, pending, outcome, core, receipt)?;
    }
    if let Some(screen) = &outcome.screen_binding {
        validate_screen_binding(pending, outcome, core, screen)?;
    }
    Ok(())
}

fn validate_required_evidence(
    state: &DreamerCycleState,
    pending: &PendingRequest,
    outcome: &ObservedOutcome,
) -> Result<(), CycleError> {
    if outcome.disposition != OutcomeDisposition::Completed {
        return Ok(());
    }
    if pending.phase == crate::contract::CyclePhase::Screened && outcome.screen_binding.is_none() {
        return Err(CycleError::IncompleteOutcome("screen_binding"));
    }
    if pending.phase == crate::contract::CyclePhase::CommonValidated
        && outcome.validation_receipt.is_none()
    {
        return Err(CycleError::IncompleteOutcome("validation_receipt"));
    }
    if state.job.job_class == JobClass::Curation
        && pending.phase == crate::contract::CyclePhase::HandlerObserved
        && (pending.handler_request.is_none() || outcome.handler_result.is_none())
    {
        return Err(CycleError::IncompleteOutcome("curation.handler_evidence"));
    }
    Ok(())
}

fn validate_phase_rule(
    pending: &PendingRequest,
    policy: &crate::contract::CyclePolicy,
    core: &eliot_receipts::ReceiptCore,
) -> Result<(), CycleError> {
    if let Some(rule) = policy
        .phase_rules
        .iter()
        .find(|rule| rule.phase == pending.phase)
        && (core.authority.authority_owner != rule.owner
            || core.work_scope.product_id != rule.product_id
            || core.request.metadata.source_id != rule.source_id
            || core.operation.operation_kind != rule.operation_kind
            || core.operation.effect != rule.effect
            || core.authority.proof_ceiling != rule.proof_ceiling)
    {
        return Err(CycleError::BindingMismatch {
            field: "receipt.phase_rule",
            reason: "receipt differs from frozen phase rule",
        });
    }
    Ok(())
}

fn validate_handler_result(
    pending: &PendingRequest,
    outcome: &ObservedOutcome,
    core: &eliot_receipts::ReceiptCore,
    result: &eliot_dreamer_contracts::TypedCurationHandlerResult,
) -> Result<(), CycleError> {
    result.validate().map_err(|error| contract_error(&error))?;
    let request = pending
        .handler_request
        .as_ref()
        .ok_or(CycleError::IncompleteOutcome("handler_result.request"))?;
    if result.request_id != request.request_id
        || result.kind != request.kind
        || result.family != request.family
        || result.handler_id != pending.owner
    {
        return Err(CycleError::BindingMismatch {
            field: "handler_result.binding",
            reason: "handler result identity differs from pending request",
        });
    }
    let request_bytes = canonical_bytes(request).map_err(|error| contract_error(&error))?;
    let typed_request_digest = eliot_contracts::sha256_hex(&request_bytes);
    if result.request_digest != typed_request_digest {
        return Err(CycleError::BindingMismatch {
            field: "handler_result.request_digest",
            reason: "handler result does not bind canonical typed request",
        });
    }
    require_evidence_artifact(
        &core.artifacts,
        &outcome.evidence_refs,
        &result.result_digest,
        "handler_result.result_digest",
    )?;
    require_full_evidence_artifact(
        &core.artifacts,
        &outcome.evidence_refs,
        result,
        "handler_result.canonical_artifact",
    )
}

fn validate_validation_receipt(
    state: &DreamerCycleState,
    pending: &PendingRequest,
    outcome: &ObservedOutcome,
    core: &eliot_receipts::ReceiptCore,
    receipt: &eliot_dreamer_contracts::ValidationReceipt,
) -> Result<(), CycleError> {
    receipt.validate().map_err(|error| contract_error(&error))?;
    if receipt.job_id != state.job.canonical_id()
        || receipt.task_id != pending.task_id
        || receipt.scope_id != pending.scope_id
        || receipt.bundle_digest != pending.bundle_digest
        || receipt.manifest_digest != state.job.frozen_manifest_digest
        || receipt.state_fence != pending.state_fence
    {
        return Err(CycleError::BindingMismatch {
            field: "validation_receipt",
            reason: "validation receipt is outside the pending scope",
        });
    }
    require_evidence_artifact(
        &core.artifacts,
        &outcome.evidence_refs,
        &receipt.input_digest,
        "validation_receipt.input_digest",
    )?;
    require_full_evidence_artifact(
        &core.artifacts,
        &outcome.evidence_refs,
        receipt,
        "validation_receipt.canonical_artifact",
    )?;
    require_evidence_artifact(
        &core.artifacts,
        &outcome.evidence_refs,
        &receipt.output_digest,
        "validation_receipt.output_digest",
    )
}

fn validate_screen_binding(
    pending: &PendingRequest,
    outcome: &ObservedOutcome,
    core: &eliot_receipts::ReceiptCore,
    screen: &eliot_dreamer_contracts::ScreenBinding,
) -> Result<(), CycleError> {
    screen.validate().map_err(|error| contract_error(&error))?;
    if screen.request_id.as_str() != pending.request_id.as_str()
        || screen.task_id != pending.task_id
        || screen.scope_id != pending.scope_id
        || screen.state_fence != pending.state_fence
    {
        return Err(CycleError::BindingMismatch {
            field: "screen_binding",
            reason: "screen binding is outside the pending scope",
        });
    }
    require_evidence_artifact(
        &core.artifacts,
        &outcome.evidence_refs,
        &screen.result_digest,
        "screen_binding.result_digest",
    )?;
    if screen.item_digest != pending.payload_digest {
        require_evidence_artifact(
            &core.artifacts,
            &outcome.evidence_refs,
            &screen.item_digest,
            "screen_binding.item_digest",
        )?;
    }
    require_full_evidence_artifact(
        &core.artifacts,
        &outcome.evidence_refs,
        screen,
        "screen_binding.canonical_artifact",
    )
}

fn validate_expected_artifacts(
    actual: &[eliot_receipts::ArtifactBinding],
    expected: &[ExpectedArtifact],
    request_digest: &str,
    payload_digest: &str,
    evidence_refs: &[eliot_contracts::ArtifactId],
) -> Result<(), CycleError> {
    let mut seen = BTreeSet::new();
    for artifact in actual {
        if !seen.insert(artifact.artifact_id.as_str()) {
            return Err(CycleError::IdentityConflict {
                identity: artifact.artifact_id.as_str().to_owned(),
            });
        }
    }
    for item in expected {
        if !actual.iter().any(|artifact| {
            artifact.artifact_id == item.artifact_id
                && artifact.sha256 == item.sha256
                && artifact.role == item.role
                && artifact.source_revision == item.source_revision
        }) {
            return Err(CycleError::BindingMismatch {
                field: "receipt.artifacts",
                reason: "receipt omits a frozen expected artifact",
            });
        }
    }
    for artifact in actual {
        if artifact.role != ReceiptKind::Request
            && !expected.iter().any(|item| {
                item.artifact_id == artifact.artifact_id
                    && item.sha256 == artifact.sha256
                    && item.role == artifact.role
                    && item.source_revision == artifact.source_revision
            })
            && !evidence_refs
                .iter()
                .any(|reference| reference == &artifact.artifact_id)
        {
            return Err(CycleError::BindingMismatch {
                field: "receipt.artifacts",
                reason: "unfrozen output artifact is not retained as evidence",
            });
        }
    }
    let request_artifacts: Vec<_> = actual
        .iter()
        .filter(|artifact| artifact.role == ReceiptKind::Request)
        .collect();
    if request_artifacts.len() != 1 || request_artifacts[0].sha256 != request_digest {
        return Err(CycleError::IncompleteOutcome("receipt.request_artifact"));
    }
    if !expected.iter().any(|item| item.sha256 == payload_digest) {
        return Err(CycleError::IncompleteOutcome("pending.payload_artifact"));
    }
    Ok(())
}

fn validate_receipt_bounds(
    core: &eliot_receipts::ReceiptCore,
    outcome: &ObservedOutcome,
) -> Result<(), CycleError> {
    for (count, field) in [
        (core.artifacts.len(), "receipt.artifacts"),
        (
            core.causal.predecessor_receipt_ids.len(),
            "receipt.predecessors",
        ),
        (outcome.evidence_refs.len(), "outcome.evidence_refs"),
    ] {
        if count > crate::contract::MAX_RECORDS {
            return Err(CycleError::Bound {
                field,
                maximum: crate::contract::MAX_RECORDS,
            });
        }
    }
    if let Some(verifier) = &core.verifier
        && verifier.artifact_ids.len() > crate::contract::MAX_RECORDS
    {
        return Err(CycleError::Bound {
            field: "receipt.verifier.artifact_ids",
            maximum: crate::contract::MAX_RECORDS,
        });
    }
    let mut refs = BTreeSet::new();
    if outcome
        .evidence_refs
        .iter()
        .any(|reference| !refs.insert(reference.as_str()))
    {
        return Err(CycleError::IdentityConflict {
            identity: "outcome.evidence_refs".to_owned(),
        });
    }
    if let eliot_receipts::ReceiptDisposition::Partial { unresolved, .. } = &core.disposition {
        if unresolved.len() > crate::contract::MAX_RECORDS {
            return Err(CycleError::Bound {
                field: "receipt.disposition.unresolved",
                maximum: crate::contract::MAX_RECORDS,
            });
        }
        if unresolved
            .iter()
            .any(|item| item.len() > crate::contract::MAX_TEXT_BYTES)
        {
            return Err(CycleError::Bound {
                field: "receipt.disposition.unresolved",
                maximum: crate::contract::MAX_TEXT_BYTES,
            });
        }
    }
    Ok(())
}

fn require_evidence_artifact(
    artifacts: &[eliot_receipts::ArtifactBinding],
    evidence_refs: &[eliot_contracts::ArtifactId],
    digest: &str,
    field: &'static str,
) -> Result<(), CycleError> {
    if artifacts.iter().any(|artifact| {
        artifact.sha256 == digest
            && artifact.role != ReceiptKind::Request
            && evidence_refs
                .iter()
                .any(|reference| reference == &artifact.artifact_id)
    }) {
        return Ok(());
    }
    Err(CycleError::IncompleteOutcome(field))
}

fn require_full_evidence_artifact<T: serde::Serialize>(
    artifacts: &[eliot_receipts::ArtifactBinding],
    evidence_refs: &[eliot_contracts::ArtifactId],
    value: &T,
    field: &'static str,
) -> Result<(), CycleError> {
    let bytes = canonical_bytes(value).map_err(|error| contract_error(&error))?;
    let digest = eliot_contracts::sha256_hex(&bytes);
    require_evidence_artifact(artifacts, evidence_refs, &digest, field)
}

fn validate_outcome_disposition(
    generic: ReceiptDispositionKind,
    specialized: OutcomeDisposition,
) -> Result<(), CycleError> {
    let valid = match generic {
        ReceiptDispositionKind::Success => matches!(
            specialized,
            OutcomeDisposition::Accepted | OutcomeDisposition::Completed
        ),
        ReceiptDispositionKind::Partial => specialized == OutcomeDisposition::Partial,
        ReceiptDispositionKind::Failure => matches!(
            specialized,
            OutcomeDisposition::Rejected
                | OutcomeDisposition::Unavailable
                | OutcomeDisposition::Stale
                | OutcomeDisposition::Expired
                | OutcomeDisposition::Superseded
        ),
        ReceiptDispositionKind::Unknown => specialized == OutcomeDisposition::Unknown,
        ReceiptDispositionKind::Cancelled => specialized == OutcomeDisposition::Cancelled,
    };
    if valid {
        Ok(())
    } else {
        Err(CycleError::BindingMismatch {
            field: "outcome.disposition",
            reason: "specialized disposition disagrees with generic receipt",
        })
    }
}

/// Hashes the digest-excluded immutable pending request, including attempt ID.
pub(crate) fn request_digest(pending: &PendingRequest) -> Result<String, CycleError> {
    let bytes = eliot_contracts::canonical_json_bytes(&pending)
        .map_err(|error| CycleError::Encoding(error.to_string()))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

fn contract_error(error: &ContractViolation) -> CycleError {
    CycleError::Contract(error.to_string())
}
