//! Admission readback checks for the canonical instrument registry (issue #1814).
//!
//! A current row's ordinary registry digest is not evidence that the fields
//! in that row were admitted. This check recovers the original canonical
//! request view retained by the store and binds it to the original committed
//! receipt before the row can be used for a fresh stage admission.

use serde_json::Value;

use crate::{
    CanonicalRequestView, EffectClass, NamedMutationOperation, NamedReadOperation,
    NamedReadResponse, StoreError, TransitionClass, WriteReceipt, WriteReceiptStatus,
    canonical_request_hash,
};

/// Proves that the current instrument-registry row is the exact row admitted
/// by `receipt`'s original canonical request.
///
/// Historical rows that predate `registration_request_json` remain readable
/// through the Store API, but cannot provide this proof. A real owner
/// re-registration must replace such a row before it can support a fresh
/// stage admission.
pub fn validate_instrument_registry_registration_readback(
    readback: &NamedReadResponse,
    receipt: &WriteReceipt,
) -> Result<(), StoreError> {
    readback.validate()?;
    receipt.validate()?;
    if readback.operation != NamedReadOperation::GetInstrumentRegistryState {
        return Err(StoreError::UnknownOperation);
    }
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.transition_class != TransitionClass::InstrumentRegistry
    {
        return Err(StoreError::InvalidReceipt);
    }

    let snapshot_json = required_text(&readback.payload, "snapshot_json")?;
    let registration_authority_json =
        required_text(&readback.payload, "registration_authority_json")?;
    let registration_request_json = required_text(&readback.payload, "registration_request_json")?;
    let revision = readback
        .payload
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision > 0)
        .ok_or(StoreError::InvalidField {
            field: "instrument_registry.revision",
            reason: "existing registry row must carry a positive revision",
        })?;
    let operation_id = required_text(&readback.payload, "operation_id")?;
    let stored_hash = required_text(&readback.payload, "canonical_request_hash")?;
    let scope_id = required_text(&readback.payload, "scope_id")?;
    let task_id = optional_text(&readback.payload, "task_id")?;
    let row_fence = readback
        .payload
        .get("state_fence")
        .ok_or(StoreError::InvalidField {
            field: "instrument_registry.state_fence",
            reason: "existing registry row must carry its state fence",
        })?;
    if row_fence
        != &serde_json::to_value(&readback.state_fence)
            .map_err(|error| StoreError::Serialization(error.to_string()))?
        || readback.state_fence != receipt.state_fence
    {
        return Err(StoreError::FenceMismatch);
    }

    // Do not synthesize an original request for pre-field rows, or repair the
    // hash they retained. The exact original request bytes are the evidence.
    let original_request: CanonicalRequestView = serde_json::from_str(registration_request_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let original_hash = canonical_request_hash(&original_request)?;
    if original_hash != receipt.canonical_request_hash
        || stored_hash != receipt.canonical_request_hash
    {
        return Err(StoreError::IdentityConflict);
    }

    let [command] = original_request.semantic_commands.as_slice() else {
        return Err(StoreError::InvalidField {
            field: "instrument_registry.registration_request_json",
            reason: "original registration request must contain exactly one command",
        });
    };
    if original_request.transition_class != TransitionClass::InstrumentRegistry
        || original_request.requested_effect_ceiling != EffectClass::ReversibleMutation
        || command.operation != NamedMutationOperation::ApplyInstrumentRegistryState
    {
        return Err(StoreError::TransitionClassExceeded);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(
        command.operation,
        &command.parameters,
    )?;
    let command_snapshot =
        crate::operation_parameters::decode_instrument_registry_mutation(&command.parameters)?;
    let command_authority =
        crate::operation_parameters::decode_instrument_registry_authority_ledger(
            &command.parameters,
        )?;
    let expected_revision =
        crate::operation_parameters::decode_instrument_registry_expected_revision(
            &command.parameters,
        )?;
    if command_snapshot != snapshot_json || command_authority != registration_authority_json {
        return Err(StoreError::IdentityConflict);
    }
    if expected_revision.checked_add(1) != Some(revision) {
        return Err(StoreError::InvalidField {
            field: "instrument_registry.revision",
            reason: "row revision must advance the originally admitted expected revision by one",
        });
    }

    let envelope = receipt.require_reconciliation_envelope()?;
    if original_request.operation_id != receipt.operation_id
        || original_request.idempotency_key != receipt.idempotency_key
        || original_request.request.state_fence != receipt.state_fence
        || original_request.scope_id.as_str() != scope_id
        || original_request.task_id.as_deref() != task_id
        || original_request.task_id.as_deref()
            != original_request
                .request
                .task_id
                .as_ref()
                .map(|task_id| task_id.as_str())
        || operation_id != receipt.operation_id.as_str()
        || original_request.operation_manifest_digest != receipt.operation_manifest_digest
        || envelope.core.request.metadata != original_request.request
        || envelope.core.request.state_fence != receipt.state_fence
        || envelope.core.operation.operation_id != receipt.operation_id
        || envelope.core.operation.request_id != original_request.request.request_id
        || envelope.core.operation.idempotency_key != receipt.idempotency_key
        || envelope.core.operation.operation_kind != "store.apply.instrument_registry"
        || envelope.core.operation.effect != original_request.requested_effect_ceiling
        || envelope.core.operation.state_fence != receipt.state_fence
        || envelope.core.work_scope.scope_id.as_str() != scope_id
        || envelope.core.work_scope.product_id != original_request.request.product_id
        || envelope.core.work_scope.state_fence != receipt.state_fence
        || envelope.core.authority.state_fence != receipt.state_fence
        || envelope
            .core
            .task
            .as_ref()
            .map(|task| task.task_id.as_str())
            != task_id
        || envelope
            .core
            .task
            .as_ref()
            .is_some_and(|task| task.state_fence != receipt.state_fence)
    {
        return Err(StoreError::InvalidReceipt);
    }

    Ok(())
}

fn required_text<'a>(payload: &'a Value, field: &'static str) -> Result<&'a str, StoreError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(StoreError::InvalidField {
            field: "instrument_registry.readback",
            reason: "existing registry row is missing a required field",
        })
}

fn optional_text(payload: &Value, field: &'static str) -> Result<Option<&str>, StoreError> {
    match payload.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(StoreError::InvalidField {
            field: "instrument_registry.readback",
            reason: "optional registry row field must be a string or null",
        }),
    }
}
