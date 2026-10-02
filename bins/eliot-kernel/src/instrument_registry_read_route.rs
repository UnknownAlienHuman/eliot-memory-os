//! Closed authenticated read route for the persisted instrument registry.
//!
//! The route accepts only the two Store named reads needed to retain the
//! original registration proof. Every receipt lookup is first joined to the
//! current registry row at the exact fixed scope carried by the request.

#[cfg(windows)]
use eliot_ipc::{PeerIdentity, SessionState};
use eliot_ipc::{RequestIdentity, Session, TransportError};
#[cfg(any(windows, test))]
use eliot_store_api::{
    NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency, RevisionKey, ScopeId,
    StoreError, TransitionClass, WriteReceipt, WriteReceiptStatus,
};
#[cfg(any(windows, test))]
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(windows)]
use serde_json::json;

/// Closed Kernel Execute selector. The manager registers this selector on the
/// authenticated daemon dispatcher; it is not a generic Store route.
#[cfg(windows)]
pub const INSTRUMENT_REGISTRY_READ_OPERATION: &str = "instrument_registry.read";

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstrumentRegistryReadRequest {
    scope_id: ScopeId,
    request: NamedReadRequest,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CurrentRegistryOwner {
    operation_id: String,
    canonical_request_hash: String,
    task_id: String,
    readback: NamedReadResponse,
}

impl super::KernelComposition {
    /// Executes the registered instrument-registry read selector using the
    /// session's authenticated original request identity.
    #[cfg(windows)]
    pub(crate) async fn instrument_registry_read_operation(
        &self,
        session: &Session,
        identity: &RequestIdentity,
        payload: Value,
    ) -> Result<Value, TransportError> {
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if session.state != SessionState::Open
            || !matches!(&session.peer, PeerIdentity::Authenticated { .. })
            || session.peer.validate().is_err()
            || identity.request.state_fence != identity.request.metadata.state_fence
            || identity.request.state_fence != session.module_generation.state_fence
            || identity.request.metadata.task_id.is_none()
        {
            return Err(TransportError::SessionFenced);
        }

        let route_request: InstrumentRegistryReadRequest =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        validate_registry_read_request(&route_request, &identity.request.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;

        let gateway = self.retained_store_gateway()?;
        match route_request.request.operation {
            NamedReadOperation::GetInstrumentRegistryState => {
                let current = read_current_registry(
                    gateway.as_ref(),
                    &route_request.scope_id,
                    &identity.request.state_fence,
                    identity,
                )
                .await?;
                resolve_current_registration_receipt(
                    gateway.as_ref(),
                    &route_request.scope_id,
                    &identity.request.state_fence,
                    identity,
                    &current,
                )
                .await?;
                let latest = read_current_registry(
                    gateway.as_ref(),
                    &route_request.scope_id,
                    &identity.request.state_fence,
                    identity,
                )
                .await?;
                require_same_current_registration(&current, &latest)?;
                serde_json::to_value(latest.readback).map_err(|_| TransportError::SessionFenced)
            }
            NamedReadOperation::ResolveWriteReceipt => {
                let current = read_current_registry(
                    gateway.as_ref(),
                    &route_request.scope_id,
                    &identity.request.state_fence,
                    identity,
                )
                .await?;
                let requested_operation_id = route_request
                    .request
                    .parameters
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .ok_or(TransportError::SessionFenced)?;
                if requested_operation_id != current.operation_id {
                    return Err(TransportError::SessionFenced);
                }
                resolve_current_registration_receipt(
                    gateway.as_ref(),
                    &route_request.scope_id,
                    &identity.request.state_fence,
                    identity,
                    &current,
                )
                .await?;
                let receipt_response = gateway
                    .execute_named_with_error(route_request.request)
                    .await
                    .map_err(|_| TransportError::SessionFenced)?;
                validate_receipt_response(
                    &receipt_response,
                    &route_request.scope_id,
                    identity,
                    &current,
                )?;
                let latest = read_current_registry(
                    gateway.as_ref(),
                    &route_request.scope_id,
                    &identity.request.state_fence,
                    identity,
                )
                .await?;
                require_same_current_registration(&current, &latest)?;
                serde_json::to_value(receipt_response).map_err(|_| TransportError::SessionFenced)
            }
            _ => Err(TransportError::SessionFenced),
        }
    }

    /// Non-Windows builds have no composed production Kernel store gateway.
    #[cfg(not(windows))]
    pub(crate) async fn instrument_registry_read_operation(
        &self,
        _session: &Session,
        _identity: &RequestIdentity,
        _payload: Value,
    ) -> Result<Value, TransportError> {
        Err(TransportError::SessionFenced)
    }
}

#[cfg(any(windows, test))]
fn validate_registry_read_request(
    route_request: &InstrumentRegistryReadRequest,
    authenticated_fence: &eliot_contracts::StateFence,
) -> Result<(), StoreError> {
    let request = &route_request.request;
    request.validate()?;
    if request.consistency != ReadConsistency::ExactFence
        || request.state_fence != *authenticated_fence
    {
        return Err(StoreError::FenceMismatch);
    }
    match request.operation {
        NamedReadOperation::GetInstrumentRegistryState
            if request.scope_id.as_ref() == Some(&route_request.scope_id)
                && request.parameters.is_empty() =>
        {
            Ok(())
        }
        NamedReadOperation::ResolveWriteReceipt
            if request.scope_id.is_none()
                && request.parameters.len() == 1
                && request
                    .parameters
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .is_some_and(|operation_id| {
                        !operation_id.trim().is_empty()
                            && !operation_id.chars().any(char::is_control)
                    }) =>
        {
            Ok(())
        }
        _ => Err(StoreError::InvalidField {
            field: "instrument_registry.read.request",
            reason: "only exact-fence registry state and current registration receipt reads are admitted",
        }),
    }
}

#[cfg(windows)]
async fn read_current_registry(
    gateway: &eliot_kernel_service::KernelStoreGateway,
    scope_id: &ScopeId,
    state_fence: &eliot_contracts::StateFence,
    identity: &RequestIdentity,
) -> Result<CurrentRegistryOwner, TransportError> {
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetInstrumentRegistryState,
        scope_id: Some(scope_id.clone()),
        consistency: ReadConsistency::ExactFence,
        state_fence: state_fence.clone(),
        parameters: Default::default(),
    };
    let response = gateway
        .execute_named_with_error(request)
        .await
        .map_err(|_| TransportError::SessionFenced)?;
    validate_registry_response(&response, scope_id, identity)?;
    let payload = &response.payload;
    Ok(CurrentRegistryOwner {
        operation_id: payload
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or(TransportError::SessionFenced)?
            .to_owned(),
        canonical_request_hash: payload
            .get("canonical_request_hash")
            .and_then(Value::as_str)
            .ok_or(TransportError::SessionFenced)?
            .to_owned(),
        task_id: payload
            .get("task_id")
            .and_then(Value::as_str)
            .ok_or(TransportError::SessionFenced)?
            .to_owned(),
        readback: response.clone(),
    })
}

#[cfg(windows)]
fn require_same_current_registration(
    before: &CurrentRegistryOwner,
    after: &CurrentRegistryOwner,
) -> Result<(), TransportError> {
    if before.operation_id != after.operation_id
        || before.canonical_request_hash != after.canonical_request_hash
        || before.task_id != after.task_id
        || before.readback.payload != after.readback.payload
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_registry_response(
    response: &NamedReadResponse,
    scope_id: &ScopeId,
    identity: &RequestIdentity,
) -> Result<(), TransportError> {
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    let payload = &response.payload;
    let task_id = identity
        .request
        .metadata
        .task_id
        .as_ref()
        .map(ToString::to_string);
    let row_fence: Option<eliot_contracts::StateFence> = payload
        .get("state_fence")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    if response.operation != NamedReadOperation::GetInstrumentRegistryState
        || response.state_fence != identity.request.state_fence
        || payload.get("scope_id").and_then(Value::as_str) != Some(scope_id.as_str())
        || payload.get("task_id").and_then(Value::as_str) != task_id.as_deref()
        || row_fence.as_ref() != Some(&identity.request.state_fence)
        || payload
            .get("snapshot_json")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || payload
            .get("registration_authority_json")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || payload
            .get("revision")
            .and_then(Value::as_u64)
            .is_none_or(|revision| revision == 0)
        || payload
            .get("operation_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || payload
            .get("canonical_request_hash")
            .and_then(Value::as_str)
            .is_none_or(|digest| !valid_digest(digest))
    {
        return Err(TransportError::SessionFenced);
    }
    let key = RevisionKey::new(format!("scope:{}", scope_id.as_str()))
        .map_err(|_| TransportError::SessionFenced)?;
    if !response
        .revision_heads
        .iter()
        .any(|head| head.key == key && head.state_fence == response.state_fence)
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

#[cfg(windows)]
async fn resolve_current_registration_receipt(
    gateway: &eliot_kernel_service::KernelStoreGateway,
    scope_id: &ScopeId,
    state_fence: &eliot_contracts::StateFence,
    identity: &RequestIdentity,
    current: &CurrentRegistryOwner,
) -> Result<WriteReceipt, TransportError> {
    let request = NamedReadRequest {
        operation: NamedReadOperation::ResolveWriteReceipt,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence: state_fence.clone(),
        parameters: std::collections::BTreeMap::from([(
            "operation_id".to_owned(),
            json!(current.operation_id),
        )]),
    };
    let response = gateway
        .execute_named_with_error(request)
        .await
        .map_err(|_| TransportError::SessionFenced)?;
    validate_receipt_response(&response, scope_id, identity, current)?;
    serde_json::from_value::<Option<WriteReceipt>>(response.payload)
        .map_err(|_| TransportError::SessionFenced)?
        .ok_or(TransportError::SessionFenced)
}

#[cfg(windows)]
fn validate_receipt_response(
    response: &NamedReadResponse,
    scope_id: &ScopeId,
    identity: &RequestIdentity,
    current: &CurrentRegistryOwner,
) -> Result<(), TransportError> {
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if response.operation != NamedReadOperation::ResolveWriteReceipt
        || response.state_fence != identity.request.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    let receipt: Option<WriteReceipt> = serde_json::from_value(response.payload.clone())
        .map_err(|_| TransportError::SessionFenced)?;
    let receipt = receipt.ok_or(TransportError::SessionFenced)?;
    eliot_store_api::validate_instrument_registry_registration_readback(
        &current.readback,
        &receipt,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    receipt
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    let envelope = receipt
        .require_reconciliation_envelope()
        .map_err(|_| TransportError::SessionFenced)?;
    let expected_task = identity
        .request
        .metadata
        .task_id
        .as_ref()
        .map(ToString::to_string);
    let registration_metadata = &envelope.core.request.metadata;
    let [scope_delta] = receipt.revision_before_after.as_slice() else {
        return Err(TransportError::SessionFenced);
    };
    let expected_key = RevisionKey::new(format!("scope:{}", scope_id.as_str()))
        .map_err(|_| TransportError::SessionFenced)?;
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.commit_id.is_none()
        || receipt.transition_class != TransitionClass::InstrumentRegistry
        || receipt.operation_id.as_str() != current.operation_id
        || receipt.canonical_request_hash != current.canonical_request_hash
        || receipt.state_fence != identity.request.state_fence
        || scope_delta.key != expected_key
        || scope_delta.after <= scope_delta.before
        || !original_registration_binding_matches(
            &registration_metadata.request_id,
            registration_metadata
                .task_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            &registration_metadata.state_fence,
            envelope.core.work_scope.scope_id.as_str(),
            &registration_metadata.product_id,
            &envelope.core.work_scope.product_id,
            &envelope.core.operation.request_id,
            envelope.core.operation.operation_id.as_str(),
            &envelope.core.operation.state_fence,
            current.operation_id.as_str(),
            expected_task.as_deref().unwrap_or_default(),
            scope_id,
            &identity.request.state_fence,
        )
        || envelope.core.request.state_fence != receipt.state_fence
        || envelope.core.work_scope.state_fence != receipt.state_fence
        || envelope.core.operation.state_fence != receipt.state_fence
        || envelope
            .core
            .task
            .as_ref()
            .map(|task| task.task_id.to_string())
            != expected_task
        || current.task_id != expected_task.unwrap_or_default()
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn original_registration_binding_matches(
    registration_request_id: &eliot_contracts::RequestId,
    registration_task_id: Option<&str>,
    registration_fence: &eliot_contracts::StateFence,
    registration_scope_id: &str,
    registration_product_id: &eliot_contracts::ProductId,
    work_scope_product_id: &eliot_contracts::ProductId,
    operation_request_id: &eliot_contracts::RequestId,
    operation_id: &str,
    operation_fence: &eliot_contracts::StateFence,
    current_operation_id: &str,
    current_task_id: &str,
    fixed_scope_id: &ScopeId,
    current_fence: &eliot_contracts::StateFence,
) -> bool {
    registration_task_id == Some(current_task_id)
        && registration_fence == current_fence
        && registration_scope_id == fixed_scope_id.as_str()
        && registration_product_id == work_scope_product_id
        && operation_request_id == registration_request_id
        && operation_id == current_operation_id
        && operation_fence == current_fence
}

#[cfg(windows)]
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use std::num::NonZeroU64;

    fn fence() -> eliot_contracts::StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("registry route lineage"),
                NonZeroU64::new(1).expect("registry route epoch"),
            )
            .expect("registry route fence"),
            ResourceGeneration::genesis(),
        )
    }

    fn read(scope_id: &str) -> InstrumentRegistryReadRequest {
        let scope = ScopeId::new(scope_id).expect("registry route scope");
        InstrumentRegistryReadRequest {
            scope_id: scope.clone(),
            request: NamedReadRequest {
                operation: NamedReadOperation::GetInstrumentRegistryState,
                scope_id: Some(scope),
                consistency: ReadConsistency::ExactFence,
                state_fence: fence(),
                parameters: Default::default(),
            },
        }
    }

    #[test]
    fn registry_read_route_accepts_exact_fixed_scope_request() {
        let request = read("scope:instrument-registry");
        assert_eq!(validate_registry_read_request(&request, &fence()), Ok(()));
    }

    #[test]
    fn registry_read_route_refuses_scope_substitution() {
        let mut request = read("scope:instrument-registry");
        request.request.scope_id = Some(ScopeId::new("scope:foreign").expect("foreign scope"));
        assert!(validate_registry_read_request(&request, &fence()).is_err());
    }

    #[test]
    fn registry_read_route_accepts_original_registration_with_distinct_read_request_id() {
        use eliot_contracts::{ProductId, RequestId, TaskId};

        let fence = fence();
        let scope = ScopeId::new("scope:instrument-registry").expect("registry scope");
        let registration_request =
            RequestId::new("request:registry-registration").expect("original registration request");
        let current_read_request =
            RequestId::new("request:current-registry-read").expect("current read request");
        let product = ProductId::new("registry-product").expect("registration product");
        let task = TaskId::new("task:registry-current").expect("current task");

        assert_ne!(registration_request, current_read_request);
        assert!(original_registration_binding_matches(
            &registration_request,
            Some(task.as_str()),
            &fence,
            scope.as_str(),
            &product,
            &product,
            &registration_request,
            "operation:registry-registration",
            &fence,
            "operation:registry-registration",
            task.as_str(),
            &scope,
            &fence,
        ));
    }

    #[test]
    fn registry_read_route_refuses_foreign_task_scope_or_operation_binding() {
        use eliot_contracts::{ProductId, RequestId, TaskId};

        let fence = fence();
        let scope = ScopeId::new("scope:instrument-registry").expect("registry scope");
        let foreign_scope = ScopeId::new("scope:foreign").expect("foreign scope");
        let registration_request =
            RequestId::new("request:registry-registration").expect("original registration request");
        let product = ProductId::new("registry-product").expect("registration product");
        let task = TaskId::new("task:registry-current").expect("current task");
        let foreign_task = TaskId::new("task:foreign").expect("foreign task");
        let call_matches = |task_id: &str, scope_id: &ScopeId, operation_id: &str| {
            original_registration_binding_matches(
                &registration_request,
                Some(task.as_str()),
                &fence,
                scope_id.as_str(),
                &product,
                &product,
                &registration_request,
                operation_id,
                &fence,
                "operation:registry-registration",
                task_id,
                &scope,
                &fence,
            )
        };

        assert!(!call_matches(
            foreign_task.as_str(),
            &scope,
            "operation:registry-registration"
        ));
        assert!(!call_matches(
            task.as_str(),
            &foreign_scope,
            "operation:registry-registration"
        ));
        assert!(!call_matches(task.as_str(), &scope, "operation:foreign"));
    }
}
