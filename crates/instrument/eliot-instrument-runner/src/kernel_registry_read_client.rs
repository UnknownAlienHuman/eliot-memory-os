//! Read-only Kernel front-door client for the canonical instrument registry.
//!
//! The caller retains the original authenticated request identity and scope.
//! The Kernel endpoint accepts only the two named reads needed to retain and
//! refresh the registry registration proof. No store write or raw query is
//! expressible through this client.

use std::sync::Arc;

use eliot_ipc::KernelClient;
use eliot_ipc::RequestIdentity;
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    RevisionHead, RevisionKey, ScopeId, StoreError, TransitionClass, WriteReceiptStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Existing Kernel Execute selector for the closed registry read endpoint.
pub const INSTRUMENT_REGISTRY_READ_OPERATION: &str = "instrument_registry.read";

/// Closed request carrier. `scope_id` is fixed by the retained client and is
/// repeated outside `NamedReadRequest` because `ResolveWriteReceipt` is a
/// global named-read operation and therefore cannot carry a Store scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRegistryReadRequest {
    pub scope_id: ScopeId,
    pub request: NamedReadRequest,
}

/// Read-only canonical store capability backed by the authenticated Kernel
/// front door and the current persisted instrument-registry row.
pub struct InstrumentRegistryReadClient {
    kernel: Arc<KernelClient>,
    identity: RequestIdentity,
    scope_id: ScopeId,
}

impl InstrumentRegistryReadClient {
    /// Retains the already-admitted registration identity and its fixed scope.
    pub fn new(
        mut kernel: KernelClient,
        identity: RequestIdentity,
        scope_id: ScopeId,
    ) -> Result<Self, StoreError> {
        identity
            .validate()
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let task_id =
            identity
                .request
                .metadata
                .task_id
                .as_ref()
                .ok_or(StoreError::InvalidField {
                    field: "request_identity.metadata.task_id",
                    reason: "instrument registry reads require the original task binding",
                })?;
        if task_id.as_str().is_empty()
            || identity.request.state_fence != identity.request.metadata.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        kernel.set_request_identity(identity.clone());
        Ok(Self {
            kernel: Arc::new(kernel),
            identity,
            scope_id,
        })
    }

    /// The immutable scope bound to every registry read from this client.
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    /// The original authenticated request identity retained by this client.
    pub fn request_identity(&self) -> &RequestIdentity {
        &self.identity
    }

    async fn execute_registry_read(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        self.validate_request(&request)?;
        let query = InstrumentRegistryReadRequest {
            scope_id: self.scope_id.clone(),
            request: request.clone(),
        };
        let payload = serde_json::to_value(query)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let response = self
            .kernel
            .transact_json_async(
                INSTRUMENT_REGISTRY_READ_OPERATION,
                payload,
                self.identity.clone(),
            )
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let response: NamedReadResponse = serde_json::from_value(response)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        response.validate()?;
        if response.operation != request.operation || response.state_fence != request.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        match request.operation {
            NamedReadOperation::GetInstrumentRegistryState => {
                self.validate_registry_payload(&response)?;
            }
            NamedReadOperation::ResolveWriteReceipt => {
                self.validate_receipt_payload(&request, &response)?;
            }
            _ => return Err(StoreError::UnknownOperation),
        }
        Ok(response)
    }

    fn validate_request(&self, request: &NamedReadRequest) -> Result<(), StoreError> {
        validate_named_read_request(&self.scope_id, &self.identity.request.state_fence, request)
    }
}

fn validate_named_read_request(
    scope_id: &ScopeId,
    authenticated_fence: &eliot_contracts::StateFence,
    request: &NamedReadRequest,
) -> Result<(), StoreError> {
    request.validate()?;
    if request.consistency != ReadConsistency::ExactFence
        || request.state_fence != *authenticated_fence
    {
        return Err(StoreError::FenceMismatch);
    }
    match request.operation {
        NamedReadOperation::GetInstrumentRegistryState
            if request.scope_id.as_ref() == Some(scope_id) && request.parameters.is_empty() =>
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
            reason: "only exact-fence registry state and its named receipt reads are admitted",
        }),
    }
}

impl InstrumentRegistryReadClient {
    fn validate_registry_payload(&self, response: &NamedReadResponse) -> Result<(), StoreError> {
        let payload = &response.payload;
        let task_id = self
            .identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(ToString::to_string);
        let row_fence = payload
            .get("state_fence")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        let row_scope = payload.get("scope_id").and_then(Value::as_str);
        let row_task = payload.get("task_id").and_then(Value::as_str);
        let operation_id = payload.get("operation_id").and_then(Value::as_str);
        let request_hash = payload
            .get("canonical_request_hash")
            .and_then(Value::as_str);
        if row_scope != Some(self.scope_id.as_str())
            || row_task != task_id.as_deref()
            || row_fence.as_ref() != Some(&self.identity.request.state_fence)
            || operation_id.is_none_or(str::is_empty)
            || request_hash.is_none_or(str::is_empty)
            || payload
                .get("revision")
                .and_then(Value::as_u64)
                .is_none_or(|revision| revision == 0)
            || payload
                .get("snapshot_json")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || payload
                .get("registration_authority_json")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(StoreError::FenceMismatch);
        }
        let expected_head = RevisionKey::new(format!("scope:{}", self.scope_id.as_str()))?;
        if !response
            .revision_heads
            .iter()
            .any(|head| head.key == expected_head && head.state_fence == response.state_fence)
        {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }

    fn validate_receipt_payload(
        &self,
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<(), StoreError> {
        let operation_id = request
            .parameters
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or(StoreError::UnknownOperation)?;
        let receipt: Option<eliot_store_api::WriteReceipt> =
            serde_json::from_value(response.payload.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let receipt = receipt.ok_or(StoreError::ReceiptNotFound)?;
        receipt.validate()?;
        let envelope = receipt.require_reconciliation_envelope()?;
        let task_id = self
            .identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(ToString::to_string);
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.commit_id.is_none()
            || receipt.transition_class != TransitionClass::InstrumentRegistry
            || receipt.operation_id.as_str() != operation_id
            || receipt.state_fence != self.identity.request.state_fence
            || envelope.core.request.metadata != self.identity.request.metadata
            || envelope.core.work_scope.scope_id.as_str() != self.scope_id.as_str()
            || envelope
                .core
                .task
                .as_ref()
                .map(|task| task.task_id.to_string())
                != task_id
            || envelope.core.operation.operation_id.as_str() != operation_id
            || envelope.core.operation.state_fence != self.identity.request.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }
}

impl CanonicalReadClient for InstrumentRegistryReadClient {
    async fn revision_heads(
        &self,
        _keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        Err(StoreError::UnknownOperation)
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        self.execute_registry_read(query).await
    }
}

/// Creates the only valid registry-state request for this client.
pub fn registry_state_request(
    scope_id: &ScopeId,
    state_fence: &eliot_contracts::StateFence,
) -> NamedReadRequest {
    NamedReadRequest {
        operation: NamedReadOperation::GetInstrumentRegistryState,
        scope_id: Some(scope_id.clone()),
        consistency: ReadConsistency::ExactFence,
        state_fence: state_fence.clone(),
        parameters: Default::default(),
    }
}

/// Creates the only valid original-receipt request; the Kernel checks that
/// the operation remains the current registration for the fixed scope.
pub fn registration_receipt_request(
    operation_id: &str,
    state_fence: &eliot_contracts::StateFence,
) -> Result<NamedReadRequest, StoreError> {
    if operation_id.trim().is_empty() || operation_id.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "operation_id",
            reason: "must identify the current registry registration",
        });
    }
    Ok(NamedReadRequest {
        operation: NamedReadOperation::ResolveWriteReceipt,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence: state_fence.clone(),
        parameters: std::collections::BTreeMap::from([(
            "operation_id".to_owned(),
            json!(operation_id),
        )]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    fn state_fence() -> eliot_contracts::StateFence {
        eliot_contracts::StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("registry read lineage"),
                NonZeroU64::new(1).expect("registry read epoch"),
            )
            .expect("registry read fence"),
            ResourceGeneration::genesis(),
        )
    }

    #[test]
    fn registry_read_client_accepts_exact_fixed_scope_read() {
        let scope = ScopeId::new("scope:instrument-registry").expect("registry scope");
        let request = registry_state_request(&scope, &state_fence());
        assert_eq!(
            validate_named_read_request(&scope, &state_fence(), &request),
            Ok(())
        );
    }

    #[test]
    fn registry_read_client_refuses_foreign_scope() {
        let scope = ScopeId::new("scope:instrument-registry").expect("registry scope");
        let foreign = ScopeId::new("scope:foreign").expect("foreign scope");
        let request = registry_state_request(&foreign, &state_fence());
        assert!(validate_named_read_request(&scope, &state_fence(), &request).is_err());
    }
}
