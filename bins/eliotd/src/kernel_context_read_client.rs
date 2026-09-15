//! Kernel-backed read-only context client for the daemon (T11.1).
//!
//! Architecture: A2.3 (contract -> ports -> adapters layering), A13.2
//! (Kernel failure-domain ownership).
//! Implementation: T11.1 one real cognitive named read through the daemon.
//!
//! This module owns only the read-only [`CanonicalReadClient`] adapter over
//! the already-authenticated [`DaemonKernelClient`]: a fresh
//! operation/scope/fence-bound capability per call with exact
//! [`NamedReadResponse`] validation. It performs no consistency algorithm of
//! its own — callers compose it with the Governor `ReadService` (which owns
//! the stable/exact re-read and churn detection). It owns no transport
//! beyond the retained client, no Store, no semantic authority, and no write
//! capability: only [`NamedReadOperation::GetEvidencePack`] passes
//! [`CanonicalReadClient::execute_named`]; every other named operation fails
//! closed as [`StoreError::UnknownOperation`] before any transport.
//!
//! Forbidden authority: no raw query strings (impossible by construction —
//! only the closed [`NamedReadOperation`] crosses), no second consistency
//! implementation, no fake full [`CanonicalStoreClient`] with
//! always-unavailable writes, no catalogue/parameter widening.

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_governor::{KernelGenerationSnapshotProvider, KernelPortError};
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    RevisionHead, RevisionKey, StoreError,
};

use super::DaemonKernelClient;

/// Read-only Kernel-backed adapter implementing [`CanonicalReadClient`].
///
/// Clones only the retained [`Arc`] — no new session, no new handshake, no
/// thread. Every call binds the exact admitted fence observed from the
/// retained snapshot at call time; a request carrying another fence fails
/// closed before transport, and a response substituting the operation or
/// fence fails closed after transport.
pub struct KernelContextReadClient {
    kernel: Arc<DaemonKernelClient>,
}

impl KernelContextReadClient {
    /// Wraps an already-connected authenticated Kernel client.
    #[must_use]
    pub const fn new(kernel: Arc<DaemonKernelClient>) -> Self {
        Self { kernel }
    }

    /// Borrows the retained Kernel client (for composition-root wiring).
    #[must_use]
    pub const fn kernel(&self) -> &Arc<DaemonKernelClient> {
        &self.kernel
    }

    /// Checks the T11.1 execute capability before any transport is touched:
    /// `GetEvidencePack` only, scope-bound, structurally valid.
    fn check_execute_capability(request: &NamedReadRequest) -> Result<(), StoreError> {
        if request.operation != NamedReadOperation::GetEvidencePack {
            return Err(StoreError::UnknownOperation);
        }
        if request.scope_id.is_none() {
            return Err(StoreError::InvalidField {
                field: "scope_id",
                reason: "GetEvidencePack requires an exact scope",
            });
        }
        request.validate()?;
        Ok(())
    }

    /// Checks an execute response against the exact request it answers:
    /// structural validity plus operation identity and fence equality.
    fn check_execute_response(
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<(), StoreError> {
        response.validate()?;
        if response.operation != request.operation {
            return Err(StoreError::UnknownOperation);
        }
        if response.state_fence != request.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }

    /// Maps a Kernel boundary failure to the store-neutral [`StoreError`].
    ///
    /// Contract failures (malformed request, kind mismatch, decode failure,
    /// operation/fence substitution) serialize as [`StoreError::Serialization`]
    /// except the two exact mismatches the capability checks name directly
    /// (`UnknownOperation` / `FenceMismatch`, already raised before mapping).
    /// A non-admitted or faulted route is [`StoreError::Unavailable`]: never
    /// a successful view, never a silent retry.
    fn map_kernel_error(error: KernelPortError) -> StoreError {
        match error {
            KernelPortError::Contract(reason) | KernelPortError::Unknown(reason) => {
                StoreError::Serialization(reason)
            }
            KernelPortError::NotAdmitted(_) => StoreError::Unavailable,
        }
    }
}

#[allow(async_fn_in_trait)]
impl CanonicalReadClient for KernelContextReadClient {
    /// Reads revision heads by stable key through the Kernel named-read route.
    ///
    /// An empty key set returns empty without touching transport (mirroring
    /// the adapter reference behavior). Otherwise a fence-bound
    /// `GetRevisionHeads` request (no scope, no parameters — the only
    /// catalogue-activated head read) travels the single `store_named`
    /// transport, and the result is projected to the requested keys in
    /// request order (absent keys are omitted, mirroring the memory
    /// reference `revision_heads_sync`). Heads validate before return; a
    /// substituted fence fails closed.
    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let fence = self.kernel.snapshot().state_fence();
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetRevisionHeads,
            scope_id: None,
            consistency: ReadConsistency::ExactFence,
            state_fence: fence,
            parameters: BTreeMap::new(),
        };
        let response = self
            .kernel
            .store_named_async(request)
            .await
            .map_err(Self::map_kernel_error)?;
        // The transport already validated operation/fence identity; keep the
        // projection exact: every returned head validates, carries the
        // admitted fence, and only requested keys cross back in request order.
        response.validate()?;
        let mut by_key: BTreeMap<String, RevisionHead> = BTreeMap::new();
        for head in response.revision_heads {
            head.validate()?;
            if head.state_fence != response.state_fence {
                return Err(StoreError::FenceMismatch);
            }
            by_key.insert(head.key.as_str().to_owned(), head);
        }
        Ok(keys
            .iter()
            .filter_map(|key| by_key.get(key.as_str()).cloned())
            .collect())
    }

    /// Executes one closed `GetEvidencePack` read through the Kernel route.
    ///
    /// Fresh capability per call: the operation must be `GetEvidencePack`,
    /// the scope must be present, the request must validate, and its fence
    /// must equal the currently admitted snapshot fence — otherwise this
    /// fails closed before transport. The response validates exactly and
    /// must echo the requested operation and fence. Consistency (stable /
    /// exact re-read, churn detection) stays with the Governor `ReadService`
    /// caller; this method performs no second implementation.
    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        Self::check_execute_capability(&query)?;
        let admitted = self.kernel.snapshot().state_fence();
        if query.state_fence != admitted {
            return Err(StoreError::FenceMismatch);
        }
        let response = self
            .kernel
            .store_named_async(query.clone())
            .await
            .map_err(Self::map_kernel_error)?;
        Self::check_execute_response(&query, &response)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_store_api::ScopeId;
    use serde_json::json;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
        Ok(EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A)?,
            NonZeroU64::new(sequence).ok_or("non-zero test sequence")?,
        )?)
    }

    fn test_fence(generation: u64) -> Result<StateFence, Box<dyn std::error::Error>> {
        Ok(StateFence::new(
            test_epoch(1)?,
            ResourceGeneration::new(generation)?,
        ))
    }

    fn evidence_request(
        fence: &StateFence,
    ) -> Result<NamedReadRequest, Box<dyn std::error::Error>> {
        let mut parameters = BTreeMap::new();
        parameters.insert("subject".to_owned(), json!("observation:exact-subject-1"));
        parameters.insert("max_records".to_owned(), json!("8"));
        Ok(NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(ScopeId::new("governor")?),
            consistency: ReadConsistency::Eventual,
            state_fence: fence.clone(),
            parameters,
        })
    }

    fn evidence_response(
        request: &NamedReadRequest,
        payload: serde_json::Value,
    ) -> NamedReadResponse {
        NamedReadResponse {
            operation: request.operation,
            state_fence: request.state_fence.clone(),
            revision_heads: Vec::new(),
            payload,
        }
    }

    #[test]
    fn execute_capability_rejects_non_evidence_operations_before_transport()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence(1)?;
        let mut request = evidence_request(&fence)?;
        request.operation = NamedReadOperation::GetTaskState;
        assert!(matches!(
            KernelContextReadClient::check_execute_capability(&request),
            Err(StoreError::UnknownOperation)
        ));

        let mut receipt = evidence_request(&fence)?;
        receipt.operation = NamedReadOperation::ResolveWriteReceipt;
        assert!(matches!(
            KernelContextReadClient::check_execute_capability(&receipt),
            Err(StoreError::UnknownOperation)
        ));
        Ok(())
    }

    #[test]
    fn execute_capability_requires_an_exact_scope() -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence(1)?;
        let mut request = evidence_request(&fence)?;
        request.scope_id = None;
        assert!(matches!(
            KernelContextReadClient::check_execute_capability(&request),
            Err(StoreError::InvalidField {
                field: "scope_id",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn execute_response_rejects_operation_and_fence_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence(1)?;
        let request = evidence_request(&fence)?;
        let payload = json!({"version": 1, "records": []});

        let mut wrong_operation = evidence_response(&request, payload.clone());
        wrong_operation.operation = NamedReadOperation::GetRevisionHeads;
        assert!(matches!(
            KernelContextReadClient::check_execute_response(&request, &wrong_operation),
            Err(StoreError::UnknownOperation)
        ));

        let mut wrong_fence = evidence_response(&request, payload);
        wrong_fence.state_fence = test_fence(2)?;
        assert!(matches!(
            KernelContextReadClient::check_execute_response(&request, &wrong_fence),
            Err(StoreError::FenceMismatch)
        ));
        Ok(())
    }

    #[test]
    fn execute_response_accepts_an_exact_evidence_pack() -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence(1)?;
        let request = evidence_request(&fence)?;
        let response = evidence_response(&request, json!({"version": 1, "records": []}));
        KernelContextReadClient::check_execute_response(&request, &response)?;
        Ok(())
    }

    #[test]
    fn kernel_boundary_maps_to_fail_closed_store_errors() {
        assert!(matches!(
            KernelContextReadClient::map_kernel_error(KernelPortError::NotAdmitted(
                "route fenced".to_owned()
            )),
            StoreError::Unavailable
        ));
        assert!(matches!(
            KernelContextReadClient::map_kernel_error(KernelPortError::Contract(
                "kind mismatch".to_owned()
            )),
            StoreError::Serialization(_)
        ));
        assert!(matches!(
            KernelContextReadClient::map_kernel_error(KernelPortError::Unknown(
                "ambiguous outcome".to_owned()
            )),
            StoreError::Serialization(_)
        ));
    }
}
