//! Authenticated, identity-retaining adapter for the pre-launch Instrument
//! Registry admission owner operation.
//!
//! The runner supplies a value produced by its real profile/supply-chain
//! resolver. The registry mutation is a separate Governor-owned operation;
//! this adapter returns only that original retained receipt plus a fresh
//! same-fence named read under the selected-source RequestIdentity.

use eliot_protocol::RequestIdentity;
use eliot_instrument_runner::{AdmissionSubmission, AdmissionSubmissionProofPort, RunnerError};
use eliot_store_api::{
    CanonicalReadClient, NamedReadRequest, NamedReadResponse, RevisionHead, RevisionKey,
    StoreError, WriteReceipt,
};

use crate::DaemonKernelClient;

/// The proof adapter keeps the current selected-source identity for its fresh
/// exact-fence read and borrows the original one-time registration proof from
/// the daemon's profile-registry owner.
pub(crate) struct KernelAdmissionSubmissionProofPort {
    kernel: std::sync::Arc<DaemonKernelClient>,
    composition: std::sync::Arc<tokio::sync::Mutex<crate::DaemonComposition>>,
    identity: RequestIdentity,
}

impl KernelAdmissionSubmissionProofPort {
    pub(crate) fn new(
        kernel: std::sync::Arc<DaemonKernelClient>,
        composition: std::sync::Arc<tokio::sync::Mutex<crate::DaemonComposition>>,
        identity: RequestIdentity,
    ) -> Self {
        Self {
            kernel,
            composition,
            identity,
        }
    }
}

impl AdmissionSubmissionProofPort for KernelAdmissionSubmissionProofPort {
    fn read_admission<'a>(
        &'a self,
        submission: &'a AdmissionSubmission,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(WriteReceipt, NamedReadResponse), RunnerError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let proof = {
                let composition = self.composition.lock().await;
                composition
                    .instrument_registry_registration_proof()
                    .cloned()
                    .ok_or_else(|| RunnerError::Binding(
                        "original Instrument Registry registration proof is unavailable".to_owned(),
                    ))?
            };
            if proof.snapshot_json() != submission.snapshot_json() {
                return Err(RunnerError::Binding(
                    "selected profile registry differs from the original registration receipt".to_owned(),
                ));
            }
            let receipt = proof.receipt().clone();
            if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
                || receipt.commit_id.is_none()
                || receipt.state_fence != self.identity.request.metadata.state_fence
            {
                return Err(RunnerError::Binding(
                    "original registration receipt is not committed at the selected request fence".to_owned(),
                ));
            }
            let read = IdentityBoundCanonicalReadClient::new(
                &self.kernel,
                self.identity.clone(),
            );
            let request = NamedReadRequest {
                operation: eliot_store_api::NamedReadOperation::GetInstrumentRegistryState,
                scope_id: None,
                consistency: eliot_store_api::ReadConsistency::ExactFence,
                state_fence: self.identity.request.metadata.state_fence.clone(),
                parameters: std::collections::BTreeMap::new(),
            };
            let readback = read
                .execute_named(request)
                .await
                .map_err(|error| RunnerError::Binding(error.to_string()))?;
            readback
                .validate()
                .map_err(|error| RunnerError::Binding(error.to_string()))?;
            if readback.operation != eliot_store_api::NamedReadOperation::GetInstrumentRegistryState
                || readback.state_fence != receipt.state_fence
                || readback
                    .payload
                    .get("state_fence")
                    .and_then(|value| serde_json::from_value::<eliot_contracts::StateFence>(value.clone()).ok())
                    .as_ref()
                    != Some(&receipt.state_fence)
                || readback
                    .payload
                    .get("snapshot_json")
                    .and_then(serde_json::Value::as_str)
                    != Some(submission.snapshot_json())
            {
                return Err(RunnerError::Binding(
                    "current registry named read differs from the original registration bytes and fence".to_owned(),
                ));
            }
            Ok((receipt, readback))
        })
    }
}

/// Read capability retained for one original admitted launch identity.
/// Kernel performs the authenticated dispatch and validates the owner result;
/// this adapter additionally requires the exact RequestIdentity fence.
pub(crate) struct IdentityBoundCanonicalReadClient<'a> {
    kernel: &'a DaemonKernelClient,
    identity: RequestIdentity,
}

impl<'a> IdentityBoundCanonicalReadClient<'a> {
    pub(crate) fn new(kernel: &'a DaemonKernelClient, identity: RequestIdentity) -> Self {
        Self { kernel, identity }
    }
}

impl CanonicalReadClient for IdentityBoundCanonicalReadClient<'_> {
    async fn revision_heads(
        &self,
        _keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        // This closed named-read port deliberately supports only the registry
        // readback required by this operation; an unrelated read must use its
        // owning authenticated port rather than widening this capability.
        Err(StoreError::Unavailable)
    }

    async fn execute_named(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        request.validate()?;
        if request.state_fence != self.identity.request.metadata.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        let value = self
            .kernel
            .transact_async_with_identity(
                "store_named",
                serde_json::json!({ "request": request }),
                self.identity.clone(),
            )
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let body = crate::kind_value(&value, "store_named")
            .map_err(|_| StoreError::Unavailable)?;
        let response: NamedReadResponse = serde_json::from_value(body)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        response.validate()?;
        if response.operation != request.operation
            || response.state_fence != self.identity.request.metadata.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        Ok(response)
    }
}
