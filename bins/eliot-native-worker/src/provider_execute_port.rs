//! Authenticated retained-provider reads at the normal native-worker Execute
//! boundary.
//!
//! This port never promotes `WorkerRequest::payload` to provider material. It
//! resolves the original claim-scoped reference from Kernel and re-reads the
//! immutable material and separately sealed child-process admission through
//! the same authenticated session. Launch remains refused until the distinct
//! prompt-retention, Claude descriptor/request/credential, and process-owner
//! producers return their typed current owner records.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use eliot_agent_claude::CLAUDE_SIDECAR_ROUTE_CLASS;
use eliot_native_worker_core::{
    NativeWorkerClaim, NativeWorkerExecutePort, NativeWorkerRetainedOperationOutcome,
    WorkerError, WorkerFrame, WorkerRequest,
};
use eliot_process::{
    ActionLeaseRef, FencingToken, Generation, ProcessExecutionAdmissionRequest, ProcessRequest,
};
use eliot_protocol::{
    NativeWorkerProviderProcessIdentityV1, NativeWorkerProviderProcessReadbackV1,
};

use crate::{
    NativeWorkerDispatchAuthority, NativeWorkerDispatchAuthorityRouter, NativeWorkerError,
    SharedKernelTransport, ValidatedDispatchGrant, dispatch_now_unix_ms,
};
use eliot_process_executor::WindowsProcessExecutor;

/// Production Execute hook bound to the one admitted claim and authenticated
/// Kernel session already used by lifecycle, replay, and checkpoint ports.
pub struct AuthenticatedRetainedProviderExecutePort {
    transport: SharedKernelTransport,
    claim: NativeWorkerClaim,
    process_executor: Arc<WindowsProcessExecutor>,
    authority_router: Arc<NativeWorkerDispatchAuthorityRouter>,
}

/// Rebuilds one original provider `ProcessRequest` from the independently
/// Kernel-read inert admission projection and grant. The supervisor request,
/// claim operation, and launch nonce are never substituted for the separate
/// provider-process identity.
pub fn issue_provider_process_request(
    claim: &NativeWorkerClaim,
    provider_process: &NativeWorkerProviderProcessIdentityV1,
    readback: &NativeWorkerProviderProcessReadbackV1,
    now_unix_ms: u64,
) -> Result<(ProcessRequest, Arc<NativeWorkerDispatchAuthority>), NativeWorkerError> {
    readback
        .validate_for(provider_process)
        .map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "provider-process owner readback failed validation: {error}"
            ))
        })?;
    if now_unix_ms == 0
        || now_unix_ms < readback.grant.issued_at_unix_ms
        || now_unix_ms >= readback.grant.expires_at_unix_ms
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "provider-process grant is outside its owner-issued freshness window".to_owned(),
        ));
    }
    let provider_launch_nonce = readback.grant.fence_nonce.as_str();
    if provider_launch_nonce.trim().is_empty()
        || provider_process.provider_operation_id == claim.operation_id.as_str()
        || readback.grant.authority_epoch != claim.authority_epoch
        || readback.grant.fence_generation != claim.worker_generation
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "provider-process identity is foreign to the exact admitted claim".to_owned(),
        ));
    }

    let admission: ProcessExecutionAdmissionRequest =
        serde_json::from_str(&readback.admission_request_json).map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "provider-process admission projection is not the closed inert request: {error}"
            ))
        })?;
    admission.validate().map_err(|error| {
        NativeWorkerError::KernelAdmissionRequired(format!(
            "provider-process admission projection is invalid: {error}"
        ))
    })?;
    let grant = &readback.grant;
    let fence = FencingToken::new(
        grant.authority_epoch.clone(),
        Generation::new(grant.fence_generation).map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "provider-process grant generation is invalid: {error}"
            ))
        })?,
        grant.fence_nonce.clone(),
    )
    .map_err(|error| {
        NativeWorkerError::KernelAdmissionRequired(format!(
            "provider-process grant fence is invalid: {error}"
        ))
    })?;
    let lease = ActionLeaseRef::new(grant.idempotency_key.clone()).map_err(|error| {
        NativeWorkerError::KernelAdmissionRequired(format!(
            "provider-process grant lease is invalid: {error}"
        ))
    })?;
    if admission.state_fence() != &fence
        || admission.action_lease_ref() != &lease
        || admission.intent().operation_id().as_str() != provider_process.provider_operation_id
        || admission.intent().generation().get() != claim.worker_generation
        || admission.intent().executable_sha256() != provider_process.provider_executable_digest
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "provider-process admission differs from the exact original process identity or grant"
                .to_owned(),
        ));
    }

    let validated_grant = ValidatedDispatchGrant::new(
        fence,
        lease,
        grant.grant_digest.clone(),
        grant.issued_at_unix_ms,
        grant.expires_at_unix_ms,
    )?;
    let epoch_json = serde_json::to_value(&grant.authority_epoch)?;
    let authority = Arc::new(NativeWorkerDispatchAuthority::new(
        claim.claim_id.as_str(),
        provider_process.provider_operation_id.as_str(),
        claim.worker_generation,
        &epoch_json,
        provider_launch_nonce,
    )?);
    let request = authority.issue(
        admission.intent(),
        &validated_grant,
        provider_launch_nonce,
        now_unix_ms,
    )?;
    request.validate().map_err(|error| {
        NativeWorkerError::KernelAdmissionRequired(format!(
            "locally issued provider process request is invalid: {error}"
        ))
    })?;
    if request.operation_id().as_str() != provider_process.provider_operation_id
        || request.invocation_digest() != provider_process.provider_process_invocation_digest
        || request.executable_sha256() != provider_process.provider_executable_digest
        || request.generation().get() != claim.worker_generation
        || request.fence() != admission.state_fence()
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "locally reconstructed ProcessRequest does not match the independent provider-process identity"
                .to_owned(),
        ));
    }
    Ok((request, authority))
}

impl AuthenticatedRetainedProviderExecutePort {
    /// Binds the real Execute hook to an exact admitted claim and the existing
    /// shared Kernel transport. No provider operation identity is supplied by
    /// the caller.
    #[must_use]
    pub fn new(
        transport: SharedKernelTransport,
        claim: NativeWorkerClaim,
        process_executor: Arc<WindowsProcessExecutor>,
        authority_router: Arc<NativeWorkerDispatchAuthorityRouter>,
    ) -> Self {
        Self {
            transport,
            claim,
            process_executor,
            authority_router,
        }
    }

    async fn execute_admitted(
        &self,
        frame: &WorkerFrame,
        request: &WorkerRequest,
    ) -> Result<Option<NativeWorkerRetainedOperationOutcome>, WorkerError> {
        request_attempt_matches(
            self.claim.attempt_id.as_str(),
            request.attempt_id.as_str(),
        )?;
        require_claude_route(&self.claim.route_class)?;
        if frame.state_fence != self.claim.state_fence
            || frame.authority_epoch != self.claim.authority_epoch
            || frame.producer_generation != self.claim.worker_generation
            || frame.deadline_unix_ms != self.claim.deadline_unix_ms
        {
            return Err(WorkerError::AdmissionMismatch(
                "provider_execute_frame_claim_identity",
            ));
        }

        // Each call performs a fresh owner read against the current Ready
        // claim. The exact original ref and child operation returned by
        // resolve are the only keys accepted by subsequent reads.
        let (reference, provider_process) = self
            .transport
            .resolve_retained_provider_material()
            .map_err(|_| {
                WorkerError::AdmissionRejected(
                    "Kernel did not provide a current retained provider material identity".to_owned(),
                )
            })?;
        let _material = self
            .transport
            .read_retained_provider_material(&reference, &provider_process)
            .map_err(|_| {
                WorkerError::AdmissionRejected(
                    "Kernel did not provide the exact retained provider material".to_owned(),
                )
            })?;
        let process_admission = self
            .transport
            .read_provider_process_admission(&reference, &provider_process)
            .map_err(|_| {
                WorkerError::AdmissionRejected(
                    "Kernel did not provide the separately sealed provider-process admission".to_owned(),
                )
            })?;

        // The same Kernel-issued inert admission/grant and separate provider
        // identity are reconstructed through the existing native dispatch
        // derivation. This only produces the in-memory sealed request; the
        // provider sidecar remains blocked below until its privacy, adapter,
        // credential, replay and usage owners all return exact readbacks.
        let now = crate::dispatch_now_unix_ms().map_err(|error| {
            WorkerError::AdmissionRejected(format!(
                "provider process issue time is unavailable: {error}"
            ))
        })?;
        let (provider_request, provider_authority) = issue_provider_process_request(
            &self.claim,
            &provider_process,
            &process_admission,
            now,
        )
        .map_err(|error| WorkerError::AdmissionRejected(error.to_string()))?;
        self.authority_router
            .retain_provider_authority(provider_process.clone(), provider_authority)
            .map_err(|error| WorkerError::AdmissionRejected(error.to_string()))?;

        match self
            .process_executor
            .inspect(provider_request.operation_id().clone())
            .await
        {
            Ok(_) => {
                return Err(WorkerError::AdmissionRejected(
                    "the original provider process is already retained and must be reconciled under its operation".to_owned(),
                ));
            }
            Err(eliot_process::ProcessExecutionError::NotFound) => {}
            Err(error) => {
                return Err(WorkerError::AdmissionRejected(format!(
                    "same-operation provider process inspection did not establish a safe start: {error}"
                )));
            }
        }

        // The current owner APIs do not yet publish/validate the typed
        // prompt-retention receipt, pinned Claude descriptor/configuration,
        // exact launch plan, credential ref, prior idempotency/gate record,
        // or Governor consumption issuer. Reading immutable bytes alone does
        // not authorize disclosure or process effect, so the normal Execute
        // path stops here until those independent owner records are present.
        Err(WorkerError::AdmissionRejected(
            "Claude provider execution is refused before effect because required owner-issued retention and adapter inputs are unavailable".to_owned(),
        ))
    }
}

impl NativeWorkerExecutePort for AuthenticatedRetainedProviderExecutePort {
    fn execute<'a>(
        &'a self,
        frame: &'a WorkerFrame,
        request: &'a WorkerRequest,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<Option<NativeWorkerRetainedOperationOutcome>, WorkerError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.execute_admitted(frame, request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #22 Work/Acceptance refusal: a provider Execute frame for a different
    /// attempt is stopped before any authenticated material lookup.
    #[test]
    fn execute_port_refuses_foreign_attempt_before_owner_reads() {
        // This identity mismatch is rejected before the port needs a live
        // Kernel session. Constructing a fully admitted claim is covered by
        // the Kernel-client claim fixture; the test below exercises the
        // isolated identity predicate used at the entry boundary.
        assert!(request_attempt_matches("attempt:expected", "attempt:foreign").is_err());
    }

    /// #22 Work/Acceptance positive: exact request attempt equality is the
    /// first necessary join before the Kernel owner is consulted.
    #[test]
    fn execute_port_accepts_exact_attempt_join() {
        assert!(request_attempt_matches("attempt:exact", "attempt:exact").is_ok());
    }

}

fn request_attempt_matches(expected: &str, presented: &str) -> Result<(), WorkerError> {
    if expected == presented {
        Ok(())
    } else {
        Err(WorkerError::AdmissionMismatch(
            "provider_execute_frame_claim_identity",
        ))
    }
}

fn require_claude_route(route_class: &str) -> Result<(), WorkerError> {
    if route_class == CLAUDE_SIDECAR_ROUTE_CLASS {
        Ok(())
    } else {
        Err(WorkerError::AdmissionRejected(
            "the admitted provider route has no execution owner in this native-worker composition"
                .to_owned(),
        ))
    }
}
