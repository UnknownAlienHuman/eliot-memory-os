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

use eliot_agent_claude::CLAUDE_SIDECAR_ROUTE_CLASS;
use eliot_native_worker_core::{
    NativeWorkerClaim, NativeWorkerExecutePort, WorkerError, WorkerFrame, WorkerRequest,
};

use crate::SharedKernelTransport;

/// Production Execute hook bound to the one admitted claim and authenticated
/// Kernel session already used by lifecycle, replay, and checkpoint ports.
pub struct AuthenticatedRetainedProviderExecutePort {
    transport: SharedKernelTransport,
    claim: NativeWorkerClaim,
}

impl AuthenticatedRetainedProviderExecutePort {
    /// Binds the real Execute hook to an exact admitted claim and the existing
    /// shared Kernel transport. No provider operation identity is supplied by
    /// the caller.
    #[must_use]
    pub fn new(transport: SharedKernelTransport, claim: NativeWorkerClaim) -> Self {
        Self { transport, claim }
    }

    fn execute_admitted(
        &self,
        frame: &WorkerFrame,
        request: &WorkerRequest,
    ) -> Result<(), WorkerError> {
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
        let _process_admission = self
            .transport
            .read_provider_process_admission(&reference, &provider_process)
            .map_err(|_| {
                WorkerError::AdmissionRejected(
                    "Kernel did not provide the separately sealed provider-process admission".to_owned(),
                )
            })?;

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
    ) -> Pin<Box<dyn Future<Output = Result<(), WorkerError>> + Send + 'a>> {
        Box::pin(async move { self.execute_admitted(frame, request) })
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
