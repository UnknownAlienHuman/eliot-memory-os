//! Composition-root process-execution ports over the P-04 gateway.
//!
//! Wiring only: every operation delegates to an existing
//! [`ProcessExecutionGateway`] method. The starter retains the path proof
//! through [`KernelComposition::retain_process_path_proof`] and starts through
//! the gateway; observations delegate to the gateway's replay-authorized
//! inspect/cancel/reconcile. No validation, replay, permit, or evidence logic
//! is reimplemented here.

use std::sync::Arc;

use eliot_ipc::Session;
use eliot_kernel_service::{
    KernelProcessExecutionClient, ProcessExecutionRejection, ProcessOperationFuture,
    ProcessOperationPort, ProcessStarter, ProcessStarterFuture,
};
use eliot_process::{
    CancellationReceipt, OperationId, ProcessEvidence, ProcessExecutionAdmissionRequest,
    ProcessExecutionView, ProcessOwnerBinding, ProcessSessionBinding,
};

use super::{KernelComposition, ProcessExecutionGateway, caller_binding};

/// Operation port delegating to the gateway under one bound owner.
///
/// The gateway methods already authorize the owner against the replay record
/// and map failures to process-execution errors; results pass through so the
/// front-door client can project them into responses.
pub(crate) struct GatewayOperationPort {
    gateway: Arc<ProcessExecutionGateway>,
    owner: ProcessOwnerBinding,
}

impl ProcessOperationPort for GatewayOperationPort {
    fn inspect(
        &self,
        operation_id: OperationId,
    ) -> ProcessOperationFuture<'_, ProcessExecutionView> {
        let gateway = Arc::clone(&self.gateway);
        let owner = self.owner.clone();
        Box::pin(async move { gateway.inspect(&owner, operation_id).await })
    }

    fn cancel(&self, operation_id: OperationId) -> ProcessOperationFuture<'_, CancellationReceipt> {
        let gateway = Arc::clone(&self.gateway);
        let owner = self.owner.clone();
        Box::pin(async move { gateway.cancel(&owner, operation_id).await })
    }

    fn reconcile(&self, operation_id: OperationId) -> ProcessOperationFuture<'_, ProcessEvidence> {
        let gateway = Arc::clone(&self.gateway);
        let owner = self.owner.clone();
        Box::pin(async move { gateway.reconcile(&owner, operation_id).await })
    }
}

/// Starter retaining the path proof through the composition, then delegating.
///
/// The gateway [`Arc`] is cloned at construction, where presence was already
/// proven by the fail-closed configuration check below; `process_gateway` is
/// written once during composition assembly and only read afterwards, so the
/// retained [`Arc`] cannot go stale. The kernel [`Arc`] supplies only
/// [`KernelComposition::retain_process_path_proof`].
pub(crate) struct GatewayProcessStarter {
    kernel: Arc<KernelComposition>,
    gateway: Arc<ProcessExecutionGateway>,
    owner: ProcessOwnerBinding,
}

impl ProcessStarter for GatewayProcessStarter {
    fn start(&self, admission: ProcessExecutionAdmissionRequest) -> ProcessStarterFuture<'_> {
        let kernel = Arc::clone(&self.kernel);
        let gateway = Arc::clone(&self.gateway);
        let owner = self.owner.clone();
        Box::pin(async move {
            let proof = kernel.retain_process_path_proof(&admission)?;
            gateway.start(&owner, admission, proof).await
        })
    }
}

/// Builds the front-door client for one authenticated session binding.
///
/// Replicates the [`KernelComposition::execute_process_request`] preamble
/// exactly: unavailable caller binding, session binding mismatch, and missing
/// process authority each fail closed with the same rejection code and detail.
pub fn process_execution_client(
    kernel: &Arc<KernelComposition>,
    session: &Session,
    session_binding: &ProcessSessionBinding,
) -> Result<KernelProcessExecutionClient, ProcessExecutionRejection> {
    let Ok((owner, expected_session_binding)) = caller_binding(session) else {
        return Err(ProcessExecutionRejection {
            code: "AUTHENTICATED_CALLER_REQUIRED".to_owned(),
            detail: "the established authenticated session binding is unavailable".to_owned(),
        });
    };
    if *session_binding != expected_session_binding {
        return Err(ProcessExecutionRejection {
            code: "SESSION_BINDING_MISMATCH".to_owned(),
            detail: "process operation session binding does not match the established authenticated session".to_owned(),
        });
    }
    let Some(gateway) = kernel.process_gateway.as_ref() else {
        return Err(ProcessExecutionRejection {
            code: "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED".to_owned(),
            detail: "external process authority key, snapshot, replay, and evidence bindings are required".to_owned(),
        });
    };
    let gateway = Arc::clone(gateway);
    let starter: Arc<dyn ProcessStarter> = Arc::new(GatewayProcessStarter {
        kernel: Arc::clone(kernel),
        gateway: Arc::clone(&gateway),
        owner: owner.clone(),
    });
    let operations: Arc<dyn ProcessOperationPort> =
        Arc::new(GatewayOperationPort { gateway, owner });
    Ok(KernelProcessExecutionClient::new(starter, operations))
}
