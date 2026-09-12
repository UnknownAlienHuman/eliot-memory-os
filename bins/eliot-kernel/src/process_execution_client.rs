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
    ProcessExecutionView, ProcessOwnerBinding, ProcessSessionBinding, ProcessStartReceipt,
};

use super::native_worker_lifecycle_route::{native_worker_json_str, native_worker_json_u64};
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

/// Starts one already-built admission bound to an admitted native-worker claim.
///
/// The admission itself is supplied by its owner (the permit issuer); this
/// function never mints authority, permits, intents, or leases. It verifies
/// that the admission binds the exact staged claim — operation identity,
/// deadline, authority epoch, worker generation, and recipient — then starts
/// it through [`GatewayProcessStarter`], which retains the path proof through
/// [`KernelComposition::retain_process_path_proof`]. Any binding mismatch
/// fails closed before the gateway is touched.
///
/// `claim` and `receipt` are the Wave-A claim-request and claim-receipt JSON
/// projections (`eliot_kernel_service::protocol::native_worker_claim`,
/// unreachable from this crate at this base; the integrator rebinds these
/// parameters to `NativeWorkerClaimRequest`/`NativeWorkerClaimReceipt`).
#[allow(clippy::too_many_lines)]
#[allow(
    dead_code,
    reason = "Wave-D entry point: the post-Ready starter binds this conversion"
)]
pub async fn start_admitted_native_worker_claim(
    kernel: &Arc<KernelComposition>,
    session: &Session,
    claim: &serde_json::Value,
    receipt: &serde_json::Value,
    admission: ProcessExecutionAdmissionRequest,
) -> Result<ProcessStartReceipt, ProcessExecutionRejection> {
    const MAX_TEXT: usize = 1_024;
    let reject = |code: &str, detail: &str| ProcessExecutionRejection {
        code: code.to_owned(),
        detail: detail.to_owned(),
    };
    if admission.validate().is_err() {
        return Err(reject(
            "CONTRACT_REJECTED",
            "native-worker claim admission failed contract validation",
        ));
    }
    let claim_id = native_worker_json_str(claim, "claim_id", 256).map_err(|_| {
        reject(
            "CLAIM_BINDING_MISSING",
            "native-worker claim identity is missing",
        )
    })?;
    let claim_operation =
        native_worker_json_str(claim, "operation_id", MAX_TEXT).map_err(|_| {
            reject(
                "CLAIM_BINDING_MISSING",
                "native-worker claim operation binding is missing",
            )
        })?;
    let claim_digest = native_worker_json_str(claim, "binding_digest", MAX_TEXT).map_err(|_| {
        reject(
            "CLAIM_BINDING_MISSING",
            "native-worker claim binding digest is missing",
        )
    })?;
    let claim_deadline = native_worker_json_u64(claim, "deadline_unix_ms").map_err(|_| {
        reject(
            "CLAIM_BINDING_MISSING",
            "native-worker claim deadline is missing",
        )
    })?;
    let claim_epoch = native_worker_json_u64(claim, "authority_epoch").map_err(|_| {
        reject(
            "CLAIM_BINDING_MISSING",
            "native-worker claim authority epoch is missing",
        )
    })?;
    let claim_generation = native_worker_json_u64(claim, "worker_generation").map_err(|_| {
        reject(
            "CLAIM_BINDING_MISSING",
            "native-worker claim worker generation is missing",
        )
    })?;
    let receipt_claim = native_worker_json_str(receipt, "claim_id", 256).map_err(|_| {
        reject(
            "CLAIM_RECEIPT_MISMATCH",
            "native-worker claim receipt identity is missing",
        )
    })?;
    let receipt_digest =
        native_worker_json_str(receipt, "binding_digest", MAX_TEXT).map_err(|_| {
            reject(
                "CLAIM_RECEIPT_MISMATCH",
                "native-worker claim receipt digest is missing",
            )
        })?;
    if receipt_claim != claim_id || receipt_digest != claim_digest {
        return Err(reject(
            "CLAIM_RECEIPT_MISMATCH",
            "native-worker claim receipt does not echo the admitted claim",
        ));
    }
    let Ok((owner, _)) = caller_binding(session) else {
        return Err(reject(
            "AUTHENTICATED_CALLER_REQUIRED",
            "the established authenticated session binding is unavailable",
        ));
    };
    if admission.recipient_module_id() != owner.module_id() {
        return Err(reject(
            "CLAIM_RECIPIENT_MISMATCH",
            "native-worker claim admission recipient is not the authenticated caller",
        ));
    }
    if admission.intent().operation_id().as_str() != claim_operation {
        return Err(reject(
            "CLAIM_BINDING_MISMATCH",
            "native-worker claim admission operation does not match the admitted claim",
        ));
    }
    if admission.deadline_unix_ms() != claim_deadline {
        return Err(reject(
            "CLAIM_BINDING_MISMATCH",
            "native-worker claim admission deadline does not match the admitted claim",
        ));
    }
    if admission.state_fence().authority_epoch() != claim_epoch
        || admission.state_fence().generation().get() != claim_generation
    {
        return Err(reject(
            "CLAIM_BINDING_MISMATCH",
            "native-worker claim admission fence does not match the admitted claim",
        ));
    }
    let Some(gateway) = kernel.process_gateway.as_ref() else {
        return Err(reject(
            "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED",
            "external process authority key, snapshot, replay, and evidence bindings are required",
        ));
    };
    let starter = GatewayProcessStarter {
        kernel: Arc::clone(kernel),
        gateway: Arc::clone(gateway),
        owner,
    };
    starter
        .start(admission)
        .await
        .map_err(|error| ProcessExecutionRejection::from_error(&error))
}
