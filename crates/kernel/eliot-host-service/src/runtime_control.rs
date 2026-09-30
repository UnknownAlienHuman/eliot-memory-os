#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    dead_code,
    missing_docs,
    reason = "provider-neutral runtime-control wire seam keeps explicit validation and frame plumbing"
)]

use crate::reactive_context_delivery::{
    DeliveryDisposition, ReactiveContextDeliveryReceipt, ReactiveContextDeliveryRequest,
};
use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_host_state::{
    ActivationState, EpochIdentity, EpochTransition, IdempotencyIdentity, WakeDisposition,
};
use eliot_kernel_service::{
    UserAutomationHostExecutionOperation, UserAutomationHostExecutionRequest,
    UserAutomationHostExecutionResponse,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::backup::{
    BackupArtifactHandle, BackupCutoverAdmission, BackupIsolatedRestorePrepare,
    BackupOperationKind, BackupPhaseAttestation, BackupRequestIdentity, BackupRestoreReconcile,
    BackupRestoreStatus, BackupStage, attesting_roles, operation_for_phase,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    ReactiveContextStage, RequestIdentity,
};
use eliot_receipts::RequestBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Stable wire identifier for Host runtime-control requests and responses.
pub const HOST_RUNTIME_CONTROL_WIRE: &str = "eliot.host.runtime-control.v2";
/// Stable trace discriminator for the authenticated Host runtime-control contour.
pub const HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR: &str =
    "eliot-host::production-runtime-control:v1";
/// Trace-context key carrying the Host runtime-control discriminator.
pub const HOST_RUNTIME_CONTROL_PRODUCTION_TRACE_CONTEXT_KEY: &str =
    "eliot.host.production-discriminator";
const WIRE: &str = HOST_RUNTIME_CONTROL_WIRE;
const UNKNOWN_REF_TAG: &str = "unknown";
const UNKNOWN_REF_REASONS: &[&str] = &[
    "kernel-restart-validation",
    "kernel-restart-queue-lock",
    "kernel-restart-queue-full",
    "kernel-restart-queue-response",
    "kernel-restart",
    "kernel-restart-reconcile",
    "kernel-restart-reconcile-conflict",
    "kernel-restart-pending",
    "kernel-restart-reconcile-snapshot",
    "kernel-restart-reconcile-unknown",
    "store-recovery-validation",
    "store-recovery-queue-lock",
    "store-recovery-queue-full",
    "store-recovery-queue-response",
    "store-recovery",
    "store-recovery-pending",
    "store-recovery-reconcile",
    "store-recovery-reconcile-conflict",
    "store-recovery-reconcile-snapshot",
    "store-recovery-reconcile-unknown",
    "store-recovery-crash-fence-manual-new-lineage",
    "reactive-context-validation",
    "reactive-context-queue-lock",
    "reactive-context-queue-full",
    "reactive-context-queue-response",
    "reactive-context",
    "user-automation-admit-validation",
    "user-automation-admit-queue-lock",
    "user-automation-admit-queue-full",
    "user-automation-admit-queue-response",
    "user-automation-admit",
    "user-automation-cancel-wakes-validation",
    "user-automation-cancel-wakes-queue-lock",
    "user-automation-cancel-wakes-queue-full",
    "user-automation-cancel-wakes-queue-response",
    "user-automation-cancel-wakes",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HostRuntimeControlOperation {
    RestartKernel,
    ReconcileKernelRestart,
    RecoverStore,
    ReconcileStoreRecovery,
    DeliverReactiveContext,
    AdmitUserAutomationOccurrence,
    CancelUserAutomationPendingWakes,
}

fn canonical_operation_name(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel => "RestartKernel",
        HostRuntimeControlOperation::ReconcileKernelRestart => "ReconcileKernelRestart",
        HostRuntimeControlOperation::RecoverStore => "RecoverStore",
        HostRuntimeControlOperation::ReconcileStoreRecovery => "ReconcileStoreRecovery",
        HostRuntimeControlOperation::DeliverReactiveContext => "DeliverReactiveContext",
        HostRuntimeControlOperation::AdmitUserAutomationOccurrence => {
            "AdmitUserAutomationOccurrence"
        }
        HostRuntimeControlOperation::CancelUserAutomationPendingWakes => {
            "CancelUserAutomationPendingWakes"
        }
    }
}

fn operation_unknown_prefix(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel
        | HostRuntimeControlOperation::ReconcileKernelRestart => "kernel-restart",
        HostRuntimeControlOperation::RecoverStore
        | HostRuntimeControlOperation::ReconcileStoreRecovery => "store-recovery",
        HostRuntimeControlOperation::DeliverReactiveContext => "reactive-context",
        HostRuntimeControlOperation::AdmitUserAutomationOccurrence => "user-automation-admit",
        HostRuntimeControlOperation::CancelUserAutomationPendingWakes => {
            "user-automation-cancel-wakes"
        }
    }
}

pub fn operation_unknown_ref(
    operation: &HostRuntimeControlOperation,
    suffix: &str,
    request: &HostRuntimeControlRequest,
) -> PlatformHandle {
    runtime_control_unknown_ref(
        &format!("{}-{suffix}", operation_unknown_prefix(operation)),
        request,
    )
}

fn is_sha256_digest(value: &PlatformHandle) -> bool {
    value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_store_process_identity(value: &PlatformHandle) -> bool {
    let Some(identity) = value.as_str().strip_prefix("pid:") else {
        return false;
    };
    let Some((pid, start)) = identity.split_once(":start:") else {
        return false;
    };
    !pid.is_empty()
        && !start.is_empty()
        && pid.parse::<u32>().is_ok_and(|value| value != 0)
        && start.parse::<u64>().is_ok_and(|value| value != 0)
        && !start.contains(':')
}

fn mutation_digest_for_request_id(wire: &PlatformHandle, request_id: &PlatformHandle) -> String {
    sha256_hex(format!("{}:mutation:{}", wire.as_str(), request_id.as_str()).as_bytes())
}

fn request_digest_for(
    wire: &PlatformHandle,
    operation: &HostRuntimeControlOperation,
    request_id: &PlatformHandle,
    mutation_digest: &PlatformHandle,
) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}",
            wire.as_str(),
            canonical_operation_name(operation),
            request_id.as_str(),
            mutation_digest.as_str()
        )
        .as_bytes(),
    )
}

fn reactive_context_mutation_digest(
    source: &HostReactiveContextRuntimeRequest,
) -> Result<String, String> {
    let encoded = serde_json::to_vec(source)
        .map_err(|_| "reactive Context source could not be encoded".to_owned())?;
    let mut material = Vec::with_capacity(WIRE.len() + encoded.len() + 20);
    material.extend_from_slice(WIRE.as_bytes());
    material.extend_from_slice(b":reactive-context:");
    material.extend_from_slice(&encoded);
    Ok(sha256_hex(&material))
}

fn user_automation_mutation_digest(
    operation: &HostRuntimeControlOperation,
    source: &HostUserAutomationRuntimeRequest,
) -> Result<String, String> {
    let encoded = serde_json::to_vec(source)
        .map_err(|_| "user automation source could not be encoded".to_owned())?;
    let operation_name = canonical_operation_name(operation);
    let mut material = Vec::with_capacity(WIRE.len() + operation_name.len() + encoded.len() + 32);
    material.extend_from_slice(WIRE.as_bytes());
    material.extend_from_slice(b":user-automation:");
    material.extend_from_slice(operation_name.as_bytes());
    material.extend_from_slice(b":");
    material.extend_from_slice(&encoded);
    Ok(sha256_hex(&material))
}

pub fn runtime_control_unknown_ref(
    prefix: &str,
    request: &HostRuntimeControlRequest,
) -> PlatformHandle {
    let payload = serde_json::to_string(&(
        canonical_operation_name(&request.operation),
        request.request_id.as_str(),
        request.mutation_digest.as_str(),
        request.request_digest.as_str(),
    ))
    .unwrap_or_else(|_| unreachable!());
    PlatformHandle::new(format!("{WIRE}:{UNKNOWN_REF_TAG}:{prefix}:{payload}"))
        .unwrap_or_else(|_| unreachable!())
}

fn parse_runtime_control_unknown_ref(
    pending_ref: &PlatformHandle,
) -> Option<HostRuntimeControlRequest> {
    let mut parts = pending_ref.as_str().splitn(4, ':');
    let wire = parts.next()?;
    let tag = parts.next()?;
    let reason = parts.next()?;
    let payload = parts.next()?;
    if wire != WIRE || tag != UNKNOWN_REF_TAG || !UNKNOWN_REF_REASONS.contains(&reason) {
        return None;
    }
    let (operation_name, request_id, mutation_digest, request_digest) =
        serde_json::from_str::<(String, String, String, String)>(payload).ok()?;
    if serde_json::to_string(&(
        operation_name.as_str(),
        request_id.as_str(),
        mutation_digest.as_str(),
        request_digest.as_str(),
    ))
    .ok()
    .as_deref()
        != Some(payload)
    {
        return None;
    }
    let operation = match operation_name.as_str() {
        "RestartKernel" => HostRuntimeControlOperation::RestartKernel,
        "ReconcileKernelRestart" => HostRuntimeControlOperation::ReconcileKernelRestart,
        "RecoverStore" => HostRuntimeControlOperation::RecoverStore,
        "ReconcileStoreRecovery" => HostRuntimeControlOperation::ReconcileStoreRecovery,
        "DeliverReactiveContext" => HostRuntimeControlOperation::DeliverReactiveContext,
        "AdmitUserAutomationOccurrence" => {
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence
        }
        "CancelUserAutomationPendingWakes" => {
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes
        }
        _ => return None,
    };
    let request = HostRuntimeControlRequest {
        wire: PlatformHandle::new(wire.to_owned()).ok()?,
        operation,
        request_id: PlatformHandle::new(request_id).ok()?,
        mutation_digest: PlatformHandle::new(mutation_digest).ok()?,
        request_digest: PlatformHandle::new(request_digest).ok()?,
        reactive_context: None,
        user_automation: None,
    };
    request.validate_identity().ok().map(|_| request)
}

/// Complete owner-produced reactive Context input accepted by the
/// authenticated Host runtime-control front door.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostReactiveContextRuntimeRequest {
    /// Complete typed payload and owner enqueue evidence.
    pub delivery: ReactiveContextDeliveryRequest,
    /// Owner admission reference for this exact request.
    pub admission_ref: PlatformHandle,
}

impl HostReactiveContextRuntimeRequest {
    /// Validate the source handoff before it enters the Host queue.
    pub fn validate(&self) -> Result<(), String> {
        if self.admission_ref.as_str().trim().is_empty() {
            return Err("reactive Context admission_ref is blank".to_owned());
        }
        self.delivery
            .payload
            .validate()
            .map_err(|error| format!("reactive Context payload is invalid: {error}"))?;
        let owner_receipt = self
            .delivery
            .owner_receipt
            .as_ref()
            .ok_or_else(|| "reactive Context owner_receipt is required".to_owned())?;
        owner_receipt
            .validate()
            .map_err(|error| format!("reactive Context owner_receipt is invalid: {error}"))
    }
}

/// Complete owner-produced UserAutomation execution carrier accepted by the
/// authenticated Host runtime-control front door.
///
/// The wrapped value is the existing typed Kernel-to-Host execution carrier;
/// this wire adds only the authenticated runtime-control envelope and digest
/// binding around it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostUserAutomationRuntimeRequest {
    /// Complete typed execution carrier and authenticated channel evidence.
    pub execution: UserAutomationHostExecutionRequest,
}

impl HostUserAutomationRuntimeRequest {
    /// Validate the carrier handoff before it enters the Host queue.
    pub fn validate(&self) -> Result<(), String> {
        self.execution
            .validate()
            .map_err(|error| format!("user automation carrier is invalid: {error}"))
    }

    /// Validate the carrier for the occurrence-admission operation.
    pub fn validate_for_admit(&self) -> Result<(), String> {
        self.validate()?;
        if !matches!(
            self.execution.operation,
            UserAutomationHostExecutionOperation::AdmitOccurrence { .. }
        ) {
            return Err("user automation admit requires an AdmitOccurrence carrier".to_owned());
        }
        Ok(())
    }

    /// Validate the carrier for the pending-wake-cancellation operation.
    pub fn validate_for_cancel(&self) -> Result<(), String> {
        self.validate()?;
        if !matches!(
            self.execution.operation,
            UserAutomationHostExecutionOperation::CancelPendingWakes { .. }
        ) {
            return Err("user automation cancel requires a CancelPendingWakes carrier".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuntimeControlRequest {
    pub wire: PlatformHandle,
    pub operation: HostRuntimeControlOperation,
    pub request_id: PlatformHandle,
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    /// Complete typed input for the authenticated reactive Context operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactive_context: Option<HostReactiveContextRuntimeRequest>,
    /// Complete typed UserAutomation execution carrier for the authenticated
    /// occurrence-admission and wake-cancellation operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_automation: Option<HostUserAutomationRuntimeRequest>,
}

impl HostRuntimeControlRequest {
    pub fn new(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
    ) -> Result<Self, String> {
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest =
            PlatformHandle::new(mutation_digest_for_request_id(&wire, &request_id))
                .map_err(|e| e.to_string())?;
        Self::new_with_mutation_digest(operation, request_id, mutation_digest)
    }

    pub fn new_with_mutation_digest(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: None,
            user_automation: None,
        };
        value.validate().map_err(|e| e.to_string())?;
        Ok(value)
    }

    /// Construct an authenticated reactive Context request whose mutation
    /// digest covers the complete typed owner handoff.
    pub fn new_reactive_context(
        request_id: PlatformHandle,
        delivery: ReactiveContextDeliveryRequest,
        admission_ref: PlatformHandle,
    ) -> Result<Self, String> {
        let reactive_context = HostReactiveContextRuntimeRequest {
            delivery,
            admission_ref,
        };
        reactive_context.validate()?;
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest =
            PlatformHandle::new(reactive_context_mutation_digest(&reactive_context)?)
                .map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &HostRuntimeControlOperation::DeliverReactiveContext,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation: HostRuntimeControlOperation::DeliverReactiveContext,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: Some(reactive_context),
            user_automation: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn new_reconcile(
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        Self::new_with_mutation_digest(
            HostRuntimeControlOperation::ReconcileKernelRestart,
            request_id,
            mutation_digest,
        )
    }
    pub fn new_store_reconcile(
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        Self::new_with_mutation_digest(
            HostRuntimeControlOperation::ReconcileStoreRecovery,
            request_id,
            mutation_digest,
        )
    }

    /// Construct an authenticated UserAutomation occurrence-admission request
    /// whose mutation digest covers the complete typed execution carrier.
    pub fn new_admit_user_automation_occurrence(
        request_id: PlatformHandle,
        execution: UserAutomationHostExecutionRequest,
    ) -> Result<Self, String> {
        Self::new_user_automation(
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            request_id,
            execution,
        )
    }

    /// Construct an authenticated UserAutomation pending-wake-cancellation
    /// request whose mutation digest covers the complete typed carrier.
    pub fn new_cancel_user_automation_pending_wakes(
        request_id: PlatformHandle,
        execution: UserAutomationHostExecutionRequest,
    ) -> Result<Self, String> {
        Self::new_user_automation(
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
            request_id,
            execution,
        )
    }

    fn new_user_automation(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
        execution: UserAutomationHostExecutionRequest,
    ) -> Result<Self, String> {
        let user_automation = HostUserAutomationRuntimeRequest { execution };
        match operation {
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence => {
                user_automation.validate_for_admit()?;
            }
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes => {
                user_automation.validate_for_cancel()?;
            }
            _ => {
                return Err(
                    "user automation input is reserved for AdmitUserAutomationOccurrence and CancelUserAutomationPendingWakes"
                        .to_owned(),
                );
            }
        }
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest = PlatformHandle::new(user_automation_mutation_digest(
            &operation,
            &user_automation,
        )?)
        .map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: None,
            user_automation: Some(user_automation),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_identity()?;
        match (&self.operation, &self.reactive_context) {
            (HostRuntimeControlOperation::DeliverReactiveContext, Some(source)) => {
                source.validate()?;
                let expected = reactive_context_mutation_digest(source)?;
                if self.mutation_digest.as_str() != expected {
                    return Err("reactive Context mutation_digest mismatch".to_owned());
                }
            }
            (HostRuntimeControlOperation::DeliverReactiveContext, None) => {
                return Err("reactive Context input is required".to_owned());
            }
            (_, Some(_)) => {
                return Err(
                    "reactive Context input is reserved for DeliverReactiveContext".to_owned(),
                );
            }
            (_, None) => {}
        }
        match (&self.operation, &self.user_automation) {
            (HostRuntimeControlOperation::AdmitUserAutomationOccurrence, Some(source)) => {
                source.validate_for_admit()?;
                let expected = user_automation_mutation_digest(&self.operation, source)?;
                if self.mutation_digest.as_str() != expected {
                    return Err("user automation mutation_digest mismatch".to_owned());
                }
            }
            (HostRuntimeControlOperation::CancelUserAutomationPendingWakes, Some(source)) => {
                source.validate_for_cancel()?;
                let expected = user_automation_mutation_digest(&self.operation, source)?;
                if self.mutation_digest.as_str() != expected {
                    return Err("user automation mutation_digest mismatch".to_owned());
                }
            }
            (
                HostRuntimeControlOperation::AdmitUserAutomationOccurrence
                | HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
                None,
            ) => {
                return Err("user automation input is required".to_owned());
            }
            (_, Some(_)) => {
                return Err("user automation input is reserved for AdmitUserAutomationOccurrence and CancelUserAutomationPendingWakes"
                    .to_owned());
            }
            (_, None) => {}
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), String> {
        if self.wire.as_str() != WIRE {
            return Err("unsupported wire".to_owned());
        }
        if self.request_id.as_str().trim().is_empty()
            || self.request_id.as_str().chars().any(char::is_control)
        {
            return Err("request_id invalid".to_owned());
        }
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("mutation_digest must be lowercase sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("request_digest must be lowercase sha256".to_owned());
        }
        let expected = request_digest_for(
            &self.wire,
            &self.operation,
            &self.request_id,
            &self.mutation_digest,
        );
        if expected != self.request_digest.as_str() {
            return Err("request_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKernelRestartReceipt {
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    pub old_kernel_generation: PlatformHandle,
    pub new_kernel_generation: PlatformHandle,
    pub store_fence: PlatformHandle,
    pub activation_receipt_digest: PlatformHandle,
    pub ready_receipt_digest: PlatformHandle,
    pub receipt_digest: PlatformHandle,
}

impl HostKernelRestartReceipt {
    pub fn computed_digest(&self) -> Result<PlatformHandle, String> {
        let bytes = serde_json::to_vec(&(
            self.mutation_digest.as_str(),
            self.request_digest.as_str(),
            self.old_kernel_generation.as_str(),
            self.new_kernel_generation.as_str(),
            self.store_fence.as_str(),
            self.activation_receipt_digest.as_str(),
            self.ready_receipt_digest.as_str(),
        ))
        .map_err(|e| e.to_string())?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|e| e.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("mutation_digest must be sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("request_digest must be sha256".to_owned());
        }
        for (v, name) in [
            (&self.old_kernel_generation, "old_kernel_generation"),
            (&self.new_kernel_generation, "new_kernel_generation"),
            (&self.store_fence, "store_fence"),
            (&self.activation_receipt_digest, "activation_receipt_digest"),
            (&self.ready_receipt_digest, "ready_receipt_digest"),
            (&self.receipt_digest, "receipt_digest"),
        ] {
            if v.as_str().len() != 64
                || !v
                    .as_str()
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(format!("{name} must be sha256"));
            }
        }
        if self.receipt_digest != self.computed_digest()? {
            return Err("receipt_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStoreRecoveryReceipt {
    /// The mutation identity of the external Host runtime-control request.
    pub external_control_mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    /// The canonical payload digest of the inner Kernel StoreRebind request.
    pub store_rebind_request_digest: PlatformHandle,
    pub store_fence: PlatformHandle,
    pub new_store_process_id: PlatformHandle,
    pub kernel_generation: PlatformHandle,
    pub activation_nonce_digest: PlatformHandle,
    pub ready_receipt_digest: PlatformHandle,
    pub receipt_digest: PlatformHandle,
}

impl HostStoreRecoveryReceipt {
    pub fn computed_digest(&self) -> Result<PlatformHandle, String> {
        let bytes = serde_json::to_vec(&(
            self.external_control_mutation_digest.as_str(),
            self.request_digest.as_str(),
            self.store_rebind_request_digest.as_str(),
            self.store_fence.as_str(),
            self.new_store_process_id.as_str(),
            self.kernel_generation.as_str(),
            self.activation_nonce_digest.as_str(),
            self.ready_receipt_digest.as_str(),
        ))
        .map_err(|e| e.to_string())?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|e| e.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        for (v, name) in [
            (
                &self.external_control_mutation_digest,
                "external_control_mutation_digest",
            ),
            (&self.request_digest, "request_digest"),
            (
                &self.store_rebind_request_digest,
                "store_rebind_request_digest",
            ),
            (&self.store_fence, "store_fence"),
            (&self.kernel_generation, "kernel_generation"),
            (&self.activation_nonce_digest, "activation_nonce_digest"),
            (&self.ready_receipt_digest, "ready_receipt_digest"),
            (&self.receipt_digest, "receipt_digest"),
        ] {
            if !is_sha256_digest(v) {
                return Err(format!("{name} must be sha256"));
            }
        }
        if self.external_control_mutation_digest == self.store_rebind_request_digest {
            return Err(
                "external_control_mutation_digest and store_rebind_request_digest must remain distinct"
                    .to_owned(),
            );
        }
        if !is_store_process_identity(&self.new_store_process_id) {
            return Err("new_store_process_id must be pid:<u32>:start:<u64>".to_owned());
        }
        if self.receipt_digest != self.computed_digest()? {
            return Err("receipt_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[allow(private_interfaces)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum HostRuntimeControlResponse {
    Restarted {
        receipt: HostKernelRestartReceipt,
    },
    StoreRecovered {
        receipt: HostStoreRecoveryReceipt,
    },
    UserAutomationOccurrenceAdmitted {
        mutation_digest: PlatformHandle,
        request_digest: PlatformHandle,
        response: UserAutomationHostExecutionResponse,
    },
    UserAutomationPendingWakesCancelled {
        mutation_digest: PlatformHandle,
        request_digest: PlatformHandle,
        response: UserAutomationHostExecutionResponse,
    },
    ReactiveContextDeliveryObserved {
        observation: ReactiveContextDeliveryObservation,
    },
    ReactiveContextPreEffectRejected {
        mutation_digest: PlatformHandle,
        request_digest: PlatformHandle,
        failure: ReactiveContextPreEffectFailure,
    },
    ReactiveContextDeliveryUnknown {
        mutation_digest: PlatformHandle,
        request_digest: PlatformHandle,
        operation: IdempotencyIdentity,
        pending_ref: PlatformHandle,
    },
    Unknown {
        pending_ref: PlatformHandle,
    },
    /// Generation-bound activation admission projected with the operation
    /// answer.
    ///
    /// I1.5 acceptance: an authenticated request returns an admission result
    /// tied to the current generations. The wrapped `response` is the
    /// unchanged operation answer; `admission` carries the activation state,
    /// activation generation, governance profile, held lease references and
    /// drain disposition proven for the current Host/Kernel/Watchdog
    /// generations. Validators treat the projection transparently: the inner
    /// answer keeps its exact request binding.
    AdmissionProjected {
        response: Box<HostRuntimeControlResponse>,
        admission: HostActivationAdmission,
    },
}

/// Generation-bound activation admission carried on the runtime-control
/// response path.
///
/// I1.5: "A request is not admitted as an active Session/Attempt until it
/// receives an activation result bound to the current Host/Kernel/Watchdog
/// generations." Every field reuses the durable journal owner types from
/// `eliot-host-state`; this struct adds only `Serialize` wire membership
/// through the existing response owner — no second wire protocol and no new
/// vocabulary. The Host activation producer projects the same journal
/// snapshot the local diagnostics line reads, so the caller sees exactly
/// what the Host proved instead of inferring it from process liveness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostActivationAdmission {
    /// Durable activation identity of the joined generation.
    pub activation_id: PlatformHandle,
    /// Installation-scoped activation generation the result is bound to.
    pub activation_generation: EpochTransition,
    /// Current activation state.
    pub state: ActivationState,
    /// Host/Kernel/Watchdog/store generations proven for this admission.
    pub host_epoch: EpochIdentity,
    pub kernel_epoch: EpochIdentity,
    pub watchdog_epoch: EpochIdentity,
    pub store_generation: EpochIdentity,
    /// Derived governance profile carried by the durable record.
    pub governance_profile: PlatformHandle,
    /// Fresh readiness evidence flags proven by the readiness owner.
    pub control_ready: bool,
    pub supervision_ready: bool,
    /// Capabilities requested by the observed triggers of this generation.
    pub requested_capabilities: Vec<PlatformHandle>,
    /// Dependency branches the journal proves are running.
    pub admitted_capabilities: Vec<PlatformHandle>,
    /// Runtime-lease references the generation holds.
    pub runtime_lease_refs: Vec<PlatformHandle>,
    /// Supervision-lease references the generation holds.
    pub supervision_lease_refs: Vec<PlatformHandle>,
    /// `WakeIntent` references the generation holds.
    pub wake_intent_refs: Vec<PlatformHandle>,
    /// Durable wake-during-drain disposition, once a drain ran.
    pub drain_disposition: Option<WakeDisposition>,
    /// Whether a concurrent trigger coalesced behind this generation.
    pub coalesced: bool,
}

impl HostActivationAdmission {
    pub fn validate(&self) -> Result<(), String> {
        self.activation_generation
            .validate()
            .map_err(|error| format!("activation_generation is not a valid transition: {error}"))?;
        if self.activation_id.as_str().trim().is_empty() {
            return Err("activation_id is blank".to_owned());
        }
        if self.governance_profile.as_str().trim().is_empty() {
            return Err("governance_profile is blank".to_owned());
        }
        Ok(())
    }
}

/// Exact durable Host queue observation returned for one runtime-control request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextDeliveryObservation {
    /// Mutation digest binding the complete typed delivery request.
    pub mutation_digest: PlatformHandle,
    /// Runtime-control request digest for this observation.
    pub request_digest: PlatformHandle,
    /// Exact durable Host queue operation identity.
    pub operation: IdempotencyIdentity,
    /// Canonical digest of the queued protocol payload.
    pub payload_sha256: String,
    /// Durable lifecycle stage reported by the Host queue.
    pub stage: ReactiveContextStage,
    /// Host transport/queue disposition; `Delivered` means transport delivery only.
    pub disposition: ReactiveContextRuntimeDisposition,
}

/// Closed runtime-control projection of a Host delivery disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveContextRuntimeDisposition {
    Queued,
    Delivered,
    DeliveryUnknown,
    NotAttempted,
    Replay,
    AlreadyAcknowledged,
    AlreadyTerminal,
}

impl From<DeliveryDisposition> for ReactiveContextRuntimeDisposition {
    fn from(value: DeliveryDisposition) -> Self {
        match value {
            DeliveryDisposition::Queued => Self::Queued,
            DeliveryDisposition::Delivered => Self::Delivered,
            DeliveryDisposition::DeliveryUnknown => Self::DeliveryUnknown,
            DeliveryDisposition::NotAttempted => Self::NotAttempted,
            DeliveryDisposition::Replay => Self::Replay,
            DeliveryDisposition::AlreadyAcknowledged => Self::AlreadyAcknowledged,
            DeliveryDisposition::AlreadyTerminal => Self::AlreadyTerminal,
        }
    }
}

/// Pre-effect rejection class reported by the Host runtime-control boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveContextPreEffectFailureKind {
    ProducerConstruction,
    HostAdmission,
}

/// Typed reason for a request refused before delivery coordination.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextPreEffectFailure {
    /// Failure boundary that rejected the request before queue/send effects.
    pub kind: ReactiveContextPreEffectFailureKind,
    /// Diagnostic from the typed producer or Host admission error.
    pub reason: String,
}

fn is_sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn validate_user_automation_response(
    expect_admit: bool,
    response: &UserAutomationHostExecutionResponse,
) -> Result<(), String> {
    match response {
        UserAutomationHostExecutionResponse::Admitted { request_sha256, .. } => {
            if !expect_admit {
                return Err("user automation cancel response must be Cancelled".to_owned());
            }
            if !is_sha256_text(request_sha256) {
                return Err("user automation request_sha256 must be sha256".to_owned());
            }
            Ok(())
        }
        UserAutomationHostExecutionResponse::Cancelled { request_sha256, .. } => {
            if expect_admit {
                return Err("user automation admit response must be Admitted".to_owned());
            }
            if !is_sha256_text(request_sha256) {
                return Err("user automation request_sha256 must be sha256".to_owned());
            }
            Ok(())
        }
        UserAutomationHostExecutionResponse::Failed { failure, .. } => {
            failure
                .validate()
                .map_err(|error| format!("user automation failure projection: {error}"))?;
            Ok(())
        }
        UserAutomationHostExecutionResponse::WakeRead { .. }
        | UserAutomationHostExecutionResponse::WakeEnumeration { .. }
        | UserAutomationHostExecutionResponse::WakeCancellationBatchReadback { .. }
        | UserAutomationHostExecutionResponse::WakeHorizonPublication { .. } => Err(
            "user automation wake readback, cancellation-batch readback, batch enumeration, and wake-horizon publication travel over the authenticated execution transport, never runtime-control"
                .to_owned(),
        ),
    }
}

impl HostRuntimeControlResponse {
    pub fn restarted_for(
        request: &HostRuntimeControlRequest,
        receipt: HostKernelRestartReceipt,
    ) -> Self {
        let _ = request;
        Self::Restarted { receipt }
    }

    pub fn store_recovered_for(
        request: &HostRuntimeControlRequest,
        receipt: HostStoreRecoveryReceipt,
    ) -> Self {
        let _ = request;
        Self::StoreRecovered { receipt }
    }

    /// Bind a typed occurrence-admission answer to its runtime-control
    /// request. The typed carrier binding itself is checked by
    /// [`response_matches_request`].
    pub fn user_automation_occurrence_admitted_for(
        request: &HostRuntimeControlRequest,
        response: UserAutomationHostExecutionResponse,
    ) -> Self {
        Self::UserAutomationOccurrenceAdmitted {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            response,
        }
    }

    /// Bind a typed wake-cancellation answer to its runtime-control request.
    /// The typed carrier binding itself is checked by
    /// [`response_matches_request`].
    pub fn user_automation_pending_wakes_cancelled_for(
        request: &HostRuntimeControlRequest,
        response: UserAutomationHostExecutionResponse,
    ) -> Self {
        Self::UserAutomationPendingWakesCancelled {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            response,
        }
    }

    /// Bind the durable Host queue receipt to the exact typed delivery request.
    pub fn reactive_context_delivery_observed_for(
        request: &HostRuntimeControlRequest,
        receipt: &ReactiveContextDeliveryReceipt,
    ) -> Self {
        Self::ReactiveContextDeliveryObserved {
            observation: ReactiveContextDeliveryObservation {
                mutation_digest: request.mutation_digest.clone(),
                request_digest: request.request_digest.clone(),
                operation: receipt.entry.operation.clone(),
                payload_sha256: receipt.entry.payload_sha256.clone(),
                stage: receipt.entry.stage,
                disposition: receipt.disposition.into(),
            },
        }
    }

    /// Preserve a typed pre-coordinator refusal without implying a queue entry.
    pub fn reactive_context_pre_effect_rejected_for(
        request: &HostRuntimeControlRequest,
        kind: ReactiveContextPreEffectFailureKind,
        reason: String,
    ) -> Self {
        Self::ReactiveContextPreEffectRejected {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            failure: ReactiveContextPreEffectFailure { kind, reason },
        }
    }

    /// Preserve uncertainty while correlating it with the stable intended queue operation.
    pub fn reactive_context_delivery_unknown_for(
        request: &HostRuntimeControlRequest,
    ) -> Result<Self, String> {
        let source = request
            .reactive_context
            .as_ref()
            .ok_or_else(|| "reactive Context request is absent".to_owned())?;
        let operation = IdempotencyIdentity {
            operation_id: PlatformHandle::new(
                source.delivery.payload.operation_id.as_str().to_owned(),
            )
            .map_err(|error| error.to_string())?,
            idempotency_key: PlatformHandle::new(source.delivery.payload.idempotency_key.clone())
                .map_err(|error| error.to_string())?,
        };
        Ok(Self::ReactiveContextDeliveryUnknown {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            operation,
            pending_ref: operation_unknown_ref(&request.operation, "queue-response", request),
        })
    }

    pub fn unknown_for(request: &HostRuntimeControlRequest, pending_ref: PlatformHandle) -> Self {
        let _ = request;
        Self::Unknown { pending_ref }
    }

    /// Project the generation-bound activation admission onto this response.
    ///
    /// The operation answer is preserved unchanged inside the projection; the
    /// admission travels with it so an authenticated caller receives the
    /// activation state, generation, governance profile, held lease state
    /// and drain disposition instead of only a local diagnostics line.
    /// Emission point is the runtime-control dispatch loop (STITCH: the
    /// `envelope.respond` call in `process_runtime_control_requests`,
    /// `bins/eliot-host/src/main.rs`, second-writer scope).
    pub fn with_activation_admission(self, admission: HostActivationAdmission) -> Self {
        Self::AdmissionProjected {
            response: Box::new(self),
            admission,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Restarted { receipt, .. } => receipt.validate(),
            Self::StoreRecovered { receipt, .. } => receipt.validate(),
            Self::UserAutomationOccurrenceAdmitted {
                mutation_digest,
                request_digest,
                response,
                ..
            } => {
                if !is_sha256_digest(mutation_digest) {
                    return Err("mutation_digest must be sha256".to_owned());
                }
                if !is_sha256_digest(request_digest) {
                    return Err("request_digest must be sha256".to_owned());
                }
                validate_user_automation_response(true, response)
            }
            Self::UserAutomationPendingWakesCancelled {
                mutation_digest,
                request_digest,
                response,
                ..
            } => {
                if !is_sha256_digest(mutation_digest) {
                    return Err("mutation_digest must be sha256".to_owned());
                }
                if !is_sha256_digest(request_digest) {
                    return Err("request_digest must be sha256".to_owned());
                }
                validate_user_automation_response(false, response)
            }
            Self::ReactiveContextDeliveryObserved { observation } => {
                validate_reactive_context_observation(observation)
            }
            Self::ReactiveContextPreEffectRejected {
                mutation_digest,
                request_digest,
                failure,
            } => {
                validate_runtime_control_digest(mutation_digest, "mutation_digest")?;
                validate_runtime_control_digest(request_digest, "request_digest")?;
                if failure.reason.trim().is_empty() {
                    return Err("reactive Context pre-effect reason is blank".to_owned());
                }
                Ok(())
            }
            Self::ReactiveContextDeliveryUnknown {
                mutation_digest,
                request_digest,
                operation,
                pending_ref,
            } => {
                validate_runtime_control_digest(mutation_digest, "mutation_digest")?;
                validate_runtime_control_digest(request_digest, "request_digest")?;
                if operation.operation_id.as_str().trim().is_empty()
                    || operation.idempotency_key.as_str().trim().is_empty()
                {
                    return Err("reactive Context queue operation identity is blank".to_owned());
                }
                parse_runtime_control_unknown_ref(pending_ref)
                    .map(|_| ())
                    .ok_or_else(|| "pending_ref is not canonical".to_owned())
            }
            Self::Unknown { pending_ref, .. } => parse_runtime_control_unknown_ref(pending_ref)
                .map(|_| ())
                .ok_or_else(|| "pending_ref is not canonical".to_owned()),
            Self::AdmissionProjected {
                response,
                admission,
            } => {
                response.validate()?;
                admission.validate()
            }
        }
    }
}

fn pending_ref_matches_request(
    pending_ref: &PlatformHandle,
    request: &HostRuntimeControlRequest,
) -> bool {
    parse_runtime_control_unknown_ref(pending_ref).is_some_and(|parsed| {
        parsed.wire == request.wire
            && parsed.operation == request.operation
            && parsed.request_id == request.request_id
            && parsed.mutation_digest == request.mutation_digest
            && parsed.request_digest == request.request_digest
    })
}

pub fn response_matches_request(
    request: &HostRuntimeControlRequest,
    response: &HostRuntimeControlResponse,
) -> bool {
    if request.validate().is_err() || response.validate().is_err() {
        return false;
    }
    match response {
        HostRuntimeControlResponse::Restarted { receipt } => {
            receipt.request_digest == request.request_digest
                && receipt.mutation_digest == request.mutation_digest
        }
        HostRuntimeControlResponse::StoreRecovered { receipt } => {
            receipt.request_digest == request.request_digest
                && receipt.external_control_mutation_digest == request.mutation_digest
        }
        HostRuntimeControlResponse::UserAutomationOccurrenceAdmitted {
            mutation_digest,
            request_digest,
            response,
        } => {
            request.operation == HostRuntimeControlOperation::AdmitUserAutomationOccurrence
                && *mutation_digest == request.mutation_digest
                && *request_digest == request.request_digest
                && user_automation_response_matches_request(request, response)
        }
        HostRuntimeControlResponse::UserAutomationPendingWakesCancelled {
            mutation_digest,
            request_digest,
            response,
        } => {
            request.operation == HostRuntimeControlOperation::CancelUserAutomationPendingWakes
                && *mutation_digest == request.mutation_digest
                && *request_digest == request.request_digest
                && user_automation_response_matches_request(request, response)
        }
        HostRuntimeControlResponse::ReactiveContextDeliveryObserved { observation } => {
            request.operation == HostRuntimeControlOperation::DeliverReactiveContext
                && observation.mutation_digest == request.mutation_digest
                && observation.request_digest == request.request_digest
                && reactive_context_observation_matches_request(request, observation)
        }
        HostRuntimeControlResponse::ReactiveContextPreEffectRejected {
            mutation_digest,
            request_digest,
            ..
        } => {
            request.operation == HostRuntimeControlOperation::DeliverReactiveContext
                && request.reactive_context.is_some()
                && *mutation_digest == request.mutation_digest
                && *request_digest == request.request_digest
        }
        HostRuntimeControlResponse::ReactiveContextDeliveryUnknown {
            mutation_digest,
            request_digest,
            operation,
            pending_ref,
        } => {
            request.operation == HostRuntimeControlOperation::DeliverReactiveContext
                && *mutation_digest == request.mutation_digest
                && *request_digest == request.request_digest
                && reactive_context_operation_matches_request(request, operation)
                && pending_ref_matches_request(pending_ref, request)
        }
        HostRuntimeControlResponse::Unknown { pending_ref } => {
            pending_ref_matches_request(pending_ref, request)
        }
        // The projection is transparent: the inner operation answer keeps
        // its exact request binding, and the admission itself was already
        // validated above as generation-bound durable evidence.
        HostRuntimeControlResponse::AdmissionProjected { response, .. } => {
            response_matches_request(request, response)
        }
    }
}

/// Check the typed UserAutomation answer against the exact carrier admitted
/// by the runtime-control request. The carrier digest and fence binding are
/// enforced by the existing typed response validation; a missing carrier or
/// an operation mismatch fails closed.
fn user_automation_response_matches_request(
    request: &HostRuntimeControlRequest,
    response: &UserAutomationHostExecutionResponse,
) -> bool {
    let Some(carrier) = request
        .user_automation
        .as_ref()
        .map(|source| &source.execution)
    else {
        return false;
    };
    let operation_matches = match (&request.operation, &carrier.operation) {
        (
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            UserAutomationHostExecutionOperation::AdmitOccurrence { .. },
        )
        | (
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
            UserAutomationHostExecutionOperation::CancelPendingWakes { .. },
        ) => true,
        _ => false,
    };
    if !operation_matches {
        return false;
    }
    response.validate_for(carrier).is_ok()
}

fn validate_runtime_control_digest(value: &PlatformHandle, field: &str) -> Result<(), String> {
    if is_sha256_digest(value) {
        Ok(())
    } else {
        Err(format!("{field} must be sha256"))
    }
}

fn validate_reactive_context_observation(
    observation: &ReactiveContextDeliveryObservation,
) -> Result<(), String> {
    validate_runtime_control_digest(&observation.mutation_digest, "mutation_digest")?;
    validate_runtime_control_digest(&observation.request_digest, "request_digest")?;
    if !is_sha256_text(&observation.payload_sha256) {
        return Err("reactive Context payload_sha256 must be sha256".to_owned());
    }
    if observation
        .operation
        .operation_id
        .as_str()
        .trim()
        .is_empty()
        || observation
            .operation
            .idempotency_key
            .as_str()
            .trim()
            .is_empty()
    {
        return Err("reactive Context queue operation identity is blank".to_owned());
    }
    let stage_matches = match observation.disposition {
        ReactiveContextRuntimeDisposition::Queued | ReactiveContextRuntimeDisposition::Replay => {
            observation.stage == ReactiveContextStage::EnqueuedPersisted
        }
        ReactiveContextRuntimeDisposition::Delivered => {
            observation.stage == ReactiveContextStage::DeliveredToExactEndpoint
        }
        ReactiveContextRuntimeDisposition::DeliveryUnknown => matches!(
            observation.stage,
            ReactiveContextStage::DeliveryAttempted | ReactiveContextStage::UnknownDelivery
        ),
        ReactiveContextRuntimeDisposition::NotAttempted => matches!(
            observation.stage,
            ReactiveContextStage::RejectedNotAttempted | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextRuntimeDisposition::AlreadyAcknowledged => matches!(
            observation.stage,
            ReactiveContextStage::RecipientReceived
                | ReactiveContextStage::RecipientDurable
                | ReactiveContextStage::NormalizedProjection
                | ReactiveContextStage::AppliedProjection
        ),
        ReactiveContextRuntimeDisposition::AlreadyTerminal => matches!(
            observation.stage,
            ReactiveContextStage::RejectedNotAttempted
                | ReactiveContextStage::AcknowledgementRejected
                | ReactiveContextStage::AcknowledgementUnknown
                | ReactiveContextStage::ExpiredBeforeAck
                | ReactiveContextStage::CancelledRetracted
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
                | ReactiveContextStage::InvalidAcknowledgement
        ),
    };
    if !stage_matches {
        return Err("reactive Context disposition does not match durable stage".to_owned());
    }
    Ok(())
}

fn reactive_context_operation_matches_request(
    request: &HostRuntimeControlRequest,
    operation: &IdempotencyIdentity,
) -> bool {
    let Some(source) = request.reactive_context.as_ref() else {
        return false;
    };
    operation.operation_id.as_str() == source.delivery.payload.operation_id.as_str()
        && operation.idempotency_key.as_str() == source.delivery.payload.idempotency_key.as_str()
}

fn reactive_context_observation_matches_request(
    request: &HostRuntimeControlRequest,
    observation: &ReactiveContextDeliveryObservation,
) -> bool {
    if !reactive_context_operation_matches_request(request, &observation.operation) {
        return false;
    }
    request
        .reactive_context
        .as_ref()
        .and_then(|source| source.delivery.payload.payload_sha256().ok())
        .is_some_and(|payload_sha256| payload_sha256 == observation.payload_sha256)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn durable_frame_identity(digest: &str) -> Result<(RequestId, RequestIdentity), String> {
    let request_id = RequestId::new(digest.to_owned()).map_err(|_| "SessionFenced".to_owned())?;
    // Canonical lineage-A genesis fence for the synthetic frame identity
    // (Implements #64): the frame carries no authority; the exact tuple uses
    // the fixed canonical lineage at sequence 1.
    let genesis_epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .map_err(|_| "SessionFenced".to_owned())?,
        std::num::NonZeroU64::new(1).ok_or("SessionFenced")?,
    )
    .map_err(|_| "SessionFenced".to_owned())?;
    let state_fence = StateFence::new(genesis_epoch, ResourceGeneration::genesis());
    let product_id = ProductId::new("eliot.host.runtime-control".to_owned())
        .map_err(|_| "SessionFenced".to_owned())?;
    let source_id =
        SourceId::new("eliot-host".to_owned()).map_err(|_| "SessionFenced".to_owned())?;
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata: RequestMetadata {
                request_id: request_id.clone(),
                session_id: None,
                task_id: None,
                product_id,
                source_id,
                state_fence: state_fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence,
        },
        idempotency_key: digest.to_owned(),
        deadline_unix_ms: u64::MAX,
        cancellation_id: digest.to_owned(),
    };
    identity
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    Ok((request_id, identity))
}

pub fn runtime_control_request_frame(
    connection_id: impl Into<String>,
    request: &HostRuntimeControlRequest,
) -> Result<Frame, String> {
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let (request_id, request_identity) = durable_frame_identity(request.request_digest.as_str())
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Start,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(request).map_err(|_| "SessionFenced".to_owned())?,
        ),
        trace_context: production_trace_context(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_runtime_control_request_frame(
    frame: &Frame,
) -> Result<HostRuntimeControlRequest, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    validate_production_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Start {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    let request: HostRuntimeControlRequest =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if frame_request_id.as_str() != request.request_digest.as_str() {
        return Err("SessionFenced".to_owned());
    }
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id.as_str() != request.request_digest.as_str()
        || identity.idempotency_key != request.request_digest.as_str()
        || identity.cancellation_id != request.request_digest.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    if identity.request.metadata.request_id != *frame_request_id {
        return Err("SessionFenced".to_owned());
    }
    Ok(request)
}

fn response_frame_digest(response: &HostRuntimeControlResponse) -> Result<String, String> {
    match response {
        HostRuntimeControlResponse::Restarted { receipt, .. } => {
            Ok(receipt.request_digest.as_str().to_owned())
        }
        HostRuntimeControlResponse::StoreRecovered { receipt, .. } => {
            Ok(receipt.request_digest.as_str().to_owned())
        }
        HostRuntimeControlResponse::UserAutomationOccurrenceAdmitted { request_digest, .. }
        | HostRuntimeControlResponse::UserAutomationPendingWakesCancelled {
            request_digest, ..
        }
        | HostRuntimeControlResponse::ReactiveContextPreEffectRejected { request_digest, .. }
        | HostRuntimeControlResponse::ReactiveContextDeliveryUnknown { request_digest, .. } => {
            Ok(request_digest.as_str().to_owned())
        }
        HostRuntimeControlResponse::ReactiveContextDeliveryObserved { observation } => {
            Ok(observation.request_digest.as_str().to_owned())
        }
        HostRuntimeControlResponse::Unknown { pending_ref, .. } => {
            Ok(parse_runtime_control_unknown_ref(pending_ref)
                .ok_or_else(|| "SessionFenced".to_owned())?
                .request_digest
                .as_str()
                .to_owned())
        }
        // The projection carries no frame identity of its own; the frame
        // stays bound to the inner operation answer.
        HostRuntimeControlResponse::AdmissionProjected { response, .. } => {
            response_frame_digest(response)
        }
    }
}

pub fn runtime_control_response_frame(
    connection_id: impl Into<String>,
    response: &HostRuntimeControlResponse,
) -> Result<Frame, String> {
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let digest = response_frame_digest(response)?;
    let (request_id, request_identity) =
        durable_frame_identity(&digest).map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Ready,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(response).map_err(|_| "SessionFenced".to_owned())?,
        ),
        trace_context: production_trace_context(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_runtime_control_response_frame(
    frame: &Frame,
) -> Result<HostRuntimeControlResponse, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    validate_production_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Ready {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    let response: HostRuntimeControlResponse =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id != *frame_request_id
        || identity.idempotency_key != frame_request_id.as_str()
        || identity.cancellation_id != frame_request_id.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    if !response_matches_frame_request_id(&response, frame_request_id.as_str()) {
        return Err("SessionFenced".to_owned());
    }
    Ok(response)
}

fn response_matches_frame_request_id(
    response: &HostRuntimeControlResponse,
    frame_request_id: &str,
) -> bool {
    match response {
        HostRuntimeControlResponse::Restarted { receipt, .. } => {
            frame_request_id == receipt.request_digest.as_str()
        }
        HostRuntimeControlResponse::StoreRecovered { receipt, .. } => {
            frame_request_id == receipt.request_digest.as_str()
        }
        HostRuntimeControlResponse::UserAutomationOccurrenceAdmitted { request_digest, .. }
        | HostRuntimeControlResponse::UserAutomationPendingWakesCancelled {
            request_digest, ..
        }
        | HostRuntimeControlResponse::ReactiveContextPreEffectRejected { request_digest, .. }
        | HostRuntimeControlResponse::ReactiveContextDeliveryUnknown { request_digest, .. } => {
            frame_request_id == request_digest.as_str()
        }
        HostRuntimeControlResponse::ReactiveContextDeliveryObserved { observation } => {
            frame_request_id == observation.request_digest.as_str()
        }
        HostRuntimeControlResponse::Unknown { pending_ref, .. } => {
            parse_runtime_control_unknown_ref(pending_ref).is_some_and(|pending_request| {
                frame_request_id == pending_request.request_digest.as_str()
            })
        }
        // The projection carries no frame identity of its own; the frame
        // stays bound to the inner operation answer.
        HostRuntimeControlResponse::AdmissionProjected { response, .. } => {
            response_matches_frame_request_id(response, frame_request_id)
        }
    }
}

// ---------------------------------------------------------------------------
// #954 backup envelope/method bridge (#962).
//
// Provider-neutral, fail-closed envelope around the closed #954 backup
// operation vocabulary (`eliot_protocol::backup`). This bridge mints no
// backup authority and changes none of the seven existing
// `HostRuntimeControlOperation` variants or the v2 wire above: it binds the
// operation, role, capability, session, nonce, generation, fence, and
// installation identities into digests and frames on the same SessionFenced
// contour. `eliot-protocol` is already a dependency of this crate, so the
// closed #954 types and MAX bounds are reused directly; no local vocabulary
// is introduced and no version distinction is widened.
// ---------------------------------------------------------------------------

/// Retired wire identifier of the header-only backup carrier.
///
/// That carrier carried correlation only: an operation, a role, and
/// digest-shaped strings, with no operation body at all. It is refused
/// explicitly by both decoders and is never reinterpreted as an executable
/// body by the current carrier.
pub const HOST_BACKUP_RUNTIME_CONTROL_LEGACY_HEADER_WIRE: &str = "eliot.host.backup-control.v1";
/// Stable wire identifier for Host backup runtime-control envelopes that
/// carry the exact `#954` operation body. Distinct from
/// [`HOST_RUNTIME_CONTROL_WIRE`]; existing v2 version distinctions are
/// unchanged.
pub const HOST_BACKUP_RUNTIME_CONTROL_WIRE: &str = "eliot.host.backup-control.v2";
/// Maximum canonical JSON bytes accepted for one backup envelope payload.
/// Reuses the closed #954 bound.
pub const MAX_BACKUP_RUNTIME_CONTROL_PAYLOAD_BYTES: usize =
    eliot_protocol::backup::MAX_BACKUP_PAYLOAD_BYTES;
/// Maximum bytes for one bounded backup envelope text field.
/// Reuses the closed #954 bound.
pub const MAX_BACKUP_RUNTIME_CONTROL_TEXT_BYTES: usize =
    eliot_protocol::backup::MAX_BACKUP_TEXT_BYTES;
const BACKUP_WIRE: &str = HOST_BACKUP_RUNTIME_CONTROL_WIRE;
const BACKUP_LEGACY_HEADER_WIRE: &str = HOST_BACKUP_RUNTIME_CONTROL_LEGACY_HEADER_WIRE;

/// Bounded refusal reason for the retired header-only backup carrier.
const BACKUP_LEGACY_HEADER_REFUSAL: &str = "legacy header-only backup carrier is unsupported";

/// Closed capability projection for one #954 backup operation. The envelope
/// capability is always derived from the operation; a stored capability that
/// diverges fails closed.
fn backup_capability_for_operation(
    operation: &eliot_protocol::backup::BackupOperationKind,
) -> eliot_protocol::backup::BackupCapability {
    use eliot_protocol::backup::{BackupCapability as Capability, BackupOperationKind as Kind};
    match operation {
        Kind::RequestCapture => Capability::RequestCapture,
        Kind::ReadSnapshotPage => Capability::ReadSnapshotPage,
        Kind::VerifyArchive => Capability::VerifyArchive,
        Kind::PrepareIsolatedRestore => Capability::PrepareIsolatedRestore,
        Kind::RestoreStep => Capability::RestoreStep,
        Kind::ReconcileRestore => Capability::ReconcileRestore,
        Kind::RestoreStatus => Capability::RestoreStatus,
        Kind::CompleteRehearsal => Capability::CompleteRehearsal,
        Kind::AdmitCutover => Capability::AdmitCutover,
    }
}

/// Envelope mutation identity: the transport fields of one carrier plus the
/// request digest of the exact operation body it carries.
///
/// The body's own request digest is included as a single committed value, not
/// as a second digest domain derived here. The body commits its own identity
/// and its operation-specific fields; this digest commits that body to this
/// envelope's operation, session, nonce, generation, fence, source,
/// destination and owner. Deriving the body's request digest from the header
/// instead would let a header and a body be independently well-formed while
/// together committing to something neither describes.
fn backup_mutation_digest_for(
    wire: &PlatformHandle,
    operation: &eliot_protocol::backup::BackupOperationKind,
    request_id: &PlatformHandle,
    session_id: &PlatformHandle,
    nonce: &PlatformHandle,
    generation: &PlatformHandle,
    fence: &PlatformHandle,
    source: &PlatformHandle,
    destination: &PlatformHandle,
    owner: &PlatformHandle,
    body_request_digest: &str,
) -> String {
    sha256_hex(
        format!(
            "{}:backup:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            wire.as_str(),
            operation.as_str(),
            request_id.as_str(),
            session_id.as_str(),
            nonce.as_str(),
            generation.as_str(),
            fence.as_str(),
            source.as_str(),
            destination.as_str(),
            owner.as_str(),
            body_request_digest
        )
        .as_bytes(),
    )
}

fn backup_request_digest_for(
    wire: &PlatformHandle,
    operation: &eliot_protocol::backup::BackupOperationKind,
    request_id: &PlatformHandle,
    mutation_digest: &PlatformHandle,
) -> String {
    sha256_hex(
        format!(
            "{}:backup:{}:{}:{}",
            wire.as_str(),
            operation.as_str(),
            request_id.as_str(),
            mutation_digest.as_str()
        )
        .as_bytes(),
    )
}

fn backup_bounded_text(value: &PlatformHandle, field: &'static str) -> Result<(), String> {
    if value.as_str().trim().is_empty() || value.as_str().chars().any(char::is_control) {
        return Err(format!("backup {field} invalid"));
    }
    if value.as_str().len() > MAX_BACKUP_RUNTIME_CONTROL_TEXT_BYTES {
        return Err(format!("backup {field} exceeds the bounded wire limit"));
    }
    Ok(())
}

/// The exact `#954` operation body carried by the backup carrier.
///
/// The carrier header (wire, operation, role, capability, source,
/// destination, owner, session, nonce, generation, fence and digests) is
/// correlation only. This body is the operation itself: it commits the
/// complete preparation/cutover/status/reconcile request, its source and
/// destination installations, its operation, its class, its state fence, and
/// the admission authority, scope, capability and receipt that admitted it. A
/// role enum plus a digest-shaped string is not that body, so this field is
/// required: a payload without one does not decode into a backup request.
///
/// The bodies are the canonical `#954` per-operation request types, consumed
/// from their single owner. This module introduces no second backup operation
/// vocabulary: each variant is validated by that type's own contract, and the
/// operation is bound by the serialization tag as well as by the body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum BackupOperationBody {
    /// `PREPARE_ISOLATED_RESTORE`: the destination-only preparation request.
    PrepareIsolatedRestore(BackupIsolatedRestorePrepare),
    /// `ADMIT_CUTOVER`: the separately admitted installation cutover request.
    AdmitCutover(BackupCutoverAdmission),
    /// `RESTORE_STATUS`: the read-only restore status query.
    RestoreStatus(BackupRestoreStatus),
    /// `RECONCILE_RESTORE`: the reconcile query over the retained operation.
    ReconcileRestore(BackupRestoreReconcile),
}

impl BackupOperationBody {
    /// Returns the operation this body is the request for.
    #[must_use]
    pub fn operation(&self) -> BackupOperationKind {
        match self {
            Self::PrepareIsolatedRestore(_) => BackupOperationKind::PrepareIsolatedRestore,
            Self::AdmitCutover(_) => BackupOperationKind::AdmitCutover,
            Self::RestoreStatus(_) => BackupOperationKind::RestoreStatus,
            Self::ReconcileRestore(_) => BackupOperationKind::ReconcileRestore,
        }
    }

    /// Returns the shared request identity every `#954` body binds. It carries
    /// the principal, fence, class, source/destination installations and the
    /// admission authority, scope, capability and receipt of this operation.
    #[must_use]
    pub fn identity(&self) -> &BackupRequestIdentity {
        match self {
            Self::PrepareIsolatedRestore(body) => &body.identity,
            Self::AdmitCutover(body) => &body.identity,
            Self::RestoreStatus(body) => &body.identity,
            Self::ReconcileRestore(body) => &body.identity,
        }
    }

    /// Returns the canonical request digest of the exact body.
    ///
    /// This is the body's own `#954` request identity, not a digest derived
    /// by this carrier, and not the shared request-identity digest. The
    /// carrier commits it; it never recomputes or replaces it.
    #[must_use]
    pub fn request_digest(&self) -> &str {
        match self {
            Self::PrepareIsolatedRestore(body) => &body.request_digest,
            Self::AdmitCutover(body) => &body.request_digest,
            Self::RestoreStatus(body) => &body.request_digest,
            Self::ReconcileRestore(body) => &body.request_digest,
        }
    }

    /// Validates the body through its own canonical `#954` contract.
    pub fn validate(&self) -> Result<(), String> {
        let validated = match self {
            Self::PrepareIsolatedRestore(body) => body.validate(),
            Self::AdmitCutover(body) => body.validate(),
            Self::RestoreStatus(body) => body.validate(),
            Self::ReconcileRestore(body) => body.validate(),
        };
        validated.map_err(|error| error.to_string())
    }
}

/// The retained operation one owner outcome refers to.
///
/// This is the owner's own record of the admitted operation, not a requester
/// retry token. It names the operation, the retained `#954` request identity
/// digest that binds the original admitted request, and the owner retaining
/// it, so a pending or possibly-effected answer identifies the exact original
/// operation to reconcile instead of asking for a blind new attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRetainedOperation {
    /// The operation the owner retained.
    pub operation: BackupOperationKind,
    /// Retained request identity digest of that exact operation.
    pub identity_digest: PlatformHandle,
    /// Identity of the owner retaining the operation.
    pub owner: PlatformHandle,
}

impl BackupRetainedOperation {
    /// Validates the bounded shape of one retained-operation reference.
    pub fn validate(&self) -> Result<(), String> {
        if !is_sha256_digest(&self.identity_digest) {
            return Err("backup retained identity_digest must be lowercase sha256".to_owned());
        }
        backup_bounded_text(&self.owner, "retained owner")
    }
}

/// The typed owner outcome of one admitted backup dispatch.
///
/// A pre-effect refusal is deliberately not an outcome: it is the typed
/// `BackupDispatchRefusal` error the owner returns before it has done
/// anything. Everything an owner that reached its operation can report is one
/// of these three variants, and they are not collapsible into one another,
/// because they are three different facts with three different next actions:
/// read the retained operation, accept the owner's receipt, or reconcile the
/// original operation. An owner that may already have effected must return
/// [`BackupOwnerOutcome::PossibleEffect`]; it can never report its failure as
/// an effect-free refusal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupOwnerOutcome {
    /// Admitted and pending: the owner retained the exact operation and is
    /// still executing it. No stage is claimed and no receipt exists yet, so
    /// the requester reads this same retained operation instead of
    /// resubmitting.
    Admitted { retained: BackupRetainedOperation },
    /// Completed: the owner performed the operation and issued its own phase
    /// attestation. A produced destination or artifact travels as a bounded
    /// immutable handle, never as a path, a URL, or an inline body.
    Completed {
        attestation: BackupPhaseAttestation,
        handle: Option<BackupArtifactHandle>,
    },
    /// Possible effect: the owner retained the exact operation but cannot say
    /// whether the effect committed. The same operation must be reconciled;
    /// this outcome is never success and never authorizes a second effect.
    PossibleEffect { retained: BackupRetainedOperation },
}

impl BackupOwnerOutcome {
    /// Validates the owner outcome on its own terms.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Admitted { retained } | Self::PossibleEffect { retained } => retained.validate(),
            Self::Completed {
                attestation,
                handle,
            } => {
                attestation.validate().map_err(|error| error.to_string())?;
                match handle {
                    Some(handle) => handle
                        .validate("backup_owner_outcome.handle")
                        .map_err(|error| error.to_string()),
                    None => Ok(()),
                }
            }
        }
    }

    /// Validates this owner outcome against the exact admitted request.
    ///
    /// A retained reference must name the admitted operation, the admitted
    /// request's own identity digest, and the admitted owner. A completion
    /// attestation must be bound to the admitted archive, fence and deadline,
    /// must be issued by an attesting role admitted for its own phase, and
    /// must attest a phase the admitted operation can actually establish.
    /// Correlation alone never passes.
    pub fn validate_against_request(
        &self,
        request: &BackupRuntimeControlRequest,
    ) -> Result<(), String> {
        self.validate()?;
        let identity = request.body.identity();
        match self {
            Self::Admitted { retained } | Self::PossibleEffect { retained } => {
                if retained.operation != request.operation
                    || retained.identity_digest.as_str() != identity.identity_digest.as_str()
                    || retained.owner != request.owner
                {
                    return Err(
                        "backup retained operation does not match the admitted request".to_owned(),
                    );
                }
                Ok(())
            }
            Self::Completed { attestation, .. } => {
                if attestation.archive_id != identity.archive_id
                    || attestation.fence != identity.fence
                {
                    return Err(
                        "backup owner attestation does not match the admitted request".to_owned(),
                    );
                }
                if attestation.observed_at_unix_ms > identity.deadline_unix_ms {
                    return Err("backup owner attestation is no longer current".to_owned());
                }
                if !attestation.owner_role.is_attesting_role()
                    || !attesting_roles(attestation.phase).contains(&attestation.owner_role)
                    || !attestation
                        .owner_role
                        .permits(operation_for_phase(attestation.phase))
                    || !backup_phase_matches_operation(request.operation, attestation.phase)
                {
                    return Err(
                        "backup owner attestation does not attest the admitted operation"
                            .to_owned(),
                    );
                }
                Ok(())
            }
        }
    }
}

/// Returns whether a completed owner attestation may carry `phase` for
/// `operation`.
///
/// A read-only status query advances no stage of its own: it reports the
/// stage the retained restore operation has reached, so any restore stage is
/// admissible there and nothing else is. Every other accepted operation
/// establishes exactly one stage, and the capture and rehearsal stages belong
/// to operations the Host does not serve.
fn backup_phase_matches_operation(operation: BackupOperationKind, phase: BackupStage) -> bool {
    match operation {
        BackupOperationKind::PrepareIsolatedRestore => phase == BackupStage::RestorePrepared,
        BackupOperationKind::AdmitCutover => phase == BackupStage::CutoverAdmitted,
        BackupOperationKind::ReconcileRestore => phase == BackupStage::Reconciled,
        BackupOperationKind::RestoreStatus => matches!(
            phase,
            BackupStage::RestorePrepared
                | BackupStage::RestoreStepApplied
                | BackupStage::Reconciled
        ),
        BackupOperationKind::RequestCapture
        | BackupOperationKind::ReadSnapshotPage
        | BackupOperationKind::VerifyArchive
        | BackupOperationKind::RestoreStep
        | BackupOperationKind::CompleteRehearsal => false,
    }
}

/// Authenticated backup envelope binding one closed #954 operation to its
/// session, nonce, generation, fence, and installation identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRuntimeControlRequest {
    pub wire: PlatformHandle,
    pub operation: eliot_protocol::backup::BackupOperationKind,
    pub role: eliot_protocol::backup::BackupRole,
    pub capability: eliot_protocol::backup::BackupCapability,
    pub source: PlatformHandle,
    pub destination: PlatformHandle,
    pub owner: PlatformHandle,
    pub request_id: PlatformHandle,
    pub session_id: PlatformHandle,
    pub nonce: PlatformHandle,
    pub generation: PlatformHandle,
    pub fence: PlatformHandle,
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    /// The exact `#954` operation body this envelope admits. Required: a
    /// header-only payload is the retired carrier and does not decode.
    pub body: BackupOperationBody,
}

impl BackupRuntimeControlRequest {
    /// Construct an authenticated backup envelope around one exact `#954`
    /// operation body.
    ///
    /// The operation, role, source, destination, and session are read from
    /// the body, never supplied beside it, so a caller cannot present a header
    /// that describes an operation the body does not carry. The caller
    /// supplies only what the body does not own: the owner, the transport
    /// request identity, the nonce, the generation, and the fence. The
    /// envelope mutation digest then commits the body's own request digest
    /// together with those transport fields.
    ///
    /// The body is validated first, so an unsupported method, a role without
    /// the operation, or a body that is not the exact `#954` request for its
    /// own identity errors before any digest is minted, and therefore before
    /// effects.
    pub fn new_backup(
        body: BackupOperationBody,
        owner: PlatformHandle,
        request_id: PlatformHandle,
        nonce: PlatformHandle,
        generation: PlatformHandle,
        fence: PlatformHandle,
    ) -> Result<Self, String> {
        body.validate()?;
        let identity = body.identity();
        let operation = body.operation();
        let role = identity.principal.role;
        if !role.permits(operation) {
            return Err("backup role does not permit operation".to_owned());
        }
        let source =
            PlatformHandle::new(identity.source_installation.clone()).map_err(|e| e.to_string())?;
        let destination =
            PlatformHandle::new(identity.dest_installation.clone()).map_err(|e| e.to_string())?;
        let session_id = PlatformHandle::new(identity.principal.session_id.clone())
            .map_err(|e| e.to_string())?;
        let wire = PlatformHandle::new(BACKUP_WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest = PlatformHandle::new(backup_mutation_digest_for(
            &wire,
            &operation,
            &request_id,
            &session_id,
            &nonce,
            &generation,
            &fence,
            &source,
            &destination,
            &owner,
            body.request_digest(),
        ))
        .map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(backup_request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            capability: backup_capability_for_operation(&operation),
            operation,
            role,
            source,
            destination,
            owner,
            request_id,
            session_id,
            nonce,
            generation,
            fence,
            mutation_digest,
            request_digest,
            body,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.wire.as_str() == BACKUP_LEGACY_HEADER_WIRE {
            return Err(BACKUP_LEGACY_HEADER_REFUSAL.to_owned());
        }
        if self.wire.as_str() != BACKUP_WIRE {
            return Err("unsupported backup wire".to_owned());
        }
        if !self.role.permits(self.operation) {
            return Err("backup role does not permit operation".to_owned());
        }
        if self.capability != backup_capability_for_operation(&self.operation) {
            return Err("backup capability mismatch".to_owned());
        }
        for (value, name) in [
            (&self.source, "source"),
            (&self.destination, "destination"),
            (&self.owner, "owner"),
            (&self.request_id, "request_id"),
            (&self.session_id, "session_id"),
            (&self.nonce, "nonce"),
        ] {
            backup_bounded_text(value, name)?;
        }
        if self.source == self.destination {
            return Err("backup source and destination must remain distinct".to_owned());
        }
        // Generation and fence travel digest-bound: stale free-text values
        // fail closed at the envelope. Exact-equality against live owner
        // state stays with admission at the dispatch owner.
        for (value, name) in [(&self.generation, "generation"), (&self.fence, "fence")] {
            if !is_sha256_digest(value) {
                return Err(format!("backup {name} must be lowercase sha256"));
            }
        }
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("backup mutation_digest must be lowercase sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("backup request_digest must be lowercase sha256".to_owned());
        }
        let expected_mutation = backup_mutation_digest_for(
            &self.wire,
            &self.operation,
            &self.request_id,
            &self.session_id,
            &self.nonce,
            &self.generation,
            &self.fence,
            &self.source,
            &self.destination,
            &self.owner,
            self.body.request_digest(),
        );
        if expected_mutation != self.mutation_digest.as_str() {
            return Err("backup mutation_digest mismatch".to_owned());
        }
        let expected = backup_request_digest_for(
            &self.wire,
            &self.operation,
            &self.request_id,
            &self.mutation_digest,
        );
        if expected != self.request_digest.as_str() {
            return Err("backup request_digest mismatch".to_owned());
        }
        self.validate_body_binding()?;
        Ok(())
    }

    /// Joins the correlation header to the exact `#954` operation body.
    ///
    /// The header cannot describe an operation the body does not carry, and
    /// it cannot name a different source, destination, role, session, or
    /// capability than the body commits. Every effect-relevant value lives in
    /// the body, which validates itself through its own canonical contract;
    /// these joins are what make the header a faithful correlation of that
    /// body rather than a second, self-consistent claim about a different one.
    ///
    /// The body is additionally committed by the envelope mutation digest,
    /// which is checked above over the body's own request digest, so a
    /// swapped body cannot keep a valid header.
    fn validate_body_binding(&self) -> Result<(), String> {
        self.body.validate()?;
        let identity = self.body.identity();
        if self.body.operation() != self.operation || identity.mutation.operation != self.operation
        {
            return Err("backup operation does not match the carried operation body".to_owned());
        }
        if identity.source_installation != self.source.as_str()
            || identity.dest_installation != self.destination.as_str()
        {
            return Err("backup installations do not match the carried operation body".to_owned());
        }
        if identity.principal.role != self.role
            || identity.principal.session_id != self.session_id.as_str()
        {
            return Err("backup principal does not match the carried operation body".to_owned());
        }
        Ok(())
    }
}

/// Authenticated backup answer bound to one [`BackupRuntimeControlRequest`].
/// The operation, source, destination, owner, and digest identities must
/// match the request exactly, and the carried [`BackupOwnerOutcome`] must
/// validate against that exact request; see
/// [`backup_response_matches_request`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRuntimeControlResponse {
    pub wire: PlatformHandle,
    pub operation: eliot_protocol::backup::BackupOperationKind,
    pub source: PlatformHandle,
    pub destination: PlatformHandle,
    pub owner: PlatformHandle,
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    /// What the owner actually did. The correlation fields above say which
    /// request this answers; only this says whether the operation is pending,
    /// completed with its receipt, or possibly effected. A transport
    /// acknowledgement is never this field's value.
    pub outcome: BackupOwnerOutcome,
}

impl BackupRuntimeControlResponse {
    /// Bind a backup answer to its exact request identity and the owner's own
    /// outcome. This constructor supplies the correlation portion only: the
    /// outcome is never derived from the request, so no answer can be built
    /// without one.
    pub fn backup_response_for(
        request: &BackupRuntimeControlRequest,
        outcome: BackupOwnerOutcome,
    ) -> Self {
        Self {
            wire: request.wire.clone(),
            operation: request.operation,
            source: request.source.clone(),
            destination: request.destination.clone(),
            owner: request.owner.clone(),
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            outcome,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.wire.as_str() == BACKUP_LEGACY_HEADER_WIRE {
            return Err(BACKUP_LEGACY_HEADER_REFUSAL.to_owned());
        }
        if self.wire.as_str() != BACKUP_WIRE {
            return Err("unsupported backup wire".to_owned());
        }
        for (value, name) in [
            (&self.source, "source"),
            (&self.destination, "destination"),
            (&self.owner, "owner"),
        ] {
            backup_bounded_text(value, name)?;
        }
        if self.source == self.destination {
            return Err("backup source and destination must remain distinct".to_owned());
        }
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("backup mutation_digest must be lowercase sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("backup request_digest must be lowercase sha256".to_owned());
        }
        self.outcome.validate()
    }
}

/// Check the backup answer against the exact request identity. The
/// operation, source, destination, owner, and both digests must match, and
/// the carried owner outcome must validate against that exact admitted
/// request; any substitution, and any outcome that describes another
/// operation, another retained identity, or a phase this operation cannot
/// establish, fails closed.
pub fn backup_response_matches_request(
    request: &BackupRuntimeControlRequest,
    response: &BackupRuntimeControlResponse,
) -> bool {
    let outcome = response.outcome.validate_against_request(request);
    if response.validate().is_err() || outcome.is_err() {
        return false;
    }
    response.operation == request.operation
        && response.source == request.source
        && response.destination == request.destination
        && response.owner == request.owner
        && response.mutation_digest == request.mutation_digest
        && response.request_digest == request.request_digest
}

/// Returns whether `payload` presents the retired header-only backup
/// carrier.
///
/// That wire identity never carried an operation body, so it is refused by
/// name here rather than being left to a field check: a decoder must never
/// be able to reinterpret it as an executable body of a newer carrier.
fn backup_legacy_header_only_payload(payload: &serde_json::Value) -> bool {
    payload.get("wire").and_then(serde_json::Value::as_str) == Some(BACKUP_LEGACY_HEADER_WIRE)
        && payload.get("body").is_none()
}

fn backup_frame_payload_len(payload: &serde_json::Value) -> Result<usize, String> {
    serde_json::to_vec(payload)
        .map(|bytes| bytes.len())
        .map_err(|_| "SessionFenced".to_owned())
}

pub fn backup_request_frame(
    connection_id: impl Into<String>,
    request: &BackupRuntimeControlRequest,
) -> Result<Frame, String> {
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let payload = serde_json::to_value(request).map_err(|_| "SessionFenced".to_owned())?;
    if backup_frame_payload_len(&payload)? > MAX_BACKUP_RUNTIME_CONTROL_PAYLOAD_BYTES {
        return Err("SessionFenced".to_owned());
    }
    let (request_id, request_identity) = durable_frame_identity(request.request_digest.as_str())
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Start,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(payload),
        trace_context: production_trace_context(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_backup_request_frame(frame: &Frame) -> Result<BackupRuntimeControlRequest, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    validate_production_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Start {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    if backup_frame_payload_len(payload)? > MAX_BACKUP_RUNTIME_CONTROL_PAYLOAD_BYTES {
        return Err("SessionFenced".to_owned());
    }
    // The retired header-only carrier is refused explicitly: it carried no
    // operation body, so it is never decoded into a runnable request.
    if backup_legacy_header_only_payload(payload) {
        return Err(BACKUP_LEGACY_HEADER_REFUSAL.to_owned());
    }
    // Closed vocabulary with `deny_unknown_fields`: payload overrides,
    // oversize text, malformed shapes, and duplicate fields fail here,
    // before any effect. Unsupported methods (role without the operation),
    // stale generation/fence digests, and capability divergence fail in the
    // envelope validation below, also before effects.
    let request: BackupRuntimeControlRequest =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if frame_request_id.as_str() != request.request_digest.as_str() {
        return Err("SessionFenced".to_owned());
    }
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id.as_str() != request.request_digest.as_str()
        || identity.idempotency_key != request.request_digest.as_str()
        || identity.cancellation_id != request.request_digest.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    if identity.request.metadata.request_id != *frame_request_id {
        return Err("SessionFenced".to_owned());
    }
    Ok(request)
}

pub fn backup_response_frame(
    connection_id: impl Into<String>,
    response: &BackupRuntimeControlResponse,
) -> Result<Frame, String> {
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let payload = serde_json::to_value(response).map_err(|_| "SessionFenced".to_owned())?;
    if backup_frame_payload_len(&payload)? > MAX_BACKUP_RUNTIME_CONTROL_PAYLOAD_BYTES {
        return Err("SessionFenced".to_owned());
    }
    let (request_id, request_identity) = durable_frame_identity(response.request_digest.as_str())
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Ready,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(payload),
        trace_context: production_trace_context(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_backup_response_frame(frame: &Frame) -> Result<BackupRuntimeControlResponse, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    validate_production_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Ready {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    if backup_frame_payload_len(payload)? > MAX_BACKUP_RUNTIME_CONTROL_PAYLOAD_BYTES {
        return Err("SessionFenced".to_owned());
    }
    // The retired header-only carrier is refused explicitly here too: a
    // requester must never read one as an owner outcome of this carrier.
    if backup_legacy_header_only_payload(payload) {
        return Err(BACKUP_LEGACY_HEADER_REFUSAL.to_owned());
    }
    let response: BackupRuntimeControlResponse =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if frame_request_id.as_str() != response.request_digest.as_str() {
        return Err("SessionFenced".to_owned());
    }
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id != *frame_request_id
        || identity.idempotency_key != frame_request_id.as_str()
        || identity.cancellation_id != frame_request_id.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    Ok(response)
}

fn production_trace_context() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([(
        HOST_RUNTIME_CONTROL_PRODUCTION_TRACE_CONTEXT_KEY.to_owned(),
        HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR.to_owned(),
    )])
}

fn validate_production_trace_context(frame: &Frame) -> Result<(), String> {
    if frame.trace_context.len() != 1
        || frame
            .trace_context
            .get(HOST_RUNTIME_CONTROL_PRODUCTION_TRACE_CONTEXT_KEY)
            .map(String::as_str)
            != Some(HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR)
    {
        return Err("SessionFenced".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value.to_owned()).unwrap()
    }

    fn digest(seed: &str) -> PlatformHandle {
        handle(&sha256_hex(seed.as_bytes()))
    }

    fn restart_receipt(request: &HostRuntimeControlRequest) -> HostKernelRestartReceipt {
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            old_kernel_generation: digest("old"),
            new_kernel_generation: digest("new"),
            store_fence: digest("fence"),
            activation_receipt_digest: digest("activation"),
            ready_receipt_digest: digest("ready"),
            receipt_digest: digest("placeholder"),
        };
        receipt.receipt_digest = receipt.computed_digest().unwrap();
        receipt
    }

    #[test]
    fn request_roundtrip_preserves_exact_idempotency_and_request_digests() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("shared-roundtrip"),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: HostRuntimeControlRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.mutation_digest, request.mutation_digest);
        assert_eq!(decoded.request_digest, request.request_digest);
        decoded.validate().unwrap();
    }

    #[test]
    fn old_wire_unknown_fields_and_operation_substitution_are_rejected() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("strict-wire"),
        )
        .unwrap();
        let mut old_wire = serde_json::to_value(&request).unwrap();
        old_wire["wire"] = serde_json::json!("eliot.host.runtime-control.v1");
        let old_wire_request: HostRuntimeControlRequest = serde_json::from_value(old_wire).unwrap();
        assert!(old_wire_request.validate().is_err());

        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostRuntimeControlRequest>(unknown).is_err());

        let mut substituted = request.clone();
        substituted.operation = HostRuntimeControlOperation::RecoverStore;
        assert!(substituted.validate().is_err());
    }

    #[test]
    fn response_substitution_is_rejected_and_exact_response_is_accepted() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("response-binding"),
        )
        .unwrap();
        let trusted =
            HostRuntimeControlResponse::restarted_for(&request, restart_receipt(&request));
        assert!(response_matches_request(&request, &trusted));

        let foreign = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("foreign-response"),
        )
        .unwrap();
        let forged = HostRuntimeControlResponse::restarted_for(&foreign, restart_receipt(&foreign));
        assert!(!response_matches_request(&request, &forged));

        let mut substituted_receipt = restart_receipt(&request);
        substituted_receipt.new_kernel_generation = digest("substituted");
        let substituted = HostRuntimeControlResponse::restarted_for(&request, substituted_receipt);
        assert!(!response_matches_request(&request, &substituted));
    }

    #[test]
    fn request_and_response_frames_roundtrip_and_reject_identity_substitution() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RecoverStore,
            handle("frame-roundtrip"),
        )
        .unwrap();
        let frame = runtime_control_request_frame("request-connection", &request).unwrap();
        let decoded = decode_runtime_control_request_frame(&frame).unwrap();
        assert_eq!(decoded, request);

        let mut tampered = frame.clone();
        tampered.request_id =
            Some(RequestId::new(digest("wrong-frame-id").as_str().to_owned()).unwrap());
        assert!(decode_runtime_control_request_frame(&tampered).is_err());

        let response = HostRuntimeControlResponse::Unknown {
            pending_ref: runtime_control_unknown_ref("store-recovery", &request),
        };
        let response_frame =
            runtime_control_response_frame("response-connection", &response).unwrap();
        let decoded_response = decode_runtime_control_response_frame(&response_frame).unwrap();
        assert_eq!(decoded_response, response);
    }

    fn test_fence() -> StateFence {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let epoch = EpochId::new(lineage, std::num::NonZeroU64::new(1).unwrap()).unwrap();
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn cancelled_wakes() -> UserAutomationHostExecutionResponse {
        UserAutomationHostExecutionResponse::Cancelled {
            request_sha256: sha256_hex(b"cancel-carrier"),
            state_fence: test_fence(),
            wake_ids: vec!["wake-1".to_owned()],
        }
    }

    /// Identity-only request used to prove the Unknown reconciliation path.
    /// Typed UserAutomation requests always carry a validated carrier, so this
    /// helper covers only the digest-identity reconciliation after a lost
    /// response, exactly like `parse_runtime_control_unknown_ref` does.
    fn identity_only_user_automation_request(
        operation: HostRuntimeControlOperation,
        request_id: &str,
    ) -> HostRuntimeControlRequest {
        let wire = PlatformHandle::new(WIRE.to_owned()).unwrap();
        let request_id = handle(request_id);
        let mutation_digest =
            PlatformHandle::new(mutation_digest_for_request_id(&wire, &request_id)).unwrap();
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .unwrap();
        HostRuntimeControlRequest {
            wire,
            operation,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: None,
            user_automation: None,
        }
    }

    #[test]
    fn user_automation_requests_fail_closed_without_typed_carrier() {
        let admit = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            handle("ua-admit-no-carrier"),
        );
        assert_eq!(
            admit.unwrap_err(),
            "user automation input is required".to_owned()
        );
        let cancel = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
            handle("ua-cancel-no-carrier"),
        );
        assert_eq!(
            cancel.unwrap_err(),
            "user automation input is required".to_owned()
        );
    }

    #[test]
    fn user_automation_operation_wire_names_are_canonical() {
        assert_eq!(
            serde_json::to_value(HostRuntimeControlOperation::AdmitUserAutomationOccurrence)
                .unwrap(),
            serde_json::json!("ADMIT_USER_AUTOMATION_OCCURRENCE")
        );
        assert_eq!(
            serde_json::to_value(HostRuntimeControlOperation::CancelUserAutomationPendingWakes)
                .unwrap(),
            serde_json::json!("CANCEL_USER_AUTOMATION_PENDING_WAKES")
        );
        assert_eq!(
            serde_json::from_value::<HostRuntimeControlOperation>(serde_json::json!(
                "ADMIT_USER_AUTOMATION_OCCURRENCE"
            ))
            .unwrap(),
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence
        );
        assert_eq!(
            operation_unknown_prefix(&HostRuntimeControlOperation::AdmitUserAutomationOccurrence),
            "user-automation-admit"
        );
        assert_eq!(
            operation_unknown_prefix(
                &HostRuntimeControlOperation::CancelUserAutomationPendingWakes
            ),
            "user-automation-cancel-wakes"
        );
    }

    #[test]
    fn user_automation_unknown_refs_roundtrip_and_reconcile_after_lost_response() {
        for operation in [
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
        ] {
            let request = identity_only_user_automation_request(operation.clone(), "ua-reconcile");
            for suffix in ["validation", "queue-lock", "queue-full", "queue-response"] {
                let pending_ref = operation_unknown_ref(&operation, suffix, &request);
                let parsed = parse_runtime_control_unknown_ref(&pending_ref).unwrap();
                assert_eq!(parsed.operation, operation);
                assert_eq!(parsed.request_digest, request.request_digest);
                let unknown = HostRuntimeControlResponse::Unknown {
                    pending_ref: pending_ref.clone(),
                };
                unknown.validate().unwrap();
                assert!(response_matches_request(&request, &unknown));
                let frame =
                    runtime_control_response_frame("ua-reconcile-connection", &unknown).unwrap();
                let decoded = decode_runtime_control_response_frame(&frame).unwrap();
                assert_eq!(decoded, unknown);
            }
        }

        let restart = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("ua-foreign"),
        )
        .unwrap();
        let foreign = HostRuntimeControlResponse::Unknown {
            pending_ref: operation_unknown_ref(
                &HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
                "validation",
                &restart,
            ),
        };
        foreign.validate().unwrap();
        assert!(!response_matches_request(&restart, &foreign));

        let payload = serde_json::to_string(&(
            "NoSuchOperation",
            "id",
            sha256_hex(b"mutation"),
            sha256_hex(b"request"),
        ))
        .unwrap();
        let unknown_operation =
            PlatformHandle::new(format!("{WIRE}:unknown:reactive-context:{payload}")).unwrap();
        assert!(parse_runtime_control_unknown_ref(&unknown_operation).is_none());
        let unknown_reason =
            PlatformHandle::new(format!("{WIRE}:unknown:no-such-reason:{payload}")).unwrap();
        assert!(parse_runtime_control_unknown_ref(&unknown_reason).is_none());
    }

    #[test]
    fn user_automation_responses_bind_to_exact_request_and_reject_crossed_answers() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("ua-crossed"),
        )
        .unwrap();
        let cancelled = cancelled_wakes();

        let crossed = HostRuntimeControlResponse::user_automation_occurrence_admitted_for(
            &request,
            cancelled.clone(),
        );
        assert!(crossed.validate().is_err());
        assert!(!response_matches_request(&request, &crossed));

        let bound = HostRuntimeControlResponse::user_automation_pending_wakes_cancelled_for(
            &request, cancelled,
        );
        bound.validate().unwrap();
        assert!(!response_matches_request(&request, &bound));
    }

    #[test]
    fn user_automation_response_frames_roundtrip_and_reject_digest_substitution() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("ua-frame"),
        )
        .unwrap();
        let response = HostRuntimeControlResponse::user_automation_pending_wakes_cancelled_for(
            &request,
            cancelled_wakes(),
        );
        let frame = runtime_control_response_frame("ua-connection", &response).unwrap();
        let decoded = decode_runtime_control_response_frame(&frame).unwrap();
        assert_eq!(decoded, response);

        let mut tampered = frame.clone();
        tampered.request_id =
            Some(RequestId::new(digest("wrong-ua-frame-id").as_str().to_owned()).unwrap());
        assert!(decode_runtime_control_response_frame(&tampered).is_err());
    }
}
